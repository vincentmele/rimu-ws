//! A connection's whole protocol state, owned by one value and driven by bytes in and bytes out.
//!
//! [`Http2Conn`] parses every complete frame of the bytes it is fed, updates its state, queues its
//! replies (SETTINGS and PING acknowledgements, window updates, resets, GOAWAY) and reports what
//! happened as [`ConnEvent`]s. It does no I/O and holds no locks: the I/O loops of the server
//! framework and of the client feed it what they read and write what it queued.

pub(crate) mod output;
pub(crate) mod scan;
pub(crate) mod stream_table;
#[cfg(test)]
pub(crate) mod test_frames;
#[cfg(test)]
pub(crate) mod tests;

use crate::{
  collections::{ArrayVectorCopy, DequeUsize, VectorUsize},
  http::{HttpRecvParams, U31},
  http2::{
    Http2Error, Http2ErrorCode,
    common_flags::CommonFlags,
    conn::{
      output::Output,
      scan::{PREFACE, Preface, next_frame, strip_preface},
      stream_table::StreamTable,
    },
    frame_init::{FrameInit, FrameInitTy},
    headers_frame::HeadersFrame,
    hpack_decoder::HpackDecoder,
    hpack_encoder::HpackEncoder,
    misc::{protocol_err, trim_frame_pad},
    ping_frame::PingFrame,
    settings_frame::SettingsFrame,
  },
  rng::Rng,
};
use core::mem;

/// The window every stream and the connection start with (RFC 9113 §6.9.2).
const DEFAULT_WINDOW: i32 = 65_535;
const DEFAULT_MAX_FRAME_LEN: u32 = 16_384;

/// What a [`Http2Conn::feed`] call found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnEvent {
  /// The initial HEADERS of a stream arrived; with `end_stream` the message has no body.
  Headers { end_stream: bool, stream_id: U31 },
  /// Body bytes were appended to the stream's message; with `end_stream` it is complete.
  Data { end_stream: bool, stream_id: U31 },
  /// Trailers arrived, which end the stream.
  Trailers { stream_id: U31 },
  /// The stream was reset, by the peer or by this side.
  Reset { code: Http2ErrorCode, stream_id: U31 },
  /// A WINDOW_UPDATE or a SETTINGS change let queued data of this stream move.
  SendCapacity { stream_id: U31 },
  /// The peer sent GOAWAY.
  GoAway { code: Http2ErrorCode, last_stream_id: U31 },
}

/// The peer's settings that govern what this side sends.
#[derive(Clone, Copy, Debug)]
struct PeerSettings {
  initial_window: i32,
  max_concurrent_streams: u32,
  max_frame_len: u32,
}

/// A HEADERS frame whose block continues in CONTINUATION frames.
#[derive(Clone, Copy, Debug)]
struct PendingBlock {
  continuations: u8,
  end_stream: bool,
  stream_id: u32,
}

/// One connection's protocol state.
#[derive(Debug)]
pub(crate) struct Http2Conn<const IS_CLIENT: bool> {
  /// Bytes of a header block split over CONTINUATION frames.
  block: VectorUsize<u8>,
  conn_recv: i32,
  conn_recv_unacked: u32,
  conn_send: i32,
  events: DequeUsize<ConnEvent>,
  fatal: bool,
  go_away_recv: Option<U31>,
  go_away_sent: bool,
  /// Highest stream id the peer opened.
  highest_peer_id: u32,
  /// The id this side opens its next stream with (client).
  next_local_id: u32,
  hp: HttpRecvParams,
  hpack_dec: HpackDecoder,
  hpack_enc: HpackEncoder,
  out: Output,
  peer: PeerSettings,
  peer_settings_seen: bool,
  pending_block: Option<PendingBlock>,
  /// The server still expects the client's connection preface.
  wants_preface: bool,
  streams: StreamTable,
}

impl<const IS_CLIENT: bool> Http2Conn<IS_CLIENT> {
  /// A connection that has queued its opening bytes: the preface (client), its SETTINGS and a
  /// connection WINDOW_UPDATE up to `hp.initial_window_len()`.
  pub(crate) fn new(hp: HttpRecvParams, rng: &mut impl Rng) -> Self {
    let mut hpack_dec = HpackDecoder::new();
    hpack_dec.set_max_bytes(hp.max_hpack_len().0);
    let mut hpack_enc = HpackEncoder::new(rng);
    hpack_enc.set_max_dyn_super_bytes(hp.max_hpack_len().1);
    let initial = i32::try_from(hp.initial_window_len()).unwrap_or(i32::MAX);
    let mut this = Self {
      block: VectorUsize::new(),
      conn_recv: DEFAULT_WINDOW.max(initial),
      conn_recv_unacked: 0,
      conn_send: DEFAULT_WINDOW,
      events: DequeUsize::new(),
      fatal: false,
      go_away_recv: None,
      go_away_sent: false,
      highest_peer_id: 0,
      next_local_id: 1,
      hp,
      hpack_dec,
      hpack_enc,
      out: Output::new(),
      peer: PeerSettings {
        initial_window: DEFAULT_WINDOW,
        max_concurrent_streams: u32::MAX,
        max_frame_len: DEFAULT_MAX_FRAME_LEN,
      },
      peer_settings_seen: false,
      pending_block: None,
      wants_preface: !IS_CLIENT,
      streams: StreamTable::new(),
    };
    let sf = SettingsFrame::from_hrp(hp);
    let mut sf_buffer = [0; 45];
    let sf_bytes = sf.bytes(&mut sf_buffer);
    let preface: &[u8] = if IS_CLIENT { PREFACE } else { &[] };
    let _rslt = this.out.push_many(&[preface, sf_bytes]);
    if initial > DEFAULT_WINDOW {
      push_window_update(&mut this.out, 0, initial.wrapping_sub(DEFAULT_WINDOW).cast_unsigned());
    }
    this
  }

  /// Parses every complete frame at the start of `input` and returns how many bytes it used.
  /// The caller keeps the rest and feeds it again with what it reads next.
  ///
  /// A connection error queues GOAWAY and returns `Err`; the caller writes the output and
  /// closes.
  pub(crate) fn feed(&mut self, input: &[u8]) -> crate::Result<usize> {
    if self.fatal {
      return Err(protocol_err(Http2Error::UnknownStreamReceiver));
    }
    let mut consumed = 0;
    if self.wants_preface {
      match strip_preface(input) {
        Preface::Incomplete => return Ok(0),
        Preface::Invalid => return self.conn_error(protocol_err(Http2Error::NoPreface)),
        Preface::Done(len) => {
          consumed = len;
          self.wants_preface = false;
        }
      }
    }
    loop {
      let rest = input.get(consumed..).unwrap_or_default();
      match next_frame(rest, self.hp.max_frame_len()) {
        Ok(None) => break,
        Ok(Some((fi, payload, len))) => {
          consumed = consumed.wrapping_add(len);
          if let Err(err) = self.on_frame(fi, payload) {
            return self.conn_error(err);
          }
        }
        Err(err) => return self.conn_error(err),
      }
    }
    if self.conn_recv_unacked > 0 {
      let value = mem::take(&mut self.conn_recv_unacked);
      self.conn_recv = self.conn_recv.saturating_add(value.cast_signed());
      push_window_update(&mut self.out, 0, value);
    }
    Ok(consumed)
  }

  /// The next event, oldest first.
  pub(crate) fn poll_event(&mut self) -> Option<ConnEvent> {
    self.events.pop_front()
  }

  /// The queued bytes, front first.
  pub(crate) fn output<'this>(&'this self, out: &mut ArrayVectorCopy<&'this [u8], 16>) {
    self.out.slices(out);
  }

  /// Marks the first `n` queued bytes as written.
  pub(crate) fn advance_output(&mut self, n: usize) {
    self.out.advance(n);
  }

  /// Whether bytes are queued. Call it before [`Self::output`]: it queues what is still pending
  /// (window updates for released capacity).
  pub(crate) fn has_output(&mut self) -> bool {
    !self.out.is_empty()
  }

  /// Starts a graceful shutdown: GOAWAY with the last stream processed, and every later stream
  /// refused. Streams already open finish.
  pub(crate) fn go_away(&mut self, code: Http2ErrorCode) {
    if !self.go_away_sent {
      self.go_away_sent = true;
      push_go_away(&mut self.out, self.highest_peer_id, code);
    }
  }

  /// Nothing more will happen on this connection: a fatal error, or GOAWAY with no stream left
  /// open. Either way the output has been written.
  pub(crate) fn is_closed(&self) -> bool {
    let ending =
      self.fatal || ((self.go_away_sent || self.go_away_recv.is_some()) && self.streams.len() == 0);
    ending && self.out.is_empty()
  }

  /// Streams open now.
  pub(crate) fn open_streams(&self) -> u32 {
    u32::try_from(self.streams.len()).unwrap_or(u32::MAX)
  }

  /// Ends the sending side of a stream as if a response had been sent, so tests of the receiving
  /// rules can close streams before the sending path exists.
  #[cfg(test)]
  pub(crate) fn close_stream_for_test(&mut self, id: u32) {
    if let Some(stream) = self.streams.get_mut(id) {
      stream.send_closed = true;
      if stream.recv_closed {
        let _ = self.streams.close(id);
      }
    }
  }

  fn conn_error<T>(&mut self, err: crate::Error) -> crate::Result<T> {
    let code = match &err {
      crate::Error::Http2ErrorGoAway(code, _) => *code,
      _ => Http2ErrorCode::InternalError,
    };
    if !self.go_away_sent {
      self.go_away_sent = true;
      push_go_away(&mut self.out, self.highest_peer_id, code);
    }
    self.fatal = true;
    Err(err)
  }

  fn on_frame(&mut self, fi: Option<FrameInit>, payload: &[u8]) -> crate::Result<()> {
    if let Some(block) = self.pending_block {
      let is_continuation =
        fi.is_some_and(|el| el.ty == FrameInitTy::Continuation && el.stream_id.u32() == block.stream_id);
      if !is_continuation {
        return Err(protocol_err(Http2Error::InvalidContinuationFrame));
      }
    }
    let Some(fi) = fi else {
      return Ok(());
    };
    if !self.peer_settings_seen {
      if fi.ty != FrameInitTy::Settings || fi.cf.has_ack() {
        return Err(protocol_err(Http2Error::NoPreface));
      }
      self.peer_settings_seen = true;
    }
    let id = fi.stream_id.u32();
    match fi.ty {
      FrameInitTy::Continuation => self.on_continuation(fi, payload),
      FrameInitTy::Data => self.on_data(fi, payload),
      FrameInitTy::GoAway => self.on_go_away(fi, payload),
      FrameInitTy::Headers => self.on_headers(fi, payload),
      FrameInitTy::Ping => {
        let ping = PingFrame::read(payload, fi)?;
        if !ping.has_ack() {
          let mut ack = ping;
          ack.set_ack();
          self.out.push(&ack.bytes())?;
        }
        Ok(())
      }
      FrameInitTy::Priority => {
        if id == 0 {
          return Err(protocol_err(Http2Error::UnexpectedStreamId));
        }
        if payload.len() != 5 {
          self.stream_error(id, Http2ErrorCode::FrameSizeError);
        }
        Ok(())
      }
      FrameInitTy::PushPromise => Err(protocol_err(Http2Error::PushPromiseIsUnsupported)),
      FrameInitTy::Reset => self.on_reset(id, payload),
      FrameInitTy::Settings => self.on_settings(fi, payload),
      FrameInitTy::WindowUpdate => self.on_window_update(id, payload),
    }
  }

  fn on_continuation(&mut self, fi: FrameInit, payload: &[u8]) -> crate::Result<()> {
    let Some(mut block) = self.pending_block else {
      return Err(protocol_err(Http2Error::InvalidContinuationFrame));
    };
    block.continuations = block.continuations.wrapping_add(1);
    self.block.extend_from_copyable_slice(payload)?;
    if !fi.cf.has_eoh() {
      self.pending_block = Some(block);
      return Ok(());
    }
    self.pending_block = None;
    let bytes = mem::take(&mut self.block);
    let rslt = self.on_header_block(block.stream_id, block.end_stream, &bytes);
    self.block = bytes;
    self.block.clear();
    rslt
  }

  fn on_data(&mut self, fi: FrameInit, payload: &[u8]) -> crate::Result<()> {
    let id = fi.stream_id.u32();
    if id == 0 {
      return Err(protocol_err(Http2Error::InvalidDataFrameZeroId));
    }
    let frame_len = i32::try_from(payload.len()).unwrap_or(i32::MAX);
    self.conn_recv = self.conn_recv.wrapping_sub(frame_len);
    if self.conn_recv < 0 {
      return Err(crate::Error::Http2ErrorGoAway(
        Http2ErrorCode::FlowControlError,
        Http2Error::InvalidWindowUpdateSize,
      ));
    }
    self.conn_recv_unacked = self.conn_recv_unacked.wrapping_add(frame_len.cast_unsigned());
    let mut body = payload;
    let _ = trim_frame_pad(fi.cf, &mut body)?;
    let end_stream = fi.cf.has_eos();
    let Some(stream) = self.streams.get_mut(id) else {
      if self.is_idle(id) {
        return Err(protocol_err(Http2Error::UnknownStreamReceiver));
      }
      push_reset(&mut self.out, id, Http2ErrorCode::StreamClosed);
      return Ok(());
    };
    if stream.recv_closed {
      self.stream_error(id, Http2ErrorCode::StreamClosed);
      return Ok(());
    }
    stream.recv_window = stream.recv_window.wrapping_sub(frame_len);
    if stream.recv_window < 0 {
      self.stream_error(id, Http2ErrorCode::FlowControlError);
      return Ok(());
    }
    stream.msg.body.extend_from_copyable_slice(body)?;
    stream.recv_body_len = stream.recv_body_len.wrapping_add(body.len());
    let over_length = stream.content_length.is_some_and(|el| {
      stream.recv_body_len > el || (end_stream && stream.recv_body_len != el)
    });
    if over_length {
      self.stream_error(id, Http2ErrorCode::ProtocolError);
      return Ok(());
    }
    stream.recv_closed = end_stream;
    self.events.push_back(ConnEvent::Data { end_stream, stream_id: fi.stream_id })?;
    Ok(())
  }

  fn on_go_away(&mut self, fi: FrameInit, payload: &[u8]) -> crate::Result<()> {
    if fi.stream_id.is_not_zero() {
      return Err(protocol_err(Http2Error::InvalidGoAwayFrameNonZeroId));
    }
    let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = payload else {
      return Err(crate::Error::Http2ErrorGoAway(
        Http2ErrorCode::FrameSizeError,
        Http2Error::InvalidGoAwayFrameBytes,
      ));
    };
    let last_stream_id = U31::from_u32(u32::from_be_bytes([*b0, *b1, *b2, *b3]));
    let code = u32::from_be_bytes([*b4, *b5, *b6, *b7])
      .try_into()
      .unwrap_or(Http2ErrorCode::InternalError);
    self.go_away_recv = Some(last_stream_id);
    self.events.push_back(ConnEvent::GoAway { code, last_stream_id })?;
    Ok(())
  }

  fn on_headers(&mut self, fi: FrameInit, payload: &[u8]) -> crate::Result<()> {
    let id = fi.stream_id.u32();
    if id == 0 {
      return Err(protocol_err(Http2Error::InvalidHeadersFrameZeroId));
    }
    let mut fragment = payload;
    let _ = trim_frame_pad(fi.cf, &mut fragment)?;
    if fi.cf.has_pri() {
      let Some(rest) = fragment.get(5..) else {
        return Err(protocol_err(Http2Error::InvalidHeaderFrame));
      };
      fragment = rest;
    }
    let end_stream = fi.cf.has_eos();
    if fi.cf.has_eoh() {
      return self.on_header_block(id, end_stream, fragment);
    }
    self.block.clear();
    self.block.extend_from_copyable_slice(fragment)?;
    self.pending_block = Some(PendingBlock { continuations: 0, end_stream, stream_id: id });
    Ok(())
  }

  fn on_header_block(&mut self, id: u32, end_stream: bool, block: &[u8]) -> crate::Result<()> {
    let mut cf = CommonFlags::empty();
    cf.set_eoh();
    if end_stream {
      cf.set_eos();
    }
    let len = u32::try_from(block.len()).unwrap_or(u32::MAX);
    let fi = FrameInit::new(cf, len, U31::from_u32(id), FrameInitTy::Headers);
    if self.streams.contains(id) {
      return self.on_trailers(fi, block);
    }
    if !IS_CLIENT && (id % 2 == 0 || id <= self.highest_peer_id) {
      if id % 2 == 0 {
        return Err(protocol_err(Http2Error::UnexpectedStreamId));
      }
      return Err(crate::Error::Http2ErrorGoAway(
        Http2ErrorCode::StreamClosed,
        Http2Error::UnexpectedStreamId,
      ));
    }
    self.highest_peer_id = id;
    let refuse = self.go_away_sent
      || u32::try_from(self.streams.len()).unwrap_or(u32::MAX)
        >= self.hp.max_concurrent_streams_num();
    let recv_window = i32::try_from(self.hp.initial_window_len()).unwrap_or(i32::MAX);
    let send_window = self.peer.initial_window;
    let stream = self.streams.open(id, recv_window, send_window)?;
    let rslt = HeadersFrame::read::<IS_CLIENT, false>(
      Some(block),
      fi,
      &self.hp,
      &mut self.hpack_dec,
      (&mut stream.msg, 0),
    );
    let (content_length, hf) = match rslt {
      Ok(elem) => elem,
      Err(err) => {
        if is_malformed(&err) {
          self.stream_error(id, Http2ErrorCode::ProtocolError);
          return Ok(());
        }
        let _ = self.streams.close(id);
        return Err(err);
      }
    };
    if refuse {
      let _ = self.streams.close(id);
      push_reset(&mut self.out, id, Http2ErrorCode::RefusedStream);
      return Ok(());
    }
    stream.content_length = content_length;
    stream.method = hf.hsreqh().method;
    stream.protocol = hf.hsreqh().protocol;
    stream.recv_closed = end_stream;
    stream.recv_headers = true;
    if end_stream && content_length.is_some_and(|el| el != 0) {
      self.stream_error(id, Http2ErrorCode::ProtocolError);
      return Ok(());
    }
    self.events.push_back(ConnEvent::Headers { end_stream, stream_id: U31::from_u32(id) })?;
    Ok(())
  }

  fn on_reset(&mut self, id: u32, payload: &[u8]) -> crate::Result<()> {
    if id == 0 {
      return Err(protocol_err(Http2Error::InvalidResetStreamFrameZeroId));
    }
    let [b0, b1, b2, b3] = payload else {
      return Err(crate::Error::Http2ErrorGoAway(
        Http2ErrorCode::FrameSizeError,
        Http2Error::InvalidResetStreamFrameBytes,
      ));
    };
    if self.is_idle(id) {
      return Err(protocol_err(Http2Error::UnknownStreamReceiver));
    }
    if self.streams.close(id) {
      let code =
        u32::from_be_bytes([*b0, *b1, *b2, *b3]).try_into().unwrap_or(Http2ErrorCode::InternalError);
      self.events.push_back(ConnEvent::Reset { code, stream_id: U31::from_u32(id) })?;
    }
    Ok(())
  }

  fn on_settings(&mut self, fi: FrameInit, payload: &[u8]) -> crate::Result<()> {
    let sf = match SettingsFrame::read(payload, fi) {
      Ok(elem) => elem,
      Err(crate::Error::Http2ErrorGoAway(_, Http2Error::OutOfBoundsWindowSize)) => {
        return Err(crate::Error::Http2ErrorGoAway(
          Http2ErrorCode::FlowControlError,
          Http2Error::OutOfBoundsWindowSize,
        ));
      }
      Err(err) => return Err(err),
    };
    if sf.has_ack() {
      return Ok(());
    }
    if let Some(elem) = sf.header_table_size() {
      let _rslt = self.hpack_enc.set_max_dyn_sub_bytes(elem.min(self.hp.max_hpack_len().1));
    }
    if let Some(elem) = sf.max_frame_size() {
      self.peer.max_frame_len = elem;
    }
    if let Some(elem) = sf.max_concurrent_streams() {
      self.peer.max_concurrent_streams = elem;
    }
    if let Some(elem) = sf.initial_window_size() {
      let delta = elem.i32().wrapping_sub(self.peer.initial_window);
      self.peer.initial_window = elem.i32();
      for stream in self.streams.iter_mut() {
        let Some(window) = stream.send_window.checked_add(delta) else {
          return Err(crate::Error::Http2ErrorGoAway(
            Http2ErrorCode::FlowControlError,
            Http2Error::InvalidWindowUpdateSize,
          ));
        };
        stream.send_window = window;
      }
    }
    let mut ack_buffer = [0; 45];
    self.out.push(SettingsFrame::ack().bytes(&mut ack_buffer))?;
    Ok(())
  }

  fn on_trailers(&mut self, fi: FrameInit, block: &[u8]) -> crate::Result<()> {
    let id = fi.stream_id.u32();
    let Some(stream) = self.streams.get_mut(id) else {
      return Ok(());
    };
    if stream.recv_closed {
      return Err(crate::Error::Http2ErrorGoAway(
        Http2ErrorCode::StreamClosed,
        Http2Error::InvalidReceivedFrameAfterEos,
      ));
    }
    let rslt = HeadersFrame::read::<IS_CLIENT, true>(
      Some(block),
      fi,
      &self.hp,
      &mut self.hpack_dec,
      (&mut stream.msg, 0),
    );
    if let Err(err) = rslt {
      if is_malformed(&err) {
        self.stream_error(id, Http2ErrorCode::ProtocolError);
        return Ok(());
      }
      return Err(err);
    }
    if !fi.cf.has_eos() {
      self.stream_error(id, Http2ErrorCode::ProtocolError);
      return Ok(());
    }
    stream.recv_closed = true;
    if stream.content_length.is_some_and(|el| el != stream.recv_body_len) {
      self.stream_error(id, Http2ErrorCode::ProtocolError);
      return Ok(());
    }
    self.events.push_back(ConnEvent::Trailers { stream_id: fi.stream_id })?;
    Ok(())
  }

  fn on_window_update(&mut self, id: u32, payload: &[u8]) -> crate::Result<()> {
    let [b0, b1, b2, b3] = payload else {
      return Err(crate::Error::Http2ErrorGoAway(
        Http2ErrorCode::FrameSizeError,
        Http2Error::InvalidWindowUpdateFrameBytes,
      ));
    };
    let increment = (u32::from_be_bytes([*b0, *b1, *b2, *b3]) & 0x7FFF_FFFF).cast_signed();
    if id == 0 {
      if increment == 0 {
        return Err(protocol_err(Http2Error::InvalidWindowUpdateZeroIncrement));
      }
      self.conn_send = self.conn_send.checked_add(increment).ok_or(
        crate::Error::Http2ErrorGoAway(
          Http2ErrorCode::FlowControlError,
          Http2Error::InvalidWindowUpdateSize,
        ),
      )?;
      return Ok(());
    }
    if self.is_idle(id) {
      return Err(protocol_err(Http2Error::UnknownStreamReceiver));
    }
    let Some(stream) = self.streams.get_mut(id) else {
      return Ok(());
    };
    if increment == 0 {
      self.stream_error(id, Http2ErrorCode::ProtocolError);
      return Ok(());
    }
    match stream.send_window.checked_add(increment) {
      Some(elem) => stream.send_window = elem,
      None => self.stream_error(id, Http2ErrorCode::FlowControlError),
    }
    Ok(())
  }

  /// A stream this side has not seen yet: above the highest id the peer used (peer-initiated
  /// ids), or one this side never opened.
  fn is_idle(&self, id: u32) -> bool {
    let peer_initiated = (id % 2 == 1) != IS_CLIENT;
    if peer_initiated { id > self.highest_peer_id } else { id >= self.next_local_id }
  }

  /// Resets stream `id` with `code` and reports it.
  fn stream_error(&mut self, id: u32, code: Http2ErrorCode) {
    push_reset(&mut self.out, id, code);
    if self.streams.close(id) {
      let _rslt = self.events.push_back(ConnEvent::Reset { code, stream_id: U31::from_u32(id) });
    }
  }
}

fn push_go_away(out: &mut Output, last_stream_id: u32, code: Http2ErrorCode) {
  let mut frame = [0; 17];
  let fi = FrameInit::new(CommonFlags::empty(), 8, U31::ZERO, FrameInitTy::GoAway);
  frame[..9].copy_from_slice(&fi.bytes());
  frame[9..13].copy_from_slice(&(last_stream_id & 0x7FFF_FFFF).to_be_bytes());
  frame[13..].copy_from_slice(&u32::from(code).to_be_bytes());
  let _rslt = out.push(&frame);
}

fn push_reset(out: &mut Output, id: u32, code: Http2ErrorCode) {
  let mut frame = [0; 13];
  let fi = FrameInit::new(CommonFlags::empty(), 4, U31::from_u32(id), FrameInitTy::Reset);
  frame[..9].copy_from_slice(&fi.bytes());
  frame[9..].copy_from_slice(&u32::from(code).to_be_bytes());
  let _rslt = out.push(&frame);
}

fn push_window_update(out: &mut Output, id: u32, increment: u32) {
  let mut frame = [0; 13];
  let fi = FrameInit::new(CommonFlags::empty(), 4, U31::from_u32(id), FrameInitTy::WindowUpdate);
  frame[..9].copy_from_slice(&fi.bytes());
  frame[9..].copy_from_slice(&(increment & 0x7FFF_FFFF).to_be_bytes());
  let _rslt = out.push(&frame);
}

/// A header block that decoded but describes a malformed message (RFC 9113 §8.1.1): a stream
/// error, unlike a decoding failure, which breaks the connection's HPACK state.
fn is_malformed(err: &crate::Error) -> bool {
  matches!(
    err,
    crate::Error::Http2ErrorGoAway(
      Http2ErrorCode::ProtocolError,
      Http2Error::InvalidHeaderFrame
        | Http2Error::InvalidServerHeader
        | Http2Error::InvalidClientHeader
        | Http2Error::InvalidContentLength
    )
  )
}
