//! A connection's whole protocol state, owned by one value and driven by bytes in and bytes out.
//!
//! [`Http2Conn`] parses every complete frame of the bytes it is fed, updates its state, queues its
//! replies (SETTINGS and PING acknowledgements, window updates, resets, GOAWAY) and reports what
//! happened as [`ConnEvent`]s. It does no I/O and holds no locks: the I/O loops of the server
//! framework and of the client feed it what they read and write what it queued.

pub(crate) mod body;
mod decode_memo;
#[cfg(any(test, feature = "_fuzz"))]
#[doc(hidden)]
pub mod differential;
pub(crate) mod header_cache;
pub(crate) mod output;
pub(crate) mod scan;
pub(crate) mod stream_table;
#[cfg(any(test, feature = "_fuzz"))]
pub(crate) mod test_frames;
#[cfg(test)]
pub(crate) mod tests;

use crate::{
  collections::{ArrayVectorCopy, DequeUsize, VectorUsize},
  http::{
    Header, Headers, HttpRecvParams, Method, MsgBufferString, MsgDataMut as _, Protocol,
    StatusCode, U31,
  },
  http2::{
    Http2Error, Http2ErrorCode,
    common_flags::CommonFlags,
    conn::{
      body::{Body, SharedBytes},
      decode_memo::{DecodeMemo, Decoded},
      header_cache::HeaderCache,
      output::Output,
      scan::{PREFACE, Preface, next_frame, strip_preface},
      stream_table::{SendItem, StreamTable},
    },
    frame_init::{FrameInit, FrameInitTy},
    headers_frame::HeadersFrame,
    hpack_decoder::HpackDecoder,
    hpack_encoder::HpackEncoder,
    hpack_static_headers::{HpackStaticRequestHeaders, HpackStaticResponseHeaders},
    misc::{protocol_err, trim_frame_pad},
    ping_frame::PingFrame,
    settings_frame::SettingsFrame,
  },
  misc::Lease,
  net::Uri,
  rng::Rng,
};
use alloc::vec::Vec;
use core::{mem, time::Duration};

/// The window every stream and the connection start with (RFC 9113 §6.9.2).
const DEFAULT_WINDOW: i32 = 65_535;
const DEFAULT_MAX_FRAME_LEN: u32 = 16_384;
/// The HPACK table size a decoder allows before its SETTINGS say otherwise (RFC 9113 §6.5.2).
const DEFAULT_HEADER_TABLE_SIZE: u32 = 4096;

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

/// The last stream ids this side reset. Late frames on them are ignored for as long as they are
/// remembered, which RFC 9113 §5.1 allows to be limited.
#[derive(Clone, Copy, Debug, Default)]
struct RecentResets {
  ids: [u32; 32],
  next: usize,
}

impl RecentResets {
  fn contains(&self, id: u32) -> bool {
    id != 0 && self.ids.contains(&id)
  }

  fn push(&mut self, id: u32) {
    if let Some(slot) = self.ids.get_mut(self.next) {
      *slot = id;
    }
    self.next = self.next.wrapping_add(1) % self.ids.len();
  }
}

/// Counts events in fixed windows of time.
#[derive(Clone, Copy, Debug, Default)]
struct RateWindow {
  count: u32,
  start: Duration,
}

impl RateWindow {
  /// Counts one event at `now`; true when that makes more than `max` in the current window.
  fn exceeded(&mut self, now: Duration, (max, window): (u32, Duration)) -> bool {
    if now.saturating_sub(self.start) >= window {
      self.start = now;
      self.count = 0;
    }
    self.count = self.count.saturating_add(1);
    self.count > max
  }
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
  /// Streams with queued data that wait for window.
  blocked: DequeUsize<u32>,
  /// Scratch for encoding header blocks.
  header_buf: VectorUsize<u8>,
  header_cache: HeaderCache,
  /// The `content-length` of the last response sent.
  last_content_length: Option<usize>,
  /// Request blocks seen lately (server).
  decode_memo: DecodeMemo,
  /// Streams whose released capacity is not yet announced.
  window_updates: DequeUsize<u32>,
  conn_recv: i32,
  conn_recv_unacked: u32,
  conn_send: i32,
  control_frames: RateWindow,
  events: DequeUsize<ConnEvent>,
  fatal: bool,
  go_away_recv: Option<U31>,
  go_away_sent: bool,
  /// The peer acknowledged our SETTINGS: our initial stream window is in force.
  settings_acked: bool,
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
  /// The time of the bytes being fed.
  now: Duration,
  resets: RateWindow,
  /// Streams this side reset lately, whose late frames are ignored (RFC 9113 §5.1).
  reset_by_us: RecentResets,
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
    hpack_enc.set_initial_dyn_bytes(DEFAULT_HEADER_TABLE_SIZE);
    let initial = i32::try_from(hp.initial_window_len()).unwrap_or(i32::MAX);
    let mut this = Self {
      block: VectorUsize::new(),
      blocked: DequeUsize::new(),
      header_buf: VectorUsize::new(),
      header_cache: HeaderCache::new(),
      last_content_length: None,
      decode_memo: DecodeMemo::new(),
      window_updates: DequeUsize::new(),
      conn_recv: DEFAULT_WINDOW.max(initial),
      conn_recv_unacked: 0,
      conn_send: DEFAULT_WINDOW,
      control_frames: RateWindow::default(),
      events: DequeUsize::new(),
      fatal: false,
      go_away_recv: None,
      go_away_sent: false,
      settings_acked: false,
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
      now: Duration::ZERO,
      resets: RateWindow::default(),
      reset_by_us: RecentResets::default(),
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

  #[cfg(any(test, feature = "_fuzz"))]
  /// Parses every complete frame at the start of `input` and returns how many bytes it used.
  /// The caller keeps the rest and feeds it again with what it reads next.
  ///
  /// A connection error queues GOAWAY and returns `Err`; the caller writes the output and
  /// closes.
  pub(crate) fn feed(&mut self, input: &[u8]) -> crate::Result<usize> {
    self.feed_at(input, crate::calendar::Instant::now_timestamp().unwrap_or_default())
  }

  /// [`Self::feed`] with the time the bytes arrived, which the rate limits count against. Any
  /// clock that only moves forward works.
  pub(crate) fn feed_at(&mut self, input: &[u8], now: Duration) -> crate::Result<usize> {
    self.feed_some_at(input, now, usize::MAX)
  }

  /// [`Self::feed_at`] that stops after the frame which brings the queued events to
  /// `max_events`, so a server can answer a few requests before decoding the next: their stream
  /// slots and buffers are then reused while still in cache. Returns the bytes consumed.
  pub(crate) fn feed_some_at(
    &mut self,
    input: &[u8],
    now: Duration,
    max_events: usize,
  ) -> crate::Result<usize> {
    self.now = self.now.max(now);
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
          if self.events.len() >= max_events && consumed < input.len() {
            // The rest comes in a later call, which announces the window once.
            return Ok(consumed);
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

  /// The queued bytes as one buffer, taken without a copy, when they are a single run of own
  /// bytes; `spare` takes their place. `Err(spare)` otherwise: use [`Self::output`]. Call
  /// [`Self::has_output`] first.
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn take_output(&mut self, spare: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
    self.out.take_bytes(spare)
  }

  /// Undoes [`Self::take_output`] when the bytes could not be handed on; returns the spare.
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn untake_output(&mut self, bytes: Vec<u8>) -> Vec<u8> {
    self.out.untake_bytes(bytes)
  }

  /// A recycled buffer to queue the next output into, used if the output holds none.
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn give_output_buffer(&mut self, buffer: Vec<u8>) {
    self.out.give_buffer(buffer);
  }

  /// The output buffer, when nothing is queued, so an idle connection holds none; see
  /// [`Self::give_output_buffer`].
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn take_idle_output_buffer(&mut self) -> Option<Vec<u8>> {
    self.out.take_idle_buffer()
  }

  /// Whether the output holds a buffer to queue into.
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn has_output_buffer(&self) -> bool {
    self.out.has_buffer()
  }

  /// Marks the first `n` queued bytes as written.
  pub(crate) fn advance_output(&mut self, n: usize) {
    self.out.advance(n);
  }

  /// Whether bytes are queued. Call it before [`Self::output`]: it queues what is still pending
  /// (window updates for released capacity).
  pub(crate) fn has_output(&mut self) -> bool {
    self.flush_window_updates();
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

  /// Nothing more will happen on this connection: a fatal error, or GOAWAY sent (on a client,
  /// sent or received) with no stream left open. Either way the output has been written.
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn is_closed(&self) -> bool {
    // A server keeps reading after the client's GOAWAY until the client closes: closing first
    // with frames unread would make the close a TCP reset.
    let peer_ended = IS_CLIENT && self.go_away_recv.is_some();
    let ending = self.fatal || ((self.go_away_sent || peer_ended) && self.streams.len() == 0);
    ending && self.out.is_empty()
  }

  /// No GOAWAY was sent or received and no connection error happened: new streams may open.
  pub(crate) const fn accepts_streams(&self) -> bool {
    !self.fatal && !self.go_away_sent && self.go_away_recv.is_none()
  }

  /// The peer's first SETTINGS frame arrived.
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) const fn peer_settings_seen(&self) -> bool {
    self.peer_settings_seen
  }

  /// Streams open now.
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn open_streams(&self) -> u32 {
    u32::try_from(self.streams.len()).unwrap_or(u32::MAX)
  }

  /// The message being received on `stream_id`: the request (server) or the response (client).
  pub(crate) fn msg_mut(&mut self, stream_id: U31) -> Option<&mut MsgBufferString> {
    self.streams.get_mut(stream_id.u32()).map(|el| &mut el.msg)
  }

  /// The request method of `stream_id` (server).
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn method(&self, stream_id: U31) -> Option<Method> {
    self.streams.get(stream_id.u32())?.method
  }

  /// Whether the peer ended its side of `stream_id`; `None` when the stream is not open.
  pub(crate) fn recv_closed(&self, stream_id: U31) -> Option<bool> {
    self.streams.get(stream_id.u32()).map(|el| el.recv_closed)
  }

  /// The `:protocol` of `stream_id`, for an extended CONNECT (server).
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn protocol(&self, stream_id: U31) -> Option<Protocol> {
    self.streams.get(stream_id.u32())?.protocol
  }

  /// The response status of `stream_id` (client).
  pub(crate) fn status(&self, stream_id: U31) -> Option<StatusCode> {
    self.streams.get(stream_id.u32())?.status
  }

  /// The application consumed `n` body bytes of `stream_id`: the peer may send that many more.
  /// The WINDOW_UPDATE goes out, coalesced, with the next output.
  pub(crate) fn release_capacity(&mut self, stream_id: U31, n: u32) -> crate::Result<()> {
    let id = stream_id.u32();
    let Some(stream) = self.streams.get_mut(id) else {
      return Ok(());
    };
    if stream.recv_closed || n == 0 {
      return Ok(());
    }
    if stream.recv_unacked == 0 {
      self.window_updates.push_back(id)?;
    }
    stream.recv_unacked = stream.recv_unacked.saturating_add(n);
    Ok(())
  }

  /// Bytes of output waiting to be written that the connection holds itself (not those sent by
  /// reference).
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn owned_output_len(&self) -> usize {
    self.out.owned_len()
  }

  /// Whether `stream_id` is open.
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn has_stream(&self, stream_id: U31) -> bool {
    self.streams.get(stream_id.u32()).is_some()
  }

  /// Closes every stream without a frame or an event: the connection is gone, and handlers still
  /// holding a stream then see it closed.
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn close_all_streams(&mut self) {
    let ids: Vec<u32> = self.streams.iter().map(|el| el.id).collect();
    for id in ids {
      let _ = self.streams.close(id);
    }
  }

  /// `n` bytes of the body of `stream_id` were taken by its handler: they no longer count against
  /// `max_body_len` and `max_conn_buffered_len`, which bound what streams hold.
  pub(crate) fn consume_body(&mut self, stream_id: U31, n: usize) {
    let Some(stream) = self.streams.get_mut(stream_id.u32()) else {
      return;
    };
    let n = n.min(stream.recv_held);
    stream.recv_held = stream.recv_held.wrapping_sub(n);
    self.streams.sub_buffered(n);
  }

  /// Queues HEADERS for `stream_id`: `:status` (server) and `headers`.
  pub(crate) fn send_headers(
    &mut self,
    stream_id: U31,
    status: Option<StatusCode>,
    headers: &Headers,
    end_stream: bool,
  ) -> crate::Result<()> {
    let id = stream_id.u32();
    let Self { header_buf, hpack_enc, out, peer, streams, .. } = self;
    let stream = streams.get_mut(id).ok_or(protocol_err(Http2Error::UnknownStreamReceiver))?;
    if stream.send_headers || stream.send_closed {
      return Err(protocol_err(Http2Error::InvalidSendStreamState));
    }
    stream.send_headers = true;
    header_buf.clear();
    let hsresph = HpackStaticResponseHeaders { status_code: status };
    let hint = hsresph.bytes_len().wrapping_add(headers.bytes_len());
    hpack_enc.encode(header_buf, hint, hsresph.iter(), headers.iter())?;
    push_header_block(out, id, header_buf, end_stream, peer.max_frame_len)?;
    if end_stream {
      stream.send_closed = true;
      self.after_send_closed(id);
    }
    Ok(())
  }

  /// Queues `body` on `stream_id` and sends as much of it as the windows allow; the rest goes out
  /// as WINDOW_UPDATEs arrive. With `end_stream`, END_STREAM follows the last byte.
  pub(crate) fn send_data(
    &mut self,
    stream_id: U31,
    body: Body<'_>,
    end_stream: bool,
  ) -> crate::Result<()> {
    let id = stream_id.u32();
    // Shared bytes don't count toward the send queue: their memory is their owner's, whatever
    // the number of streams that send them.
    let owned_len = match &body {
      Body::Borrowed(elem) => elem.len(),
      Body::Shared(_) => 0,
    };
    self.check_send_queue(owned_len)?;
    let stream = self.streams.get_mut(id).ok_or(protocol_err(Http2Error::UnknownStreamReceiver))?;
    if stream.send_closed || stream.end_after_queue {
      return Err(protocol_err(Http2Error::InvalidSendStreamState));
    }
    if let Body::Borrowed(bytes) = &body
      && self.send_now(id, bytes, end_stream)?
    {
      return Ok(());
    }
    self.streams.add_queued(owned_len);
    let Some(stream) = self.streams.get_mut(id) else {
      return Ok(());
    };
    match body {
      Body::Borrowed(bytes) => {
        if !bytes.is_empty() {
          stream.owned.extend_from_copyable_slice(bytes)?;
          stream.send_queue.push_back(SendItem::Owned(bytes.len()))?;
        }
      }
      Body::Shared(bytes) => {
        if !bytes.is_empty() {
          stream.send_queue.push_back(SendItem::Shared(bytes))?;
        }
      }
    }
    stream.end_after_queue = end_stream;
    let _ = self.flush_stream(id)?;
    Ok(())
  }

  /// The common case of [`Self::send_data`]: nothing is queued on the stream and the windows take
  /// all of `bytes`, so its DATA frames go straight to the output without a copy into the
  /// stream's queue. Returns whether it did.
  fn send_now(&mut self, id: u32, bytes: &[u8], end_stream: bool) -> crate::Result<bool> {
    let Self { conn_send, out, peer, streams, .. } = self;
    let Some(stream) = streams.get_mut(id) else {
      return Ok(false);
    };
    let len = i32::try_from(bytes.len()).unwrap_or(i32::MAX);
    let fits = (*conn_send).min(stream.send_window) >= len;
    if !fits || bytes.is_empty() || stream.send_queue.len() > 0 || stream.trailers.is_some() {
      return Ok(false);
    }
    let max_frame_len = usize::try_from(peer.max_frame_len).unwrap_or(usize::MAX).max(1);
    let mut chunks = bytes.chunks(max_frame_len).peekable();
    while let Some(chunk) = chunks.next() {
      let mut cf = CommonFlags::empty();
      if end_stream && chunks.peek().is_none() {
        cf.set_eos();
      }
      let frame_len = u32::try_from(chunk.len()).unwrap_or(u32::MAX);
      let fi = FrameInit::new(cf, frame_len, U31::from_u32(id), FrameInitTy::Data);
      out.push_many(&[&fi.bytes(), chunk])?;
    }
    *conn_send = conn_send.wrapping_sub(len);
    stream.send_window = stream.send_window.wrapping_sub(len);
    if end_stream {
      stream.send_closed = true;
      self.after_send_closed(id);
    }
    Ok(true)
  }

  /// Sends `trailers`, which end the stream, after the queued body.
  pub(crate) fn send_trailers(&mut self, stream_id: U31, trailers: &Headers) -> crate::Result<()> {
    let id = stream_id.u32();
    let stream = self.streams.get_mut(id).ok_or(protocol_err(Http2Error::UnknownStreamReceiver))?;
    if stream.send_closed || stream.end_after_queue {
      return Err(protocol_err(Http2Error::InvalidSendStreamState));
    }
    let mut copy = Headers::new();
    for header in trailers.iter() {
      copy.push_from_iter(Header::new(
        header.is_sensitive,
        header.is_trailer,
        header.name,
        [header.value],
      ))?;
    }
    stream.trailers = Some(copy);
    stream.end_after_queue = true;
    let _ = self.flush_stream(id)?;
    Ok(())
  }

  /// Resets `stream_id` with `code`. No event is reported: the caller knows.
  pub(crate) fn send_reset(&mut self, stream_id: U31, code: Http2ErrorCode) {
    let id = stream_id.u32();
    if self.streams.close(id) {
      self.push_stream_reset(id, code);
    }
  }

  /// A whole response: HEADERS with `:status`, the headers of `msg` and `content-length`, then
  /// `msg.body` (as the windows allow). `msg` is cleared for reuse.
  pub(crate) fn send_response(
    &mut self,
    stream_id: U31,
    status: StatusCode,
    msg: &mut MsgBufferString,
  ) -> crate::Result<()> {
    self.send_whole_response(stream_id, status, msg, None)
  }

  /// [`Self::send_response`] with `body`, sent by reference, in place of `msg.body`.
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn send_response_shared(
    &mut self,
    stream_id: U31,
    status: StatusCode,
    msg: &mut MsgBufferString,
    body: SharedBytes,
  ) -> crate::Result<()> {
    self.send_whole_response(stream_id, status, msg, Some(body))
  }

  fn send_whole_response(
    &mut self,
    stream_id: U31,
    status: StatusCode,
    msg: &mut MsgBufferString,
    shared: Option<SharedBytes>,
  ) -> crate::Result<()> {
    let id = stream_id.u32();
    let body_len = shared.as_ref().map_or(msg.body.len(), SharedBytes::len);
    if shared.is_none() {
      self.check_send_queue(body_len)?;
    }
    {
      let Self { header_buf, header_cache, hpack_enc, last_content_length, out, peer, streams, .. } =
        self;
      let stream = streams.get_mut(id).ok_or(protocol_err(Http2Error::UnknownStreamReceiver))?;
      if stream.send_headers || stream.send_closed {
        return Err(protocol_err(Http2Error::InvalidSendStreamState));
      }
      stream.send_headers = true;
      header_buf.clear();
      let generation = hpack_enc.generation();
      if let Some(block) = header_cache.get(status, &msg.headers, generation)? {
        header_buf.extend_from_copyable_slice(block)?;
      } else {
        let hsresph = HpackStaticResponseHeaders { status_code: Some(status) };
        let hint = hsresph.bytes_len().wrapping_add(msg.headers.bytes_len());
        let fields = msg.headers.iter().filter(HeaderCache::is_cached_field);
        hpack_enc.encode(header_buf, hint, hsresph.iter(), fields)?;
        if hpack_enc.generation() == generation {
          header_cache.insert(status, header_buf, generation)?;
        }
      }
      let rest = msg.headers.iter().filter(|el| !HeaderCache::is_cached_field(el));
      hpack_enc.encode(header_buf, 0, [], rest)?;
      let repeat = *last_content_length == Some(body_len);
      *last_content_length = Some(body_len);
      push_content_length(hpack_enc, header_buf, body_len, repeat)?;
      push_header_block(out, id, header_buf, body_len == 0, peer.max_frame_len)?;
      if body_len == 0 {
        stream.send_closed = true;
      }
    }
    if body_len == 0 {
      self.after_send_closed(id);
    } else if let Some(elem) = shared {
      self.send_data(stream_id, Body::Shared(elem), true)?;
    } else {
      self.send_data(stream_id, Body::Borrowed(&msg.body), true)?;
    }
    msg.clear();
    Ok(())
  }

  /// Body bytes of `stream_id` queued and not yet sent.
  pub(crate) fn stream_send_pending(&self, stream_id: U31) -> u32 {
    self
      .streams
      .get(stream_id.u32())
      .map_or(0, |el| u32::try_from(el.send_pending()).unwrap_or(u32::MAX))
  }

  /// Sends what the windows allow of the queue of `id`; reports whether anything moved.
  fn flush_stream(&mut self, id: u32) -> crate::Result<bool> {
    let Self { blocked, conn_send, header_buf, hpack_enc, out, peer, streams, .. } = self;
    // Ids of streams that closed while waiting are only dropped when the window opens: keep them
    // from piling up on a connection whose window never does.
    if blocked.len() >= streams.len().saturating_mul(2).max(16) {
      for _ in 0..blocked.len() {
        if let Some(elem) = blocked.pop_front()
          && streams.get(elem).is_some_and(|el| el.blocked)
        {
          blocked.push_back(elem)?;
        }
      }
    }
    let Some(stream) = streams.get_mut(id) else {
      return Ok(false);
    };
    let max_frame_len = i32::try_from(peer.max_frame_len).unwrap_or(i32::MAX);
    let mut progressed = false;
    let mut queued_sent: usize = 0;
    while let Some(item) = stream.send_queue.get(0) {
      let remaining = item.len().wrapping_sub(stream.front_sent);
      let avail = (*conn_send).min(stream.send_window).min(max_frame_len);
      if avail <= 0 {
        if !stream.blocked {
          stream.blocked = true;
          blocked.push_back(id)?;
        }
        break;
      }
      let n = remaining.min(usize::try_from(avail).unwrap_or(0));
      let is_last = stream.send_queue.len() == 1 && n == remaining;
      let eos = is_last && stream.end_after_queue && stream.trailers.is_none();
      let mut cf = CommonFlags::empty();
      if eos {
        cf.set_eos();
      }
      let len = u32::try_from(n).unwrap_or(u32::MAX);
      let fi = FrameInit::new(cf, len, U31::from_u32(id), FrameInitTy::Data);
      match item {
        SendItem::Owned(_) => {
          let start = stream.owned_read;
          let bytes = stream.owned.get(start..start.wrapping_add(n)).unwrap_or_default();
          out.push_many(&[&fi.bytes(), bytes])?;
          stream.owned_read = start.wrapping_add(n);
          queued_sent = queued_sent.wrapping_add(n);
        }
        SendItem::Shared(elem) => {
          let part = elem.slice(stream.front_sent, stream.front_sent.wrapping_add(n));
          out.push(&fi.bytes())?;
          out.push_shared(part)?;
        }
      }
      let signed = i32::try_from(n).unwrap_or(i32::MAX);
      *conn_send = conn_send.wrapping_sub(signed);
      stream.send_window = stream.send_window.wrapping_sub(signed);
      progressed = true;
      if n == remaining {
        let _ = stream.send_queue.pop_front();
        stream.front_sent = 0;
      } else {
        stream.front_sent = stream.front_sent.wrapping_add(n);
      }
      if eos {
        stream.send_closed = true;
      }
    }
    if stream.send_queue.len() == 0 {
      stream.owned.clear();
      stream.owned_read = 0;
      if stream.end_after_queue && !stream.send_closed {
        if let Some(trailers) = stream.trailers.take() {
          header_buf.clear();
          hpack_enc.encode(header_buf, trailers.bytes_len(), [], trailers.iter())?;
          push_header_block(out, id, header_buf, true, peer.max_frame_len)?;
        } else {
          let mut cf = CommonFlags::empty();
          cf.set_eos();
          out.push(&FrameInit::new(cf, 0, U31::from_u32(id), FrameInitTy::Data).bytes())?;
        }
        stream.send_closed = true;
        progressed = true;
      }
    }
    let send_closed = stream.send_closed;
    self.streams.sub_queued(queued_sent);
    if send_closed {
      self.after_send_closed(id);
    }
    Ok(progressed)
  }

  /// Counts a PING, SETTINGS or empty frame against the control-frame budget.
  fn count_control_frame(&mut self) -> crate::Result<()> {
    if self.control_frames.exceeded(self.now, self.hp.max_control_frames_per_window()) {
      return Err(crate::Error::Http2ErrorGoAway(
        Http2ErrorCode::EnhanceYourCalm,
        Http2Error::TooManyControlFrames,
      ));
    }
    Ok(())
  }

  /// Fails when `additional` more bytes would put the output over `max_send_queue_len`.
  /// Ends the connection, GOAWAY included, when `additional` more bytes would put more than
  /// `max_send_queue_len` in the core.
  fn check_send_queue(&mut self, additional: usize) -> crate::Result<()> {
    let max = usize::try_from(self.hp.max_send_queue_len()).unwrap_or(usize::MAX);
    let total =
      self.out.owned_len().saturating_add(self.streams.queued()).saturating_add(additional);
    if total > max {
      return self.conn_error(crate::Error::Http2ErrorGoAway(
        Http2ErrorCode::EnhanceYourCalm,
        Http2Error::SendQueueFull,
      ));
    }
    Ok(())
  }

  /// Retries every stream that waits for window, reporting those that moved.
  fn flush_blocked(&mut self) -> crate::Result<()> {
    let mut left = self.blocked.len();
    while left > 0 {
      left = left.wrapping_sub(1);
      let Some(id) = self.blocked.pop_front() else {
        break;
      };
      if let Some(stream) = self.streams.get_mut(id) {
        stream.blocked = false;
      }
      if self.flush_stream(id)? {
        self.events.push_back(ConnEvent::SendCapacity { stream_id: U31::from_u32(id) })?;
      }
    }
    Ok(())
  }

  /// The sending side of `id` ended: close the stream if the receiving side has too. A server
  /// that answered before the request ended tells the client to stop sending (RFC 9113 §8.1).
  fn after_send_closed(&mut self, id: u32) {
    let Some(stream) = self.streams.get(id) else {
      return;
    };
    if IS_CLIENT {
      // The handle still reads the response; it finishes the stream (`finish_stream`).
    } else if stream.recv_closed {
      let _ = self.streams.close(id);
    } else {
      let _ = self.streams.close(id);
      self.push_stream_reset(id, Http2ErrorCode::NoError);
    }
  }

  fn flush_window_updates(&mut self) {
    while let Some(id) = self.window_updates.pop_front() {
      let Some(stream) = self.streams.get_mut(id) else {
        continue;
      };
      let n = mem::take(&mut stream.recv_unacked);
      if n == 0 || stream.recv_closed {
        continue;
      }
      stream.recv_window = stream.recv_window.saturating_add(n.cast_signed());
      push_window_update(&mut self.out, id, n);
    }
  }

  /// The HPACK encoder's generation, which changes with its dynamic table.
  #[cfg(test)]
  pub(crate) const fn hpack_generation(&self) -> u64 {
    self.hpack_enc.generation()
  }

  /// Ids in the queue of streams waiting for window.
  #[cfg(test)]
  pub(crate) fn blocked_len(&self) -> usize {
    self.blocked.len()
  }

  /// Stream slots allocated so far, open or free.
  #[cfg(test)]
  pub(crate) fn stream_slots(&self) -> usize {
    self.streams.slots_len()
  }

  /// Request header blocks replayed from the decode memo.
  #[cfg(test)]
  pub(crate) const fn decode_memo_hits(&self) -> u64 {
    self.decode_memo.hits()
  }

  /// Responses whose header block came from the cache.
  #[cfg(test)]
  pub(crate) const fn header_cache_hits(&self) -> u64 {
    self.header_cache.hits()
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
      let is_continuation = fi.is_some_and(|el| {
        el.ty == FrameInitTy::Continuation && el.stream_id.u32() == block.stream_id
      });
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
          self.count_control_frame()?;
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
          self.stream_error(id, Http2ErrorCode::FrameSizeError)?;
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
    if block.continuations > self.hp.max_continuations() {
      return Err(crate::Error::Http2ErrorGoAway(
        Http2ErrorCode::EnhanceYourCalm,
        Http2Error::TooManyContinuations,
      ));
    }
    self.check_block_len(self.block.len().wrapping_add(payload.len()))?;
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
    if payload.is_empty() && !end_stream {
      self.count_control_frame()?;
    }
    let Some(stream) = self.streams.get_mut(id) else {
      if self.is_idle(id) {
        return Err(protocol_err(Http2Error::UnknownStreamReceiver));
      }
      // Sent before our reset reached the peer: ignored, its bytes handed back to the connection
      // window like any others.
      if !self.reset_by_us.contains(id) {
        self.push_stream_reset(id, Http2ErrorCode::StreamClosed);
      }
      return Ok(());
    };
    if stream.recv_closed {
      self.stream_error(id, Http2ErrorCode::StreamClosed)?;
      return Ok(());
    }
    stream.recv_window = stream.recv_window.wrapping_sub(frame_len);
    if stream.recv_window < 0 {
      self.stream_error(id, Http2ErrorCode::FlowControlError)?;
      return Ok(());
    }
    let max_body_len = usize::try_from(self.hp.max_body_len()).unwrap_or(usize::MAX);
    if stream.recv_held.saturating_add(body.len()) > max_body_len {
      self.stream_error(id, Http2ErrorCode::Cancel)?;
      return Ok(());
    }
    let max_buffered = usize::try_from(self.hp.max_conn_buffered_len()).unwrap_or(usize::MAX);
    if self.streams.buffered().saturating_add(body.len()) > max_buffered {
      self.stream_error(id, Http2ErrorCode::RefusedStream)?;
      return Ok(());
    }
    let Some(stream) = self.streams.get_mut(id) else {
      return Ok(());
    };
    stream.msg.body.extend_from_copyable_slice(body)?;
    stream.recv_body_len = stream.recv_body_len.wrapping_add(body.len());
    stream.recv_held = stream.recv_held.wrapping_add(body.len());
    self.streams.add_buffered(body.len());
    let Some(stream) = self.streams.get_mut(id) else {
      return Ok(());
    };
    let over_length = stream
      .content_length
      .is_some_and(|el| stream.recv_body_len > el || (end_stream && stream.recv_body_len != el));
    if over_length {
      self.stream_error(id, Http2ErrorCode::ProtocolError)?;
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
    let code =
      u32::from_be_bytes([*b4, *b5, *b6, *b7]).try_into().unwrap_or(Http2ErrorCode::InternalError);
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
    if fragment.is_empty() && fi.cf.has_eoh() && !end_stream {
      self.count_control_frame()?;
    }
    if fi.cf.has_eoh() {
      return self.on_header_block(id, end_stream, fragment);
    }
    self.check_block_len(fragment.len())?;
    self.block.clear();
    self.block.extend_from_copyable_slice(fragment)?;
    self.pending_block = Some(PendingBlock { continuations: 0, end_stream, stream_id: id });
    Ok(())
  }

  /// A header block split over frames is buffered only up to `max_headers_len`: an HPACK block is
  /// never larger than the header list it decodes to, so a bigger one could only be refused after
  /// buffering it whole. It ends the connection: dropping it unread would leave HPACK out of sync.
  /// A new stream's receive window: ours, but no less than the default until the peer
  /// acknowledged our SETTINGS, as it may send under the default until then (RFC 9113 §6.9.2).
  fn initial_recv_window(&self) -> i32 {
    let ours = i32::try_from(self.hp.initial_window_len()).unwrap_or(i32::MAX);
    if self.settings_acked { ours } else { ours.max(DEFAULT_WINDOW) }
  }

  fn check_block_len(&self, len: usize) -> crate::Result<()> {
    if len > usize::try_from(self.hp.max_headers_len()).unwrap_or(usize::MAX) {
      return Err(crate::Error::Http2ErrorGoAway(
        Http2ErrorCode::EnhanceYourCalm,
        Http2Error::VeryLargeHeadersLen,
      ));
    }
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
    if let Some(stream) = self.streams.get(id) {
      if IS_CLIENT && !stream.recv_headers {
        return self.on_response_headers(fi, block);
      }
      return self.on_trailers(fi, block);
    }
    if IS_CLIENT {
      if id % 2 == 1 && id < self.next_local_id {
        return Err(crate::Error::Http2ErrorGoAway(
          Http2ErrorCode::StreamClosed,
          Http2Error::UnexpectedStreamId,
        ));
      }
      return Err(protocol_err(Http2Error::UnexpectedStreamId));
    }
    if !IS_CLIENT && (id.is_multiple_of(2) || id <= self.highest_peer_id) {
      if id.is_multiple_of(2) {
        return Err(protocol_err(Http2Error::UnexpectedStreamId));
      }
      if self.reset_by_us.contains(id) {
        return self.discard_header_block(fi, block);
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
    let recv_window = self.initial_recv_window();
    let send_window = self.peer.initial_window;
    let stream = self.streams.open(id, recv_window, send_window)?;
    let generation = self.hpack_dec.generation();
    let (decoded, over_size) =
      if let Some(elem) = self.decode_memo.replay(block, generation, &mut stream.msg)? {
        (elem, false)
      } else {
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
              self.stream_error(id, Http2ErrorCode::ProtocolError)?;
              return Ok(());
            }
            let _ = self.streams.close(id);
            return Err(err);
          }
        };
        let decoded =
          Decoded { content_length, method: hf.hsreqh().method, protocol: hf.hsreqh().protocol };
        // A block that left the table as it was decodes the same way while it stays so.
        if !hf.is_over_size() && self.hpack_dec.generation() == generation {
          self.decode_memo.insert(block, generation, &stream.msg, decoded)?;
        }
        (decoded, hf.is_over_size())
      };
    if refuse {
      let _ = self.streams.close(id);
      self.push_stream_reset(id, Http2ErrorCode::RefusedStream);
      return Ok(());
    }
    let content_length = decoded.content_length;
    stream.content_length = content_length;
    stream.method = decoded.method;
    stream.protocol = decoded.protocol;
    stream.recv_closed = end_stream;
    stream.recv_headers = true;
    if over_size {
      // The fields were decoded, so the HPACK state is intact: answer instead of resetting.
      stream.msg.clear();
      let status = Some(StatusCode::RequestHeaderFieldsTooLarge);
      return self.send_headers(U31::from_u32(id), status, &Headers::new(), true);
    }
    if end_stream && content_length.is_some_and(|el| el != 0) {
      self.stream_error(id, Http2ErrorCode::ProtocolError)?;
      return Ok(());
    }
    let max_body_len = usize::try_from(self.hp.max_body_len()).unwrap_or(usize::MAX);
    if content_length.is_some_and(|el| el > max_body_len) {
      // Refused before any of the body arrives; the reset that follows the answer stops it.
      stream.msg.clear();
      let status = Some(StatusCode::PayloadTooLarge);
      return self.send_headers(U31::from_u32(id), status, &Headers::new(), true);
    }
    self.events.push_back(ConnEvent::Headers { end_stream, stream_id: U31::from_u32(id) })?;
    Ok(())
  }

  fn on_response_headers(&mut self, fi: FrameInit, block: &[u8]) -> crate::Result<()> {
    let id = fi.stream_id.u32();
    let end_stream = fi.cf.has_eos();
    let Some(stream) = self.streams.get_mut(id) else {
      return Ok(());
    };
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
          self.stream_error(id, Http2ErrorCode::ProtocolError)?;
          return Ok(());
        }
        return Err(err);
      }
    };
    let status = hf.hsresh().status_code;
    // An informational (1xx) response comes before the final one.
    if status.is_some_and(|el| u16::from(el) < 200) {
      stream.msg.headers.clear();
      return Ok(());
    }
    stream.content_length = content_length;
    stream.status = status;
    stream.recv_closed = end_stream;
    stream.recv_headers = true;
    // The stream stays open until the caller has read the response.
    self.events.push_back(ConnEvent::Headers { end_stream, stream_id: fi.stream_id })?;
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
    if self.resets.exceeded(self.now, self.hp.max_resets_per_window()) {
      return Err(crate::Error::Http2ErrorGoAway(
        Http2ErrorCode::EnhanceYourCalm,
        Http2Error::TooManyResets,
      ));
    }
    if self.streams.close(id) {
      let code = u32::from_be_bytes([*b0, *b1, *b2, *b3])
        .try_into()
        .unwrap_or(Http2ErrorCode::InternalError);
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
      if !self.settings_acked {
        self.settings_acked = true;
        // Streams opened before took the default window; the peer now counts against ours.
        let ours = i32::try_from(self.hp.initial_window_len()).unwrap_or(i32::MAX);
        let delta = ours.wrapping_sub(ours.max(DEFAULT_WINDOW));
        if delta != 0 {
          for stream in self.streams.iter_mut() {
            stream.recv_window = stream.recv_window.saturating_add(delta);
          }
        }
      }
      return Ok(());
    }
    self.count_control_frame()?;
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
      if delta > 0 {
        self.flush_blocked()?;
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
        self.stream_error(id, Http2ErrorCode::ProtocolError)?;
        return Ok(());
      }
      return Err(err);
    }
    if !fi.cf.has_eos() {
      self.stream_error(id, Http2ErrorCode::ProtocolError)?;
      return Ok(());
    }
    stream.recv_closed = true;
    if stream.content_length.is_some_and(|el| el != stream.recv_body_len) {
      self.stream_error(id, Http2ErrorCode::ProtocolError)?;
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
      self.conn_send =
        self.conn_send.checked_add(increment).ok_or(crate::Error::Http2ErrorGoAway(
          Http2ErrorCode::FlowControlError,
          Http2Error::InvalidWindowUpdateSize,
        ))?;
      return self.flush_blocked();
    }
    if self.is_idle(id) {
      return Err(protocol_err(Http2Error::UnknownStreamReceiver));
    }
    let Some(stream) = self.streams.get_mut(id) else {
      return Ok(());
    };
    if increment == 0 {
      self.stream_error(id, Http2ErrorCode::ProtocolError)?;
      return Ok(());
    }
    match stream.send_window.checked_add(increment) {
      Some(elem) => stream.send_window = elem,
      None => {
        self.stream_error(id, Http2ErrorCode::FlowControlError)?;
        return Ok(());
      }
    }
    if self.flush_stream(id)? {
      self.events.push_back(ConnEvent::SendCapacity { stream_id: U31::from_u32(id) })?;
    }
    Ok(())
  }

  /// A stream this side has not seen yet: above the highest id the peer used (peer-initiated
  /// ids), or one this side never opened.
  fn is_idle(&self, id: u32) -> bool {
    let peer_initiated = (id % 2 == 1) != IS_CLIENT;
    if peer_initiated { id > self.highest_peer_id } else { id >= self.next_local_id }
  }

  /// Decodes a header block that arrived on a stream this side reset, for the HPACK state it
  /// changes, and drops it.
  fn discard_header_block(&mut self, fi: FrameInit, block: &[u8]) -> crate::Result<()> {
    let mut scratch = MsgBufferString::default();
    let rslt = HeadersFrame::read::<IS_CLIENT, true>(
      Some(block),
      fi,
      &self.hp,
      &mut self.hpack_dec,
      (&mut scratch, 0),
    );
    match rslt {
      Err(err) if !is_malformed(&err) => Err(err),
      _ => Ok(()),
    }
  }

  /// Queues RST_STREAM for `id` and remembers it, so that the peer's frames already on the way
  /// are ignored.
  fn push_stream_reset(&mut self, id: u32, code: Http2ErrorCode) {
    push_reset(&mut self.out, id, code);
    self.reset_by_us.push(id);
  }

  /// Resets stream `id` with `code` and reports it.
  /// Resets `id` for something the peer did wrong. These count against the same budget as the
  /// peer's own resets: provoking resets is as cheap as sending them (CVE-2025-8671).
  fn stream_error(&mut self, id: u32, code: Http2ErrorCode) -> crate::Result<()> {
    self.push_stream_reset(id, code);
    if self.streams.close(id) {
      let _rslt = self.events.push_back(ConnEvent::Reset { code, stream_id: U31::from_u32(id) });
    }
    if self.resets.exceeded(self.now, self.hp.max_resets_per_window()) {
      return Err(crate::Error::Http2ErrorGoAway(
        Http2ErrorCode::EnhanceYourCalm,
        Http2Error::TooManyResets,
      ));
    }
    Ok(())
  }
}

impl Http2Conn<true> {
  /// Opens the next client stream. Fails when the server's limit on concurrent streams is reached
  /// or it sent GOAWAY.
  pub(crate) fn open_stream(&mut self) -> crate::Result<U31> {
    if self.go_away_recv.is_some() || self.fatal {
      return Err(protocol_err(Http2Error::UnknownStreamReceiver));
    }
    if !self.can_open_stream(0) {
      return Err(protocol_err(Http2Error::ExceedAmountOfActiveConcurrentStreams));
    }
    let id = self.next_local_id;
    self.next_local_id = id.wrapping_add(2);
    let recv_window = self.initial_recv_window();
    let send_window = self.peer.initial_window;
    let _ = self.streams.open(id, recv_window, send_window)?;
    Ok(U31::from_u32(id))
  }

  /// Queues the request HEADERS of `stream_id` (method, the URI of `msg`, its headers), then its
  /// body, if any. With `end_stream` the request ends after that.
  #[cfg(test)]
  pub(crate) fn send_request<S>(
    &mut self,
    stream_id: U31,
    method: Method,
    msg: &crate::http::MsgBuffer<S>,
    end_stream: bool,
  ) -> crate::Result<()>
  where
    S: Lease<str>,
  {
    let body = msg.body.as_slice();
    self.send_request_head(
      stream_id,
      method,
      &msg.uri,
      &msg.headers,
      end_stream && body.is_empty(),
    )?;
    if !body.is_empty() {
      self.send_data(stream_id, Body::Borrowed(body), end_stream)?;
    }
    Ok(())
  }

  /// Queues the request HEADERS of `stream_id`: `method`, the pseudo-headers of `uri` and
  /// `headers`. With `end_stream` the request has no body.
  pub(crate) fn send_request_head<S>(
    &mut self,
    stream_id: U31,
    method: Method,
    uri: &Uri<S>,
    headers: &Headers,
    end_stream: bool,
  ) -> crate::Result<()>
  where
    S: Lease<str>,
  {
    let id = stream_id.u32();
    let Self { header_buf, hpack_enc, out, peer, streams, .. } = self;
    let stream = streams.get_mut(id).ok_or(protocol_err(Http2Error::UnknownStreamReceiver))?;
    if stream.send_headers {
      return Err(protocol_err(Http2Error::InvalidSendStreamState));
    }
    stream.send_headers = true;
    let hsreqh = HpackStaticRequestHeaders {
      authority: uri.authority(),
      method: Some(method),
      path: uri.relative_reference_slash(),
      protocol: None,
      scheme: uri.scheme(),
    };
    header_buf.clear();
    let hint = hsreqh.bytes_len().wrapping_add(headers.bytes_len());
    hpack_enc.encode(header_buf, hint, hsreqh.iter(), headers.iter())?;
    push_header_block(out, id, header_buf, end_stream, peer.max_frame_len)?;
    if end_stream {
      stream.send_closed = true;
    }
    Ok(())
  }

  /// Streams that have not ended in both directions: those the server counts against its
  /// limit.
  pub(crate) fn active_streams(&self) -> u32 {
    let ids = self.streams.iter().filter(|el| !(el.recv_closed && el.send_closed)).count();
    u32::try_from(ids).unwrap_or(u32::MAX)
  }

  /// Whether a stream can open now, beside `reserved` more that will: the server's SETTINGS
  /// arrived, it did not send GOAWAY and its limit on concurrent streams leaves room.
  pub(crate) fn can_open_stream(&self, reserved: u32) -> bool {
    self.peer_settings_seen
      && self.go_away_recv.is_none()
      && !self.fatal
      && self.active_streams().saturating_add(reserved) < self.peer.max_concurrent_streams
  }

  /// The handle of `stream_id` is done with it: its slot is freed. With `reset`, a stream that
  /// has not ended in both directions is reset with CANCEL; without, it is dropped silently
  /// (streams the server's GOAWAY did not process).
  pub(crate) fn finish_stream(&mut self, stream_id: U31, reset: bool) {
    let id = stream_id.u32();
    let Some(stream) = self.streams.get(id) else {
      return;
    };
    let ended = stream.recv_closed && stream.send_closed;
    if self.streams.close(id) && reset && !ended {
      self.push_stream_reset(id, Http2ErrorCode::Cancel);
    }
  }
}

/// A header block as HEADERS plus as many CONTINUATIONs as `max_frame_len` requires.
fn push_header_block(
  out: &mut Output,
  id: u32,
  block: &[u8],
  end_stream: bool,
  max_frame_len: u32,
) -> crate::Result<()> {
  let max = usize::try_from(max_frame_len).unwrap_or(usize::MAX).max(1);
  let mut chunks = block.chunks(max);
  let first = chunks.next().unwrap_or_default();
  let mut rest = chunks.peekable();
  let mut cf = CommonFlags::empty();
  if end_stream {
    cf.set_eos();
  }
  if rest.peek().is_none() {
    cf.set_eoh();
  }
  let len = u32::try_from(first.len()).unwrap_or(u32::MAX);
  out.push_many(&[
    &FrameInit::new(cf, len, U31::from_u32(id), FrameInitTy::Headers).bytes(),
    first,
  ])?;
  while let Some(chunk) = rest.next() {
    let mut cf = CommonFlags::empty();
    if rest.peek().is_none() {
      cf.set_eoh();
    }
    let len = u32::try_from(chunk.len()).unwrap_or(u32::MAX);
    let fi = FrameInit::new(cf, len, U31::from_u32(id), FrameInitTy::Continuation);
    out.push_many(&[&fi.bytes(), chunk])?;
  }
  Ok(())
}

/// `content-length: <len>`; see [`HpackEncoder::encode_content_length`]. `repeat`: the last
/// response had the same length, so the next ones likely will too, and it is worth indexing.
fn push_content_length(
  hpack_enc: &mut HpackEncoder,
  block: &mut VectorUsize<u8>,
  len: usize,
  repeat: bool,
) -> crate::Result<()> {
  let mut digits = [0u8; 20];
  let mut idx = digits.len();
  let mut value = len;
  loop {
    idx = idx.wrapping_sub(1);
    if let Some(elem) = digits.get_mut(idx) {
      *elem = b'0'.wrapping_add(u8::try_from(value % 10).unwrap_or(0));
    }
    value /= 10;
    if value == 0 {
      break;
    }
  }
  let text = digits.get(idx..).unwrap_or_default();
  hpack_enc.encode_content_length(block, core::str::from_utf8(text).unwrap_or_default(), repeat)
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
