//! The HTTP/3 connection (RFC 9114) as the application of QUIC connections: [`H3App`].
//!
//! # Streams
//!
//! Once a connection is established the server opens its control stream, with its SETTINGS
//! (`SETTINGS_QPACK_MAX_TABLE_CAPACITY` and `SETTINGS_QPACK_BLOCKED_STREAMS` of [`H3Params`] and
//! `SETTINGS_MAX_FIELD_SECTION_SIZE`), and its QPACK encoder and decoder streams, and never closes
//! them; nothing GREASE is sent and the encoder stream carries nothing after its type (responses
//! use the static table only). Of the unidirectional streams of the client, the control stream
//! must start with SETTINGS; its encoder stream feeds the QPACK decoder; its decoder stream may
//! only cancel streams. Closing or resetting one of them, or asking us to stop one of ours, closes
//! the connection with `H3_CLOSED_CRITICAL_STREAM`; a second one of a type, or a push stream, with
//! `H3_STREAM_CREATION_ERROR`; a stream of an unknown type is asked to stop with
//! `H3_STREAM_CREATION_ERROR`. Unknown frames and settings are skipped, PRIORITY_UPDATE with them;
//! push is never allowed (no MAX_PUSH_ID is sent).
//!
//! # Requests
//!
//! A request stream is read frame by frame as its bytes arrive. A HEADERS frame that arrived whole
//! is decoded where it is; one that is cut is kept by retaining its bytes (up to 4 KiB, which the
//! connection allows), or else in the head buffer of the request (ruling T13-b). DATA payloads are
//! copied into the body of the request, whose credit then comes back to the peer. Once the FIN
//! arrives, the request, checked ([`crate::http3::H3Request`]), goes to the handler, which answers
//! it at once or parks it ([`ReqOutcome`]) until [`H3App::resume`]. A field section that needs
//! QPACK inserts that did not arrive waits, with what follows it on its stream, until they do.
//!
//! - A malformed request (RFC 9114 section 4.1.2) gets a stream error, `H3_MESSAGE_ERROR`
//!   (RESET_STREAM and STOP_SENDING); a stream that ends without a head `H3_REQUEST_INCOMPLETE`.
//! - A field section that decodes to more than `SETTINGS_MAX_FIELD_SECTION_SIZE` (or whose
//!   HEADERS frame alone is longer) is answered with 431, a body longer than
//!   [`H3Params::max_request_body`] (or announced so by `content-length`) with 413; the rest of the
//!   request is then not read (STOP_SENDING with `H3_NO_ERROR`, RFC 9114 section 4.1).
//! - Frames out of place (DATA before HEADERS, frames of the control stream) and frames cut by the
//!   FIN are connection errors, `H3_FRAME_UNEXPECTED` and `H3_FRAME_ERROR`.
//!
//! # Shutdown
//!
//! When the endpoint shuts down ([`QuicApp::on_shutdown`]), the connection sends GOAWAY with the
//! lowest client stream that QUIC did not open, refuses requests from it on with
//! `H3_REQUEST_REJECTED`, and lets the others finish. Once no request is under way, the streams
//! below the GOAWAY that brought no request (opened by a later one, or whose data did not arrive in
//! order) are refused with `H3_REQUEST_REJECTED`, never dropped, and once every answer and refusal
//! is acknowledged the connection closes with `H3_NO_ERROR` (ruling T13-h);
//! [`crate::quic::QuicLimits::shutdown_grace_ms`] bounds the wait. GOAWAY is sent then only.
//!
//! # Memory
//!
//! The request buffers of a connection hold at most [`H3Params::max_buffered_body_per_conn`]
//! bytes (ruling T13-g); the decoder-stream output is written while that stream has less than
//! 4 KiB unsent, so a peer that gives it no credit meets the bound of the decoder (review V3); the
//! pool keeps boxes within a byte budget, and [`H3App::trim_idle`] frees it down for an idle
//! worker (review V4).

use crate::{
  collections::{VectorError, VectorUsize},
  http::prefix_int::decode_prefix_int,
  http3::{
    DecodeOutcome, H3ErrorCode, H3FrameTy, H3Settings, Http3Error, decode_frame_header,
    encode_frame_header, encode_static,
    h3_conn_state::{FrameLeft, H3Conn, H3ConnState, KEEP_SCRATCH, Phase, Req},
    request::{H3Request, check_trailer},
  },
  quic::{
    BodyRef, ConnCtx, QuicApp, QuicError, StreamId, decode_varint, encode_varint, varint_len,
  },
};
use alloc::{boxed::Box, vec::Vec};
use core::hint::cold_path;

/// The bytes that the connection retains for a stream at most (see `ConnCtx::retain`): what is
/// read in one piece without a buffer of its own.
const RETAIN_MAX: usize = 4096;
/// The bytes that the decoder stream may have unsent before more decoder output waits in the
/// decoder (review V3).
const DECODER_UNSENT_MAX: usize = 4096;
/// Boxes of connections that the pool keeps at most.
const MAX_POOLED: usize = 256;
// Room for what follows a blocked field section on its stream, on top of the limits of a request
const STASH_SLACK: u64 = 64 * 1024;
// The types of unidirectional streams (RFC 9114 section 6.2, RFC 9204 section 4.2)
const CONTROL_STREAM: u8 = 0x00;
const PUSH_STREAM: u64 = 0x01;
const ENCODER_STREAM: u8 = 0x02;
const DECODER_STREAM: u8 = 0x03;

/// The settings of the HTTP/3 connections of a server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H3Params {
  /// The advertised `SETTINGS_QPACK_MAX_TABLE_CAPACITY`: the bytes of the dynamic table that the
  /// encoders of clients may use.
  ///
  /// Defaults to 0 (no dynamic table) until the measurement of task 18 decides.
  pub qpack_max_table_capacity: u32,
  /// The advertised `SETTINGS_QPACK_BLOCKED_STREAMS`.
  ///
  /// Defaults to 0.
  pub qpack_blocked_streams: u16,
  /// The advertised `SETTINGS_MAX_FIELD_SECTION_SIZE`, which the field sections of requests are
  /// held to (RFC 9114 section 4.2.2): a request whose head or trailers decode to more is answered
  /// with 431.
  ///
  /// Defaults to 16 KiB.
  pub max_field_section_size: u32,
  /// The largest body of a request: a request with a larger one is answered with 413.
  ///
  /// Defaults to 1 MiB.
  pub max_request_body: u32,
  /// The bytes that the buffers of the requests of a connection (heads, bodies, bytes that wait
  /// for others) may hold at most, counted by their capacity: a request that would need more is
  /// answered with 413, and the others go on (ruling T13-g).
  ///
  /// Defaults to 16 MiB, the receive window of a connection.
  pub max_buffered_body_per_conn: u32,
}

impl Default for H3Params {
  #[inline]
  fn default() -> Self {
    Self {
      qpack_max_table_capacity: 0,
      qpack_blocked_streams: 0,
      max_field_section_size: 16 * 1024,
      max_request_body: 1 << 20,
      max_buffered_body_per_conn: 16 << 20,
    }
  }
}

/// What became of a request that the handler was given.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReqOutcome {
  /// It was answered.
  Responded,
  /// It is answered later, from [`H3Handler::resume`].
  Parked,
}

/// What answers the requests of the connections of an [`H3App`].
pub(crate) trait H3Handler {
  /// A complete request arrived: answer it now through `cx` and return
  /// [`ReqOutcome::Responded`], or return [`ReqOutcome::Parked`] to answer it later, when
  /// [`H3App::resume`] calls [`Self::resume`] for its stream. `req` is not kept after the call.
  ///
  /// An error resets the stream of the request with `H3_INTERNAL_ERROR`, unless it is a
  /// [`crate::Error::Http3Close`], which closes the connection with its code; so does
  /// [`ReqOutcome::Responded`] without an answer.
  fn on_request(
    &mut self,
    cx: &mut H3ReqCtx<'_, '_>,
    req: &H3Request<'_>,
  ) -> crate::Result<ReqOutcome>;

  /// The request of `stream`, parked, is resumed: answer it, or park it again. Called also for a
  /// request that the peer abandoned meanwhile, whose answer then fails.
  fn resume(&mut self, cx: &mut H3ReqCtx<'_, '_>, stream: StreamId) -> crate::Result<ReqOutcome>;
}

/// What a handler answers a request through.
#[derive(Debug)]
pub(crate) struct H3ReqCtx<'c, 'a> {
  cx: &'c mut ConnCtx<'a, H3ConnState>,
  fields: &'c mut VectorUsize<u8>,
  frame: &'c mut VectorUsize<u8>,
  responded: bool,
  stream: StreamId,
}

impl H3ReqCtx<'_, '_> {
  /// The stream of the request.
  #[inline]
  pub(crate) const fn stream(&self) -> StreamId {
    self.stream
  }

  /// Answers with the field section `encoded_headers`, encoded with QPACK by the static table,
  /// and `body`: one write of a HEADERS frame, a DATA frame (if `body` is not empty) and the
  /// FIN, which leave in one STREAM frame when they fit in a packet (spec section 5.3).
  #[inline]
  pub(crate) fn respond(&mut self, encoded_headers: &[u8], body: &[u8]) -> crate::Result<()> {
    self.check_once()?;
    let rslt = write_response(self.cx, self.frame, self.stream, encoded_headers, body);
    keep_small(self.frame);
    rslt?;
    self.responded = true;
    Ok(())
  }

  /// [`Self::respond`] with a body that is not copied: the HEADERS frame and the header of the
  /// DATA frame are written by copy, then the body by reference, with the FIN.
  #[inline]
  pub(crate) fn respond_body(
    &mut self,
    encoded_headers: &[u8],
    body: BodyRef,
  ) -> crate::Result<()> {
    self.check_once()?;
    let frame = &mut *self.frame;
    frame.clear();
    push_frame_header(frame, H3FrameTy::Headers, encoded_headers.len())?;
    frame.extend_from_copyable_slice(encoded_headers)?;
    if body.is_empty() {
      self.cx.write(self.stream, frame, true)?;
    } else {
      push_frame_header(frame, H3FrameTy::Data, usize::try_from(body.len()).unwrap_or(usize::MAX))?;
      self.cx.write(self.stream, frame, false)?;
      self.cx.write_body(self.stream, body, true)?;
    }
    keep_small(frame);
    self.responded = true;
    Ok(())
  }

  /// [`Self::respond`] with `fields`, which are encoded with the static table of QPACK.
  #[inline]
  pub(crate) fn respond_fields(
    &mut self,
    fields: &[(&[u8], &[u8])],
    body: &[u8],
  ) -> crate::Result<()> {
    self.check_once()?;
    self.fields.clear();
    encode_static(fields, self.fields)?;
    let rslt = write_response(self.cx, self.frame, self.stream, self.fields, body);
    keep_small(self.fields);
    keep_small(self.frame);
    rslt?;
    self.responded = true;
    Ok(())
  }

  fn check_once(&self) -> crate::Result<()> {
    if self.responded {
      cold_path();
      return Err(crate::Error::Http3(Http3Error::AlreadyResponded));
    }
    Ok(())
  }
}

/// HTTP/3 over the QUIC connections of a worker: their control and QPACK streams, the requests
/// that they carry, read, checked and handed to `handler`, and the pool of their state. See the
/// [module documentation](self).
#[derive(Debug)]
pub(crate) struct H3App<H> {
  /// What answers the requests.
  pub handler: H,
  // The fields of the request that the handler is given; empty between calls
  field_refs: Vec<(&'static [u8], &'static [u8])>,
  fields: VectorUsize<u8>,
  frame: VectorUsize<u8>,
  params: H3Params,
  pool: VectorUsize<Box<H3Conn>>,
  // The bytes that the boxes of the pool take
  pool_bytes: usize,
}

// What reading the bytes of a request stream came to.
enum Parsed {
  // The request was answered, refused or parked: nothing waits
  Done,
  // The bytes from this offset on wait for the ones that follow them; `true` if they are the start
  // of a frame that fits in what the connection retains (ruling T13-b)
  More(usize, bool),
  // The field section of the HEADERS frame at this offset waits for QPACK inserts
  Blocked(usize),
}

// What decoding a field section came to.
enum Section {
  // The stream goes on
  Read,
  // The request was refused
  Done,
  // The section waits for QPACK inserts
  Blocked,
}

impl<H> H3App<H>
where
  H: H3Handler,
{
  /// The connections of a worker, with `params`, whose requests `handler` answers.
  #[inline]
  pub(crate) const fn new(handler: H, params: H3Params) -> Self {
    Self {
      handler,
      field_refs: Vec::new(),
      fields: VectorUsize::new(),
      frame: VectorUsize::new(),
      params,
      pool: VectorUsize::new(),
      pool_bytes: 0,
    }
  }

  /// Resumes the parked request of `stream` ([`H3Handler::resume`]), from the context of its
  /// connection.
  #[inline]
  pub(crate) fn resume(
    &mut self,
    cx: &mut ConnCtx<'_, H3ConnState>,
    stream: StreamId,
  ) -> crate::Result<()> {
    let Some(mut conn) = cx.state.conn.take() else {
      return Ok(());
    };
    let rslt = self.resume_request(&mut conn, cx, stream);
    cx.state.conn = Some(conn);
    conclude(cx, rslt)
  }

  /// The bytes that the boxes of the pool take at most (review V4): a box that would pass it is
  /// dropped instead of pooled.
  pub(crate) const POOL_BYTES: usize = 4 << 20;
  /// The boxes that [`Self::trim_idle`] keeps at most.
  pub(crate) const IDLE_POOLED: usize = 4;
  /// The bytes that the boxes that [`Self::trim_idle`] keeps take at most.
  const IDLE_POOL_BYTES: usize = 512 * 1024;

  /// Frees all but a few boxes of the pool, and the response buffers, for a worker that has no
  /// connection (the idle hook of the server, spec section 5.4).
  #[inline]
  pub(crate) fn trim_idle(&mut self) {
    while self.pool.len() > Self::IDLE_POOLED || self.pool_bytes > Self::IDLE_POOL_BYTES {
      let Some(conn) = self.pool.pop() else {
        break;
      };
      self.pool_bytes = self.pool_bytes.saturating_sub(conn.heap_bytes());
    }
    self.field_refs = Vec::new();
    self.fields = VectorUsize::new();
    self.frame = VectorUsize::new();
  }

  /// The boxes that wait in the pool.
  #[cfg(test)]
  pub(crate) fn pooled(&self) -> usize {
    self.pool.len()
  }

  /// The bytes that the boxes of the pool take.
  #[cfg(test)]
  pub(crate) fn pooled_bytes(&self) -> usize {
    self.pool_bytes
  }

  /// If no box of the pool holds state of a connection.
  #[cfg(test)]
  pub(crate) fn pool_is_clear(&self) -> bool {
    self.pool.iter().all(|el| el.is_clear())
  }

  /// The capacity of the response buffers of the worker.
  #[cfg(test)]
  pub(crate) fn scratch_bytes(&self) -> usize {
    self.frame.capacity().saturating_add(self.fields.capacity())
  }

  // Calls the handler with request `idx`, complete.
  fn dispatch(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    idx: usize,
  ) -> crate::Result<()> {
    let Some(req) = conn.reqs.get(idx) else {
      return Ok(());
    };
    let body_len = u64::try_from(req.body.len()).unwrap_or(u64::MAX);
    if req.head.content_length().is_some_and(|el| el != body_len) {
      return stream_error(conn, cx, idx, H3ErrorCode::MessageError);
    }
    let Self { field_refs, fields, frame, handler, .. } = self;
    let mut refs = recycle(core::mem::take(field_refs));
    if refs.try_reserve(req.head.fields_len()).is_err() {
      cold_path();
      *field_refs = recycle(refs);
      return Err(crate::Error::Vector(VectorError::CapacityOverflow));
    }
    refs.extend(req.head.fields());
    let request = req.request(&refs);
    let mut rcx = H3ReqCtx { cx, fields, frame, responded: false, stream: req.id };
    let outcome = handler.on_request(&mut rcx, &request);
    let responded = rcx.responded;
    *field_refs = recycle(refs);
    after_handler(conn, cx, idx, outcome, responded)
  }

  // Reads what arrived on request stream `id`.
  fn request_data(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    id: StreamId,
    data: &[u8],
    fin: bool,
  ) -> crate::Result<()> {
    let idx = match conn.req_idx(id) {
      Some(elem) => elem,
      None => {
        // After a GOAWAY, what it did not accept is refused (RFC 9114 section 5.2)
        if conn.goaway.is_some_and(|el| id.0 >= el) {
          return reject(conn, cx, id, H3ErrorCode::RequestRejected);
        }
        conn.next_request = conn.next_request.max(id.0.wrapping_add(4));
        conn.take_req(id)?
      }
    };
    let stash_max = self.stash_max();
    let Some(req) = conn.reqs.get(idx) else {
      return Ok(());
    };
    if req.blocked || !req.stash.is_empty() {
      // What arrives behind bytes that wait, waits with them
      if req.stash.len().saturating_add(data.len()) > stash_max {
        return stream_error(conn, cx, idx, H3ErrorCode::ExcessiveLoad);
      }
      if !reserve_in(conn, idx, data.len(), |el| (&mut el.stash, None))? {
        return self.refuse(conn, cx, idx, b"413");
      }
      let Some(req) = conn.reqs.get_mut(idx) else {
        return Ok(());
      };
      req.stash.extend_from_copyable_slice(data)?;
      req.fin |= fin;
      if req.blocked {
        return Ok(());
      }
      return self.read_stash(conn, cx, idx);
    }
    let (pos, blocked) = match self.parse(conn, cx, idx, data, fin)? {
      Parsed::Done => return Ok(()),
      Parsed::More(pos, fits) => (pos, !fits),
      Parsed::Blocked(pos) => (pos, true),
    };
    // Retained bytes come again with the next ones in one block of 4 KiB: what does not fit there
    // whole waits in the head buffer of the request
    let rest = data.get(pos..).unwrap_or_default();
    if !blocked && rest.len() < RETAIN_MAX {
      return cx.retain(rest.len());
    }
    if !reserve_in(conn, idx, rest.len(), |el| (&mut el.stash, None))? {
      return self.refuse(conn, cx, idx, b"413");
    }
    let Some(req) = conn.reqs.get_mut(idx) else {
      return Ok(());
    };
    req.stash.extend_from_copyable_slice(rest)?;
    req.fin = fin;
    Ok(())
  }

  // Reads the frames of request `idx` in `input`, from the frame that the stream is in. `fin`: the
  // stream ends with `input`.
  fn parse(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    idx: usize,
    input: &[u8],
    fin: bool,
  ) -> crate::Result<Parsed> {
    let max_body = u64::from(self.params.max_request_body);
    let max_section = u64::from(self.params.max_field_section_size);
    let mut fits = true;
    let mut pos = 0usize;
    loop {
      let rest = input.get(pos..).unwrap_or_default();
      let Some(req) = conn.reqs.get_mut(idx) else {
        return Ok(Parsed::Done);
      };
      match req.frame {
        FrameLeft::Data(left) => {
          let take = usize::try_from(left).unwrap_or(usize::MAX).min(rest.len());
          if !reserve_in(conn, idx, take, |el| (&mut el.body, el.head.content_length()))? {
            self.refuse(conn, cx, idx, b"413")?;
            return Ok(Parsed::Done);
          }
          let Some(req) = conn.reqs.get_mut(idx) else {
            return Ok(Parsed::Done);
          };
          req.body.extend_from_copyable_slice(rest.get(..take).unwrap_or_default())?;
          pos = pos.wrapping_add(take);
          let left = left.wrapping_sub(u64::try_from(take).unwrap_or(u64::MAX));
          req.frame = if left == 0 { FrameLeft::None } else { FrameLeft::Data(left) };
          if left > 0 {
            break;
          }
          continue;
        }
        FrameLeft::Skip(left) => {
          let take = usize::try_from(left).unwrap_or(usize::MAX).min(rest.len());
          pos = pos.wrapping_add(take);
          let left = left.wrapping_sub(u64::try_from(take).unwrap_or(u64::MAX));
          req.frame = if left == 0 { FrameLeft::None } else { FrameLeft::Skip(left) };
          if left > 0 {
            break;
          }
          continue;
        }
        FrameLeft::None => {}
      }
      let Some((ty, len, header_len)) = decode_frame_header(rest)? else {
        break;
      };
      match ty {
        H3FrameTy::Headers => {
          if !matches!(req.phase, Phase::Head | Phase::Body) {
            return Err(unexpected_frame());
          }
          if len > max_section {
            self.refuse(conn, cx, idx, b"431")?;
            return Ok(Parsed::Done);
          }
          let end = usize::try_from(len).ok().and_then(|el| el.checked_add(header_len));
          let Some(section) = end.and_then(|el| rest.get(header_len..el)) else {
            fits = end.is_some_and(|el| el <= RETAIN_MAX);
            break;
          };
          match self.section(conn, cx, idx, section)? {
            Section::Read => {}
            Section::Done => return Ok(Parsed::Done),
            Section::Blocked => return Ok(Parsed::Blocked(pos)),
          }
          pos = pos.wrapping_add(header_len).wrapping_add(section.len());
        }
        H3FrameTy::Data => {
          // DATA before HEADERS, or after the trailers (RFC 9114 section 4.1)
          if req.phase != Phase::Body {
            return Err(unexpected_frame());
          }
          let body_len = u64::try_from(req.body.len()).unwrap_or(u64::MAX);
          let frame_len = usize::try_from(len).unwrap_or(usize::MAX);
          if body_len.saturating_add(len) > max_body
            || !fits_in(conn, idx, frame_len, |el| &mut el.body)
          {
            self.refuse(conn, cx, idx, b"413")?;
            return Ok(Parsed::Done);
          }
          let Some(req) = conn.reqs.get_mut(idx) else {
            return Ok(Parsed::Done);
          };
          req.frame = if len == 0 { FrameLeft::None } else { FrameLeft::Data(len) };
          pos = pos.wrapping_add(header_len);
        }
        H3FrameTy::Unknown(_) => {
          req.frame = if len == 0 { FrameLeft::None } else { FrameLeft::Skip(len) };
          pos = pos.wrapping_add(header_len);
        }
        H3FrameTy::CancelPush
        | H3FrameTy::Goaway
        | H3FrameTy::MaxPushId
        | H3FrameTy::PushPromise
        | H3FrameTy::Settings => return Err(unexpected_frame()),
      }
    }
    if !fin {
      return Ok(Parsed::More(pos, fits));
    }
    let Some(req) = conn.reqs.get(idx) else {
      return Ok(Parsed::Done);
    };
    if pos < input.len() || req.frame != FrameLeft::None {
      cold_path();
      return Err(close(H3ErrorCode::FrameError, Http3Error::TruncatedFrame));
    }
    match req.phase {
      Phase::Head => stream_error(conn, cx, idx, H3ErrorCode::RequestIncomplete)?,
      Phase::Body | Phase::Trailers => self.dispatch(conn, cx, idx)?,
      Phase::Free | Phase::Parked => {}
    }
    Ok(Parsed::Done)
  }

  // Reads what waits of request `idx`.
  fn read_stash(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    idx: usize,
  ) -> crate::Result<()> {
    let Some(req) = conn.reqs.get_mut(idx) else {
      return Ok(());
    };
    let mut stash = core::mem::take(&mut req.stash);
    let fin = req.fin;
    let rslt = self.parse(conn, cx, idx, &stash, fin);
    match rslt {
      Ok(Parsed::More(pos, _) | Parsed::Blocked(pos)) => drain_front(&mut stash, pos),
      Ok(Parsed::Done) | Err(_) => stash.clear(),
    }
    // The entry keeps the storage, whether it still holds the request or not; small if not
    if let Some(req) = conn.reqs.get_mut(idx) {
      req.stash = stash;
    }
    conn.trim_free_stash(idx);
    rslt.map(|_| ())
  }

  // Refuses request `idx` with a response of `status` (413 or 431) and stops reading it (RFC 9114
  // section 4.1).
  fn refuse(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    idx: usize,
    status: &[u8],
  ) -> crate::Result<()> {
    let Some(id) = conn.reqs.get(idx).map(|el| el.id) else {
      return Ok(());
    };
    self.fields.clear();
    encode_static(&[(b":status", status)], &mut self.fields)?;
    // A stream that the client stopped can not be answered: the stop is what it gets
    let _rslt = write_response(cx, &mut self.frame, id, &self.fields, &[]);
    keep_small(&mut self.frame);
    cx.stop_sending(id, H3ErrorCode::NoError.code());
    conn.decoder.on_stream_cancelled(id.0)?;
    conn.free_req(idx);
    Ok(())
  }

  fn resume_request(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    stream: StreamId,
  ) -> crate::Result<()> {
    let idx = conn
      .req_idx(stream)
      .filter(|el| conn.reqs.get(*el).is_some_and(|req| req.phase == Phase::Parked));
    let Self { fields, frame, handler, .. } = self;
    let mut rcx = H3ReqCtx { cx, fields, frame, responded: false, stream };
    let outcome = handler.resume(&mut rcx, stream);
    let responded = rcx.responded;
    match (idx, outcome) {
      (Some(idx), outcome) => after_handler(conn, cx, idx, outcome, responded),
      (None, Err(err @ crate::Error::Http3Close(..))) => Err(err),
      (None, _) => Ok(()),
    }
  }

  // The field sections that waited for the inserts that arrived are read, with what followed them.
  fn retry_blocked(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
  ) -> crate::Result<()> {
    let insert_count = conn.decoder.insert_count();
    let mut nth = 0usize;
    while let Some((id, ric)) = conn.blocked.get(nth).copied() {
      if ric > insert_count {
        nth = nth.wrapping_add(1);
        continue;
      }
      let _ = conn.blocked.swap_remove(nth);
      let Some(idx) = conn.req_idx(id) else {
        continue;
      };
      if let Some(req) = conn.reqs.get_mut(idx) {
        req.blocked = false;
      }
      self.read_stash(conn, cx, idx)?;
    }
    Ok(())
  }

  // Decodes `section`, the payload of a HEADERS frame of request `idx`: its head or its trailers.
  fn section(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    idx: usize,
    section: &[u8],
  ) -> crate::Result<Section> {
    let max_body = u64::from(self.params.max_request_body);
    let max_section = u64::from(self.params.max_field_section_size);
    if conn.budget.is_tight() {
      // What entries without a request keep goes first (ruling T13-g)
      conn.reclaim();
    }
    let H3Conn { blocked, budget, decoder, memo, reqs, scratch, .. } = &mut *conn;
    let Some(req) = reqs.get_mut(idx) else {
      return Ok(Section::Done);
    };
    let id = req.id;
    let is_head = req.phase == Phase::Head;
    // The fields are checked, and the decoded size counted, as they are decoded: a short section
    // can reference a large entry many times
    let outcome = if is_head {
      req.head.clear();
      let head = &mut req.head;
      decoder.decode_with_memo(memo, id.0, section, scratch, &mut |name, value| {
        head.push(name, value, max_section, budget)
      })
    } else {
      let mut size = 0u64;
      decoder.decode_with_memo(memo, id.0, section, scratch, &mut |name, value| {
        check_trailer(&mut size, name, value, max_section)
      })
    };
    match outcome {
      Ok(DecodeOutcome::Done { .. }) => {}
      Ok(DecodeOutcome::Blocked { required_insert_count }) => {
        req.blocked = true;
        blocked.push((id, required_insert_count))?;
        return Ok(Section::Blocked);
      }
      Err(crate::Error::Http3(Http3Error::MalformedRequest)) => {
        stream_error(conn, cx, idx, H3ErrorCode::MessageError)?;
        return Ok(Section::Done);
      }
      Err(crate::Error::Http3(Http3Error::FieldSectionTooLarge)) => {
        self.refuse(conn, cx, idx, b"431")?;
        return Ok(Section::Done);
      }
      Err(crate::Error::Http3(Http3Error::BufferedLimit)) => {
        self.refuse(conn, cx, idx, b"413")?;
        return Ok(Section::Done);
      }
      Err(err) => return Err(err),
    }
    if !is_head {
      req.phase = Phase::Trailers;
      return Ok(Section::Read);
    }
    if req.head.check().is_err() {
      stream_error(conn, cx, idx, H3ErrorCode::MessageError)?;
      return Ok(Section::Done);
    }
    // A body that is announced larger than what is allowed, or than what the buffers of the
    // connection can take, is refused before it arrives
    let length = req.head.content_length();
    req.phase = Phase::Body;
    let announced = length.map(|el| usize::try_from(el).unwrap_or(usize::MAX)).unwrap_or(0);
    if length.is_some_and(|el| el > max_body) || !fits_in(conn, idx, announced, |el| &mut el.body) {
      self.refuse(conn, cx, idx, b"413")?;
      return Ok(Section::Done);
    }
    Ok(Section::Read)
  }

  // What may wait for a request: its body, its head and its trailers, with room for frame
  // headers and unknown frames.
  fn stash_max(&self) -> usize {
    let params = &self.params;
    let max = u64::from(params.max_request_body)
      .saturating_add(u64::from(params.max_field_section_size).saturating_mul(2))
      .saturating_add(STASH_SLACK);
    usize::try_from(max).unwrap_or(usize::MAX)
  }

  // A box from the pool, cleared when it was pooled, or a new one.
  fn take_conn(&mut self) -> crate::Result<Box<H3Conn>> {
    if let Some(conn) = self.pool.pop() {
      self.pool_bytes = self.pool_bytes.saturating_sub(conn.heap_bytes());
      return Ok(conn);
    }
    H3Conn::new(&self.params)
  }

  // Reads what arrived on unidirectional stream `id` of the peer.
  fn uni_data(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    id: StreamId,
    data: &[u8],
    fin: bool,
  ) -> crate::Result<()> {
    if conn.peer_control == Some(id) {
      return control_data(conn, cx, data, fin);
    }
    if conn.peer_encoder == Some(id) {
      return self.encoder_data(conn, cx, data, fin);
    }
    if conn.peer_decoder == Some(id) {
      return decoder_data(cx, data, fin);
    }
    let Some((ty, len)) = decode_varint(data) else {
      // The type is cut: it comes again with what follows. A stream that ends before it is
      // ignored.
      return if fin { Ok(()) } else { cx.retain(data.len()) };
    };
    let slot = match u8::try_from(ty) {
      Ok(CONTROL_STREAM) => &mut conn.peer_control,
      Ok(ENCODER_STREAM) => &mut conn.peer_encoder,
      Ok(DECODER_STREAM) => &mut conn.peer_decoder,
      _ if ty == PUSH_STREAM => {
        return Err(close(H3ErrorCode::StreamCreationError, Http3Error::PushStreamFromClient));
      }
      _ => {
        // RFC 9114 section 6.2: an unknown type is not read
        cx.stop_sending(id, H3ErrorCode::StreamCreationError.code());
        return Ok(());
      }
    };
    if slot.is_some() {
      return Err(close(H3ErrorCode::StreamCreationError, Http3Error::SecondCriticalStream));
    }
    *slot = Some(id);
    self.uni_data(conn, cx, id, data.get(len..).unwrap_or_default(), fin)
  }

  // Reads what arrived on the QPACK encoder stream of the peer.
  fn encoder_data(
    &mut self,
    conn: &mut H3Conn,
    cx: &mut ConnCtx<'_, H3ConnState>,
    data: &[u8],
    fin: bool,
  ) -> crate::Result<()> {
    if fin {
      return Err(closed_critical_stream());
    }
    // The decoder keeps no instruction that is longer than about four times the capacity
    let backlog_max = usize::try_from(self.params.qpack_max_table_capacity)
      .unwrap_or(usize::MAX)
      .saturating_mul(4)
      .saturating_add(RETAIN_MAX);
    let before = conn.decoder.insert_count();
    let H3Conn { decoder, encoder_rx, .. } = &mut *conn;
    if encoder_rx.is_empty() {
      let consumed = decoder.on_encoder_stream(data)?;
      let rest = data.get(consumed..).unwrap_or_default();
      // Retained bytes come again with the next ones in one block of 4 KiB: a full block is not
      // retained, or it would have no room for them
      if rest.len() < RETAIN_MAX {
        cx.retain(rest.len())?;
      } else if rest.len() > backlog_max {
        return Err(close(H3ErrorCode::ExcessiveLoad, Http3Error::EncoderStreamBacklog));
      } else {
        encoder_rx.extend_from_copyable_slice(rest)?;
      }
    } else {
      if encoder_rx.len().saturating_add(data.len()) > backlog_max {
        return Err(close(H3ErrorCode::ExcessiveLoad, Http3Error::EncoderStreamBacklog));
      }
      encoder_rx.extend_from_copyable_slice(data)?;
      let consumed = decoder.on_encoder_stream(encoder_rx)?;
      drain_front(encoder_rx, consumed);
    }
    if conn.decoder.insert_count() > before {
      self.retry_blocked(conn, cx)?;
    }
    Ok(())
  }
}

impl<H> QuicApp for H3App<H>
where
  H: H3Handler,
{
  type ConnState = H3ConnState;

  #[inline]
  fn on_established(&mut self, cx: &mut ConnCtx<'_, H3ConnState>) -> crate::Result<()> {
    let mut conn = self.take_conn()?;
    let rslt = open_streams(&mut conn, cx, &self.params);
    cx.state.conn = Some(conn);
    conclude(cx, rslt)
  }

  #[inline]
  fn on_stream_data(
    &mut self,
    cx: &mut ConnCtx<'_, H3ConnState>,
    id: StreamId,
    data: &[u8],
    fin: bool,
  ) -> crate::Result<()> {
    let Some(mut conn) = cx.state.conn.take() else {
      return Ok(());
    };
    let rslt = if id.is_uni() {
      self.uni_data(&mut conn, cx, id, data, fin)
    } else if id.is_client_bidi() {
      self.request_data(&mut conn, cx, id, data, fin)
    } else {
      Ok(())
    };
    cx.state.conn = Some(conn);
    conclude(cx, rslt)
  }

  #[inline]
  fn on_stream_reset(
    &mut self,
    cx: &mut ConnCtx<'_, H3ConnState>,
    id: StreamId,
    _code: u64,
  ) -> crate::Result<()> {
    let Some(mut conn) = cx.state.conn.take() else {
      return Ok(());
    };
    let rslt = reset_by_peer(&mut conn, cx, id);
    cx.state.conn = Some(conn);
    conclude(cx, rslt)
  }

  #[inline]
  fn on_stop_sending(
    &mut self,
    cx: &mut ConnCtx<'_, H3ConnState>,
    id: StreamId,
    _code: u64,
  ) -> crate::Result<()> {
    let Some(mut conn) = cx.state.conn.take() else {
      return Ok(());
    };
    let rslt = stopped_by_peer(&mut conn, cx, id);
    cx.state.conn = Some(conn);
    conclude(cx, rslt)
  }

  #[inline]
  fn on_closed(&mut self, state: &mut H3ConnState) {
    // Cleared now, so that the pool holds no state of a connection (review V5); a box whose
    // release fails is dropped (ruling T13-a)
    let Some(mut conn) = state.conn.take().filter(|_| self.pool.len() < MAX_POOLED) else {
      return;
    };
    if conn.release(&self.params).is_err() {
      return;
    }
    let bytes = conn.heap_bytes();
    if self.pool_bytes.saturating_add(bytes) <= Self::POOL_BYTES && self.pool.push(conn).is_ok() {
      self.pool_bytes = self.pool_bytes.saturating_add(bytes);
    }
  }

  #[inline]
  fn on_flush(&mut self, cx: &mut ConnCtx<'_, H3ConnState>) {
    let Some(mut conn) = cx.state.conn.take() else {
      return;
    };
    let rslt = flush_conn(&mut conn, cx);
    cx.state.conn = Some(conn);
    if let Err(err) = rslt {
      cold_path();
      let code = match err {
        crate::Error::Http3Close(code, _) => code,
        _ => H3ErrorCode::InternalError,
      };
      cx.close(code.code(), b"");
    }
  }

  #[inline]
  fn on_shutdown(&mut self, cx: &mut ConnCtx<'_, H3ConnState>) -> bool {
    let Some(conn) = cx.state.conn.as_ref() else {
      return false;
    };
    if conn.goaway.is_some() {
      return true;
    }
    // The lowest client stream that QUIC did not open: the streams below it are answered or
    // refused before the close (RFC 9114 section 5.2, ruling T13-h)
    let (control, id) = (conn.control, conn.next_request.max(cx.next_peer_bidi().0));
    let mut frame = [0u8; 16];
    let len = u64::try_from(varint_len(id)).unwrap_or(u64::MAX);
    let Some(header_len) = encode_frame_header(H3FrameTy::Goaway, len, &mut frame) else {
      return false;
    };
    let Some(id_len) = frame.get_mut(header_len..).and_then(|el| encode_varint(id, el)) else {
      return false;
    };
    let bytes = frame.get(..header_len.wrapping_add(id_len)).unwrap_or_default();
    if cx.write(control, bytes, false).is_err() {
      return false;
    }
    if let Some(conn) = cx.state.conn.as_mut() {
      conn.goaway = Some(id);
    }
    true
  }
}

// What a handler did with request `idx`.
fn after_handler(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  idx: usize,
  outcome: crate::Result<ReqOutcome>,
  responded: bool,
) -> crate::Result<()> {
  match outcome {
    Err(err @ crate::Error::Http3Close(..)) => Err(err),
    Ok(ReqOutcome::Parked) if !responded => {
      if let Some(req) = conn.reqs.get_mut(idx) {
        req.body.clear();
        req.head.clear();
        req.phase = Phase::Parked;
      }
      Ok(())
    }
    _ if responded => {
      conn.free_req(idx);
      Ok(())
    }
    // It failed, or claims an answer that it did not give
    _ => stream_error(conn, cx, idx, H3ErrorCode::InternalError),
  }
}

#[cold]
fn close(code: H3ErrorCode, error: Http3Error) -> crate::Error {
  crate::Error::Http3Close(code, error)
}

#[cold]
fn closed_critical_stream() -> crate::Error {
  close(H3ErrorCode::ClosedCriticalStream, Http3Error::ClosedCriticalStream)
}

// A connection error is a close of the application that the callback asks for (ruling T8-d).
fn conclude(cx: &mut ConnCtx<'_, H3ConnState>, rslt: crate::Result<()>) -> crate::Result<()> {
  match rslt {
    Err(crate::Error::Http3Close(code, _)) => {
      cold_path();
      cx.close(code.code(), b"");
      Ok(())
    }
    rslt => rslt,
  }
}

// Reads what arrived on the control stream of the peer: SETTINGS first, then GOAWAY, MAX_PUSH_ID,
// CANCEL_PUSH and unknown frames (RFC 9114 sections 6.2.1 and 7.2).
fn control_data(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  data: &[u8],
  fin: bool,
) -> crate::Result<()> {
  let mut pos = 0usize;
  loop {
    let rest = data.get(pos..).unwrap_or_default();
    if conn.control_skip > 0 {
      let take = usize::try_from(conn.control_skip).unwrap_or(usize::MAX).min(rest.len());
      pos = pos.wrapping_add(take);
      conn.control_skip = conn.control_skip.wrapping_sub(u64::try_from(take).unwrap_or(0));
      if conn.control_skip > 0 {
        break;
      }
      continue;
    }
    let Some((ty, len, header_len)) = decode_frame_header(rest)? else {
      break;
    };
    if conn.settings.is_none() && ty != H3FrameTy::Settings {
      return Err(close(H3ErrorCode::MissingSettings, Http3Error::MissingSettings));
    }
    match ty {
      H3FrameTy::Unknown(_) => {
        conn.control_skip = len;
        pos = pos.wrapping_add(header_len);
        continue;
      }
      H3FrameTy::Data | H3FrameTy::Headers | H3FrameTy::PushPromise => {
        return Err(unexpected_frame());
      }
      H3FrameTy::Settings if conn.settings.is_some() => return Err(unexpected_frame()),
      H3FrameTy::CancelPush | H3FrameTy::Goaway | H3FrameTy::MaxPushId | H3FrameTy::Settings => {}
    }
    let Some(end) = usize::try_from(len)
      .ok()
      .and_then(|el| el.checked_add(header_len))
      .filter(|el| *el <= RETAIN_MAX)
    else {
      return Err(close(H3ErrorCode::ExcessiveLoad, Http3Error::ControlFrameTooLarge));
    };
    let Some(payload) = rest.get(header_len..end) else {
      break;
    };
    match ty {
      H3FrameTy::Settings => conn.settings = Some(H3Settings::decode(payload)?),
      H3FrameTy::Goaway => {
        // The push identifier of a client never grows (RFC 9114 section 5.2)
        let id = single_varint(payload)?;
        if conn.peer_goaway.is_some_and(|el| id > el) {
          return Err(close(H3ErrorCode::IdError, Http3Error::InvalidPushId));
        }
        conn.peer_goaway = Some(id);
      }
      H3FrameTy::MaxPushId => {
        let id = single_varint(payload)?;
        if conn.max_push_id.is_some_and(|el| id < el) {
          return Err(close(H3ErrorCode::IdError, Http3Error::InvalidPushId));
        }
        conn.max_push_id = Some(id);
      }
      H3FrameTy::CancelPush => {
        // Nothing is pushed: only an identifier that the client allowed can be cancelled
        let id = single_varint(payload)?;
        if conn.max_push_id.is_none_or(|el| id > el) {
          return Err(close(H3ErrorCode::IdError, Http3Error::InvalidPushId));
        }
      }
      H3FrameTy::Data | H3FrameTy::Headers | H3FrameTy::PushPromise | H3FrameTy::Unknown(_) => {}
    }
    pos = end.wrapping_add(pos);
  }
  if fin {
    return Err(closed_critical_stream());
  }
  cx.retain(data.len().wrapping_sub(pos))
}

// Reads what arrived on the QPACK decoder stream of the peer: Stream Cancellations only, since
// this encoder never references the dynamic table (RFC 9204 section 4.4).
fn decoder_data(cx: &mut ConnCtx<'_, H3ConnState>, data: &[u8], fin: bool) -> crate::Result<()> {
  if fin {
    return Err(closed_critical_stream());
  }
  let decoder_stream_error =
    || close(H3ErrorCode::QpackDecoderStreamError, Http3Error::DecoderStreamInstruction);
  let mut pos = 0usize;
  while let Some(first) = data.get(pos).copied() {
    if first & 0b1100_0000 != 0b0100_0000 {
      return Err(decoder_stream_error());
    }
    let rest = data.get(pos..).unwrap_or_default();
    let Some((_stream, len)) = decode_prefix_int(rest, 6).map_err(|_err| decoder_stream_error())?
    else {
      break;
    };
    pos = pos.wrapping_add(len);
  }
  cx.retain(data.len().wrapping_sub(pos))
}

// Removes the first `n` bytes of `vector`.
fn drain_front(vector: &mut VectorUsize<u8>, n: usize) {
  let len = vector.len();
  let n = n.min(len);
  vector.as_slice_mut().copy_within(n.., 0);
  vector.truncate(len.wrapping_sub(n));
}

// Writes the decoder-stream output of the turn in one write, starts the next turn of the decoder
// and, after a GOAWAY, closes once every accepted request was answered and its answer sent.
fn flush_conn(conn: &mut H3Conn, cx: &mut ConnCtx<'_, H3ConnState>) -> crate::Result<()> {
  // While the stream has room: what does not fit waits in the decoder, whose bound then closes a
  // connection whose peer gives the stream no credit (review V3)
  let room = DECODER_UNSENT_MAX.saturating_sub(cx.unsent_on(conn.decoder_stream));
  let output = conn.decoder.decoder_stream_output();
  let len = output.len().min(room);
  if let Some(bytes) = output.get(..len).filter(|el| !el.is_empty()) {
    cx.write(conn.decoder_stream, bytes, false)?;
    conn.decoder.consume_decoder_output(len);
  }
  conn.decoder.start_turn();
  if let Some(goaway) = conn.goaway
    && conn.live == 0
  {
    drain(conn, cx, StreamId(goaway))?;
  }
  Ok(())
}

// A shutdown with no request under way (ruling T13-h): the streams below the GOAWAY that brought
// no request are refused (RFC 9114 section 5.2), and once every answer and refusal is
// acknowledged, and the GOAWAY sent, the connection closes with H3_NO_ERROR.
fn drain(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  below: StreamId,
) -> crate::Result<()> {
  let mut answered = true;
  let mut from = StreamId(0);
  while let Some((id, writable)) = cx.first_unanswered(from, below) {
    if writable {
      cx.refuse(id, H3ErrorCode::RequestRejected.code())?;
      conn.decoder.on_stream_cancelled(id.0)?;
    }
    answered = false;
    from = StreamId(id.0.wrapping_add(4));
  }
  if answered && cx.unsent_on(conn.control) == 0 {
    cx.close(H3ErrorCode::NoError.code(), b"");
  }
  Ok(())
}

// Room for `add` more elements in the buffer of request `idx` that `which` picks, with the length
// that it will have if known, within the budget of the connection, what entries without a request
// keep being freed first if needed (ruling T13-g). `false` if the budget does not allow it.
fn reserve_in(
  conn: &mut H3Conn,
  idx: usize,
  add: usize,
  which: fn(&mut Req) -> (&mut VectorUsize<u8>, Option<u64>),
) -> crate::Result<bool> {
  for reclaim in [false, true] {
    if reclaim {
      conn.reclaim();
    }
    let H3Conn { budget, reqs, .. } = &mut *conn;
    let Some(req) = reqs.get_mut(idx) else {
      return Ok(false);
    };
    let (buf, hint) = which(req);
    let hint = hint.map(|el| usize::try_from(el).unwrap_or(usize::MAX));
    if budget.grow(buf, add, hint)? {
      return Ok(true);
    }
  }
  Ok(false)
}

// If the buffer of request `idx` that `which` picks can take `add` more elements within the budget
// of the connection, what entries without a request keep being freed first if needed.
fn fits_in(
  conn: &mut H3Conn,
  idx: usize,
  add: usize,
  which: fn(&mut Req) -> &mut VectorUsize<u8>,
) -> bool {
  for reclaim in [false, true] {
    if reclaim {
      conn.reclaim();
    }
    let H3Conn { budget, reqs, .. } = &mut *conn;
    let Some(req) = reqs.get_mut(idx) else {
      return false;
    };
    if budget.fits(which(req), add) {
      return true;
    }
  }
  false
}

// Frees a response buffer of the worker that a large response made grow (review V4).
fn keep_small(buf: &mut VectorUsize<u8>) {
  if buf.capacity() > KEEP_SCRATCH {
    *buf = VectorUsize::new();
  }
}

// Opens our control stream, with the SETTINGS of `params`, and our QPACK streams.
fn open_streams(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  params: &H3Params,
) -> crate::Result<()> {
  let settings = H3Settings {
    qpack_max_table_capacity: params.qpack_max_table_capacity.into(),
    qpack_blocked_streams: params.qpack_blocked_streams.into(),
    max_field_section_size: Some(params.max_field_section_size.into()),
  };
  let mut control = [0u8; 64];
  let Some(len) = control.get_mut(1..).and_then(|el| settings.encode(el)) else {
    return Err(crate::Error::Http3(Http3Error::BufferTooSmall));
  };
  conn.control = open_uni(cx)?;
  cx.write(conn.control, control.get(..len.wrapping_add(1)).unwrap_or_default(), false)?;
  conn.encoder_stream = open_uni(cx)?;
  cx.write(conn.encoder_stream, &[ENCODER_STREAM], false)?;
  conn.decoder_stream = open_uni(cx)?;
  cx.write(conn.decoder_stream, &[DECODER_STREAM], false)?;
  Ok(())
}

fn open_uni(cx: &mut ConnCtx<'_, H3ConnState>) -> crate::Result<StreamId> {
  cx.open_uni().map_err(|err| match err {
    crate::Error::Quic(QuicError::StreamsBlocked) => {
      close(H3ErrorCode::GeneralProtocolError, Http3Error::UniStreamsBlocked)
    }
    _ => err,
  })
}

// Appends the header of a frame of `ty` whose payload has `len` bytes.
fn push_frame_header(out: &mut VectorUsize<u8>, ty: H3FrameTy, len: usize) -> crate::Result<()> {
  let mut header = [0u8; 16];
  let len = u64::try_from(len).unwrap_or(u64::MAX);
  let Some(header_len) = encode_frame_header(ty, len, &mut header) else {
    cold_path();
    return Err(crate::Error::Http3(Http3Error::BufferTooSmall));
  };
  out.extend_from_copyable_slice(header.get(..header_len).unwrap_or_default())?;
  Ok(())
}

// The same storage for a list of fields of another lifetime: empty, it is collected in place.
fn recycle<'to>(mut list: Vec<(&[u8], &[u8])>) -> Vec<(&'to [u8], &'to [u8])> {
  list.clear();
  list.into_iter().map(|_| (&[][..], &[][..])).collect()
}

// Refuses stream `id`, which has no request: after a GOAWAY.
fn reject(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  id: StreamId,
  code: H3ErrorCode,
) -> crate::Result<()> {
  cx.reset(id, code.code());
  cx.stop_sending(id, code.code());
  conn.decoder.on_stream_cancelled(id.0)
}

// The peer reset stream `id`.
fn reset_by_peer(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  id: StreamId,
) -> crate::Result<()> {
  if [conn.peer_control, conn.peer_encoder, conn.peer_decoder].contains(&Some(id)) {
    return Err(closed_critical_stream());
  }
  if !id.is_client_bidi() {
    return Ok(());
  }
  // The request is abandoned, and its references to the dynamic table with it (RFC 9204 section
  // 4.4.2), and so is what would answer it: the sending part is reset, unless it has its FIN (a
  // 413 or 431 that answered already, which a reset could cut) or was reset (a stream error)
  conn.decoder.on_stream_cancelled(id.0)?;
  if let Some(idx) = conn.req_idx(id) {
    conn.free_req(idx);
  }
  if !cx.write_closed(id) {
    cx.reset(id, H3ErrorCode::RequestCancelled.code());
  }
  Ok(())
}

// The payload of a frame that is one variable-length integer.
fn single_varint(payload: &[u8]) -> crate::Result<u64> {
  match decode_varint(payload) {
    Some((value, len)) if len == payload.len() => Ok(value),
    _ => {
      cold_path();
      Err(close(H3ErrorCode::FrameError, Http3Error::MalformedFrame))
    }
  }
}

// The peer asked us to stop sending on stream `id`.
fn stopped_by_peer(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  id: StreamId,
) -> crate::Result<()> {
  if [conn.control, conn.encoder_stream, conn.decoder_stream].contains(&id) {
    return Err(closed_critical_stream());
  }
  let Some(idx) = conn.req_idx(id) else {
    return Ok(());
  };
  // Nothing will be answered: what is left of the request is not read
  if conn.reqs.get(idx).is_some_and(|el| el.phase != Phase::Parked) {
    cx.stop_sending(id, H3ErrorCode::RequestCancelled.code());
    conn.decoder.on_stream_cancelled(id.0)?;
  }
  conn.free_req(idx);
  Ok(())
}

// A stream error on request `idx` (RFC 9114 section 8): RESET_STREAM and STOP_SENDING with `code`.
fn stream_error(
  conn: &mut H3Conn,
  cx: &mut ConnCtx<'_, H3ConnState>,
  idx: usize,
  code: H3ErrorCode,
) -> crate::Result<()> {
  let Some(id) = conn.reqs.get(idx).map(|el| el.id) else {
    return Ok(());
  };
  cx.reset(id, code.code());
  cx.stop_sending(id, code.code());
  conn.decoder.on_stream_cancelled(id.0)?;
  conn.free_req(idx);
  Ok(())
}

#[cold]
fn unexpected_frame() -> crate::Error {
  close(H3ErrorCode::FrameUnexpected, Http3Error::UnexpectedFrame)
}

// One write of a HEADERS frame of `encoded_headers`, a DATA frame of `body` if it is not empty and
// the FIN, put together in `frame`.
fn write_response(
  cx: &mut ConnCtx<'_, H3ConnState>,
  frame: &mut VectorUsize<u8>,
  stream: StreamId,
  encoded_headers: &[u8],
  body: &[u8],
) -> crate::Result<()> {
  frame.clear();
  push_frame_header(frame, H3FrameTy::Headers, encoded_headers.len())?;
  frame.extend_from_copyable_slice(encoded_headers)?;
  if !body.is_empty() {
    push_frame_header(frame, H3FrameTy::Data, body.len())?;
    frame.extend_from_copyable_slice(body)?;
  }
  cx.write(stream, frame, true)
}

#[cfg(test)]
mod tests;
