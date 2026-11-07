//! Sans-I/O keep-alive HTTP/1.1 connection core.

use crate::{
  http::{HttpRecvParams, Method, StatusCode, Version},
  http1::{
    BodyDecoder, BodyKind, BodyStatus, Http1Request, ParseOutcome, ParseScratch, error_status,
    parse_request, write_response,
  },
};
use alloc::vec::Vec;

/// Maximum number of bytes buffered between two `poll_event` calls.
const BUF_CAP: usize = 256 * 1024;
/// Chunk framing, extensions and trailers a body may carry in addition to a quarter of its
/// payload.
const FRAMING_BUDGET: usize = 16 * 1024;

/// What a connection needs next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http1Event {
  /// A request is ready to be inspected through [`Http1Conn::request`].
  RequestReady,
  /// More input is required.
  NeedMore,
  /// The connection must be closed.
  Closed,
}

/// Keep-alive connection state.
///
/// The driver loop is: `feed` what was read, `poll_event` until it is not
/// [`Http1Event::RequestReady`] (answering each ready request with `respond`), flush the output
/// with `take_output` / `advance_output`, and close once `poll_event` returns
/// [`Http1Event::Closed`].
///
/// Memory is bounded: at most 256 KiB of unparsed input is buffered, a head is limited to 16 KiB
/// (and [`crate::http1::MAX_HEADERS`] headers) by the parser, and a decoded body to
/// [`HttpRecvParams::max_body_len`]. A request that breaks a limit, is malformed or uses an
/// unsupported transfer coding is answered with a `Connection: close` 413 / 431 / 400 / 501
/// response and the connection then reports [`Http1Event::Closed`] once that response is flushed.
#[derive(Debug)]
pub struct Http1Conn {
  /// Unparsed input; the live part is `buf[start..]`.
  buf: Vec<u8>,
  start: usize,
  /// Decoded body of the current request.
  body: Vec<u8>,
  out: Vec<u8>,
  /// Bytes handed out by `take_output` and not yet acknowledged by `advance_output`.
  inflight: usize,
  max_body_len: usize,
  phase: Phase,
  /// One element once a head was parsed, none before (see [`Self::scratch`]). A `Vec` and not a
  /// `Box`: moving a `Box` retags its pointee as unique, which invalidates the header slice
  /// `view` points to; moving a `Vec` does not.
  scratch: Vec<ParseScratch>,
  /// Points into `buf` and `scratch`; `Some` only while neither changed since it was set.
  view: Option<Http1Request<'static>>,
  closing: bool,
}

#[derive(Debug)]
enum Phase {
  /// Waiting for a complete head.
  Head,
  /// Head parsed (it stays at `buf[start..start + head_len]`), decoding the body.
  Body { decoder: BodyDecoder, head_len: usize, raw: usize },
  /// A complete request awaits `respond`. Its head and what is left of its body in the buffer
  /// (all of it unless it arrived over several feeds) occupy `buf[start..start + len]`.
  Ready { len: usize, keep_alive: bool, method: Method, version: Version },
}

/// Outcome of looking at the head in the buffer.
enum Head {
  Bad(StatusCode),
  Partial,
  Bodyless(Http1Request<'static>, usize),
  WithBody(BodyKind, usize),
}

/// The buffers of an [`Http1Conn`], to serve another connection with: what
/// [`Http1Conn::into_parts`] returns and [`Http1Conn::from_parts`] takes, so that a server can
/// keep them in a pool and open connections without allocating.
///
/// The buffers keep their capacity. What they hold is dropped by [`Self::clear`] or by
/// [`Http1Conn::from_parts`]. The default is a set of empty buffers, which a connection grows as
/// it needs.
#[derive(Debug, Default)]
pub struct Http1ConnParts {
  buf: Vec<u8>,
  body: Vec<u8>,
  out: Vec<u8>,
  scratch: Vec<ParseScratch>,
}

impl Http1ConnParts {
  /// Bytes the buffers hold room for.
  #[inline]
  pub fn capacity(&self) -> usize {
    let scratch = self.scratch.capacity().saturating_mul(size_of::<ParseScratch>());
    self
      .buf
      .capacity()
      .saturating_add(self.body.capacity())
      .saturating_add(self.out.capacity())
      .saturating_add(scratch)
  }

  /// Empties the buffers, keeping their capacity.
  #[inline]
  pub fn clear(&mut self) {
    self.buf.clear();
    self.body.clear();
    self.out.clear();
  }

  /// Frees every byte buffer whose capacity is above `max`, so that a pool keeps none that a
  /// large request or response grew. The parse scratch, of a fixed size, is kept.
  #[inline]
  pub fn free_larger_than(&mut self, max: usize) {
    for buffer in [&mut self.buf, &mut self.body, &mut self.out] {
      if buffer.capacity() > max {
        *buffer = Vec::new();
      }
    }
  }
}

impl Http1Conn {
  /// New connection on the buffers of an earlier one (see [`Self::into_parts`]): it allocates
  /// nothing until a request or a response needs more room than they have.
  #[inline]
  pub fn from_parts(params: &HttpRecvParams, parts: Http1ConnParts) -> Self {
    let Http1ConnParts { mut buf, mut body, mut out, mut scratch } = parts;
    buf.clear();
    body.clear();
    out.clear();
    scratch.truncate(1);
    Self {
      buf,
      start: 0,
      body,
      out,
      inflight: 0,
      max_body_len: usize::try_from(params.max_body_len()).unwrap_or(usize::MAX),
      phase: Phase::Head,
      scratch,
      view: None,
      closing: false,
    }
  }

  /// Ends the connection, returning its buffers for [`Self::from_parts`]. What is left of its
  /// input and output is discarded, by `from_parts` or [`Http1ConnParts::clear`].
  ///
  /// No view of a request survives: a request borrows the connection, which this consumes. The
  /// buffers are moved, not emptied, here: `self` is an argument and the request view it may
  /// hold points into them, so writing to them before this returns would invalidate that view
  /// while it is protected (Stacked Borrows).
  #[inline]
  pub fn into_parts(self) -> Http1ConnParts {
    let Self { buf, body, out, scratch, .. } = self;
    Http1ConnParts { buf, body, out, scratch }
  }

  /// New connection. Its buffers, the parse scratch included, are allocated as it needs them.
  #[inline]
  pub fn new(params: &HttpRecvParams) -> Self {
    Self::from_parts(params, Http1ConnParts::default())
  }

  /// Buffers `input`, returning how many bytes were consumed.
  ///
  /// Fewer than `input.len()` bytes are taken only when the buffer is full; call `poll_event`
  /// (and `respond`) and feed the rest afterwards. Input arriving after the connection started
  /// closing is discarded.
  #[inline]
  pub fn feed(&mut self, input: &[u8]) -> crate::Result<usize> {
    if self.closing {
      return Ok(input.len());
    }
    // Cleared before `buf` is touched in any way, even by an empty feed.
    self.view = None;
    if self.start > 0 {
      let _ = self.buf.drain(..self.start);
      self.start = 0;
    }
    let take = input.len().min(BUF_CAP.saturating_sub(self.buf.len()));
    if take > 0 {
      self.buf.extend_from_slice(input.get(..take).unwrap_or_default());
    }
    Ok(take)
  }

  /// Advances the state machine.
  #[inline]
  pub fn poll_event(&mut self) -> Http1Event {
    if self.closing {
      return if self.out.is_empty() && self.inflight == 0 {
        Http1Event::Closed
      } else {
        Http1Event::NeedMore
      };
    }
    if let Phase::Ready { .. } = self.phase {
      if self.view.is_none() && self.set_view().is_err() {
        return self.fail(StatusCode::BadRequest);
      }
      return Http1Event::RequestReady;
    }
    if let Phase::Head = self.phase {
      let (kind, head_len) = match self.parse_head() {
        Head::Bad(status) => return self.fail(status),
        Head::Partial => return Http1Event::NeedMore,
        Head::Bodyless(request, head_len) => {
          self.body.clear();
          self.view = Some(request);
          self.phase = Phase::Ready {
            len: head_len,
            keep_alive: request.keep_alive,
            method: request.method,
            version: request.version,
          };
          return Http1Event::RequestReady;
        }
        Head::WithBody(kind, head_len) => (kind, head_len),
      };
      if let BodyKind::ContentLength(len) = kind
        && len > self.max_body_len
      {
        return self.fail(StatusCode::PayloadTooLarge);
      }
      self.body.clear();
      self.phase = Phase::Body { decoder: BodyDecoder::new(kind), head_len, raw: 0 };
    }
    let Phase::Body { decoder, head_len, raw } = &mut self.phase else {
      return Http1Event::NeedMore;
    };
    let head_len = *head_len;
    let head_end = self.start.wrapping_add(head_len);
    let input = self.buf.get(head_end..).unwrap_or_default();
    let input_len = input.len();
    let status = match decoder.feed(input, &mut self.body) {
      Ok(status) => status,
      Err(_) => return self.fail(StatusCode::BadRequest),
    };
    // Only what belongs to this body counts, not the pipelined requests after it.
    let taken = match status {
      BodyStatus::NeedMore => input_len,
      BodyStatus::Complete { consumed } => consumed,
    };
    *raw = raw.wrapping_add(taken);
    let overhead = raw.saturating_sub(self.body.len());
    let too_large = self.body.len() > self.max_body_len
      || overhead > FRAMING_BUDGET.saturating_add(self.body.len() / 4);
    if too_large {
      return self.fail(StatusCode::PayloadTooLarge);
    }
    match status {
      BodyStatus::NeedMore => {
        // Everything after the head went through the decoder, so it is not kept.
        self.buf.truncate(head_end);
        Http1Event::NeedMore
      }
      BodyStatus::Complete { consumed } => {
        // The body stays in the buffer: `respond` moves `start` past it, so the pipelined
        // input after it is never moved.
        let request = match self.set_view() {
          Ok(request) => request,
          Err(_) => return self.fail(StatusCode::BadRequest),
        };
        self.phase = Phase::Ready {
          len: head_len.wrapping_add(consumed),
          keep_alive: request.keep_alive,
          method: request.method,
          version: request.version,
        };
        Http1Event::RequestReady
      }
    }
  }

  /// Current request. Valid only right after [`Http1Event::RequestReady`], and until the next
  /// `feed` or `respond`.
  #[inline]
  pub fn request(&self) -> Option<Http1Request<'_>> {
    // Shortens the placeholder `'static` to the borrow of `self`.
    self.view
  }

  /// Decoded body of the current request; empty when it has none. Same validity as
  /// [`Self::request`].
  #[inline]
  pub fn body(&self) -> &[u8] {
    match self.phase {
      Phase::Ready { .. } => &self.body,
      _ => &[],
    }
  }

  /// Queues the response of the current request and moves on to the next buffered one.
  /// Does nothing if no request is ready.
  ///
  /// The request's method and version shape the response as [`write_response`] describes: no
  /// body for `HEAD`, no content for 204 / 304, `Connection: keep-alive` for HTTP/1.0.
  ///
  /// `status` must be final (2xx to 5xx): a response ends the request, so an informational 1xx
  /// would be taken by the client as an interim response before the real one that never comes,
  /// and the connection would desynchronize.
  #[inline]
  pub fn respond(&mut self, status: StatusCode, content_type: &str, body: &[u8]) {
    let Phase::Ready { len, keep_alive, method, version } = self.phase else {
      return;
    };
    write_response(&mut self.out, method, version, status, content_type, body, keep_alive);
    self.view = None;
    self.body.clear();
    self.phase = Phase::Head;
    if keep_alive {
      self.start = self.start.wrapping_add(len);
      if self.start >= self.buf.len() {
        self.buf.clear();
        self.start = 0;
      }
    } else {
      self.closing = true;
      self.buf.clear();
      self.start = 0;
    }
  }

  /// Takes the pending output, swapping in `spare`. Returns `spare` back in `Err` if there is
  /// nothing to send. The taken bytes count as in flight until `advance_output` acknowledges
  /// them.
  #[inline]
  pub fn take_output(&mut self, mut spare: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
    if self.out.is_empty() {
      return Err(spare);
    }
    spare.clear();
    let taken = core::mem::replace(&mut self.out, spare);
    self.inflight = self.inflight.wrapping_add(taken.len());
    Ok(taken)
  }

  /// Marks `n` bytes of the taken output as sent.
  #[inline]
  pub fn advance_output(&mut self, n: usize) {
    self.inflight = self.inflight.saturating_sub(n);
  }

  /// If no request head has been parsed since the last response: the connection waits for (more
  /// of) one. `false` while a body is being received or a request awaits its response.
  #[inline]
  pub fn awaits_head(&self) -> bool {
    matches!(self.phase, Phase::Head)
  }

  /// If the connection should be closed once the output is flushed.
  #[inline]
  pub fn wants_close(&self) -> bool {
    self.closing
  }

  /// The parse scratch, made by the first head of a connection that has none. Called with no
  /// view set, as a push would move the scratch the view points to.
  fn scratch(scratch: &mut Vec<ParseScratch>) -> Option<&mut ParseScratch> {
    if scratch.is_empty() {
      scratch.push(ParseScratch::new());
    }
    scratch.first_mut()
  }

  /// Parses the head at the front of the live input.
  fn parse_head(&mut self) -> Head {
    let input = self.buf.get(self.start..).unwrap_or_default();
    let Some(scratch) = Self::scratch(&mut self.scratch) else {
      return Head::Bad(StatusCode::InternalServerError);
    };
    match parse_request(input, scratch) {
      Err(err) => Head::Bad(error_status(&err)),
      Ok(ParseOutcome::Partial) => Head::Partial,
      Ok(ParseOutcome::Complete { request, head_len }) => match request.body_kind {
        BodyKind::None | BodyKind::ContentLength(0) => {
          // SAFETY: `request` points into `self.buf` and `self.scratch`, heap data that does not
          // move, and is not retagged, when `self` moves (both are `Vec`s). `self.view` is
          // cleared before either changes.
          let request =
            unsafe { core::mem::transmute::<Http1Request<'_>, Http1Request<'static>>(request) };
          Head::Bodyless(request, head_len)
        }
        kind => Head::WithBody(kind, head_len),
      },
    }
  }

  /// Parses the head again to set `view`, returning it.
  fn set_view(&mut self) -> crate::Result<Http1Request<'static>> {
    let input = self.buf.get(self.start..).unwrap_or_default();
    let scratch = Self::scratch(&mut self.scratch).ok_or(crate::http::HttpError::BadRequest)?;
    match parse_request(input, scratch)? {
      ParseOutcome::Complete { request, .. } => {
        // SAFETY: same as in `parse_head`.
        let request =
          unsafe { core::mem::transmute::<Http1Request<'_>, Http1Request<'static>>(request) };
        self.view = Some(request);
        Ok(request)
      }
      ParseOutcome::Partial => Err(crate::http::HttpError::BadRequest.into()),
    }
  }

  /// Answers with an error, stops reading and starts closing.
  fn fail(&mut self, status: StatusCode) -> Http1Event {
    write_response(&mut self.out, Method::Get, Version::Http1_1, status, "text/plain", b"", false);
    self.view = None;
    self.body.clear();
    self.buf.clear();
    self.start = 0;
    self.phase = Phase::Head;
    self.closing = true;
    Http1Event::NeedMore
  }
}

#[cfg(test)]
mod tests {
  use crate::{
    http::{HttpRecvParams, Method, StatusCode},
    http1::{BodyKind, Http1Conn, Http1ConnParts, Http1Event},
  };
  use alloc::{boxed::Box, vec, vec::Vec};

  const GET: &[u8] = b"GET /plaintext?x=1 HTTP/1.1\r\nHost: a\r\n\r\n";
  const POST_CL: &[u8] = b"POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\n20";
  const POST_CHUNKED: &[u8] =
    b"POST /upload HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n2\r\n1\r\n0\r\n0\r\n\r\n";
  const CLOSE: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";

  fn conn() -> Http1Conn {
    Http1Conn::new(&HttpRecvParams::with_default_params())
  }

  fn answer(conn: &mut Http1Conn) {
    conn.respond(StatusCode::Ok, "text/plain", b"ok");
  }

  fn output(conn: &mut Http1Conn) -> Vec<u8> {
    let out = conn.take_output(Vec::new()).unwrap_or_default();
    conn.advance_output(out.len());
    out
  }

  fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack.windows(needle.len()).filter(|w| *w == needle).count()
  }

  #[test]
  fn get_request_ready_then_needmore() {
    let mut c = conn();
    assert_eq!(c.feed(GET).unwrap(), GET.len());
    assert_eq!(c.poll_event(), Http1Event::RequestReady);
    let request = c.request().unwrap();
    assert_eq!(request.method, Method::Get);
    assert_eq!(request.path, "/plaintext");
    assert_eq!(request.query, "x=1");
    assert!(request.keep_alive);
    assert!(c.body().is_empty());
    answer(&mut c);
    assert!(c.request().is_none());
    assert_eq!(c.poll_event(), Http1Event::NeedMore);
    assert!(!c.wants_close());
    assert!(output(&mut c).starts_with(b"HTTP/1.1 200 OK\r\n"));
  }

  #[test]
  fn post_body_available() {
    for raw in [POST_CL, POST_CHUNKED] {
      let mut c = conn();
      c.feed(raw).unwrap();
      assert_eq!(c.poll_event(), Http1Event::RequestReady);
      assert_eq!(c.request().unwrap().method, Method::Post);
      assert_eq!(c.body(), b"20");
      answer(&mut c);
      assert_eq!(c.poll_event(), Http1Event::NeedMore);
      assert!(c.body().is_empty());
    }
  }

  #[test]
  fn pipelined_two_requests() {
    let mut c = conn();
    let both = [GET, GET].concat();
    c.feed(&both).unwrap();
    for _ in 0..2 {
      assert_eq!(c.poll_event(), Http1Event::RequestReady);
      assert_eq!(c.request().unwrap().path, "/plaintext");
      answer(&mut c);
    }
    assert_eq!(c.poll_event(), Http1Event::NeedMore);
    let out = output(&mut c);
    assert_eq!(count(&out, b"HTTP/1.1 200 OK\r\n"), 2);
  }

  #[test]
  fn pipelined_bodies_and_gets_mixed() {
    let mut c = conn();
    let all = [POST_CHUNKED, GET, POST_CL, GET].concat();
    c.feed(&all).unwrap();
    let mut seen = Vec::new();
    while c.poll_event() == Http1Event::RequestReady {
      seen.push((c.request().unwrap().method, c.body().to_vec()));
      answer(&mut c);
    }
    assert_eq!(
      seen,
      [
        (Method::Post, b"20".to_vec()),
        (Method::Get, Vec::new()),
        (Method::Post, b"20".to_vec()),
        (Method::Get, Vec::new())
      ]
    );
    assert_eq!(count(&output(&mut c), b"HTTP/1.1 200 OK\r\n"), 4);
  }

  #[test]
  fn request_split_across_feeds() {
    for raw in [GET, POST_CL, POST_CHUNKED] {
      let mut c = conn();
      let mut ready = 0;
      for (idx, byte) in raw.iter().enumerate() {
        c.feed(&[*byte]).unwrap();
        match c.poll_event() {
          Http1Event::RequestReady => {
            assert_eq!(idx, raw.len() - 1);
            ready += 1;
          }
          event => assert_eq!(event, Http1Event::NeedMore),
        }
      }
      assert_eq!(ready, 1);
      if raw != GET {
        assert_eq!(c.body(), b"20");
      }
      answer(&mut c);
      assert_eq!(c.poll_event(), Http1Event::NeedMore);
    }
  }

  #[test]
  fn connection_close_sets_wants_close() {
    let mut c = conn();
    c.feed(&[CLOSE, GET].concat()).unwrap();
    assert_eq!(c.poll_event(), Http1Event::RequestReady);
    assert!(!c.request().unwrap().keep_alive);
    assert!(!c.wants_close());
    answer(&mut c);
    assert!(c.wants_close());
    // Output not flushed yet.
    assert_eq!(c.poll_event(), Http1Event::NeedMore);
    let out = c.take_output(Vec::new()).unwrap();
    assert!(out.windows(19).any(|w| w == b"Connection: close\r\n"));
    assert_eq!(c.poll_event(), Http1Event::NeedMore);
    c.advance_output(out.len());
    assert_eq!(c.poll_event(), Http1Event::Closed);
    // The pipelined request after the close is dropped.
    assert_eq!(c.feed(GET).unwrap(), GET.len());
    assert_eq!(c.poll_event(), Http1Event::Closed);
  }

  #[test]
  fn request_survives_feed_after_ready() {
    let mut c = conn();
    c.feed(POST_CL).unwrap();
    assert_eq!(c.poll_event(), Http1Event::RequestReady);
    c.feed(GET).unwrap();
    assert!(c.request().is_none());
    assert_eq!(c.poll_event(), Http1Event::RequestReady);
    assert_eq!(c.request().unwrap().body_kind, BodyKind::ContentLength(2));
    assert_eq!(c.body(), b"20");
    answer(&mut c);
    assert_eq!(c.poll_event(), Http1Event::RequestReady);
    assert_eq!(c.request().unwrap().method, Method::Get);
  }

  #[test]
  fn empty_feed_midpipeline_clears_view() {
    let second: &[u8] = b"GET /second HTTP/1.1\r\nHost: a\r\n\r\n";
    let mut c = conn();
    c.feed(&[GET, second].concat()).unwrap();
    assert_eq!(c.poll_event(), Http1Event::RequestReady);
    answer(&mut c);
    assert_eq!(c.poll_event(), Http1Event::RequestReady);
    assert_eq!(c.request().unwrap().path, "/second");
    assert_eq!(c.feed(&[]).unwrap(), 0);
    assert!(c.request().is_none());
    assert_eq!(c.poll_event(), Http1Event::RequestReady);
    assert_eq!(c.request().unwrap().path, "/second");
  }

  #[test]
  fn take_output_swaps_and_reports_empty() {
    let mut c = conn();
    assert_eq!(c.take_output(Vec::with_capacity(8)).unwrap_err().capacity(), 8);
    c.feed(GET).unwrap();
    c.poll_event();
    answer(&mut c);
    let out = c.take_output(Vec::new()).unwrap();
    assert!(c.take_output(Vec::new()).is_err());
    assert!(out.starts_with(b"HTTP/1.1 200 OK\r\n"));
  }

  #[test]
  fn oversized_content_length_is_rejected_then_closes() {
    let params = HttpRecvParams::with_default_params().set_max_body_len(4);
    let mut c = Http1Conn::new(&params);
    c.feed(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n").unwrap();
    assert_eq!(c.poll_event(), Http1Event::NeedMore);
    assert!(c.wants_close());
    let out = output(&mut c);
    assert!(out.starts_with(b"HTTP/1.1 413 "));
    assert_eq!(c.poll_event(), Http1Event::Closed);
  }

  #[test]
  fn oversized_chunked_body_is_rejected() {
    let params = HttpRecvParams::with_default_params().set_max_body_len(4);
    let mut c = Http1Conn::new(&params);
    c.feed(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n")
      .unwrap();
    assert_eq!(c.poll_event(), Http1Event::NeedMore);
    assert!(!c.wants_close());
    c.feed(b"3\r\ndef\r\n").unwrap();
    assert_eq!(c.poll_event(), Http1Event::NeedMore);
    assert!(c.wants_close());
    assert!(output(&mut c).starts_with(b"HTTP/1.1 413 "));
    assert_eq!(c.poll_event(), Http1Event::Closed);
  }

  #[test]
  fn endless_trailer_is_bounded() {
    let mut c = conn();
    c.feed(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n").unwrap();
    let junk = [b'a'; 1024];
    let mut closed = false;
    for _ in 0..64 {
      c.feed(&junk).unwrap();
      c.poll_event();
      if c.wants_close() {
        closed = true;
        break;
      }
    }
    assert!(closed);
    assert!(output(&mut c).starts_with(b"HTTP/1.1 413 "));
  }

  #[test]
  fn malformed_heads_get_400() {
    let mut c = conn();
    c.feed(b"NOPE\r\n\r\n").unwrap();
    assert_eq!(c.poll_event(), Http1Event::NeedMore);
    assert!(c.wants_close());
    assert!(output(&mut c).starts_with(b"HTTP/1.1 400 "));
    assert_eq!(c.poll_event(), Http1Event::Closed);
  }

  #[test]
  fn oversized_heads_get_431() {
    let mut c = conn();
    let mut head = b"GET / HTTP/1.1\r\nHost: a\r\nX: ".to_vec();
    head.resize(20 * 1024, b'a');
    c.feed(&head).unwrap();
    c.poll_event();
    assert!(c.wants_close());
    assert!(output(&mut c).starts_with(b"HTTP/1.1 431 "));
    assert_eq!(c.poll_event(), Http1Event::Closed);

    let mut c = conn();
    let mut head = b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec();
    for i in 0..crate::http1::MAX_HEADERS {
      head.extend_from_slice(alloc::format!("X-{i}: v\r\n").as_bytes());
    }
    head.extend_from_slice(b"\r\n");
    c.feed(&head).unwrap();
    c.poll_event();
    assert!(c.wants_close());
    assert!(output(&mut c).starts_with(b"HTTP/1.1 431 "));
  }

  /// Answers every ready request, returning how many there were.
  fn answer_all(conn: &mut Http1Conn) -> usize {
    let mut answered = 0;
    while conn.poll_event() == Http1Event::RequestReady {
      answered += 1;
      answer(conn);
    }
    answered
  }

  #[test]
  fn body_then_large_pipeline_is_not_too_large() {
    let get: &[u8] = b"GET /ping HTTP/1.1\r\nHost: a\r\n\r\n";
    let n = 17 * 1024 / get.len() + 1;
    for first in [POST_CL, POST_CHUNKED] {
      let mut input = first.to_vec();
      for _ in 0..n {
        input.extend_from_slice(get);
      }
      let mut c = conn();
      assert_eq!(c.feed(&input).unwrap(), input.len());
      assert_eq!(answer_all(&mut c), n + 1);
      assert!(!c.wants_close());
      let out = output(&mut c);
      assert_eq!(count(&out, b"HTTP/1.1 200 OK\r\n"), n + 1);
      assert_eq!(count(&out, b" 413 "), 0);
    }
  }

  #[test]
  fn many_pipelined_small_posts_are_all_answered() {
    let post: &[u8] = b"POST /e HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nx";
    let mut input = Vec::new();
    while input.len() + post.len() < 250 * 1024 {
      input.extend_from_slice(post);
    }
    let n = input.len() / post.len();
    let mut c = conn();
    assert_eq!(c.feed(&input).unwrap(), input.len());
    assert_eq!(answer_all(&mut c), n);
    assert!(!c.wants_close());
    assert_eq!(count(&output(&mut c), b"HTTP/1.1 200 OK\r\n"), n);
  }

  #[test]
  fn pipelined_bodies_do_not_move_the_tail() {
    // Every request is answered in place: nothing of the buffered input is moved per request,
    // which would make a large batch quadratic.
    let mut input = Vec::new();
    for _ in 0..64 {
      input.extend_from_slice(POST_CL);
      input.extend_from_slice(POST_CHUNKED);
    }
    let mut c = conn();
    c.feed(&input).unwrap();
    let mut answered = 0;
    while c.poll_event() == Http1Event::RequestReady {
      assert_eq!(c.buf.len(), input.len(), "request {answered}");
      assert_eq!(c.body(), b"20");
      answered += 1;
      answer(&mut c);
    }
    assert_eq!(answered, 128);
  }

  #[test]
  fn crlf_after_a_body_is_skipped() {
    let mut c = conn();
    c.feed(&[POST_CL, b"\r\n", GET].concat()).unwrap();
    assert_eq!(answer_all(&mut c), 2);
    assert!(!c.wants_close());
  }

  #[test]
  fn unknown_transfer_coding_gets_501() {
    let mut c = conn();
    c.feed(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n").unwrap();
    assert_eq!(c.poll_event(), Http1Event::NeedMore);
    assert!(c.wants_close());
    assert!(output(&mut c).starts_with(b"HTTP/1.1 501 "));
    assert_eq!(c.poll_event(), Http1Event::Closed);
  }

  /// Run it under Miri with Stacked Borrows: moving the connection while a request view is live
  /// must not invalidate the view.
  #[test]
  fn moving_the_conn_keeps_the_view_valid() {
    #[inline(never)]
    fn pass(conn: Http1Conn) -> Http1Conn {
      conn
    }
    for raw in [GET, POST_CL] {
      let mut c = conn();
      c.feed(raw).unwrap();
      assert_eq!(c.poll_event(), Http1Event::RequestReady);
      let c = pass(c);
      let mut c = *alloc::boxed::Box::new(c);
      let request = c.request().unwrap();
      assert_eq!(request.headers[0], ("Host", "a"));
      assert_eq!(c.poll_event(), Http1Event::RequestReady);
      assert_eq!(c.request().unwrap().headers[0], ("Host", "a"));
      answer(&mut c);
    }
  }

  #[test]
  fn http10_keep_alive_is_announced() {
    let answered = |raw: &[u8]| {
      let mut c = conn();
      c.feed(raw).unwrap();
      assert_eq!(c.poll_event(), Http1Event::RequestReady);
      answer(&mut c);
      alloc::string::String::from_utf8(output(&mut c)).unwrap()
    };
    let out = answered(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
    assert!(out.contains("\r\nConnection: keep-alive\r\n"), "{out}");
    let out = answered(b"POST / HTTP/1.0\r\nConnection: keep-alive\r\nContent-Length: 1\r\n\r\nx");
    assert!(out.contains("\r\nConnection: keep-alive\r\n"), "{out}");
    let out = answered(b"GET / HTTP/1.0\r\n\r\n");
    assert!(out.contains("\r\nConnection: close\r\n"), "{out}");
    let out = answered(GET);
    assert!(!out.contains("Connection:"), "{out}");
  }

  #[test]
  fn head_response_has_length_but_no_body() {
    let mut c = conn();
    c.feed(&[b"HEAD /x HTTP/1.1\r\nHost: a\r\n\r\n".as_slice(), GET].concat()).unwrap();
    assert_eq!(c.poll_event(), Http1Event::RequestReady);
    assert_eq!(c.request().unwrap().method, Method::Head);
    c.respond(StatusCode::Ok, "text/plain", b"hello");
    assert_eq!(c.poll_event(), Http1Event::RequestReady);
    c.respond(StatusCode::Ok, "text/plain", b"hello");
    assert_eq!(
      output(&mut c),
      b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n\
        HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
    );
  }

  #[test]
  fn no_content_and_not_modified_have_no_body_nor_length() {
    for (status, line) in [
      (StatusCode::NoContent, &b"HTTP/1.1 204 No Content\r\n"[..]),
      (StatusCode::NotModified, b"HTTP/1.1 304 Not Modified\r\n"),
    ] {
      let mut c = conn();
      c.feed(GET).unwrap();
      assert_eq!(c.poll_event(), Http1Event::RequestReady);
      c.respond(status, "text/plain", b"ignored");
      assert_eq!(output(&mut c), [line, b"\r\n"].concat());
    }
  }

  #[test]
  fn feed_is_bounded_without_polling() {
    let mut c = conn();
    let big = vec![b'a'; 1024 * 1024];
    let taken = c.feed(&big).unwrap();
    assert!(taken < big.len());
    assert_eq!(c.feed(&big).unwrap(), 0);
  }

  /// GET, POST with a Content-Length and chunked, a pipelined `pair` and a closing GET, all
  /// answered, the output taken with `spare`.
  fn serve_all(conn: &mut Http1Conn, pair: &[u8], spare: &mut Vec<u8>) -> usize {
    let mut answered = 0;
    for raw in [GET, POST_CL, POST_CHUNKED, pair, CLOSE] {
      assert_eq!(conn.feed(raw).unwrap(), raw.len());
      answered += answer_all(conn);
      if let Ok(out) = conn.take_output(core::mem::take(spare)) {
        conn.advance_output(out.len());
        *spare = out;
      }
    }
    answered
  }

  // A connection made of the parts of an earlier one, all of whose buffers have reached their
  // size, serves the same requests without allocating.
  #[cfg(not(miri))]
  #[test]
  fn recycled_parts_allocate_nothing() {
    use crate::{sync::AtomicU64, tests::_count_allocations_in};
    use core::sync::atomic::Ordering;
    static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
    let params = HttpRecvParams::with_default_params();
    let pair = [GET, POST_CL].concat();
    let mut spare = Vec::new();
    let mut parts = Http1ConnParts::default();
    for _ in 0..3 {
      let mut c = Http1Conn::from_parts(&params, parts);
      assert_eq!(serve_all(&mut c, &pair, &mut spare), 6);
      parts = c.into_parts();
    }
    _count_allocations_in(&ALLOCATIONS);
    let before = ALLOCATIONS.load(Ordering::SeqCst);
    for _ in 0..20 {
      let mut c = Http1Conn::from_parts(&params, parts);
      let _ = serve_all(&mut c, &pair, &mut spare);
      parts = c.into_parts();
    }
    let after = ALLOCATIONS.load(Ordering::SeqCst);
    assert_eq!(after - before, 0, "allocations of 20 connections on recycled parts");
  }

  // Parts taken from a connection whose request view is live, or in the middle of a body, and
  // moved around, make a connection that sees none of the earlier requests: no view, no body, no
  // input, no output; its own requests are seen whole. Run under Miri, for the views into the
  // recycled buffers.
  #[test]
  fn recycled_parts_hold_no_stale_view() {
    fn pass(parts: Http1ConnParts) -> Http1ConnParts {
      let boxed = Box::new(parts);
      *boxed
    }
    let params = HttpRecvParams::with_default_params();
    let second: &[u8] = b"GET /second?y=2 HTTP/1.1\r\nHost: b\r\nX: z\r\n\r\n";
    let partial_body: &[u8] =
      b"POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\n12345";
    let mut parts = Http1ConnParts::default();
    for round in 0..3 {
      let mut c = Http1Conn::from_parts(&params, parts);
      assert!(c.request().is_none());
      assert!(c.body().is_empty());
      assert_eq!(c.poll_event(), Http1Event::NeedMore);
      assert!(c.take_output(Vec::new()).is_err());
      c.feed(&[POST_CL, second].concat()).unwrap();
      assert_eq!(c.poll_event(), Http1Event::RequestReady);
      assert_eq!(c.request().unwrap().path, "/upload");
      assert_eq!(c.body(), b"20");
      answer(&mut c);
      assert_eq!(c.poll_event(), Http1Event::RequestReady);
      let request = c.request().unwrap();
      assert_eq!((request.path, request.query), ("/second", "y=2"));
      assert_eq!(request.headers[1], ("X", "z"));
      if round == 1 {
        // In the middle of a body instead, the view cleared by the feed
        answer(&mut c);
        c.feed(partial_body).unwrap();
        assert_eq!(c.poll_event(), Http1Event::NeedMore);
      }
      parts = pass(c.into_parts());
      if round == 2 {
        // As a pool does it, with the view gone
        parts.clear();
        parts.free_larger_than(64);
      }
    }
    let mut c = Http1Conn::from_parts(&params, parts);
    c.feed(GET).unwrap();
    assert_eq!(c.poll_event(), Http1Event::RequestReady);
    let c = Box::new(c);
    assert_eq!(c.request().unwrap().headers[0], ("Host", "a"));
  }

  // A buffer above the cap is freed, the others keep their capacity.
  #[test]
  fn free_larger_than_frees_only_the_large_buffers() {
    let params = HttpRecvParams::with_default_params();
    let mut c = Http1Conn::new(&params);
    let big =
      [&b"POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 70000\r\n\r\n"[..], &[b'x'; 70_000]]
        .concat();
    c.feed(&big).unwrap();
    assert_eq!(c.poll_event(), Http1Event::RequestReady);
    assert_eq!(c.body().len(), 70_000);
    answer(&mut c);
    let mut parts = c.into_parts();
    parts.clear();
    assert!(parts.buf.capacity() >= 70_000 && parts.body.capacity() >= 70_000);
    assert!(parts.buf.is_empty() && parts.body.is_empty() && parts.out.is_empty());
    let out = parts.out.capacity();
    assert!(out > 0 && out < 1024, "{out}");
    parts.free_larger_than(1024);
    assert_eq!((parts.buf.capacity(), parts.body.capacity(), parts.out.capacity()), (0, 0, out));
    assert_eq!(parts.scratch.len(), 1);
  }
}
