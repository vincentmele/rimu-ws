//! What answers the requests of the connections of a worker: [`RouterHandler`], the
//! [`H3Handler`] that runs the router of the HTTP/2 framework, its middlewares and endpoints.
//!
//! A complete request is copied into a pooled request buffer, the one an [`AutoStream`] holds,
//! and its route looked up once. The future of the router (middlewares around the endpoint) is
//! pinned into a pooled slot and polled once, inline, in the turn that completed the request,
//! inside `catch_unwind`: a panic answers 500 on that stream only (spec section 5.12). A future
//! that completes is answered at once; one that waits is parked in its slot, whose waker records
//! the slot in a bounded queue of the worker and wakes the endpoint task, which resumes the
//! request through its connection ([`H3Handler::resume`], ruling T14-d). At most [`MAX_PARKED`]
//! requests wait at once; past that a request whose handler waits is answered with 503.
//!
//! Responses are encoded with the static table of QPACK. The field lines of `:status`,
//! `content-type`, `content-encoding` and `vary` are kept encoded per combination of their
//! values (a few of them per worker, the least recently used replaced), the line of `date` once a
//! second; `content-length` and the other fields are encoded per response. A body sent by
//! reference ([`AutoStream::shared_body`], the cached files of
//! [`StaticFiles`](crate::http::StaticFiles)) leaves without a copy ([`BodyRef`]).

// `std::task::Wake` is implemented for `alloc::sync::Arc` only.
#![allow(clippy::disallowed_types, reason = "`Waker::from` needs the standard `Arc`")]

use crate::{
  collections::{ArrayVectorCopy, VectorUsize},
  http::{
    AutoStream, Header, Headers, KnownHeaderName, Method, MsgBufferString, MsgDataMut as _,
    OperationMode, Request, StatusCode,
    date_header::format_imf_fixdate,
    http2_server_framework::{
      Endpoint as _, EndpointNode, Http2ServerFrameworkError, HttpRouter, Middleware, RouteMatch,
    },
    http3_server_framework::Http3ManualStream,
  },
  http3::{H3Handler, H3ReqCtx, H3Request, ReqOutcome, encode_static_line, encode_static_prefix},
  misc::{SharedBytes, from_utf8_basic},
  quic::{BodyRef, ConnHandle, StreamId},
  sync::{Arc, AtomicWaker, SyncMutex},
};
use alloc::{boxed::Box, rc::Rc};
use core::{
  hint::cold_path,
  panic::AssertUnwindSafe,
  pin::Pin,
  sync::atomic::{AtomicBool, Ordering},
  task::{Context, Poll, Waker},
};

/// The requests of a worker whose handlers wait at once, at most.
pub(crate) const MAX_PARKED: usize = 1024;
/// The combinations of the fields of a response that are kept encoded.
const MAX_BLOCKS: usize = 16;
/// The bytes of the values of a combination past which it is encoded per response.
const MAX_BLOCK_KEY: usize = 512;
/// The request buffers that a worker keeps for the next requests.
const MAX_MSGS: usize = 64;
/// The bytes of fields that a new request buffer has room for: a request, then its response,
/// rarely need more, and a buffer that does grows once and keeps the room.
const MSG_FIELDS: usize = 1024;
/// The bytes of URI that a new request buffer has room for.
const MSG_URI: usize = 256;
/// The capacity of the body of a request buffer that is kept.
const KEEP_BODY: usize = 64 * 1024;
/// What [`RouterHandler::trim_idle`] keeps of the request buffers and of the slots.
const IDLE_KEEP: usize = 4;

/// The routes of an endpoint found for a path, handed back to the endpoints.
pub(crate) type Matches = ArrayVectorCopy<RouteMatch, 4>;

/// What a [`RouterHandler`] runs: the future of a request, and the lookup of its route.
pub(crate) trait AutoDispatch {
  /// The data of the requests.
  type Data: Clone;
  /// The error of the endpoints.
  type Err: From<crate::Error>;
  /// The future of a request: the request back, with the response written into it, and the
  /// status, or the error of the endpoint.
  type Fut: Future<Output = (AutoStream<Self::Data>, Result<StatusCode, Self::Err>)>;

  /// The future of `auto_stream`, for the endpoints of `matches`.
  fn call(&self, auto_stream: AutoStream<Self::Data>, matches: Matches) -> Self::Fut;

  /// The route of `path`, if any.
  fn route(&self, path: &str) -> Option<(Matches, OperationMode)>;
}

/// The router of the framework, shared by the workers, reached by the futures of a worker through
/// an `Rc` of the worker: a request clones no atomic count.
pub(crate) struct FwRouter<DA, EN, ER, M> {
  router: Rc<Arc<HttpRouter<DA, EN, ER, M, Http3ManualStream>>>,
}

impl<DA, EN, ER, M> FwRouter<DA, EN, ER, M> {
  pub(crate) fn new(router: Arc<HttpRouter<DA, EN, ER, M, Http3ManualStream>>) -> Self {
    Self { router: Rc::new(router) }
  }
}

impl<DA, EN, ER, M> AutoDispatch for FwRouter<DA, EN, ER, M>
where
  DA: Clone + 'static,
  EN: EndpointNode<DA, ER, Http3ManualStream> + 'static,
  ER: From<crate::Error> + 'static,
  M: Middleware<DA, ER> + 'static,
{
  type Data = DA;
  type Err = ER;
  type Fut = impl Future<Output = (AutoStream<DA>, Result<StatusCode, ER>)>;

  fn call(&self, mut auto_stream: AutoStream<DA>, matches: Matches) -> Self::Fut {
    let router = Rc::clone(&self.router);
    async move {
      let rslt = router.auto(&mut auto_stream, (0, &matches)).await;
      (auto_stream, rslt)
    }
  }

  fn route(&self, path: &str) -> Option<(Matches, OperationMode)> {
    self.router.router.find(path).ok().map(|el| *el.data())
  }
}

/// What a [`RouterHandler`] counted.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HandlerCounters {
  /// Panics of handlers.
  pub(crate) panics: u64,
  /// Requests answered with 503 for want of a slot to wait in.
  pub(crate) park_refused: u64,
  /// Requests.
  pub(crate) requests: u64,
}

/// See the [module documentation](self).
pub(crate) struct RouterHandler<D, EC>
where
  D: AutoDispatch,
{
  counters: HandlerCounters,
  data: D::Data,
  date: Option<DateLine>,
  dispatch: D,
  error_cb: EC,
  head: ResponseHead,
  msgs: VectorUsize<MsgBufferString>,
  // The slot that the endpoint task resumes, set before it calls into the connection
  resuming: Option<u32>,
  slots: TaskSlots<D::Fut>,
}

impl<D, EC> RouterHandler<D, EC>
where
  D: AutoDispatch,
  EC: Fn(D::Err),
{
  /// The handler of a worker: `dispatch` runs the requests, with clones of `data`; with `date`,
  /// responses carry a `date` header.
  pub(crate) fn new(data: D::Data, date: bool, dispatch: D, error_cb: EC) -> crate::Result<Self> {
    Ok(Self {
      counters: HandlerCounters::default(),
      data,
      date: if date { Some(DateLine::new()?) } else { None },
      dispatch,
      error_cb,
      head: ResponseHead::new(),
      msgs: VectorUsize::new(),
      resuming: None,
      slots: TaskSlots::new(),
    })
  }

  /// What it counted.
  pub(crate) fn counters(&self) -> HandlerCounters {
    self.counters
  }

  /// The requests whose handlers wait.
  pub(crate) fn parked(&self) -> usize {
    self.slots.len
  }

  /// The slot of `idx`, woken: the connection and the stream of its request, if it holds one.
  /// The endpoint task resumes it next ([`Self::resume`]).
  pub(crate) fn prepare_resume(&mut self, idx: u32) -> Option<(ConnHandle, StreamId)> {
    let target = self.slots.target(idx)?;
    self.resuming = Some(idx);
    Some(target)
  }

  /// Drops the future of slot `idx`, whose connection is gone.
  pub(crate) fn release(&mut self, idx: u32) {
    self.resuming = None;
    self.slots.release(idx);
  }

  /// The start of a turn of the endpoint task, whose waker `cx` has: the slots that are woken
  /// wake it, and the `date` of the responses is the one of now.
  pub(crate) fn start_turn(&mut self, cx: &Context<'_>) -> crate::Result<()> {
    self.slots.shared.task.register(cx.waker());
    if let Some(elem) = &mut self.date {
      elem.refresh()?;
    }
    Ok(())
  }

  /// Moves the slots woken since the last call into `out`.
  pub(crate) fn take_woken(&self, out: &mut VectorUsize<u32>) -> crate::Result<()> {
    self.slots.take_woken(out)
  }

  /// Frees all but a few request buffers and, if no request waits, all but a few slots: for a
  /// worker that has had no connection for a while.
  pub(crate) fn trim_idle(&mut self) {
    self.msgs.truncate(IDLE_KEEP);
    self.slots.trim_idle(IDLE_KEEP);
  }

  // Answers with `status`, the fields of `msg` and its body, or `shared`, by reference.
  fn answer(
    &mut self,
    cx: &mut H3ReqCtx<'_, '_>,
    status: StatusCode,
    msg: MsgBufferString,
    shared: Option<SharedBytes>,
  ) -> crate::Result<ReqOutcome> {
    let body_len = shared.as_ref().map_or(msg.body.len(), SharedBytes::len);
    let date = self.date.as_ref().map(DateLine::line);
    let rslt = match self.head.encode(status, &msg.headers, body_len, date) {
      Ok(section) => match shared {
        Some(body) => BodyRef::try_from(body).and_then(|el| cx.respond_body(section, el)),
        None => cx.respond(section, msg.body.as_slice()),
      },
      Err(err) => Err(err),
    };
    self.recycle(msg);
    rslt.map(|()| ReqOutcome::Responded)
  }

  // Answers with `status` and nothing else of `msg`.
  fn answer_plain(
    &mut self,
    cx: &mut H3ReqCtx<'_, '_>,
    status: StatusCode,
    mut msg: MsgBufferString,
  ) -> crate::Result<ReqOutcome> {
    msg.clear();
    self.answer(cx, status, msg, None)
  }

  // Polls the future of slot `idx`, in the context of its request.
  fn poll(&mut self, cx: &mut H3ReqCtx<'_, '_>, idx: u32) -> crate::Result<ReqOutcome> {
    match self.slots.poll(idx) {
      SlotPoll::Pending => {
        if self.slots.len <= MAX_PARKED {
          return Ok(ReqOutcome::Parked);
        }
        cold_path();
        self.slots.release(idx);
        self.counters.park_refused = self.counters.park_refused.wrapping_add(1);
        let msg = self.take_msg()?;
        self.answer_plain(cx, StatusCode::ServiceUnavailable, msg)
      }
      SlotPoll::Done((auto_stream, rslt)) => {
        let AutoStream { req, shared_body, .. } = auto_stream;
        let mut msg = req.msg_data;
        match rslt {
          Ok(status) => self.answer(cx, status, msg, shared_body),
          Err(err) => {
            cold_path();
            (self.error_cb)(err);
            // What a failed handler left behind is not a response
            msg.clear();
            self.answer(cx, StatusCode::InternalServerError, msg, None)
          }
        }
      }
      SlotPoll::Panicked => {
        cold_path();
        self.counters.panics = self.counters.panics.wrapping_add(1);
        let msg = self.take_msg()?;
        self.answer_plain(cx, StatusCode::InternalServerError, msg)
      }
    }
  }

  // A request buffer of the pool, or a new one with room for the fields and the URI of most
  // requests and responses.
  fn take_msg(&mut self) -> crate::Result<MsgBufferString> {
    if let Some(elem) = self.msgs.pop() {
      return Ok(elem);
    }
    let mut msg = MsgBufferString::default();
    msg.headers.reserve(MSG_FIELDS)?;
    if msg.uri.reset().try_reserve(MSG_URI).is_err() {
      cold_path();
      return Err(crate::Error::Vector(crate::collections::VectorError::CapacityOverflow));
    }
    Ok(msg)
  }

  // A request buffer goes back to the pool, cleared and not too large.
  fn recycle(&mut self, mut msg: MsgBufferString) {
    msg.clear();
    if msg.body.capacity() > KEEP_BODY {
      msg.body = VectorUsize::new();
    }
    if self.msgs.len() < MAX_MSGS {
      let _rslt = self.msgs.push(msg);
    }
  }
}

impl<D, EC> H3Handler for RouterHandler<D, EC>
where
  D: AutoDispatch,
  EC: Fn(D::Err),
{
  #[inline]
  fn on_request(
    &mut self,
    cx: &mut H3ReqCtx<'_, '_>,
    req: &H3Request<'_>,
  ) -> crate::Result<ReqOutcome> {
    self.counters.requests = self.counters.requests.wrapping_add(1);
    let mut msg = self.take_msg()?;
    let method = match fill_request(&mut msg, req) {
      Ok(elem) => elem,
      Err(status) => return self.answer_plain(cx, status, msg),
    };
    let Some((matches, om)) = self.dispatch.route(msg.uri.path()) else {
      return self.answer_plain(cx, StatusCode::NotFound, msg);
    };
    if om == OperationMode::Manual {
      cold_path();
      (self.error_cb)(crate::Error::from(Http2ServerFrameworkError::OperationModeMismatch).into());
      return self.answer_plain(cx, StatusCode::InternalServerError, msg);
    }
    let auto_stream =
      AutoStream::new(self.data.clone(), cx.peer(), None, Request::new(method, msg));
    let fut = self.dispatch.call(auto_stream, matches);
    let idx = self.slots.insert(fut, cx.conn(), req.stream)?;
    self.poll(cx, idx)
  }

  #[inline]
  fn resume(&mut self, cx: &mut H3ReqCtx<'_, '_>, stream: StreamId) -> crate::Result<ReqOutcome> {
    let conn = cx.conn();
    let idx = self
      .resuming
      .take()
      .filter(|el| self.slots.target(*el) == Some((conn, stream)))
      .or_else(|| self.slots.find(conn, stream));
    let Some(idx) = idx else {
      cold_path();
      return Err(crate::Error::ProgrammingError);
    };
    self.poll(cx, idx)
  }

  #[inline]
  fn on_abandoned(&mut self, conn: ConnHandle, stream: StreamId) {
    if let Some(idx) = self.slots.find(conn, stream) {
      self.slots.release(idx);
    }
  }

  #[inline]
  fn on_conn_closed(&mut self, conn: ConnHandle) {
    self.slots.release_conn(conn);
  }
}

impl<D, EC> core::fmt::Debug for RouterHandler<D, EC>
where
  D: AutoDispatch,
{
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("RouterHandler")
      .field("counters", &self.counters)
      .field("parked", &self.slots.len)
      .finish_non_exhaustive()
  }
}

// The method, URI, fields and body of `req` into `msg`; the status of the answer if they can not
// be: an unknown method (501), a URI or a field that is not UTF-8, or that the buffer does not
// take (400).
fn fill_request(msg: &mut MsgBufferString, req: &H3Request<'_>) -> Result<Method, StatusCode> {
  let Ok(method) = Method::from_canonical_bytes(req.method) else {
    return Err(StatusCode::NotImplemented);
  };
  let authority = if req.authority.is_empty() {
    req.fields.iter().find(|el| el.0 == b"host").map_or(&[][..], |el| el.1)
  } else {
    req.authority
  };
  let (Ok(scheme), Ok(authority), Ok(path)) =
    (from_utf8_basic(req.scheme), from_utf8_basic(authority), from_utf8_basic(req.path))
  else {
    return Err(StatusCode::BadRequest);
  };
  {
    let mut uri = msg.uri.reset();
    uri.push_str(scheme);
    uri.push_str("://");
    uri.push_str(authority);
    uri.push_str(path);
  }
  for (name, value) in req.fields {
    let (Ok(name), Ok(value)) = (from_utf8_basic(name), from_utf8_basic(value)) else {
      return Err(StatusCode::BadRequest);
    };
    if msg.headers.push_from_iter(Header::new(false, false, name, [value])).is_err() {
      return Err(StatusCode::BadRequest);
    }
  }
  if msg.body.extend_from_copyable_slice(req.body).is_err() {
    return Err(StatusCode::InternalServerError);
  }
  Ok(method)
}

/// The `date` field line of the responses, encoded again when the second changes.
struct DateLine {
  line: VectorUsize<u8>,
  secs: u64,
}

impl DateLine {
  fn new() -> crate::Result<Self> {
    let mut this = Self { line: VectorUsize::new(), secs: u64::MAX };
    this.refresh()?;
    Ok(this)
  }

  fn line(&self) -> &[u8] {
    self.line.as_slice()
  }

  // Reads the clock and encodes the line again if the second changed.
  fn refresh(&mut self) -> crate::Result<()> {
    let secs = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map_or(0, |el| el.as_secs());
    if secs == self.secs {
      return Ok(());
    }
    self.secs = secs;
    let mut text = [0; 29];
    format_imf_fixdate(secs, &mut text);
    self.line.clear();
    encode_static_line(b"date", &text, &mut self.line)
  }
}

/// The field lines of `:status`, `content-type`, `content-encoding` and `vary` of a combination of
/// their values.
struct Block {
  key: VectorUsize<u8>,
  last_use: u64,
  lines: VectorUsize<u8>,
}

/// What encodes the field sections of the responses of a worker: see the
/// [module documentation](self).
struct ResponseHead {
  blocks: VectorUsize<Block>,
  key: VectorUsize<u8>,
  lower: VectorUsize<u8>,
  section: VectorUsize<u8>,
  uses: u64,
}

impl ResponseHead {
  const fn new() -> Self {
    Self {
      blocks: VectorUsize::new(),
      key: VectorUsize::new(),
      lower: VectorUsize::new(),
      section: VectorUsize::new(),
      uses: 0,
    }
  }

  // The field section of a response of `status`, `headers`, a body of `body_len` bytes and the
  // `date` line if any.
  fn encode(
    &mut self,
    status: StatusCode,
    headers: &Headers,
    body_len: usize,
    date: Option<&[u8]>,
  ) -> crate::Result<&[u8]> {
    let [mut content_type, mut content_encoding, mut vary] = [None; 3];
    for header in headers.iter() {
      let slot = match known(header.name.as_bytes()) {
        Some(Known::ContentType) => &mut content_type,
        Some(Known::ContentEncoding) => &mut content_encoding,
        Some(Known::Vary) => &mut vary,
        _ => continue,
      };
      if slot.is_none() {
        *slot = Some(header.value.as_bytes());
      }
    }
    self.section.clear();
    encode_static_prefix(&mut self.section)?;
    let fields = [content_type, content_encoding, vary];
    let idx = self.block(u16::from(status), fields)?;
    match idx.and_then(|el| self.blocks.get(el)) {
      Some(block) => self.section.extend_from_copyable_slice(block.lines.as_slice())?,
      None => write_block(u16::from(status), fields, &mut self.section)?,
    }
    if let Some(elem) = date {
      self.section.extend_from_copyable_slice(elem)?;
    }
    let mut digits = [0u8; 20];
    encode_static_line(b"content-length", decimal(body_len, &mut digits), &mut self.section)?;
    let mut firsts = [true; 3];
    for header in headers.iter() {
      let name = header.name.as_bytes();
      let first = match known(name) {
        Some(Known::ContentType) => firsts.get_mut(0),
        Some(Known::ContentEncoding) => firsts.get_mut(1),
        Some(Known::Vary) => firsts.get_mut(2),
        // Written above, or not sent over HTTP/3 (RFC 9114 section 4.2)
        Some(Known::ContentLength | Known::ConnectionSpecific) => continue,
        Some(Known::Date) if date.is_some() => continue,
        Some(Known::Date) | None => None,
      };
      if let Some(elem) = first
        && core::mem::replace(elem, false)
      {
        continue;
      }
      let name = if name.iter().any(u8::is_ascii_uppercase) {
        self.lower.clear();
        self.lower.extend_from_copyable_slice(name)?;
        self.lower.as_slice_mut().make_ascii_lowercase();
        self.lower.as_slice()
      } else {
        name
      };
      encode_static_line(name, header.value.as_bytes(), &mut self.section)?;
    }
    Ok(self.section.as_slice())
  }

  // The index of the block of `status` and `fields`, encoded now if it was not; `None` for values
  // too long to keep.
  fn block(&mut self, status: u16, fields: [Option<&[u8]>; 3]) -> crate::Result<Option<usize>> {
    self.uses = self.uses.wrapping_add(1);
    let values = fields.iter().flatten().map(|el| el.len()).sum::<usize>();
    if values > MAX_BLOCK_KEY {
      return Ok(None);
    }
    self.key.clear();
    self.key.extend_from_copyable_slice(&status.to_be_bytes())?;
    for field in fields {
      let len = field.map_or(u16::MAX, |el| u16::try_from(el.len()).unwrap_or(u16::MAX));
      self.key.extend_from_copyable_slice(&len.to_be_bytes())?;
      self.key.extend_from_copyable_slice(field.unwrap_or_default())?;
    }
    if let Some(idx) = self.blocks.iter().position(|el| el.key.as_slice() == self.key.as_slice()) {
      if let Some(block) = self.blocks.get_mut(idx) {
        block.last_use = self.uses;
      }
      return Ok(Some(idx));
    }
    let idx = if self.blocks.len() < MAX_BLOCKS {
      let block = Block { key: VectorUsize::new(), last_use: 0, lines: VectorUsize::new() };
      self.blocks.push(block)?;
      self.blocks.len().wrapping_sub(1)
    } else {
      let oldest = self.blocks.iter().enumerate().min_by_key(|el| el.1.last_use).map(|el| el.0);
      oldest.unwrap_or(0)
    };
    let Some(block) = self.blocks.get_mut(idx) else {
      return Ok(None);
    };
    block.key.clear();
    block.key.extend_from_copyable_slice(self.key.as_slice())?;
    block.lines.clear();
    block.last_use = self.uses;
    write_block(status, fields, &mut block.lines)?;
    Ok(Some(idx))
  }
}

// The fields of a response that the encoder treats apart.
#[derive(Clone, Copy)]
enum Known {
  ConnectionSpecific,
  ContentEncoding,
  ContentLength,
  ContentType,
  Date,
  Vary,
}

fn known(name: &[u8]) -> Option<Known> {
  let is = |known: KnownHeaderName| name.eq_ignore_ascii_case(<&str>::from(known).as_bytes());
  if is(KnownHeaderName::ContentType) {
    Some(Known::ContentType)
  } else if is(KnownHeaderName::ContentEncoding) {
    Some(Known::ContentEncoding)
  } else if is(KnownHeaderName::Vary) {
    Some(Known::Vary)
  } else if is(KnownHeaderName::ContentLength) {
    Some(Known::ContentLength)
  } else if is(KnownHeaderName::Date) {
    Some(Known::Date)
  } else if is(KnownHeaderName::Connection)
    || is(KnownHeaderName::KeepAlive)
    || is(KnownHeaderName::ProxyConnection)
    || is(KnownHeaderName::TransferEncoding)
    || is(KnownHeaderName::Upgrade)
  {
    Some(Known::ConnectionSpecific)
  } else {
    None
  }
}

// The lines of `:status` and of the fields of a block that are present, in that order.
fn write_block(
  status: u16,
  [content_type, content_encoding, vary]: [Option<&[u8]>; 3],
  out: &mut VectorUsize<u8>,
) -> crate::Result<()> {
  let mut digits = [0u8; 20];
  encode_static_line(b":status", decimal(status.into(), &mut digits), out)?;
  for (name, value) in
    [(&b"content-type"[..], content_type), (b"content-encoding", content_encoding), (b"vary", vary)]
  {
    if let Some(elem) = value {
      encode_static_line(name, elem, out)?;
    }
  }
  Ok(())
}

// `value` in decimal digits, written at the end of `buffer`.
fn decimal(mut value: usize, buffer: &mut [u8; 20]) -> &[u8] {
  let mut start = buffer.len();
  loop {
    start = start.wrapping_sub(1);
    if let Some(elem) = buffer.get_mut(start) {
      *elem = b'0'.wrapping_add((value % 10) as u8);
    }
    value /= 10;
    if value == 0 || start == 0 {
      break;
    }
  }
  buffer.get(start..).unwrap_or_default()
}

/// How the poll of a slot ended.
enum SlotPoll<T> {
  /// The future finished.
  Done(T),
  /// The future panicked; its slot is free again.
  Panicked,
  /// The future waits.
  Pending,
}

/// What wakes the endpoint task: the slots whose futures want another poll, each queued once.
struct WakeShared {
  task: AtomicWaker,
  woken: SyncMutex<VectorUsize<u32>>,
}

/// The waker of a slot.
struct SlotWaker {
  idx: u32,
  queued: AtomicBool,
  shared: Arc<WakeShared>,
}

impl std::task::Wake for SlotWaker {
  fn wake(self: alloc::sync::Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &alloc::sync::Arc<Self>) {
    if !self.queued.swap(true, Ordering::AcqRel) {
      // Room for every slot is reserved when the slot is made: no allocation here
      let _rslt = self.shared.woken.lock().push(self.idx);
    }
    self.shared.task.wake();
  }
}

/// A slot of a future: pinned once, used again without allocating.
struct Slot<F> {
  conn: ConnHandle,
  fut: Pin<Box<Option<F>>>,
  stream: StreamId,
  wake: alloc::sync::Arc<SlotWaker>,
  waker: Waker,
}

/// The slots of the futures of a worker.
struct TaskSlots<F> {
  free: VectorUsize<u32>,
  // The futures held
  len: usize,
  shared: Arc<WakeShared>,
  slots: VectorUsize<Slot<F>>,
}

impl<F> TaskSlots<F>
where
  F: Future,
{
  fn new() -> Self {
    Self {
      free: VectorUsize::new(),
      len: 0,
      shared: Arc::new(WakeShared {
        task: AtomicWaker::new(),
        woken: SyncMutex::new(VectorUsize::new()),
      }),
      slots: VectorUsize::new(),
    }
  }

  // The slot of the request of `stream` of `conn`, if a future waits for it.
  fn find(&self, conn: ConnHandle, stream: StreamId) -> Option<u32> {
    if self.len == 0 {
      return None;
    }
    let idx = self
      .slots
      .iter()
      .position(|el| el.fut.is_some() && el.conn == conn && el.stream == stream)?;
    u32::try_from(idx).ok()
  }

  // Pins `fut`, of the request of `stream` of `conn`, into a free slot.
  fn insert(&mut self, fut: F, conn: ConnHandle, stream: StreamId) -> crate::Result<u32> {
    let idx = if let Some(idx) = self.free.pop() {
      idx
    } else {
      let idx = u32::try_from(self.slots.len()).map_err(|_err| crate::Error::ProgrammingError)?;
      self.free.reserve(usize::try_from(idx).unwrap_or(usize::MAX).wrapping_add(1))?;
      self.shared.woken.lock().reserve(1)?;
      let wake = alloc::sync::Arc::new(SlotWaker {
        idx,
        queued: AtomicBool::new(false),
        shared: self.shared.clone(),
      });
      let waker = Waker::from(wake.clone());
      self.slots.push(Slot { conn, fut: Box::pin(None), stream, wake, waker })?;
      idx
    };
    let Some(slot) = self.slots.get_mut(usize::try_from(idx).unwrap_or(usize::MAX)) else {
      return Err(crate::Error::ProgrammingError);
    };
    slot.fut.as_mut().set(Some(fut));
    slot.conn = conn;
    slot.stream = stream;
    slot.wake.queued.store(false, Ordering::Release);
    self.len = self.len.wrapping_add(1);
    Ok(idx)
  }

  // Polls the future of slot `idx` with the waker of the slot, a panic caught and confined to it.
  fn poll(&mut self, idx: u32) -> SlotPoll<F::Output> {
    let Some(slot) = self.slots.get_mut(usize::try_from(idx).unwrap_or(usize::MAX)) else {
      return SlotPoll::Pending;
    };
    slot.wake.queued.store(false, Ordering::Release);
    let mut cx = Context::from_waker(&slot.waker);
    let fut = &mut slot.fut;
    let rslt = std::panic::catch_unwind(AssertUnwindSafe(|| {
      fut.as_mut().as_pin_mut().map(|el| el.poll(&mut cx))
    }));
    match rslt {
      Ok(None | Some(Poll::Pending)) => SlotPoll::Pending,
      Ok(Some(Poll::Ready(output))) => {
        self.release(idx);
        SlotPoll::Done(output)
      }
      Err(_) => {
        self.release(idx);
        SlotPoll::Panicked
      }
    }
  }

  // Drops the future of slot `idx`, if it holds one, and frees the slot.
  fn release(&mut self, idx: u32) {
    let Some(slot) = self.slots.get_mut(usize::try_from(idx).unwrap_or(usize::MAX)) else {
      return;
    };
    if slot.fut.is_none() {
      return;
    }
    // Dropping the future may run arbitrary code: it must not unwind into the worker
    let fut = &mut slot.fut;
    let _rslt = std::panic::catch_unwind(AssertUnwindSafe(|| fut.as_mut().set(None)));
    self.len = self.len.saturating_sub(1);
    // Room for every slot
    let _rslt = self.free.push(idx);
  }

  // Drops the futures of the requests of `conn`.
  fn release_conn(&mut self, conn: ConnHandle) {
    let mut idx = 0u32;
    while self.len > 0 && usize::try_from(idx).is_ok_and(|el| el < self.slots.len()) {
      if self
        .slots
        .get(usize::try_from(idx).unwrap_or(usize::MAX))
        .is_some_and(|el| el.fut.is_some() && el.conn == conn)
      {
        self.release(idx);
      }
      idx = idx.wrapping_add(1);
    }
  }

  // Moves the slots woken since the last call into `out`.
  fn take_woken(&self, out: &mut VectorUsize<u32>) -> crate::Result<()> {
    let mut woken = self.shared.woken.lock();
    out.extend_from_copyable_slice(woken.as_slice())?;
    woken.clear();
    Ok(())
  }

  // The connection and stream of the request of slot `idx`, if it holds a future.
  fn target(&self, idx: u32) -> Option<(ConnHandle, StreamId)> {
    let slot = self.slots.get(usize::try_from(idx).ok()?)?;
    slot.fut.is_some().then_some((slot.conn, slot.stream))
  }

  // Frees all but `keep` slots if no future is held. A waker of a slot that is gone queues an
  // index past the slots, which is ignored.
  fn trim_idle(&mut self, keep: usize) {
    if self.len != 0 || self.slots.len() <= keep {
      return;
    }
    self.slots.truncate(keep);
    self.free.clear();
    for idx in (0..self.slots.len()).rev() {
      let _rslt = self.free.push(u32::try_from(idx).unwrap_or(u32::MAX));
    }
  }
}
