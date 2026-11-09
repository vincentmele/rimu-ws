//! What answers the requests of the connections of a worker: [`RouterHandler`], the
//! [`H3Handler`] that runs the router of the HTTP/2 framework, its middlewares and endpoints.
//!
//! A complete request is copied into a pooled request buffer, the one an [`AutoStream`] holds,
//! with a fresh clone of the data of the server, as on HTTP/2, or, with `reuse_data` (an opt-in,
//! ruling T16-e), one that an earlier request of the worker used, so that a request clones no
//! shared counter in the steady state (ruling T16-a); its route is looked up once. The URI is put together from the pseudo-header fields
//! with the offsets that parsing it would find, without parsing it. The future of the router (middlewares around the endpoint) is
//! pinned into a pooled slot and polled once, inline, in the turn that completed the request,
//! inside `catch_unwind`: a panic answers 500 on that stream only (spec section 5.12). A future
//! that completes is answered at once; one that waits is parked in its slot, whose waker records
//! the slot in a bounded queue of the worker and wakes the endpoint task, which resumes the
//! request through its connection ([`H3Handler::resume`], ruling T14-d). At most [`MAX_PARKED`]
//! requests wait at once; past that a request whose handler waits is answered with 503.
//!
//! Responses are encoded with the static table of QPACK. The field lines of `:status`,
//! `content-type`, `content-encoding` and `vary` are kept encoded per combination of their
//! values (a few of them per worker, the least recently used replaced, the last one used looked
//! at first, without making its key), the line of `date` once a second; `content-length` and the
//! other fields are encoded per response, in a second pass over the fields that only a response
//! with such fields takes. A body sent by
//! reference ([`AutoStream::shared_body`], the cached files of
//! [`StaticFiles`](crate::http::StaticFiles)) leaves without a copy ([`BodyRef`]).
//!
//! RFC 9110 (ruling T14-i): a response to `HEAD` has the fields that `GET` would get,
//! `content-length` included, and no content (section 9.3.2); 1xx and 204 have neither content
//! nor `content-length` (section 8.6), 304 no content and no `content-length` (section 15.4.5).
//! `content-length` of the other responses can be left out (ruling T14-j), and by default it is,
//! like `date`: the lean default is not RFC 9110-compliant, see
//! [`Http3ServerFramework::set_rfc9110_headers`](super::Http3ServerFramework::set_rfc9110_headers).

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
  sync::{Arc, AtomicU64, AtomicWaker, SyncMutex},
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
///
/// The steady state allocates nothing while at most [`MAX_MSGS`] requests are under way at once
/// and their bodies fit in [`KEEP_BODY`]: past that, the request buffers of the requests above the
/// bound are freed when they end and made again by the next burst (Task 20 measures it).
pub(crate) const MAX_PARKED: usize = 1024;
/// The combinations of the fields of a response that are kept encoded.
const MAX_BLOCKS: usize = 16;
/// The bytes of the values of a combination past which it is encoded per response.
const MAX_BLOCK_KEY: usize = 512;
/// The request buffers that a worker keeps for the next requests: fewer than [`MAX_PARKED`], see
/// there for the bound of the steady state.
const MAX_MSGS: usize = 64;
/// The bytes of fields that a new request buffer has room for: a request, then its response,
/// rarely need more, and a buffer that does grows once and keeps the room.
const MSG_FIELDS: usize = 1024;
/// The bytes of URI that a new request buffer has room for.
const MSG_URI: usize = 256;
/// The capacity of the body of a request buffer that is kept: a buffer of a larger request or
/// response body is freed when it goes back to the pool (see [`MAX_PARKED`]).
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
  content_length: bool,
  counters: HandlerCounters,
  data: D::Data,
  // Clones of `data` that requests used, for the next ones, with `reuse_data`
  datas: VectorUsize<D::Data>,
  date: Option<DateLine>,
  reuse_data: bool,
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
  /// The handler of a worker: `dispatch` runs the requests, with clones of `data`; with
  /// `content_length`, responses with content carry `content-length`, and with `date` a `date`
  /// header.
  pub(crate) fn new(
    (data, reuse_data): (D::Data, bool),
    (content_length, date): (bool, bool),
    dispatch: D,
    error_cb: EC,
  ) -> crate::Result<Self> {
    Ok(Self {
      content_length,
      counters: HandlerCounters::default(),
      data,
      datas: VectorUsize::new(),
      date: if date { Some(DateLine::new()?) } else { None },
      reuse_data,
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
    self.datas.truncate(IDLE_KEEP);
    self.msgs.truncate(IDLE_KEEP);
    self.slots.trim_idle(IDLE_KEEP);
  }

  // Answers a request, of `HEAD` if `head`, with `status`, the fields of `msg` and its body, or
  // `shared`, by reference: no content, and no `content-length`, where RFC 9110 says so (see the
  // module documentation).
  fn answer(
    &mut self,
    cx: &mut H3ReqCtx<'_, '_>,
    head: bool,
    status: StatusCode,
    msg: MsgBufferString,
    shared: Option<SharedBytes>,
  ) -> crate::Result<ReqOutcome> {
    let code = u16::from(status);
    let without_length = (100..200).contains(&code) || code == 204 || code == 304;
    let body_len = shared.as_ref().map_or(msg.body.len(), SharedBytes::len);
    let length = if without_length {
      None
    } else if head || self.content_length {
      Some(body_len)
    } else {
      None
    };
    let date = self.date.as_ref().map(DateLine::line);
    let rslt = match self.head.encode(status, &msg.headers, length, date) {
      Ok(section) if head || without_length => cx.respond(section, &[]),
      Ok(section) => match shared {
        Some(body) => BodyRef::try_from(body).and_then(|el| cx.respond_body(section, el)),
        None => cx.respond(section, msg.body.as_slice()),
      },
      Err(err) => Err(err),
    };
    self.recycle(msg);
    rslt.map(|()| ReqOutcome::Responded)
  }

  // Answers a request, of `HEAD` if `head`, with `status` and nothing else of `msg`.
  fn answer_plain(
    &mut self,
    cx: &mut H3ReqCtx<'_, '_>,
    head: bool,
    status: StatusCode,
    mut msg: MsgBufferString,
  ) -> crate::Result<ReqOutcome> {
    msg.clear();
    self.answer(cx, head, status, msg, None)
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
        // Without content: the same for HEAD as for the other methods
        let msg = self.take_msg()?;
        self.answer_plain(cx, false, StatusCode::ServiceUnavailable, msg)
      }
      SlotPoll::Done((auto_stream, rslt)) => {
        let AutoStream { data, req, shared_body, .. } = auto_stream;
        if self.reuse_data && self.datas.len() < MAX_MSGS {
          let _rslt = self.datas.push(data);
        }
        let head = req.method == Method::Head;
        let mut msg = req.msg_data;
        match rslt {
          Ok(status) => self.answer(cx, head, status, msg, shared_body),
          Err(err) => {
            cold_path();
            (self.error_cb)(err);
            // What a failed handler left behind is not a response
            msg.clear();
            self.answer(cx, head, StatusCode::InternalServerError, msg, None)
          }
        }
      }
      SlotPoll::Panicked => {
        cold_path();
        self.counters.panics = self.counters.panics.wrapping_add(1);
        let msg = self.take_msg()?;
        self.answer_plain(cx, false, StatusCode::InternalServerError, msg)
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
    let head = req.method == b"HEAD";
    let method = match fill_request(&mut msg, req) {
      Ok(elem) => elem,
      Err(status) => return self.answer_plain(cx, head, status, msg),
    };
    let Some((matches, om)) = self.dispatch.route(msg.uri.path()) else {
      return self.answer_plain(cx, head, StatusCode::NotFound, msg);
    };
    if om == OperationMode::Manual {
      cold_path();
      (self.error_cb)(crate::Error::from(Http2ServerFrameworkError::OperationModeMismatch).into());
      return self.answer_plain(cx, head, StatusCode::InternalServerError, msg);
    }
    let data = match self.datas.pop() {
      Some(elem) => elem,
      None => self.data.clone(),
    };
    // Every handler, whatever its route, gets its request through the `AutoStream` (a `State`
    // borrows it), and the router picks the endpoint of the route by its matches: neither can be
    // left out with the same effect for the handler (ruling T16-a; building it moves pooled
    // buffers, it allocates nothing)
    let auto_stream = AutoStream::new(data, cx.peer(), None, Request::new(method, msg));
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
  let authority = if req.authority.is_empty() { req.host } else { req.authority };
  let (Ok(scheme), Ok(authority), Ok(path)) =
    (from_utf8_basic(req.scheme), from_utf8_basic(authority), from_utf8_basic(req.path))
  else {
    return Err(StatusCode::BadRequest);
  };
  msg.uri.set_from_parts(scheme, authority, path);
  // Checked once, when they were decoded, if they are ASCII (ruling T16-a); else here
  match req.fields.ascii() {
    Some(fields) => {
      for (name, value) in fields {
        if msg.headers.push_from_iter(Header::new(false, false, name, [value])).is_err() {
          return Err(StatusCode::BadRequest);
        }
      }
    }
    None => {
      for (name, value) in req.fields.iter() {
        let (Ok(name), Ok(value)) = (from_utf8_basic(name), from_utf8_basic(value)) else {
          return Err(StatusCode::BadRequest);
        };
        if msg.headers.push_from_iter(Header::new(false, false, name, [value])).is_err() {
          return Err(StatusCode::BadRequest);
        }
      }
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
  // The block used last
  last: Option<usize>,
  lower: VectorUsize<u8>,
  section: VectorUsize<u8>,
  uses: u64,
}

impl ResponseHead {
  const fn new() -> Self {
    Self {
      blocks: VectorUsize::new(),
      key: VectorUsize::new(),
      last: None,
      lower: VectorUsize::new(),
      section: VectorUsize::new(),
      uses: 0,
    }
  }

  // The field section of a response of `status`, `headers`, `content-length` if `length` and the
  // `date` line if any.
  fn encode(
    &mut self,
    status: StatusCode,
    headers: &Headers,
    length: Option<usize>,
    date: Option<&[u8]>,
  ) -> crate::Result<&[u8]> {
    let [mut content_type, mut content_encoding, mut vary] = [None; 3];
    // If a field is left for the second pass below
    let mut others = false;
    for header in headers.iter() {
      let slot = match known(header.name.as_bytes()) {
        Some(Known::ContentType) => &mut content_type,
        Some(Known::ContentEncoding) => &mut content_encoding,
        Some(Known::Vary) => &mut vary,
        Some(Known::ContentLength | Known::ConnectionSpecific) => continue,
        Some(Known::Date) | None => {
          others = true;
          continue;
        }
      };
      if slot.is_none() {
        *slot = Some(header.value.as_bytes());
      } else {
        others = true;
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
    if let Some(elem) = length {
      let mut digits = [0u8; 20];
      encode_static_line(b"content-length", decimal(elem, &mut digits), &mut self.section)?;
    }
    if !others {
      return Ok(self.section.as_slice());
    }
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
    // The last block used first, then the others, compared without making the key
    let last = self.last.filter(|el| {
      self.blocks.get(*el).is_some_and(|block| key_matches(block.key.as_slice(), status, fields))
    });
    let found = last
      .or_else(|| self.blocks.iter().position(|el| key_matches(el.key.as_slice(), status, fields)));
    if let Some(idx) = found {
      if let Some(block) = self.blocks.get_mut(idx) {
        block.last_use = self.uses;
      }
      self.last = Some(idx);
      return Ok(Some(idx));
    }
    self.key.clear();
    self.key.extend_from_copyable_slice(&status.to_be_bytes())?;
    for field in fields {
      let len = field.map_or(u16::MAX, |el| u16::try_from(el.len()).unwrap_or(u16::MAX));
      self.key.extend_from_copyable_slice(&len.to_be_bytes())?;
      self.key.extend_from_copyable_slice(field.unwrap_or_default())?;
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
    self.last = Some(idx);
    Ok(Some(idx))
  }
}

// If `key` is the key of a block of `status` and `fields`: the status, then for each field the
// length of its value (`u16::MAX` for none) and the value, as `ResponseHead::block` makes it.
fn key_matches(key: &[u8], status: u16, fields: [Option<&[u8]>; 3]) -> bool {
  let Some((head, mut rest)) = key.split_first_chunk::<2>() else {
    return false;
  };
  if *head != status.to_be_bytes() {
    return false;
  }
  for field in fields {
    let Some((len, after)) = rest.split_first_chunk::<2>() else {
      return false;
    };
    let value = field.unwrap_or_default();
    let expected = field.map_or(u16::MAX, |el| u16::try_from(el.len()).unwrap_or(u16::MAX));
    if *len != expected.to_be_bytes() || !after.starts_with(value) {
      return false;
    }
    rest = after.get(value.len()..).unwrap_or_default();
  }
  rest.is_empty()
}

// The fields of a response that the encoder treats apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Known {
  ConnectionSpecific,
  ContentEncoding,
  ContentLength,
  ContentType,
  Date,
  Vary,
}

// By the length of the name first: one comparison at most for most names (ruling T16-a).
fn known(name: &[u8]) -> Option<Known> {
  let is = |known: KnownHeaderName| name.eq_ignore_ascii_case(<&str>::from(known).as_bytes());
  match name.len() {
    4 if is(KnownHeaderName::Vary) => Some(Known::Vary),
    4 if is(KnownHeaderName::Date) => Some(Known::Date),
    7 if is(KnownHeaderName::Upgrade) => Some(Known::ConnectionSpecific),
    10 if is(KnownHeaderName::Connection) || is(KnownHeaderName::KeepAlive) => {
      Some(Known::ConnectionSpecific)
    }
    12 if is(KnownHeaderName::ContentType) => Some(Known::ContentType),
    14 if is(KnownHeaderName::ContentLength) => Some(Known::ContentLength),
    16 if is(KnownHeaderName::ContentEncoding) => Some(Known::ContentEncoding),
    16 if is(KnownHeaderName::ProxyConnection) => Some(Known::ConnectionSpecific),
    17 if is(KnownHeaderName::TransferEncoding) => Some(Known::ConnectionSpecific),
    _ => None,
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
pub(super) enum SlotPoll<T> {
  /// The future finished.
  Done(T),
  /// The future panicked; its slot is free again.
  Panicked,
  /// The future waits.
  Pending,
}

/// What wakes the endpoint task: the slots whose futures want another poll, each queued once.
struct WakeShared {
  // Wakes that found the queue full, and were lost: never, while the queue has room for every
  // slot (review X2)
  lost: AtomicU64,
  task: AtomicWaker,
  woken: SyncMutex<VectorUsize<u32>>,
}

/// The waker of a slot.
// `std::task::Wake` is implemented for `alloc::sync::Arc` only
#[allow(clippy::disallowed_types, reason = "`Waker::from` needs the standard `Arc`")]
struct SlotWaker {
  idx: u32,
  queued: AtomicBool,
  shared: Arc<WakeShared>,
}

#[allow(clippy::disallowed_types, reason = "`Waker::from` needs the standard `Arc`")]
impl std::task::Wake for SlotWaker {
  fn wake(self: alloc::sync::Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &alloc::sync::Arc<Self>) {
    if !self.queued.swap(true, Ordering::AcqRel) {
      // The queue has room for every slot, each queued at most once: a push never allocates, and
      // one that would is not made: the wake is counted lost, and the next one queues the slot
      let mut woken = self.shared.woken.lock();
      if woken.len() >= woken.capacity() || woken.push(self.idx).is_err() {
        cold_path();
        drop(woken);
        self.queued.store(false, Ordering::Release);
        let _ = self.shared.lost.fetch_add(1, Ordering::Relaxed);
      }
    }
    self.shared.task.wake();
  }
}

/// A slot of a future: pinned once, used again without allocating.
#[allow(clippy::disallowed_types, reason = "`Waker::from` needs the standard `Arc`")]
struct Slot<F> {
  conn: ConnHandle,
  fut: Pin<Box<Option<F>>>,
  stream: StreamId,
  wake: alloc::sync::Arc<SlotWaker>,
  waker: Waker,
}

/// The slots of the futures of a worker.
pub(super) struct TaskSlots<F> {
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
  pub(super) fn new() -> Self {
    Self {
      free: VectorUsize::new(),
      len: 0,
      shared: Arc::new(WakeShared {
        lost: AtomicU64::new(0),
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
  #[allow(clippy::disallowed_types, reason = "`Waker::from` needs the standard `Arc`")]
  pub(super) fn insert(
    &mut self,
    fut: F,
    conn: ConnHandle,
    stream: StreamId,
  ) -> crate::Result<u32> {
    let idx = if let Some(idx) = self.free.pop() {
      idx
    } else {
      let idx = u32::try_from(self.slots.len()).map_err(|_err| crate::Error::ProgrammingError)?;
      let slots = usize::try_from(idx).unwrap_or(usize::MAX).wrapping_add(1);
      self.free.reserve(slots)?;
      {
        // Room in the queue of woken slots for every slot, this one included (review X2): the
        // capacity of the queue never shrinks, so the wakers of slots that a trim let go fit too
        let mut woken = self.shared.woken.lock();
        let len = woken.len();
        woken.reserve(slots.saturating_sub(len))?;
      }
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
  pub(super) fn poll(&mut self, idx: u32) -> SlotPoll<F::Output> {
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
  pub(super) fn take_woken(&self, out: &mut VectorUsize<u32>) -> crate::Result<()> {
    let mut woken = self.shared.woken.lock();
    out.extend_from_copyable_slice(woken.as_slice())?;
    woken.clear();
    Ok(())
  }

  // The wakes that found the queue of woken slots full.
  #[cfg(test)]
  pub(super) fn wakes_lost(&self) -> u64 {
    self.shared.lost.load(Ordering::Relaxed)
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

#[cfg(test)]
mod tests {
  use crate::{
    collections::VectorUsize,
    http::{
      Header, Headers, KnownHeaderName, StatusCode,
      http3_server_framework::router_handler::{Known, ResponseHead, known},
    },
    http3::encode_static,
  };
  use alloc::{vec, vec::Vec};

  // The fields of the encoder as one comparison after the other found them before ruling T16-a.
  fn known_one_by_one(name: &[u8]) -> Option<Known> {
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

  // Ruling T16-a: the fields that the encoder treats apart are found by the length of the name
  // first, with the same answers, whatever the case of the name.
  #[test]
  fn known_fields_by_length_match_one_by_one() {
    let names = [
      "content-type",
      "Content-Type",
      "content-encoding",
      "CONTENT-ENCODING",
      "vary",
      "Vary",
      "content-length",
      "date",
      "DATE",
      "connection",
      "keep-alive",
      "proxy-connection",
      "transfer-encoding",
      "upgrade",
      "server",
      "x-vary",
      "dat",
      "content-typ",
      "content-types",
      "content-encodinG",
      "proxy-connectio",
      "",
      "etag",
      "location",
      "keep_alive",
    ];
    for name in names {
      assert_eq!(known(name.as_bytes()), known_one_by_one(name.as_bytes()), "{name}");
    }
  }

  fn headers(fields: &[(&str, &str)]) -> Headers {
    let mut rslt = Headers::new();
    for (name, value) in fields {
      rslt.push_from_iter(Header::from_name_and_value(name, [*value])).unwrap();
    }
    rslt
  }

  // Ruling T16-a: blocks found without making their key, the last one used first, and responses
  // without other fields encoded in one pass give the sections that the plain static encoding of
  // their fields gives, whatever the order in which combinations come and go.
  // A response: its status, the fields that its handler wrote, and the lines expected of it
  type Case = (
    StatusCode,
    &'static [(&'static str, &'static str)],
    &'static [(&'static [u8], &'static [u8])],
  );

  #[test]
  fn sections_match_the_static_encoding_of_their_fields() {
    let cases: [Case; 6] = [
      (
        StatusCode::Ok,
        &[("content-type", "text/plain")],
        &[(b":status", b"200"), (b"content-type", b"text/plain")],
      ),
      (
        StatusCode::Ok,
        &[("content-type", "text/css"), ("content-encoding", "br"), ("vary", "accept-encoding")],
        &[
          (b":status", b"200"),
          (b"content-type", b"text/css"),
          (b"content-encoding", b"br"),
          (b"vary", b"accept-encoding"),
        ],
      ),
      (StatusCode::NotFound, &[], &[(b":status", b"404")]),
      (
        StatusCode::Ok,
        &[("Server", "rimu"), ("content-type", "text/plain"), ("content-type", "x/y")],
        &[
          (b":status", b"200"),
          (b"content-type", b"text/plain"),
          (b"server", b"rimu"),
          (b"content-type", b"x/y"),
        ],
      ),
      (
        StatusCode::Ok,
        &[("content-type", "text/plain"), ("connection", "close"), ("content-length", "9")],
        &[(b":status", b"200"), (b"content-type", b"text/plain")],
      ),
      (
        StatusCode::Ok,
        &[("content-type", "text/plai"), ("date", "x")],
        &[(b":status", b"200"), (b"content-type", b"text/plai"), (b"date", b"x")],
      ),
    ];
    let mut head = ResponseHead::new();
    let mut expected = VectorUsize::new();
    let order: Vec<usize> = (0..4).flat_map(|_| [0, 0, 1, 2, 0, 3, 4, 5, 1, 1, 5]).collect();
    for idx in order {
      let (status, fields, lines) = cases[idx];
      expected.clear();
      encode_static(lines, &mut expected).unwrap();
      let section = head.encode(status, &headers(fields), None, None).unwrap();
      assert_eq!(section, expected.as_slice(), "case {idx}");
    }
  }

  // The section with the `date` line, `content-length` and a combination too long to keep encoded
  // is the static encoding of the fields in that order: block lines, date, content-length, others.
  #[test]
  fn sections_with_date_length_and_long_values_match_the_static_encoding() {
    let long = "x".repeat(600);
    let mut date = VectorUsize::new();
    crate::http3::encode_static_line(b"date", b"Mon, 09 Nov 2026 12:00:00 GMT", &mut date).unwrap();
    let mut head = ResponseHead::new();
    for round in 0..3 {
      for (content_type, length, with_date) in
        [("text/plain", Some(17), true), (long.as_str(), Some(5), false), ("a/b", None, true)]
      {
        let fields = headers(&[("content-type", content_type), ("server", "rimu")]);
        let date_line = with_date.then_some(date.as_slice());
        let section = head.encode(StatusCode::Ok, &fields, length, date_line).unwrap().to_vec();
        let mut expected = VectorUsize::new();
        let length_text = length.map(|el: usize| alloc::format!("{el}"));
        let mut lines: Vec<(&[u8], &[u8])> =
          vec![(b":status", b"200"), (b"content-type", content_type.as_bytes())];
        if with_date {
          lines.push((b"date", b"Mon, 09 Nov 2026 12:00:00 GMT"));
        }
        if let Some(elem) = &length_text {
          lines.push((b"content-length", elem.as_bytes()));
        }
        lines.push((b"server", b"rimu"));
        encode_static(&lines, &mut expected).unwrap();
        assert_eq!(section, expected.as_slice(), "round {round} {content_type:.10}");
      }
    }
  }
}
