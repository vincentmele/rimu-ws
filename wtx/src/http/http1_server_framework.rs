//! HTTP/1.1 server framework on top of the sans-I/O [`crate::http1::Http1Conn`] core.
//!
//! One runtime per thread, each with its own `SO_REUSEPORT` listener. Requests are routed by path
//! through the protocol-agnostic radix [`Router`], and answered by synchronous handlers, so a
//! request costs no allocation and no boxed future. The server is plaintext, or TLS through
//! [`Http1ServerFramework::new_tls`] (user-space TLS, ALPN `http/1.1`).

mod conn_driver;

use crate::{
  executor::{Executor, Runtime as _},
  http::{
    HttpRecvParams, Method, Router, RouterError, RouterMatch, ShutdownSignal, StatusCode,
    misc::{accept_or_shutdown, admit, counter, drain_connections, on_accept_error, tracked},
  },
  http1::Http1Request,
  net::{TcpListener as _, TcpParams, Uri},
  rng::{ChaCha20, CryptoRng, CryptoSeedableRng},
  sync::Arc,
  tls::{PlaintextCtx, TlsAcceptor, TlsConfig, TlsCtxSk},
};
use alloc::{boxed::Box, rc::Rc, string::String, vec::Vec};
use conn_driver::{ConnGroup, DriveParams, Http1Service, drive_conn};
use core::{num::NonZeroUsize, ops::ControlFlow, time::Duration};

/// Default of [`Http1ServerFramework::set_max_delay`].
const DEFAULT_MAX_DELAY: Duration = Duration::from_secs(10);

type Handler<DA, ER> =
  Box<dyn Fn(&mut DA, &Http1Req<'_>, &mut Http1Res) -> Result<(), ER> + Send + Sync>;

/// A request being served: the head the parser found, the decoded body and the route that matched.
#[derive(Debug)]
pub struct Http1Req<'a> {
  head: Http1Request<'a>,
  body: &'a [u8],
  route: Option<RouterMatch<'a, usize>>,
}

impl<'a> Http1Req<'a> {
  /// Decoded body, empty when the request has none.
  #[inline]
  pub const fn body(&self) -> &'a [u8] {
    self.body
  }

  /// First header called `name`, ignoring case.
  #[inline]
  pub fn header(&self, name: &str) -> Option<&'a str> {
    self.head.headers.iter().find(|el| el.0.eq_ignore_ascii_case(name)).map(|el| el.1)
  }

  /// All headers, in the order they were received.
  #[inline]
  pub const fn headers(&self) -> &'a [(&'a str, &'a str)] {
    self.head.headers
  }

  /// If `false`, the connection is closed after the response.
  #[inline]
  pub const fn keep_alive(&self) -> bool {
    self.head.keep_alive
  }

  /// Request method.
  #[inline]
  pub const fn method(&self) -> Method {
    self.head.method
  }

  /// Value of the path parameter `name` of the matched route.
  #[inline]
  pub fn param(&self, name: &str) -> Option<&str> {
    self.route.as_ref()?.param_by_name(name.as_bytes()).map(|el| el.value)
  }

  /// Percent-encoded path, without the query.
  #[inline]
  pub const fn path(&self) -> &'a str {
    self.head.path
  }

  /// Everything after `?`, or an empty string.
  #[inline]
  pub const fn query(&self) -> &'a str {
    self.head.query
  }

  /// The route that matched the path, if any.
  #[inline]
  pub const fn route(&self) -> Option<&RouterMatch<'a, usize>> {
    self.route.as_ref()
  }
}

/// The response a handler builds. `Content-Length` and, for a closing connection, `Connection:
/// close` are added when it is written; any other header goes through [`Self::push_header`].
#[derive(Debug)]
pub struct Http1Res {
  body: Vec<u8>,
  content_type: &'static str,
  delay: Option<core::time::Duration>,
  headers: Vec<u8>,
  status: StatusCode,
}

impl Http1Res {
  pub(crate) fn new(body: Vec<u8>) -> Self {
    Self {
      body,
      content_type: "text/plain",
      delay: None,
      headers: Vec::new(),
      status: StatusCode::Ok,
    }
  }

  /// Time the connection waits, without blocking its thread, before this response is sent.
  /// Responses of the same connection stay in order. Cleared for every request. A delay longer
  /// than the server's maximum ([`Http1ServerFramework::set_max_delay`]) is cut to it.
  ///
  /// The connection's socket is watched while it waits: a peer that goes away ends the
  /// connection at once, and requests that arrive meanwhile are answered after this response.
  #[inline]
  pub fn delay(&self) -> Option<core::time::Duration> {
    self.delay
  }

  /// Asks for the response to be sent only after `delay`. See [`Self::delay`].
  #[inline]
  pub const fn set_delay(&mut self, delay: core::time::Duration) {
    self.delay = Some(delay);
  }

  /// Body written so far.
  #[inline]
  pub fn body(&self) -> &[u8] {
    &self.body
  }

  /// Buffer the body is written into. It is reused across the connection's responses.
  #[inline]
  pub fn body_mut(&mut self) -> &mut Vec<u8> {
    &mut self.body
  }

  /// Adds the header `name: value` to the response. Fails if either holds a line break.
  #[inline]
  pub fn push_header(&mut self, name: &str, value: &str) -> crate::Result<()> {
    let invalid = |el: &str| el.bytes().any(|b| b == b'\r' || b == b'\n');
    if name.is_empty() || invalid(name) || invalid(value) {
      return Err(crate::http::HttpError::BadRequest.into());
    }
    self.headers.extend_from_slice(name.as_bytes());
    self.headers.extend_from_slice(b": ");
    self.headers.extend_from_slice(value.as_bytes());
    self.headers.extend_from_slice(b"\r\n");
    Ok(())
  }

  /// Sets `Content-Type`. Defaults to `text/plain`.
  #[inline]
  pub const fn set_content_type(&mut self, value: &'static str) {
    self.content_type = value;
  }

  /// Sets the status code. Defaults to 200.
  #[inline]
  pub const fn set_status(&mut self, value: StatusCode) {
    self.status = value;
  }

  /// Current status code.
  #[inline]
  pub const fn status(&self) -> StatusCode {
    self.status
  }

  pub(crate) fn content_type(&self) -> &'static str {
    self.content_type
  }

  pub(crate) fn extra_headers(&self) -> &[u8] {
    &self.headers
  }

  pub(crate) fn reset(&mut self) {
    self.body.clear();
    self.content_type = "text/plain";
    self.delay = None;
    self.headers.clear();
    self.status = StatusCode::Ok;
  }

  pub(crate) fn take_body(&mut self) -> Vec<u8> {
    core::mem::take(&mut self.body)
  }
}

/// Runs around every request, matched or not.
pub trait Http1Middleware<DA, ER> {
  /// Looks at the request before its handler. [`ControlFlow::Break`] answers with `res` as it is,
  /// without calling the handler.
  #[inline]
  fn req(
    &self,
    data: &mut DA,
    req: &Http1Req<'_>,
    res: &mut Http1Res,
  ) -> Result<ControlFlow<()>, ER> {
    let _ = (data, req, res);
    Ok(ControlFlow::Continue(()))
  }

  /// Modifies the response after its handler.
  #[inline]
  fn res(&self, data: &mut DA, req: &Http1Req<'_>, res: &mut Http1Res) -> Result<(), ER> {
    let _ = (data, req, res);
    Ok(())
  }
}

impl<DA, ER> Http1Middleware<DA, ER> for () {}

/// Adds a `server` header to every response.
#[derive(Clone, Copy, Debug)]
pub struct Http1ServerHeader(
  /// Header value
  pub &'static str,
);

impl<DA, ER> Http1Middleware<DA, ER> for Http1ServerHeader
where
  ER: From<crate::Error>,
{
  #[inline]
  fn res(&self, _: &mut DA, _: &Http1Req<'_>, res: &mut Http1Res) -> Result<(), ER> {
    res.push_header("server", self.0)?;
    Ok(())
  }
}

/// Routes paths to handlers. A path may have one handler per method, or one for any method.
///
/// A HEAD request is answered by the path's HEAD handler or, without one, by its GET handler: the
/// response then has the headers of the GET response, `Content-Length` included, and no body. A
/// method a path has no handler for is answered 405, with an `Allow` header listing the methods it
/// has.
pub struct Http1Router<DA, ER, M = ()> {
  /// For every path, the value of the `Allow` header of its 405 responses.
  allows: Vec<String>,
  groups: Vec<Vec<(Option<Method>, Handler<DA, ER>)>>,
  matcher: Router<usize>,
  middleware: M,
  pending: Vec<(&'static str, Option<Method>, Handler<DA, ER>)>,
}

impl<DA, ER> Http1Router<DA, ER, ()> {
  /// No route and no middleware.
  #[inline]
  pub const fn new() -> Self {
    Self {
      allows: Vec::new(),
      groups: Vec::new(),
      matcher: Router::new(),
      middleware: (),
      pending: Vec::new(),
    }
  }
}

impl<DA, ER, M> Http1Router<DA, ER, M> {
  /// Handles `path` for `method`, or for every method if it is [`None`]. See [`Router`] for the
  /// syntax of paths. An invalid or duplicated route is reported when the server starts.
  #[inline]
  #[must_use]
  pub fn route<F>(mut self, method: Option<Method>, path: &'static str, handler: F) -> Self
  where
    F: Fn(&mut DA, &Http1Req<'_>, &mut Http1Res) -> Result<(), ER> + Send + Sync + 'static,
  {
    self.pending.push((path, method, Box::new(handler)));
    self
  }

  /// Handles GET requests of `path`.
  #[inline]
  #[must_use]
  pub fn get<F>(self, path: &'static str, handler: F) -> Self
  where
    F: Fn(&mut DA, &Http1Req<'_>, &mut Http1Res) -> Result<(), ER> + Send + Sync + 'static,
  {
    self.route(Some(Method::Get), path, handler)
  }

  /// Handles POST requests of `path`.
  #[inline]
  #[must_use]
  pub fn post<F>(self, path: &'static str, handler: F) -> Self
  where
    F: Fn(&mut DA, &Http1Req<'_>, &mut Http1Res) -> Result<(), ER> + Send + Sync + 'static,
  {
    self.route(Some(Method::Post), path, handler)
  }

  /// Runs `middleware` around every request.
  #[inline]
  #[must_use]
  pub fn set_middleware<_M>(self, middleware: _M) -> Http1Router<DA, ER, _M> {
    Http1Router {
      allows: self.allows,
      groups: self.groups,
      matcher: self.matcher,
      middleware,
      pending: self.pending,
    }
  }

  /// Moves the registered routes into the path matcher.
  fn build(&mut self) -> crate::Result<()> {
    self.groups.clear();
    let mut paths: Vec<&'static str> = Vec::new();
    for (path, method, handler) in core::mem::take(&mut self.pending) {
      let idx = match paths.iter().position(|el| *el == path) {
        Some(elem) => elem,
        None => {
          paths.push(path);
          self.groups.push(Vec::new());
          paths.len().wrapping_sub(1)
        }
      };
      let Some(group) = self.groups.get_mut(idx) else {
        continue;
      };
      if group.iter().any(|el| el.0 == method || el.0.is_none() || method.is_none()) {
        return Err(RouterError::AddErrDuplicate.into());
      }
      group.push((method, handler));
    }
    self.allows = self.groups.iter().map(|group| allow(group.iter().map(|el| el.0))).collect();
    let mut builder = self.matcher.builder();
    for (idx, path) in paths.iter().enumerate() {
      let _ = builder.add(&(*path).try_into()?, idx)?;
    }
    Ok(())
  }
}

impl<DA, ER, M> Http1Router<DA, ER, M>
where
  M: Http1Middleware<DA, ER>,
{
  fn dispatch(
    &self,
    data: &mut DA,
    head: Http1Request<'_>,
    body: &[u8],
    res: &mut Http1Res,
  ) -> Result<(), ER> {
    let route = self.matcher.find(head.path).ok();
    let req = Http1Req { head, body, route };
    if let ControlFlow::Continue(()) = self.middleware.req(data, &req, res)? {
      let idx = req.route.as_ref().map(|el| *el.data());
      match idx.and_then(|el| self.groups.get(el)) {
        None => res.set_status(StatusCode::NotFound),
        Some(group) => {
          let find = |method| group.iter().find(|el| el.0.is_none_or(|elem| elem == method));
          let mut found = find(head.method);
          // HEAD is GET without the body, which the core leaves out.
          if found.is_none() && head.method == Method::Head {
            found = find(Method::Get);
          }
          match found {
            None => {
              res.set_status(StatusCode::MethodNotAllowed);
              if let Some(allow) = idx.and_then(|el| self.allows.get(el)) {
                // Method names: never a line break.
                let _rslt = res.push_header("allow", allow);
              }
            }
            Some((_, handler)) => handler(data, &req, res)?,
          }
        }
      }
    }
    self.middleware.res(data, &req, res)
  }
}

/// The `Allow` header of a path with handlers for `methods`: they in the order they were added,
/// and HEAD after GET when the path has no HEAD handler of its own.
fn allow(methods: impl Clone + Iterator<Item = Option<Method>>) -> String {
  let has_head = methods.clone().any(|el| el == Some(Method::Head));
  let mut allow = String::new();
  let mut push = |method: Method| {
    if !allow.is_empty() {
      allow.push_str(", ");
    }
    allow.push_str(method.strings().custom.first().copied().unwrap_or_default());
  };
  for method in methods.flatten() {
    push(method);
    if method == Method::Get && !has_head {
      push(Method::Head);
    }
  }
  allow
}

impl<DA, ER> Default for Http1Router<DA, ER, ()> {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

impl<DA, ER, M> core::fmt::Debug for Http1Router<DA, ER, M> {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Http1Router").field("paths", &self.groups.len()).finish()
  }
}

/// HTTP/1.1 Server Framework
#[derive(Debug)]
pub struct Http1ServerFramework<DA, EC, EX, RC, RNG = ChaCha20, TCX = PlaintextCtx> {
  data: DA,
  error_cb: EC,
  executor: EX,
  hrc: HttpRecvParams,
  local_runtime_cb: RC,
  local_runtimes: Option<NonZeroUsize>,
  max_connections: Option<NonZeroUsize>,
  max_delay: Duration,
  shutdown: Option<(ShutdownSignal, Duration)>,
  tcp_params: TcpParams,
  /// The generator and the configuration of the TLS connections, if the server is a TLS one.
  tls: Option<(RNG, Arc<TlsConfig<TCX>>)>,
}

impl<ER, EX>
  Http1ServerFramework<
    (),
    fn(ER),
    EX,
    fn() -> Result<<EX as Executor>::LocalRuntime, ER>,
    ChaCha20,
    PlaintextCtx,
  >
where
  ER: From<crate::Error>,
  EX: Executor,
{
  /// Plaintext server; taking aside the provided executor, everything else is set to default
  /// values. Idle and slow connections are bounded by the runtime (see
  /// [`crate::executor::UringParams`]): its idle timeout counts from the last received or sent
  /// bytes, so a client pausing in the middle of a request is not cut off.
  #[inline]
  pub fn new(executor: EX) -> crate::Result<Self> {
    let error_cb: fn(_) = |_| {};
    let local_runtime_cb: fn() -> _ = || Ok(EX::LocalRuntime::new()?);
    Ok(Self {
      data: (),
      error_cb,
      executor,
      hrc: HttpRecvParams::with_default_params(),
      local_runtime_cb,
      local_runtimes: None,
      max_connections: None,
      max_delay: DEFAULT_MAX_DELAY,
      shutdown: None,
      tcp_params: TcpParams::default(),
      tls: None,
    })
  }
}

impl<ER, EX, RNG, TCX>
  Http1ServerFramework<
    (),
    fn(ER),
    EX,
    fn() -> Result<<EX as Executor>::LocalRuntime, ER>,
    RNG,
    TCX,
  >
where
  ER: From<crate::Error>,
  EX: Executor,
{
  /// TLS server; taking aside the provided parameters, everything else is set to default values.
  ///
  /// The "http/1.1" ALPN will always be pushed into the TLS configuration, and kernel TLS turned
  /// off ([`TlsConfig::kernel_tls`]): connections seal their records in user space, as the
  /// HTTP/2 server does. `rng` seeds the generator of each thread and, from it, those of the
  /// connections.
  ///
  /// Unlike the plaintext server, a TLS handshake is not bounded by anything but the runtime's
  /// idle timeout (see [`Self::new`]).
  #[inline]
  pub fn new_tls(executor: EX, rng: RNG, mut tls_config: TlsConfig<TCX>) -> crate::Result<Self> {
    tls_config
      .alpn_mut()
      .get_or_insert_default()
      .protocol_name_list
      .push(b"http/1.1".as_slice().try_into()?)?;
    *tls_config.kernel_tls_mut() = false;
    let error_cb: fn(_) = |_| {};
    let local_runtime_cb: fn() -> _ = || Ok(EX::LocalRuntime::new()?);
    Ok(Self {
      data: (),
      error_cb,
      executor,
      hrc: HttpRecvParams::with_default_params(),
      local_runtime_cb,
      local_runtimes: None,
      max_connections: None,
      max_delay: DEFAULT_MAX_DELAY,
      shutdown: None,
      tcp_params: TcpParams::default(),
      tls: Some((rng, tls_config.into())),
    })
  }
}

impl<DA, EC, EX, RC, RNG, TCX> Http1ServerFramework<DA, EC, EX, RC, RNG, TCX> {
  /// Shared data that is cloned for each connection.
  #[inline]
  pub fn set_data<_DA>(self, value: _DA) -> Http1ServerFramework<_DA, EC, EX, RC, RNG, TCX> {
    Http1ServerFramework {
      data: value,
      error_cb: self.error_cb,
      executor: self.executor,
      hrc: self.hrc,
      local_runtime_cb: self.local_runtime_cb,
      local_runtimes: self.local_runtimes,
      max_connections: self.max_connections,
      max_delay: self.max_delay,
      shutdown: self.shutdown,
      tcp_params: self.tcp_params,
      tls: self.tls,
    }
  }

  /// Sets the error callback function. A peer that goes away is not an error.
  #[inline]
  pub fn set_error_cb<_EC>(self, value: _EC) -> Http1ServerFramework<DA, _EC, EX, RC, RNG, TCX> {
    Http1ServerFramework {
      data: self.data,
      error_cb: value,
      executor: self.executor,
      hrc: self.hrc,
      local_runtime_cb: self.local_runtime_cb,
      local_runtimes: self.local_runtimes,
      max_connections: self.max_connections,
      max_delay: self.max_delay,
      shutdown: self.shutdown,
      tcp_params: self.tcp_params,
      tls: self.tls,
    }
  }

  /// Only [`HttpRecvParams::max_body_len`] applies to HTTP/1.1.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_http_recv_params(mut self, value: HttpRecvParams) -> Self {
    self.hrc = value;
    self
  }

  /// Allows the tweaking of the chosen runtime.
  #[inline]
  pub fn set_local_runtime_cb<_RC>(self, value: _RC) -> Http1ServerFramework<DA, EC, EX, _RC, RNG, TCX> {
    Http1ServerFramework {
      data: self.data,
      error_cb: self.error_cb,
      executor: self.executor,
      hrc: self.hrc,
      local_runtime_cb: value,
      local_runtimes: self.local_runtimes,
      max_connections: self.max_connections,
      max_delay: self.max_delay,
      shutdown: self.shutdown,
      tcp_params: self.tcp_params,
      tls: self.tls,
    }
  }

  /// The number of spawned runtimes. Shouldn't be greater than the number of available threads.
  /// If [`None`], defaults to the number of threads.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_local_runtimes(mut self, value: Option<NonZeroUsize>) -> Self {
    self.local_runtimes = value;
    self
  }

  /// How many connections the server serves at once, across all of its runtimes. A connection
  /// accepted past that is closed at once, and the error callback receives
  /// [`crate::Error::TooManyConnections`]. Defaults to `None`.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_max_connections(mut self, value: Option<NonZeroUsize>) -> Self {
    self.max_connections = value;
    self
  }

  /// The longest delay a response may ask for ([`Http1Res::set_delay`]): longer ones are cut to
  /// it, so that a handler fed a client's number can't hold a connection for as long as the client
  /// likes. Defaults to 10 s.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_max_delay(mut self, value: Duration) -> Self {
    self.max_delay = value;
    self
  }

  /// Stops the server when `signal` is triggered: it stops accepting, closes the connections that
  /// wait for a request, lets those in the middle of one answer it (within `drain`), and then
  /// returns `Ok`. Connections still open after `drain` are closed with their runtime.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub fn set_shutdown(mut self, signal: ShutdownSignal, drain: Duration) -> Self {
    self.shutdown = Some((signal, drain));
    self
  }

  /// See [`TcpParams`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_tcp_params(mut self, value: TcpParams) -> Self {
    self.tcp_params = value;
    self
  }
}

impl<DA, EC, ER, EX, RC, RNG, TCX> Http1ServerFramework<DA, EC, EX, RC, RNG, TCX>
where
  DA: Clone + 'static,
  EC: Clone + Fn(ER) + 'static,
  ER: From<crate::Error> + 'static,
  EX: Clone + Executor + 'static,
  RC: Clone + Fn() -> Result<EX::LocalRuntime, ER> + 'static,
  RNG: CryptoRng + CryptoSeedableRng + 'static,
  TCX: TlsCtxSk + 'static,
{
  /// Starts the server using a runtime-per-thread architecture: each thread has its own runtime
  /// and its own `SO_REUSEPORT` listener on `addr`.
  ///
  /// Returns the first thread's error, or its panic as an error, as soon as one happens. The
  /// other threads are left running, so call this from the main thread. After a shutdown (see
  /// [`Self::set_shutdown`]), returns `Ok` once every thread has drained.
  #[inline]
  pub fn run_in_threads<M>(
    mut self,
    addr: &str,
    mut router: Http1Router<DA, ER, M>,
  ) -> Result<(), ER>
  where
    DA: Send,
    EC: Send,
    ER: Send,
    EX: Send,
    M: Http1Middleware<DA, ER> + Send + Sync + 'static,
    RC: Send,
    RNG: Send,
    TCX: Send + Sync,
  {
    let runtimes = if let Some(elem) = self.local_runtimes {
      elem.get()
    } else {
      std::thread::available_parallelism().map_err(crate::Error::from)?.get()
    };
    router.build()?;
    let router = Arc::new(router);
    let (done_tx, done_rx) = std::sync::mpsc::channel::<Result<(), ER>>();
    // One count for every runtime, so that the limit is the server's
    let active = counter(self.shutdown.as_ref(), self.max_connections);
    for _ in 0..runtimes {
      let tls = match &mut self.tls {
        Some((rng, tls_config)) => Some((RNG::from_crypto_rng(rng)?, tls_config.clone())),
        None => None,
      };
      let thread = ThreadServer {
        active: active.clone(),
        data: self.data.clone(),
        error_cb: self.error_cb.clone(),
        params: DriveParams { hrc: self.hrc, max_delay: self.max_delay },
        max_connections: self.max_connections,
        router: router.clone(),
        shutdown: self.shutdown.clone(),
        tcp_params: self.tcp_params,
        tls,
      };
      let executor = self.executor.clone();
      let local_runtime_cb = self.local_runtime_cb.clone();
      let thread_addr = Uri::new(String::from(addr));
      let thread_done = done_tx.clone();
      let _jh = std::thread::spawn(move || {
        let body = move || -> Result<(), ER> {
          let lc = local_runtime_cb()?;
          lc.block_on(thread.serve(&executor, &lc, &thread_addr))
        };
        let rslt = std::panic::catch_unwind(core::panic::AssertUnwindSafe(body))
          .unwrap_or_else(|payload| Err(crate::Error::from(payload).into()));
        let _rslt = thread_done.send(rslt);
      });
    }
    drop(done_tx);
    // A thread ends only on an error, a panic or a shutdown.
    let mut ended = 0;
    while let Ok(rslt) = done_rx.recv() {
      rslt?;
      ended += 1;
      if ended == runtimes {
        break;
      }
    }
    Ok(())
  }
}

/// What one runtime thread serves.
struct ThreadServer<DA, EC, ER, M, RNG, TCX> {
  active: Option<Arc<crate::sync::AtomicUsize>>,
  data: DA,
  error_cb: EC,
  max_connections: Option<NonZeroUsize>,
  params: DriveParams,
  router: Arc<Http1Router<DA, ER, M>>,
  shutdown: Option<(ShutdownSignal, Duration)>,
  tcp_params: TcpParams,
  tls: Option<(RNG, Arc<TlsConfig<TCX>>)>,
}

impl<DA, EC, ER, M, RNG, TCX> ThreadServer<DA, EC, ER, M, RNG, TCX>
where
  DA: Clone + 'static,
  EC: Clone + Fn(ER) + 'static,
  ER: From<crate::Error> + 'static,
  M: Http1Middleware<DA, ER> + 'static,
  RNG: CryptoRng + CryptoSeedableRng + 'static,
  TCX: TlsCtxSk + 'static,
{
  async fn serve<EX>(
    mut self,
    executor: &EX,
    lc: &EX::LocalRuntime,
    addr: &Uri<String>,
  ) -> Result<(), ER>
  where
    EX: Executor + 'static,
  {
    let listener =
      EX::TcpListener::bind(addr.hostname_with_implied_port(), self.tcp_params).await?;
    // This server's connections on this thread: its shutdown reaches them alone.
    let group = self.shutdown.as_ref().map(|_| Rc::new(ConnGroup::default()));
    loop {
      let accept = listener.accept(self.tcp_params);
      let Some(rslt) = accept_or_shutdown(accept, self.shutdown.as_ref().map(|el| &el.0)).await
      else {
        break;
      };
      let (stream, _peer) = match rslt {
        Ok(elem) => elem,
        Err(err) => {
          on_accept_error(&self.error_cb, err).await;
          continue;
        }
      };
      if let Some(active) = &self.active
        && !admit(active, self.max_connections)
      {
        drop(stream);
        (self.error_cb)(crate::Error::TooManyConnections.into());
        continue;
      }
      let service = RouterService {
        data: self.data.clone(),
        error_cb: self.error_cb.clone(),
        router: self.router.clone(),
      };
      let tls = match &mut self.tls {
        Some((rng, tls_config)) => Some((RNG::from_crypto_rng(rng)?, tls_config.clone())),
        None => None,
      };
      let fut = conn_fut(stream, service, self.params, group.clone(), tls);
      if let Some(active) = &self.active {
        let _jh = executor.spawn_local(tracked(fut, active.clone()), lc);
      } else {
        let _jh = executor.spawn_local(fut, lc);
      }
    }
    drop(listener);
    if let Some(elem) = &group {
      elem.go_away();
    }
    if let (Some((_, drain)), Some(active)) = (&self.shutdown, &self.active) {
      drain_connections(active, *drain).await;
    }
    Ok(())
  }
}

async fn conn_fut<DA, EC, ER, M, RNG, S, TCX>(
  mut stream: S,
  mut service: RouterService<DA, EC, ER, M>,
  params: DriveParams,
  group: Option<Rc<ConnGroup>>,
  tls: Option<(RNG, Arc<TlsConfig<TCX>>)>,
) where
  EC: Fn(ER),
  ER: From<crate::Error>,
  M: Http1Middleware<DA, ER>,
  RNG: CryptoRng,
  S: crate::net::Stream,
  TCX: TlsCtxSk,
{
  let rslt = match tls {
    None => drive_conn(&mut stream, &mut service, &params, group.as_deref()).await,
    // The stream is never split: the core drives the TLS stream as it drives a plain one.
    Some((mut rng, tls_config)) => {
      match TlsAcceptor::new(&*tls_config, &mut rng, stream).accept().await {
        Ok(accepted) => {
          let mut tls_stream = accepted.tls_stream;
          drive_conn(&mut tls_stream, &mut service, &params, group.as_deref()).await
        }
        Err(err) => Err(err),
      }
    }
  };
  if let Err(err) = rslt {
    (service.error_cb)(err.into());
  }
}

/// Answers the requests of one connection through the server's router.
struct RouterService<DA, EC, ER, M> {
  data: DA,
  error_cb: EC,
  router: Arc<Http1Router<DA, ER, M>>,
}

impl<DA, EC, ER, M> Http1Service for RouterService<DA, EC, ER, M>
where
  EC: Fn(ER),
  M: Http1Middleware<DA, ER>,
{
  #[inline]
  fn call(&mut self, head: Http1Request<'_>, body: &[u8], res: &mut Http1Res) {
    if let Err(err) = self.router.dispatch(&mut self.data, head, body, res) {
      (self.error_cb)(err);
      res.reset();
      res.set_status(StatusCode::InternalServerError);
    }
  }
}

#[cfg(all(test, feature = "io-uring"))]
mod tests {
  use crate::{
    executor::{UringExecutor, UringParams, UringRuntime},
    http::{Http1Router, Http1ServerFramework, Http1ServerHeader, StatusCode},
    tests::_uri,
  };
  use core::time::Duration;
  use std::{
    io::{Read, Write},
    net::TcpStream,
    string::String,
    vec::Vec,
  };

  fn router() -> Http1Router<(), crate::Error> {
    Http1Router::new()
      .get("/ping", |_, _, res| {
        res.body_mut().extend_from_slice(b"pong");
        Ok(())
      })
      .post("/echo", |_, req, res| {
        res.body_mut().extend_from_slice(req.body());
        Ok(())
      })
      .get("/item/{id}", |_, req, res| {
        res.body_mut().extend_from_slice(req.param("id").unwrap_or_default().as_bytes());
        Ok(())
      })
      .get("/delay/{ms}", |_, req, res| {
        let ms = req.param("ms").unwrap_or("0");
        res.set_delay(Duration::from_millis(ms.parse().unwrap_or(0)));
        res.body_mut().extend_from_slice(ms.as_bytes());
        Ok(())
      })
      .get("/boom", |_, _, _| Err(crate::Error::ClosedHttpConnection))
      .get("/teapot", |_, _, res| {
        res.set_status(StatusCode::Created);
        Ok(())
      })
      .post("/both", |_, _, _| Ok(()))
      .get("/both", |_, _, _| Ok(()))
      .get("/own-head", |_, _, _| Ok(()))
      .route(Some(crate::http::Method::Head), "/own-head", |_, _, res| {
        res.set_status(StatusCode::Created);
        Ok(())
      })
  }

  // A one-runtime server; returns its address.
  fn server(error_cb: fn(crate::Error)) -> String {
    server_with(error_cb, None, Duration::from_secs(10))
  }

  // A one-runtime server serving at most `max_connections` at once; returns its address.
  fn server_with(
    error_cb: fn(crate::Error),
    max_connections: Option<core::num::NonZeroUsize>,
    max_delay: Duration,
  ) -> String {
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    let addr = std::format!("{host}:{port}");
    let server_addr = addr.clone();
    let _server = std::thread::spawn(move || {
      Http1ServerFramework::<(), fn(crate::Error), UringExecutor, _>::new(UringExecutor::default())
        .unwrap()
        .set_error_cb(error_cb)
        .set_local_runtime_cb(|| UringRuntime::with_params(UringParams::new()))
        .set_local_runtimes(core::num::NonZeroUsize::new(1))
        .set_max_connections(max_connections)
        .set_max_delay(max_delay)
        .run_in_threads(&server_addr, router().set_middleware(Http1ServerHeader("rimu-ws")))
    });
    addr
  }

  /// Resets the connection (linger 0) instead of closing it.
  fn reset(stream: TcpStream) {
    let socket = socket2::Socket::from(stream);
    socket.set_linger(Some(Duration::ZERO)).unwrap();
    drop(socket);
  }

  /// How long, from now, until a new connection to a server that serves one at a time is served.
  fn time_to_serve_another(addr: &str) -> Duration {
    let begin = std::time::Instant::now();
    loop {
      assert!(begin.elapsed() < Duration::from_secs(5), "never served");
      let mut next = connect(addr);
      next.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
      let _rslt = next.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n");
      let mut buf = [0; 256];
      let mut got = Vec::new();
      while let Ok(len @ 1..) = next.read(&mut buf) {
        got.extend_from_slice(&buf[..len]);
        if got.ends_with(b"pong") {
          return begin.elapsed();
        }
      }
      std::thread::sleep(Duration::from_millis(20));
    }
  }

  fn connect(addr: &str) -> TcpStream {
    loop {
      if let Ok(elem) = TcpStream::connect(addr) {
        elem.set_nodelay(true).unwrap();
        elem.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        return elem;
      }
      std::thread::sleep(Duration::from_millis(5));
    }
  }

  /// Status line and headers (lower-cased) of the next response, and its body.
  fn read_response(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
      assert_eq!(stream.read(&mut byte).unwrap(), 1, "closed in the middle of a head");
      head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
    let len = head
      .lines()
      .find_map(|el| el.strip_prefix("content-length: "))
      .map(|el| el.trim().parse::<usize>().unwrap())
      .unwrap();
    let mut body = std::vec![0; len];
    stream.read_exact(&mut body).unwrap();
    (head, body)
  }

  #[test]
  fn serves_one_get() {
    let addr = server(|_| {});
    let mut stream = connect(&addr);
    stream.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let (head, body) = read_response(&mut stream);
    assert!(head.starts_with("http/1.1 200 ok\r\n"), "{head}");
    assert_eq!(body, b"pong");
  }

  #[test]
  fn keep_alive_two_requests_one_connection() {
    let addr = server(|_| {});
    let mut stream = connect(&addr);
    for _ in 0..2 {
      stream.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
      let (head, body) = read_response(&mut stream);
      assert!(head.starts_with("http/1.1 200 ok\r\n"), "{head}");
      assert_eq!(body, b"pong");
    }
    // Pipelined: both in one write, answered in order, one of them with a body.
    stream
      .write_all(
        b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabcGET /ping HTTP/1.1\r\nHost: x\r\n\r\n",
      )
      .unwrap();
    assert_eq!(read_response(&mut stream).1, b"abc");
    assert_eq!(read_response(&mut stream).1, b"pong");
  }

  #[test]
  fn connection_close_then_eof() {
    let addr = server(|_| {});
    let mut stream = connect(&addr);
    stream.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let (head, body) = read_response(&mut stream);
    assert!(head.contains("connection: close\r\n"), "{head}");
    assert_eq!(body, b"pong");
    let mut rest = [0; 8];
    assert_eq!(stream.read(&mut rest).unwrap(), 0, "the server did not close");
  }

  #[test]
  fn peer_rst_midrequest_is_clean() {
    use crate::sync::AtomicUsize;
    use core::sync::atomic::Ordering;
    static ERRORS: AtomicUsize = AtomicUsize::new(0);
    let addr = server(|_| {
      let _prev = ERRORS.fetch_add(1, Ordering::Relaxed);
    });
    let mut stream = connect(&addr);
    stream.write_all(b"GET /pi").unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let socket = socket2::Socket::from(stream);
    socket.set_linger(Some(Duration::ZERO)).unwrap();
    drop(socket);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(ERRORS.load(Ordering::Relaxed), 0, "a reset peer was reported as an error");
    let mut next = connect(&addr);
    next.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    assert_eq!(read_response(&mut next).1, b"pong");
  }

  // The head arrives in three pieces with pauses: no deadline counts from the accept, and
  // nothing is written or closed meanwhile.
  #[test]
  fn fragmented_request_with_pauses() {
    let addr = server(|_| {});
    let mut stream = connect(&addr);
    for piece in [&b"GET /pi"[..], b"ng HTTP/1.1\r\nHo", b"st: x\r\n\r\n"] {
      stream.write_all(piece).unwrap();
      std::thread::sleep(Duration::from_millis(50));
    }
    let (head, body) = read_response(&mut stream);
    assert!(head.starts_with("http/1.1 200 ok\r\n"), "{head}");
    assert_eq!(body, b"pong");
    // And a body in pieces
    stream.write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nab").unwrap();
    std::thread::sleep(Duration::from_millis(50));
    stream.write_all(b"cd").unwrap();
    assert_eq!(read_response(&mut stream).1, b"abcd");
  }

  #[test]
  fn routing_params_statuses_and_middleware() {
    let addr = server(|_| {});
    let mut stream = connect(&addr);
    let mut ask = |req: &str| {
      stream.write_all(req.as_bytes()).unwrap();
      read_response(&mut stream)
    };
    let (head, body) = ask("GET /item/42?x=1 HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(body, b"42");
    assert!(head.contains("server: rimu-ws\r\n"), "{head}");
    assert!(ask("GET /nowhere HTTP/1.1\r\nHost: x\r\n\r\n").0.starts_with("http/1.1 404 "));
    let (head, _) = ask("POST /ping HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
    assert!(head.starts_with("http/1.1 405 "), "{head}");
    assert!(head.contains("server: rimu-ws\r\n"), "{head}");
    // A failing handler is a 500 and the connection lives on
    assert!(ask("GET /boom HTTP/1.1\r\nHost: x\r\n\r\n").0.starts_with("http/1.1 500 "));
    let (head, _) = ask("GET /teapot HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(head.starts_with("http/1.1 201 "), "{head}");
    assert_eq!(ask("GET /ping HTTP/1.1\r\nHost: x\r\n\r\n").1, b"pong");
  }

  /// Status line and headers (lower-cased) of the next response, which has no body.
  fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
      assert_eq!(stream.read(&mut byte).unwrap(), 1, "closed in the middle of a head");
      head.push(byte[0]);
    }
    String::from_utf8(head).unwrap().to_ascii_lowercase()
  }

  // HEAD is answered by the GET route, with the length of the GET body and no body, so the next
  // response of the connection is not misread. A method the path has no route for is a 405 that
  // lists the methods it has.
  #[test]
  fn head_is_served_by_get_and_405_lists_allow() {
    let addr = server(|_| {});
    let mut stream = connect(&addr);
    stream
      .write_all(b"HEAD /ping HTTP/1.1\r\nHost: x\r\n\r\nGET /ping HTTP/1.1\r\nHost: x\r\n\r\n")
      .unwrap();
    let head = read_head(&mut stream);
    assert!(head.starts_with("http/1.1 200 ok\r\n"), "{head}");
    assert!(head.contains("content-length: 4\r\n"), "{head}");
    let (head, body) = read_response(&mut stream);
    assert!(head.starts_with("http/1.1 200 ok\r\n"), "{head}");
    assert_eq!(body, b"pong");
    stream.write_all(b"POST /ping HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n").unwrap();
    let (head, _) = read_response(&mut stream);
    assert!(head.starts_with("http/1.1 405 "), "{head}");
    assert!(head.contains("allow: get, head\r\n"), "{head}");
    // A path with routes for two methods lists both, and HEAD after GET
    stream.write_all(b"PUT /both HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n").unwrap();
    let (head, _) = read_response(&mut stream);
    assert!(head.starts_with("http/1.1 405 "), "{head}");
    assert!(head.contains("allow: post, get, head\r\n"), "{head}");
    // A HEAD route of its own wins over the GET one
    stream.write_all(b"HEAD /own-head HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let head = read_head(&mut stream);
    assert!(head.starts_with("http/1.1 201 "), "{head}");
  }

  // A malformed head is answered 400 and then closed.
  #[test]
  fn malformed_request_gets_400_then_eof() {
    let addr = server(|_| {});
    let mut stream = connect(&addr);
    stream.write_all(b"GARBAGE\r\n\r\n").unwrap();
    let (head, _) = read_response(&mut stream);
    assert!(head.starts_with("http/1.1 400 "), "{head}");
    let mut rest = [0; 8];
    assert_eq!(stream.read(&mut rest).unwrap(), 0);
  }

  // A triggered shutdown closes the idle keep-alive connections at once and returns from
  // `run_in_threads` well before the drain time.
  #[test]
  fn shutdown_closes_idle_connections() {
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    let addr = std::format!("{host}:{port}");
    let server_addr = addr.clone();
    let signal = crate::http::ShutdownSignal::new();
    let server_signal = signal.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let _server = std::thread::spawn(move || {
      let rslt = Http1ServerFramework::<(), fn(crate::Error), UringExecutor, _>::new(
        UringExecutor::default(),
      )
      .unwrap()
      .set_local_runtime_cb(|| UringRuntime::with_params(UringParams::new()))
      .set_local_runtimes(core::num::NonZeroUsize::new(2))
      .set_shutdown(server_signal, Duration::from_secs(5))
      .run_in_threads(&server_addr, router());
      let _rslt = done_tx.send(rslt.is_ok());
    });
    let mut stream = connect(&addr);
    stream.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    assert_eq!(read_response(&mut stream).1, b"pong");
    let begin = std::time::Instant::now();
    signal.trigger();
    assert_eq!(done_rx.recv_timeout(Duration::from_secs(3)), Ok(true));
    assert!(begin.elapsed() < Duration::from_secs(3), "{:?}", begin.elapsed());
    let mut rest = [0; 8];
    assert_eq!(stream.read(&mut rest).unwrap(), 0, "the idle connection stayed open");
  }
  // A TLS client that offers only "http/1.1" completes the handshake (a server without that ALPN
  // would reject it) and is served by the same core as a plaintext one, keep-alive included.
  #[cfg(feature = "crypto-ring")]
  #[test]
  fn serves_one_get_over_tls() {
    use crate::{
      executor::StdRuntime,
      net::{StreamReader as _, StreamWriter as _},
      rng::{ChaCha20, CryptoSeedableRng as _},
      tests::{_PUBLIC_KEY, _ROOT_CA, _SECRET_KEY},
      tls::{TlsConfig, TlsConnectorBuilder},
    };
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    let addr = std::format!("{host}:{port}");
    let server_addr = addr.clone();
    let _server = std::thread::spawn(move || {
      let config = TlsConfig::from_keys_pem(_PUBLIC_KEY, _SECRET_KEY).unwrap();
      let rng = ChaCha20::from_std_random().unwrap();
      Http1ServerFramework::<(), fn(crate::Error), UringExecutor, _, _, _>::new_tls(
        UringExecutor::default(),
        rng,
        config,
      )
      .unwrap()
      .set_local_runtime_cb(|| UringRuntime::with_params(UringParams::new()))
      .set_local_runtimes(core::num::NonZeroUsize::new(1))
      .run_in_threads(&server_addr, router().set_middleware(Http1ServerHeader("rimu-ws")))
    });
    let (head, body) = StdRuntime::new().block_on(async move {
      let mut rng = ChaCha20::from_std_random().unwrap();
      let mut config = TlsConfig::from_trust_anchors_pem([_ROOT_CA]).unwrap();
      config
        .alpn_mut()
        .get_or_insert_default()
        .protocol_name_list
        .push(b"http/1.1".as_slice().try_into().unwrap())
        .unwrap();
      let mut tls_stream = loop {
        let connector = TlsConnectorBuilder::std(uri.clone()).build(&config, &mut rng).await;
        if let Ok(elem) = connector {
          break elem.connect().await.unwrap().tls_stream;
        }
        std::thread::sleep(Duration::from_millis(5));
      };
      let mut got = Vec::new();
      let mut buf = [0u8; 4096];
      // Two requests on one connection
      for _ in 0..2 {
        got.clear();
        tls_stream.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        while !got.ends_with(b"pong") {
          let len = tls_stream.read(buf.as_mut_slice().into()).await.unwrap().unwrap();
          got.extend_from_slice(&buf[..len.get()]);
        }
      }
      let at = got.windows(4).position(|el| el == b"\r\n\r\n").unwrap();
      (String::from_utf8(got[..at].to_vec()).unwrap().to_ascii_lowercase(), got[at + 4..].to_vec())
    });
    assert!(head.starts_with("http/1.1 200 ok\r\n"), "{head}");
    assert!(head.contains("server: rimu-ws"), "{head}");
    assert_eq!(body, b"pong");
  }

  /// A one-runtime TLS server; returns its address, and a receiver of whether `run_in_threads`
  /// returned `Ok`.
  #[cfg(feature = "crypto-ring")]
  fn tls_server(
    error_cb: fn(crate::Error),
    max_connections: Option<core::num::NonZeroUsize>,
    shutdown: Option<(crate::http::ShutdownSignal, Duration)>,
  ) -> (crate::net::UriString, std::sync::mpsc::Receiver<bool>) {
    use crate::{
      rng::{ChaCha20, CryptoSeedableRng as _},
      tests::{_PUBLIC_KEY, _SECRET_KEY},
      tls::TlsConfig,
    };
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    let server_addr = std::format!("{host}:{port}");
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let _server = std::thread::spawn(move || {
      let config = TlsConfig::from_keys_pem(_PUBLIC_KEY, _SECRET_KEY).unwrap();
      let rng = ChaCha20::from_std_random().unwrap();
      let fw = Http1ServerFramework::<(), fn(crate::Error), UringExecutor, _, _, _>::new_tls(
        UringExecutor::default(),
        rng,
        config,
      )
      .unwrap()
      .set_error_cb(error_cb)
      .set_local_runtime_cb(|| UringRuntime::with_params(UringParams::new()))
      .set_local_runtimes(core::num::NonZeroUsize::new(1))
      .set_max_connections(max_connections);
      let fw = match shutdown {
        Some((signal, drain)) => fw.set_shutdown(signal, drain),
        None => fw,
      };
      let rslt = fw.run_in_threads(&server_addr, router());
      let _rslt = done_tx.send(rslt.is_ok());
    });
    (uri, done_rx)
  }

  /// A TLS connection to `uri` that offers "http/1.1", retried until the server is up. Reads
  /// time out after 2 s.
  #[cfg(feature = "crypto-ring")]
  async fn tls_connect(
    uri: &crate::net::UriString,
  ) -> crate::tls::TlsStream<TcpStream, crate::tls::TrustedCtx, true> {
    use crate::{
      rng::{ChaCha20, CryptoSeedableRng as _},
      tests::_ROOT_CA,
      tls::{TlsConfig, TlsConnectorBuilder},
    };
    let mut rng = ChaCha20::from_std_random().unwrap();
    let mut config = TlsConfig::from_trust_anchors_pem([_ROOT_CA]).unwrap();
    config
      .alpn_mut()
      .get_or_insert_default()
      .protocol_name_list
      .push(b"http/1.1".as_slice().try_into().unwrap())
      .unwrap();
    let begin = std::time::Instant::now();
    loop {
      assert!(begin.elapsed() < Duration::from_secs(5), "never connected");
      let connector = TlsConnectorBuilder::std(uri.clone()).build(&config, &mut rng).await;
      if let Ok(elem) = connector
        && let Ok(output) = elem.connect().await
      {
        let tls_stream = output.tls_stream;
        tls_stream.stream().set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        return tls_stream;
      }
      std::thread::sleep(Duration::from_millis(5));
    }
  }

  /// Bytes read over TLS until `end` is seen; `None` if the stream ended or failed first.
  #[cfg(feature = "crypto-ring")]
  async fn tls_read_until<S>(stream: &mut S, end: &[u8]) -> Option<Vec<u8>>
  where
    S: crate::net::StreamReader,
  {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while !got.ends_with(end) {
      let len = stream.read(buf.as_mut_slice().into()).await.ok()??;
      got.extend_from_slice(&buf[..len.get()]);
    }
    Some(got)
  }

  // Over TLS too, a peer that resets its connection while its response is delayed ends it at
  // once.
  #[cfg(feature = "crypto-ring")]
  #[test]
  fn delayed_tls_response_notices_a_reset_peer() {
    use crate::{executor::StdRuntime, net::StreamWriter as _};
    let (uri, _done) = tls_server(|_| {}, core::num::NonZeroUsize::new(1), None);
    StdRuntime::new().block_on(async move {
      let mut first = tls_connect(&uri).await;
      first.write_all(b"GET /delay/3000 HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
      std::thread::sleep(Duration::from_millis(100));
      socket2::SockRef::from(first.stream()).set_linger(Some(Duration::ZERO)).unwrap();
      drop(first);
      let begin = std::time::Instant::now();
      loop {
        assert!(begin.elapsed() < Duration::from_secs(5), "never served");
        let mut next = tls_connect(&uri).await;
        next.stream().set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        if next.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n").await.is_ok()
          && tls_read_until(&mut next, b"pong").await.is_some()
        {
          break;
        }
        std::thread::sleep(Duration::from_millis(20));
      }
      let elapsed = begin.elapsed();
      assert!(elapsed < Duration::from_millis(1000), "{elapsed:?}");
    });
  }

  // A triggered shutdown reaches an idle TLS keep-alive connection too: it is closed at once and
  // `run_in_threads` returns well before the drain time.
  #[cfg(feature = "crypto-ring")]
  #[test]
  fn shutdown_closes_idle_tls_connections() {
    use crate::{executor::StdRuntime, net::StreamWriter as _};
    let signal = crate::http::ShutdownSignal::new();
    let (uri, done) = tls_server(|_| {}, None, Some((signal.clone(), Duration::from_secs(4))));
    StdRuntime::new().block_on(async move {
      let mut stream = tls_connect(&uri).await;
      stream.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
      assert!(tls_read_until(&mut stream, b"pong").await.is_some());
      std::thread::sleep(Duration::from_millis(100));
      let begin = std::time::Instant::now();
      signal.trigger();
      assert_eq!(done.recv_timeout(Duration::from_secs(6)), Ok(true));
      let elapsed = begin.elapsed();
      assert!(elapsed < Duration::from_millis(1000), "{elapsed:?}");
      assert!(
        tls_read_until(&mut stream, b"pong").await.is_none(),
        "the idle connection stayed open"
      );
    });
  }

  // The response leaves only after the handler's delay, and the next response of the same
  // connection, which asks for none, is not held back.
  #[test]
  fn delayed_response_waits_not_early() {
    let addr = server(|_| {});
    let mut stream = connect(&addr);
    let begin = std::time::Instant::now();
    stream.write_all(b"GET /delay/60 HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let (head, body) = read_response(&mut stream);
    let elapsed = begin.elapsed();
    assert!(head.starts_with("http/1.1 200 ok\r\n"), "{head}");
    assert_eq!(body, b"60");
    assert!(elapsed >= Duration::from_millis(55), "{elapsed:?}");
    // The delay does not leak into the next response
    let begin = std::time::Instant::now();
    stream.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    assert_eq!(read_response(&mut stream).1, b"pong");
    assert!(begin.elapsed() < Duration::from_millis(40), "{:?}", begin.elapsed());
  }

  // A peer that resets its connection while its response is delayed ends the connection at
  // once: its slot is free for the next client long before the delay is over.
  #[test]
  fn delayed_response_notices_a_reset_peer() {
    use crate::sync::AtomicUsize;
    use core::sync::atomic::Ordering;
    static ERRORS: AtomicUsize = AtomicUsize::new(0);
    let addr = server_with(
      |err| {
        if !matches!(err, crate::Error::TooManyConnections) {
          let _prev = ERRORS.fetch_add(1, Ordering::Relaxed);
        }
      },
      core::num::NonZeroUsize::new(1),
      Duration::from_secs(10),
    );
    let mut first = connect(&addr);
    first.write_all(b"GET /delay/3000 HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(100));
    reset(first);
    let elapsed = time_to_serve_another(&addr);
    assert!(elapsed < Duration::from_millis(1000), "{elapsed:?}");
    assert_eq!(ERRORS.load(Ordering::Relaxed), 0, "a reset peer was reported as an error");
    // The same for a peer that only closes
    let mut first = connect(&addr);
    first.write_all(b"GET /delay/3000 HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(100));
    drop(first);
    let elapsed = time_to_serve_another(&addr);
    assert!(elapsed < Duration::from_millis(1000), "{elapsed:?}");
    assert_eq!(ERRORS.load(Ordering::Relaxed), 0, "a closed peer was reported as an error");
  }

  // What arrives while a response is delayed is kept: a request pipelined during the delay is
  // answered after the delayed response, which still waits for the whole delay.
  #[test]
  fn request_pipelined_during_a_delay_is_answered_after_it() {
    let addr = server(|_| {});
    let mut stream = connect(&addr);
    let begin = std::time::Instant::now();
    stream.write_all(b"GET /delay/300 HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(50));
    // In two pieces, the second with a body
    stream.write_all(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\nPOST /echo HTTP/1.1\r\nHo").unwrap();
    std::thread::sleep(Duration::from_millis(50));
    stream.write_all(b"st: x\r\nContent-Length: 3\r\n\r\nabc").unwrap();
    let (head, body) = read_response(&mut stream);
    let elapsed = begin.elapsed();
    assert!(head.starts_with("http/1.1 200 ok\r\n"), "{head}");
    assert_eq!(body, b"300");
    assert!(elapsed >= Duration::from_millis(295), "{elapsed:?}");
    assert_eq!(read_response(&mut stream).1, b"pong");
    assert_eq!(read_response(&mut stream).1, b"abc");
    // And a delay after a delay, both pipelined at once
    let begin = std::time::Instant::now();
    stream
      .write_all(
        b"GET /delay/100 HTTP/1.1\r\nHost: x\r\n\r\nGET /delay/100 HTTP/1.1\r\nHost: x\r\n\r\n",
      )
      .unwrap();
    assert_eq!(read_response(&mut stream).1, b"100");
    assert_eq!(read_response(&mut stream).1, b"100");
    assert!(begin.elapsed() >= Duration::from_millis(195), "{:?}", begin.elapsed());
  }

  // A delay longer than the server's maximum is cut to it.
  #[test]
  fn delay_is_capped_by_max_delay() {
    let addr = server_with(|_| {}, None, Duration::from_millis(150));
    let mut stream = connect(&addr);
    let begin = std::time::Instant::now();
    stream.write_all(b"GET /delay/3000 HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    assert_eq!(read_response(&mut stream).1, b"3000");
    let elapsed = begin.elapsed();
    assert!(elapsed >= Duration::from_millis(145), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(1000), "{elapsed:?}");
  }

  // Delays overlap: the one runtime thread serves every connection while they wait.
  #[test]
  fn concurrent_distinct_delays() {
    let addr = server(|_| {});
    let begin = std::time::Instant::now();
    let handles: Vec<_> = [40u64, 80, 120, 40, 80, 120]
      .into_iter()
      .map(|ms| {
        let addr = addr.clone();
        std::thread::spawn(move || {
          let mut stream = connect(&addr);
          let sent = std::time::Instant::now();
          stream
            .write_all(std::format!("GET /delay/{ms} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .unwrap();
          let (_, body) = read_response(&mut stream);
          assert_eq!(body, std::format!("{ms}").as_bytes());
          let elapsed = sent.elapsed();
          assert!(elapsed >= Duration::from_millis(ms) * 9 / 10, "{ms}: {elapsed:?}");
        })
      })
      .collect();
    for handle in handles {
      handle.join().unwrap();
    }
    // Serialized they would take 480 ms
    assert!(begin.elapsed() < Duration::from_millis(300), "{:?}", begin.elapsed());
  }
}
