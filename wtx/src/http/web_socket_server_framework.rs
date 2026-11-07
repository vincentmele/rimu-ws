use crate::{
  executor::{Executor, Runtime as _},
  http::{
    Router, ShutdownSignal,
    misc::{accept_or_shutdown, admit, counter, drain_connections, on_accept_error, tracked, within},
  },
  net::{StreamReader, StreamWriter, TcpListener as _, TcpParams, Uri},
  rng::{CryptoRng, CryptoSeedableRng},
  sync::Arc,
  tls::{TlsAcceptor, TlsConfig, TlsCtxSk},
  web_socket::{WebSocket, WebSocketAcceptor, WsCompression},
};
use alloc::{boxed::Box, string::String};
use core::{num::NonZeroUsize, time::Duration};

type LocalWebSocket<CO, EX, TCX> = WebSocket<
  <CO as WsCompression<false>>::NegotiatedCompression,
  <EX as Executor>::TcpStream,
  TCX,
  false,
>;

/// WebSocket Server Framework
#[derive(Debug)]
pub struct WebSocketServerFramework<CO, EC, EX, RC, RNG, TCX> {
  compression: CO,
  error_cb: EC,
  executor: EX,
  handshake_timeout: Option<Duration>,
  local_runtime_cb: RC,
  local_runtimes: Option<NonZeroUsize>,
  max_connections: Option<NonZeroUsize>,
  rng: RNG,
  shutdown: Option<(ShutdownSignal, Duration)>,
  tcp_params: TcpParams,
  tls_config: Arc<TlsConfig<TCX>>,
}

impl<ER, EX, RNG, TCX>
  WebSocketServerFramework<
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
  /// Taking aside the provided parameters, everything else is set to default values.
  #[inline]
  pub fn new(executor: EX, rng: RNG, tls_config: TlsConfig<TCX>) -> crate::Result<Self> {
    let error_cb: fn(_) = |_| {};
    let local_runtime_cb: fn() -> _ = || Ok(EX::LocalRuntime::new()?);
    Ok(Self {
      compression: (),
      error_cb,
      executor,
      handshake_timeout: Some(Duration::from_secs(10)),
      local_runtime_cb,
      local_runtimes: None,
      max_connections: None,
      rng,
      shutdown: None,
      tcp_params: TcpParams::default(),
      tls_config: tls_config.into(),
    })
  }
}

#[cfg(feature = "tokio")]
impl<ER, TCX>
  WebSocketServerFramework<
    (),
    fn(ER),
    crate::executor::TokioExecutor,
    fn() -> Result<<crate::executor::TokioExecutor as Executor>::LocalRuntime, ER>,
    crate::rng::ChaCha20,
    TCX,
  >
where
  ER: From<crate::Error>,
{
  /// Calls [`Self::new`] using the elements provided by the tokio project
  #[inline]
  pub fn tokio(tls_config: TlsConfig<TCX>) -> crate::Result<Self> {
    Self::new(
      crate::executor::TokioExecutor::default(),
      crate::rng::ChaCha20::from_std_random()?,
      tls_config,
    )
  }
}

impl<CO, EC, EX, RC, RNG, TCX> WebSocketServerFramework<CO, EC, EX, RC, RNG, TCX> {
  /// Sets the compression algorithm.
  #[inline]
  pub fn set_compression<_C>(
    self,
    value: _C,
  ) -> WebSocketServerFramework<_C, EC, EX, RC, RNG, TCX> {
    WebSocketServerFramework {
      compression: value,
      error_cb: self.error_cb,
      executor: self.executor,
      handshake_timeout: self.handshake_timeout,
      local_runtime_cb: self.local_runtime_cb,
      local_runtimes: self.local_runtimes,
      max_connections: self.max_connections,
      rng: self.rng,
      shutdown: self.shutdown,
      tcp_params: self.tcp_params,
      tls_config: self.tls_config,
    }
  }

  /// Sets the error callback function.
  #[inline]
  pub fn set_error_cb<_EC>(
    self,
    value: _EC,
  ) -> WebSocketServerFramework<CO, _EC, EX, RC, RNG, TCX> {
    WebSocketServerFramework {
      compression: self.compression,
      error_cb: value,
      executor: self.executor,
      handshake_timeout: self.handshake_timeout,
      local_runtime_cb: self.local_runtime_cb,
      local_runtimes: self.local_runtimes,
      max_connections: self.max_connections,
      rng: self.rng,
      shutdown: self.shutdown,
      tcp_params: self.tcp_params,
      tls_config: self.tls_config,
    }
  }

  /// How long a client has to complete its upgrade (and, with TLS, its TLS handshake) once
  /// accepted. Past that, the connection is closed and the error callback receives
  /// [`crate::Error::ExpiredFuture`]. Defaults to 10 s; `None` waits for as long as it takes.
  ///
  /// [`crate::executor::UringRuntime`] also bounds handshakes on its own (see
  /// [`crate::executor::UringParams::set_handshake_timeout`]), more cheaply than this timer per
  /// connection, so a server on it can set this to `None`.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_handshake_timeout(mut self, value: Option<Duration>) -> Self {
    self.handshake_timeout = value;
    self
  }

  /// Allows the tweaking of the chosen runtime.
  ///
  /// Only works when calling [`Self::run_in_threads`].
  #[inline]
  pub fn set_local_runtime_cb<_RC>(
    self,
    value: _RC,
  ) -> WebSocketServerFramework<CO, EC, EX, _RC, RNG, TCX> {
    WebSocketServerFramework {
      compression: self.compression,
      error_cb: self.error_cb,
      executor: self.executor,
      handshake_timeout: self.handshake_timeout,
      local_runtime_cb: value,
      local_runtimes: self.local_runtimes,
      max_connections: self.max_connections,
      rng: self.rng,
      shutdown: self.shutdown,
      tcp_params: self.tcp_params,
      tls_config: self.tls_config,
    }
  }

  /// The number of spawned runtimes. Shouldn't be greater than the number of available threads.
  ///
  /// Only works when calling [`Self::run_in_threads`]. If [`None`], defaults to the number of threads.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_local_runtimes(mut self, value: Option<NonZeroUsize>) -> Self {
    self.local_runtimes = value;
    self
  }

  /// How many connections the server serves at once, across all of its runtimes. A connection
  /// accepted past that is closed at once, and the error callback receives
  /// [`crate::Error::TooManyConnections`]. Defaults to `None`: no limit beyond the process's
  /// descriptors.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_max_connections(mut self, value: Option<NonZeroUsize>) -> Self {
    self.max_connections = value;
    self
  }

  /// Stops the server when `signal` is triggered: it stops accepting, gives the open connections
  /// up to `drain` to finish, and then returns `Ok`. Connections still open after `drain` are
  /// closed with their runtime. A handler that should close before then (with close code 1001,
  /// say) can wait on a clone of `signal`.
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

  /// See [`TlsConfig`].
  #[inline]
  pub fn set_tls_config<_TM>(
    self,
    value: TlsConfig<_TM>,
  ) -> WebSocketServerFramework<CO, EC, EX, RC, RNG, _TM> {
    WebSocketServerFramework {
      compression: self.compression,
      error_cb: self.error_cb,
      executor: self.executor,
      handshake_timeout: self.handshake_timeout,
      local_runtime_cb: self.local_runtime_cb,
      local_runtimes: self.local_runtimes,
      max_connections: self.max_connections,
      rng: self.rng,
      shutdown: self.shutdown,
      tcp_params: self.tcp_params,
      tls_config: Arc::new(value),
    }
  }
}

impl<CO, EC, ER, EX, RC, RNG, TCX> WebSocketServerFramework<CO, EC, EX, RC, RNG, TCX>
where
  CO: Clone + WsCompression<false> + 'static,
  EC: Clone + Fn(ER) + 'static,
  ER: From<crate::Error> + 'static,
  EX: Clone + Executor + 'static,
  RC: Clone + Fn() -> Result<EX::LocalRuntime, ER> + 'static,
  RNG: CryptoRng + CryptoSeedableRng + 'static,
  TCX: TlsCtxSk + 'static,
{
  /// Starts the server distributing connections across multiple tasks.
  ///
  /// You must call this method from within an existing async environment. Preferably, a
  /// multi-thread environment.
  #[inline]
  pub async fn run<WSR>(mut self, addr: &str, wsr: WSR) -> Result<(), ER>
  where
    CO: Send,
    CO::NegotiatedCompression: Send + Sync,
    EC: Send,
    ER: Send,
    EX: Send,
    EX::TcpStream: Send,
    RC: Send,
    RNG: Send,
    TCX: Send + Sync,
    WSR: WebSocketRouter<CO, ER, EX, TCX> + Send + Sync + 'static,
    WSR::call(..): Send,
    <EX::TcpStream as StreamReader>::read(..): Send,
    <EX::TcpStream as StreamWriter>::write_all(..): Send,
    <EX::TcpStream as StreamWriter>::write_all_vectored(..): Send,
    <EX::TcpStream as StreamWriter>::send_room(..): Send,
  {
    let uri = Uri::new(addr);
    let web_socket_router = Arc::new(wsr);
    let listener = EX::TcpListener::bind(uri.hostname_with_implied_port(), self.tcp_params).await?;
    let router = build_matcher(&*web_socket_router)?;
    let shutdown = self.shutdown.clone();
    let active = counter(shutdown.as_ref(), self.max_connections);
    loop {
      let accept = conn_params::<CO, EC, EX, RNG, TCX, WSR>(
        (&self.compression, &self.error_cb),
        (&mut self.rng, self.tcp_params, &self.tls_config, self.handshake_timeout),
        &listener,
        &router,
        &web_socket_router,
      );
      let Some(rslt) = accept_or_shutdown(accept, shutdown.as_ref().map(|el| &el.0)).await else {
        break;
      };
      let cp = match rslt {
        Ok(elem) => elem,
        Err(err) => {
          on_accept_error(&self.error_cb, err).await;
          continue;
        }
      };
      if let Some(active) = &active {
        if !admit(active, self.max_connections) {
          drop(cp);
          (self.error_cb)(crate::Error::TooManyConnections.into());
          continue;
        }
        let _jh = self.executor.spawn(tracked(conn_fut(cp), active.clone()));
      } else {
        let _jh = self.executor.spawn(conn_fut(cp));
      }
    }
    drop(listener);
    if let (Some((_, drain)), Some(active)) = (&shutdown, &active) {
      drain_connections(active, *drain).await;
    }
    Ok(())
  }

  /// Starts the server using a runtime-per-thread architecture.
  ///
  /// Contrary to the other methods, this method internally creates a runtime according to the
  /// specified `local_runtimes` value.
  ///
  /// Returns the first thread's error, or its panic as an error, as soon as one happens. The
  /// other threads are left running, so call this from the main thread: returning from `main`
  /// then ends the process instead of leaving a server short of a core. After a shutdown (see
  /// [`Self::set_shutdown`]), returns `Ok` once every thread has drained.
  #[cfg(feature = "std")]
  #[inline]
  pub fn run_in_threads<WSR>(mut self, addr: &str, wsr: WSR) -> Result<(), ER>
  where
    CO: Send,
    EC: Send,
    ER: Send,
    EX: Send,
    RC: Send,
    RNG: Send,
    TCX: Send + Sync,
    WSR: WebSocketRouter<CO, ER, EX, TCX> + Send + Sync + 'static,
  {
    let runtimes = if let Some(elem) = self.local_runtimes {
      elem.get()
    } else {
      std::thread::available_parallelism().map_err(crate::Error::from)?.get()
    };
    let web_socket_router = Arc::new(wsr);
    let router = build_matcher(&*web_socket_router)?;
    let (done_tx, done_rx) = std::sync::mpsc::channel::<Result<(), ER>>();
    // One count for every runtime, so that the limit is the server's
    let active = counter(self.shutdown.as_ref(), self.max_connections);
    for _ in 0..runtimes {
      let thread_active = active.clone();
      let thread_max_connections = self.max_connections;
      let thread_done = done_tx.clone();
      let thread_comp = self.compression.clone();
      let thread_error_cb = self.error_cb.clone();
      let thread_executor = self.executor.clone();
      let thread_local_runtime_cb = self.local_runtime_cb.clone();
      let mut thread_rng = RNG::from_crypto_rng(&mut self.rng)?;
      let thread_router = router.clone();
      let thread_tcp_params = self.tcp_params;
      let thread_tls_config = self.tls_config.clone();
      let thread_uri = Uri::new(String::from(addr));
      let thread_web_socket_router = web_socket_router.clone();
      let thread_shutdown = self.shutdown.clone();
      let thread_handshake_timeout = self.handshake_timeout;
      let thread_body = move || -> Result<(), ER> {
        let lc = thread_local_runtime_cb()?;
        lc.block_on(async {
          let hostname = thread_uri.hostname_with_implied_port();
          let listener = EX::TcpListener::bind(hostname, thread_tcp_params).await?;
          let shutdown = thread_shutdown;
          let active = thread_active;
          loop {
            let accept = conn_params::<CO, EC, EX, RNG, TCX, WSR>(
              (&thread_comp, &thread_error_cb),
              (&mut thread_rng, thread_tcp_params, &thread_tls_config, thread_handshake_timeout),
              &listener,
              &thread_router,
              &thread_web_socket_router,
            );
            let Some(rslt) = accept_or_shutdown(accept, shutdown.as_ref().map(|el| &el.0)).await
            else {
              break;
            };
            let cp = match rslt {
              Ok(elem) => elem,
              Err(err) => {
                on_accept_error(&thread_error_cb, err).await;
                continue;
              }
            };
            if let Some(active) = &active {
              if !admit(active, thread_max_connections) {
                drop(cp);
                (thread_error_cb)(crate::Error::TooManyConnections.into());
                continue;
              }
              let _jh = thread_executor.spawn_local(tracked(conn_fut(cp), active.clone()), &lc);
            } else {
              let _jh = thread_executor.spawn_local(conn_fut(cp), &lc);
            }
          }
          drop(listener);
          if let (Some((_, drain)), Some(active)) = (&shutdown, &active) {
            drain_connections(active, *drain).await;
          }
          Ok(())
        })
      };
      let _jh = std::thread::spawn(move || {
        let rslt = std::panic::catch_unwind(core::panic::AssertUnwindSafe(thread_body))
          .unwrap_or_else(|payload| Err(crate::Error::from(payload).into()));
        let _rslt = thread_done.send(rslt);
      });
    }
    drop(done_tx);
    // A thread ends only on an error, a panic or a shutdown. The first error is returned at once;
    // after a shutdown, every thread drains before this returns.
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

  /// Starts the server handling all connections on the current thread.
  ///
  /// You must call this method from within an existing async environment.
  #[inline]
  pub async fn run_local<WSR>(
    mut self,
    addr: &str,
    lc: &EX::LocalRuntime,
    wsr: WSR,
  ) -> Result<(), ER>
  where
    WSR: WebSocketRouter<CO, ER, EX, TCX> + 'static,
  {
    let web_socket_router = Arc::new(wsr);
    let router = build_matcher(&*web_socket_router)?;
    let uri = Uri::new(addr);
    let listener = EX::TcpListener::bind(uri.hostname_with_implied_port(), self.tcp_params).await?;
    let shutdown = self.shutdown.clone();
    let active = counter(shutdown.as_ref(), self.max_connections);
    loop {
      let accept = conn_params::<CO, EC, EX, RNG, TCX, WSR>(
        (&self.compression, &self.error_cb),
        (&mut self.rng, self.tcp_params, &self.tls_config, self.handshake_timeout),
        &listener,
        &router,
        &web_socket_router,
      );
      let Some(rslt) = accept_or_shutdown(accept, shutdown.as_ref().map(|el| &el.0)).await else {
        break;
      };
      let cp = match rslt {
        Ok(elem) => elem,
        Err(err) => {
          on_accept_error(&self.error_cb, err).await;
          continue;
        }
      };
      if let Some(active) = &active {
        if !admit(active, self.max_connections) {
          drop(cp);
          (self.error_cb)(crate::Error::TooManyConnections.into());
          continue;
        }
        let _jh = self.executor.spawn_local(tracked(conn_fut(cp), active.clone()), lc);
      } else {
        let _jh = self.executor.spawn_local(conn_fut(cp), lc);
      }
    }
    drop(listener);
    if let (Some((_, drain)), Some(active)) = (&shutdown, &active) {
      drain_connections(active, *drain).await;
    }
    Ok(())
  }
}

/// Routes path according to the set of user-provided functions and paths.
pub trait WebSocketRouter<CO, ER, EX, TCX>
where
  CO: WsCompression<false>,
  EX: Executor,
{
  /// Calls user-provided functions.
  fn call(
    &self,
    matcher: &Router<u8>,
    path: String,
    ws: LocalWebSocket<CO, EX, TCX>,
  ) -> impl Future<Output = Result<(), ER>>;

  /// All user registered paths
  fn paths(&self) -> impl ExactSizeIterator<Item = &'static str>;
}

struct ConnParams<CO, EC, EX, RNG, TCX, WSR>
where
  EX: Executor,
{
  compression: CO,
  error_cb: EC,
  handshake_timeout: Option<Duration>,
  rng: RNG,
  router: Arc<Router<u8>>,
  stream: EX::TcpStream,
  tls_config: Arc<TlsConfig<TCX>>,
  web_socket_router: Arc<WSR>,
}

fn build_matcher<CO, ER, EX, TCX, WSR>(web_socket_router: &WSR) -> crate::Result<Arc<Router<u8>>>
where
  CO: WsCompression<false>,
  EX: Executor,
  WSR: WebSocketRouter<CO, ER, EX, TCX>,
{
  let mut matcher = Router::new();
  {
    let mut builder = matcher.builder();
    let mut idx: u8 = 0;
    for path in web_socket_router.paths() {
      let _ = builder.add(&path.try_into()?, idx)?;
      idx = idx.wrapping_add(1);
    }
  }
  Ok(Arc::new(matcher))
}

// The handshake is boxed and freed once the upgrade is done. Inline, its state (the TLS
// acceptor, the RNG and the request parse, about 6 KiB) would set the size of every
// connection's task for as long as the connection stays open, though the handler never
// touches it. A plain `fn` returning `async move` also keeps the parameters from being stored
// twice, as an `async fn` stores its arguments.
#[inline]
fn conn_fut<CO, EC, ER, EX, RNG, TCX, WSR>(
  conn_params: ConnParams<CO, EC, EX, RNG, TCX, WSR>,
) -> impl Future<Output = ()>
where
  CO: WsCompression<false>,
  EC: Fn(ER),
  ER: From<crate::Error>,
  EX: Executor,
  RNG: CryptoRng + CryptoSeedableRng,
  TCX: TlsCtxSk,
  WSR: WebSocketRouter<CO, ER, EX, TCX>,
{
  let ConnParams {
    compression,
    error_cb,
    handshake_timeout,
    rng,
    router,
    stream,
    tls_config,
    web_socket_router,
  } = conn_params;
  let handshake_router = router.clone();
  let handshake = Box::pin(async move {
    let mut path = String::new();
    let accept = WebSocketAcceptor::default()
      .set_compression(compression)
      .set_req(|req| {
        // Routed on the path without its query, and before the 101: a path no route has is
        // answered 400, not upgraded and dropped.
        let route = req.path.map_or("", |el| el.split_once('?').map_or(el, |parts| parts.0));
        if handshake_router.find(route).is_err() {
          return crate::Result::Ok(false);
        }
        path.push_str(route);
        crate::Result::Ok(true)
      })
      .accept(TlsAcceptor::new(&*tls_config, rng, stream));
    let web_socket = within(accept, handshake_timeout).await?;
    crate::Result::Ok((path, web_socket))
  });
  // Errors handled inline rather than through an inner `async` block: each nested future is
  // another state the task walks through on every poll.
  async move {
    let (path, web_socket) = match handshake.await {
      Ok(elem) => elem,
      Err(err) => {
        error_cb(err.into());
        return;
      }
    };
    if let Err(err) = web_socket_router.call(&router, path, web_socket).await {
      error_cb(err);
    }
  }
}

async fn conn_params<CO, EC, EX, RNG, TCX, WSR>(
  (compression, error_cb): (&CO, &EC),
  (rng, tcp_params, tls_config, handshake_timeout): (
    &mut RNG,
    TcpParams,
    &Arc<TlsConfig<TCX>>,
    Option<Duration>,
  ),
  listener: &EX::TcpListener,
  router: &Arc<Router<u8>>,
  web_socket_router: &Arc<WSR>,
) -> crate::Result<ConnParams<CO, EC, EX, RNG, TCX, WSR>>
where
  CO: Clone,
  EC: Clone,
  EX: Executor,
  RNG: CryptoRng + CryptoSeedableRng,
{
  Ok(ConnParams {
    compression: compression.clone(),
    error_cb: error_cb.clone(),
    handshake_timeout,
    rng: RNG::from_crypto_rng(rng)?,
    router: router.clone(),
    stream: listener.accept(tcp_params).await?.0,
    tls_config: tls_config.clone(),
    web_socket_router: web_socket_router.clone(),
  })
}

#[cfg(all(test, feature = "io-uring"))]
mod tests {
  use crate::{
    collections::VectorUsize,
    executor::{UringExecutor, UringRuntime, UringTcpStream},
    http::WebSocketServerFramework,
    rng::{ChaCha20, CryptoSeedableRng},
    tests::_uri,
    tls::{PlaintextCtx, TlsConfig},
    web_socket::{OpCode, WebSocket, WebSocketPayloadOrigin},
  };
  use std::io::{Read, Write};

  async fn echo(
    mut buffer: VectorUsize<u8>,
    mut ws: WebSocket<(), UringTcpStream, PlaintextCtx, false>,
  ) -> crate::Result<()> {
    let (mut common, mut reader, mut writer) = ws.split_mut();
    loop {
      let mut frame =
        reader.read_frame(&mut buffer, &mut common, WebSocketPayloadOrigin::Adaptive).await?;
      match frame.op_code() {
        OpCode::Text | OpCode::Binary => writer.write_frame(&mut common, &mut frame).await?,
        OpCode::Close => return Ok(()),
        _ => {}
      }
    }
  }

  /// The status of the server's answer to an upgrade of `target`, and whether a text sent after
  /// a 101 came back.
  fn upgrade(addr: &str, target: &str) -> (std::string::String, bool) {
    let mut stream = loop {
      if let Ok(elem) = std::net::TcpStream::connect(addr) {
        break elem;
      }
      std::thread::sleep(core::time::Duration::from_millis(5));
    };
    stream.set_read_timeout(Some(core::time::Duration::from_secs(2))).unwrap();
    let req = std::format!(
      "GET {target} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut head = std::vec::Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
      head.push(byte[0]);
    }
    let status =
      std::string::String::from_utf8_lossy(head.get(9..12).unwrap_or_default()).into_owned();
    if status != "101" {
      return (status, false);
    }
    // A masked "hi".
    stream.write_all(&[0x81, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2]).unwrap();
    let mut echo = [0; 4];
    let echoed = stream.read_exact(&mut echo).is_ok() && echo == [0x81, 2, b'h', b'i'];
    (status, echoed)
  }

  // Queries and long paths reach the handler of their route; a path no route has gets a 400, not
  // a 101 and a dropped connection.
  #[test]
  fn routes_are_matched_before_the_upgrade() {
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    let addr = std::format!("{host}:{port}");
    let server_addr = addr.clone();
    let _server = std::thread::spawn(move || {
      WebSocketServerFramework::<(), fn(crate::Error), UringExecutor, _, ChaCha20, PlaintextCtx>::new(
        UringExecutor::default(),
        ChaCha20::from_std_random().unwrap(),
        TlsConfig::plaintext(),
      )
      .unwrap()
      .set_local_runtime_cb(|| UringRuntime::with_params(crate::executor::UringParams::new()))
      .set_local_runtimes(core::num::NonZeroUsize::new(1))
      .run_in_threads(&server_addr, (("/chat", echo),))
    });
    assert_eq!(upgrade(&addr, "/chat"), ("101".into(), true));
    assert_eq!(upgrade(&addr, "/chat?room=1&user=2"), ("101".into(), true));
    let long = std::format!("/chat?pad={}", "a".repeat(4000));
    assert_eq!(upgrade(&addr, &long), ("101".into(), true));
    assert_eq!(upgrade(&addr, "/nowhere").0, "400");
  }

  // A triggered shutdown stops the accept loops, gives the open connections the drain time to
  // finish, and then returns from `run_in_threads`, which waits for every thread.
  #[test]
  fn shutdown_stops_accepting_and_drains() {
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    let addr = std::format!("{host}:{port}");
    let server_addr = addr.clone();
    let signal = crate::http::ShutdownSignal::new();
    let server_signal = signal.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let _server = std::thread::spawn(move || {
      let rslt = WebSocketServerFramework::<
        (),
        fn(crate::Error),
        UringExecutor,
        _,
        ChaCha20,
        PlaintextCtx,
      >::new(
        UringExecutor::default(),
        ChaCha20::from_std_random().unwrap(),
        TlsConfig::plaintext(),
      )
      .unwrap()
      .set_local_runtime_cb(|| UringRuntime::with_params(crate::executor::UringParams::new()))
      .set_local_runtimes(core::num::NonZeroUsize::new(2))
      .set_shutdown(server_signal, core::time::Duration::from_millis(300))
      .run_in_threads(&server_addr, (("/", echo),));
      let _rslt = done_tx.send(rslt.is_ok());
    });
    // A client that stays connected through the shutdown
    let (status, _) = upgrade(&addr, "/");
    assert_eq!(status, "101");
    let mut open = std::net::TcpStream::connect(&addr).unwrap();
    open
      .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
      .unwrap();
    std::thread::sleep(core::time::Duration::from_millis(100));
    let begin = std::time::Instant::now();
    signal.trigger();
    let rslt = done_rx.recv_timeout(core::time::Duration::from_secs(3));
    assert_eq!(rslt, Ok(true), "run_in_threads did not return after the shutdown");
    assert!(begin.elapsed() >= core::time::Duration::from_millis(300), "{:?}", begin.elapsed());
    assert!(std::net::TcpStream::connect(&addr).is_err(), "still accepting after the shutdown");
    open.set_read_timeout(Some(core::time::Duration::from_secs(2))).unwrap();
    let mut rest = std::vec::Vec::new();
    let _rslt = open.read_to_end(&mut rest);
    assert!(rest.starts_with(b"HTTP/1.1 101"), "the open connection was not served then closed");
  }

  // A one-runtime server on `addr`, its handshake timeout and connection limit as given.
  fn server(
    addr: &str,
    params: crate::executor::UringParams,
    handshake_timeout: Option<core::time::Duration>,
    max_connections: Option<core::num::NonZeroUsize>,
    error_cb: fn(crate::Error),
  ) {
    let server_addr = std::string::String::from(addr);
    let _server = std::thread::spawn(move || {
      WebSocketServerFramework::<(), fn(crate::Error), UringExecutor, _, ChaCha20, PlaintextCtx>::new(
        UringExecutor::default(),
        ChaCha20::from_std_random().unwrap(),
        TlsConfig::plaintext(),
      )
      .unwrap()
      .set_error_cb(error_cb)
      .set_handshake_timeout(handshake_timeout)
      .set_local_runtime_cb(move || UringRuntime::with_params(params))
      .set_local_runtimes(core::num::NonZeroUsize::new(1))
      .set_max_connections(max_connections)
      .run_in_threads(&server_addr, (("/", echo),))
    });
  }

  fn connect(addr: &str) -> std::net::TcpStream {
    loop {
      if let Ok(elem) = std::net::TcpStream::connect(addr) {
        elem.set_read_timeout(Some(core::time::Duration::from_secs(2))).unwrap();
        return elem;
      }
      std::thread::sleep(core::time::Duration::from_millis(5));
    }
  }

  // What a connection reads before the server closes it, or `None` if it is still open after the
  // read timeout.
  fn read_until_closed(stream: &mut std::net::TcpStream) -> Option<std::vec::Vec<u8>> {
    let mut rest = std::vec::Vec::new();
    match stream.read_to_end(&mut rest) {
      Ok(_) => Some(rest),
      Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => Some(rest),
      Err(_) => None,
    }
  }

  // A client that connects and sends nothing is closed once the handshake timeout passes, also
  // on a runtime that has no handshake timeout of its own (as with tokio).
  #[test]
  fn a_silent_client_is_closed_after_the_handshake_timeout() {
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    let addr = std::format!("{host}:{port}");
    server(
      &addr,
      crate::executor::UringParams::new().set_handshake_timeout(None),
      Some(core::time::Duration::from_millis(200)),
      None,
      |_| {},
    );
    let mut silent = connect(&addr);
    let begin = std::time::Instant::now();
    assert_eq!(read_until_closed(&mut silent), Some(std::vec::Vec::new()));
    let elapsed = begin.elapsed();
    assert!(elapsed >= core::time::Duration::from_millis(150), "{elapsed:?}");
    // A client that upgrades in time is served past the timeout.
    let (status, echoed) = upgrade(&addr, "/");
    assert_eq!((status.as_str(), echoed), ("101", true));
  }

  // Past the connection limit, a new connection is closed at once instead of served, and the
  // error callback hears of it; once one closes, the next is served again.
  #[test]
  fn connections_past_the_limit_are_refused() {
    use crate::sync::AtomicUsize;
    use core::sync::atomic::Ordering;
    static REFUSED: AtomicUsize = AtomicUsize::new(0);
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    let addr = std::format!("{host}:{port}");
    server(
      &addr,
      crate::executor::UringParams::new(),
      None,
      core::num::NonZeroUsize::new(2),
      |err| {
        if matches!(err, crate::Error::TooManyConnections) {
          let _prev = REFUSED.fetch_add(1, Ordering::Relaxed);
        }
      },
    );
    let req = b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let mut first = connect(&addr);
    first.write_all(req).unwrap();
    let mut second = connect(&addr);
    second.write_all(req).unwrap();
    let mut head = [0; 12];
    first.read_exact(&mut head).unwrap();
    assert_eq!(&head, b"HTTP/1.1 101");
    second.read_exact(&mut head).unwrap();
    assert_eq!(&head, b"HTTP/1.1 101");
    let mut third = connect(&addr);
    let _rslt = third.write_all(req);
    assert_eq!(read_until_closed(&mut third), Some(std::vec::Vec::new()));
    assert_eq!(REFUSED.load(Ordering::Relaxed), 1);
    drop(first);
    // The server sees the close and ends the first connection's task.
    let begin = std::time::Instant::now();
    loop {
      let (status, echoed) = upgrade(&addr, "/");
      if status == "101" {
        assert!(echoed);
        break;
      }
      assert!(begin.elapsed() < core::time::Duration::from_secs(2), "no room after a close");
      std::thread::sleep(core::time::Duration::from_millis(10));
    }
  }

  // When one thread of `run_in_threads` fails, the call returns its error at once, whichever
  // thread it was: it used to join the threads in order and wait on the first forever.
  #[test]
  fn a_failed_thread_ends_run_in_threads() {
    use crate::sync::AtomicUsize;
    use core::sync::atomic::Ordering;
    static RUNTIMES: AtomicUsize = AtomicUsize::new(0);
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    let addr = std::format!("{host}:{port}");
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let _server = std::thread::spawn(move || {
      let rslt = WebSocketServerFramework::<
        (),
        fn(crate::Error),
        UringExecutor,
        _,
        ChaCha20,
        PlaintextCtx,
      >::new(
        UringExecutor::default(),
        ChaCha20::from_std_random().unwrap(),
        TlsConfig::plaintext(),
      )
      .unwrap()
      .set_local_runtime_cb(|| {
        // The second runtime fails to start; give the first time to be serving.
        if RUNTIMES.fetch_add(1, Ordering::Relaxed) == 0 {
          UringRuntime::with_params(crate::executor::UringParams::new())
        } else {
          std::thread::sleep(core::time::Duration::from_millis(100));
          Err(std::io::Error::from_raw_os_error(libc::ENOMEM).into())
        }
      })
      .set_local_runtimes(core::num::NonZeroUsize::new(2))
      .run_in_threads(&addr, (("/", echo),));
      let _rslt = done_tx.send(rslt.is_err());
    });
    let failed = done_rx.recv_timeout(core::time::Duration::from_secs(5));
    assert_eq!(failed, Ok(true), "run_in_threads did not return the failed thread's error");
  }
}
