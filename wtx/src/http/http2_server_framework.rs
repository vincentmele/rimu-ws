//! Tools and libraries that make it easier to write, maintain, and scale web applications.

#[macro_use]
mod macros;

#[cfg(feature = "std")]
pub(crate) mod conn_driver;
mod cors_middleware;
mod dyn_params;
mod endpoint;
mod endpoint_node;
mod form_data;
#[cfg(feature = "std")]
mod handler_slots;
mod http2_server_framework_error;
mod http_router;
mod json_reply;
mod methods;
mod middleware;
mod misc;
mod path;
mod path_params;
mod redirect;
mod res_finalizer;
mod route_match;
mod state;
#[cfg(feature = "std")]
mod static_files;
#[cfg(all(test, feature = "io-uring"))]
mod fw_tests;
#[cfg(test)]
mod tests;
#[cfg(all(test, feature = "io-uring", feature = "web-socket"))]
mod uring_tests;
mod verbatim_params;

use crate::{
  executor::{Executor, Runtime as _},
  http::{HttpRecvParams, ShutdownSignal, push_h2_alpn},
  net::TcpParams,
  sync::Arc,
  tls::TlsConfig,
};
use core::{num::NonZeroUsize, time::Duration};
pub use cors_middleware::{CorsMiddleware, OriginResponse};
pub use dyn_params::DynParams;
pub use endpoint::Endpoint;
pub use endpoint_node::EndpointNode;
pub use form_data::*;
pub use http_router::HttpRouter;
pub use http2_server_framework_error::Http2ServerFrameworkError;
pub use json_reply::*;
pub use methods::{
  delete::{Delete, delete},
  get::{Get, get},
  json::{Json, json},
  patch::{Patch, patch},
  post::{Post, post},
  put::{Put, put},
  web_socket::{WebSocket, web_socket},
};
pub use middleware::Middleware;
pub use path::Path;
pub use path_params::PathParams;
pub use redirect::Redirect;
pub use res_finalizer::ResFinalizer;
pub use route_match::RouteMatch;
pub use state::{State, StateClean, StateGeneric, StateTest};
#[cfg(feature = "std")]
pub use static_files::StaticFiles;
pub use verbatim_params::VerbatimParams;

/// HTTP/2 Server Framework
#[derive(Debug)]
pub struct Http2ServerFramework<DA, EC, EX, RC, RNG, TCX> {
  data: DA,
  error_cb: EC,
  executor: EX,
  handshake_timeout: Option<Duration>,
  hrc: HttpRecvParams,
  idle_timeout: Option<Duration>,
  local_runtime_cb: RC,
  local_runtimes: Option<NonZeroUsize>,
  max_connections: Option<NonZeroUsize>,
  rng: RNG,
  shutdown: Option<(ShutdownSignal, Duration)>,
  tcp_params: TcpParams,
  tls_config: Arc<TlsConfig<TCX>>,
}

impl<ERR, EX, RNG, TCX>
  Http2ServerFramework<
    (),
    fn(ERR),
    EX,
    fn() -> Result<<EX as Executor>::LocalRuntime, ERR>,
    RNG,
    TCX,
  >
where
  ERR: From<crate::Error>,
  EX: Executor,
{
  /// Taking aside the provided parameters, everything else is set to default values.
  ///
  /// The "h2" ALPN will always be pushed into the TLS configuration, and kernel TLS turned off
  /// ([`TlsConfig::kernel_tls`]): HTTP/2 connections seal their records in user space, which
  /// measured faster than the kernel on small and on 16 KiB records alike (the kernel sends one
  /// TCP segment per record and copies each record twice).
  #[inline]
  pub fn new(executor: EX, rng: RNG, mut tls_config: TlsConfig<TCX>) -> crate::Result<Self> {
    push_h2_alpn(&mut tls_config)?;
    *tls_config.kernel_tls_mut() = false;
    let error_cb: fn(_) = |_| {};
    let local_runtime_cb: fn() -> _ = || Ok(EX::LocalRuntime::new()?);
    Ok(Self {
      data: (),
      error_cb,
      executor,
      handshake_timeout: Some(Duration::from_secs(10)),
      hrc: HttpRecvParams::with_optioned_params(),
      idle_timeout: Some(Duration::from_secs(300)),
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

impl<DA, EC, EX, RC, RNG, TCX> Http2ServerFramework<DA, EC, EX, RC, RNG, TCX> {
  /// Mutable Random Number Generator.
  #[inline]
  pub const fn rng_mut(&mut self) -> &mut RNG {
    &mut self.rng
  }

  /// Shared data that is cloned across connections and streams.
  #[inline]
  pub fn set_data<_DA>(self, value: _DA) -> Http2ServerFramework<_DA, EC, EX, RC, RNG, TCX> {
    Http2ServerFramework {
      data: value,
      error_cb: self.error_cb,
      executor: self.executor,
      handshake_timeout: self.handshake_timeout,
      hrc: self.hrc,
      idle_timeout: self.idle_timeout,
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
  pub fn set_error_cb<_EC>(self, value: _EC) -> Http2ServerFramework<DA, _EC, EX, RC, RNG, TCX> {
    Http2ServerFramework {
      data: self.data,
      error_cb: value,
      executor: self.executor,
      handshake_timeout: self.handshake_timeout,
      hrc: self.hrc,
      idle_timeout: self.idle_timeout,
      local_runtime_cb: self.local_runtime_cb,
      local_runtimes: self.local_runtimes,
      max_connections: self.max_connections,
      rng: self.rng,
      shutdown: self.shutdown,
      tcp_params: self.tcp_params,
      tls_config: self.tls_config,
    }
  }

  /// See [`HttpRecvParams`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_http_recv_params(mut self, value: HttpRecvParams) -> Self {
    self.hrc = value;
    self
  }

  /// Allows the tweaking of the chosen runtime.
  #[inline]
  pub fn set_local_runtime_cb<_RC>(
    self,
    value: _RC,
  ) -> Http2ServerFramework<DA, EC, EX, _RC, RNG, TCX> {
    Http2ServerFramework {
      data: self.data,
      error_cb: self.error_cb,
      executor: self.executor,
      handshake_timeout: self.handshake_timeout,
      hrc: self.hrc,
      idle_timeout: self.idle_timeout,
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

  /// How long a client has to complete the TLS handshake (if any) and send its preface and first
  /// SETTINGS once accepted. Past that, the connection is closed and the error callback receives
  /// [`crate::Error::ExpiredFuture`]. Defaults to 10 s; `None` waits for as long as it takes.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_handshake_timeout(mut self, value: Option<Duration>) -> Self {
    self.handshake_timeout = value;
    self
  }

  /// How long a connection may go with no open stream and nothing received. Past that, it is sent
  /// GOAWAY (`NO_ERROR`) and closed. Defaults to 300 s; `None` keeps idle connections open.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_idle_timeout(mut self, value: Option<Duration>) -> Self {
    self.idle_timeout = value;
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

  /// Stops the server when `signal` is triggered: it stops accepting, sends every connection
  /// GOAWAY (`NO_ERROR`), lets the streams already open finish within `drain`, and then returns
  /// `Ok`. Connections still open after `drain` are closed with their runtime.
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

#[cfg(feature = "io-uring")]
mod uring {
  use crate::{
    executor::{Executor as _, Runtime as _, UringExecutor, UringRuntime},
    http::{
      AutoStream, HttpRecvParams, ManualStream, MsgBufferString, OperationMode, Protocol, Request,
      StatusCode,
      ShutdownSignal,
      http2_server_framework::{
        Endpoint as _, EndpointNode, Http2ServerFramework, HttpRouter, Middleware, RouteMatch,
        conn_driver::{
          AutoOutput, DriveParams, Route, StreamDispatcher, drive_conn, go_away_local_conns,
          reset_going_away,
        },
      },
      misc::{
        accept_or_shutdown, admit, counter, drain_connections, on_accept_error, tracked, within,
      },
    },
    collections::ArrayVectorCopy,
    http2::{ServerStream, conn::Http2Conn},
    net::{TcpListener as _, TcpParams, Uri},
    rng::{CryptoRng, CryptoSeedableRng, SeedableRng as _, Xorshift64},
    sync::{Arc, AtomicUsize},
    tls::{TlsAcceptor, TlsConfig, TlsCtxSk},
  };
  use alloc::string::String;
  use core::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    time::Duration,
  };

  impl<DA, EC, ER, RC, RNG, TCX> Http2ServerFramework<DA, EC, UringExecutor, RC, RNG, TCX>
  where
    EC: Clone + Fn(ER) + 'static,
    DA: Clone + 'static,
    ER: From<crate::Error> + 'static,
    RC: Clone + Fn() -> Result<UringRuntime, ER> + 'static,
    RNG: CryptoRng + CryptoSeedableRng + 'static,
    TCX: TlsCtxSk + 'static,
  {
    /// Starts the server with one io_uring runtime per thread, each with its own listener
    /// (`SO_REUSEPORT`).
    ///
    /// Call it from the main thread: the first thread that ends with an error ends the call.
    #[inline]
    pub fn run_in_threads<EN, M>(
      mut self,
      addr: &str,
      hr: HttpRouter<DA, EN, ER, M, ServerStream>,
    ) -> Result<(), ER>
    where
      DA: Send,
      EC: Send,
      EN: EndpointNode<DA, ER, ServerStream> + Send + Sync + 'static,
      ER: Send,
      M: Middleware<DA, ER> + Send + Sync + 'static,
      RC: Send,
      RNG: Send,
      TCX: Send + Sync,
    {
      let runtimes = if let Some(elem) = self.local_runtimes {
        elem.get()
      } else {
        std::thread::available_parallelism().map_err(crate::Error::from)?.get()
      };
      let http_router = Arc::new(hr);
      let (done_tx, done_rx) = std::sync::mpsc::channel::<Result<(), ER>>();
      // One count for every runtime, so that the limit is the server's
      let active = counter(self.shutdown.as_ref(), self.max_connections);
      for _ in 0..runtimes {
        let server = ThreadServer {
          active: active.clone(),
          data: self.data.clone(),
          drive_params: self.drive_params(),
          error_cb: self.error_cb.clone(),
          hrc: self.hrc,
          http_router: http_router.clone(),
          max_connections: self.max_connections,
          rng: RNG::from_crypto_rng(&mut self.rng)?,
          shutdown: self.shutdown.clone(),
          tcp_params: self.tcp_params,
          tls_config: self.tls_config.clone(),
        };
        let local_runtime_cb = self.local_runtime_cb.clone();
        let thread_addr = String::from(addr);
        let thread_done = done_tx.clone();
        let _jh = std::thread::spawn(move || {
          let body = move || -> Result<(), ER> {
            let runtime = Arc::new(local_runtime_cb()?);
            runtime.block_on(server.serve(&thread_addr, runtime.clone()))
          };
          let rslt = std::panic::catch_unwind(core::panic::AssertUnwindSafe(body))
            .unwrap_or_else(|payload| Err(crate::Error::from(payload).into()));
          let _rslt = thread_done.send(rslt);
        });
      }
      drop(done_tx);
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

    /// Starts the server on the current thread's io_uring runtime, `runtime`.
    #[inline]
    pub async fn run_local<EN, M>(
      mut self,
      addr: &str,
      hr: HttpRouter<DA, EN, ER, M, ServerStream>,
      runtime: Arc<UringRuntime>,
    ) -> Result<(), ER>
    where
      EN: EndpointNode<DA, ER, ServerStream> + 'static,
      M: Middleware<DA, ER> + 'static,
    {
      let server = ThreadServer {
        active: counter(self.shutdown.as_ref(), self.max_connections),
        drive_params: self.drive_params(),
        data: self.data,
        error_cb: self.error_cb,
        hrc: self.hrc,
        http_router: Arc::new(hr),
        max_connections: self.max_connections,
        rng: RNG::from_crypto_rng(&mut self.rng)?,
        shutdown: self.shutdown,
        tcp_params: self.tcp_params,
        tls_config: self.tls_config,
      };
      server.serve(addr, runtime).await
    }

    fn drive_params(&self) -> DriveParams {
      DriveParams { handshake: self.handshake_timeout, idle: self.idle_timeout }
    }
  }

  /// What one runtime thread serves.
  struct ThreadServer<DA, EC, EN, ER, M, RNG, TCX> {
    /// Open connections across the server's runtimes, when a limit or a shutdown needs them.
    active: Option<Arc<AtomicUsize>>,
    data: DA,
    drive_params: DriveParams,
    error_cb: EC,
    hrc: HttpRecvParams,
    http_router: Arc<HttpRouter<DA, EN, ER, M, ServerStream>>,
    max_connections: Option<NonZeroUsize>,
    rng: RNG,
    shutdown: Option<(ShutdownSignal, Duration)>,
    tcp_params: TcpParams,
    tls_config: Arc<TlsConfig<TCX>>,
  }

  impl<DA, EC, EN, ER, M, RNG, TCX> ThreadServer<DA, EC, EN, ER, M, RNG, TCX>
  where
    DA: Clone + 'static,
    EC: Clone + Fn(ER) + 'static,
    EN: EndpointNode<DA, ER, ServerStream> + 'static,
    ER: From<crate::Error> + 'static,
    M: Middleware<DA, ER> + 'static,
    RNG: CryptoRng + CryptoSeedableRng + 'static,
    TCX: TlsCtxSk + 'static,
  {
    async fn serve(mut self, addr: &str, runtime: Arc<UringRuntime>) -> Result<(), ER> {
      let uri = Uri::new(addr);
      let executor = UringExecutor::default();
      let listener = <UringExecutor as crate::executor::Executor>::TcpListener::bind(
        uri.hostname_with_implied_port(),
        self.tcp_params,
      )
      .await?;
      let mut xorshift = Xorshift64::from_simple_seed()?;
      reset_going_away();
      loop {
        let accept = listener.accept(self.tcp_params);
        let Some(rslt) = accept_or_shutdown(accept, self.shutdown.as_ref().map(|el| &el.0)).await
        else {
          break;
        };
        let (stream, peer) = match rslt {
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
        let conn = ConnTask {
          dispatcher: FwDispatcher {
            data: self.data.clone(),
            error_cb: self.error_cb.clone(),
            peer: peer_ip(peer),
            router: self.http_router.clone(),
            runtime: runtime.clone(),
          },
          drive_params: self.drive_params,
          hrc: self.hrc,
          rng: RNG::from_crypto_rng(&mut self.rng)?,
          tls_config: self.tls_config.clone(),
          xorshift: Xorshift64::from_rng(&mut xorshift)?,
        };
        if let Some(active) = &self.active {
          let _jh = executor.spawn_local(tracked(conn.run(stream), active.clone()), &runtime);
        } else {
          let _jh = executor.spawn_local(conn.run(stream), &runtime);
        }
      }
      drop(listener);
      go_away_local_conns();
      if let (Some((_, drain)), Some(active)) = (&self.shutdown, &self.active) {
        drain_connections(active, *drain).await;
      }
      Ok(())
    }
  }

  /// The accepted address, or the unspecified one where the runtime does not report it (direct
  /// descriptors).
  fn peer_ip(addr: SocketAddr) -> IpAddr {
    let ip = addr.ip();
    if ip.is_unspecified() { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { ip }
  }

  struct ConnTask<DA, EC, EN, ER, M, RNG, TCX> {
    dispatcher: FwDispatcher<DA, EC, EN, ER, M>,
    drive_params: DriveParams,
    hrc: HttpRecvParams,
    rng: RNG,
    tls_config: Arc<TlsConfig<TCX>>,
    xorshift: Xorshift64,
  }

  impl<DA, EC, EN, ER, M, RNG, TCX> ConnTask<DA, EC, EN, ER, M, RNG, TCX>
  where
    DA: Clone + 'static,
    EC: Clone + Fn(ER) + 'static,
    EN: EndpointNode<DA, ER, ServerStream> + 'static,
    ER: From<crate::Error> + 'static,
    M: Middleware<DA, ER> + 'static,
    RNG: CryptoRng,
    TCX: TlsCtxSk,
  {
    async fn run(mut self, stream: crate::executor::UringTcpStream) {
      let error_cb = self.dispatcher.error_cb.clone();
      let rslt = async {
        let begin = crate::calendar::Instant::new();
        // The stream is never split, so the kernel TLS switch can run once the handshake ends.
        let accept = TlsAcceptor::new(&*self.tls_config, &mut self.rng, stream).accept();
        let accepted = within(accept, self.drive_params.handshake).await?;
        let mut tls_stream = accepted.tls_stream;
        let conn = Http2Conn::<false>::new(self.hrc, &mut self.xorshift);
        let peer = self.dispatcher.peer;
        // What is left of the handshake deadline covers the preface and the first SETTINGS.
        let mut params = self.drive_params;
        let spent = |el: Duration| el.saturating_sub(begin.elapsed().unwrap_or(el));
        params.handshake = params.handshake.map(spent);
        drive_conn(&mut tls_stream, conn, &self.dispatcher, peer, params).await
      }
      .await;
      if let Err(err) = rslt {
        error_cb(err.into());
      }
    }
  }

  /// Routes the requests of one connection through the framework's router.
  struct FwDispatcher<DA, EC, EN, ER, M> {
    data: DA,
    error_cb: EC,
    peer: IpAddr,
    router: Arc<HttpRouter<DA, EN, ER, M, ServerStream>>,
    runtime: Arc<UringRuntime>,
  }

  impl<DA, EC, EN, ER, M> StreamDispatcher for FwDispatcher<DA, EC, EN, ER, M>
  where
    DA: Clone + 'static,
    EC: Clone + Fn(ER) + 'static,
    EN: EndpointNode<DA, ER, ServerStream> + 'static,
    ER: From<crate::Error> + 'static,
    M: Middleware<DA, ER> + 'static,
  {
    type AutoFut = impl Future<Output = AutoOutput>;
    type Matches = ArrayVectorCopy<RouteMatch, 4>;

    fn auto(
      &self,
      req: Request<MsgBufferString>,
      protocol: Option<Protocol>,
      matches: Option<Self::Matches>,
    ) -> Self::AutoFut {
      let (data, error_cb, peer, router) =
        (self.data.clone(), self.error_cb.clone(), self.peer, self.router.clone());
      async move {
        let Some(matches) = matches else {
          return (req, None, Ok(StatusCode::NotFound));
        };
        let mut auto_stream = AutoStream::new(data, peer, protocol, req);
        let rslt = router.auto(&mut auto_stream, (0, &matches)).await;
        let status = match rslt {
          Ok(elem) => Ok(elem),
          Err(err) => {
            error_cb(err);
            Err(crate::Error::ClosedHttpConnection)
          }
        };
        (auto_stream.req, auto_stream.shared_body, status)
      }
    }

    fn manual(&self, stream: ServerStream, req: Request<MsgBufferString>, matches: Self::Matches) {
      let (data, error_cb, peer, router) =
        (self.data.clone(), self.error_cb.clone(), self.peer, self.router.clone());
      let fut = async move {
        let protocol = stream.protocol();
        let manual_stream = ManualStream::new(data, peer, protocol, req, stream);
        if let Err(err) = router.manual(manual_stream, (0, &matches)).await {
          error_cb(err);
        }
      };
      let _jh = UringExecutor::default().spawn_local(fut, &self.runtime);
    }

    fn route(&self, path: &str) -> Route<Self::Matches> {
      match self.router.router.find(path) {
        Ok(found) => {
          let (matches, om) = *found.data();
          if om == OperationMode::Manual { Route::Manual(matches) } else { Route::Auto(matches) }
        }
        Err(_) => Route::NotFound,
      }
    }
  }
}
