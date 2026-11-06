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
#[cfg(test)]
mod tests;
#[cfg(all(test, feature = "io-uring", feature = "web-socket"))]
mod uring_tests;
mod verbatim_params;

use crate::{
  executor::{Executor, Runtime as _},
  http::{HttpRecvParams, push_h2_alpn},
  net::TcpParams,
  sync::Arc,
  tls::TlsConfig,
};
use core::num::NonZeroUsize;
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
pub use verbatim_params::VerbatimParams;

/// HTTP/2 Server Framework
#[derive(Debug)]
pub struct Http2ServerFramework<DA, EC, EX, RC, RNG, TCX> {
  data: DA,
  error_cb: EC,
  executor: EX,
  hrc: HttpRecvParams,
  local_runtime_cb: RC,
  local_runtimes: Option<NonZeroUsize>,
  rng: RNG,
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
  /// The "h2" ALPN will always be pushed into the TLS configuration.
  #[inline]
  pub fn new(executor: EX, rng: RNG, mut tls_config: TlsConfig<TCX>) -> crate::Result<Self> {
    push_h2_alpn(&mut tls_config)?;
    let error_cb: fn(_) = |_| {};
    let local_runtime_cb: fn() -> _ = || Ok(EX::LocalRuntime::new()?);
    Ok(Self {
      data: (),
      error_cb,
      executor,
      hrc: HttpRecvParams::with_optioned_params(),
      local_runtime_cb,
      local_runtimes: None,
      rng,
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
      hrc: self.hrc,
      local_runtime_cb: self.local_runtime_cb,
      local_runtimes: self.local_runtimes,
      rng: self.rng,
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
      hrc: self.hrc,
      local_runtime_cb: self.local_runtime_cb,
      local_runtimes: self.local_runtimes,
      rng: self.rng,
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
      hrc: self.hrc,
      local_runtime_cb: value,
      local_runtimes: self.local_runtimes,
      rng: self.rng,
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
      http2_server_framework::{
        Endpoint as _, EndpointNode, Http2ServerFramework, HttpRouter, Middleware, RouteMatch,
        conn_driver::{Route, StreamDispatcher, drive_conn},
      },
      misc::on_accept_error,
    },
    collections::ArrayVectorCopy,
    http2::{ServerStream, conn::Http2Conn},
    net::{TcpListener as _, TcpParams, Uri},
    rng::{CryptoRng, CryptoSeedableRng, SeedableRng as _, Xorshift64},
    sync::Arc,
    tls::{TlsAcceptor, TlsConfig, TlsCtxSk},
  };
  use alloc::string::String;
  use core::net::{IpAddr, Ipv4Addr, SocketAddr};

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
      for _ in 0..runtimes {
        let server = ThreadServer {
          data: self.data.clone(),
          error_cb: self.error_cb.clone(),
          hrc: self.hrc,
          http_router: http_router.clone(),
          rng: RNG::from_crypto_rng(&mut self.rng)?,
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
        data: self.data,
        error_cb: self.error_cb,
        hrc: self.hrc,
        http_router: Arc::new(hr),
        rng: RNG::from_crypto_rng(&mut self.rng)?,
        tcp_params: self.tcp_params,
        tls_config: self.tls_config,
      };
      server.serve(addr, runtime).await
    }
  }

  /// What one runtime thread serves.
  struct ThreadServer<DA, EC, EN, ER, M, RNG, TCX> {
    data: DA,
    error_cb: EC,
    hrc: HttpRecvParams,
    http_router: Arc<HttpRouter<DA, EN, ER, M, ServerStream>>,
    rng: RNG,
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
      loop {
        let (stream, peer) = match listener.accept(self.tcp_params).await {
          Ok(elem) => elem,
          Err(err) => {
            on_accept_error(&self.error_cb, err).await;
            continue;
          }
        };
        let conn = ConnTask {
          dispatcher: FwDispatcher {
            data: self.data.clone(),
            error_cb: self.error_cb.clone(),
            peer: peer_ip(peer),
            router: self.http_router.clone(),
            runtime: runtime.clone(),
          },
          hrc: self.hrc,
          rng: RNG::from_crypto_rng(&mut self.rng)?,
          tls_config: self.tls_config.clone(),
          xorshift: Xorshift64::from_rng(&mut xorshift)?,
        };
        let _jh = executor.spawn_local(conn.run(stream), &runtime);
      }
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
        // The stream is never split, so the kernel TLS switch can run once the handshake ends.
        let accepted = TlsAcceptor::new(&*self.tls_config, &mut self.rng, stream).accept().await?;
        let mut tls_stream = accepted.tls_stream;
        let conn = Http2Conn::<false>::new(self.hrc, &mut self.xorshift);
        let peer = self.dispatcher.peer;
        drive_conn(&mut tls_stream, conn, &self.dispatcher, peer).await
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
    type AutoFut = impl Future<Output = (Request<MsgBufferString>, crate::Result<StatusCode>)>;
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
          return (req, Ok(StatusCode::NotFound));
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
        (auto_stream.req, status)
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
