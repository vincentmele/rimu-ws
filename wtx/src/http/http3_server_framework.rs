//! HTTP/3 server framework (spec section 5.10): the router, routes, middlewares and
//! [`StaticFiles`](crate::http::StaticFiles) of the HTTP/2 framework served over QUIC.
//!
//! One worker per runtime thread, each with one UDP socket of a `SO_REUSEPORT` group, its QUIC
//! endpoint and the HTTP/3 connection layer of its connections: the endpoint task of the worker
//! (`endpoint_task`) receives the datagrams of a turn, hands each to the endpoint, flushes every
//! connection that has something to send once, and sends what they wrote with one submission.
//! Handlers run inline: the future of a request is polled once as soon as the request is complete
//! and its response leaves in the same turn; a future that waits is parked in a pooled slot and
//! polled again when it is woken (`router_handler`). No task per stream or connection.

mod endpoint_task;
mod router_handler;
#[cfg(test)]
mod tests;

use crate::{
  executor::{Executor, Runtime as _, UdpParams},
  http::{HttpRecvParams, ShutdownSignal},
  http3::H3Params,
  quic::QuicParams,
  sync::{Arc, AtomicBool, AtomicU64, CachePadded},
  tls::TlsConfig,
};
use alloc::vec::Vec;
use core::{num::NonZeroUsize, sync::atomic::Ordering, time::Duration};

/// The stream of the manual-mode endpoints of the routers of [`Http3ServerFramework`]. HTTP/3 has
/// no manual mode: a request routed to a manual-mode endpoint is answered with 500 and the error
/// callback receives `OperationModeMismatch` ([`Http2ServerFrameworkError`]).
///
/// [`Http2ServerFrameworkError`]: crate::http::http2_server_framework::Http2ServerFrameworkError
#[derive(Debug)]
pub struct Http3ManualStream {
  _private: (),
}

/// What the workers of an [`Http3ServerFramework`] counted, each for itself, as they go: see
/// [`Http3ServerFramework::stats`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Http3WorkerStats {
  /// Packets sent that were not ack-eliciting, other than CONNECTION_CLOSE: those that carry
  /// acknowledgments and padding only.
  pub ack_only_out: u64,
  /// If the datagrams of the worker are steered by connection ID (spec section 5.11), or reach it
  /// by the hash of the kernel (an attach of the steering program that failed, or a single
  /// worker that was not asked to steer).
  pub cid_steering: bool,
  /// Connections open, those whose handshake is under way included.
  pub conns: u64,
  /// Datagrams received, each segment of a coalesced one counted.
  pub datagrams_in: u64,
  /// Datagrams sent.
  pub datagrams_out: u64,
  /// Datagrams handed to another worker.
  pub forwarded: u64,
  /// Datagrams for another worker that its inbox could not take, dropped.
  pub forward_dropped: u64,
  /// Panics of handlers, each answered with 500 on its stream.
  pub handler_panics: u64,
  /// Times the pools of the worker were trimmed after it had no connection for a while.
  pub idle_trims: u64,
  /// Packets sent, each packet of a coalesced datagram counted.
  pub packets_out: u64,
  /// Requests parked now: their handlers wait.
  pub parked: u64,
  /// Requests whose handler would have waited past the parked requests a worker keeps, answered
  /// with 503.
  pub park_refused: u64,
  /// Requests given to handlers.
  pub requests: u64,
  /// Retry packets sent.
  pub retries: u64,
  /// Stateless resets sent.
  pub stateless_resets: u64,
  /// Sends of datagrams that failed (their packets count as lost).
  pub udp_send_errors: u64,
}

/// The counters of the workers of an [`Http3ServerFramework`], updated by each worker as it goes
/// and read from any thread. Clones share them.
#[derive(Clone, Debug)]
pub struct Http3Stats {
  workers: Arc<WorkersStats>,
}

impl Http3Stats {
  /// The counters of each worker, by worker index; empty before the server runs.
  #[inline]
  pub fn workers(&self) -> Vec<Http3WorkerStats> {
    let cells = self.workers.cells.lock();
    cells.iter().map(|el| el.load()).collect()
  }

  fn new() -> Self {
    let cells: Arc<[CachePadded<StatsCell>]> = Arc::from(Vec::new().into_boxed_slice());
    Self { workers: Arc::new(WorkersStats { cells: crate::sync::SyncMutex::new(cells) }) }
  }

  // The cells of `workers` workers, set when the server runs.
  fn start(&self, workers: usize) -> Arc<[CachePadded<StatsCell>]> {
    let cells: Arc<[CachePadded<StatsCell>]> = Arc::from(
      (0..workers)
        .map(|_| CachePadded(StatsCell::default()))
        .collect::<Vec<_>>()
        .into_boxed_slice(),
    );
    *self.workers.cells.lock() = cells.clone();
    cells
  }
}

#[derive(Debug)]
struct WorkersStats {
  cells: crate::sync::SyncMutex<Arc<[CachePadded<StatsCell>]>>,
}

/// The counters of a worker, which it stores each turn, without a lock.
#[derive(Debug)]
pub(crate) struct StatsCell {
  cid_steering: AtomicBool,
  values: [AtomicU64; 15],
}

impl Default for StatsCell {
  #[inline]
  fn default() -> Self {
    Self { cid_steering: AtomicBool::new(false), values: [const { AtomicU64::new(0) }; 15] }
  }
}

impl StatsCell {
  fn load(&self) -> Http3WorkerStats {
    let value = |idx: usize| self.values.get(idx).map_or(0, |el| el.load(Ordering::Relaxed));
    Http3WorkerStats {
      ack_only_out: value(13),
      cid_steering: self.cid_steering.load(Ordering::Relaxed),
      conns: value(0),
      datagrams_in: value(1),
      datagrams_out: value(2),
      forwarded: value(3),
      forward_dropped: value(4),
      handler_panics: value(5),
      idle_trims: value(6),
      packets_out: value(14),
      parked: value(7),
      park_refused: value(8),
      requests: value(9),
      retries: value(10),
      stateless_resets: value(11),
      udp_send_errors: value(12),
    }
  }

  pub(crate) fn store(&self, stats: &Http3WorkerStats) {
    self.cid_steering.store(stats.cid_steering, Ordering::Relaxed);
    let values = [
      stats.conns,
      stats.datagrams_in,
      stats.datagrams_out,
      stats.forwarded,
      stats.forward_dropped,
      stats.handler_panics,
      stats.idle_trims,
      stats.parked,
      stats.park_refused,
      stats.requests,
      stats.retries,
      stats.stateless_resets,
      stats.udp_send_errors,
      stats.ack_only_out,
      stats.packets_out,
    ];
    for (cell, value) in self.values.iter().zip(values) {
      cell.store(value, Ordering::Relaxed);
    }
  }
}

/// HTTP/3 Server Framework: see the [module documentation](self).
///
/// The responses carry `:status` and `content-type` only by default (plus `content-encoding` and
/// `vary` where static files need them), like the HttpArena HTTP/3 leaders (cnetmod, zix). That
/// is not RFC 9110-compliant: `date` (section 6.6.1) and `content-length` (section 8.6) are left
/// out, and [`Http3ServerFramework::set_rfc9110_headers`] turns both on.
#[derive(Debug)]
pub struct Http3ServerFramework<DA, EC, EX, RC, RNG, TCX> {
  content_length: bool,
  data: DA,
  date: bool,
  error_cb: EC,
  executor: EX,
  h3_params: H3Params,
  local_runtime_cb: RC,
  local_runtimes: Option<NonZeroUsize>,
  pin_workers: bool,
  quic_params: QuicParams,
  rng: RNG,
  shutdown: Option<(ShutdownSignal, Duration)>,
  stats: Http3Stats,
  #[cfg(test)]
  test: tests::TestHooks,
  tls_config: Arc<TlsConfig<TCX>>,
  udp_params: UdpParams,
}

impl<ERR, EX, RNG, TCX>
  Http3ServerFramework<
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
  /// Taking aside the provided parameters, everything else is set to default values. The QUIC
  /// handshake negotiates the `h3` ALPN whatever `tls_config` lists.
  #[inline]
  pub fn new(executor: EX, rng: RNG, tls_config: TlsConfig<TCX>) -> crate::Result<Self> {
    let error_cb: fn(_) = |_| {};
    let local_runtime_cb: fn() -> _ = || Ok(EX::LocalRuntime::new()?);
    Ok(Self {
      content_length: false,
      data: (),
      date: false,
      error_cb,
      executor,
      h3_params: H3Params::default(),
      local_runtime_cb,
      local_runtimes: None,
      pin_workers: true,
      quic_params: QuicParams::default(),
      rng,
      shutdown: None,
      stats: Http3Stats::new(),
      #[cfg(test)]
      test: tests::TestHooks::default(),
      tls_config: Arc::new(tls_config),
      udp_params: UdpParams::new(),
    })
  }
}

impl<DA, EC, EX, RC, RNG, TCX> Http3ServerFramework<DA, EC, EX, RC, RNG, TCX> {
  /// Mutable Random Number Generator: the generator of the process, which every worker derives
  /// its own from.
  #[inline]
  pub const fn rng_mut(&mut self) -> &mut RNG {
    &mut self.rng
  }

  /// Shared data that is cloned for each request.
  #[inline]
  pub fn set_data<_DA>(self, value: _DA) -> Http3ServerFramework<_DA, EC, EX, RC, RNG, TCX> {
    Http3ServerFramework {
      content_length: self.content_length,
      data: value,
      date: self.date,
      error_cb: self.error_cb,
      executor: self.executor,
      h3_params: self.h3_params,
      local_runtime_cb: self.local_runtime_cb,
      local_runtimes: self.local_runtimes,
      pin_workers: self.pin_workers,
      quic_params: self.quic_params,
      rng: self.rng,
      shutdown: self.shutdown,
      stats: self.stats,
      #[cfg(test)]
      test: self.test,
      tls_config: self.tls_config,
      udp_params: self.udp_params,
    }
  }

  /// If responses with content carry `content-length` (RFC 9110 section 8.6: a SHOULD when the size
  /// is known; HTTP/3 frames the content without it). A response to `HEAD` carries it either way.
  /// Defaults to `false`, which matches the lean style of the HttpArena HTTP/3 leaders (cnetmod,
  /// zix) and is not RFC 9110-compliant: see [`Self::set_rfc9110_headers`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_content_length(mut self, value: bool) -> Self {
    self.content_length = value;
    self
  }

  /// If responses carry a `date` header (RFC 9110 section 6.6.1: an origin server with a clock
  /// must send one), formatted once a second. Defaults to `false`, which matches the lean style
  /// of the HttpArena HTTP/3 leaders (cnetmod, zix) and is not RFC 9110-compliant: see
  /// [`Self::set_rfc9110_headers`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_date(mut self, value: bool) -> Self {
    self.date = value;
    self
  }

  /// Sets the error callback function.
  #[inline]
  pub fn set_error_cb<_EC>(self, value: _EC) -> Http3ServerFramework<DA, _EC, EX, RC, RNG, TCX> {
    Http3ServerFramework {
      content_length: self.content_length,
      data: self.data,
      date: self.date,
      error_cb: value,
      executor: self.executor,
      h3_params: self.h3_params,
      local_runtime_cb: self.local_runtime_cb,
      local_runtimes: self.local_runtimes,
      pin_workers: self.pin_workers,
      quic_params: self.quic_params,
      rng: self.rng,
      shutdown: self.shutdown,
      stats: self.stats,
      #[cfg(test)]
      test: self.test,
      tls_config: self.tls_config,
      udp_params: self.udp_params,
    }
  }

  /// See [`H3Params`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_h3_params(mut self, value: H3Params) -> Self {
    self.h3_params = value;
    self
  }

  /// The limits that HTTP/3 shares with HTTP/2, into the [`H3Params`] of the server: the largest
  /// body of a request ([`HttpRecvParams::max_body_len`] into [`H3Params::max_request_body`]), of
  /// the headers of a request ([`HttpRecvParams::max_headers_len`] into
  /// [`H3Params::max_field_section_size`]) and the bytes of request buffers of a connection
  /// ([`HttpRecvParams::max_conn_buffered_len`] into [`H3Params::max_buffered_body_per_conn`]).
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_http_recv_params(mut self, value: HttpRecvParams) -> Self {
    self.h3_params.max_request_body = value.max_body_len();
    self.h3_params.max_field_section_size = value.max_headers_len();
    self.h3_params.max_buffered_body_per_conn = value.max_conn_buffered_len();
    self
  }

  /// Allows the tweaking of the chosen runtime. Called on the thread of each worker.
  #[inline]
  pub fn set_local_runtime_cb<_RC>(
    self,
    value: _RC,
  ) -> Http3ServerFramework<DA, EC, EX, _RC, RNG, TCX> {
    Http3ServerFramework {
      content_length: self.content_length,
      data: self.data,
      date: self.date,
      error_cb: self.error_cb,
      executor: self.executor,
      h3_params: self.h3_params,
      local_runtime_cb: value,
      local_runtimes: self.local_runtimes,
      pin_workers: self.pin_workers,
      quic_params: self.quic_params,
      rng: self.rng,
      shutdown: self.shutdown,
      stats: self.stats,
      #[cfg(test)]
      test: self.test,
      tls_config: self.tls_config,
      udp_params: self.udp_params,
    }
  }

  /// The number of workers, each a runtime on a thread of its own, at most 255. If [`None`],
  /// defaults to the number of threads, at most 255.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_local_runtimes(mut self, value: Option<NonZeroUsize>) -> Self {
    self.local_runtimes = value;
    self
  }

  /// If the thread of each worker is pinned to a CPU of the process, physical cores first (spec
  /// section 5.2). Defaults to `true`.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_pin_workers(mut self, value: bool) -> Self {
    self.pin_workers = value;
    self
  }

  /// See [`QuicParams`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_quic_params(mut self, value: QuicParams) -> Self {
    self.quic_params = value;
    self
  }

  /// Turns on both response fields that RFC 9110 asks of an origin server and the default leaves
  /// out: `date` (section 6.6.1, a MUST for a server with a clock) and `content-length` (section
  /// 8.6, a SHOULD when the size is known). Shorthand for [`Self::set_date`] and
  /// [`Self::set_content_length`] with the same value. Defaults to `false`: responses carry
  /// `:status` and `content-type` only (plus `content-encoding` and `vary` where static files
  /// need them), like the HttpArena HTTP/3 leaders (cnetmod, zix); that is not RFC
  /// 9110-compliant, so call this with `true` where compliance matters. A response to `HEAD`
  /// carries `content-length` either way.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_rfc9110_headers(mut self, value: bool) -> Self {
    self.content_length = value;
    self.date = value;
    self
  }

  /// Stops the server when `signal` is triggered: new clients are dropped, every connection is
  /// sent GOAWAY and its requests under way have `drain` to finish (spec section 5.12), after
  /// which what is left is closed with `H3_NO_ERROR`, and the server returns `Ok` once every
  /// connection is closed.
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub fn set_shutdown(mut self, signal: ShutdownSignal, drain: Duration) -> Self {
    self.shutdown = Some((signal, drain));
    self
  }

  /// See [`UdpParams`].
  #[inline]
  #[must_use = must_use_itself_doc!()]
  pub const fn set_udp_params(mut self, value: UdpParams) -> Self {
    self.udp_params = value;
    self
  }

  /// The counters of the workers, which they update as they serve: a handle that stays valid
  /// once the server runs.
  #[inline]
  pub fn stats(&self) -> Http3Stats {
    self.stats.clone()
  }
}

mod uring {
  use crate::{
    executor::{Runtime as _, UringExecutor, UringRuntime},
    http::{
      http2_server_framework::{EndpointNode, HttpRouter, Middleware},
      http3_server_framework::{
        Http3ManualStream, Http3ServerFramework,
        endpoint_task::{self, Startup, WorkerEnd, WorkerParams, cpu_order},
      },
    },
    quic::{EndpointKeys, WorkerLoads},
    rng::{CryptoRng, CryptoSeedableRng},
    sync::Arc,
    tls::TlsCtxSk,
  };
  use alloc::vec::Vec;

  impl<DA, EC, ER, RC, RNG, TCX> Http3ServerFramework<DA, EC, UringExecutor, RC, RNG, TCX>
  where
    EC: Clone + Fn(ER) + 'static,
    DA: Clone + 'static,
    ER: From<crate::Error> + 'static,
    RC: Clone + Fn() -> Result<UringRuntime, ER> + 'static,
    RNG: CryptoRng + CryptoSeedableRng + 'static,
    TCX: TlsCtxSk + 'static,
  {
    /// Starts the server with one worker per thread, each an io_uring runtime with its own UDP
    /// socket (`SO_REUSEPORT`, bound to `addr` one after the other in the order of the workers).
    ///
    /// Call it from the main thread: the first worker that ends with an error ends the call.
    #[inline]
    pub fn run_in_threads<EN, M>(
      mut self,
      addr: &str,
      hr: HttpRouter<DA, EN, ER, M, Http3ManualStream>,
    ) -> Result<(), ER>
    where
      DA: Send,
      EC: Send,
      EN: EndpointNode<DA, ER, Http3ManualStream> + Send + Sync + 'static,
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
      let workers = u8::try_from(runtimes.min(255)).unwrap_or(u8::MAX);
      let addr = endpoint_task::resolve(addr)?;
      let http_router = Arc::new(hr);
      // Once per process (ruling T14-c): the keys of the stateless packets, and the generators of
      // the workers, each derived from the one of the process on this thread
      let keys = Arc::new(EndpointKeys::new(&mut self.rng));
      let loads = Arc::new(WorkerLoads::new(workers));
      let startup = Arc::new(Startup::new(workers));
      let stats = self.stats.start(workers.into());
      let cpus = if self.pin_workers {
        // Without the CPUs of the process the workers run unpinned, which the callback is told once
        cpu_order().unwrap_or_else(|err| {
          (self.error_cb)(err.into());
          Vec::new()
        })
      } else {
        Vec::new()
      };
      let epoch = std::time::Instant::now();
      let (done_tx, done_rx) = std::sync::mpsc::channel::<Result<(), WorkerEnd<ER>>>();
      for worker in 0..workers {
        let params = WorkerParams {
          addr,
          cpu: cpus.get(usize::from(worker) % cpus.len().max(1)).copied(),
          data: self.data.clone(),
          content_length: self.content_length,
          date: self.date,
          epoch,
          error_cb: self.error_cb.clone(),
          h3_params: self.h3_params,
          keys: keys.clone(),
          loads: loads.clone(),
          quic_params: self.quic_params,
          rng: RNG::from_crypto_rng(&mut self.rng)?,
          router: http_router.clone(),
          shutdown: self.shutdown.clone(),
          startup: startup.clone(),
          stats: stats.clone(),
          #[cfg(test)]
          test: self.test.clone(),
          tls: self.tls_config.clone(),
          udp_params: self.udp_params,
          worker,
          workers,
        };
        let local_runtime_cb = self.local_runtime_cb.clone();
        let thread_done = done_tx.clone();
        let thread_startup = startup.clone();
        let _jh = std::thread::spawn(move || {
          let body = move || -> Result<(), WorkerEnd<ER>> {
            endpoint_task::pin(&params);
            let runtime = local_runtime_cb().map_err(WorkerEnd::Failed)?;
            runtime.block_on(endpoint_task::run(params))
          };
          let rslt = std::panic::catch_unwind(core::panic::AssertUnwindSafe(body))
            .unwrap_or_else(|payload| Err(WorkerEnd::Failed(crate::Error::from(payload).into())));
          if let Err(WorkerEnd::Failed(_)) = &rslt {
            thread_startup.fail();
          }
          let _rslt = thread_done.send(rslt);
        });
      }
      drop(done_tx);
      // The first error of a worker ends the call; a worker that stopped waiting for another that
      // failed to start reports nothing of its own (review X1)
      let mut ended = 0usize;
      while let Ok(rslt) = done_rx.recv() {
        if let Err(WorkerEnd::Failed(err)) = rslt {
          return Err(err);
        }
        ended = ended.wrapping_add(1);
        if ended == usize::from(workers) {
          break;
        }
      }
      Ok(())
    }

    /// Starts one worker on the io_uring runtime of the current thread, which it does not pin.
    #[inline]
    pub async fn run_local<EN, M>(
      mut self,
      addr: &str,
      hr: HttpRouter<DA, EN, ER, M, Http3ManualStream>,
    ) -> Result<(), ER>
    where
      EN: EndpointNode<DA, ER, Http3ManualStream> + 'static,
      M: Middleware<DA, ER> + 'static,
    {
      let keys = Arc::new(EndpointKeys::new(&mut self.rng));
      let params = WorkerParams {
        addr: endpoint_task::resolve(addr)?,
        content_length: self.content_length,
        cpu: None,
        data: self.data,
        date: self.date,
        epoch: std::time::Instant::now(),
        error_cb: self.error_cb,
        h3_params: self.h3_params,
        keys,
        loads: Arc::new(crate::quic::WorkerLoads::new(1)),
        quic_params: self.quic_params,
        rng: RNG::from_crypto_rng(&mut self.rng)?,
        router: Arc::new(hr),
        shutdown: self.shutdown,
        startup: Arc::new(Startup::new(1)),
        stats: self.stats.start(1),
        #[cfg(test)]
        test: self.test,
        tls: self.tls_config,
        udp_params: self.udp_params,
        worker: 0,
        workers: 1,
      };
      endpoint_task::run(params).await.map_err(WorkerEnd::into_error)
    }
  }
}
