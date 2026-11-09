//! The task of a worker (spec section 5.2): its socket, its QUIC endpoint and the HTTP/3
//! connection layer of its connections, driven in turns on the io_uring runtime of its thread.
//!
//! # Start
//!
//! The thread of worker `i` is pinned to the `i`-th CPU of the process, physical cores first, if
//! the server pins its workers. The workers bind their sockets one after the other, in their order,
//! so that the socket of worker `i` is the `i`-th of the `SO_REUSEPORT` group, which the steering
//! program indexes (spec section 5.11). The last one attaches the program for the group; if that
//! fails, the error callback is told once and every worker runs with the hash of the kernel:
//! `cid_steering` and `balance` off, one connection ID per connection and no rotation (ruling
//! T14-f, the degraded mode of ruling T11-a). Each worker then makes its endpoint, whose
//! generator is derived from the one of the worker, itself derived from the one of the process on
//! the thread that started the server (ruling T14-c), with the keys and the loads of the process.
//! A worker that can not start (its bind fails, say) ends the server with its error; the workers
//! that waited for it stop and report nothing of their own (review X1).
//!
//! # Turn
//!
//! The clock is read once. Every datagram received is handed to the endpoint, and those that it
//! returns for another worker are pushed into the inbox of that worker
//! ([`Endpoint::forward_dropped`] if the inbox does not take them, ruling T14-e); then the
//! datagrams of the inbox of this worker; then the parked requests whose futures were woken are
//! resumed through their connections ([`Endpoint::with_conn`], ruling T14-d); then the timers
//! that are due run, and every connection that has something to send is flushed once into the
//! arena of the socket, whose trains are queued for the one submission that ends the turn of the
//! runtime. One timer of the ring waits for the next deadline: of the endpoint, of the idle trim,
//! of the end of a shutdown.
//!
//! # Idle
//!
//! A worker that has had no connection for [`IDLE_TRIM_AFTER`] trims its pools down to a few
//! entries: those of the endpoint, of the TLS handshakes of the thread, of the HTTP/3 connection
//! state and of the router handler (ruling T14-e). Its counters are stored for
//! [`crate::http::http3_server_framework::Http3Stats`] at each turn.

#[cfg(test)]
use crate::http::http3_server_framework::tests::PoolSizes;
use crate::{
  collections::VectorUsize,
  executor::{UdpInbox, UdpParams, UringSleep, UringUdpSocket},
  http::{
    ShutdownSignal,
    http2_server_framework::{EndpointNode, HttpRouter, Middleware},
    http3_server_framework::{
      Http3ManualStream, Http3WorkerStats, StatsCell,
      router_handler::{FwRouter, RouterHandler},
    },
  },
  http3::{H3App, H3ErrorCode, H3Params},
  quic::{
    DatagramMeta, Endpoint, EndpointKeys, FlushOutcome, QuicApp, QuicLimits, QuicParams,
    RecvOutcome, WorkerLoads, steering_cbpf,
  },
  rng::{CryptoRng, CryptoSeedableRng},
  sync::{Arc, AtomicBool, AtomicUsize, CachePadded, SyncMutex},
  tls::{TlsConfig, TlsCtxSk},
};
use alloc::vec::Vec;
use core::{
  future::poll_fn,
  hint::cold_path,
  net::SocketAddr,
  pin::Pin,
  sync::atomic::Ordering,
  task::{Context, Poll},
  time::Duration,
};
use std::time::Instant;

/// A worker trims its pools once it has had no connection for this long.
pub(crate) const IDLE_TRIM_AFTER: Duration = Duration::from_secs(1);
// Past the end of the drain of a shutdown, the time that the connections closed then have to end
// their closing period before the worker stops anyway
const SHUTDOWN_LINGER: Duration = Duration::from_secs(5);

/// What a worker is given.
pub(crate) struct WorkerParams<DA, EC, EN, ER, M, RNG, TCX> {
  pub(crate) addr: SocketAddr,
  pub(crate) content_length: bool,
  pub(crate) cpu: Option<usize>,
  pub(crate) data: DA,
  pub(crate) date: bool,
  /// The clock of the process, which every worker reads its time from.
  pub(crate) epoch: Instant,
  pub(crate) error_cb: EC,
  pub(crate) h3_params: H3Params,
  pub(crate) keys: Arc<EndpointKeys>,
  pub(crate) loads: Arc<WorkerLoads>,
  pub(crate) quic_params: QuicParams,
  /// The generator of the worker, derived from the one of the process.
  pub(crate) rng: RNG,
  pub(crate) router: Arc<HttpRouter<DA, EN, ER, M, Http3ManualStream>>,
  pub(crate) shutdown: Option<(ShutdownSignal, Duration)>,
  pub(crate) startup: Arc<Startup>,
  pub(crate) stats: Arc<[CachePadded<StatsCell>]>,
  #[cfg(test)]
  pub(crate) test: crate::http::http3_server_framework::tests::TestHooks,
  pub(crate) tls: Arc<TlsConfig<TCX>>,
  pub(crate) udp_params: UdpParams,
  pub(crate) worker: u8,
  pub(crate) workers: u8,
}

/// What the workers of a server share while they start: whose turn it is to bind, the port of the
/// first socket, the inboxes, and if steering is on.
#[derive(Debug)]
pub(crate) struct Startup {
  failed: AtomicBool,
  inboxes: SyncMutex<Vec<Option<UdpInbox>>>,
  port: AtomicUsize,
  steering: AtomicBool,
  // The workers that bound
  turn: AtomicUsize,
}

impl Startup {
  pub(crate) fn new(workers: u8) -> Self {
    Self {
      failed: AtomicBool::new(false),
      inboxes: SyncMutex::new((0..workers).map(|_| None).collect()),
      port: AtomicUsize::new(0),
      steering: AtomicBool::new(false),
      turn: AtomicUsize::new(0),
    }
  }

  /// A worker ended with an error or a panic: the others stop waiting for it.
  pub(crate) fn fail(&self) {
    self.failed.store(true, Ordering::Release);
  }

  // Waits until `turn` workers bound. `Aborted` if a worker failed to start, which reports why.
  fn wait_turn(&self, turn: usize) -> Result<(), Start> {
    while self.turn.load(Ordering::Acquire) < turn {
      if self.failed.load(Ordering::Acquire) {
        return Err(Start::Aborted);
      }
      std::thread::sleep(Duration::from_micros(100));
    }
    Ok(())
  }
}

/// How a worker ended without serving.
#[derive(Debug)]
pub(crate) enum WorkerEnd<ER> {
  /// It stopped waiting for a worker that failed to start, and that reports why.
  Aborted,
  /// It failed.
  Failed(ER),
}

impl<ER> WorkerEnd<ER>
where
  ER: From<crate::Error>,
{
  /// The error, for a caller that has no other worker to report it.
  pub(crate) fn into_error(self) -> ER {
    match self {
      Self::Aborted => crate::Error::ClosedHttpConnection.into(),
      Self::Failed(err) => err,
    }
  }
}

impl<ER> From<crate::Error> for WorkerEnd<ER>
where
  ER: From<crate::Error>,
{
  #[inline]
  fn from(from: crate::Error) -> Self {
    Self::Failed(from.into())
  }
}

// How the start of a worker failed.
enum Start {
  // Another worker failed
  Aborted,
  // The bind failed
  Failed(crate::Error),
}

/// The address `addr` names, the first one if several.
pub(crate) fn resolve(addr: &str) -> crate::Result<SocketAddr> {
  std::net::ToSocketAddrs::to_socket_addrs(addr)?
    .next()
    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::AddrNotAvailable).into())
}

/// The CPUs of the process, the first thread of each physical core first, then the others. Fails
/// if the kernel does not tell the CPUs of the process.
pub(crate) fn cpu_order() -> crate::Result<Vec<usize>> {
  let allowed = affinity::allowed()?;
  let first_of_core = |cpu: &usize| {
    let path = alloc::format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
    std::fs::read_to_string(path).map_or(true, |list| {
      let first = list.trim().split([',', '-']).next().and_then(|el| el.parse::<usize>().ok());
      first.is_none_or(|el| el == *cpu)
    })
  };
  let (mut rslt, others): (Vec<usize>, Vec<usize>) = allowed.into_iter().partition(first_of_core);
  rslt.extend(others);
  Ok(rslt)
}

/// Pins the thread of the worker to its CPU, if it has one. A failure is reported to the error
/// callback, and the worker runs unpinned.
pub(crate) fn pin<DA, EC, EN, ER, M, RNG, TCX>(params: &WorkerParams<DA, EC, EN, ER, M, RNG, TCX>)
where
  EC: Fn(ER),
  ER: From<crate::Error>,
{
  if let Some(cpu) = params.cpu
    && let Err(err) = affinity::pin(cpu)
  {
    (params.error_cb)(err.into());
  }
}

/// Runs the worker of `params` until its server shuts down.
pub(crate) async fn run<DA, EC, EN, ER, M, RNG, TCX>(
  params: WorkerParams<DA, EC, EN, ER, M, RNG, TCX>,
) -> Result<(), WorkerEnd<ER>>
where
  DA: Clone + 'static,
  EC: Clone + Fn(ER) + 'static,
  EN: EndpointNode<DA, ER, Http3ManualStream> + 'static,
  ER: From<crate::Error> + 'static,
  M: Middleware<DA, ER> + 'static,
  RNG: CryptoRng + CryptoSeedableRng,
  TCX: TlsCtxSk,
{
  let WorkerParams {
    addr,
    content_length,
    cpu: _,
    data,
    date,
    epoch,
    error_cb,
    h3_params,
    keys,
    loads,
    quic_params,
    mut rng,
    router,
    shutdown,
    startup,
    stats,
    #[cfg(test)]
    test,
    tls,
    udp_params,
    worker,
    workers,
  } = params;
  #[cfg(test)]
  let steering_program = test.steering.unwrap_or(steering_cbpf);
  #[cfg(not(test))]
  let steering_program = steering_cbpf;
  // The last worker steers the group, whose sockets all bound: a single worker has none to steer
  let socket = bind_in_order(&startup, (addr, &udp_params), (worker, workers), &|socket| {
    if !quic_params.cid_steering() || workers <= 1 {
      return quic_params.cid_steering();
    }
    match socket.attach_reuseport_cbpf(&steering_program(workers)) {
      Ok(()) => true,
      Err(err) => {
        cold_path();
        error_cb(err.into());
        false
      }
    }
  })
  .map_err(|el| match el {
    Start::Aborted => WorkerEnd::Aborted,
    Start::Failed(err) => WorkerEnd::Failed(err.into()),
  })?;
  #[cfg(test)]
  if let Some(elem) = &test.bound {
    let _rslt = elem.send(socket.local_addr());
  }
  let steering = startup.steering.load(Ordering::Acquire);
  // Every worker bound: every inbox is there
  let inboxes: Option<Vec<UdpInbox>> = startup.inboxes.lock().iter().cloned().collect();
  let inboxes = inboxes.ok_or(crate::Error::ProgrammingError)?;
  let mut quic = if steering { quic_params } else { quic_params.set_cid_steering(false) };
  if !steering {
    quic = quic.set_balance(false);
  }
  if let Some((_, drain)) = &shutdown {
    let grace_ms = u64::try_from(drain.as_millis()).unwrap_or(u64::MAX);
    quic = quic.set_limits(QuicLimits { shutdown_grace_ms: grace_ms, ..*quic.limits() });
  }
  let endpoint = Endpoint::<App<DA, EC, EN, ER, M>, RNG, TCX>::new(
    quic,
    worker,
    workers,
    tls,
    &mut rng,
    Some(loads),
    keys,
  )?;
  let handler =
    RouterHandler::new(data, (content_length, date), FwRouter::new(router), error_cb.clone())?;
  let app = H3App::new(handler, h3_params);
  #[cfg(test)]
  let idle_trim_after = test.idle_trim_after.unwrap_or(IDLE_TRIM_AFTER);
  #[cfg(not(test))]
  let idle_trim_after = IDLE_TRIM_AFTER;
  let mut task = Task {
    app,
    endpoint,
    epoch,
    error_cb,
    forward_dropped: 0,
    idle_since_us: None,
    idle_trim_us: u64::try_from(idle_trim_after.as_micros()).unwrap_or(u64::MAX),
    idle_trims: 0,
    inboxes,
    shutdown,
    shutdown_since_us: None,
    signal_registered: false,
    sleep: None,
    socket,
    stats,
    steering,
    #[cfg(test)]
    trims: test.trims,
    trimmed: false,
    woken: VectorUsize::new(),
    worker,
  };
  let rslt = poll_fn(|cx| task.turn(cx)).await.map_err(WorkerEnd::Failed);
  let Task { app, endpoint, .. } = &mut task;
  endpoint.abort_all(app);
  task.store_stats();
  rslt
}

// Binds the socket of worker `worker` of `workers` once the workers before it did, then gives the
// turn to the next one. `steer`, given the socket, says if steering is on: what the last worker
// decides is what every worker runs with. Returns once every worker bound.
fn bind_in_order(
  startup: &Startup,
  (addr, udp_params): (SocketAddr, &UdpParams),
  (worker, workers): (u8, u8),
  steer: &dyn Fn(&UringUdpSocket) -> bool,
) -> Result<UringUdpSocket, Start> {
  let worker = usize::from(worker);
  startup.wait_turn(worker)?;
  let mut addr = addr;
  // The workers after the first take the port that it was given, for an address of port 0
  if addr.port() == 0 && worker > 0 {
    addr.set_port(u16::try_from(startup.port.load(Ordering::Acquire)).unwrap_or(0));
  }
  let socket = match UringUdpSocket::bind(addr, udp_params) {
    Ok(elem) => elem,
    Err(err) => {
      startup.fail();
      return Err(Start::Failed(err));
    }
  };
  if worker == 0 {
    startup.port.store(usize::from(socket.local_addr().port()), Ordering::Release);
  }
  if let Some(elem) = startup.inboxes.lock().get_mut(worker) {
    *elem = Some(socket.inbox());
  }
  if worker.wrapping_add(1) == usize::from(workers) {
    startup.steering.store(steer(&socket), Ordering::Release);
  }
  let _ = startup.turn.fetch_add(1, Ordering::AcqRel);
  startup.wait_turn(usize::from(workers))?;
  Ok(socket)
}

/// Hands `datagram`, which the endpoint returned for `worker`, to the inbox of that worker. If the
/// inbox does not take it (full, its socket gone) or the worker is not there, the endpoint gives
/// back the place that the datagram took on it (ruling T14-e). Returns `false` then.
pub(crate) fn forward<A, RNG, TCX>(
  endpoint: &mut Endpoint<A, RNG, TCX>,
  inboxes: &[UdpInbox],
  datagram: &[u8],
  meta: DatagramMeta,
  worker: u8,
) -> bool
where
  A: QuicApp,
  RNG: CryptoRng + CryptoSeedableRng,
  TCX: TlsCtxSk,
{
  if inboxes.get(usize::from(worker)).is_some_and(|el| el.push(datagram, meta)) {
    return true;
  }
  cold_path();
  endpoint.forward_dropped(datagram, worker);
  false
}

type App<DA, EC, EN, ER, M> = H3App<RouterHandler<FwRouter<DA, EN, ER, M>, EC>>;

/// The state of the task of a worker.
struct Task<DA, EC, EN, ER, M, RNG, TCX>
where
  DA: Clone + 'static,
  EC: Fn(ER),
  EN: EndpointNode<DA, ER, Http3ManualStream> + 'static,
  ER: From<crate::Error> + 'static,
  M: Middleware<DA, ER> + 'static,
{
  app: App<DA, EC, EN, ER, M>,
  endpoint: Endpoint<App<DA, EC, EN, ER, M>, RNG, TCX>,
  epoch: Instant,
  error_cb: EC,
  forward_dropped: u64,
  // Since when the worker has had no connection
  idle_since_us: Option<u64>,
  idle_trim_us: u64,
  idle_trims: u64,
  inboxes: Vec<UdpInbox>,
  shutdown: Option<(ShutdownSignal, Duration)>,
  // Since when the endpoint shuts down
  shutdown_since_us: Option<u64>,
  signal_registered: bool,
  // The timer of the ring, and the time that it was armed for
  sleep: Option<(UringSleep, u64)>,
  socket: UringUdpSocket,
  stats: Arc<[CachePadded<StatsCell>]>,
  steering: bool,
  #[cfg(test)]
  trims: Option<crate::sync::Arc<std::sync::Mutex<Vec<(PoolSizes, PoolSizes)>>>>,
  // The pools were trimmed since the worker was last busy
  trimmed: bool,
  woken: VectorUsize<u32>,
  worker: u8,
}

impl<DA, EC, EN, ER, M, RNG, TCX> Task<DA, EC, EN, ER, M, RNG, TCX>
where
  DA: Clone + 'static,
  EC: Clone + Fn(ER) + 'static,
  EN: EndpointNode<DA, ER, Http3ManualStream> + 'static,
  ER: From<crate::Error> + 'static,
  M: Middleware<DA, ER> + 'static,
  RNG: CryptoRng + CryptoSeedableRng,
  TCX: TlsCtxSk,
{
  // The microseconds since the clock of the process started.
  fn now_us(&self) -> u64 {
    u64::try_from(self.epoch.elapsed().as_micros()).unwrap_or(u64::MAX)
  }

  // One turn: see the module documentation. Ready once the worker is done.
  fn turn(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ER>> {
    let now_us = self.now_us();
    if let Err(err) = self.app.handler.start_turn(cx) {
      cold_path();
      (self.error_cb)(err.into());
    }
    self.receive(cx, now_us);
    self.resume_woken(now_us);
    if self.endpoint.next_deadline().is_some_and(|el| el <= now_us) {
      self.endpoint.on_timeout(now_us, &mut self.app);
    }
    self.poll_shutdown(cx, now_us);
    let outcome = {
      let Self { app, endpoint, socket, .. } = self;
      endpoint.flush(now_us, &mut socket.tx(), app)
    };
    if let Err(err) = self.socket.submit() {
      cold_path();
      (self.error_cb)(err.into());
    }
    if outcome == FlushOutcome::ArenaFull {
      // The arena has room again once the sends of this turn complete
      cx.waker().wake_by_ref();
    }
    self.idle(now_us);
    self.store_stats();
    if let Some(since) = self.shutdown_since_us {
      let drain = self.shutdown.as_ref().map_or(Duration::ZERO, |el| el.1);
      let limit = u64::try_from(drain.saturating_add(SHUTDOWN_LINGER).as_micros()).unwrap_or(0);
      if self.endpoint.stats().conns == 0 || now_us.saturating_sub(since) >= limit {
        return Poll::Ready(Ok(()));
      }
    }
    self.arm(cx, now_us);
    Poll::Pending
  }

  // Arms the timer of the ring for the next deadline, unless it is armed for an earlier one,
  // which then fires early and arms it again.
  fn arm(&mut self, cx: &mut Context<'_>, now_us: u64) {
    let idle =
      self.idle_since_us.filter(|_| !self.trimmed).map(|el| el.saturating_add(self.idle_trim_us));
    let shutdown = self.shutdown_since_us.map(|since| {
      let drain = self.shutdown.as_ref().map_or(Duration::ZERO, |el| el.1);
      let limit = u64::try_from(drain.saturating_add(SHUTDOWN_LINGER).as_micros()).unwrap_or(0);
      since.saturating_add(limit)
    });
    let Some(deadline) =
      self.endpoint.next_deadline().into_iter().chain(idle).chain(shutdown).min()
    else {
      self.sleep = None;
      return;
    };
    if deadline <= now_us {
      cx.waker().wake_by_ref();
      return;
    }
    // A timer armed for later than now and not later than the deadline stays: it fires early, if
    // at all, and is armed again then. One that is due is replaced.
    if let Some((sleep, at)) = &mut self.sleep
      && *at > now_us
      && *at <= deadline
    {
      if Pin::new(sleep).poll(cx).is_ready() {
        self.sleep = None;
        cx.waker().wake_by_ref();
      }
      return;
    }
    let Some(mut sleep) = UringSleep::new(Duration::from_micros(deadline.wrapping_sub(now_us)))
    else {
      return;
    };
    if Pin::new(&mut sleep).poll(cx).is_ready() {
      self.sleep = None;
      cx.waker().wake_by_ref();
      return;
    }
    self.sleep = Some((sleep, deadline));
  }

  // The pools are trimmed once the worker has had no connection for a while.
  fn idle(&mut self, now_us: u64) {
    if self.endpoint.stats().conns != 0 {
      self.idle_since_us = None;
      self.trimmed = false;
      return;
    }
    let since = *self.idle_since_us.get_or_insert(now_us);
    if self.trimmed || now_us.saturating_sub(since) < self.idle_trim_us {
      return;
    }
    #[cfg(test)]
    let before = self.pool_sizes();
    self.endpoint.trim_idle();
    self.app.trim_idle();
    self.app.handler.trim_idle();
    crate::tls::trim_idle_pools();
    #[cfg(test)]
    if let Some(elem) = &self.trims {
      let after = self.pool_sizes();
      elem.lock().unwrap().push((before, after));
    }
    self.trimmed = true;
    self.idle_trims = self.idle_trims.wrapping_add(1);
  }

  // The sizes of the pools that an idle trim frees down.
  #[cfg(test)]
  fn pool_sizes(&self) -> PoolSizes {
    PoolSizes {
      quic_conns: self.endpoint.pools().conn_cold.len(),
      tls_states: crate::tls::pooled_states(),
      h3_conns: self.app.pooled(),
    }
  }

  // Begins the shutdown of the endpoint once its signal is triggered.
  fn poll_shutdown(&mut self, cx: &Context<'_>, now_us: u64) {
    let Some((signal, _)) = &self.shutdown else {
      return;
    };
    if self.shutdown_since_us.is_some() {
      return;
    }
    let triggered = if self.signal_registered {
      signal.is_triggered()
    } else {
      self.signal_registered = true;
      signal.poll_triggered(cx).is_ready()
    };
    if triggered {
      self.endpoint.begin_shutdown(now_us, &mut self.app);
      self.shutdown_since_us = Some(now_us);
    }
  }

  // The datagrams of the socket, then those of the inbox.
  fn receive(&mut self, cx: &mut Context<'_>, now_us: u64) {
    let Self { app, endpoint, error_cb, forward_dropped, inboxes, socket, .. } = self;
    let rslt = socket.poll_recv(cx, &mut |datagram, meta| {
      if let RecvOutcome::Forward { worker } = endpoint.recv(now_us, datagram, meta, app)
        && !forward(endpoint, inboxes, datagram, meta, worker)
      {
        *forward_dropped = forward_dropped.wrapping_add(1);
      }
    });
    if let Poll::Ready(Err(err)) = rslt {
      cold_path();
      error_cb(err.into());
    }
    let _count = socket.poll_inbox(cx, &mut |datagram, meta| {
      endpoint.recv_forwarded(now_us, datagram, meta, app);
    });
  }

  // Resumes the parked requests whose futures were woken, each through its connection; the future
  // of a connection that is gone is dropped.
  fn resume_woken(&mut self, now_us: u64) {
    self.woken.clear();
    if let Err(err) = self.app.handler.take_woken(&mut self.woken) {
      cold_path();
      (self.error_cb)(err.into());
    }
    let mut nth = 0usize;
    while let Some(idx) = self.woken.get(nth).copied() {
      nth = nth.wrapping_add(1);
      let Some((conn, stream)) = self.app.handler.prepare_resume(idx) else {
        continue;
      };
      let ran = self.endpoint.with_conn(now_us, conn, &mut self.app, |app, cx| {
        if app.resume(cx, stream).is_err() {
          cold_path();
          cx.close(H3ErrorCode::InternalError.code(), b"");
        }
      });
      if ran.is_none() {
        self.app.handler.release(idx);
      }
    }
  }

  // Stores the counters of the worker for the readers of the stats of the server.
  fn store_stats(&self) {
    let Some(cell) = self.stats.get(usize::from(self.worker)) else {
      return;
    };
    let endpoint = self.endpoint.stats();
    let handler = self.app.handler.counters();
    cell.0.store(&Http3WorkerStats {
      cid_steering: self.steering,
      conns: endpoint.conns.into(),
      datagrams_in: endpoint.datagrams_in,
      datagrams_out: endpoint.datagrams_out,
      forwarded: endpoint.forwarded,
      forward_dropped: self.forward_dropped,
      handler_panics: handler.panics,
      idle_trims: self.idle_trims,
      parked: u64::try_from(self.app.handler.parked()).unwrap_or(u64::MAX),
      park_refused: handler.park_refused,
      requests: handler.requests,
      retries: endpoint.retries,
      stateless_resets: endpoint.resets,
      udp_send_errors: self.socket.stats().send_errors,
    });
  }
}

/// The CPU affinity of threads (Linux).
pub(crate) mod affinity {
  use alloc::vec::Vec;

  /// The CPUs that the process may run on, in increasing order.
  pub(crate) fn allowed() -> crate::Result<Vec<usize>> {
    // SAFETY: a `cpu_set_t` is a plain bitmask, valid when all zeroes
    let mut set: libc::cpu_set_t = unsafe { core::mem::zeroed() };
    // SAFETY: `set` outlives the call, which writes at most the size that is passed
    let rslt = unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &raw mut set) };
    if rslt != 0 {
      core::hint::cold_path();
      return Err(std::io::Error::last_os_error().into());
    }
    let max = usize::try_from(libc::CPU_SETSIZE).unwrap_or(0);
    // SAFETY: `CPU_ISSET` reads the bit of a CPU below `CPU_SETSIZE` of `set`, which is valid
    Ok((0..max).filter(|el| unsafe { libc::CPU_ISSET(*el, &set) }).collect())
  }

  /// Pins the calling thread to `cpu`.
  pub(crate) fn pin(cpu: usize) -> crate::Result<()> {
    // SAFETY: a `cpu_set_t` is a plain bitmask, valid when all zeroes
    let mut set: libc::cpu_set_t = unsafe { core::mem::zeroed() };
    if cpu >= usize::try_from(libc::CPU_SETSIZE).unwrap_or(0) {
      return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput).into());
    }
    // SAFETY: `CPU_SET` writes the bit of a CPU below `CPU_SETSIZE` of `set`, which is valid
    unsafe { libc::CPU_SET(cpu, &mut set) };
    // SAFETY: `set` outlives the call, which reads the size that is passed
    let rslt = unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &raw const set) };
    if rslt != 0 {
      return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
  }
}
