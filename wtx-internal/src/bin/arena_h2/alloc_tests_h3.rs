//! Allocation tests of the arena-h2 HTTP/3 server, end to end: the program's own server
//! ([`spawn_h3_with`]: its router, endpoints, `ConnAux`, switches and `StaticFiles`) on a counted
//! worker thread, and the loopback HTTP/3 client of the library
//! ([`rimu_ws::http3::loopback_client`]) on the test's threads, over UDP on loopback. They are
//! correctness tests, not benchmarks: the load is a few thousand requests.
//!
//! After a warm-up that reaches the measured steady state (the connections open, the streams in
//! flight), a keep-alive load of `/baseline2` or `/static` allocates nothing on the server's
//! thread, and opening, serving and closing a connection allocates only the crypto backend's
//! [`CRYPTO_PER_HANDSHAKE`] (ring's RSA signature).
//!
//! A counting global allocator counts the allocations of the threads that were told to (the
//! worker thread of each test server, from its local-runtime callback), each server in its own
//! counters, so the clients and the tests running alongside are not counted.
//!
//! `ALLOC_TRACE=n` prints the backtraces of the first `n` allocations of every measured window.
//! `ALLOC_WARMUP=n` replaces the warm-up of the steady-state tests (requests) and of the churn test
//! (connections): `0` shows that the tests can fail. `memory_report` (ignored) prints the pool
//! memory of a worker.
//!
//! The tests need the arena data (`DATASET_PATH`, `STATIC_DIR`) and the certificate pair
//! (`CERT_DIR`): without them they fail, instead of passing on nothing. Run them with
//! `--test-threads 1`.

#![allow(clippy::disallowed_methods, reason = "a test harness")]
#![allow(clippy::disallowed_types, reason = "a test harness")]

use super::{ConnAux, DatasetItem, H3Run, knobs::H3Knobs, spawn_h3_with};
use core::{
  alloc::{GlobalAlloc, Layout},
  cell::Cell,
  net::{IpAddr, Ipv4Addr, SocketAddr},
  num::NonZeroUsize,
  sync::atomic::Ordering,
  time::Duration,
};
use rimu_ws::{
  collections::VectorUsize,
  executor::UdpParams,
  http::{ShutdownSignal, http3_server_framework::Http3Stats},
  http3::loopback_client::{H3Get, H3LoopbackClient, H3Reply},
  sync::{Arc, AtomicBool, AtomicU64},
};
use std::{collections::BTreeMap, time::Instant};

/// Requests sent before counting, so that every buffer has reached its size.
const WARMUP: usize = 10_000;
/// Requests counted.
const MEASURED: usize = 10_000;
/// Connections of the steady-state tests, and the streams in flight on each: 16 × 64 requests under
/// way at once, more than the 64 that a benchmark connection keeps and fewer connections.
const CONNS: usize = 16;
const DEPTH: usize = 64;
/// Connections opened before counting in the churn test, and counted.
const CHURN_WARMUP: usize = 100;
const CHURN_CONNS: usize = 200;
/// The connections of the burst that warms the churn test up, open at once.
const BURST: usize = 64;
/// The allocations of the crypto backend that one RSA handshake signature takes (ring).
const CRYPTO_PER_HANDSHAKE: u64 = 9;
/// Where the certificate pair is, unless `CERT_DIR` says.
const CERT_DIR: &str = "/mnt/nvme1tb/claude-tmp/arena-main/certs";
/// The dataset, unless `DATASET_PATH` says.
const DATASET_FILE: &str = "/mnt/nvme1tb/claude-tmp/arena-main/data/dataset.json";
/// The static files, unless `STATIC_DIR` says.
const STATIC_ROOT: &str = "/mnt/nvme1tb/claude-tmp/arena-main/data/static";
/// The budget of spec section 5.4 for the pools of a worker: under load, and idle after the trim.
const POOL_BUDGET_LOAD: u64 = 16 << 20;
const POOL_BUDGET_IDLE: u64 = 2 << 20;
const TIMEOUT: Duration = Duration::from_secs(20);

// ---- the counting allocator

/// The allocations of one server's worker thread.
struct Counts {
  allocs: AtomicU64,
  bytes: AtomicU64,
  /// While set, every allocation is charged to its [`Owner`] in `sites`.
  classify: AtomicBool,
  /// The allocations charged: owner, the frame charged and size.
  sites: std::sync::Mutex<Vec<(Owner, String, u64)>>,
  /// Backtraces left to print, while a window is measured.
  trace: AtomicU64,
  tracing: AtomicBool,
}

impl Counts {
  fn leak() -> &'static Self {
    Box::leak(Box::new(Self {
      allocs: AtomicU64::new(0),
      bytes: AtomicU64::new(0),
      classify: AtomicBool::new(false),
      sites: std::sync::Mutex::new(Vec::new()),
      trace: AtomicU64::new(0),
      tracing: AtomicBool::new(false),
    }))
  }

  fn snapshot(&self) -> (u64, u64) {
    (self.allocs.load(Ordering::SeqCst), self.bytes.load(Ordering::SeqCst))
  }
}

std::thread_local! {
  static COUNTS: Cell<Option<&'static Counts>> = const { Cell::new(None) };
  /// In the middle of printing a backtrace, whose allocations are not counted.
  static IN_TRACE: Cell<bool> = const { Cell::new(false) };
}

struct CountingAlloc;

impl CountingAlloc {
  fn count(size: usize) {
    let Some(counts) = COUNTS.try_with(Cell::get).ok().flatten() else { return };
    if IN_TRACE.try_with(Cell::get).unwrap_or(true) {
      return;
    }
    let _ = counts.allocs.fetch_add(1, Ordering::SeqCst);
    let _ = counts.bytes.fetch_add(size as u64, Ordering::SeqCst);
    if counts.classify.load(Ordering::SeqCst) {
      IN_TRACE.set(true);
      let (owner, site) = Owner::of_backtrace(&std::backtrace::Backtrace::force_capture());
      counts.sites.lock().unwrap().push((owner, site, size as u64));
      IN_TRACE.set(false);
    }
    if counts.tracing.load(Ordering::SeqCst)
      && counts.trace.try_update(Ordering::SeqCst, Ordering::SeqCst, |el| el.checked_sub(1)).is_ok()
    {
      IN_TRACE.set(true);
      let bt = std::backtrace::Backtrace::force_capture();
      eprintln!("=== allocation of {size} bytes on the server thread\n{bt}");
      IN_TRACE.set(false);
    }
  }
}

// SAFETY: every call is forwarded to the system allocator unchanged.
unsafe impl GlobalAlloc for CountingAlloc {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    Self::count(layout.size());
    // SAFETY: forwarded as is
    unsafe { std::alloc::System.alloc(layout) }
  }

  unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
    Self::count(layout.size());
    // SAFETY: forwarded as is
    unsafe { std::alloc::System.alloc_zeroed(layout) }
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
    // SAFETY: forwarded as is
    unsafe { std::alloc::System.dealloc(ptr, layout) }
  }

  unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    Self::count(new_size);
    // SAFETY: forwarded as is
    unsafe { std::alloc::System.realloc(ptr, layout, new_size) }
  }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// Who an allocation is charged to: the innermost frame of its backtrace that belongs to one of
/// these. `Core` is the sans-I/O QUIC and HTTP/3 code, `Framework` the HTTP/3 server framework
/// (its router handler and the static files), `Driver` the framework's endpoint task (the loop of
/// a worker), `App` the arena's endpoints, `Executor` the io_uring runtime (sockets, timers, the
/// UDP ring) and `Tls` the handshake state machine. The crypto backend's own frames are charged to
/// it, not to the TLS code that called it.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Owner {
  Core,
  Framework,
  Driver,
  App,
  Executor,
  Tls,
  /// Inside the crypto backend (ring).
  Crypto,
  /// None of the above: the site is the innermost frame outside the standard library.
  Other,
}

impl Owner {
  /// The owner of a frame of the function `path` (without its generics), if any.
  fn of_path(path: &str) -> Option<Self> {
    const OWNERS: [(&str, Owner); 11] = [
      ("ring::", Owner::Crypto),
      ("rimu_ws::quic::", Owner::Core),
      ("rimu_ws::http3::", Owner::Core),
      ("rimu_ws::http::http3_server_framework::endpoint_task::", Owner::Driver),
      ("rimu_ws::http::http3_server_framework::", Owner::Framework),
      ("rimu_ws::http::static_files::", Owner::Framework),
      ("rimu_ws::http::http2_server_framework::", Owner::Framework),
      ("rimu_ws::executor::", Owner::Executor),
      ("rimu_ws::tls::", Owner::Tls),
      ("arena_h2::endpoint_", Owner::App),
      ("arena_h2::write_json", Owner::App),
    ];
    if path.starts_with("arena_h2::alloc_tests_h3::") {
      return None;
    }
    OWNERS.iter().find(|el| path.starts_with(el.0)).map(|el| el.1)
  }

  /// The owner of the allocation `bt` was captured in, and the frame charged.
  fn of_backtrace(bt: &std::backtrace::Backtrace) -> (Self, String) {
    let text = bt.to_string();
    let mut first = None;
    for line in text.lines() {
      let Some((idx, name)) = line.trim_start().split_once(": ") else { continue };
      if idx.is_empty() || !idx.bytes().all(|el| el.is_ascii_digit()) {
        continue;
      }
      // `<rimu_ws::tls::Foo<..> as ..>::read` is charged as `rimu_ws::tls::Foo`
      let name = name.trim_start_matches('<');
      let path = name.split(['<', ' ']).next().unwrap_or(name);
      let path = path.replace('>', "");
      let path = path.trim_end_matches(':');
      if let Some(owner) = Self::of_path(path) {
        return (owner, path.to_owned());
      }
      let ours = !["std::", "core::", "alloc::", "__rust", "arena_h2::alloc_tests_h3::"]
        .iter()
        .any(|el| path.starts_with(el));
      if first.is_none() && ours {
        first = Some(path.to_owned());
      }
    }
    (Self::Other, first.unwrap_or_default())
  }
}

fn trace_budget() -> u64 {
  std::env::var("ALLOC_TRACE").ok().and_then(|el| el.parse().ok()).unwrap_or(0)
}

/// `default`, or what `ALLOC_WARMUP` says.
fn warmup(default: usize) -> usize {
  std::env::var("ALLOC_WARMUP").ok().and_then(|el| el.parse().ok()).unwrap_or(default)
}

// ---- the server

fn env_or(name: &str, default: &str) -> String {
  std::env::var(name).unwrap_or_else(|_| default.into())
}

/// The arena-h2 HTTP/3 server on loopback, one worker whose thread is counted in `counts`.
struct Served {
  addr: SocketAddr,
  handle: Option<std::thread::JoinHandle<rimu_ws::Result<()>>>,
  signal: ShutdownSignal,
  stats: Http3Stats,
  udp: UdpParams,
}

impl Served {
  fn new(counts: &'static Counts) -> Self {
    let dir = env_or("CERT_DIR", CERT_DIR);
    let cert =
      std::fs::read(format!("{dir}/server.crt")).unwrap_or_else(|err| panic!("{dir}: {err}"));
    let key =
      std::fs::read(format!("{dir}/server.key")).unwrap_or_else(|err| panic!("{dir}: {err}"));
    let path = env_or("DATASET_PATH", DATASET_FILE);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path}: {err}"));
    let dataset: VectorUsize<DatasetItem> = serde_json::from_str(&text).unwrap();
    assert!(dataset.len() >= 50, "{path}");
    // As the program, but for the workers (one), their pinning, and where it binds
    let knobs =
      H3Knobs::from_vars(|name| (name == "ARENA_H3_PIN").then(|| "0".to_string())).unwrap();
    let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let signal = ShutdownSignal::new();
    let run = H3Run {
      addr: format!("[::]:{port}"),
      knobs,
      local_runtimes: NonZeroUsize::new(1),
      shutdown: Some((signal.clone(), Duration::from_secs(1))),
      static_root: env_or("STATIC_DIR", STATIC_ROOT),
    };
    let rc = move || {
      COUNTS.set(Some(counts));
      super::runtime()
    };
    let (stats, handle) =
      spawn_h3_with(&cert, key, ConnAux { dataset: Arc::new(dataset) }, run, rc).unwrap();
    let begin = Instant::now();
    while stats.workers().is_empty() {
      assert!(begin.elapsed() < TIMEOUT, "the h3 server did not start");
      std::thread::sleep(Duration::from_millis(5));
    }
    Self {
      addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
      handle: Some(handle),
      signal,
      stats,
      udp: knobs.udp,
    }
  }

  /// A client whose handshake is done.
  fn client(&self) -> H3LoopbackClient {
    H3LoopbackClient::connect(self.addr).unwrap()
  }

  /// Waits until `f` holds for the counters of the worker.
  fn wait(
    &self,
    what: &str,
    f: impl Fn(&rimu_ws::http::http3_server_framework::Http3WorkerStats) -> bool,
  ) {
    let begin = Instant::now();
    loop {
      let workers = self.stats.workers();
      if workers.first().is_some_and(&f) {
        return;
      }
      assert!(begin.elapsed() < TIMEOUT, "{what}: {workers:?}");
      std::thread::sleep(Duration::from_millis(5));
    }
  }
}

impl Drop for Served {
  fn drop(&mut self) {
    self.signal.trigger();
    if let Some(handle) = self.handle.take() {
      let _rslt = handle.join();
    }
  }
}

// ---- the load

fn get(path: String, fields: &[(&str, &str)]) -> H3Get {
  H3Get { fields: fields.iter().map(|el| (el.0.to_string(), el.1.to_string())).collect(), path }
}

/// Sends `total` requests, `request(n)` the n-th, over `clients`, `depth` in flight on each, and
/// checks every reply with `check(n, reply)`.
fn drive(
  clients: &mut [H3LoopbackClient],
  depth: usize,
  total: usize,
  mut request: impl FnMut(usize) -> H3Get,
  mut check: impl FnMut(usize, &H3Reply),
) {
  let mut flights: Vec<Vec<(u64, usize)>> = vec![Vec::new(); clients.len()];
  let (mut sent, mut done) = (0usize, 0usize);
  let mut last = Instant::now();
  while done < total {
    for (client, flight) in clients.iter_mut().zip(flights.iter_mut()) {
      while sent < total && flight.len() < depth {
        match client.send(&request(sent)) {
          Ok(id) => {
            flight.push((id, sent));
            sent += 1;
          }
          Err(_) => break,
        }
      }
      client.poll(Duration::from_micros(200)).unwrap();
      let mut nth = 0;
      while let Some(&(id, n)) = flight.get(nth) {
        if let Some(reply) = client.take(id).unwrap() {
          check(n, &reply);
          let _ = flight.swap_remove(nth);
          done += 1;
          last = Instant::now();
        } else {
          nth += 1;
        }
      }
    }
    assert!(last.elapsed() < TIMEOUT, "{done} of {total} replies");
  }
}

/// What a measured window allocated on the server's thread.
#[derive(Debug)]
struct Measured {
  allocs: u64,
  bytes: u64,
  requests: usize,
  /// Allocations of the server's thread from its start to the end of the window, so that a
  /// thread that is not counted shows.
  total: u64,
}

/// `warm` requests, then `measured` counted ones, every reply checked, over `CONNS` connections.
fn measure(
  counts: &'static Counts,
  served: &Served,
  mut request: impl FnMut(usize) -> H3Get,
  mut check: impl FnMut(usize, &H3Reply),
  (warm, measured): (usize, usize),
) -> Measured {
  let mut clients: Vec<_> = (0..CONNS).map(|_| served.client()).collect();
  drive(&mut clients, DEPTH, warm, &mut request, &mut check);
  counts.trace.store(trace_budget(), Ordering::SeqCst);
  counts.tracing.store(true, Ordering::SeqCst);
  let before = counts.snapshot();
  drive(&mut clients, DEPTH, measured, &mut request, &mut check);
  let after = counts.snapshot();
  counts.tracing.store(false, Ordering::SeqCst);
  for client in &mut clients {
    client.close().unwrap();
  }
  Measured {
    allocs: after.0 - before.0,
    bytes: after.1 - before.1,
    requests: measured,
    total: after.0,
  }
}

fn assert_zero(name: &str, measured: &Measured) {
  assert!(measured.total > 0, "{name}: the server's thread is not counted");
  assert_eq!(
    measured.allocs, 0,
    "{name}: {} allocations ({} bytes) over {} requests on the server's thread \
     (ALLOC_TRACE=n prints where)",
    measured.allocs, measured.bytes, measured.requests
  );
}

/// `/baseline2?a=..&b=..`, the query changing with the request.
fn baseline(n: usize) -> (H3Get, i64) {
  let (a, b) = (1 + (n % 7) as i64, 100 + (n % 13) as i64);
  (get(format!("/baseline2?a={a}&b={b}"), &[]), a + b)
}

#[test]
fn h3_baseline_requests_allocate_nothing_after_warmup() {
  let counts = Counts::leak();
  let served = Served::new(counts);
  let measured = measure(
    counts,
    &served,
    |n| baseline(n).0,
    |n, reply| {
      assert_eq!(reply.status, 200);
      assert_eq!(reply.body, baseline(n).1.to_string().as_bytes());
    },
    (warmup(WARMUP), MEASURED),
  );
  eprintln!("baseline: {measured:?}");
  assert_zero("baseline", &measured);
}

/// The base names of the static files that have no encoded twin in `root` and, with each of them,
/// what the server must send for no encoding, `br` and `gzip`.
fn static_files(root: &str) -> Vec<(String, [(Option<&'static str>, Vec<u8>); 3])> {
  let mut names: Vec<String> = std::fs::read_dir(root)
    .unwrap_or_else(|err| panic!("{root}: {err}"))
    .map(|el| el.unwrap().file_name().into_string().unwrap())
    .filter(|el| !el.ends_with(".br") && !el.ends_with(".gz"))
    .collect();
  names.sort();
  assert_eq!(names.len(), 20, "{root}");
  names
    .into_iter()
    .map(|name| {
      let plain = std::fs::read(format!("{root}/{name}")).unwrap();
      let twin = |ext: &str| std::fs::read(format!("{root}/{name}.{ext}")).ok();
      let (br, gz) = (twin("br"), twin("gz"));
      let expected = [
        (None, plain.clone()),
        (br.as_ref().map(|_| "br"), br.unwrap_or_else(|| plain.clone())),
        (gz.as_ref().map(|_| "gzip"), gz.unwrap_or(plain)),
      ];
      (name, expected)
    })
    .collect()
}

#[test]
fn h3_static_requests_allocate_nothing_after_warmup() {
  let counts = Counts::leak();
  let served = Served::new(counts);
  let files = static_files(&env_or("STATIC_DIR", STATIC_ROOT));
  // Every file with no encoding, `br` and `gzip`: the 60 combinations in turn
  let accept = [None, Some("br"), Some("gzip")];
  let pick = |n: usize| (&files[(n / 3) % files.len()], n % 3);
  let measured = measure(
    counts,
    &served,
    |n| {
      let (file, enc) = pick(n);
      let fields: Vec<(&str, &str)> =
        accept[enc].map(|el| ("accept-encoding", el)).into_iter().collect();
      get(format!("/static/{}", file.0), &fields)
    },
    |n, reply| {
      let (file, enc) = pick(n);
      let (encoding, body) = &file.1[enc];
      assert_eq!(reply.status, 200, "{}", file.0);
      assert_eq!(reply.field("content-encoding"), encoding.map(str::as_bytes), "{}", file.0);
      assert!(
        reply.body == *body,
        "{} {:?}: {} bytes of {}",
        file.0,
        accept[enc],
        reply.body.len(),
        body.len()
      );
    },
    // 10,000 requests are 166 rounds of the 60 combinations; the window lasts more than the
    // once-a-second disk re-check of the static files
    (warmup(WARMUP), MEASURED),
  );
  eprintln!("static: {measured:?}");
  assert_zero("static", &measured);
}

/// What a churn window allocated on the server's thread.
struct Churn {
  conns: usize,
  /// Allocations and bytes by owner and site.
  sites: BTreeMap<(Owner, String), (u64, u64)>,
}

impl Churn {
  fn owners(&self) -> BTreeMap<Owner, (u64, u64)> {
    let mut out = BTreeMap::new();
    for ((owner, _), (allocs, bytes)) in &self.sites {
      let elem = out.entry(*owner).or_insert((0, 0));
      elem.0 += allocs;
      elem.1 += bytes;
    }
    out
  }

  fn report(&self) -> String {
    let conns = self.conns as f64;
    let mut out = String::new();
    for (owner, (allocs, bytes)) in self.owners() {
      out.push_str(&format!(
        "  {owner:?}: {:.2} allocations, {:.0} bytes per connection\n",
        allocs as f64 / conns,
        bytes as f64 / conns
      ));
    }
    for ((owner, site), (allocs, bytes)) in &self.sites {
      out.push_str(&format!("    {owner:?} {site}: {allocs} allocations, {bytes} bytes\n"));
    }
    out
  }
}

/// A connection that sends a baseline request and closes.
fn serve_one(served: &Served) {
  let mut client = served.client();
  let reply = client.get(&baseline(3).0).unwrap();
  assert_eq!((reply.status, reply.body.as_slice()), (200, baseline(3).1.to_string().as_bytes()));
  client.close().unwrap();
}

/// `warm` connections, then `conns` counted ones, every allocation of the counted ones charged to
/// its owner.
fn churn(counts: &'static Counts, served: &Served, (warm, conns): (usize, usize)) -> Churn {
  // The most connections the window has open at once on the server is that of connections still
  // draining after their close, which depends on the speed of the clients: the warm-up reaches
  // more than that with a burst of connections open together, then the connections one by one
  if warm > 0 {
    let mut burst: Vec<_> = (0..BURST).map(|_| served.client()).collect();
    for client in &mut burst {
      let _ = client.get(&baseline(0).0).unwrap();
    }
    for client in &mut burst {
      client.close().unwrap();
    }
    drop(burst);
    served.wait("burst closed", |el| el.conns == 0);
  }
  for _ in 0..warm {
    serve_one(served);
  }
  // The symbols are loaded once here, not in the middle of a connection of the server
  let _ = std::backtrace::Backtrace::force_capture().to_string();
  counts.sites.lock().unwrap().clear();
  counts.trace.store(trace_budget(), Ordering::SeqCst);
  counts.tracing.store(true, Ordering::SeqCst);
  counts.classify.store(true, Ordering::SeqCst);
  for _ in 0..conns {
    serve_one(served);
  }
  // The connections the window opened are closed on the server too
  served.wait("connections closed", |el| el.conns == 0);
  counts.classify.store(false, Ordering::SeqCst);
  counts.tracing.store(false, Ordering::SeqCst);
  let mut sites = BTreeMap::new();
  for (owner, site, bytes) in counts.sites.lock().unwrap().drain(..) {
    let elem = sites.entry((owner, site)).or_insert((0, 0));
    elem.0 += 1;
    elem.1 += bytes;
  }
  Churn { conns, sites }
}

#[test]
fn h3_connection_churn_allocates_only_crypto_budget() {
  let counts = Counts::leak();
  let served = Served::new(counts);
  let churn = churn(counts, &served, (warmup(CHURN_WARMUP), CHURN_CONNS));
  let report = churn.report();
  eprintln!("churn per connection:\n{report}");
  let owners = churn.owners();
  let other: u64 = owners.iter().filter(|el| *el.0 != Owner::Crypto).map(|el| el.1.0).sum();
  assert_eq!(other, 0, "allocations outside the crypto backend after the warm-up:\n{report}");
  let crypto = owners.get(&Owner::Crypto).map_or(0, |el| el.0);
  assert!(
    crypto <= CRYPTO_PER_HANDSHAKE * CHURN_CONNS as u64,
    "{crypto} crypto allocations over {CHURN_CONNS} handshakes, {CRYPTO_PER_HANDSHAKE} each at most:\n{report}"
  );
}

/// The canary: the counting is live on the server's thread, and the classification finds the owner
/// of an allocation (a cold connection allocates, and its handshake signature is the crypto
/// backend's).
#[test]
fn counting_is_live_on_server_threads() {
  let counts = Counts::leak();
  assert_eq!(counts.snapshot(), (0, 0));
  let served = Served::new(counts);
  let started = counts.snapshot();
  assert!(started.0 > 0 && started.1 > 0, "the worker thread started with no allocation counted");
  counts.sites.lock().unwrap().clear();
  let _ = std::backtrace::Backtrace::force_capture().to_string();
  counts.classify.store(true, Ordering::SeqCst);
  serve_one(&served);
  served.wait("connections closed", |el| el.conns == 0);
  counts.classify.store(false, Ordering::SeqCst);
  let after = counts.snapshot();
  assert!(after.0 > started.0, "a cold connection allocated nothing on the server's thread");
  let sites = counts.sites.lock().unwrap();
  assert!(sites.len() as u64 <= after.0 - started.0);
  assert!(
    sites.iter().any(|el| el.0 == Owner::Crypto),
    "the handshake signature was not charged to the crypto backend: {:?}",
    sites.iter().map(|el| (el.0, el.1.as_str())).collect::<Vec<_>>()
  );
  // The classification of frames
  assert_eq!(Owner::of_path("ring::rsa::signing::sign"), Some(Owner::Crypto));
  assert_eq!(Owner::of_path("rimu_ws::quic::conn::flush"), Some(Owner::Core));
  assert_eq!(
    Owner::of_path("rimu_ws::http::http3_server_framework::endpoint_task::turn"),
    Some(Owner::Driver)
  );
  assert_eq!(Owner::of_path("arena_h2::alloc_tests_h3::drive"), None);
}

/// The pool memory of a worker under the benchmark's load (64 connections, 64 streams each), then
/// idle after the trim, against the budget of spec section 5.4. The receive ring and the transmit
/// arena are not pools and are reported apart.
#[test]
fn h3_pool_memory_stays_within_the_budget() {
  let (idle, peak, ring, arena) = pool_memory();
  eprintln!(
    "pool memory per worker: idle {idle} B ({:.2} MiB), peak {peak} B ({:.2} MiB); \
     receive ring {ring} B, transmit arena {arena} B",
    idle as f64 / f64::from(1 << 20),
    peak as f64 / f64::from(1 << 20)
  );
  assert!(peak <= POOL_BUDGET_LOAD, "peak {peak} B over the budget of {POOL_BUDGET_LOAD} B");
  assert!(idle <= POOL_BUDGET_IDLE, "idle {idle} B over the budget of {POOL_BUDGET_IDLE} B");
}

/// (idle bytes after the trim, peak bytes, bytes of the receive ring, bytes of the transmit arena)
/// of the worker of a new server after 64 × 64 requests of `/baseline2` and of `/static`.
fn pool_memory() -> (u64, u64, u64, u64) {
  let counts = Counts::leak();
  let served = Served::new(counts);
  let mut clients: Vec<_> = (0..64).map(|_| served.client()).collect();
  drive(&mut clients, 64, 8_000, |n| baseline(n).0, |_, reply| assert_eq!(reply.status, 200));
  let files = static_files(&env_or("STATIC_DIR", STATIC_ROOT));
  drive(
    &mut clients,
    64,
    3_000,
    |n| get(format!("/static/{}", files[n % files.len()].0), &[("accept-encoding", "br")]),
    |_, reply| assert_eq!(reply.status, 200),
  );
  let loaded = served.stats.workers()[0];
  eprintln!(
    "loaded: {} connections, pools {} B, peak {} B",
    loaded.conns, loaded.pool_bytes, loaded.pool_bytes_peak
  );
  for client in &mut clients {
    client.close().unwrap();
  }
  drop(clients);
  served.wait("idle trim", |el| el.conns == 0 && el.idle_trims >= 1);
  let worker = served.stats.workers()[0];
  let udp = served.udp;
  // The ring: 256 buffers of 64 KiB with GRO (exactly 16 MiB, apart from the headroom of each)
  let payload = if udp.gro { udp.recv_buffer_len.max(65_536) } else { udp.recv_buffer_len };
  let ring = u64::from(udp.recv_buffers.next_power_of_two()) * u64::from(payload);
  (worker.pool_bytes, worker.pool_bytes_peak, ring, udp.tx_arena_bytes as u64)
}

/// Prints the pool memory of a worker (see [`h3_pool_memory_stays_within_the_budget`]).
#[test]
#[ignore = "prints numbers"]
fn memory_report() {
  let (idle, peak, ring, arena) = pool_memory();
  eprintln!("idle {idle} B, peak {peak} B, receive ring {ring} B, transmit arena {arena} B");
}
