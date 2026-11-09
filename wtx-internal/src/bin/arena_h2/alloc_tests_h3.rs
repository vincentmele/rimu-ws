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
//! `ALLOC_BIG=n` prints the owner and site of every allocation of `n` bytes or more on the server's
//! thread (the memory of a worker, attributed). `ALLOC_WARMUP=n` replaces the warm-up of the steady-state tests (requests) and of the churn test
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
  sync::atomic::{AtomicI64, Ordering},
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
/// Connections of the steady-state tests, and the streams in flight on each: the benchmark's 64 ×
/// 64 requests under way at once.
const CONNS: usize = 64;
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
/// The budget of spec section 5.4 for the heap of a worker (rulings T20-e and T20-f): under load
/// (everything), and idle after the trim (the on-demand state, over the floor a worker has at
/// start).
const POOL_BUDGET_LOAD: u64 = 16 << 20;
const POOL_BUDGET_IDLE: u64 = 2 << 20;
/// The floor of a worker at start, before any connection: fixed structures sized by configuration
/// (transmit arena, receive ring, inbox, send slots, CID table, timer wheel). Measured 1.86 MiB
/// with GRO on (its ring apart) and 2.41 MiB with the library's I/O defaults; these bounds pin
/// it, so that growth of a fixed structure shows (ruling T20-f).
const FLOOR_BOUND_GRO: u64 = 2 << 20;
const FLOOR_BOUND_PLAIN: u64 = 5 << 19;
const TIMEOUT: Duration = Duration::from_secs(20);

// ---- the counting allocator

/// The allocations of one server's worker thread.
struct Counts {
  allocs: AtomicU64,
  bytes: AtomicU64,
  /// The sizes of the allocations of [`BIG`] bytes or more made by `BufRing::new`, in order: the
  /// receive rings of the sockets, up to eight.
  big: [AtomicU64; 8],
  /// Net live bytes: the sizes of the allocations of the thread minus those of its deallocations
  /// (ruling T20-e). A block that another thread allocated and this one frees counts negative.
  live: AtomicI64,
  /// The most [`Self::live`] ever, tracked at every allocation.
  peak: AtomicI64,
  /// The size from which an allocation prints its owner and site when it is made (`ALLOC_BIG`, 0
  /// for never): to attribute the memory of a worker.
  print_from: AtomicU64,
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
      big: [const { AtomicU64::new(0) }; 8],
      live: AtomicI64::new(0),
      print_from: AtomicU64::new(0),
      peak: AtomicI64::new(0),
      classify: AtomicBool::new(false),
      sites: std::sync::Mutex::new(Vec::new()),
      trace: AtomicU64::new(0),
      tracing: AtomicBool::new(false),
    }))
  }

  fn snapshot(&self) -> (u64, u64) {
    (self.allocs.load(Ordering::SeqCst), self.bytes.load(Ordering::SeqCst))
  }

  /// The net live bytes now.
  fn live(&self) -> i64 {
    self.live.load(Ordering::SeqCst)
  }

  /// The largest ring of [`BIG`] bytes or more.
  fn largest(&self) -> u64 {
    self.big.iter().map(|el| el.load(Ordering::SeqCst)).max().unwrap_or(0)
  }

  /// `delta` more live bytes (fewer if negative).
  fn track(&self, delta: i64) {
    let live = self.live.fetch_add(delta, Ordering::SeqCst).wrapping_add(delta);
    let _ = self.peak.fetch_max(live, Ordering::SeqCst);
  }
}

/// The size from which an allocation is recorded in [`Counts::big`].
const BIG: usize = 4 << 20;

std::thread_local! {
  static COUNTS: Cell<Option<&'static Counts>> = const { Cell::new(None) };
  /// In the middle of printing a backtrace, whose allocations are not counted.
  static IN_TRACE: Cell<bool> = const { Cell::new(false) };
}

struct CountingAlloc;

impl CountingAlloc {
  /// The net live bytes of the thread change by `delta`.
  /// What the allocator itself allocates while it captures a backtrace (the symbol tables stay
  /// loaded) is not the worker's.
  fn track(delta: i64) {
    if IN_TRACE.try_with(Cell::get).unwrap_or(true) {
      return;
    }
    if let Some(counts) = COUNTS.try_with(Cell::get).ok().flatten() {
      counts.track(delta);
    }
  }

  fn count(size: usize) {
    let Some(counts) = COUNTS.try_with(Cell::get).ok().flatten() else { return };
    if IN_TRACE.try_with(Cell::get).unwrap_or(true) {
      return;
    }
    let _ = counts.allocs.fetch_add(1, Ordering::SeqCst);
    let _ = counts.bytes.fetch_add(size as u64, Ordering::SeqCst);
    let print_from = counts.print_from.load(Ordering::SeqCst);
    if print_from != 0 && size as u64 >= print_from {
      IN_TRACE.set(true);
      let (owner, site) = Owner::of_backtrace(&std::backtrace::Backtrace::force_capture());
      eprintln!("ALLOC_BIG {size} B {owner:?} {site}");
      IN_TRACE.set(false);
    }
    if size >= BIG {
      IN_TRACE.set(true);
      let (_, site) = Owner::of_backtrace(&std::backtrace::Backtrace::force_capture());
      IN_TRACE.set(false);
      if site.ends_with("BufRing::new") {
        for slot in &counts.big {
          if slot.compare_exchange(0, size as u64, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            break;
          }
        }
      }
    }
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
    Self::track(layout.size() as i64);
    // SAFETY: forwarded as is
    unsafe { std::alloc::System.alloc(layout) }
  }

  unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
    Self::count(layout.size());
    Self::track(layout.size() as i64);
    // SAFETY: forwarded as is
    unsafe { std::alloc::System.alloc_zeroed(layout) }
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
    Self::track(-(layout.size() as i64));
    // SAFETY: forwarded as is
    unsafe { std::alloc::System.dealloc(ptr, layout) }
  }

  unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    Self::count(new_size);
    Self::track(new_size as i64 - layout.size() as i64);
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
    Self::with_gro(counts, true)
  }

  /// [`Self::new`] with the receive offload `gro` (the program's default is on, the library's off).
  fn with_gro(counts: &'static Counts, gro: bool) -> Self {
    counts.print_from.store(
      std::env::var("ALLOC_BIG").ok().and_then(|el| el.parse().ok()).unwrap_or(0),
      Ordering::SeqCst,
    );
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
    let knobs = H3Knobs::from_vars(|name| match name {
      "ARENA_H3_PIN" => Some("0".to_string()),
      "ARENA_H3_GRO" if !gro => Some("0".to_string()),
      _ => None,
    })
    .unwrap();
    let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let signal = ShutdownSignal::new();
    let run = H3Run {
      addr: format!("[::]:{port}"),
      knobs,
      local_runtimes: NonZeroUsize::new(1),
      shutdown: Some((signal.clone(), Duration::from_secs(1))),
      static_root: env_or("STATIC_DIR", STATIC_ROOT),
      test_routes: false,
    };
    let rc = move || {
      COUNTS.set(Some(counts));
      super::runtime_h3()
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
  /// The allocations of the crypto backend that each counted connection took.
  crypto: Vec<u64>,
  /// The most connections the worker held at once in the window (as sampled after each), and in
  /// the warm-up.
  peak: u64,
  warm_peak: u64,
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

/// The connections the worker held at once (those still draining after their close included).
fn held(served: &Served) -> u64 {
  served.stats.workers().first().map_or(0, |el| el.conns)
}

/// `warm` connections, then `conns` counted ones, every allocation of the counted ones charged to
/// its owner.
fn churn(counts: &'static Counts, served: &Served, (warm, conns): (usize, usize)) -> Churn {
  // The most connections the window has open at once on the server is that of connections still
  // draining after their close, which depends on the speed of the clients: the warm-up reaches
  // more than that with a burst of connections open together, then the connections one by one
  let mut warm_peak = 0;
  if warm > 0 {
    let mut burst: Vec<_> = (0..BURST).map(|_| served.client()).collect();
    for client in &mut burst {
      let _ = client.get(&baseline(0).0).unwrap();
    }
    warm_peak = held(served);
    for client in &mut burst {
      client.close().unwrap();
    }
    drop(burst);
    served.wait("burst closed", |el| el.conns == 0);
  }
  for _ in 0..warm {
    serve_one(served);
    warm_peak = warm_peak.max(held(served));
  }
  // The symbols are loaded once here, not in the middle of a connection of the server
  let _ = std::backtrace::Backtrace::force_capture().to_string();
  counts.sites.lock().unwrap().clear();
  counts.trace.store(trace_budget(), Ordering::SeqCst);
  counts.tracing.store(true, Ordering::SeqCst);
  counts.classify.store(true, Ordering::SeqCst);
  let (mut peak, mut crypto) = (0, Vec::new());
  for _ in 0..conns {
    let before = counts.sites.lock().unwrap().len();
    serve_one(served);
    // The handshake signature is made before the server answers: its allocations are in the sites
    // by now
    let sites = counts.sites.lock().unwrap();
    crypto.push(sites.iter().skip(before).filter(|el| el.0 == Owner::Crypto).count() as u64);
    drop(sites);
    peak = peak.max(held(served));
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
  Churn { conns, crypto, peak, sites, warm_peak }
}

#[test]
fn h3_connection_churn_allocates_only_crypto_budget() {
  let counts = Counts::leak();
  let served = Served::new(counts);
  let warmed = warmup(CHURN_WARMUP) > 0;
  let churn = churn(counts, &served, (warmup(CHURN_WARMUP), CHURN_CONNS));
  let report = churn.report();
  eprintln!("churn per connection:\n{report}");
  let owners = churn.owners();
  let other: u64 = owners.iter().filter(|el| *el.0 != Owner::Crypto).map(|el| el.1.0).sum();
  assert_eq!(other, 0, "allocations outside the crypto backend after the warm-up:\n{report}");
  // Each handshake took at most the 9 of ring's RSA signature
  let worst = churn.crypto.iter().copied().max().unwrap_or(0);
  assert!(worst <= CRYPTO_PER_HANDSHAKE, "a handshake took {worst} crypto allocations:\n{report}");
  // The warm-up held as many connections at once as the window did, so that a pool does not grow
  // in the window for want of a warm-up that was smaller than it
  assert!(
    !warmed || churn.warm_peak >= churn.peak,
    "the window held {} connections at once, the warm-up {}",
    churn.peak,
    churn.warm_peak
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

/// What the heap of a worker thread held (ruling T20-e: net live bytes, alloc minus dealloc by
/// `Layout`, on the thread of the worker only).
#[derive(Debug)]
struct Memory {
  /// The allocation of the receive ring, if one of 4 MiB or more was made (the GRO ring).
  ring: u64,
  /// Held once the worker runs, before any connection.
  startup: i64,
  /// Held under load, 64 connections with 64 streams each.
  loaded: i64,
  /// The most held, tracked at every allocation.
  peak: i64,
  /// Held after the idle trim.
  idle: i64,
  /// What the estimate of the pools said under load (a diagnostic).
  pools: u64,
  /// The transmit arena.
  arena: u64,
}

impl Memory {
  fn mib(bytes: i64) -> f64 {
    bytes as f64 / f64::from(1 << 20)
  }

  /// Without the GRO ring, the one thing that ruling T20-e reports apart.
  fn peak_without_ring(&self) -> i64 {
    self.peak - self.ring as i64
  }

  fn report(&self, name: &str) -> String {
    format!(
      "{name}: startup {:.2} MiB (floor {:.2} without the ring), loaded {:.2}, peak {:.2}, idle {:.2} \
       (on-demand {:.2} over the start); ring {:.2} MiB (apart), \
       arena {:.2}, pool estimate {:.2}; unattributed at peak {:.2} MiB",
      Self::mib(self.startup),
      Self::mib(self.startup - self.ring as i64),
      Self::mib(self.loaded),
      Self::mib(self.peak),
      Self::mib(self.idle),
      Self::mib(self.idle - self.startup),
      Self::mib(self.ring as i64),
      Self::mib(self.arena as i64),
      Self::mib(self.pools as i64),
      Self::mib(self.peak_without_ring() - self.arena as i64 - self.pools as i64),
    )
  }
}

/// The memory of the heap of one worker under the benchmark's load (64 connections, 64 streams
/// each, `/baseline2` then `/static`), against spec section 5.4 as rulings T20-e and T20-f count it
/// (net live bytes of the worker thread, everything), with the program's receive offload (GRO on;
/// its ring is the one thing reported apart) and with the library's I/O defaults (GRO off;
/// everything counted):
/// - the peak is within 16 MiB;
/// - the idle trim leaves at most 2 MiB of on-demand state over the floor of a worker at start;
/// - that floor, a fixed cost of the configuration, stays within its bound.
#[test]
fn h3_pool_memory_stays_within_the_budget() {
  for gro in [true, false] {
    let name = if gro { "arena-h2 knobs (GRO on)" } else { "library I/O defaults (GRO off)" };
    let memory = pool_memory(gro);
    eprintln!("{}", memory.report(name));
    if gro {
      assert!(memory.ring >= 16 << 20, "the GRO ring was not seen: {memory:?}");
    }
    let peak = memory.peak_without_ring();
    assert!(peak <= POOL_BUDGET_LOAD as i64, "{name}: peak {peak} B over 16 MiB: {memory:?}");
    let left = memory.idle - memory.startup;
    assert!(left <= POOL_BUDGET_IDLE as i64, "{name}: {left} B left over the floor: {memory:?}");
    let floor = memory.startup - memory.ring as i64;
    let bound = if gro { FLOOR_BOUND_GRO } else { FLOOR_BOUND_PLAIN };
    assert!(floor <= bound as i64, "{name}: floor {floor} B over {bound} B: {memory:?}");
  }
}

fn pool_memory(gro: bool) -> Memory {
  let counts = Counts::leak();
  let served = Served::with_gro(counts, gro);
  // The worker binds its socket (and makes its ring) after it stored its counters: settled when
  // its heap does not change for a while
  let mut startup = counts.live();
  loop {
    std::thread::sleep(Duration::from_millis(200));
    let now = counts.live();
    if now == startup {
      break;
    }
    startup = now;
  }
  let ring = counts.largest();
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
  let loaded = counts.live();
  let pools = served.stats.workers()[0].pool_bytes;
  for client in &mut clients {
    client.close().unwrap();
  }
  drop(clients);
  served.wait("idle trim", |el| el.conns == 0 && el.idle_trims >= 1);
  // The stats are stored in the turn that trimmed; the thread is quiet after it
  std::thread::sleep(Duration::from_millis(100));
  Memory {
    ring,
    startup,
    loaded,
    peak: counts.peak.load(Ordering::SeqCst),
    idle: counts.live(),
    pools,
    arena: served.udp.tx_arena_bytes as u64,
  }
}

/// Prints the memory of a worker (see [`h3_pool_memory_stays_within_the_budget`]).
#[test]
#[ignore = "prints numbers"]
fn memory_report() {
  for gro in [true, false] {
    eprintln!("{}", pool_memory(gro).report(if gro { "GRO on" } else { "GRO off" }));
  }
}
