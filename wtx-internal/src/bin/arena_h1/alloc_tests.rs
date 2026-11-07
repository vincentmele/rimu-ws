//! Allocation tests of the arena-h1 servers, after a warm-up, on the server's runtime thread:
//! a keep-alive connection's requests allocate nothing (steady state), and neither does opening,
//! serving and closing a connection (churn), but for the share of the executor and of TLS.
//!
//! A counting global allocator counts the allocations of the threads that were told to (the
//! runtime thread of each test server, from its local-runtime callback), each server in its own
//! counters, so the clients and the tests running alongside are not counted.
//!
//! `ALLOC_TRACE=n` prints the backtraces of the first `n` allocations of every measured window,
//! to find where they come from. `alloc_table` (ignored) prints the allocations of every path,
//! `churn_table` (ignored) those of a connection of every profile, by [`Owner`].
//!
//! The JSON tests need the arena dataset (`DATASET_PATH`), the TLS ones its certificate pair
//! (`CERT_DIR`): without them they fail, instead of passing on nothing.

#![allow(clippy::disallowed_methods, reason = "a test harness: responses are parsed as text")]

use super::*;
use core::{
  alloc::{GlobalAlloc, Layout},
  cell::Cell,
  sync::atomic::Ordering,
};
use rimu_ws::{
  executor::StdRuntime,
  net::{StreamReader as _, StreamWriter as _},
  sync::{AtomicBool, AtomicU64},
  tls::TlsConnectorBuilder,
};
use std::collections::BTreeMap;

/// Requests sent before counting, so that every buffer has reached its size.
const WARMUP: usize = 200;
/// Requests counted.
const MEASURED: usize = 1000;
/// Where the certificate pair of the TLS tests is, unless `CERT_DIR` says.
const CERT_DIR: &str = "/mnt/nvme1tb/claude-tmp/arena-main/certs";
/// The dataset of the JSON tests, unless `DATASET_PATH` says.
const DATASET_FILE: &str = "/mnt/nvme1tb/claude-tmp/arena-main/data/dataset.json";

/// The allocations of one server's runtime thread.
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

/// A free loopback port.
fn free_addr() -> String {
  let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
  format!("127.0.0.1:{port}")
}

/// The arena runtime, with this thread's allocations counted in `counts`.
fn counted_runtime(counts: &'static Counts) -> impl Clone + Fn() -> rimu_ws::Result<UringRuntime> {
  move || {
    COUNTS.set(Some(counts));
    runtime()
  }
}

fn load_test_dataset() -> bool {
  if DATASET_LOADED.get().is_some() {
    return super::DATASET.get().is_some_and(|el| !el.is_empty());
  }
  let path = std::env::var("DATASET_PATH").unwrap_or_else(|_| DATASET_FILE.into());
  let dataset = std::fs::read_to_string(&path)
    .ok()
    .and_then(|el| serde_json::from_str::<VectorUsize<DatasetItem>>(&el).ok());
  if let Some(elem) = dataset {
    let _ = super::DATASET.set(elem);
  } else {
    eprintln!("no dataset at {path}");
  }
  let _ = DATASET_LOADED.set(());
  super::DATASET.get().is_some_and(|el| !el.is_empty())
}

static DATASET_LOADED: OnceLock<()> = OnceLock::new();

/// The directory of the TLS tests' certificate pair.
fn cert_dir() -> String {
  std::env::var("CERT_DIR").unwrap_or_else(|_| CERT_DIR.into())
}

/// A one-runtime plaintext arena server whose runtime thread is counted; returns its address.
fn plain_server(counts: &'static Counts) -> String {
  let addr = free_addr();
  let server_addr = addr.clone();
  let _jh = std::thread::spawn(move || {
    serve_plain(&server_addr, NonZeroUsize::new(1), counted_runtime(counts))
  });
  for _ in 0..500 {
    if std::net::TcpStream::connect(&addr).is_ok() {
      return addr;
    }
    std::thread::sleep(Duration::from_millis(10));
  }
  panic!("the plaintext server did not start");
}

/// A one-runtime TLS arena server whose runtime thread is counted; returns its address, `None`
/// without the certificate pair.
fn tls_server(counts: &'static Counts) -> Option<String> {
  let dir = cert_dir();
  let cert = std::fs::read(format!("{dir}/server.crt")).ok()?;
  let key = std::fs::read(format!("{dir}/server.key")).ok()?;
  let addr = free_addr();
  let server_addr = addr.clone();
  let _jh = std::thread::spawn(move || {
    serve_tls(&server_addr, NonZeroUsize::new(1), &cert, &key, counted_runtime(counts))
  });
  Some(addr)
}

/// A response as the client read it.
struct Response {
  body: Vec<u8>,
  /// `Content-Encoding`, lower-cased.
  encoding: Option<String>,
  status: u16,
}

/// One response read off `buf` once it is complete; `buf` keeps what follows.
fn take_response(buf: &mut Vec<u8>) -> Option<Response> {
  let end = buf.windows(4).position(|el| el == b"\r\n\r\n")? + 4;
  let head = core::str::from_utf8(&buf[..end]).unwrap().to_ascii_lowercase();
  let status = head.get(9..12).unwrap().parse().unwrap();
  let field = |name: &str| head.lines().find_map(|el| el.strip_prefix(name)).map(str::trim);
  let len = field("content-length:").map_or(0, |el| el.parse().unwrap());
  let encoding = field("content-encoding:").map(String::from);
  if buf.len() < end + len {
    return None;
  }
  let body = buf[end..end + len].to_vec();
  let _ = buf.drain(..end + len);
  Some(Response { body, encoding, status })
}

/// The bytes of a request: `head` (without its final empty line) and, if any, `body`, sent with
/// `Content-Length` or chunked in 4 KiB chunks.
fn request(head: &str, body: Option<(&[u8], bool)>) -> Vec<u8> {
  let mut out = Vec::from(head.as_bytes());
  match body {
    None => out.extend_from_slice(b"\r\n"),
    Some((body, false)) => {
      out.extend_from_slice(format!("content-length: {}\r\n\r\n", body.len()).as_bytes());
      out.extend_from_slice(body);
    }
    Some((body, true)) => {
      out.extend_from_slice(b"transfer-encoding: chunked\r\n\r\n");
      for chunk in body.chunks(4096) {
        out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
      }
      out.extend_from_slice(b"0\r\n\r\n");
    }
  }
  out
}

/// What a measured window allocated on the server's thread.
#[derive(Debug)]
struct Measured {
  allocs: u64,
  bytes: u64,
  /// Requests measured.
  requests: usize,
  /// Allocations of the server's thread from its start to the end of the window, so that a
  /// thread that is not counted shows.
  total: u64,
}

impl Measured {
  fn per_req(&self) -> (f64, f64) {
    (self.allocs as f64 / self.requests as f64, self.bytes as f64 / self.requests as f64)
  }
}

fn trace_budget() -> u64 {
  std::env::var("ALLOC_TRACE").ok().and_then(|el| el.parse().ok()).unwrap_or(0)
}

/// Sends `cases` in turn, as a load generator rotating requests does, on one keep-alive
/// connection: `warm` requests, then `measured` counted ones, every response checked. `exchange`
/// sends the requests it is given, if any, and returns the next response.
fn measure(
  counts: &'static Counts,
  mut exchange: impl FnMut(Option<&[u8]>) -> Response,
  cases: &[Case],
  warm: usize,
  measured: usize,
) -> Measured {
  let mut next = 0usize;
  // One case's requests; returns how many were sent
  let mut step = || {
    let case = &cases[next % cases.len()];
    next = next.wrapping_add(1);
    (case.check)(&exchange(Some(&case.req)));
    for _ in 1..case.responses {
      (case.check)(&exchange(None));
    }
    case.responses
  };
  let mut sent = 0;
  while sent < warm {
    sent += step();
  }
  counts.trace.store(trace_budget(), Ordering::SeqCst);
  counts.tracing.store(true, Ordering::SeqCst);
  let before = counts.snapshot();
  let mut requests = 0;
  while requests < measured {
    requests += step();
  }
  let after = counts.snapshot();
  counts.tracing.store(false, Ordering::SeqCst);
  Measured { allocs: after.0 - before.0, bytes: after.1 - before.1, requests, total: after.0 }
}

/// Measures `cases` on a new plaintext server.
fn measure_plain(cases: &[Case], warm: usize, measured: usize) -> Measured {
  let counts = Counts::leak();
  let addr = plain_server(counts);
  let mut stream = std::net::TcpStream::connect(&addr).unwrap();
  stream.set_nodelay(true).unwrap();
  stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
  let mut buf = Vec::new();
  let mut chunk = vec![0u8; 256 * 1024];
  let exchange = |req: Option<&[u8]>| {
    if let Some(elem) = req {
      std::io::Write::write_all(&mut stream, elem).unwrap();
    }
    loop {
      if let Some(elem) = take_response(&mut buf) {
        return elem;
      }
      let len = std::io::Read::read(&mut stream, &mut chunk).unwrap();
      assert_ne!(len, 0, "the server closed the connection");
      buf.extend_from_slice(&chunk[..len]);
    }
  };
  measure(counts, exchange, cases, warm, measured)
}

/// Measures `cases` on a new TLS server, `None` without the certificate pair.
fn measure_tls(cases: &[Case], warm: usize, measured: usize) -> Option<Measured> {
  let counts = Counts::leak();
  let addr = tls_server(counts)?;
  let uri = rimu_ws::net::UriString::new(format!("https://{addr}"));
  let rt = StdRuntime::new();
  let mut tls_stream = rt.block_on(async {
    let mut rng = ChaCha20::from_std_random().unwrap();
    // The arena certificate (a CA that signs itself) is not one a client can verify
    let mut config = TlsConfig::unverified();
    config
      .alpn_mut()
      .get_or_insert_default()
      .protocol_name_list
      .push(b"http/1.1".as_slice().try_into().unwrap())
      .unwrap();
    for _ in 0..500 {
      if let Ok(elem) = TlsConnectorBuilder::std(uri.clone()).build(&config, &mut rng).await {
        return elem.connect().await.unwrap().tls_stream;
      }
      std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the TLS server did not start");
  });
  let mut buf = Vec::new();
  let mut chunk = vec![0u8; 256 * 1024];
  let exchange = |req: Option<&[u8]>| {
    rt.block_on(async {
      if let Some(elem) = req {
        tls_stream.write_all(elem).await.unwrap();
      }
      loop {
        if let Some(elem) = take_response(&mut buf) {
          return elem;
        }
        let len = tls_stream.read(chunk.as_mut_slice().into()).await.unwrap();
        let len = len.expect("the server closed the connection").get();
        buf.extend_from_slice(&chunk[..len]);
      }
    })
  };
  Some(measure(counts, exchange, cases, warm, measured))
}

/// The JSON of `/json/{count}?m={m}`.
fn json(count: usize, m: i64) -> Vec<u8> {
  let mut out = VectorUsize::new();
  write_json(&mut out, super::DATASET.get().unwrap(), count, m).unwrap();
  out.as_slice().to_vec()
}

fn ungzip(data: &[u8]) -> Vec<u8> {
  let mut out = vec![0u8; 1 << 20];
  let (done, code) = zlib_rs::decompress_slice(
    &mut out,
    data,
    zlib_rs::InflateConfig { window_bits: GZIP_WINDOW_BITS },
  );
  assert_eq!(code, zlib_rs::ReturnCode::Ok);
  done.to_vec()
}

fn unbrotli(data: &[u8]) -> Vec<u8> {
  let mut out = Vec::new();
  brotli::BrotliDecompress(&mut &*data, &mut out).unwrap();
  out
}

/// A path measured.
struct Case {
  /// Checks every response.
  check: Box<dyn Fn(&Response)>,
  name: String,
  /// The requests, sent at once.
  req: Vec<u8>,
  /// How many requests `req` holds.
  responses: usize,
  tls: bool,
}

impl Case {
  fn new(name: impl Into<String>, tls: bool, req: Vec<u8>, check: Box<dyn Fn(&Response)>) -> Self {
    Self { check, name: name.into(), req, responses: 1, tls }
  }
}

/// `/json/{count}?m={m}` on the plaintext server, answered with `coding`: asked for as the
/// json-comp load asks (`gzip, br`) for gzip, by `br` alone for brotli (gzip is preferred), with
/// no `Accept-Encoding` for none. The response must say its coding and decode to the JSON.
fn json_case(count: usize, m: i64, coding: Encoding) -> Case {
  let mut head = format!("GET /json/{count}?m={m} HTTP/1.1\r\nhost: x\r\n");
  let (accept, name, encoding, decode): (_, _, _, fn(&[u8]) -> Vec<u8>) = match coding {
    Encoding::Brotli => (Some("br"), "br", Some("br"), unbrotli),
    Encoding::Gzip => (Some("gzip, br"), "gzip", Some("gzip"), ungzip),
    Encoding::Identity => (None, "identity", None, <[u8]>::to_vec),
  };
  if let Some(elem) = accept {
    head.push_str(&format!("accept-encoding: {elem}\r\n"));
  }
  let expected = json(count, m);
  let check = move |res: &Response| {
    assert_eq!(res.status, 200);
    assert_eq!(res.encoding.as_deref(), encoding);
    assert_eq!(decode(&res.body), expected);
  };
  Case::new(
    format!("json-comp /json/{count}?m={m} {name}"),
    false,
    request(&head, None),
    Box::new(check),
  )
}

/// The json-comp rotation of the load (`json-gzip-25.raw,json-gzip-40.raw,json-gzip-50.raw`).
const JSON_ROTATION: [(usize, i64); 3] = [(25, 4), (40, 8), (50, 6)];

/// Loads the dataset, or fails the test.
fn need_dataset() {
  assert!(load_test_dataset(), "no arena dataset: set DATASET_PATH (default {DATASET_FILE})");
}

/// The paths measured.
fn cases() -> Vec<Case> {
  let mut out = Vec::new();
  let base = "POST /baseline11?a=1&b=2 HTTP/1.1\r\nhost: x\r\n";
  let sum = |expected: &'static [u8]| -> Box<dyn Fn(&Response)> {
    Box::new(move |res| {
      assert_eq!(res.status, 200);
      assert_eq!(res.body, expected);
    })
  };
  let get = request("GET /baseline11?a=1&b=2 HTTP/1.1\r\nhost: x\r\n", None);
  out.push(Case::new("baseline GET", false, get.clone(), sum(b"3")));
  out.push(Case::new(
    "baseline POST content-length",
    false,
    request(base, Some((b"20", false))),
    sum(b"23"),
  ));
  out.push(Case::new(
    "baseline POST chunked",
    false,
    request(base, Some((b"20", true))),
    sum(b"23"),
  ));
  // Sixteen requests in one write, as a pipelining client sends them
  let mut pipelined = Case::new("baseline GET pipelined x16", false, get.repeat(16), sum(b"3"));
  pipelined.responses = 16;
  out.push(pipelined);
  out.push(Case::new(
    "async GET /delay/1",
    false,
    request("GET /delay/1 HTTP/1.1\r\nhost: x\r\n", None),
    sum(b"1"),
  ));
  if load_test_dataset() {
    for (count, m) in JSON_ROTATION {
      for coding in [Encoding::Identity, Encoding::Gzip, Encoding::Brotli] {
        out.push(json_case(count, m, coding));
      }
    }
    let mut tls = json_case(25, 4, Encoding::Identity);
    tls.name = "json-tls /json/25?m=4".into();
    tls.tls = true;
    out.push(tls);
  }
  for len in [1, 10 * 1024, 100 * 1024] {
    for chunked in [false, true] {
      let body: Vec<u8> = (0..len).map(|el| (el % 251) as u8).collect();
      let req = request("POST /echo HTTP/1.1\r\nhost: x\r\n", Some((&body, chunked)));
      let name =
        format!("8gbit POST /echo {len} B {}", if chunked { "chunked" } else { "content-length" });
      let check: Box<dyn Fn(&Response)> = Box::new(move |res| {
        assert_eq!(res.status, 200);
        assert_eq!(res.body, body.as_slice());
      });
      out.push(Case::new(name, true, req, check));
    }
  }
  out
}

fn run_case(case: Case) -> Option<Measured> {
  let tls = case.tls;
  let cases = [case];
  if tls {
    measure_tls(&cases, WARMUP, MEASURED)
  } else {
    Some(measure_plain(&cases, WARMUP, MEASURED))
  }
}

/// Prints the allocations per request of every path:
/// `cargo test ... --bin arena-h1 alloc_table -- --ignored --nocapture --test-threads 1`.
#[test]
#[ignore = "prints a table"]
fn alloc_table() {
  println!("| path | allocs/req | bytes/req | thread total |\n|---|---|---|---|");
  let filter = std::env::var("ALLOC_CASE").unwrap_or_default();
  for case in cases() {
    let name = case.name.clone();
    if !name.contains(&filter) {
      continue;
    }
    let Some(measured) = run_case(case) else {
      println!("| {name} | skipped (no certificate) | | |");
      continue;
    };
    let (allocs, bytes) = measured.per_req();
    println!("| {name} | {allocs:.3} | {bytes:.1} | {} |", measured.total);
  }
}

/// Asserts that every path `select` picks allocates nothing on the server's thread after the
/// warm-up; fails if it picks none or one could not run.
fn assert_no_alloc(select: impl Fn(&str) -> bool) {
  let mut ran = Vec::new();
  let mut failed = Vec::new();
  for case in cases() {
    let name = case.name.clone();
    if !select(&name) {
      continue;
    }
    let Some(measured) = run_case(case) else {
      panic!("{name}: no certificate pair in {}: set CERT_DIR", cert_dir());
    };
    if measured.allocs != 0 {
      failed.push(format!(
        "{name}: {} allocations, {} bytes over {} requests",
        measured.allocs, measured.bytes, measured.requests
      ));
    }
    ran.push(name);
  }
  assert!(!ran.is_empty(), "no path ran");
  assert!(failed.is_empty(), "allocations after the warm-up:\n{}", failed.join("\n"));
  eprintln!("{} paths allocate nothing: {}", ran.len(), ran.join(", "));
}

// baseline, limited-conn, latency-1m/10k: GET, POST with a Content-Length and a chunked body,
// and pipelined GETs.
#[test]
fn baseline_steady_state_allocates_nothing() {
  assert_no_alloc(|el| el.starts_with("baseline "));
}

#[test]
fn async_delay_steady_state_allocates_nothing() {
  assert_no_alloc(|el| el.starts_with("async "));
}

#[test]
fn json_comp_identity_steady_state_allocates_nothing() {
  need_dataset();
  assert_no_alloc(|el| el.starts_with("json-comp ") && el.ends_with(" identity"));
}

#[test]
fn json_comp_gzip_steady_state_allocates_nothing() {
  need_dataset();
  assert_no_alloc(|el| el.starts_with("json-comp ") && el.ends_with(" gzip"));
}

#[test]
fn json_comp_br_steady_state_allocates_nothing() {
  need_dataset();
  assert_no_alloc(|el| el.starts_with("json-comp ") && el.ends_with(" br"));
}

#[test]
fn json_tls_steady_state_allocates_nothing() {
  need_dataset();
  assert_no_alloc(|el| el.starts_with("json-tls "));
}

// 8gbit: 1 B, 10 KiB and 100 KiB bodies, with a Content-Length and chunked.
#[test]
fn echo_tls_steady_state_allocates_nothing() {
  assert_no_alloc(|el| el.starts_with("8gbit "));
}

/// Fails if `measured` allocated.
fn assert_zero(what: &str, measured: &Measured) {
  assert_eq!(
    measured.allocs, 0,
    "{what}: {} allocations, {} bytes over {} requests",
    measured.allocs, measured.bytes, measured.requests
  );
}

// The load rotates 25/40/50 on every connection: the bodies of the three sizes take turns in the
// same buffers and the same compressor state.
#[test]
fn json_comp_rotation_allocates_nothing() {
  need_dataset();
  for coding in [Encoding::Identity, Encoding::Gzip, Encoding::Brotli] {
    let cases: Vec<Case> =
      JSON_ROTATION.iter().map(|&(count, m)| json_case(count, m, coding)).collect();
    assert_zero(&format!("rotation {coding:?}"), &measure_plain(&cases, 300, 3000));
  }
}

/// `count` 1..=50 and `m` 1..=97 drawn from `seed`, as the validator draws them.
fn random_json(seed: u32, len: usize) -> Vec<(usize, i64)> {
  let mut seed = seed;
  let mut next = |modulo: u32| {
    seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    (seed >> 16) % modulo
  };
  (0..len).map(|_| (1 + next(50) as usize, 1 + i64::from(next(97)))).collect()
}

// Brotli over bodies of every size, on one connection: after a warm-up of the same draws, none
// asks for a block the thread's pool can't give.
#[test]
fn json_comp_br_random_sizes_allocate_nothing() {
  need_dataset();
  let cases: Vec<Case> = random_json(12_345, 400)
    .into_iter()
    .map(|(count, m)| json_case(count, m, Encoding::Brotli))
    .collect();
  assert_zero("random brotli", &measure_plain(&cases, 1000, 2000));
}

// On the thread itself: a sweep of every size (as a validator run leaves the pool), then the
// load's rotation finds its blocks, and the pool stays within its bound.
#[test]
fn brotli_pool_serves_the_rotation_after_a_sweep() {
  need_dataset();
  let counts = Counts::leak();
  let rotation: Vec<Vec<u8>> = JSON_ROTATION.iter().map(|&(count, m)| json(count, m)).collect();
  let sweep: Vec<Vec<u8>> =
    (1..=50).flat_map(|count| [1, 2, 5, 8, 13, 40, 97].map(|m| json(count, m))).collect();
  let mut out = Vec::new();
  COUNTS.set(Some(counts));
  for input in &sweep {
    encode(Encoding::Brotli, input, &mut out).unwrap();
  }
  let swept = BROTLI_FREE.with(|el| el.borrow().bytes);
  for _ in 0..10 {
    for input in &rotation {
      encode(Encoding::Brotli, input, &mut out).unwrap();
    }
  }
  let before = counts.snapshot();
  for _ in 0..100 {
    for input in &rotation {
      encode(Encoding::Brotli, input, &mut out).unwrap();
    }
  }
  let after = counts.snapshot();
  COUNTS.set(None);
  eprintln!("brotli pool after the sweep: {swept} bytes");
  assert!(swept <= BROTLI_POOL_MAX, "{swept}");
  assert_eq!(after.0 - before.0, 0, "allocations of 300 encodes, {} bytes", after.1 - before.1);
  assert_eq!(unbrotli(&out), rotation[2]);
}

// Connection churn: after a warm-up, a new connection is opened, sends a profile's requests and is
// closed, `CHURN_CONNS` times, one after the other. What the server's thread allocates for them is
// charged to an `Owner` by the backtrace of every allocation.
//
// Two cases. `Beside`: another connection stays open on the thread meanwhile, as under a load,
// where a thread serves many. `Alone`: the thread has no other connection, and drops to none
// between two of them, which is when the pools trim themselves: the driver's to a few sets, the
// executor's send pool to nothing. The driver's buffers go through that send pool (an owned send
// swaps the buffer sent for one of the pool's), so the executor's trim costs the core and the
// driver an allocation or a few per connection, which D3 owns: `Alone` is held to zero once D3
// keeps send buffers at idle (`connection_churn_alone_allocates_nothing`, ignored until then).

/// Connections opened before counting, so that the thread's pools have filled.
const CHURN_WARMUP: usize = 30;
/// Connections counted.
const CHURN_CONNS: usize = 100;

/// Owners a churn test lets allocate, per connection: D3's (the executor's task of the connection
/// and TLS state). D3 empties this, and every churn test then holds the whole connection to zero.
const CHURN_ALLOWED: &[Owner] = &[Owner::Executor, Owner::Tls];

/// Who an allocation is charged to: the innermost frame of its backtrace that belongs to one of
/// these. D2 owns the HTTP/1.1 core, the framework, its connection driver and the arena's code; D3
/// the executor (a connection's task, its timers and sockets) and TLS (a connection's session).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Owner {
  Core,
  Framework,
  Driver,
  App,
  Executor,
  Tls,
  /// None of the above: the site is the innermost frame outside the standard library.
  Other,
}

impl Owner {
  /// The owner of a frame of the function `path` (without its generics), if any.
  fn of_path(path: &str) -> Option<Self> {
    const OWNERS: [(&str, Owner); 6] = [
      ("rimu_ws::http1::", Owner::Core),
      ("rimu_ws::http::http1_server_framework::conn_driver::", Owner::Driver),
      ("rimu_ws::http::http1_server_framework::", Owner::Framework),
      ("rimu_ws::executor::", Owner::Executor),
      ("rimu_ws::tls::", Owner::Tls),
      ("arena_h1::", Owner::App),
    ];
    if path.starts_with("arena_h1::alloc_tests::") {
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
      // `<rimu_ws::tls::TlsStream<..> as ..>::read` is charged as `rimu_ws::tls::TlsStream`
      let name = name.trim_start_matches('<');
      let path = name.split(['<', ' ']).next().unwrap_or(name);
      let path = path.replace('>', "");
      let path = path.trim_end_matches(':');
      if let Some(owner) = Self::of_path(path) {
        return (owner, path.to_owned());
      }
      let ours = !["std::", "core::", "alloc::", "__rust", "arena_h1::alloc_tests::"]
        .iter()
        .any(|el| path.starts_with(el));
      if first.is_none() && ours {
        first = Some(path.to_owned());
      }
    }
    (Self::Other, first.unwrap_or_default())
  }
}

/// What a churn connection is asked to do.
enum Op<'a> {
  /// Sends the requests, if any, and returns the next response.
  Exchange(Option<&'a [u8]>),
  /// Ends the connection, and returns once the server closed its side.
  Close,
}

/// What a churn window allocated on the server's thread.
struct Churn {
  allocs: u64,
  bytes: u64,
  conns: usize,
  /// Allocations and bytes by owner and site.
  sites: BTreeMap<(Owner, String), (u64, u64)>,
}

impl Churn {
  /// Allocations and bytes by owner.
  fn owners(&self) -> BTreeMap<Owner, (u64, u64)> {
    let mut out = BTreeMap::new();
    for ((owner, _), (allocs, bytes)) in &self.sites {
      let elem = out.entry(*owner).or_insert((0, 0));
      elem.0 += allocs;
      elem.1 += bytes;
    }
    out
  }

  /// The allocations of the owners `CHURN_ALLOWED` does not let through.
  fn charged(&self) -> u64 {
    self.sites.iter().filter(|el| !CHURN_ALLOWED.contains(&el.0.0)).map(|el| el.1.0).sum()
  }

  /// Per connection, by owner, then every site.
  fn report(&self, name: &str) -> String {
    let conns = self.conns as f64;
    let mut out = format!(
      "{name}: {:.2} allocations, {:.0} bytes per connection ({} over {} connections)\n",
      self.allocs as f64 / conns,
      self.bytes as f64 / conns,
      self.allocs,
      self.conns
    );
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

/// What else the server's thread serves during a churn test.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Neighbor {
  /// Nothing.
  Alone,
  /// A connection that answered a request and stays open.
  Beside,
}

/// Sends `cases` on `conn`, every response checked.
fn send_cases<C>(conn: &mut C, cases: &[Case])
where
  C: FnMut(Op<'_>) -> Option<Response>,
{
  for case in cases {
    (case.check)(&conn(Op::Exchange(Some(&case.req))).unwrap());
    for _ in 1..case.responses {
      (case.check)(&conn(Op::Exchange(None)).unwrap());
    }
  }
}

/// `conns` connections from `open`, one after the other, each sending `cases` in turn and then
/// closing, after `warm` of them; every response checked, every allocation of the counted ones
/// charged to its owner.
fn measure_churn<C>(
  counts: &'static Counts,
  mut open: impl FnMut() -> C,
  cases: &[Case],
  neighbor: Neighbor,
  (warm, conns): (usize, usize),
) -> Churn
where
  C: FnMut(Op<'_>) -> Option<Response>,
{
  let mut kept = (neighbor == Neighbor::Beside).then(|| {
    let mut conn = open();
    send_cases(&mut conn, &cases[..1]);
    conn
  });
  let mut serve_one = || {
    let mut conn = open();
    send_cases(&mut conn, cases);
    let _ = conn(Op::Close);
  };
  for _ in 0..warm {
    serve_one();
  }
  // The symbols are loaded once here, not in the middle of a connection of the server
  let _ = std::backtrace::Backtrace::force_capture().to_string();
  counts.sites.lock().unwrap().clear();
  counts.trace.store(trace_budget(), Ordering::SeqCst);
  counts.tracing.store(true, Ordering::SeqCst);
  counts.classify.store(true, Ordering::SeqCst);
  let before = counts.snapshot();
  for _ in 0..conns {
    serve_one();
  }
  let after = counts.snapshot();
  counts.classify.store(false, Ordering::SeqCst);
  counts.tracing.store(false, Ordering::SeqCst);
  if let Some(conn) = &mut kept {
    let _ = conn(Op::Close);
  }
  let mut sites = BTreeMap::new();
  for (owner, site, bytes) in counts.sites.lock().unwrap().drain(..) {
    let elem = sites.entry((owner, site)).or_insert((0, 0));
    elem.0 += 1;
    elem.1 += bytes;
  }
  Churn { allocs: after.0 - before.0, bytes: after.1 - before.1, conns, sites }
}

/// Churn of `cases` on a new plaintext server. A connection half-closes, and waits for the
/// server to close it.
fn churn_plain(cases: &[Case], neighbor: Neighbor) -> Churn {
  let counts = Counts::leak();
  let addr = plain_server(counts);
  let open = || {
    let mut stream = std::net::TcpStream::connect(&addr).unwrap();
    stream.set_nodelay(true).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 256 * 1024];
    move |op: Op<'_>| match op {
      Op::Exchange(req) => {
        if let Some(elem) = req {
          std::io::Write::write_all(&mut stream, elem).unwrap();
        }
        loop {
          if let Some(elem) = take_response(&mut buf) {
            return Some(elem);
          }
          let len = std::io::Read::read(&mut stream, &mut chunk).unwrap();
          assert_ne!(len, 0, "the server closed the connection");
          buf.extend_from_slice(&chunk[..len]);
        }
      }
      Op::Close => {
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        while std::io::Read::read(&mut stream, &mut chunk).is_ok_and(|el| el > 0) {}
        None
      }
    }
  };
  measure_churn(counts, open, cases, neighbor, (CHURN_WARMUP, CHURN_CONNS))
}

/// Churn of `cases` on a new TLS server, `None` without the certificate pair. A connection sends
/// its close_notify, and waits for the server's.
fn churn_tls(cases: &[Case], neighbor: Neighbor) -> Option<Churn> {
  let counts = Counts::leak();
  let addr = tls_server(counts)?;
  let uri = rimu_ws::net::UriString::new(format!("https://{addr}"));
  let mut config = TlsConfig::unverified();
  config
    .alpn_mut()
    .get_or_insert_default()
    .protocol_name_list
    .push(b"http/1.1".as_slice().try_into().unwrap())
    .unwrap();
  let rt = StdRuntime::new();
  let mut rng = ChaCha20::from_std_random().unwrap();
  let open = || {
    let mut tls_stream = rt.block_on(async {
      for _ in 0..500 {
        if let Ok(elem) = TlsConnectorBuilder::std(uri.clone()).build(&config, &mut rng).await {
          return elem.connect().await.unwrap().tls_stream;
        }
        std::thread::sleep(Duration::from_millis(10));
      }
      panic!("the TLS server did not start");
    });
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 256 * 1024];
    let rt = &rt;
    move |op: Op<'_>| {
      rt.block_on(async {
        match op {
          Op::Exchange(req) => {
            if let Some(elem) = req {
              tls_stream.write_all(elem).await.unwrap();
            }
            loop {
              if let Some(elem) = take_response(&mut buf) {
                return Some(elem);
              }
              let len = tls_stream.read(chunk.as_mut_slice().into()).await.unwrap();
              let len = len.expect("the server closed the connection").get();
              buf.extend_from_slice(&chunk[..len]);
            }
          }
          Op::Close => {
            tls_stream.send_close_notify().await.unwrap();
            while let Ok(Some(_)) = tls_stream.read(chunk.as_mut_slice().into()).await {}
            None
          }
        }
      })
    }
  };
  Some(measure_churn(counts, open, cases, neighbor, (CHURN_WARMUP, CHURN_CONNS)))
}

/// The profiles of the churn tests: a name and the cases (see [`cases`]) a connection sends.
fn churn_profiles() -> Vec<(String, Vec<Case>)> {
  let profiles: [(&str, fn(&str) -> bool); 7] = [
    ("baseline", |el| el.starts_with("baseline ")),
    ("async", |el| el.starts_with("async ")),
    ("json-comp identity", |el| el.starts_with("json-comp ") && el.ends_with(" identity")),
    ("json-comp gzip", |el| el.starts_with("json-comp ") && el.ends_with(" gzip")),
    ("json-comp br", |el| el.starts_with("json-comp ") && el.ends_with(" br")),
    ("json-tls", |el| el.starts_with("json-tls ")),
    ("8gbit", |el| el.starts_with("8gbit ")),
  ];
  let mut out: Vec<(String, Vec<Case>)> =
    profiles.iter().map(|el| (el.0.into(), Vec::new())).collect();
  for case in cases() {
    if let Some(idx) = profiles.iter().position(|el| (el.1)(&case.name)) {
      out[idx].1.push(case);
    }
  }
  out.retain(|el| !el.1.is_empty());
  out
}

fn run_churn(name: &str, cases: &[Case], neighbor: Neighbor) -> Churn {
  if cases[0].tls {
    churn_tls(cases, neighbor)
      .unwrap_or_else(|| panic!("{name}: no certificate pair in {}: set CERT_DIR", cert_dir()))
  } else {
    churn_plain(cases, neighbor)
  }
}

/// Prints what a connection of every profile allocates, by owner, beside another connection and
/// alone: `cargo test ... --bin arena-h1 churn_table -- --ignored --nocapture --test-threads 1`.
#[test]
#[ignore = "prints a table"]
fn churn_table() {
  let filter = std::env::var("ALLOC_CASE").unwrap_or_default();
  for neighbor in [Neighbor::Beside, Neighbor::Alone] {
    println!("## {neighbor:?}\n");
    for (name, cases) in churn_profiles() {
      if name.contains(&filter) {
        println!("{}", run_churn(&name, &cases, neighbor).report(&name));
      }
    }
  }
}

/// Asserts that the connections of `profile` allocate nothing on the server's thread after the
/// warm-up, but for the owners in [`CHURN_ALLOWED`], whose share is printed.
fn assert_churn_free(profile: &str, neighbor: Neighbor) {
  let Some((name, cases)) = churn_profiles().into_iter().find(|el| el.0 == profile) else {
    panic!("no case of the profile {profile}");
  };
  let churn = run_churn(&name, &cases, neighbor);
  let report = churn.report(&format!("{name} ({neighbor:?})"));
  eprintln!("{report}");
  assert!(churn.allocs > 0 || churn.sites.is_empty());
  assert_eq!(
    churn.charged(),
    0,
    "allocations outside {CHURN_ALLOWED:?} after the warm-up:\n{report}"
  );
}

#[test]
fn baseline_connection_churn_allocates_nothing() {
  assert_churn_free("baseline", Neighbor::Beside);
}

#[test]
fn async_connection_churn_allocates_nothing() {
  assert_churn_free("async", Neighbor::Beside);
}

#[test]
fn json_comp_identity_connection_churn_allocates_nothing() {
  need_dataset();
  assert_churn_free("json-comp identity", Neighbor::Beside);
}

#[test]
fn json_comp_gzip_connection_churn_allocates_nothing() {
  need_dataset();
  assert_churn_free("json-comp gzip", Neighbor::Beside);
}

#[test]
fn json_comp_br_connection_churn_allocates_nothing() {
  need_dataset();
  assert_churn_free("json-comp br", Neighbor::Beside);
}

#[test]
fn json_tls_connection_churn_allocates_nothing() {
  need_dataset();
  assert_churn_free("json-tls", Neighbor::Beside);
}

#[test]
fn echo_tls_connection_churn_allocates_nothing() {
  assert_churn_free("8gbit", Neighbor::Beside);
}

// A thread with no other connection: see the comment above `CHURN_WARMUP`.
#[test]
#[ignore = "D3: the executor empties its send pool when its thread has no connection open"]
fn connection_churn_alone_allocates_nothing() {
  need_dataset();
  for (name, _) in churn_profiles() {
    assert_churn_free(&name, Neighbor::Alone);
  }
}
