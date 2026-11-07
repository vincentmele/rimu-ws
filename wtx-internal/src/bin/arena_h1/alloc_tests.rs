//! Steady-state allocation tests of the arena-h1 servers: after a warm-up, a keep-alive
//! connection's requests allocate nothing on the server's runtime thread.
//!
//! A counting global allocator counts the allocations of the threads that were told to (the
//! runtime thread of each test server, from its local-runtime callback), each server in its own
//! counters, so the clients and the tests running alongside are not counted.
//!
//! `ALLOC_TRACE=n` prints the backtraces of the first `n` allocations of every measured window,
//! to find where they come from. `alloc_table` (ignored) prints the allocations of every path.

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

/// Requests sent before counting, so that every buffer has reached its size.
const WARMUP: usize = 200;
/// Requests counted.
const MEASURED: usize = 1000;
const CERT_DIR: &str = "/mnt/nvme1tb/claude-tmp/arena-main/certs";
const DATASET_FILE: &str = "/mnt/nvme1tb/claude-tmp/arena-main/data/dataset.json";

/// The allocations of one server's runtime thread.
struct Counts {
  allocs: AtomicU64,
  bytes: AtomicU64,
  /// Backtraces left to print, while a window is measured.
  trace: AtomicU64,
  tracing: AtomicBool,
}

impl Counts {
  fn leak() -> &'static Self {
    Box::leak(Box::new(Self {
      allocs: AtomicU64::new(0),
      bytes: AtomicU64::new(0),
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

/// A one-runtime TLS arena server whose runtime thread is counted; returns its address.
fn tls_server(counts: &'static Counts) -> Option<String> {
  let cert = std::fs::read(format!("{CERT_DIR}/server.crt")).ok()?;
  let key = std::fs::read(format!("{CERT_DIR}/server.key")).ok()?;
  let addr = free_addr();
  let server_addr = addr.clone();
  let _jh = std::thread::spawn(move || {
    serve_tls(&server_addr, NonZeroUsize::new(1), &cert, &key, counted_runtime(counts))
  });
  Some(addr)
}

/// The end of a response's head, its status and its `Content-Length`, once `buf` holds the head.
fn parse_head(buf: &[u8]) -> Option<(usize, u16, usize)> {
  let end = buf.windows(4).position(|el| el == b"\r\n\r\n")? + 4;
  let head = core::str::from_utf8(&buf[..end]).unwrap().to_ascii_lowercase();
  let status = head.get(9..12).unwrap().parse().unwrap();
  let len = head
    .lines()
    .find_map(|el| el.strip_prefix("content-length:"))
    .map_or(0, |el| el.trim().parse().unwrap());
  Some((end, status, len))
}

/// One response read off `buf` once it is complete: its status and body; `buf` keeps what follows.
fn take_response(buf: &mut Vec<u8>) -> Option<(u16, Vec<u8>)> {
  let (end, status, len) = parse_head(buf)?;
  if buf.len() < end + len {
    return None;
  }
  let body = buf[end..end + len].to_vec();
  let _ = buf.drain(..end + len);
  Some((status, body))
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

/// What a measured path allocated per request on the server's thread.
#[derive(Debug)]
struct Measured {
  allocs: u64,
  bytes: u64,
  /// Requests measured: [`MEASURED`], or more for pipelined batches.
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

/// Sends the requests of `case` [`WARMUP`] times and then [`MEASURED`] times on one keep-alive
/// connection, by `exchange` (which sends them and returns the next response), checking every
/// response, and counts what the server allocated over the measured requests.
fn measure(
  counts: &'static Counts,
  mut exchange: impl FnMut(Option<&[u8]>) -> (u16, Vec<u8>),
  case: &Case,
) -> Measured {
  let mut round = || {
    let (status, body) = exchange(Some(&case.req));
    (case.check)(status, &body);
    for _ in 1..case.responses {
      let (status, body) = exchange(None);
      (case.check)(status, &body);
    }
  };
  for _ in 0..WARMUP.div_ceil(case.responses) {
    round();
  }
  let rounds = MEASURED.div_ceil(case.responses);
  counts.trace.store(trace_budget(), Ordering::SeqCst);
  counts.tracing.store(true, Ordering::SeqCst);
  let before = counts.snapshot();
  for _ in 0..rounds {
    round();
  }
  let after = counts.snapshot();
  counts.tracing.store(false, Ordering::SeqCst);
  Measured {
    allocs: after.0 - before.0,
    bytes: after.1 - before.1,
    requests: rounds * case.responses,
    total: after.0,
  }
}

/// Measures `case` on a new plaintext server.
fn measure_plain(case: &Case) -> Measured {
  let counts = Counts::leak();
  let addr = plain_server(counts);
  let mut stream = std::net::TcpStream::connect(&addr).unwrap();
  stream.set_nodelay(true).unwrap();
  stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
  let mut buf = Vec::new();
  let mut chunk = vec![0u8; 256 * 1024];
  measure(
    counts,
    |req| {
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
    },
    case,
  )
}

/// Measures `case` on a new TLS server, `None` without the certificate.
fn measure_tls(case: &Case) -> Option<Measured> {
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
  Some(measure(
    counts,
    |req| {
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
    },
    case,
  ))
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
  check: Box<dyn Fn(u16, &[u8])>,
  name: String,
  /// The requests, sent at once.
  req: Vec<u8>,
  /// How many requests `req` holds.
  responses: usize,
  tls: bool,
}

impl Case {
  fn new(name: impl Into<String>, tls: bool, req: Vec<u8>, check: Box<dyn Fn(u16, &[u8])>) -> Self {
    Self { check, name: name.into(), req, responses: 1, tls }
  }
}

/// `/json/{count}?m={m}` with `accept` as `Accept-Encoding`, on the plaintext server.
fn json_case(count: usize, m: i64, accept: Option<&str>) -> Case {
  let mut head = format!("GET /json/{count}?m={m} HTTP/1.1\r\nhost: x\r\n");
  if let Some(elem) = accept {
    head.push_str(&format!("accept-encoding: {elem}\r\n"));
  }
  let expected = json(count, m);
  let decode: fn(&[u8]) -> Vec<u8> = match accept {
    Some("gzip") => ungzip,
    Some("br") => unbrotli,
    _ => <[u8]>::to_vec,
  };
  let check = move |status: u16, body: &[u8]| {
    assert_eq!(status, 200);
    assert_eq!(decode(body), expected);
  };
  let name = format!("json-comp /json/{count}?m={m} {}", accept.unwrap_or("identity"));
  Case::new(name, false, request(&head, None), Box::new(check))
}

/// The paths measured.
fn cases() -> Vec<Case> {
  let mut out = Vec::new();
  let base = "POST /baseline11?a=1&b=2 HTTP/1.1\r\nhost: x\r\n";
  let sum = |expected: &'static [u8]| -> Box<dyn Fn(u16, &[u8])> {
    Box::new(move |status, body| {
      assert_eq!(status, 200);
      assert_eq!(body, expected);
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
    for (count, m) in [(25, 4), (40, 8), (50, 6)] {
      for accept in [None, Some("gzip"), Some("br")] {
        out.push(json_case(count, m, accept));
      }
    }
    let mut tls = json_case(25, 4, None);
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
      let check: Box<dyn Fn(u16, &[u8])> = Box::new(move |status, got| {
        assert_eq!(status, 200);
        assert_eq!(got, body.as_slice());
      });
      out.push(Case::new(name, true, req, check));
    }
  }
  out
}

fn run_case(case: &Case) -> Option<Measured> {
  if case.tls { measure_tls(case) } else { Some(measure_plain(case)) }
}

/// Prints the allocations per request of every path:
/// `cargo test ... --bin arena-h1 alloc_table -- --ignored --nocapture --test-threads 1`.
#[test]
#[ignore = "prints a table"]
fn alloc_table() {
  println!("| path | allocs/req | bytes/req | thread total |\n|---|---|---|---|");
  let filter = std::env::var("ALLOC_CASE").unwrap_or_default();
  for case in cases() {
    let name = &case.name;
    if !name.contains(&filter) {
      continue;
    }
    let Some(measured) = run_case(&case) else {
      println!("| {name} | skipped (no certificate) | | |");
      continue;
    };
    let (allocs, bytes) = measured.per_req();
    println!("| {name} | {allocs:.3} | {bytes:.1} | {} |", measured.total);
  }
}

/// Asserts that every path whose name starts with `prefix` allocates nothing on the server's
/// thread over [`MEASURED`] requests after the warm-up.
fn assert_no_alloc(prefix: &str) {
  let mut ran = 0;
  let mut failed = Vec::new();
  for case in cases() {
    let name = &case.name;
    if !name.starts_with(prefix) {
      continue;
    }
    let Some(measured) = run_case(&case) else {
      eprintln!("{name}: skipped, no certificate in {CERT_DIR}");
      continue;
    };
    ran += 1;
    if measured.allocs != 0 {
      failed.push(format!(
        "{name}: {} allocations, {} bytes over {} requests",
        measured.allocs, measured.bytes, measured.requests
      ));
    }
  }
  assert!(failed.is_empty(), "allocations after the warm-up:\n{}", failed.join("\n"));
  eprintln!("{prefix}: {ran} paths allocate nothing");
}

// baseline, limited-conn, latency-1m/10k: GET, and POST with a Content-Length and a chunked body.
#[test]
fn baseline_steady_state_allocates_nothing() {
  assert_no_alloc("baseline ");
}

#[test]
fn async_delay_steady_state_allocates_nothing() {
  assert_no_alloc("async ");
}

#[test]
fn json_comp_identity_steady_state_allocates_nothing() {
  assert_no_alloc_json("identity");
}

#[test]
fn json_comp_gzip_steady_state_allocates_nothing() {
  assert_no_alloc_json("gzip");
}

#[test]
fn json_comp_br_steady_state_allocates_nothing() {
  assert_no_alloc_json("br");
}

/// [`assert_no_alloc`] for the json-comp paths of one coding; skipped without the dataset.
fn assert_no_alloc_json(coding: &str) {
  if !load_test_dataset() {
    eprintln!("skipped: no dataset");
    return;
  }
  let mut failed = Vec::new();
  for case in cases() {
    let name = &case.name;
    if !name.starts_with("json-comp ") || !name.ends_with(&format!(" {coding}")) {
      continue;
    }
    let measured = run_case(&case).unwrap();
    if measured.allocs != 0 {
      failed.push(format!(
        "{name}: {} allocations, {} bytes over {} requests",
        measured.allocs, measured.bytes, measured.requests
      ));
    }
  }
  assert!(failed.is_empty(), "allocations after the warm-up:\n{}", failed.join("\n"));
}

#[test]
fn json_tls_steady_state_allocates_nothing() {
  assert_no_alloc("json-tls ");
}

// 8gbit: 1 B, 10 KiB and 100 KiB bodies, with a Content-Length and chunked.
#[test]
fn echo_tls_steady_state_allocates_nothing() {
  assert_no_alloc("8gbit ");
}
