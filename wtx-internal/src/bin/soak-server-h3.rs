//! The `rimu-ws-soak h3` target: the HTTP/3 server framework on UDP, dual-stack, with the library's
//! default QUIC and HTTP/3 limits (the limits task 23 soaks). One process per server: the worker
//! count is the CPUs the process is pinned to (`taskset -c 0-3` → 4 workers; `taskset -c 4` → 1), so
//! the per-worker caps can be driven on a one-worker server.
//!
//! - `GET /baseline2` answers `ok`;
//! - `POST /echo` answers the request body;
//! - `GET /mem` answers the net live heap bytes of the worker thread that serves it (the counting
//!   allocator below, opt-in with `SOAK_H3_ALLOC_STATS=1`), so the soak can measure per-connection
//!   memory in the server (ruling T23-j #3 / N3). On a one-worker server every connection is on the
//!   one worker thread, so its counter is the whole server's live heap;
//! - `GET /stats` answers `workers=N conns=a,b,...`, the per-worker open connections (handshakes
//!   under way included), the ground truth for the per-worker cap;
//! - `GET /static/{*file}` serves `$SOAK_STATIC_DIR` (default
//!   `/mnt/nvme1tb/claude-tmp/soak/h3-static`), filled at start with `small.txt` (1 KiB) and
//!   `big.bin` (10 MiB) for the slow-reader scenario.
//!
//! Environment: `SOAK_H3_ADDR` (default `[::]:8443`, dual-stack), `CERT_DIR` (default
//! `/mnt/nvme1tb/claude-tmp/arena-main/certs`, with `server.crt` and `server.key`),
//! `SOAK_STATIC_DIR`, `SOAK_H3_ALLOC_STATS=1` to count net live heap bytes per worker thread,
//! `WTX_LOG_ERRORS=1` to print connection errors.

#![expect(clippy::print_stderr, reason = "internal")]
#![allow(clippy::disallowed_methods, reason = "an internal soak server")]
#![allow(clippy::disallowed_types, reason = "an internal soak server")]

use core::{
  alloc::{GlobalAlloc, Layout},
  cell::Cell,
  sync::atomic::{AtomicBool, Ordering},
};
use rimu_ws::{
  executor::{UringExecutor, UringParams, UringRuntime},
  http::{
    MsgDataMut as _, StatusCode,
    http2_server_framework::{Get, HttpRouter, State, StaticFiles, VerbatimParams, get, post},
    http3_server_framework::{Http3ServerFramework, Http3Stats},
  },
  rng::{ChaCha20, CryptoSeedableRng as _},
  tls::TlsConfig,
};
use std::{alloc::System, sync::OnceLock};

/// The framework's per-worker counters, for `GET /stats` (ground truth for the per-worker cap).
static STATS: OnceLock<Http3Stats> = OnceLock::new();

// ---- a counting global allocator (the arena-h2 `alloc_tests_h3` net-live technique, N3)

/// Whether the allocator tracks net live bytes. Off unless `SOAK_H3_ALLOC_STATS=1`, so an ordinary
/// soak pays nothing.
static ALLOC_STATS: AtomicBool = AtomicBool::new(false);

std::thread_local! {
  /// The net live heap bytes of this thread: the sizes of its allocations minus its deallocations.
  /// `const` so first use allocates nothing (no re-entrancy in the allocator).
  static LIVE: Cell<i64> = const { Cell::new(0) };
}

struct CountingAlloc;

impl CountingAlloc {
  fn add(delta: i64) {
    if ALLOC_STATS.load(Ordering::Relaxed) {
      let _ = LIVE.try_with(|cell| cell.set(cell.get().wrapping_add(delta)));
    }
  }
}

// SAFETY: every path forwards to the system allocator with the same layout; the counters only read
// and write thread-local and atomic state and never touch the returned memory.
unsafe impl GlobalAlloc for CountingAlloc {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    // SAFETY: the caller's contract is forwarded unchanged to the system allocator.
    let ptr = unsafe { System.alloc(layout) };
    if !ptr.is_null() {
      Self::add(layout.size() as i64);
    }
    ptr
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
    Self::add(-(layout.size() as i64));
    // SAFETY: forwarded unchanged.
    unsafe { System.dealloc(ptr, layout) }
  }

  unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
    // SAFETY: forwarded unchanged.
    let ptr = unsafe { System.alloc_zeroed(layout) };
    if !ptr.is_null() {
      Self::add(layout.size() as i64);
    }
    ptr
  }

  unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    // SAFETY: forwarded unchanged.
    let out = unsafe { System.realloc(ptr, layout, new_size) };
    if !out.is_null() {
      Self::add((new_size as i64).wrapping_sub(layout.size() as i64));
    }
    out
  }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

fn env(name: &str, default: &str) -> String {
  std::env::var(name).unwrap_or_else(|_| default.into())
}

fn main() -> rimu_ws::Result<()> {
  if std::env::var("SOAK_H3_ALLOC_STATS").is_ok_and(|el| el == "1") {
    ALLOC_STATS.store(true, Ordering::Relaxed);
  }
  let addr = env("SOAK_H3_ADDR", "[::]:8443");
  let cert_dir = env("CERT_DIR", "/mnt/nvme1tb/claude-tmp/arena-main/certs");
  let dir = env("SOAK_STATIC_DIR", "/mnt/nvme1tb/claude-tmp/soak/h3-static");
  std::fs::create_dir_all(&dir)?;
  std::fs::write(format!("{dir}/small.txt"), static_bytes(1024))?;
  std::fs::write(format!("{dir}/big.bin"), static_bytes(10 << 20))?;
  let cert = std::fs::read(format!("{cert_dir}/server.crt"))?;
  let key = std::fs::read(format!("{cert_dir}/server.key"))?;
  let log_errors = std::env::var("WTX_LOG_ERRORS").is_ok_and(|el| el == "1");
  let error_cb: fn(rimu_ws::Error) =
    if log_errors { |error| eprintln!("soak-server-h3: {error}") } else { |_| {} };
  eprintln!(
    "soak-server-h3: {addr}, static {dir}, cert {cert_dir}, alloc_stats {}",
    ALLOC_STATS.load(Ordering::Relaxed)
  );
  let framework = Http3ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new(
    UringExecutor::default(),
    ChaCha20::from_std_random()?,
    TlsConfig::from_keys_pem(&cert, key.as_slice())?,
  )?
  .set_error_cb(error_cb)
  .set_pin_workers(false)
  .set_local_runtime_cb(|| {
    UringRuntime::with_params(UringParams::default().set_recv_buffers(4, 4096))
  });
  let _ = STATS.set(framework.stats());
  framework.run_in_threads(
    &addr,
    HttpRouter::paths(rimu_ws::paths!(
      ("/baseline2", get(baseline2)),
      ("/mem", get(mem)),
      ("/stats", get(stats)),
      ("/echo", post(echo)),
      ("/static/{*file}", Get(StaticFiles::new(dir)?)),
    ))?,
  )
}

/// The bytes of a static file of `len`: byte `i` is `i % 251`.
fn static_bytes(len: usize) -> Vec<u8> {
  (0..len).map(|el| (el % 251) as u8).collect()
}

async fn baseline2(state: State<'_, ()>) -> rimu_ws::Result<VerbatimParams> {
  state.req.msg_data.clear();
  state.req.msg_data.body.extend_from_copyable_slice(b"ok")?;
  Ok(VerbatimParams(StatusCode::Ok))
}

/// The net live heap bytes of the worker thread serving this request, as decimal text.
async fn mem(state: State<'_, ()>) -> rimu_ws::Result<VerbatimParams> {
  let live = LIVE.try_with(Cell::get).unwrap_or(0);
  state.req.msg_data.clear();
  state.req.msg_data.body.extend_from_copyable_slice(live.to_string().as_bytes())?;
  Ok(VerbatimParams(StatusCode::Ok))
}

/// The worker count and each worker's open connections (handshakes under way included), as
/// `workers=N conns=a,b,...`.
async fn stats(state: State<'_, ()>) -> rimu_ws::Result<VerbatimParams> {
  let workers = STATS.get().map(Http3Stats::workers).unwrap_or_default();
  let conns: Vec<String> = workers.iter().map(|el| el.conns.to_string()).collect();
  let text = format!("workers={} conns={}", workers.len(), conns.join(","));
  state.req.msg_data.clear();
  state.req.msg_data.body.extend_from_copyable_slice(text.as_bytes())?;
  Ok(VerbatimParams(StatusCode::Ok))
}

async fn echo(state: State<'_, ()>) -> rimu_ws::Result<VerbatimParams> {
  state.req.msg_data.headers.clear();
  Ok(VerbatimParams(StatusCode::Ok))
}
