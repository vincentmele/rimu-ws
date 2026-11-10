//! The `rimu-ws-soak h3` target: the HTTP/3 server framework on UDP, dual-stack, with the library's
//! default QUIC and HTTP/3 limits (the limits task 23 soaks). One process per server: the worker
//! count is the CPUs the process is pinned to (`taskset -c 0-3` → 4 workers; `taskset -c 4` → 1), so
//! the per-worker caps can be driven on a one-worker server.
//!
//! - `GET /baseline2` answers `ok`;
//! - `POST /echo` answers the request body;
//! - `GET /static/{*file}` serves `$SOAK_STATIC_DIR` (default
//!   `/mnt/nvme1tb/claude-tmp/soak/h3-static`), filled at start with `small.txt` (1 KiB) and
//!   `big.bin` (10 MiB) for the slow-reader scenario.
//!
//! Environment: `SOAK_H3_ADDR` (default `[::]:8443`, dual-stack), `CERT_DIR` (default
//! `/mnt/nvme1tb/claude-tmp/arena-main/certs`, with `server.crt` and `server.key`),
//! `SOAK_STATIC_DIR`, `WTX_LOG_ERRORS=1` to print connection errors.

#![expect(clippy::print_stderr, reason = "internal")]

use rimu_ws::{
  executor::{UringExecutor, UringParams, UringRuntime},
  http::{
    MsgDataMut as _, StatusCode,
    http2_server_framework::{Get, HttpRouter, State, StaticFiles, VerbatimParams, get, post},
    http3_server_framework::Http3ServerFramework,
  },
  rng::{ChaCha20, CryptoSeedableRng as _},
  tls::TlsConfig,
};

fn env(name: &str, default: &str) -> String {
  std::env::var(name).unwrap_or_else(|_| default.into())
}

fn main() -> rimu_ws::Result<()> {
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
  eprintln!("soak-server-h3: {addr}, static {dir}, cert {cert_dir}");
  Http3ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new(
    UringExecutor::default(),
    ChaCha20::from_std_random()?,
    TlsConfig::from_keys_pem(&cert, key.as_slice())?,
  )?
  .set_error_cb(error_cb)
  .set_pin_workers(false)
  .set_local_runtime_cb(|| {
    UringRuntime::with_params(UringParams::default().set_recv_buffers(4, 4096))
  })
  .run_in_threads(
    &addr,
    HttpRouter::paths(rimu_ws::paths!(
      ("/baseline2", get(baseline2)),
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

async fn echo(state: State<'_, ()>) -> rimu_ws::Result<VerbatimParams> {
  state.req.msg_data.headers.clear();
  Ok(VerbatimParams(StatusCode::Ok))
}
