//! The `rimu-ws-soak --proto h2` target: the HTTP/2 server framework on `UringExecutor`, plaintext,
//! at `127.0.0.1:9081`, with the framework's default HTTP/2 settings.
//!
//! - `GET /baseline2` answers `ok`;
//! - `POST /echo` answers the request body;
//! - `GET /static/{*file}` serves `$SOAK_STATIC_DIR` (default
//!   `/mnt/nvme1tb/claude-tmp/soak/h2-static`), filled at start with `small.txt` (1 KiB) and
//!   `big.bin` (10 MiB).
//!
//! The runtime's limits come from the environment, as for `soak-server-uring`, so the harness's
//! oracles can match them: `WTX_HANDSHAKE_MS` (default 2000, also the framework's handshake
//! timeout), `WTX_IDLE_MS` (5000, also the framework's idle timeout), `WTX_CLOSE_MS` (2000). A
//! `0` timeout turns it off. `WTX_LOG_ERRORS=1` prints connection errors.

#![expect(clippy::print_stderr, reason = "internal")]

use rimu_ws::{
  executor::{UringExecutor, UringParams, UringRuntime},
  http::{
    MsgDataMut as _, StatusCode,
    http2_server_framework::{
      Get, Http2ServerFramework, HttpRouter, State, StaticFiles, VerbatimParams, get, post,
    },
  },
  rng::{ChaCha20, CryptoSeedableRng},
  tls::TlsConfig,
};
use std::time::Duration;

fn env(name: &str, default: u64) -> u64 {
  std::env::var(name).ok().and_then(|el| el.parse().ok()).unwrap_or(default)
}

fn timeout(name: &str, default_ms: u64) -> Option<Duration> {
  Some(env(name, default_ms)).filter(|el| *el > 0).map(Duration::from_millis)
}

fn main() -> rimu_ws::Result<()> {
  let dir = std::env::var("SOAK_STATIC_DIR")
    .unwrap_or_else(|_| "/mnt/nvme1tb/claude-tmp/soak/h2-static".into());
  std::fs::create_dir_all(&dir)?;
  std::fs::write(format!("{dir}/small.txt"), static_bytes(1024))?;
  std::fs::write(format!("{dir}/big.bin"), static_bytes(10 << 20))?;
  let handshake = timeout("WTX_HANDSHAKE_MS", 2000);
  let idle = timeout("WTX_IDLE_MS", 5000);
  let params = UringParams::new()
    .set_close_timeout(timeout("WTX_CLOSE_MS", 2000))
    .set_handshake_timeout(handshake)
    .set_idle_timeout(idle)
    .set_peer_addrs(false);
  let error_cb: fn(rimu_ws::Error) =
    if env("WTX_LOG_ERRORS", 0) == 1 { |error| eprintln!("{error}") } else { |_| {} };
  eprintln!("soak-server-h2: handshake {handshake:?}, idle {idle:?}, static {dir}");
  Http2ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new(
    UringExecutor::default(),
    ChaCha20::from_std_random()?,
    TlsConfig::plaintext(),
  )?
  .set_error_cb(error_cb)
  .set_handshake_timeout(handshake)
  .set_idle_timeout(idle)
  .set_local_runtime_cb(move || UringRuntime::with_params(params))
  .run_in_threads(
    "127.0.0.1:9081",
    HttpRouter::paths(rimu_ws::paths!(
      ("/baseline2", get(baseline2)),
      ("/echo", post(echo)),
      ("/static/{*file}", Get(StaticFiles::new(dir)?)),
    ))?,
  )
}

/// The bytes of a static file of `len`: byte `i` is `i % 251`, so a prefix can be checked.
fn static_bytes(len: usize) -> Vec<u8> {
  (0..len).map(|el| (el % 251) as u8).collect()
}

async fn baseline2(state: State<'_, ()>) -> rimu_ws::Result<VerbatimParams> {
  state.req.msg_data.clear();
  state.req.msg_data.body.extend_from_copyable_slice(b"ok")?;
  Ok(VerbatimParams(StatusCode::Ok))
}

/// The request body goes back as the response's.
async fn echo(state: State<'_, ()>) -> rimu_ws::Result<VerbatimParams> {
  state.req.msg_data.headers.clear();
  Ok(VerbatimParams(StatusCode::Ok))
}
