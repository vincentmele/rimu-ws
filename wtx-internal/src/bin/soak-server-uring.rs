//! The `rimu-ws-soak` target: an echo server on `UringExecutor`, at `127.0.0.1:9080`, with the
//! executor's limits from the environment so the harness's oracles can match them.
//!
//! `WTX_HANDSHAKE_MS` (default 2000), `WTX_IDLE_MS` (5000), `WTX_CLOSE_MS` (2000),
//! `WTX_RX_HIGH_WATER` (65536), `WTX_DIRECT` (0). A `0` timeout turns it off. The loop,
//! compression, send buffer, message limit and error logging are in `common/soak_echo.rs`.

#![expect(clippy::print_stderr, reason = "internal")]

#[path = "common/soak_echo.rs"]
mod soak_echo;

use rimu_ws::{
  collections::VectorUsize,
  executor::{UringExecutor, UringParams, UringRuntime, UringTcpStream},
  http::WebSocketServerFramework,
  rng::{ChaCha20, CryptoSeedableRng},
  tls::{PlaintextCtx, TlsConfig},
  web_socket::{
    WebSocket,
    web_socket_compression::{NegotiatedZlibRs, ZlibRs},
  },
};
use soak_echo::{env, settings, tcp_params};
use std::time::Duration;

fn timeout(name: &str, default_ms: u64) -> Option<Duration> {
  Some(env(name, default_ms)).filter(|el| *el > 0).map(Duration::from_millis)
}

fn main() -> rimu_ws::Result<()> {
  let settings = settings();
  eprintln!("soak-server-uring: {settings:?}");
  let params = UringParams::new()
    .set_close_timeout(timeout("WTX_CLOSE_MS", 2000))
    .set_direct_files(u32::try_from(env("WTX_DIRECT", 0)).unwrap_or(0))
    .set_handshake_timeout(timeout("WTX_HANDSHAKE_MS", 2000))
    .set_idle_timeout(timeout("WTX_IDLE_MS", 5000))
    .set_peer_addrs(false)
    .set_rx_high_water(usize::try_from(env("WTX_RX_HIGH_WATER", 65536)).unwrap_or(65536));
  let error_cb: fn(rimu_ws::Error) =
    if settings.log_errors { |error| eprintln!("{error}") } else { |_| {} };
  let framework =
    WebSocketServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, ChaCha20, PlaintextCtx>::new(
      UringExecutor::default(),
      ChaCha20::from_std_random()?,
      TlsConfig::plaintext(),
    )?
    .set_error_cb(error_cb)
    .set_local_runtime_cb(move || UringRuntime::with_params(params))
    .set_tcp_params(tcp_params());
  if settings.deflate {
    framework.set_compression(ZlibRs::default()).run_in_threads("127.0.0.1:9080", (("/", echo_deflate),))
  } else {
    framework.run_in_threads("127.0.0.1:9080", (("/", echo),))
  }
}

async fn echo(
  buffer: VectorUsize<u8>,
  ws: WebSocket<(), UringTcpStream, PlaintextCtx, false>,
) -> rimu_ws::Result<()> {
  soak_echo::echo(buffer, ws).await
}

async fn echo_deflate(
  buffer: VectorUsize<u8>,
  ws: WebSocket<Option<NegotiatedZlibRs>, UringTcpStream, PlaintextCtx, false>,
) -> rimu_ws::Result<()> {
  soak_echo::echo(buffer, ws).await
}
