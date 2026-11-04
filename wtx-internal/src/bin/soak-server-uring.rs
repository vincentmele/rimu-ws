//! The `rimu-ws-soak` target: an uncompressed echo server on `UringExecutor`, at
//! `127.0.0.1:9080`, with the executor's limits from the environment so the harness's oracles can
//! match them.
//!
//! `WTX_HANDSHAKE_MS` (default 2000), `WTX_IDLE_MS` (5000), `WTX_CLOSE_MS` (2000),
//! `WTX_RX_HIGH_WATER` (65536), `WTX_DIRECT` (0), `WTX_MAX_PAYLOAD` (1048576). A `0` timeout
//! turns it off. `WTX_LOG_ERRORS=1` prints connection errors, which hostile clients cause by the
//! thousand.

#![expect(clippy::print_stderr, reason = "internal")]

use rimu_ws::{
  collections::VectorUsize,
  executor::{UringExecutor, UringParams, UringRuntime, UringTcpStream},
  http::WebSocketServerFramework,
  rng::{ChaCha20, CryptoSeedableRng},
  tls::{PlaintextCtx, TlsConfig},
  web_socket::{Fill, OpCode, WebSocket, WebSocketPayloadOrigin},
};
use std::{sync::OnceLock, time::Duration};

static MAX_PAYLOAD: OnceLock<usize> = OnceLock::new();

fn env(name: &str, default: u64) -> u64 {
  std::env::var(name).ok().and_then(|el| el.parse().ok()).unwrap_or(default)
}

fn timeout(name: &str, default_ms: u64) -> Option<Duration> {
  Some(env(name, default_ms)).filter(|el| *el > 0).map(Duration::from_millis)
}

fn main() -> rimu_ws::Result<()> {
  let _ = MAX_PAYLOAD.set(usize::try_from(env("WTX_MAX_PAYLOAD", 1 << 20)).unwrap_or(1 << 20));
  let log_errors = env("WTX_LOG_ERRORS", 0) != 0;
  let params = UringParams::new()
    .set_close_timeout(timeout("WTX_CLOSE_MS", 2000))
    .set_direct_files(u32::try_from(env("WTX_DIRECT", 0)).unwrap_or(0))
    .set_handshake_timeout(timeout("WTX_HANDSHAKE_MS", 2000))
    .set_idle_timeout(timeout("WTX_IDLE_MS", 5000))
    .set_peer_addrs(false)
    .set_rx_high_water(usize::try_from(env("WTX_RX_HIGH_WATER", 65536)).unwrap_or(65536));
  let error_cb: fn(rimu_ws::Error) = if log_errors { |error| eprintln!("{error}") } else { |_| {} };
  WebSocketServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, ChaCha20, PlaintextCtx>::new(
    UringExecutor::default(),
    ChaCha20::from_std_random()?,
    TlsConfig::plaintext(),
  )?
  .set_error_cb(error_cb)
  .set_local_runtime_cb(move || UringRuntime::with_params(params))
  .run_in_threads("127.0.0.1:9080", (("/", echo),))
}

async fn echo(
  mut buffer: VectorUsize<u8>,
  mut ws: WebSocket<(), UringTcpStream, PlaintextCtx, false>,
) -> rimu_ws::Result<()> {
  *ws.max_payload_len_mut() = MAX_PAYLOAD.get().copied().unwrap_or(1 << 20);
  let (mut common, mut reader, mut writer) = ws.split_mut();
  let origin = WebSocketPayloadOrigin::Adaptive;
  loop {
    while let Some(mut frame) = reader.read_buffered_frame(&mut buffer, &common, origin)? {
      if !writer.queue_frame(&mut common, &mut frame)? {
        writer.write_frame_buffered(&mut common, &mut frame).await?;
      }
    }
    let _ = writer.try_flush(&mut common)?;
    match reader.fill(&mut common).await? {
      Fill::Buffered => continue,
      Fill::Closed => break,
      Fill::ReadFrame => {}
    }
    let mut frame = reader.read_frame(&mut buffer, &mut common, origin).await?;
    match frame.op_code() {
      OpCode::Binary | OpCode::Text => writer.write_frame_buffered(&mut common, &mut frame).await?,
      OpCode::Close => break,
      _ => {}
    }
  }
  Ok(())
}
