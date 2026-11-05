//! rimu-ws in the soak's comparison: an echo server on the settings rimu-ws documents for
//! production (`docs/production-settings.md`), written as a user would write it. It listens on
//! `0.0.0.0:8080`, path `/`.

use rimu_ws::{
  collections::VectorUsize,
  executor::{UringExecutor, UringParams, UringRuntime, UringTcpStream},
  http::WebSocketServerFramework,
  rng::{ChaCha20, CryptoSeedableRng},
  tls::{PlaintextCtx, TlsConfig},
  web_socket::{OpCode, WebSocket, WebSocketPayloadOrigin},
};
use std::time::Duration;

/// The largest message: the library's default is 64 MiB.
const MAX_MESSAGE: usize = 1 << 20;

fn main() -> rimu_ws::Result<()> {
  let params = UringParams::new()
    .set_handshake_timeout(Some(Duration::from_secs(10)))
    .set_idle_timeout(Some(Duration::from_secs(300)))
    .set_tx_high_water(256 * 1024);
  WebSocketServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, ChaCha20, PlaintextCtx>::new(
    UringExecutor::default(),
    ChaCha20::from_std_random()?,
    TlsConfig::plaintext(),
  )?
  .set_error_cb(|_| {})
  // The runtime bounds handshakes itself (`UringParams::set_handshake_timeout`).
  .set_handshake_timeout(None)
  .set_local_runtime_cb(move || UringRuntime::with_params(params))
  .run_in_threads("0.0.0.0:8080", (("/", echo),))
}

async fn echo(
  mut buffer: VectorUsize<u8>,
  mut ws: WebSocket<(), UringTcpStream, PlaintextCtx, false>,
) -> rimu_ws::Result<()> {
  *ws.max_payload_len_mut() = MAX_MESSAGE;
  let (mut common, mut reader, mut writer) = ws.split_mut();
  loop {
    let origin = WebSocketPayloadOrigin::Adaptive;
    let mut frame = reader.read_frame(&mut buffer, &mut common, origin).await?;
    match frame.op_code() {
      OpCode::Binary | OpCode::Text => writer.write_frame(&mut common, &mut frame).await?,
      OpCode::Close => return Ok(()),
      _ => {}
    }
  }
}
