//! Autobahn fuzzing-client target for the draining echo path on `UringExecutor`, echoing buffered
//! frames with `queue_frame` and waiting with `fill`: uncompressed connections queue every buffered
//! frame, and on compressed ones both decline, so the awaited path is exercised too. Set
//! `WTX_DIRECT=<slots>` to accept into direct descriptors.

#![expect(clippy::print_stderr, reason = "internal")]

use rimu_ws::{
  collections::VectorUsize,
  executor::{UringExecutor, UringParams, UringRuntime, UringTcpStream},
  http::WebSocketServerFramework,
  rng::{ChaCha20, CryptoSeedableRng},
  tls::{PlaintextCtx, TlsConfig},
  web_socket::{
    Fill, OpCode, WebSocket, WebSocketPayloadOrigin,
    web_socket_compression::{NegotiatedZlibRs, ZlibRs},
  },
};

fn main() -> rimu_ws::Result<()> {
  let direct = std::env::var("WTX_DIRECT").ok().and_then(|el| el.parse().ok()).unwrap_or(0);
  WebSocketServerFramework::<
    (),
    fn(rimu_ws::Error),
    UringExecutor,
    fn() -> rimu_ws::Result<UringRuntime>,
    ChaCha20,
    PlaintextCtx,
  >::new(UringExecutor::default(), ChaCha20::from_std_random()?, TlsConfig::plaintext())?
  .set_compression(ZlibRs::default())
  .set_error_cb(|error: rimu_ws::Error| eprintln!("{error}"))
  .set_local_runtime_cb(move || {
    UringRuntime::with_params(UringParams::new().set_direct_files(direct))
  })
  .run_in_threads("127.0.0.1:9070", (("/", echo),))
}

async fn echo(
  mut buffer: VectorUsize<u8>,
  mut ws: WebSocket<Option<NegotiatedZlibRs>, UringTcpStream, PlaintextCtx, false>,
) -> rimu_ws::Result<()> {
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
