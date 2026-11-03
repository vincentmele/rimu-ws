//! Autobahn fuzzing-client target for the draining echo path on `UringExecutor`. Set
//! `WTX_DIRECT=<slots>` to accept into direct descriptors.

#![expect(clippy::print_stderr, reason = "internal")]

use wtx::{
  collections::VectorUsize,
  executor::{UringExecutor, UringParams, UringRuntime, UringTcpStream},
  http::WebSocketServerFramework,
  rng::{ChaCha20, CryptoSeedableRng},
  tls::{PlaintextCtx, TlsConfig},
  web_socket::{
    OpCode, WebSocket, WebSocketPayloadOrigin,
    web_socket_compression::{NegotiatedZlibRs, ZlibRs},
  },
};

fn main() -> wtx::Result<()> {
  let direct = std::env::var("WTX_DIRECT").ok().and_then(|el| el.parse().ok()).unwrap_or(0);
  WebSocketServerFramework::<
    (),
    fn(wtx::Error),
    UringExecutor,
    fn() -> wtx::Result<UringRuntime>,
    ChaCha20,
    PlaintextCtx,
  >::new(UringExecutor::default(), ChaCha20::from_std_random()?, TlsConfig::plaintext())?
  .set_compression(ZlibRs::default())
  .set_error_cb(|error: wtx::Error| eprintln!("{error}"))
  .set_local_runtime_cb(move || {
    UringRuntime::with_params(UringParams::new().set_direct_files(direct))
  })
  .run_in_threads("127.0.0.1:9070", (("/", echo),))
}

async fn echo(
  mut buffer: VectorUsize<u8>,
  mut ws: WebSocket<Option<NegotiatedZlibRs>, UringTcpStream, PlaintextCtx, false>,
) -> wtx::Result<()> {
  let (mut common, mut reader, mut writer) = ws.split_mut();
  let origin = WebSocketPayloadOrigin::Adaptive;
  loop {
    while let Some(mut frame) = reader.read_buffered_frame(&mut buffer, &common, origin)? {
      if !writer.try_write_frame_buffered(&mut common, &mut frame)? {
        writer.write_frame_buffered(&mut common, &mut frame).await?;
      }
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
