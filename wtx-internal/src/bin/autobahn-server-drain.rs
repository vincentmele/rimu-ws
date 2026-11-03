//! Autobahn fuzzing-client target for the queued, draining echo path on tokio: frames that arrive
//! together are echoed without an `await` each and written in one go.

#![expect(clippy::print_stderr, reason = "internal")]

use tokio::net::TcpStream;
use wtx::{
  collections::VectorUsize,
  http::WebSocketServerFramework,
  tls::{PlaintextCtx, TlsConfig},
  web_socket::{
    OpCode, WebSocket, WebSocketPayloadOrigin,
    web_socket_compression::{NegotiatedZlibRs, ZlibRs},
  },
};

#[tokio::main]
async fn main() -> wtx::Result<()> {
  WebSocketServerFramework::tokio(TlsConfig::plaintext())?
    .set_compression(ZlibRs::default())
    .set_error_cb(|error| eprintln!("{error}"))
    .run("127.0.0.1:9070", (("/", echo),))
    .await
}

async fn echo(
  mut buffer: VectorUsize<u8>,
  mut ws: WebSocket<Option<NegotiatedZlibRs>, TcpStream, PlaintextCtx, false>,
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
