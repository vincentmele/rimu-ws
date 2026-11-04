//! The `rimu-ws-soak` target on tokio, at `127.0.0.1:9080`. Tokio has none of the uring
//! executor's handshake, idle or close timeouts, so run it with the `untimed` profile. The loop,
//! compression, send buffer, message limit and error logging are in `common/soak_echo.rs`.

#![expect(clippy::print_stderr, reason = "internal")]

#[path = "common/soak_echo.rs"]
mod soak_echo;

use rimu_ws::{
  collections::VectorUsize,
  http::WebSocketServerFramework,
  tls::{PlaintextCtx, TlsConfig},
  web_socket::{
    WebSocket,
    web_socket_compression::{NegotiatedZlibRs, ZlibRs},
  },
};
use soak_echo::{settings, tcp_params};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> rimu_ws::Result<()> {
  let settings = settings();
  eprintln!("soak-server-tokio: {settings:?}");
  let error_cb: fn(rimu_ws::Error) =
    if settings.log_errors { |error| eprintln!("{error}") } else { |_| {} };
  let framework = WebSocketServerFramework::tokio(TlsConfig::plaintext())?
    .set_error_cb(error_cb)
    .set_tcp_params(tcp_params());
  if settings.deflate {
    framework.set_compression(ZlibRs::default()).run("127.0.0.1:9080", (("/", echo_deflate),)).await
  } else {
    framework.run("127.0.0.1:9080", (("/", echo),)).await
  }
}

async fn echo(
  buffer: VectorUsize<u8>,
  ws: WebSocket<(), TcpStream, PlaintextCtx, false>,
) -> rimu_ws::Result<()> {
  soak_echo::echo(buffer, ws).await
}

async fn echo_deflate(
  buffer: VectorUsize<u8>,
  ws: WebSocket<Option<NegotiatedZlibRs>, TcpStream, PlaintextCtx, false>,
) -> rimu_ws::Result<()> {
  soak_echo::echo(buffer, ws).await
}
