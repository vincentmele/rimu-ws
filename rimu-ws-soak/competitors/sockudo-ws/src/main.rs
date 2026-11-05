//! sockudo-ws 3.1.0 (35933d7) in the soak's comparison: an echo server on `0.0.0.0:8080`, path
//! `/`, through `WebSocketServer::accept`, with the production settings in CONFIG.md. sockudo-ws
//! has no handshake timeout.

use futures_util::{SinkExt, StreamExt};
use sockudo_ws::{Config, protocol::Message, server::WebSocketServer};
use tokio::net::TcpListener;

const MAX_MESSAGE: usize = 1 << 20;

#[tokio::main]
async fn main() {
  let mut config = Config::default();
  config.max_message_size = MAX_MESSAGE;
  config.max_frame_size = MAX_MESSAGE;
  config.idle_timeout = 300;
  config.max_backpressure = 256 * 1024;
  let server = WebSocketServer::new(config);
  let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
  loop {
    let Ok((stream, _)) = listener.accept().await else { continue };
    let _ = stream.set_nodelay(true);
    let server = server.clone();
    tokio::spawn(async move {
      let Ok((mut ws, _)) = server.accept(stream).await else { return };
      while let Some(Ok(msg)) = ws.next().await {
        match msg {
          Message::Text(_) | Message::Binary(_) => {
            if ws.send(msg).await.is_err() {
              return;
            }
          }
          Message::Close(_) => break,
          // Pongs are answered by the stream.
          _ => {}
        }
      }
    });
  }
}
