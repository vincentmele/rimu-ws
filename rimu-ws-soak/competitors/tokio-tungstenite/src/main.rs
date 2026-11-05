//! tokio-tungstenite 0.30 in the soak's comparison: an echo server on `0.0.0.0:8080`, path `/`,
//! with the production settings in CONFIG.md. tokio-tungstenite has no handshake or idle timeout.

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::{Message, protocol::WebSocketConfig};

const MAX_MESSAGE: usize = 1 << 20;
/// tungstenite's default `write_buffer_size`.
const WRITE_BUFFER: usize = 128 * 1024;

#[tokio::main]
async fn main() {
  // The docs ask for `max_write_buffer_size` of at least `write_buffer_size` plus one message.
  let config = WebSocketConfig::default()
    .max_message_size(Some(MAX_MESSAGE))
    .max_frame_size(Some(MAX_MESSAGE))
    .write_buffer_size(WRITE_BUFFER)
    .max_write_buffer_size(WRITE_BUFFER + MAX_MESSAGE + 256 * 1024);
  let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
  loop {
    let Ok((stream, _)) = listener.accept().await else { continue };
    let _ = stream.set_nodelay(true);
    tokio::spawn(async move {
      let Ok(mut ws) = tokio_tungstenite::accept_async_with_config(stream, Some(config)).await else {
        return;
      };
      while let Some(Ok(msg)) = ws.next().await {
        match msg {
          Message::Text(_) | Message::Binary(_) => {
            if ws.send(msg).await.is_err() {
              return;
            }
          }
          // tungstenite answers pings and closes itself; reading on until the stream ends sends
          // the close reply (the documented pattern).
          _ => {}
        }
      }
    });
  }
}
