//! fastwebsockets 0.10.0 in the soak's comparison: an echo server on `0.0.0.0:8080`, path `/`, as
//! its `echo_server` example (hyper upgrade, `FragmentCollector`) on a multi-thread runtime, with
//! the production settings in CONFIG.md. The handshake timeout is hyper's header read timeout;
//! fastwebsockets has no idle timeout and no write-buffer limit.

use fastwebsockets::{FragmentCollector, OpCode, WebSocketError, upgrade};
use http_body_util::Empty;
use hyper::{
  Request, Response, StatusCode,
  body::{Bytes, Incoming},
  server::conn::http1,
  service::service_fn,
};
use hyper_util::rt::TokioTimer;
use std::time::Duration;
use tokio::net::TcpListener;

const MAX_MESSAGE: usize = 1 << 20;

async fn handle_client(fut: upgrade::UpgradeFut) -> Result<(), WebSocketError> {
  let mut ws = fut.await?;
  ws.set_max_message_size(MAX_MESSAGE);
  let mut ws = FragmentCollector::new(ws);
  loop {
    let frame = ws.read_frame().await?;
    match frame.opcode {
      OpCode::Close => break,
      OpCode::Text | OpCode::Binary => ws.write_frame(frame).await?,
      _ => {}
    }
  }
  Ok(())
}

#[tokio::main]
async fn main() {
  let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
  loop {
    let Ok((stream, _)) = listener.accept().await else { continue };
    let _ = stream.set_nodelay(true);
    tokio::spawn(async move {
      let io = hyper_util::rt::TokioIo::new(stream);
      let service = service_fn(|mut req: Request<Incoming>| async move {
        // The documented check before upgrading.
        if !upgrade::is_upgrade_request(&req) {
          let mut res = Response::new(Empty::new());
          *res.status_mut() = StatusCode::BAD_REQUEST;
          return Ok::<Response<Empty<Bytes>>, WebSocketError>(res);
        }
        let (response, fut) = upgrade::upgrade(&mut req)?;
        tokio::spawn(async move {
          let _ = handle_client(fut).await;
        });
        Ok(response)
      });
      let _ = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .serve_connection(io, service)
        .with_upgrades()
        .await;
    });
  }
}
