//! A low-level HTTP/2 server: one manual-mode endpoint that drives its stream itself, reading the
//! request body and answering with a teapot.
//!
//! The server runs on io_uring. For a router of ordinary endpoints, see the
//! `http2-server-framework` examples.

extern crate rimu_ws;
extern crate rimu_ws_examples;

use rimu_ws::{
  collections::VectorUsize,
  executor::UringExecutor,
  http::{
    Headers, ManualStream, StatusCode,
    http2_server_framework::{Http2ServerFramework, HttpRouter, get},
  },
  http2::{Http2RecvStatus, ServerStream},
  rng::{ChaCha20, CryptoSeedableRng},
  tls::TlsConfig,
};
use rimu_ws_examples::{PUBLIC_KEY, SECRET_KEY, host_from_args};

fn main() -> rimu_ws::Result<()> {
  let router = HttpRouter::paths(rimu_ws::paths!(("/", get(teapot))))?;
  Http2ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new(
    UringExecutor::default(),
    ChaCha20::from_std_random()?,
    TlsConfig::from_keys_pem(PUBLIC_KEY, SECRET_KEY)?,
  )?
  .set_error_cb(|err| eprintln!("Error: {err}"))
  .run_in_threads(&host_from_args(), router)
}

async fn teapot(mut manual_stream: ManualStream<(), ServerStream>) -> rimu_ws::Result<()> {
  println!("An arbitrary request has been received: {:#?}", manual_stream.req);
  let mut body = VectorUsize::new();
  loop {
    match manual_stream.stream.recv_data(&mut body).await? {
      Http2RecvStatus::Ongoing(()) => {}
      Http2RecvStatus::Eos(()) => break,
      Http2RecvStatus::ClosedConnection | Http2RecvStatus::ClosedStream(()) => return Ok(()),
    }
  }
  println!("With a body of {} bytes", body.len());
  let stream = &mut manual_stream.stream;
  let _ = stream.send_headers(&Headers::new(), false, StatusCode::ImATeapot).await?;
  let _ = stream.send_data(b"By tea, for tea\n", true).await?;
  Ok(())
}
