//! h2spec target for manual streams: the HTTP/2 server framework on io_uring, port 9000, with one
//! manual-mode endpoint that reads the request body and answers through its stream.
//! `H2SPEC_TLS=1` serves TLS with the repository's test certificate.

#![expect(clippy::print_stderr, reason = "internal")]

use rimu_ws::{
  collections::VectorUsize,
  executor::UringExecutor,
  http::{
    Headers, HttpRecvParams, ManualStream, StatusCode,
    http2_server_framework::{Http2ServerFramework, HttpRouter, get},
  },
  http2::{Http2RecvStatus, ServerStream},
  rng::{ChaCha20, CryptoSeedableRng as _},
  tls::TlsConfig,
};

const PUBLIC_KEY: &[u8] = include_bytes!("../../../.certs/cert.pem");
const SECRET_KEY: &[u8] = include_bytes!("../../../.certs/key.pem");

fn main() -> rimu_ws::Result<()> {
  let tls = std::env::var("H2SPEC_TLS").is_ok_and(|el| el == "1");
  macro_rules! run {
    ($tls_config:expr) => {
      Http2ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new(
        UringExecutor::default(),
        ChaCha20::from_std_random()?,
        $tls_config,
      )?
      .set_error_cb((|err: rimu_ws::Error| eprintln!("{err}")) as fn(rimu_ws::Error))
      .set_http_recv_params(HttpRecvParams::with_default_params())
      .set_local_runtimes(core::num::NonZeroUsize::new(1))
      .run_in_threads("127.0.0.1:9000", HttpRouter::paths(rimu_ws::paths!(("/", get(hello))))?)
    };
  }
  if tls {
    run!(TlsConfig::from_keys_pem(PUBLIC_KEY, SECRET_KEY)?)
  } else {
    run!(TlsConfig::plaintext())
  }
}

async fn hello(mut ms: ManualStream<(), ServerStream>) -> rimu_ws::Result<()> {
  let mut body = VectorUsize::new();
  loop {
    match ms.stream.recv_data(&mut body).await? {
      Http2RecvStatus::Ongoing(()) => body.clear(),
      Http2RecvStatus::Eos(()) => break,
      Http2RecvStatus::ClosedConnection | Http2RecvStatus::ClosedStream(()) => return Ok(()),
    }
  }
  let _ = ms.stream.send_headers(&Headers::new(), false, StatusCode::Ok).await?;
  let _ = ms.stream.send_data(b"Hello", true).await?;
  Ok(())
}
