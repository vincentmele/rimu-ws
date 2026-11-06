//! h2load target: the HTTP/2 server framework on io_uring, port 9000, permissive limits.

use rimu_ws::{
  executor::UringExecutor,
  http::{
    HttpRecvParams,
    http2_server_framework::{Http2ServerFramework, HttpRouter, get},
  },
  rng::{ChaCha20, CryptoSeedableRng as _},
  tls::TlsConfig,
};

fn main() -> rimu_ws::Result<()> {
  let router = HttpRouter::paths(rimu_ws::paths!(("/", get(root)),))?;
  Http2ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new(
    UringExecutor::default(),
    ChaCha20::from_std_random()?,
    TlsConfig::plaintext(),
  )?
  .set_http_recv_params(HttpRecvParams::with_permissive_params())
  .run_in_threads("127.0.0.1:9000", router)
}

async fn root() -> rimu_ws::Result<()> {
  Ok(())
}
