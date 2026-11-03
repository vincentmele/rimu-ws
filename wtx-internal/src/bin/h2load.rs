//! h2load

use rimu_ws::{
  http::{
    HttpRecvParams,
    http2_server_framework::{Http2ServerFramework, HttpRouter, get},
  },
  tls::TlsConfig,
};

#[tokio::main]
async fn main() -> rimu_ws::Result<()> {
  let router = HttpRouter::paths(rimu_ws::paths!(("/", get(root)),))?;
  Http2ServerFramework::tokio(TlsConfig::plaintext())?
    .set_http_recv_params(HttpRecvParams::with_permissive_params())
    .set_error_cb(|err| println!("Error: {err}"))
    .run("127.0.0.1:9000", router)
    .await
}

async fn root() -> rimu_ws::Result<()> {
  Ok(())
}
