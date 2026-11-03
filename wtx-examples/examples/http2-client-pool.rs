//! Fetches and prints the response body of a provided URI.

extern crate tokio;
extern crate rimu_ws;

use rimu_ws::{
  collections::VectorUsize,
  http::{HttpClient, ReqBuilder, http2_client_pool::Http2ClientPoolBuilder},
  misc::from_utf8_basic,
  net::Uri,
  tls::TlsConfig,
};

#[tokio::main]
async fn main() -> rimu_ws::Result<()> {
  let uri = Uri::new("https://github.com/c410-f3r/wtx");
  let res = Http2ClientPoolBuilder::tokio(1, TlsConfig::from_ccadb()?)?
    .build()
    .send_req_recv_res(&mut VectorUsize::new(), ReqBuilder::get(uri.to_ref()).into_request())
    .await?;
  println!("{}", from_utf8_basic(&res.msg_data.body)?);
  Ok(())
}
