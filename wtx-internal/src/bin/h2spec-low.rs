//! h2spec target for manual streams: the HTTP/2 server framework on io_uring, port 9000, with one
//! manual-mode endpoint, for any method, that reads the request body and answers through its
//! stream. (A GET-only route would answer h2spec's POSTs before their bodies arrive, so the
//! body checks would never run on a manual stream.)
//! `H2SPEC_TLS=1` serves TLS with the repository's test certificate; `H2SPEC_TLS=user` does too,
//! with the records sealed in user space instead of by the kernel.

#![expect(clippy::print_stderr, reason = "internal")]

use rimu_ws::{
  collections::{ArrayVectorCopy, VectorUsize},
  executor::UringExecutor,
  futures::FnFut as _,
  http::{
    AutoStream, Headers, HttpRecvParams, ManualStream, OperationMode, StatusCode,
    http2_server_framework::{Endpoint, EndpointNode, Http2ServerFramework, HttpRouter, RouteMatch},
  },
  http2::{Http2RecvStatus, ServerStream},
  rng::{ChaCha20, CryptoSeedableRng as _},
  tls::TlsConfig,
};

const PUBLIC_KEY: &[u8] = include_bytes!("../../../.certs/cert.pem");
const SECRET_KEY: &[u8] = include_bytes!("../../../.certs/key.pem");

fn main() -> rimu_ws::Result<()> {
  let tls = std::env::var("H2SPEC_TLS").ok().filter(|el| el == "1" || el == "user");
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
      .run_in_threads("127.0.0.1:9000", HttpRouter::paths(rimu_ws::paths!(("/", AnyMethod(hello.into_wrapper()))))?)
    };
  }
  if let Some(mode) = tls {
    let mut tls_config = TlsConfig::from_keys_pem(PUBLIC_KEY, SECRET_KEY)?;
    *tls_config.kernel_tls_mut() = mode != "user";
    run!(tls_config)
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

/// An endpoint for every method.
struct AnyMethod<T>(T);

impl<D, E, S, T> Endpoint<D, E, S> for AnyMethod<T>
where
  E: From<rimu_ws::Error>,
  T: Endpoint<D, E, S>,
{
  const OM: OperationMode = T::OM;

  async fn auto(
    &self,
    auto_stream: &mut AutoStream<D>,
    path_defs: (u8, &[RouteMatch]),
  ) -> Result<StatusCode, E> {
    self.0.auto(auto_stream, path_defs).await
  }

  async fn manual(&self, manual_stream: ManualStream<D, S>, path_defs: (u8, &[RouteMatch])) -> Result<(), E> {
    self.0.manual(manual_stream, path_defs).await
  }
}

impl<D, E, S, T> EndpointNode<D, E, S> for AnyMethod<T>
where
  E: From<rimu_ws::Error>,
  T: Endpoint<D, E, S>,
{
  const IS_ROUTER: bool = false;

  fn paths_indices(
    &self,
    _: ArrayVectorCopy<RouteMatch, 4>,
    _: &mut VectorUsize<ArrayVectorCopy<RouteMatch, 4>>,
  ) -> rimu_ws::Result<()> {
    Ok(())
  }
}
