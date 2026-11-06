//! h2spec target: the HTTP/2 server framework on io_uring, port 9000. `H2SPEC_TLS=1` serves TLS
//! with the repository's test certificate; `H2SPEC_TLS=user` does too, with the records sealed in
//! user space instead of by the kernel.

#![expect(clippy::print_stderr, reason = "internal")]

use rimu_ws::{
  executor::UringExecutor,
  http::{
    HttpRecvParams, StatusCode,
    http2_server_framework::{Http2ServerFramework, HttpRouter, StateClean, VerbatimParams, get},
  },
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
      .run_in_threads(
        "127.0.0.1:9000",
        HttpRouter::paths(rimu_ws::paths!(("/", get(hello))))?,
      )
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

async fn hello(state: StateClean<'_, ()>) -> rimu_ws::Result<VerbatimParams> {
  state.req.msg_data.body.extend_from_copyable_slice(b"Hello")?;
  Ok(VerbatimParams(StatusCode::Ok))
}
