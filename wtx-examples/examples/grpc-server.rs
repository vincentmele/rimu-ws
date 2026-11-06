//! gRPC server that uses the structure definitions found in the `wtx_instances::grpc_bindings`
//! module.

extern crate tokio;
extern crate rimu_ws;
extern crate rimu_ws_examples;

use std::borrow::Cow;
use rimu_ws::{
  codec::format::QuickProtobuf,
  executor::UringExecutor,
  grpc::{GrpcManager, GrpcMiddleware},
  http::{
    StatusCode,
    http2_server_framework::{Http2ServerFramework, HttpRouter, State, post},
  },
  rng::{ChaCha20, CryptoSeedableRng},
  tls::TlsConfig,
};
use rimu_ws_examples::{
  PUBLIC_KEY, SECRET_KEY,
  grpc_bindings::wtx::{GenericRequest, GenericResponse},
  host_from_args,
};

fn main() -> rimu_ws::Result<()> {
  let rng = ChaCha20::from_std_random()?;
  let tls_config = TlsConfig::from_keys_pem(PUBLIC_KEY, SECRET_KEY)?;
  let router = HttpRouter::new(
    rimu_ws::paths!(("/wtx.GenericService/generic_method", post(wtx_generic_service_generic_method))),
    GrpcMiddleware,
  )?;
  Http2ServerFramework::new(UringExecutor::default(), rng, tls_config)?
    .set_data(GrpcManager::from_drsr(QuickProtobuf))
    .set_error_cb(|err| eprintln!("Error: {err}"))
    .run_in_threads(&host_from_args(), router)
}

async fn wtx_generic_service_generic_method(
  State { data, req }: State<'_, GrpcManager<QuickProtobuf>>,
) -> rimu_ws::Result<StatusCode> {
  let _generic_request: GenericRequest = data.des_from_req_bytes(&req.msg_data.body)?;
  req.clear();
  data.ser_to_res_bytes(
    &mut req.msg_data.body,
    GenericResponse {
      generic_response_field0: Cow::Borrowed(b"generic_response_value"),
      generic_response_field1: 321,
    },
  )?;
  Ok(StatusCode::Ok)
}
