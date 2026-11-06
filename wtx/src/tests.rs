use crate::net::UriString;
use alloc::string::String;
use std::sync::OnceLock;
use rimu_ws::misc::EnvVars;

pub(crate) static _PUBLIC_KEY: &[u8] = include_bytes!("../../.certs/cert.pem");
pub(crate) static _SECRET_KEY: &[u8] = include_bytes!("../../.certs/key.pem");
pub(crate) static _ROOT_CA: &[u8] = include_bytes!("../../.certs/root-ca.crt");

#[allow(unused, reason = "depends on feature")]
#[derive(Debug, rimu_ws::FromVars)]
pub(crate) struct Vars {
  pub(crate) wtx_database_uri_postgres: String,
}

pub(crate) fn _uri() -> UriString {
  // A port the kernel reports free: fixed ranges collide with other services on the machine and
  // with the previous run's connections in TIME_WAIT.
  let port = std::net::TcpListener::bind("127.0.0.1:0")
    .and_then(|el| el.local_addr())
    .map(|el| el.port())
    .unwrap_or(0);
  UriString::new(alloc::format!("http://127.0.0.1:{port}"))
}

pub(crate) fn _vars() -> &'static Vars {
  static VARS: OnceLock<Vars> = OnceLock::new();
  VARS.get_or_init(|| EnvVars::from_available([]).unwrap().finish())
}
