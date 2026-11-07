//! HttpArena HTTP/1.1 server: `GET|POST /baseline11?a=&b=` on plaintext 8080, served by the
//! HTTP/1.1 server framework on the io_uring executor.
//!
//! The runtimes do not spin: the latency profiles charge spin to the score.
//!
//! Environment: `ARENA_LOG_ERRORS` prints the errors the server reports to stderr.

use core::time::Duration;
use rimu_ws::{
  executor::{UringExecutor, UringParams, UringRuntime},
  http::{Http1Req, Http1Res, Http1Router, Http1ServerFramework, Method, StatusCode},
  net::TcpParams,
};

fn main() -> rimu_ws::Result<()> {
  let router = Http1Router::new()
    .route(Some(Method::Get), "/baseline11", endpoint_baseline11)
    .route(Some(Method::Post), "/baseline11", endpoint_baseline11);
  Http1ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _>::new(UringExecutor::default())?
    .set_error_cb(error_cb)
    // Every client speaks first
    .set_tcp_params(TcpParams::default().set_tcp_defer_accept(Some(1)))
    .set_local_runtime_cb(runtime)
    .run_in_threads("0.0.0.0:8080", router)
}

fn error_cb(err: rimu_ws::Error) {
  if std::env::var("ARENA_LOG_ERRORS").is_ok() {
    eprintln!("arena-h1: {err}");
  }
}

/// No spin: the latency profiles charge it to the score, and the rest measure level with it. The
/// peer address is not used by any handler.
fn runtime() -> rimu_ws::Result<UringRuntime> {
  UringRuntime::with_params(UringParams::new().set_peer_addrs(false).set_spin(Duration::ZERO))
}

/// `a + b`, plus the body of a POST. An empty or non-numeric body counts as zero, so the response
/// is always computed from this request alone.
fn baseline11_sum(a: i64, b: i64, body: Option<&[u8]>) -> i64 {
  let extra = body
    .and_then(|el| core::str::from_utf8(el).ok())
    .and_then(|el| el.trim().parse::<i64>().ok())
    .unwrap_or(0);
  a.wrapping_add(b).wrapping_add(extra)
}

/// Parses `a` and `b` from the query on every request, never from a cache.
fn endpoint_baseline11(_: &mut (), req: &Http1Req<'_>, res: &mut Http1Res) -> rimu_ws::Result<()> {
  let (mut a, mut b) = (0i64, 0i64);
  for pair in req.query().split('&') {
    match pair.split_once('=') {
      Some(("a", value)) => a = value.parse().unwrap_or(0),
      Some(("b", value)) => b = value.parse().unwrap_or(0),
      _ => {}
    }
  }
  let body = (req.method() == Method::Post).then(|| req.body());
  let sum = baseline11_sum(a, b, body);
  std::io::Write::write_fmt(res.body_mut(), format_args!("{sum}"))?;
  res.set_content_type("text/plain");
  res.set_status(StatusCode::Ok);
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn get_sums_the_query() {
    assert_eq!(baseline11_sum(13, 42, None), 55);
  }

  #[test]
  fn post_adds_the_body() {
    assert_eq!(baseline11_sum(13, 42, Some(b"20")), 75);
  }

  #[test]
  fn random_values_sum() {
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
      seed ^= seed << 13;
      seed ^= seed >> 7;
      seed ^= seed << 17;
      100 + i64::try_from(seed % 900).unwrap()
    };
    for _ in 0..100 {
      let (a, b, c) = (next(), next(), next());
      assert_eq!(baseline11_sum(a, b, None), a + b);
      assert_eq!(baseline11_sum(a, b, Some(c.to_string().as_bytes())), a + b + c);
    }
  }
}
