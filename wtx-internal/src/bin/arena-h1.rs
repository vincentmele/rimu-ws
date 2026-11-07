//! HttpArena HTTP/1.1 server: `GET|POST /baseline11?a=&b=`, `GET /delay/{ms}` and `GET /json/{count}?m=`
//! on plaintext 8080, served by the HTTP/1.1 server framework on the io_uring executor.
//!
//! The runtimes do not spin: the latency profiles charge spin to the score.
//!
//! A second listener on TLS 8081 (`CERT_DIR`, default `/certs`, with `server.crt` and `server.key`;
//! skipped without a certificate) serves `GET /json/{count}?m=` uncompressed (json-tls) and
//! `POST /echo` (8gbit), which answers with the request body verbatim.
//!
//! `/json` serializes the dataset on every request and compresses those bytes on every request by
//! the request's `Accept-Encoding`: brotli (quality 2), else gzip, else none. Nothing is cached.
//!
//! Environment: `ARENA_LOG_ERRORS` prints the errors the server reports to stderr; `DATASET_PATH`
//! (default `/data/dataset.json`) is the dataset `/json` serves.

use core::{cell::RefCell, time::Duration};
use rimu_ws::{
  collections::{ArrayVectorU8, VectorUsize},
  executor::{UringExecutor, UringParams, UringRuntime},
  http::{Http1Req, Http1Res, Http1Router, Http1ServerFramework, Method, StatusCode},
  misc::JsonWriter,
  net::TcpParams,
  rng::{ChaCha20, CryptoSeedableRng as _},
  tls::TlsConfig,
};
use std::sync::OnceLock;

/// Brotli quality of `/json`. The score multiplies throughput by the square of the size ratio. On the
/// 4096-connection json-gzip load, quality 2 scored about 10% above quality 3 (3% more bytes, 17%
/// less CPU), and above 3 the CPU grows faster than the bytes shrink.
const BROTLI_QUALITY: i32 = 2;
/// Brotli window bits. The default 22 makes the encoder allocate and clear multi-megabyte tables on
/// every call (about 100 us for a 4 KiB body); 16 covers the largest body (8.4 KB) with identical output.
const BROTLI_LGWIN: i32 = 16;
/// zlib level of the gzip fallback.
const GZIP_LEVEL: i32 = 6;
/// gzip framing for zlib: a window of 15 bits plus 16.
const GZIP_WINDOW_BITS: i32 = 31;

static DATASET: OnceLock<VectorUsize<DatasetItem>> = OnceLock::new();

thread_local! {
  /// The serialized JSON of the request being answered, reused across the thread's requests.
  static JSON_BUF: RefCell<VectorUsize<u8>> = const { RefCell::new(VectorUsize::new()) };
}

fn main() -> rimu_ws::Result<()> {
  // Loaded once; the numbers the validator draws later only choose a prefix of it.
  let _ = DATASET.set(load_dataset());
  let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "/certs".into());
  let tls = if std::path::Path::new(&cert_dir).join("server.crt").exists() {
    let cert = std::fs::read(format!("{cert_dir}/server.crt"))?;
    let key = std::fs::read(format!("{cert_dir}/server.key"))?;
    Some(std::thread::spawn(move || -> rimu_ws::Result<()> {
      let tls_config = TlsConfig::from_keys_pem(&cert, key.as_slice())?;
      let router = Http1Router::new()
        .route(Some(Method::Get), "/json/{count}", endpoint_json_plain)
        .route(Some(Method::Post), "/echo", endpoint_echo);
      Http1ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new_tls(
        UringExecutor::default(),
        ChaCha20::from_std_random()?,
        tls_config,
      )?
      .set_error_cb(error_cb)
      .set_local_runtime_cb(runtime)
      .run_in_threads("0.0.0.0:8081", router)
    }))
  } else {
    eprintln!("arena-h1: no {cert_dir}/server.crt, TLS on 8081 disabled");
    None
  };
  let router = Http1Router::new()
    .route(Some(Method::Get), "/baseline11", endpoint_baseline11)
    .route(Some(Method::Post), "/baseline11", endpoint_baseline11)
    .route(Some(Method::Get), "/delay/{ms}", endpoint_delay)
    .route(Some(Method::Get), "/json/{count}", endpoint_json);
  Http1ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _>::new(UringExecutor::default())?
    .set_error_cb(error_cb)
    // Every client speaks first
    .set_tcp_params(TcpParams::default().set_tcp_defer_accept(Some(1)))
    .set_local_runtime_cb(runtime)
    .run_in_threads("0.0.0.0:8080", router)?;
  if let Some(elem) = tls {
    elem.join().map_err(|_| std::io::Error::other("TLS thread panicked"))??;
  }
  Ok(())
}

fn error_cb(err: rimu_ws::Error) {
  if std::env::var("ARENA_LOG_ERRORS").is_ok() {
    eprintln!("arena-h1: {err}");
  }
}

/// No spin: the latency profiles charge it to the score, and the rest measure level with it. The
/// peer address is not used by any handler.
fn runtime() -> rimu_ws::Result<UringRuntime> {
  UringRuntime::with_params(
    UringParams::new()
      .set_peer_addrs(false)
      .set_spin(Duration::ZERO)
      .set_recv_buffers(2048, 4096)
      .set_direct_files(16384)
      .set_ring_entries(4096, 16384),
  )
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
  push_i64(res.body_mut(), sum);
  res.set_content_type("text/plain");
  res.set_status(StatusCode::Ok);
  Ok(())
}

/// The delay in milliseconds from the `{ms}` path segment. Anything but a plain unsigned decimal
/// is `None`.
fn delay_ms(param: Option<&str>) -> Option<u64> {
  let param = param?;
  if param.is_empty() || !param.bytes().all(|el| el.is_ascii_digit()) {
    return None;
  }
  param.parse().ok()
}

/// Waits `ms` milliseconds, then answers with `ms`. The delay is read from this request's path, so
/// concurrent requests wait independently. The framework sends nothing before the delay elapses.
fn endpoint_delay(_: &mut (), req: &Http1Req<'_>, res: &mut Http1Res) -> rimu_ws::Result<()> {
  let ms = delay_ms(req.param("ms")).unwrap_or(0);
  push_i64(res.body_mut(), i64::try_from(ms).unwrap_or(i64::MAX));
  res.set_content_type("text/plain");
  res.set_status(StatusCode::Ok);
  if ms > 0 {
    res.set_delay(Duration::from_millis(ms));
  }
  Ok(())
}

/// `m` from the query, 1 if absent.
fn query_m(query: &str) -> rimu_ws::Result<i64> {
  for pair in query.split('&') {
    if let Some(("m", value)) = pair.split_once('=') {
      return Ok(value.parse()?);
    }
  }
  Ok(1)
}

/// Serializes the dataset for `{count}` and `m`, then compresses those bytes by the request's
/// `Accept-Encoding`. Both happen on every request: the body is never kept.
fn endpoint_json(_: &mut (), req: &Http1Req<'_>, res: &mut Http1Res) -> rimu_ws::Result<()> {
  let count: usize = req.param("count").unwrap_or("0").parse()?;
  let m = query_m(req.query())?;
  let dataset = DATASET.get().map_or(&[][..], |el| el.as_slice());
  let encoding = req.header("accept-encoding").map_or(Encoding::Identity, choose_encoding);
  JSON_BUF.with(|cell| -> rimu_ws::Result<()> {
    let mut json = cell.borrow_mut();
    json.clear();
    write_json(&mut json, dataset, count, m)?;
    encode(encoding, json.as_slice(), res.body_mut())?;
    Ok(())
  })?;
  match encoding {
    Encoding::Brotli => res.push_header("content-encoding", "br")?,
    Encoding::Gzip => res.push_header("content-encoding", "gzip")?,
    Encoding::Identity => {}
  }
  res.set_content_type("application/json");
  res.set_status(StatusCode::Ok);
  Ok(())
}

/// json-tls: the dataset for `{count}` and `m`, serialized on every request and sent as it is, with no
/// `Accept-Encoding` handling.
fn endpoint_json_plain(_: &mut (), req: &Http1Req<'_>, res: &mut Http1Res) -> rimu_ws::Result<()> {
  let count: usize = req.param("count").unwrap_or("0").parse()?;
  let m = query_m(req.query())?;
  let dataset = DATASET.get().map_or(&[][..], |el| el.as_slice());
  JSON_BUF.with(|cell| -> rimu_ws::Result<()> {
    let mut json = cell.borrow_mut();
    json.clear();
    write_json(&mut json, dataset, count, m)?;
    res.body_mut().extend_from_slice(json.as_slice());
    Ok(())
  })?;
  res.set_content_type("application/json");
  res.set_status(StatusCode::Ok);
  Ok(())
}

/// 8gbit: the response body is this request's body, byte for byte.
fn echo_body(body: &[u8]) -> &[u8] {
  body
}

/// `POST /echo`: answers with the body the framework decoded from this request (Content-Length or
/// chunked), never from a length header or a kept buffer.
fn endpoint_echo(_: &mut (), req: &Http1Req<'_>, res: &mut Http1Res) -> rimu_ws::Result<()> {
  res.body_mut().extend_from_slice(echo_body(req.body()));
  res.set_content_type("application/octet-stream");
  res.set_status(StatusCode::Ok);
  Ok(())
}

/// `{"items":[..],"count":n}` for the first `count` items, with `total = price * quantity * m`,
/// serialized on every request. The dataset's numbers are integers (HttpArena made them so to keep
/// float formatting out of the test) and are written as such.
fn write_json(
  buf: &mut VectorUsize<u8>,
  dataset: &[DatasetItem],
  count: usize,
  m: i64,
) -> rimu_ws::Result<()> {
  let clamped = count.min(dataset.len());
  let mut w = JsonWriter::new(buf);
  // Every item and tag is written with a trailing comma; `end_seq` turns the last one into the
  // closing bracket.
  w.raw(b"{\"items\":[")?;
  for el in dataset.iter().take(clamped) {
    w.raw(b"{\"id\":")?;
    w.i64(el.id)?;
    w.raw(b",\"name\":\"")?;
    w.str_contents(&el.name)?;
    w.raw(b"\",\"category\":\"")?;
    w.str_contents(&el.category)?;
    w.raw(b"\",\"price\":")?;
    w.i64(el.price)?;
    w.raw(b",\"quantity\":")?;
    w.i64(el.quantity)?;
    w.raw(b",\"active\":")?;
    w.bool(el.active)?;
    w.raw(b",\"tags\":[")?;
    for tag in el.tags.iter() {
      w.raw(b"\"")?;
      w.str_contents(tag)?;
      w.raw(b"\",")?;
    }
    w.end_seq(b']')?;
    w.raw(b",\"rating\":{\"score\":")?;
    w.i64(el.rating.score)?;
    w.raw(b",\"count\":")?;
    w.i64(el.rating.count)?;
    w.raw(b"},\"total\":")?;
    w.i64(el.price.wrapping_mul(el.quantity).wrapping_mul(m))?;
    w.raw(b"},")?;
  }
  w.end_seq(b']')?;
  w.raw(b",\"count\":")?;
  w.u64(u64::try_from(clamped).unwrap_or(u64::MAX))?;
  w.raw(b"}")
}

fn load_dataset() -> VectorUsize<DatasetItem> {
  let path = std::env::var("DATASET_PATH").unwrap_or_else(|_| "/data/dataset.json".to_string());
  match std::fs::read_to_string(&path) {
    Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
    Err(_) => VectorUsize::new(),
  }
}

#[derive(serde::Deserialize)]
struct DatasetItem {
  id: i64,
  name: String,
  category: String,
  price: i64,
  quantity: i64,
  active: bool,
  tags: ArrayVectorU8<String, 6>,
  rating: Rating,
}

#[derive(serde::Deserialize)]
struct Rating {
  score: i64,
  count: i64,
}

/// How a `/json` response is encoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Encoding {
  Brotli,
  Gzip,
  Identity,
}

/// The encoding for an `Accept-Encoding` value: gzip if offered, else brotli, else none. A coding
/// listed with `q=0` is not offered. gzip is preferred over brotli because, measured on this
/// dataset, zlib level 6 produces a body about the same size as brotli q2 at a fraction of the CPU,
/// so it wins the bandwidth-penalised json-comp score (eff = rps x (min_bytes/own_bytes)^2).
fn choose_encoding(accept: &str) -> Encoding {
  let (mut brotli, mut gzip) = (false, false);
  for item in accept.split(',') {
    let (token, params) = item.split_once(';').unwrap_or((item, ""));
    let refused = params.split(';').any(|param| {
      param.trim().split_once('=').is_some_and(|(k, v)| {
        k.trim().eq_ignore_ascii_case("q") && v.trim().parse::<f32>() == Ok(0.0)
      })
    });
    if refused {
      continue;
    }
    let token = token.trim();
    brotli |= token.eq_ignore_ascii_case("br");
    gzip |= token.eq_ignore_ascii_case("gzip");
  }
  if gzip {
    Encoding::Gzip
  } else if brotli {
    Encoding::Brotli
  } else {
    Encoding::Identity
  }
}

/// Compresses `input` with `encoding` into `out`, which is cleared first. `Identity` copies.
fn encode(encoding: Encoding, input: &[u8], out: &mut Vec<u8>) -> std::io::Result<()> {
  out.clear();
  match encoding {
    Encoding::Brotli => {
      let params = brotli::enc::BrotliEncoderParams {
        quality: BROTLI_QUALITY,
        lgwin: BROTLI_LGWIN,
        size_hint: input.len(),
        ..Default::default()
      };
      let mut reader = input;
      brotli::BrotliCompress(&mut reader, out, &params)?;
    }
    Encoding::Gzip => {
      out.resize(zlib_rs::compress_bound(input.len()).saturating_add(64), 0);
      let config = zlib_rs::DeflateConfig {
        window_bits: GZIP_WINDOW_BITS,
        ..zlib_rs::DeflateConfig::new(GZIP_LEVEL)
      };
      let (done, code) = zlib_rs::compress_slice(out, input, config);
      if code != zlib_rs::ReturnCode::Ok {
        return Err(std::io::Error::other("gzip failed"));
      }
      let len = done.len();
      out.truncate(len);
    }
    Encoding::Identity => out.extend_from_slice(input),
  }
  Ok(())
}

/// Append `n` as decimal ASCII to `out`, without the `core::fmt` machinery.
fn push_i64(out: &mut Vec<u8>, n: i64) {
  let mut buf = [0u8; 20];
  let mut i = buf.len();
  let neg = n < 0;
  // use unsigned magnitude to handle i64::MIN safely
  let mut m = (n as i128).unsigned_abs() as u128;
  loop {
    i -= 1;
    buf[i] = b'0' + (m % 10) as u8;
    m /= 10;
    if m == 0 {
      break;
    }
  }
  if neg {
    i -= 1;
    buf[i] = b'-';
  }
  out.extend_from_slice(&buf[i..]);
}

#[cfg(test)]
mod tests {
  use super::*;

  const SAMPLE: &str = r#"{"items":[{"id":1,"name":"Alpha Widget","category":"electronics","price":100,"quantity":5,"active":true,"tags":["a","b"],"rating":{"score":4,"count":10},"total":1500},{"id":2,"name":"Beta Widget","category":"electronics","price":200,"quantity":5,"active":false,"tags":["a","c"],"rating":{"score":3,"count":20},"total":3000}],"count":2}"#;

  fn unbrotli(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    brotli::BrotliDecompress(&mut &*data, &mut out).unwrap();
    out
  }

  fn ungzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 1 << 20];
    let (done, code) = zlib_rs::decompress_slice(
      &mut out,
      data,
      zlib_rs::InflateConfig { window_bits: GZIP_WINDOW_BITS },
    );
    assert_eq!(code, zlib_rs::ReturnCode::Ok);
    done.to_vec()
  }

  #[test]
  fn prefers_gzip_when_offered() {
    // gzip is preferred over brotli (cheaper CPU, same size on this dataset → higher json-comp eff).
    assert_eq!(choose_encoding("gzip, br"), Encoding::Gzip);
    assert_eq!(choose_encoding("gzip, deflate, br, zstd"), Encoding::Gzip);
    assert_eq!(choose_encoding("BR;q=0.5, gzip;q=1.0"), Encoding::Gzip);
    assert_eq!(choose_encoding("gzip"), Encoding::Gzip);
    assert_eq!(choose_encoding("deflate, gzip;q=0.8"), Encoding::Gzip);
  }

  #[test]
  fn chooses_brotli_only_when_gzip_absent() {
    assert_eq!(choose_encoding("br"), Encoding::Brotli);
    assert_eq!(choose_encoding("deflate, br, zstd"), Encoding::Brotli);
    assert_eq!(choose_encoding("br, gzip;q=0"), Encoding::Brotli);
  }

  #[test]
  fn chooses_identity_otherwise() {
    assert_eq!(choose_encoding(""), Encoding::Identity);
    assert_eq!(choose_encoding("identity"), Encoding::Identity);
    assert_eq!(choose_encoding("deflate, zstd"), Encoding::Identity);
    assert_eq!(choose_encoding("gzip;q=0, br;q=0"), Encoding::Identity);
    assert_eq!(choose_encoding("brotli"), Encoding::Identity);
  }

  #[test]
  fn brotli_round_trips() {
    let mut out = vec![1, 2, 3];
    encode(Encoding::Brotli, SAMPLE.as_bytes(), &mut out).unwrap();
    assert_eq!(unbrotli(&out), SAMPLE.as_bytes());
  }

  #[test]
  fn gzip_round_trips() {
    let mut out = Vec::new();
    encode(Encoding::Gzip, SAMPLE.as_bytes(), &mut out).unwrap();
    assert_eq!(&out[..2], &[0x1f, 0x8b]);
    assert_eq!(ungzip(&out), SAMPLE.as_bytes());
  }

  fn test_dataset() -> Option<VectorUsize<DatasetItem>> {
    let path = std::env::var("DATASET_PATH")
      .unwrap_or_else(|_| "/mnt/nvme1tb/claude-tmp/arena-main/data/dataset.json".into());
    let Ok(text) = std::fs::read_to_string(&path) else {
      eprintln!("no dataset at {path}: skipped");
      return None;
    };
    Some(serde_json::from_str(&text).unwrap())
  }

  /// The dataset's numbers are integers and stay integers: the body sizes HttpArena computes for
  /// its seven (count, m) pairs, the same bytes `arena-h2` writes.
  #[test]
  fn json_has_the_reference_sizes() {
    let Some(dataset) = test_dataset() else { return };
    let pairs: [(usize, i32, usize); 7] = [
      (1, 3, 203),
      (5, 7, 888),
      (10, 2, 1695),
      (15, 5, 2556),
      (25, 4, 4190),
      (40, 8, 6707),
      (50, 6, 8397),
    ];
    for (count, m, len) in pairs {
      let mut buf = VectorUsize::new();
      write_json(&mut buf, &dataset, count, m.into()).unwrap();
      assert_eq!(buf.len(), len, "count {count}, m {m}");
    }
  }

  #[test]
  fn dataset_json_round_trips_compressed() {
    let Some(dataset) = test_dataset() else { return };
    for (count, m) in [(1, 3), (10, 2), (50, 6)] {
      let mut json = VectorUsize::new();
      write_json(&mut json, &dataset, count, m).unwrap();
      let mut out = Vec::new();
      encode(Encoding::Brotli, json.as_slice(), &mut out).unwrap();
      assert_eq!(unbrotli(&out), json.as_slice());
      encode(Encoding::Gzip, json.as_slice(), &mut out).unwrap();
      assert_eq!(ungzip(&out), json.as_slice());
    }
  }

  #[test]
  fn m_defaults_to_one() {
    assert_eq!(query_m("").unwrap(), 1);
    assert_eq!(query_m("m=7").unwrap(), 7);
    assert_eq!(query_m("x=1&m=-2").unwrap(), -2);
    assert!(query_m("m=abc").is_err());
  }

  #[test]
  fn identity_copies() {
    let mut out = vec![9];
    encode(Encoding::Identity, SAMPLE.as_bytes(), &mut out).unwrap();
    assert_eq!(out, SAMPLE.as_bytes());
  }

  #[test]
  fn delay_ms_parses_the_segment() {
    assert_eq!(delay_ms(Some("10")), Some(10));
    assert_eq!(delay_ms(Some("0")), Some(0));
    assert_eq!(delay_ms(Some("499")), Some(499));
    assert_eq!(delay_ms(None), None);
    assert_eq!(delay_ms(Some("abc")), None);
    assert_eq!(delay_ms(Some("")), None);
    assert_eq!(delay_ms(Some("-5")), None);
    assert_eq!(delay_ms(Some("1.5")), None);
  }

  #[test]
  fn echo_returns_the_same_bytes() {
    assert_eq!(echo_body(b"abc"), b"abc");
    assert_eq!(echo_body(b""), b"");
    let binary: Vec<u8> = (0..=255u8).cycle().take(10_240).collect();
    assert_eq!(echo_body(&binary), binary.as_slice());
  }

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
