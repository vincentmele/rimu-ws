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
//! the request's `Accept-Encoding` lines: gzip (level 6) if offered, else brotli (quality 2), else
//! none; with `Vary: Accept-Encoding`, and 406 if identity is refused and nothing else is
//! acceptable. Nothing is cached.
//!
//! Environment: `ARENA_LOG_ERRORS` prints the errors the server reports to stderr; `DATASET_PATH`
//! (default `/data/dataset.json`) is the dataset `/json` serves.

use core::{cell::RefCell, num::NonZeroUsize, time::Duration};
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
/// zlib level of gzip, the preferred coding.
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
    Some(std::thread::spawn(move || serve_tls("0.0.0.0:8081", None, &cert, &key, runtime)))
  } else {
    eprintln!("arena-h1: no {cert_dir}/server.crt, TLS on 8081 disabled");
    None
  };
  serve_plain("0.0.0.0:8080", None, runtime)?;
  if let Some(elem) = tls {
    elem.join().map_err(|_| std::io::Error::other("TLS thread panicked"))??;
  }
  Ok(())
}

/// The plaintext server: `runtimes` runtimes (one per thread if `None`), each built by `rc`.
fn serve_plain<RC>(addr: &str, runtimes: Option<NonZeroUsize>, rc: RC) -> rimu_ws::Result<()>
where
  RC: Clone + Fn() -> rimu_ws::Result<UringRuntime> + Send + 'static,
{
  let router = Http1Router::new()
    .route(Some(Method::Get), "/baseline11", endpoint_baseline11)
    .route(Some(Method::Post), "/baseline11", endpoint_baseline11)
    .route(Some(Method::Get), "/delay/{ms}", endpoint_delay)
    .route(Some(Method::Get), "/json/{count}", endpoint_json);
  Http1ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _>::new(UringExecutor::default())?
    .set_error_cb(error_cb)
    // `/delay/{ms}` takes at most MAX_DELAY_MS, which the framework must not cut
    .set_max_delay(Duration::from_millis(MAX_DELAY_MS))
    // Every client speaks first
    .set_tcp_params(TcpParams::default().set_tcp_defer_accept(Some(1)))
    .set_local_runtime_cb(rc)
    .set_local_runtimes(runtimes)
    .run_in_threads(addr, router)
}

/// The TLS server of the certificate `cert` and its key `key`, with runtimes as [`serve_plain`].
fn serve_tls<RC>(
  addr: &str,
  runtimes: Option<NonZeroUsize>,
  cert: &[u8],
  key: &[u8],
  rc: RC,
) -> rimu_ws::Result<()>
where
  RC: Clone + Fn() -> rimu_ws::Result<UringRuntime> + Send + 'static,
{
  let tls_config = TlsConfig::from_keys_pem(cert, key)?;
  let router = Http1Router::new()
    .route(Some(Method::Get), "/json/{count}", endpoint_json_plain)
    .route(Some(Method::Post), "/echo", endpoint_echo);
  Http1ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new_tls(
    UringExecutor::default(),
    ChaCha20::from_std_random()?,
    tls_config,
  )?
  .set_error_cb(error_cb)
  .set_local_runtime_cb(rc)
  .set_local_runtimes(runtimes)
  .run_in_threads(addr, router)
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
  // Digits that overflow are a number too big, not "not a number"
  Some(param.parse().unwrap_or(u64::MAX))
}

/// The longest `/delay/{ms}` served, in milliseconds. It is the framework's maximum delay too, set
/// below, so that a delay is never cut: a longer one is a bad request.
const MAX_DELAY_MS: u64 = 5000;

/// The status and the delay in milliseconds for the `{ms}` segment: more than [`MAX_DELAY_MS`] is a
/// 400 (no delay), no number is no delay.
fn delay_response(param: Option<&str>) -> (StatusCode, u64) {
  match delay_ms(param) {
    Some(ms) if ms > MAX_DELAY_MS => (StatusCode::BadRequest, 0),
    Some(ms) => (StatusCode::Ok, ms),
    None => (StatusCode::Ok, 0),
  }
}

/// Waits `ms` milliseconds (at most [`MAX_DELAY_MS`], else 400), then answers with `ms`. The delay is read from this request's path, so
/// concurrent requests wait independently. The framework sends nothing before the delay elapses.
fn endpoint_delay(_: &mut (), req: &Http1Req<'_>, res: &mut Http1Res) -> rimu_ws::Result<()> {
  let (status, ms) = delay_response(req.param("ms"));
  if status == StatusCode::BadRequest {
    res.body_mut().extend_from_slice(b"delay over 5000 ms");
  } else {
    push_i64(res.body_mut(), i64::try_from(ms).unwrap_or(i64::MAX));
  }
  res.set_content_type("text/plain");
  res.set_status(status);
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
/// `Accept-Encoding` lines. Both happen on every request: the body is never kept.
fn endpoint_json(_: &mut (), req: &Http1Req<'_>, res: &mut Http1Res) -> rimu_ws::Result<()> {
  let count: usize = req.param("count").unwrap_or("0").parse()?;
  let m = query_m(req.query())?;
  let dataset = DATASET.get().map_or(&[][..], |el| el.as_slice());
  let accepts = req.headers().iter().filter(|el| el.0.eq_ignore_ascii_case("accept-encoding"));
  // The response depends on `Accept-Encoding`, so every one says so (RFC 9110 §12.5.5)
  res.push_header("vary", "Accept-Encoding")?;
  let Some(encoding) = choose_encoding(accepts.map(|el| el.1)) else {
    res.body_mut().extend_from_slice(b"no acceptable content coding");
    res.set_content_type("text/plain");
    res.set_status(StatusCode::NotAcceptable);
    return Ok(());
  };
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

/// The encoding for the `Accept-Encoding` header lines of a request (none if it has no such
/// header): gzip if offered, else brotli, else none. A coding listed with `q=0` is not offered.
/// gzip is preferred over brotli because, measured on this dataset, zlib level 6 produces a body
/// about the same size as brotli q2 at a fraction of the CPU, so it wins the bandwidth-penalised
/// json-comp score (eff = rps x (min_bytes/own_bytes)^2).
///
/// `None` if no coding is acceptable: neither gzip nor brotli is offered and the identity coding is
/// refused, by `identity;q=0` or by `*;q=0` without an `identity` of its own (RFC 9110 §12.5.3).
/// The answer is then 406. A `*` with a nonzero `q` offers the codings that are not listed, but is
/// only consulted when identity is refused: otherwise identity is sent.
fn choose_encoding<'a>(lines: impl IntoIterator<Item = &'a str>) -> Option<Encoding> {
  // Whether `br` and `gzip` were listed, and if with a nonzero `q`
  let (mut brotli, mut gzip): (Option<bool>, Option<bool>) = (None, None);
  // Whether `identity` and `*` were listed, and if with a nonzero `q`
  let (mut identity, mut star): (Option<bool>, Option<bool>) = (None, None);
  for item in lines.into_iter().flat_map(|line| line.split(',')) {
    let (token, params) = item.split_once(';').unwrap_or((item, ""));
    let offered = !params.split(';').any(|param| {
      param.trim().split_once('=').is_some_and(|(k, v)| {
        k.trim().eq_ignore_ascii_case("q") && v.trim().parse::<f32>() == Ok(0.0)
      })
    });
    let token = token.trim();
    if token.eq_ignore_ascii_case("br") {
      brotli = Some(brotli.unwrap_or(false) | offered);
    } else if token.eq_ignore_ascii_case("gzip") {
      gzip = Some(gzip.unwrap_or(false) | offered);
    } else if token.eq_ignore_ascii_case("identity") {
      identity = Some(identity.unwrap_or(false) | offered);
    } else if token == "*" {
      star = Some(star.unwrap_or(false) | offered);
    }
  }
  if gzip == Some(true) {
    Some(Encoding::Gzip)
  } else if brotli == Some(true) {
    Some(Encoding::Brotli)
  } else if identity.or(star) == Some(false) {
    // Identity is refused: `*` with a nonzero `q` offers the codings that are not listed
    if star == Some(true) && gzip.is_none() {
      Some(Encoding::Gzip)
    } else if star == Some(true) && brotli.is_none() {
      Some(Encoding::Brotli)
    } else {
      None
    }
  } else {
    Some(Encoding::Identity)
  }
}

/// Compresses `input` with `encoding` into `out`, which is cleared first. `Identity` copies.
///
/// The compressors' state is the thread's, reused from one response to the next: gzip resets its
/// stream, brotli takes its blocks back from [`BrotliPool`]. Built for every response, they would
/// allocate and clear some 380 KB (gzip) or 480 KB (brotli) each time.
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
      // `brotli::BrotliCompress` with the pool for allocator, and an end-of-input error that is
      // not allocated for every call (its `io::Error::new` is)
      let (mut input_buffer, mut output_buffer) = ([0u8; 4096], [0u8; 4096]);
      let mut reader = input;
      let mut no_callback =
        |_: &mut brotli::interface::PredictionModeContextMap<brotli::InputReferenceMut<'_>>,
         _: &mut [brotli::interface::StaticCommand],
         _: brotli::InputPair<'_>,
         _: &mut BrotliPool| ();
      let _len = brotli::BrotliCompressCustomIo(
        &mut brotli::IoReaderWrapper(&mut reader),
        &mut brotli::IoWriterWrapper(out),
        &mut input_buffer,
        &mut output_buffer,
        &params,
        BrotliPool,
        &mut no_callback,
        std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
      )?;
    }
    Encoding::Gzip => {
      let thread =
        GZIP.try_with(|cell| gzip(cell.borrow_mut().get_or_insert_with(gzip_stream), input, out));
      match thread {
        Ok(rslt) => rslt?,
        // The thread is being torn down: a stream of this response's own
        Err(_) => gzip(&mut gzip_stream(), input, out)?,
      }
    }
    Encoding::Identity => out.extend_from_slice(input),
  }
  Ok(())
}

/// A gzip stream at the arena's level.
fn gzip_stream() -> zlib_rs::Deflate {
  zlib_rs::Deflate::new_with_config(zlib_rs::DeflateConfig {
    window_bits: GZIP_WINDOW_BITS,
    ..zlib_rs::DeflateConfig::new(GZIP_LEVEL)
  })
}

/// Compresses `input` into the empty `out` with `deflate`, which is reset first.
fn gzip(deflate: &mut zlib_rs::Deflate, input: &[u8], out: &mut Vec<u8>) -> std::io::Result<()> {
  // Also after a failed response, whose stream may have stopped in the middle
  deflate.reset();
  out.clear();
  out.reserve(zlib_rs::compress_bound(input.len()).saturating_add(64));
  let status = deflate
    .compress_uninit(input, out.spare_capacity_mut(), zlib_rs::DeflateFlush::Finish)
    .map_err(|_| std::io::Error::other("gzip failed"))?;
  if status != zlib_rs::Status::StreamEnd {
    return Err(std::io::Error::other("gzip failed"));
  }
  let len = usize::try_from(deflate.total_out()).unwrap_or(usize::MAX);
  if len > out.capacity() {
    return Err(std::io::Error::other("gzip failed"));
  }
  // SAFETY: the stream wrote `len` bytes into the spare capacity, which starts at 0 (`out` is
  // empty)
  unsafe {
    out.set_len(len);
  }
  Ok(())
}

thread_local! {
  /// The thread's gzip stream, built by the first gzip response.
  static GZIP: RefCell<Option<zlib_rs::Deflate>> = const { RefCell::new(None) };
  /// The blocks brotli encoders freed on this thread, for [`BrotliPool`].
  static BROTLI_FREE: RefCell<BrotliFree> = const { RefCell::new(BrotliFree { blocks: Vec::new(), bytes: 0 }) };
}

/// Bytes of free blocks a thread keeps at most for brotli. One encoder's state at the arena's
/// quality and window is about 480 KB; a sweep of every /json size leaves about 1.8 MB, the
/// smaller blocks of the smaller bodies included, which are the first to go past this.
const BROTLI_POOL_MAX: usize = 2 << 20;

/// The allocator of the brotli encoder: a block it frees is kept by the thread, and the next
/// request of the same type is served by the smallest kept block that is long enough, so blocks
/// whose length follows the body's size are reused across sizes. The encoder is shown the length
/// it asked for, cleared to its default as a new block would be, so the output is the same.
///
/// A block that must be allocated gets up to an eighth more room than asked for, so that a
/// slightly longer request later still fits. Past [`BROTLI_POOL_MAX`] the smallest blocks go back
/// to the allocator first. Without the thread's pool (during the thread's teardown) blocks are
/// plain allocations.
#[derive(Clone, Copy, Debug, Default)]
struct BrotliPool;

impl brotli::enc::BrotliAlloc for BrotliPool {}

impl<T> brotli::Allocator<T> for BrotliPool
where
  T: Clone + Default + 'static,
{
  type AllocatedMemory = BrotliBlock<T>;

  fn alloc_cell(&mut self, len: usize) -> BrotliBlock<T> {
    if len == 0 {
      return BrotliBlock::default();
    }
    let ty = core::any::TypeId::of::<T>();
    let reused = BROTLI_FREE
      .try_with(|cell| {
        let mut free = cell.borrow_mut();
        let idx = free
          .blocks
          .iter()
          .enumerate()
          .filter(|(_, el)| el.ty == ty && el.cap >= len)
          .min_by_key(|(_, el)| el.cap)
          .map(|(idx, _)| idx)?;
        let block = free.blocks.swap_remove(idx);
        free.bytes = free.bytes.saturating_sub(block.bytes);
        Some((block.ptr, block.cap))
      })
      .ok()
      .flatten();
    let Some((ptr, cap)) = reused else {
      let buf = vec![T::default(); brotli_block_cap(len)].into_boxed_slice();
      return BrotliBlock { buf, len };
    };
    // SAFETY: `ptr` and `cap` are those of the `Box<[T]>` (`ty` is `T`) that `free_cell` gave up
    let mut buf =
      unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr.cast::<T>(), cap)) };
    // Only `len` elements are shown to the encoder, as a new block would be
    if let Some(elem) = buf.get_mut(..len) {
      elem.fill(T::default());
    }
    BrotliBlock { buf, len }
  }

  fn free_cell(&mut self, data: BrotliBlock<T>) {
    let cap = data.buf.len();
    let bytes = cap.saturating_mul(size_of::<T>());
    if bytes == 0 || bytes > BROTLI_POOL_MAX {
      return;
    }
    let mut data = Some(data);
    let _rslt = BROTLI_FREE.try_with(|cell| {
      let mut free = cell.borrow_mut();
      // Room is made by the smallest blocks, but not for a block smaller than all of them
      while free.bytes.saturating_add(bytes) > BROTLI_POOL_MAX {
        let Some((idx, smallest)) = free
          .blocks
          .iter()
          .enumerate()
          .min_by_key(|(_, el)| el.bytes)
          .map(|(idx, el)| (idx, el.bytes))
        else {
          break;
        };
        if smallest >= bytes {
          return;
        }
        let evicted = free.blocks.swap_remove(idx);
        free.bytes = free.bytes.saturating_sub(evicted.bytes);
        // SAFETY: `drop` is the one of the block's type and capacity
        unsafe { (evicted.drop)(evicted.ptr, evicted.cap) }
      }
      let Some(elem) = data.take() else {
        return;
      };
      let ptr = Box::into_raw(elem.buf).cast::<u8>();
      free.bytes = free.bytes.wrapping_add(bytes);
      free.blocks.push(FreeBlock {
        bytes,
        cap,
        drop: drop_block::<T>,
        ptr,
        ty: core::any::TypeId::of::<T>(),
      });
    });
    // Not kept (no room, or no pool any more): freed here
    drop(data);
  }
}

/// The capacity a new brotli block of `len` elements is given: `len` rounded up to a step of an
/// eighth of its leading power of two.
fn brotli_block_cap(len: usize) -> usize {
  let step = (len.checked_ilog2().unwrap_or(0).saturating_sub(3)).min(usize::BITS - 2);
  let mask = (1usize << step).wrapping_sub(1);
  len.checked_add(mask).map_or(len, |el| el & !mask)
}

/// A block of a brotli encoder: the encoder sees the first `len` elements of `buf`.
struct BrotliBlock<T> {
  buf: Box<[T]>,
  len: usize,
}

impl<T> Default for BrotliBlock<T> {
  fn default() -> Self {
    Self { buf: Box::default(), len: 0 }
  }
}

impl<T> brotli::SliceWrapper<T> for BrotliBlock<T> {
  fn slice(&self) -> &[T] {
    self.buf.get(..self.len).unwrap_or_default()
  }
}

impl<T> brotli::SliceWrapperMut<T> for BrotliBlock<T> {
  fn slice_mut(&mut self) -> &mut [T] {
    self.buf.get_mut(..self.len).unwrap_or_default()
  }
}

/// The free blocks of a thread's [`BrotliPool`], and their size.
struct BrotliFree {
  blocks: Vec<FreeBlock>,
  bytes: usize,
}

impl Drop for BrotliFree {
  fn drop(&mut self) {
    for block in self.blocks.drain(..) {
      // SAFETY: `drop` is the one of the block's type and capacity
      unsafe { (block.drop)(block.ptr, block.cap) }
    }
  }
}

/// A block a brotli encoder freed: a `Box<[T]>` of `cap` elements of the type `ty`.
struct FreeBlock {
  bytes: usize,
  cap: usize,
  drop: unsafe fn(*mut u8, usize),
  ptr: *mut u8,
  ty: core::any::TypeId,
}

/// Frees the `Box<[T]>` of `len` elements at `ptr`.
///
/// # Safety
///
/// `ptr` and `len` are those of a `Box<[T]>` given up by `Box::into_raw`.
unsafe fn drop_block<T>(ptr: *mut u8, len: usize) {
  // SAFETY: as the caller ensures
  drop(unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr.cast::<T>(), len)) });
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
#[path = "arena_h1/alloc_tests.rs"]
mod alloc_tests;

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

  /// The encoding for one `Accept-Encoding` header line.
  fn choose(accept: &str) -> Option<Encoding> {
    choose_encoding([accept])
  }

  #[test]
  fn prefers_gzip_when_offered() {
    // gzip is preferred over brotli (cheaper CPU, same size on this dataset → higher json-comp eff).
    assert_eq!(choose("gzip, br"), Some(Encoding::Gzip));
    assert_eq!(choose("gzip, deflate, br, zstd"), Some(Encoding::Gzip));
    assert_eq!(choose("BR;q=0.5, gzip;q=1.0"), Some(Encoding::Gzip));
    assert_eq!(choose("gzip"), Some(Encoding::Gzip));
    assert_eq!(choose("deflate, gzip;q=0.8"), Some(Encoding::Gzip));
  }

  #[test]
  fn chooses_brotli_only_when_gzip_absent() {
    assert_eq!(choose("br"), Some(Encoding::Brotli));
    assert_eq!(choose("deflate, br, zstd"), Some(Encoding::Brotli));
    assert_eq!(choose("br, gzip;q=0"), Some(Encoding::Brotli));
  }

  #[test]
  fn chooses_identity_otherwise() {
    assert_eq!(choose(""), Some(Encoding::Identity));
    assert_eq!(choose("identity"), Some(Encoding::Identity));
    assert_eq!(choose("deflate, zstd"), Some(Encoding::Identity));
    assert_eq!(choose("gzip;q=0, br;q=0"), Some(Encoding::Identity));
    assert_eq!(choose("brotli"), Some(Encoding::Identity));
    assert_eq!(choose("*"), Some(Encoding::Identity));
    assert_eq!(choose("*;q=0, identity"), Some(Encoding::Identity));
    assert_eq!(choose("*;q=0, identity;q=0.5"), Some(Encoding::Identity));
    assert_eq!(choose("identity;q=1, gzip;q=0"), Some(Encoding::Identity));
    // No header at all
    assert_eq!(choose_encoding([]), Some(Encoding::Identity));
  }

  // RFC 9110 §12.5.3: `*` with a nonzero `q` makes every coding not listed acceptable, which
  // rescues a request that refuses identity.
  #[test]
  fn star_offers_unlisted_codings_when_identity_is_refused() {
    assert_eq!(choose("identity;q=0, *"), Some(Encoding::Gzip));
    assert_eq!(choose("identity;q=0, *;q=0.5"), Some(Encoding::Gzip));
    assert_eq!(choose("*;q=0.5, identity;q=0"), Some(Encoding::Gzip));
    // an explicit `gzip;q=0` keeps gzip out, `*` still offers brotli
    assert_eq!(choose("identity;q=0, gzip;q=0, *"), Some(Encoding::Brotli));
    assert_eq!(choose("identity;q=0, br;q=0, *"), Some(Encoding::Gzip));
    // nothing is left for `*` to offer
    assert_eq!(choose("identity;q=0, gzip;q=0, br;q=0, *"), None);
    // `*;q=0` offers nothing
    assert_eq!(choose("identity;q=0, *;q=0"), None);
    // `*` alone does not ask for compression: identity is acceptable
    assert_eq!(choose("*"), Some(Encoding::Identity));
  }

  // RFC 9110 §12.5.3: with identity refused and nothing else acceptable there is no response.
  #[test]
  fn refused_identity_without_another_coding_is_not_acceptable() {
    assert_eq!(choose("identity;q=0"), None);
    assert_eq!(choose("identity;q=0.0, deflate"), None);
    assert_eq!(choose("*;q=0"), None);
    assert_eq!(choose("*;q=0, deflate"), None);
    assert_eq!(choose("gzip;q=0, identity;q=0"), None);
    assert_eq!(choose("gzip;q=0, *;q=0"), None);
    assert_eq!(choose("br;q=0, identity;q=0, gzip;q=0"), None);
    // ...but another coding that is acceptable serves it
    assert_eq!(choose("identity;q=0, gzip"), Some(Encoding::Gzip));
    assert_eq!(choose("*;q=0, gzip"), Some(Encoding::Gzip));
    assert_eq!(choose("*;q=0, br"), Some(Encoding::Brotli));
    assert_eq!(choose("identity;q=0, br, gzip"), Some(Encoding::Gzip));
  }

  // Every `Accept-Encoding` line counts, not just the first.
  #[test]
  fn all_accept_encoding_lines_count() {
    assert_eq!(choose_encoding(["deflate", "gzip"]), Some(Encoding::Gzip));
    assert_eq!(choose_encoding(["br", "gzip;q=0"]), Some(Encoding::Brotli));
    assert_eq!(choose_encoding(["", "br"]), Some(Encoding::Brotli));
    assert_eq!(choose_encoding(["deflate", "identity;q=0"]), None);
    assert_eq!(choose_encoding(["identity;q=0", "gzip"]), Some(Encoding::Gzip));
    assert_eq!(choose_encoding(["gzip;q=0", "*;q=0"]), None);
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

  /// Inputs of several sizes, the larger ones less compressible, for the reuse tests.
  fn reuse_inputs() -> Vec<Vec<u8>> {
    let mut seed: u32 = 7;
    let mut noise = |len: usize| -> Vec<u8> {
      (0..len)
        .map(|_| {
          seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
          b'a' + (seed >> 16) as u8 % 8
        })
        .collect()
    };
    let mut out = vec![Vec::new(), b"x".to_vec(), SAMPLE.as_bytes().to_vec()];
    out.extend([100, 4190, 8397, 70_000, 4190, 1].map(&mut noise));
    out.push(SAMPLE.repeat(40).into_bytes());
    out
  }

  // The thread's gzip stream, reset for every response, writes what a new one would, input after
  // input.
  #[test]
  fn reused_gzip_stream_matches_a_new_one() {
    let mut out = Vec::new();
    for _ in 0..2 {
      for input in reuse_inputs() {
        encode(Encoding::Gzip, &input, &mut out).unwrap();
        let mut fresh = vec![0u8; zlib_rs::compress_bound(input.len()) + 64];
        let config = zlib_rs::DeflateConfig {
          window_bits: GZIP_WINDOW_BITS,
          ..zlib_rs::DeflateConfig::new(GZIP_LEVEL)
        };
        let (done, code) = zlib_rs::compress_slice(&mut fresh, &input, config);
        assert_eq!(code, zlib_rs::ReturnCode::Ok);
        assert_eq!(out, done, "{} bytes", input.len());
        assert_eq!(ungzip(&out), input);
      }
    }
  }

  // Brotli on the thread's pool writes what it does on new allocations, input after input.
  #[test]
  fn pooled_brotli_matches_a_new_encoder() {
    let mut out = Vec::new();
    for _ in 0..2 {
      for input in reuse_inputs() {
        encode(Encoding::Brotli, &input, &mut out).unwrap();
        let params = brotli::enc::BrotliEncoderParams {
          quality: BROTLI_QUALITY,
          lgwin: BROTLI_LGWIN,
          size_hint: input.len(),
          ..Default::default()
        };
        let mut fresh = Vec::new();
        brotli::BrotliCompress(&mut input.as_slice(), &mut fresh, &params).unwrap();
        assert_eq!(out, fresh, "{} bytes", input.len());
        assert_eq!(unbrotli(&out), input);
      }
    }
  }

  // The pool keeps at most BROTLI_POOL_MAX bytes, whatever the sizes it was asked for.
  #[test]
  fn brotli_pool_is_bounded() {
    let mut out = Vec::new();
    for len in (1..200).map(|el| el * 997) {
      let input: Vec<u8> = (0..len).map(|el| (el * 31 % 251) as u8).collect();
      encode(Encoding::Brotli, &input, &mut out).unwrap();
      assert_eq!(unbrotli(&out), input);
      let bytes = BROTLI_FREE.with(|el| el.borrow().bytes);
      assert!(bytes <= BROTLI_POOL_MAX, "{bytes}");
    }
  }

  /// Thread-local destructors that ran their encodes, see [`EncodeOnDrop`].
  static TEARDOWN_ENCODES: rimu_ws::sync::AtomicUsize = rimu_ws::sync::AtomicUsize::new(0);

  /// Compresses with brotli and gzip in a thread-local destructor, as code torn down with its
  /// thread may, and checks the output.
  struct EncodeOnDrop;

  impl Drop for EncodeOnDrop {
    fn drop(&mut self) {
      let mut out = Vec::new();
      encode(Encoding::Brotli, SAMPLE.as_bytes(), &mut out).unwrap();
      assert_eq!(unbrotli(&out), SAMPLE.as_bytes());
      encode(Encoding::Gzip, SAMPLE.as_bytes(), &mut out).unwrap();
      assert_eq!(ungzip(&out), SAMPLE.as_bytes());
      let _ = TEARDOWN_ENCODES.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
  }

  thread_local! {
    static BEFORE_POOLS: EncodeOnDrop = const { EncodeOnDrop };
    static AFTER_POOLS: EncodeOnDrop = const { EncodeOnDrop };
  }

  // The thread's pools are destroyed with it, in some order with the other thread-locals: one of
  // these destructors runs after them, and compresses without them (a panic there would abort).
  #[test]
  fn encodes_while_the_thread_is_torn_down() {
    std::thread::spawn(|| {
      BEFORE_POOLS.with(|_| {});
      let mut out = Vec::new();
      encode(Encoding::Brotli, SAMPLE.as_bytes(), &mut out).unwrap();
      encode(Encoding::Gzip, SAMPLE.as_bytes(), &mut out).unwrap();
      AFTER_POOLS.with(|_| {});
    })
    .join()
    .unwrap();
    assert_eq!(TEARDOWN_ENCODES.load(core::sync::atomic::Ordering::SeqCst), 2);
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
  fn delay_over_the_cap_is_a_bad_request() {
    assert_eq!(MAX_DELAY_MS, 5000);
    assert_eq!(delay_response(Some("0")), (StatusCode::Ok, 0));
    assert_eq!(delay_response(Some("500")), (StatusCode::Ok, 500));
    assert_eq!(delay_response(Some("5000")), (StatusCode::Ok, 5000));
    assert_eq!(delay_response(Some("5001")), (StatusCode::BadRequest, 0));
    assert_eq!(delay_response(Some("86400000")), (StatusCode::BadRequest, 0));
    // Digits only, but too big for a u64
    assert_eq!(delay_response(Some("99999999999999999999999")), (StatusCode::BadRequest, 0));
    // Not a number: no delay, as before
    assert_eq!(delay_response(Some("abc")), (StatusCode::Ok, 0));
    assert_eq!(delay_response(None), (StatusCode::Ok, 0));
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
