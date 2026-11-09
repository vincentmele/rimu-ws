//! HttpArena HTTP/2 and HTTP/3 server: `/baseline2`, `/json/{count}` and `/static/{*file}` on h2c
//! (8082) and h2 over TLS (8443), served by the HTTP/2 server framework on the io_uring executor, and
//! on h3 (UDP 8443, dual-stack), served by the HTTP/3 server framework. Used by `.scripts/h2-bench.sh`
//! and `.scripts/h3-bench.sh`.
//!
//! Environment: `CERT_DIR` (default `/certs`, with `server.crt` and `server.key`; without them
//! only h2c is served), `DATASET_PATH` (default `/data/dataset.json`), `STATIC_DIR` (default
//! `/data/static`), `ARENA_PARAMS` (`permissive` for `HttpRecvParams::with_permissive_params`, as
//! upstream's wtx-http2 entry does; otherwise the library defaults), `ARENA_H3_HEADERS` (`full`, the
//! default: `content-length`, `date` and the `server` middleware on h3 responses, as on h2; or
//! `min`: no `date`, no `content-length`, no middleware, which is the A/B of the user's decision Q2).
//!
//! With TLS on, SIGUSR1 prints the sums of the counters of the h3 workers on one line starting with
//! `h3-stats` (what `h3-bench.sh` reads), and SIGINT or SIGTERM prints them with one line per
//! worker and exits.

use core::ops::ControlFlow;
use rimu_ws::{
  collections::{ArrayVectorU8, VectorUsize},
  executor::{UringExecutor, UringParams, UringRuntime},
  http::{
    Header, HttpRecvParams, KnownHeaderName, MsgBufferString, MsgDataMut as _, Request, Response,
    StatusCode,
    http2_server_framework::{
      Get, Http2ServerFramework, HttpRouter, JsonReply, Middleware, Path, State, StaticFiles,
      VerbatimParams, get,
    },
    http3_server_framework::{Http3ServerFramework, Http3Stats, Http3WorkerStats},
  },
  misc::JsonWriter,
  rng::{ChaCha20, CryptoSeedableRng as _},
  sync::Arc,
  tls::TlsConfig,
};

macro_rules! paths {
  () => {
    rimu_ws::paths!(
      ("/baseline2", get(endpoint_baseline2)),
      ("/json/{count}", get(endpoint_json)),
      ("/static/{*file}", Get(StaticFiles::new(static_dir())?))
    )
  };
}

macro_rules! router {
  () => {
    HttpRouter::new(paths!(), ServerHeader)
  };
  (no_middleware) => {
    HttpRouter::paths(paths!())
  };
}

fn static_dir() -> String {
  std::env::var("STATIC_DIR").unwrap_or_else(|_| "/data/static".into())
}

fn main() -> rimu_ws::Result<()> {
  let dataset = load_dataset();
  let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "/certs".into());
  let tls_enabled = std::path::Path::new(&cert_dir).join("server.crt").exists();
  // Before any thread exists, so that every thread inherits the mask
  let signals = if tls_enabled { Some(stats_signals::block()) } else { None };
  let (tls, h3) = if tls_enabled {
    let data = dataset.clone();
    let cert = std::fs::read(format!("{cert_dir}/server.crt"))?;
    let key = std::fs::read(format!("{cert_dir}/server.key"))?;
    let (h3_stats, h3) = spawn_h3(&cert, key.clone(), ConnAux { dataset: dataset.clone() })?;
    if let Some(elem) = signals {
      stats_signals::spawn_reporter(elem, h3_stats);
    }
    let tls = std::thread::spawn(move || -> rimu_ws::Result<()> {
      let tls_config = TlsConfig::from_keys_pem(&cert, key.as_slice())?;
      Http2ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new(
        UringExecutor::default(),
        ChaCha20::from_std_random()?,
        tls_config,
      )?
      .set_data(ConnAux { dataset: data })
      .set_error_cb(error_cb)
      .set_http_recv_params(recv_params())
      .set_local_runtime_cb(runtime)
      .run_in_threads("0.0.0.0:8443", router!()?)
    });
    (Some(tls), Some(h3))
  } else {
    eprintln!("arena-h2: no {cert_dir}/server.crt, TLS on 8443 disabled");
    (None, None)
  };
  Http2ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new(
    UringExecutor::default(),
    ChaCha20::from_std_random()?,
    TlsConfig::plaintext(),
  )?
  .set_data(ConnAux { dataset })
  .set_error_cb(error_cb)
  .set_http_recv_params(recv_params())
  .set_local_runtime_cb(runtime)
  .run_in_threads("0.0.0.0:8082", router!()?)?;
  if let Some(elem) = tls {
    elem.join().map_err(|_| std::io::Error::other("TLS thread panicked"))??;
  }
  if let Some(elem) = h3 {
    elem.join().map_err(|_| std::io::Error::other("h3 thread panicked"))??;
  }
  Ok(())
}

/// Starts the HTTP/3 server on UDP 8443 (`[::]`, dual-stack) on a thread of its own. The framework
/// is built here, so that its counters can be read from the first moment.
fn spawn_h3(
  cert: &[u8],
  key: Vec<u8>,
  data: ConnAux,
) -> rimu_ws::Result<(Http3Stats, std::thread::JoinHandle<rimu_ws::Result<()>>)> {
  let min_headers = match std::env::var("ARENA_H3_HEADERS").as_deref() {
    Ok("min") => true,
    Ok("full") | Err(_) => false,
    Ok(other) => {
      let msg = format!("ARENA_H3_HEADERS must be `min` or `full`, not `{other}`");
      return Err(std::io::Error::other(msg).into());
    }
  };
  let framework = Http3ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new(
    UringExecutor::default(),
    ChaCha20::from_std_random()?,
    TlsConfig::from_keys_pem(cert, key.as_slice())?,
  )?
  .set_data(data)
  .set_error_cb(error_cb)
  .set_http_recv_params(recv_params())
  .set_local_runtime_cb(runtime);
  let stats = framework.stats();
  let handle = std::thread::spawn(move || -> rimu_ws::Result<()> {
    let rslt = if min_headers {
      framework
        .set_content_length(false)
        .set_date(false)
        .run_in_threads("[::]:8443", router!(no_middleware)?)
    } else {
      framework.run_in_threads("[::]:8443", router!()?)
    };
    if let Err(err) = &rslt {
      eprintln!("arena-h2: the h3 server ended: {err}");
    }
    rslt
  });
  Ok((stats, handle))
}

fn error_cb(err: rimu_ws::Error) {
  if std::env::var("ARENA_LOG_ERRORS").is_ok() {
    eprintln!("arena-h2: {err}");
  }
}

fn recv_params() -> HttpRecvParams {
  if std::env::var("ARENA_PARAMS").is_ok_and(|v| v == "permissive") {
    HttpRecvParams::with_permissive_params()
  } else {
    HttpRecvParams::with_default_params()
  }
}

fn runtime() -> rimu_ws::Result<UringRuntime> {
  UringRuntime::with_params(UringParams::default())
}

/// SIGUSR1 prints the counters of the h3 workers; SIGINT and SIGTERM print them and exit.
///
/// The signals are blocked in every thread (the mask is inherited, so it is set before the first
/// thread starts) and one thread takes them with `sigwait`: no handler runs, and no worker's
/// `io_uring_enter` is interrupted.
mod stats_signals {
  use super::{Http3Stats, Http3WorkerStats};

  const REPORTED: [libc::c_int; 3] = [libc::SIGUSR1, libc::SIGINT, libc::SIGTERM];

  pub(super) struct Blocked(libc::sigset_t);

  pub(super) fn block() -> Blocked {
    // SAFETY: `set` is a plain C structure that `sigemptyset` initializes before any other use;
    // the arguments are valid for the calls and `pthread_sigmask` has no other precondition.
    unsafe {
      let mut set = core::mem::zeroed::<libc::sigset_t>();
      libc::sigemptyset(&mut set);
      for sig in REPORTED {
        libc::sigaddset(&mut set, sig);
      }
      libc::pthread_sigmask(libc::SIG_BLOCK, &set, core::ptr::null_mut());
      Blocked(set)
    }
  }

  pub(super) fn spawn_reporter(blocked: Blocked, stats: Http3Stats) {
    let _jh = std::thread::spawn(move || {
      loop {
        let mut sig: libc::c_int = 0;
        // SAFETY: `blocked.0` was initialized by `sigemptyset` and `sig` is a valid `c_int`.
        let rslt = unsafe { libc::sigwait(&blocked.0, &mut sig) };
        if rslt != 0 {
          continue;
        }
        let exits = sig != libc::SIGUSR1;
        let workers = stats.workers();
        let mut sum = Counters::default();
        for worker in &workers {
          sum.add(&Counters::of(worker));
        }
        eprintln!("h3-stats workers={} {}", workers.len(), sum.line());
        if exits {
          for (idx, worker) in workers.iter().enumerate() {
            eprintln!("h3-worker {idx} {}", Counters::of(worker).line());
          }
          std::process::exit(0);
        }
      }
    });
  }

  #[derive(Default)]
  struct Counters([u64; 12]);

  impl Counters {
    const NAMES: [&'static str; 12] = [
      "conns",
      "requests",
      "datagrams_in",
      "datagrams_out",
      "packets_out",
      "ack_only_out",
      "forwarded",
      "forward_dropped",
      "retries",
      "stateless_resets",
      "udp_send_errors",
      "handler_panics",
    ];

    fn of(worker: &Http3WorkerStats) -> Self {
      Self([
        worker.conns,
        worker.requests,
        worker.datagrams_in,
        worker.datagrams_out,
        worker.packets_out,
        worker.ack_only_out,
        worker.forwarded,
        worker.forward_dropped,
        worker.retries,
        worker.stateless_resets,
        worker.udp_send_errors,
        worker.handler_panics,
      ])
    }

    fn add(&mut self, other: &Self) {
      for (to, from) in self.0.iter_mut().zip(other.0) {
        *to = to.wrapping_add(from);
      }
    }

    fn line(&self) -> String {
      let mut rslt = String::new();
      for (name, value) in Self::NAMES.iter().zip(self.0) {
        if !rslt.is_empty() {
          rslt.push(' ');
        }
        rslt.push_str(&format!("{name}={value}"));
      }
      rslt
    }
  }
}

/// Adds `server: rimu-ws` to every response.
struct ServerHeader;

impl Middleware<ConnAux, rimu_ws::Error> for ServerHeader {
  type Aux = ();

  fn aux(&self) -> Self::Aux {}

  async fn req(
    &self,
    _: &mut ConnAux,
    _: &mut Self::Aux,
    _: &mut Request<MsgBufferString>,
  ) -> rimu_ws::Result<ControlFlow<StatusCode, ()>> {
    Ok(ControlFlow::Continue(()))
  }

  async fn res(
    &self,
    _: &mut ConnAux,
    _: &mut Self::Aux,
    res: Response<&mut MsgBufferString>,
  ) -> rimu_ws::Result<ControlFlow<StatusCode, ()>> {
    res
      .msg_data
      .headers
      .push_from_iter(Header::from_name_and_value(KnownHeaderName::Server.into(), ["rimu-ws"]))?;
    Ok(ControlFlow::Continue(()))
  }
}

#[derive(Clone, rimu_ws::Lease)]
struct ConnAux {
  dataset: Arc<VectorUsize<DatasetItem>>,
}

async fn endpoint_baseline2(state: State<'_, ConnAux>) -> rimu_ws::Result<VerbatimParams> {
  let mut sum: i64 = 0;
  for (_, value) in state.req.msg_data.uri.query_params() {
    sum = sum.wrapping_add(value.parse()?);
  }
  state.req.msg_data.clear();
  std::io::Write::write_fmt(&mut state.req.msg_data.body, format_args!("{sum}"))?;
  state.req.msg_data.headers.push_from_iter(Header::from_name_and_value(
    KnownHeaderName::ContentType.into(),
    ["text/plain"],
  ))?;
  Ok(VerbatimParams(StatusCode::Ok))
}

async fn endpoint_json(
  state: State<'_, ConnAux>,
  Path(count): Path<usize>,
) -> rimu_ws::Result<JsonReply> {
  let mut m: i64 = 1;
  for (key, value) in state.req.msg_data.uri.query_params() {
    if key == "m" {
      m = value.parse()?;
      break;
    }
  }
  let dataset = &state.data.dataset;
  state.req.msg_data.clear();
  write_json(&mut state.req.msg_data.body, dataset, count, m)?;
  Ok(JsonReply(StatusCode::Ok))
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

fn load_dataset() -> Arc<VectorUsize<DatasetItem>> {
  let path = std::env::var("DATASET_PATH").unwrap_or_else(|_| "/data/dataset.json".to_string());
  Arc::new(match std::fs::read_to_string(&path) {
    Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
    Err(_) => VectorUsize::new(),
  })
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

#[cfg(test)]
mod tests {
  use super::{DatasetItem, write_json};
  use rimu_ws::{
    collections::{ArrayVectorU8, VectorUsize},
    misc::Wrapper,
  };

  /// The serde form the endpoint used before `JsonWriter`; the writer must give the same bytes.
  fn serde_json_form(dataset: &[DatasetItem], count: usize, m: i64) -> Vec<u8> {
    let clamped = count.min(dataset.len());
    let items = dataset.iter().take(clamped).map(move |el| {
      Ok(ProcessedItem {
        id: el.id,
        name: &el.name,
        category: &el.category,
        price: el.price,
        quantity: el.quantity,
        active: el.active,
        tags: ArrayVectorU8::from_iterator(el.tags.iter().map(|tag| tag.as_str()))?,
        rating: RatingOut { score: el.rating.score, count: el.rating.count },
        total: el.price.wrapping_mul(el.quantity).wrapping_mul(m),
      })
    });
    let resp = JsonResponse { count: clamped, items: Wrapper(core::cell::RefCell::new(items)) };
    serde_json::to_vec(&resp).unwrap()
  }

  fn check(dataset: &[DatasetItem]) {
    for count in [0, 1, 2, 7, 50, 1000] {
      for m in [1, 3, -2, 0, i64::MAX] {
        let mut buf = VectorUsize::new();
        write_json(&mut buf, dataset, count, m).unwrap();
        assert_eq!(
          String::from_utf8_lossy(buf.as_slice()),
          String::from_utf8_lossy(&serde_json_form(dataset, count, m)),
          "count {count}, m {m}"
        );
      }
    }
  }

  #[test]
  fn json_matches_serde_on_the_dataset() {
    let path = std::env::var("DATASET_PATH")
      .unwrap_or_else(|_| "/mnt/nvme1tb/claude-tmp/arena-main/data/dataset.json".into());
    let Ok(text) = std::fs::read_to_string(&path) else {
      eprintln!("no dataset at {path}: skipped");
      return;
    };
    let dataset: VectorUsize<DatasetItem> = serde_json::from_str(&text).unwrap();
    assert!(dataset.len() >= 50);
    check(&dataset);
  }

  /// The dataset's numbers are integers and stay integers: the body sizes HttpArena computes for
  /// its seven (count, m) pairs.
  #[test]
  fn json_has_the_reference_sizes() {
    let path = std::env::var("DATASET_PATH")
      .unwrap_or_else(|_| "/mnt/nvme1tb/claude-tmp/arena-main/data/dataset.json".into());
    let Ok(text) = std::fs::read_to_string(&path) else {
      eprintln!("no dataset at {path}: skipped");
      return;
    };
    let dataset: VectorUsize<DatasetItem> = serde_json::from_str(&text).unwrap();
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
  fn json_matches_serde_with_escapes() {
    let text = r#"[{"id":-3,"name":"a \"quoted\" \\ name\n\u0001 é 東","category":"x/y\t","price":1,
      "quantity":3,"active":true,"tags":["","t\"",  "long tag long tag long tag long tag long"],
      "rating":{"score":-4,"count":-7}},
      {"id":9007199254740993,"name":"","category":"c","price":-9223372036854775808,"quantity":9223372036854775807,"active":false,
      "tags":[],"rating":{"score":0,"count":0}}]"#;
    let dataset: VectorUsize<DatasetItem> = serde_json::from_str(text).unwrap();
    check(&dataset);
  }

  #[derive(serde::Serialize)]
  #[serde(bound = "E: serde::Serialize")]
  struct JsonResponse<E, I>
  where
    I: Iterator<Item = rimu_ws::Result<E>>,
    E: serde::Serialize,
  {
    items: Wrapper<core::cell::RefCell<I>>,
    count: usize,
  }

  #[derive(serde::Serialize)]
  struct ProcessedItem<'any> {
    id: i64,
    name: &'any str,
    category: &'any str,
    price: i64,
    quantity: i64,
    active: bool,
    tags: ArrayVectorU8<&'any str, 6>,
    rating: RatingOut,
    total: i64,
  }

  #[derive(serde::Serialize)]
  struct RatingOut {
    score: i64,
    count: i64,
  }
}
