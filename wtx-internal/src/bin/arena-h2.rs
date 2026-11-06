//! HttpArena HTTP/2 server: `/baseline2` and `/json/{count}` on h2c (8082) and h2 over TLS (8443),
//! served by the HTTP/2 server framework on the io_uring executor. Used by `.scripts/h2-bench.sh`.
//!
//! Environment: `CERT_DIR` (default `/certs`, with `server.crt` and `server.key`), `DATASET_PATH`
//! (default `/data/dataset.json`), `STATIC_DIR` (default `/data/static`), `ARENA_PARAMS`
//! (`permissive` for `HttpRecvParams::with_permissive_params`, as upstream's wtx-http2 entry does;
//! otherwise the library defaults).

use core::ops::ControlFlow;
use rimu_ws::{
  collections::{ArrayVectorU8, VectorUsize},
  executor::{UringExecutor, UringParams, UringRuntime},
  http::{
    Header, HttpRecvParams, KnownHeaderName, MsgBufferString, MsgDataMut as _, Request, Response,
    StatusCode,
    http2_server_framework::{
      Http2ServerFramework, HttpRouter, JsonReply, Middleware, Path, State, VerbatimParams, get,
    },
  },
  misc::JsonWriter,
  rng::{ChaCha20, CryptoSeedableRng as _},
  sync::Arc,
  tls::TlsConfig,
};

macro_rules! router {
  () => {
    HttpRouter::new(
      rimu_ws::paths!(
        ("/baseline2", get(endpoint_baseline2)),
        ("/json/{count}", get(endpoint_json))
      ),
      ServerHeader,
    )
  };
}

fn main() -> rimu_ws::Result<()> {
  let dataset = load_dataset();
  let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "/certs".into());
  let tls_enabled = std::path::Path::new(&cert_dir).join("server.crt").exists();
  let tls = if tls_enabled {
    let data = dataset.clone();
    let cert = std::fs::read(format!("{cert_dir}/server.crt"))?;
    let key = std::fs::read(format!("{cert_dir}/server.key"))?;
    Some(std::thread::spawn(move || -> rimu_ws::Result<()> {
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
    }))
  } else {
    eprintln!("arena-h2: no {cert_dir}/server.crt, TLS on 8443 disabled");
    None
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
  Ok(())
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
  w.raw(b"{\"items\":[")?;
  for (idx, el) in dataset.iter().take(clamped).enumerate() {
    w.raw(if idx == 0 { b"{\"id\":" } else { b",{\"id\":" })?;
    w.i64(el.id)?;
    w.raw(b",\"name\":\"")?;
    w.str_contents(&el.name)?;
    w.raw(b"\",\"category\":\"")?;
    w.str_contents(&el.category)?;
    w.raw(b"\",\"price\":")?;
    w.i64(el.price)?;
    w.raw(b",\"quantity\":")?;
    w.i64(el.quantity)?;
    w.raw(if el.active { b",\"active\":true,\"tags\":[" } else { b",\"active\":false,\"tags\":[" })?;
    for (tag_idx, tag) in el.tags.iter().enumerate() {
      w.raw(if tag_idx == 0 { b"\"" } else { b",\"" })?;
      w.str_contents(tag)?;
      w.raw(b"\"")?;
    }
    w.raw(b"],\"rating\":{\"score\":")?;
    w.i64(el.rating.score)?;
    w.raw(b",\"count\":")?;
    w.i64(el.rating.count)?;
    w.raw(b"},\"total\":")?;
    w.i64(el.price.wrapping_mul(el.quantity).wrapping_mul(m))?;
    w.raw(b"}")?;
  }
  w.raw(b"],\"count\":")?;
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
    let pairs: [(usize, i32, usize); 7] =
      [(1, 3, 203), (5, 7, 888), (10, 2, 1695), (15, 5, 2556), (25, 4, 4190), (40, 8, 6707), (50, 6, 8397)];
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
