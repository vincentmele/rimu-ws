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
  misc::Wrapper,
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
  let mut m: f64 = 1.0;
  for (key, value) in state.req.msg_data.uri.query_params() {
    if key == "m" {
      m = f64::from(value.parse::<i32>()?);
      break;
    }
  }
  let clamped = count.min(state.data.dataset.len());
  state.req.msg_data.clear();
  let items = state.data.dataset.iter().take(clamped).map(move |el| {
    Ok(ProcessedItem {
      id: el.id,
      name: &el.name,
      category: &el.category,
      price: el.price,
      quantity: el.quantity,
      active: el.active,
      tags: ArrayVectorU8::from_iterator(el.tags.iter().map(|tag| tag.as_str()))?,
      rating: RatingOut { score: el.rating.score, count: el.rating.count },
      total: el.price * el.quantity * m,
    })
  });
  let resp = JsonResponse { count: clamped, items: Wrapper(core::cell::RefCell::new(items)) };
  serde_json::to_writer(&mut state.req.msg_data.body, &resp)?;
  Ok(JsonReply(StatusCode::Ok))
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
  price: f64,
  quantity: f64,
  active: bool,
  tags: ArrayVectorU8<String, 6>,
  rating: Rating,
}

#[derive(serde::Deserialize)]
struct Rating {
  score: f64,
  count: i64,
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
  price: f64,
  quantity: f64,
  active: bool,
  tags: ArrayVectorU8<&'any str, 6>,
  rating: RatingOut,
  total: f64,
}

#[derive(serde::Serialize)]
struct RatingOut {
  score: f64,
  count: i64,
}
