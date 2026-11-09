//! The framework end to end, over UDP on loopback: a QUIC client of tests (the client connection
//! of `quic::testing`, whose application collects what arrives on every stream) against workers
//! run by [`Http3ServerFramework::run_in_threads`].

use crate::{
  executor::{Runtime as _, UdpInbox, UdpParams, UringExecutor, UringRuntime, UringUdpSocket},
  futures::Sleep,
  http::{
    AutoStream, Header, KnownHeaderName, MsgDataMut as _, ShutdownSignal, StaticFiles, StatusCode,
    http2_server_framework::{
      Endpoint, Get, HttpRouter, RouteMatch, State, VerbatimParams, get, post,
    },
    http3_server_framework::{
      Http3ServerFramework, Http3Stats, Http3WorkerStats,
      endpoint_task::{IDLE_TRIM_AFTER, affinity, cpu_order, forward},
    },
  },
  http3::{
    H3FrameTy, H3Params, decode_frame_header,
    testing::{Response, headers_frame, response_of},
  },
  misc::SharedBytes,
  quic::{
    Cid, ConnParams, ConnState, DatagramMeta, QuicParams, RecvOutcome, SteeringProgram, StreamId,
    decode_varint,
    testing::{ClientConn, Net, Parts, SERVER_ADDR, TestApp, client_conn, server_tls_config},
  },
  rng::{ChaCha20, CryptoSeedableRng as _, Rng as _},
  sync::{Arc, AtomicU64},
  tests::_count_allocations_in,
};
use alloc::{
  format,
  string::{String, ToString as _},
  vec,
  vec::Vec,
};
use core::{
  net::{IpAddr, Ipv4Addr, SocketAddr},
  num::NonZeroUsize,
  sync::atomic::Ordering,
  time::Duration,
};
use std::{
  net::UdpSocket,
  path::PathBuf,
  sync::{Mutex, mpsc},
  thread::JoinHandle,
  time::Instant,
};

const TIMEOUT: Duration = Duration::from_secs(10);

/// What tests change in the workers.
#[derive(Clone, Debug, Default)]
pub(crate) struct TestHooks {
  /// Each worker sends the address of its socket once it bound.
  pub(crate) bound: Option<mpsc::Sender<SocketAddr>>,
  /// Replaces [`IDLE_TRIM_AFTER`].
  pub(crate) idle_trim_after: Option<Duration>,
  /// Replaces the steering program, to make its attach fail.
  pub(crate) steering: Option<fn(u8) -> SteeringProgram>,
}

// ---- endpoints

async fn baseline2(state: State<'_, ()>) -> crate::Result<VerbatimParams> {
  let mut sum: i64 = 0;
  for (_, value) in state.req.msg_data.uri.query_params() {
    sum = sum.wrapping_add(value.parse()?);
  }
  text(state, format_args!("{sum}"))
}

async fn panics(_: State<'_, ()>) -> crate::Result<VerbatimParams> {
  panic!("handler panic of a test")
}

async fn sleep(state: State<'_, ()>) -> crate::Result<VerbatimParams> {
  Sleep::new(Duration::from_millis(query(&state, "ms")))?.await?;
  text(state, format_args!("slept"))
}

async fn sleep_then_panic(state: State<'_, ()>) -> crate::Result<VerbatimParams> {
  Sleep::new(Duration::from_millis(query(&state, "ms")))?.await?;
  panic!("handler panic of a test, after a wait")
}

// The length of the body and the sum of its bytes.
async fn upload(state: State<'_, ()>) -> crate::Result<VerbatimParams> {
  let body = state.req.msg_data.body.as_slice();
  let (len, sum) = (body.len(), body.iter().map(|el| u64::from(*el)).sum::<u64>());
  text(state, format_args!("{len}:{sum}"))
}

fn query(state: &State<'_, ()>, name: &str) -> u64 {
  let mut params = state.req.msg_data.uri.query_params();
  params.find(|el| el.0 == name).and_then(|el| el.1.parse().ok()).unwrap_or(0)
}

fn text(state: State<'_, ()>, args: core::fmt::Arguments<'_>) -> crate::Result<VerbatimParams> {
  state.req.msg_data.clear();
  std::io::Write::write_fmt(&mut state.req.msg_data.body, args)?;
  let content_type = KnownHeaderName::ContentType.into();
  state
    .req
    .msg_data
    .headers
    .push_from_iter(Header::from_name_and_value(content_type, ["text/plain"]))?;
  Ok(VerbatimParams(StatusCode::Ok))
}

/// [`StaticFiles`] that keeps, if `record`, the bodies that it answers with by reference.
#[derive(Clone)]
struct Probe {
  files: StaticFiles,
  record: bool,
  seen: Arc<Mutex<Vec<SharedBytes>>>,
}

impl<D, E, S> Endpoint<D, E, S> for Probe
where
  E: From<crate::Error>,
{
  async fn auto(
    &self,
    auto_stream: &mut AutoStream<D>,
    path_defs: (u8, &[RouteMatch]),
  ) -> Result<StatusCode, E> {
    let status = Endpoint::<D, E, S>::auto(&self.files, auto_stream, path_defs).await?;
    if self.record
      && let Some(elem) = &auto_stream.shared_body
    {
      self.seen.lock().unwrap().push(elem.clone());
    }
    Ok(status)
  }
}

// ---- the server

struct Opts {
  count: Option<&'static AtomicU64>,
  date: bool,
  drain: Duration,
  h3: H3Params,
  hooks: TestHooks,
  record: bool,
  root: PathBuf,
  workers: usize,
}

impl Opts {
  fn new(name: &str) -> Self {
    Self {
      count: None,
      date: true,
      drain: Duration::from_secs(1),
      h3: H3Params::default(),
      hooks: TestHooks::default(),
      record: false,
      root: static_dir(name),
      workers: 1,
    }
  }
}

struct Served {
  addr: SocketAddr,
  errors: Arc<Mutex<Vec<String>>>,
  run: Option<JoinHandle<crate::Result<()>>>,
  seen: Arc<Mutex<Vec<SharedBytes>>>,
  signal: ShutdownSignal,
  stats: Http3Stats,
}

impl Served {
  fn errors(&self) -> Vec<String> {
    self.errors.lock().unwrap().clone()
  }

  fn worker(&self, idx: usize) -> Http3WorkerStats {
    self.stats.workers()[idx]
  }

  // Waits until `f` holds for the stats of the workers.
  fn wait_stats(&self, f: impl Fn(&[Http3WorkerStats]) -> bool) {
    let begin = Instant::now();
    while !f(&self.stats.workers()) {
      assert!(begin.elapsed() < TIMEOUT, "{:?}", self.stats.workers());
      std::thread::sleep(Duration::from_millis(5));
    }
  }
}

impl Drop for Served {
  fn drop(&mut self) {
    self.signal.trigger();
  }
}

/// A directory of static files for one test.
fn static_dir(name: &str) -> PathBuf {
  let dir = std::env::temp_dir().join(format!("rimu-h3fw-{name}-{}", std::process::id()));
  let _rslt = std::fs::remove_dir_all(&dir);
  std::fs::create_dir_all(&dir).unwrap();
  dir
}

/// A port that no UDP socket has now, for a group of `SO_REUSEPORT` sockets: a socket of tests
/// that binds port 0 with `SO_REUSEPORT` on can join the group of another socket.
fn free_port() -> u16 {
  UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn serve(opts: Opts) -> Served {
  let errors = Arc::new(Mutex::new(Vec::new()));
  let seen = Arc::new(Mutex::new(Vec::new()));
  let signal = ShutdownSignal::new();
  let (bound_tx, bound_rx) = mpsc::channel();
  let count = opts.count;
  let thread_errors = errors.clone();
  let error_cb = move |err: crate::Error| thread_errors.lock().unwrap().push(format!("{err:?}"));
  let reuseport = opts.workers > 1;
  let mut fw = Http3ServerFramework::<(), fn(crate::Error), UringExecutor, _, _, _>::new(
    UringExecutor::default(),
    ChaCha20::from_std_random().unwrap(),
    server_tls_config(),
  )
  .unwrap()
  .set_error_cb(error_cb)
  .set_date(opts.date)
  .set_h3_params(opts.h3)
  .set_local_runtimes(NonZeroUsize::new(opts.workers))
  .set_pin_workers(false)
  .set_shutdown(signal.clone(), opts.drain)
  .set_udp_params(UdpParams { reuseport, ..UdpParams::new() })
  .set_local_runtime_cb(move || {
    if let Some(elem) = count {
      _count_allocations_in(elem);
    }
    UringRuntime::new()
  });
  fw.test = TestHooks { bound: Some(bound_tx), ..opts.hooks };
  let stats = fw.stats();
  let addr =
    if reuseport { format!("127.0.0.1:{}", free_port()) } else { "127.0.0.1:0".to_string() };
  let probe =
    Probe { files: StaticFiles::new(&opts.root).unwrap(), record: opts.record, seen: seen.clone() };
  let run = std::thread::spawn(move || {
    let router = HttpRouter::paths(crate::paths!(
      ("/baseline2", get(baseline2)),
      ("/panic", get(panics)),
      ("/sleep", get(sleep)),
      ("/sleep-panic", get(sleep_then_panic)),
      ("/static/{*file}", Get(probe)),
      ("/upload", post(upload)),
    ))?;
    fw.run_in_threads(&addr, router)
  });
  let addr = bound_rx.recv_timeout(TIMEOUT).expect("the server did not bind");
  for _ in 1..opts.workers {
    assert_eq!(bound_rx.recv_timeout(TIMEOUT).unwrap(), addr);
  }
  Served { addr, errors, run: Some(run), seen, signal, stats }
}

// ---- the client

/// A client of tests over a UDP socket of its own.
struct Client {
  app: TestApp,
  conn: ClientConn,
  epoch: Instant,
  parts: Parts,
  rx: Vec<u8>,
  server: SocketAddr,
  socket: UdpSocket,
}

impl Client {
  fn new(server: SocketAddr) -> Self {
    let socket = UdpSocket::bind(SocketAddr::new(server.ip(), 0)).unwrap();
    let mut rng = ChaCha20::from_std_random().unwrap();
    let (mut local, mut original) = ([0; 8], [0; 8]);
    rng.fill_slice(&mut local);
    rng.fill_slice(&mut original);
    let mut parts = Parts::new();
    let cids = (Cid::new(&local).unwrap(), Cid::new(&original).unwrap());
    let conn =
      client_conn(&ConnParams::default(), cids.0, cids.1, &mut rng, 0, &mut parts.pools, |_| {});
    Self {
      app: TestApp::default(),
      conn,
      epoch: Instant::now(),
      parts,
      rx: vec![0; 1 << 16],
      server,
      socket,
    }
  }

  /// A client whose handshake is done.
  fn connect(server: SocketAddr) -> Self {
    let mut this = Self::new(server);
    assert!(this.run_until(|el| el.conn.state() == ConnState::Confirmed), "no handshake");
    this
  }

  fn now_us(&self) -> u64 {
    u64::try_from(self.epoch.elapsed().as_micros()).unwrap()
  }

  /// Sends what the connection has to send, then takes what arrives for at most `wait` (or until
  /// the next timer of the connection), and runs the timers that are due.
  fn step(&mut self, wait: Duration) {
    let now_us = self.now_us();
    let _ = self.conn.flush(now_us, &mut self.parts.tx, &mut self.app, &mut self.parts.pools);
    loop {
      let next =
        self.parts.tx.pending().next().map(|el| (el.id, el.bytes.to_vec(), el.segment_size));
      let Some((id, bytes, segment)) = next else {
        break;
      };
      self.parts.tx.mark_submitted(id);
      self.parts.tx.release(id);
      for datagram in bytes.chunks(usize::from(segment).max(1)) {
        let _ = self.socket.send_to(datagram, self.server).unwrap();
      }
    }
    let until_timer = self
      .conn
      .next_deadline()
      .map_or(wait, |el| Duration::from_micros(el.saturating_sub(now_us)).min(wait));
    self.socket.set_read_timeout(Some(until_timer.max(Duration::from_micros(100)))).unwrap();
    loop {
      match self.socket.recv_from(&mut self.rx) {
        Ok((len, _)) => {
          let now_us = self.now_us();
          let meta = DatagramMeta { peer: SERVER_ADDR, local: None, segment_size: None };
          let datagram = &mut self.rx[..len];
          let _ =
            self.conn.recv_datagram(now_us, datagram, meta, &mut self.app, &mut self.parts.pools);
          self.socket.set_nonblocking(true).unwrap();
        }
        Err(err)
          if matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
          ) =>
        {
          break;
        }
        Err(err) => panic!("{err}"),
      }
    }
    self.socket.set_nonblocking(false).unwrap();
    let now_us = self.now_us();
    if self.conn.next_deadline().is_some_and(|el| el <= now_us) {
      self.conn.on_timeout(now_us, &mut self.app, &mut self.parts.pools);
    }
  }

  /// Steps until `f` holds, for at most [`TIMEOUT`]. Returns if it held.
  fn run_until(&mut self, f: impl Fn(&Self) -> bool) -> bool {
    let begin = Instant::now();
    while !f(self) {
      if begin.elapsed() > TIMEOUT {
        return false;
      }
      self.step(Duration::from_millis(5));
    }
    true
  }

  /// Opens a request stream and writes `bytes` on it, with `fin`.
  fn send(&mut self, bytes: &[u8], fin: bool) -> StreamId {
    let now_us = self.now_us();
    let rslt = self.conn.with_ctx(now_us, &mut self.parts.pools, |cx| {
      let id = cx.open_bidi()?;
      cx.write(id, bytes, fin)?;
      Ok::<_, crate::Error>(id)
    });
    rslt.unwrap()
  }

  /// Sends a request of `method` for `path` with `extra` fields, without a body.
  fn request(&mut self, method: &[u8], path: &str, extra: &[(&[u8], &[u8])]) -> StreamId {
    let mut fields: Vec<(&[u8], &[u8])> = vec![
      (b":method", method),
      (b":scheme", b"https"),
      (b":authority", b"localhost"),
      (b":path", path.as_bytes()),
    ];
    fields.extend_from_slice(extra);
    self.send(&headers_frame(&fields), true)
  }

  fn done(&self, id: StreamId) -> bool {
    self.app.streams.get(&id.0).is_some_and(|el| el.fin)
  }

  /// The response of stream `id`, once complete.
  fn wait(&mut self, id: StreamId) -> Response {
    assert!(self.run_until(|el| el.done(id)), "no response on {id:?}");
    response_of(&self.app, id).unwrap()
  }

  fn get(&mut self, path: &str, extra: &[(&[u8], &[u8])]) -> Response {
    let id = self.request(b"GET", path, extra);
    self.wait(id)
  }

  /// The frames of the control stream of the server: type and payload.
  fn control_frames(&self) -> Vec<(u64, Vec<u8>)> {
    let Some(log) = self.app.streams.get(&3) else {
      return Vec::new();
    };
    let (_, len) = decode_varint(&log.data).unwrap();
    let mut rest = &log.data[len..];
    let mut rslt = Vec::new();
    while let Some((ty, len, header_len)) = decode_frame_header(rest).unwrap() {
      let len = usize::try_from(len).unwrap();
      if rest.len() < header_len + len {
        break;
      }
      rslt.push((ty.code(), rest[header_len..header_len + len].to_vec()));
      rest = &rest[header_len + len..];
    }
    rslt
  }

  /// Steps until `f` holds for the stats of the workers of `served`.
  fn wait_server(&mut self, served: &Served, f: impl Fn(&[Http3WorkerStats]) -> bool) {
    assert!(self.run_until(|_| f(&served.stats.workers())), "{:?}", served.stats.workers());
  }

  /// The CONNECTION_CLOSE of the server, once it arrived.
  fn peer_close(&self) -> Option<(bool, u64)> {
    self.conn.test_client().and_then(|el| el.peer_close)
  }
}

impl Drop for Client {
  fn drop(&mut self) {
    self.conn.abort(&mut self.app, &mut self.parts.pools);
  }
}

fn status(rsp: &Response) -> &[u8] {
  rsp.field(b":status").unwrap_or_default()
}

// ---- tests

// Brief step 1: `/baseline2?a=1&b=1` of the router is answered `2` over HTTP/3, with the fields of
// the endpoint, `content-length` and `date`; a path with no route gets 404.
#[cfg_attr(miri, ignore)]
#[test]
fn baseline2_route_answers_2() {
  let served = serve(Opts::new("baseline2"));
  let mut client = Client::connect(served.addr);
  let rsp = client.get("/baseline2?a=1&b=1", &[]);
  assert_eq!((status(&rsp), rsp.body.as_slice()), (&b"200"[..], &b"2"[..]));
  assert_eq!(rsp.field(b"content-type"), Some(&b"text/plain"[..]));
  assert_eq!(rsp.field(b"content-length"), Some(&b"1"[..]));
  assert_eq!(rsp.frames, [H3FrameTy::Headers.code(), H3FrameTy::Data.code()]);
  let rsp = client.get("/baseline2?a=40&b=2", &[]);
  assert_eq!(rsp.body, b"42");
  let rsp = client.get("/nothing-here", &[]);
  assert_eq!((status(&rsp), rsp.field(b"content-length")), (&b"404"[..], Some(&b"0"[..])));
  assert!(rsp.body.is_empty());
  assert_eq!(served.worker(0).requests, 3);
  assert_eq!(client.conn.state(), ConnState::Confirmed);
  assert!(served.errors().is_empty(), "{:?}", served.errors());
}

// Brief step 1 and ruling T14-a: the `.br` twin of a file is served with `content-encoding: br`
// and `vary: accept-encoding`, its bytes by reference: while the response is in flight the cached
// buffer has a holder more than the cache and the test (the stream), which lets it go once the
// client acknowledged it.
#[cfg_attr(miri, ignore)]
#[test]
fn static_file_br_twin_served_by_reference() {
  let mut opts = Opts::new("brtwin");
  let css: Vec<u8> = (0..20_000u32).map(|el| (el % 251) as u8).collect();
  let br: Vec<u8> = (0..9_000u32).map(|el| (el % 241) as u8).collect();
  std::fs::write(opts.root.join("a.css"), &css).unwrap();
  std::fs::write(opts.root.join("a.css.br"), &br).unwrap();
  opts.record = true;
  let served = serve(opts);
  let mut client = Client::connect(served.addr);
  let accept = [(&b"accept-encoding"[..], &b"br;q=1, gzip;q=0.8"[..])];
  let id = client.request(b"GET", "/static/a.css", &accept);
  assert!(client.run_until(|el| el.done(id)));
  // The FIN arrived; what carried it is not acknowledged yet
  let held = served.seen.lock().unwrap().pop().unwrap();
  assert_eq!(held.as_slice(), br.as_slice());
  assert!(held.strong_count() > 2, "{}", held.strong_count());
  let rsp = response_of(&client.app, id).unwrap();
  assert_eq!(status(&rsp), b"200");
  assert_eq!(rsp.field(b"content-encoding"), Some(&b"br"[..]));
  assert_eq!(rsp.field(b"vary"), Some(&b"accept-encoding"[..]));
  assert_eq!(rsp.field(b"content-type"), Some(&b"text/css"[..]));
  assert_eq!(rsp.field(b"content-length"), Some(br.len().to_string().as_bytes()));
  assert_eq!(rsp.body, br);
  // Acknowledged: the cache and the test are left
  assert!(client.run_until(|_| held.strong_count() == 2), "{}", held.strong_count());
  // Without `br` the file itself, from the same cache
  let rsp = client.get("/static/a.css", &[]);
  assert_eq!((rsp.field(b"content-encoding"), rsp.body.as_slice()), (None, css.as_slice()));
  assert_eq!(rsp.field(b"vary"), Some(&b"accept-encoding"[..]));
  assert_eq!(status(&client.get("/static/missing.css", &[])), b"404");
}

// Brief step 1 and review focus 4: a POST of 2 MiB, past the stream window of 1 MiB, from a client
// that never says it is blocked, reaches the handler whole.
#[cfg_attr(miri, ignore)]
#[test]
fn post_body_over_window_reaches_handler() {
  let mut opts = Opts::new("upload");
  opts.h3 = H3Params { max_request_body: 4 << 20, ..H3Params::default() };
  let served = serve(opts);
  let mut client = Client::connect(served.addr);
  let body: Vec<u8> = (0..(2u32 << 20)).map(|el| (el % 253) as u8).collect();
  let len = body.len().to_string();
  let fields: [(&[u8], &[u8]); 5] = [
    (b":method", b"POST"),
    (b":scheme", b"https"),
    (b":authority", b"localhost"),
    (b":path", b"/upload"),
    (b"content-length", len.as_bytes()),
  ];
  let mut request = headers_frame(&fields);
  request.extend_from_slice(&crate::http3::testing::data_frame(&body));
  let id = client.send(&request, true);
  let rsp = client.wait(id);
  let sum: u64 = body.iter().map(|el| u64::from(*el)).sum();
  assert_eq!(status(&rsp), b"200");
  assert_eq!(rsp.body, format!("{}:{sum}", body.len()).into_bytes());
}

// Brief step 1 and ruling T14-g: a handler that panics, inline or once resumed, gets 500 on its
// stream; the other streams of the connection, and the connection, go on.
#[cfg_attr(miri, ignore)]
#[test]
fn handler_panic_answers_500_and_other_streams_continue() {
  let served = serve(Opts::new("panic"));
  let mut client = Client::connect(served.addr);
  let panicked = client.request(b"GET", "/panic", &[]);
  let later = client.request(b"GET", "/sleep-panic?ms=20", &[]);
  let fine = client.request(b"GET", "/baseline2?a=2&b=3", &[]);
  for (id, expected) in [(panicked, &b"500"[..]), (later, b"500"), (fine, b"200")] {
    let rsp = client.wait(id);
    assert_eq!(status(&rsp), expected, "{id:?}");
  }
  assert_eq!(response_of(&client.app, fine).unwrap().body, b"5");
  assert_eq!(client.get("/baseline2?a=1&b=1", &[]).body, b"2");
  assert_eq!(client.conn.state(), ConnState::Confirmed);
  client.wait_server(&served, |el| el[0].handler_panics == 2);
  assert_eq!(served.worker(0).parked, 0);
}

// Brief step 1 and ruling T14-d: a handler that waits is parked, the requests after it are
// answered meanwhile, and it is answered once its timer wakes it, through its connection.
#[cfg_attr(miri, ignore)]
#[test]
fn pending_handler_parks_and_resumes() {
  let served = serve(Opts::new("park"));
  let mut client = Client::connect(served.addr);
  let begin = Instant::now();
  let parked = client.request(b"GET", "/sleep?ms=200", &[]);
  let quick = client.request(b"GET", "/baseline2?a=1&b=1", &[]);
  let quick = client.wait(quick);
  assert_eq!(quick.body, b"2");
  assert!(!client.done(parked));
  assert_eq!(served.worker(0).parked, 1);
  let rsp = client.wait(parked);
  assert!(begin.elapsed() >= Duration::from_millis(200));
  assert_eq!((status(&rsp), rsp.body.as_slice()), (&b"200"[..], &b"slept"[..]));
  client.wait_server(&served, |el| el[0].parked == 0);
  // Many at once, each in a slot of its own
  let ids: Vec<StreamId> = (0..32).map(|_| client.request(b"GET", "/sleep?ms=30", &[])).collect();
  for id in ids {
    assert_eq!(client.wait(id).body, b"slept");
  }
  assert!(served.errors().is_empty(), "{:?}", served.errors());
}

// Ruling T14-d: a parked request that the client abandons, or whose connection closes, is dropped
// with its future; a wake that finds its connection gone is ignored.
#[cfg_attr(miri, ignore)]
#[test]
fn abandoned_and_orphaned_parked_requests_are_dropped() {
  let served = serve(Opts::new("orphan"));
  let mut client = Client::connect(served.addr);
  let id = client.request(b"GET", "/sleep?ms=5000", &[]);
  client.wait_server(&served, |el| el[0].parked == 1);
  let now_us = client.now_us();
  client.conn.with_ctx(now_us, &mut client.parts.pools, |cx| cx.reset(id, 0x10c));
  client.step(Duration::from_millis(1));
  client.wait_server(&served, |el| el[0].parked == 0);
  let _id = client.request(b"GET", "/sleep?ms=100", &[]);
  client.wait_server(&served, |el| el[0].parked == 1);
  let now_us = client.now_us();
  client.conn.close_app(now_us, 0x100);
  client.step(Duration::from_millis(1));
  client.wait_server(&served, |el| el[0].parked == 0 && el[0].conns == 0);
  // The timer of the dropped future fires into nothing; the next client is served
  std::thread::sleep(Duration::from_millis(150));
  let mut client = Client::connect(served.addr);
  assert_eq!(client.get("/baseline2?a=1&b=1", &[]).body, b"2");
  assert!(served.errors().is_empty(), "{:?}", served.errors());
}

// Brief step 1: `date` is sent by default (RFC 9110 section 6.6.1), as an IMF-fixdate, and not
// with `set_date(false)`.
#[cfg_attr(miri, ignore)]
#[test]
fn date_header_toggles() {
  let served = serve(Opts::new("date-on"));
  let mut client = Client::connect(served.addr);
  let rsp = client.get("/baseline2?a=1&b=1", &[]);
  let date = rsp.field(b"date").unwrap();
  assert_eq!(date.len(), 29);
  assert!(date.ends_with(b" GMT") && date[3] == b',', "{date:?}");
  drop((client, served));
  let mut opts = Opts::new("date-off");
  opts.date = false;
  let served = serve(opts);
  let mut client = Client::connect(served.addr);
  let rsp = client.get("/baseline2?a=1&b=1", &[]);
  assert_eq!((rsp.field(b"date"), rsp.body.as_slice()), (None, &b"2"[..]));
}

// Brief step 1: the static files module moved to `http`, re-exported where it was: the old path
// names the same type, and it serves a `.br` twin through a router of HTTP/2 as before.
#[cfg_attr(miri, ignore)]
#[test]
fn h2_static_files_tests_still_pass() {
  use crate::{
    executor::StdRuntime,
    http::{Method, MsgBufferString, Request, http2_server_framework},
  };
  let root = static_dir("h2-static");
  std::fs::write(root.join("a.js"), b"plain").unwrap();
  std::fs::write(root.join("a.js.br"), b"BROTLI").unwrap();
  let files: http2_server_framework::StaticFiles = StaticFiles::new(&root).unwrap();
  let router = HttpRouter::paths(crate::paths!(("/static/{*file}", Get(files)))).unwrap();
  StdRuntime::new().block_on(async {
    let req = Request::new(Method::Get, MsgBufferString::default());
    let mut auto_stream = AutoStream::new((), IpAddr::V4(Ipv4Addr::LOCALHOST), None, req);
    auto_stream.req.msg_data.uri.reset().push_str("http://localhost/static/a.js");
    let header = Header::from_name_and_value("accept-encoding", ["br"]);
    auto_stream.req.msg_data.headers.push_from_iter(header).unwrap();
    let matches = router.router.find("/static/a.js").unwrap().data().0;
    let status = Endpoint::<(), crate::Error, ()>::auto(&router, &mut auto_stream, (0, &matches))
      .await
      .unwrap();
    assert_eq!(status, StatusCode::Ok);
    let headers = &auto_stream.req.msg_data.headers;
    assert_eq!(headers.get_by_name(b"content-encoding").unwrap().value, "br");
    assert_eq!(auto_stream.shared_body.unwrap().as_slice(), b"BROTLI");
  });
}

// Brief step 1 (spec section 5.12): on shutdown the connection is sent GOAWAY, the request under
// way finishes, then the connection closes with H3_NO_ERROR and the server returns.
#[cfg_attr(miri, ignore)]
#[test]
fn graceful_shutdown_drains_in_flight() {
  let mut opts = Opts::new("shutdown");
  opts.drain = Duration::from_secs(3);
  let mut served = serve(opts);
  let mut client = Client::connect(served.addr);
  let id = client.request(b"GET", "/sleep?ms=300", &[]);
  client.wait_server(&served, |el| el[0].parked == 1);
  served.signal.trigger();
  assert!(client.run_until(|el| el.control_frames().iter().any(|frame| frame.0 == 0x07)));
  assert!(!client.done(id));
  let rsp = client.wait(id);
  assert_eq!((status(&rsp), rsp.body.as_slice()), (&b"200"[..], &b"slept"[..]));
  assert!(client.run_until(|el| el.peer_close().is_some()));
  assert_eq!(client.peer_close(), Some((true, 0x100)));
  let begin = Instant::now();
  let run = served.run.take().unwrap();
  while !run.is_finished() {
    assert!(begin.elapsed() < TIMEOUT, "the server did not return");
    std::thread::sleep(Duration::from_millis(5));
  }
  run.join().unwrap().unwrap();
  assert!(served.errors().is_empty(), "{:?}", served.errors());
}

// A program that the kernel refuses: it does not end with a return.
fn broken_program(_: u8) -> SteeringProgram {
  [libc::sock_filter { code: 0, jt: 0, jf: 0, k: 0 }; crate::quic::STEERING_PROGRAM_LEN]
}

// Brief step 1 and ruling T14-f: if the steering program can not be attached, the error callback
// is told once and every worker runs on the hash of the kernel, without steering or balancing:
// clients are served by the worker that their first datagram reached.
#[cfg_attr(miri, ignore)]
#[test]
fn cbpf_attach_failure_falls_back_to_kernel_hash() {
  let mut opts = Opts::new("cbpf");
  opts.workers = 2;
  opts.hooks.steering = Some(broken_program);
  let served = serve(opts);
  let mut clients: Vec<Client> = (0..4).map(|_| Client::connect(served.addr)).collect();
  for client in &mut clients {
    assert_eq!(client.get("/baseline2?a=1&b=1", &[]).body, b"2");
  }
  let errors = served.errors();
  assert_eq!(errors.len(), 1, "{errors:?}");
  served.wait_stats(|el| el.iter().map(|stats| stats.conns).sum::<u64>() == 4);
  for worker in served.stats.workers() {
    assert!(!worker.cid_steering, "{worker:?}");
    assert_eq!((worker.forwarded, worker.forward_dropped), (0, 0), "{worker:?}");
  }
  // Each connection is on the worker that its CID names
  let on_worker = |client: &Client| client.conn.peer_cid().as_slice()[0];
  let total: u64 = served.stats.workers().iter().map(|el| el.requests).sum();
  assert_eq!(total, 4);
  assert!(clients.iter().all(|el| on_worker(el) < 2));
}

// Ruling T14-c: with steering on, a second client goes to the other worker (balancing), and the
// first CIDs of the two workers differ beyond the byte that names the worker: each worker has a
// generator of its own, derived from the one of the process.
#[cfg_attr(miri, ignore)]
#[test]
fn workers_have_generators_of_their_own() {
  let mut opts = Opts::new("rng");
  opts.workers = 2;
  let served = serve(opts);
  let mut first = Client::connect(served.addr);
  served.wait_stats(|el| el.iter().map(|stats| stats.conns).sum::<u64>() == 1);
  let mut second = Client::connect(served.addr);
  for client in [&mut first, &mut second] {
    assert_eq!(client.get("/baseline2?a=1&b=1", &[]).body, b"2");
  }
  let (lhs, rhs) = (first.conn.peer_cid().as_slice(), second.conn.peer_cid().as_slice());
  assert_ne!(lhs[0], rhs[0], "both on worker {}", lhs[0]);
  assert_ne!(lhs[1..], rhs[1..]);
  assert!(served.stats.workers().iter().all(|el| el.cid_steering));
  assert!(served.errors().is_empty(), "{:?}", served.errors());
}

// Ruling T14-e: a datagram for a worker whose inbox does not take it, or for a worker that is not
// there, is dropped, and the place that it took on that worker is given back.
#[cfg_attr(miri, ignore)]
#[test]
fn forward_dropped_gives_back_the_place() {
  let mut net = Net::new(2, QuicParams::default(), &TestApp::default());
  // Worker 0 is the busier: the first Initial of a client that reaches it goes to worker 1
  net.loads.placed(0);
  let client = net.add_client();
  let mut datagrams = net.client_datagrams(client);
  let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000);
  let meta = DatagramMeta { peer, local: None, segment_size: None };
  let closed = UringRuntime::new().unwrap().block_on(async {
    let params = UdpParams { reuseport: false, ..UdpParams::new() };
    let socket = UringUdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), &params);
    socket.unwrap().inbox()
  });
  let now_us = net.now_us;
  for inboxes in [vec![closed.clone(), closed.clone()], vec![closed]] {
    let server = &mut net.servers[0];
    let outcome = server.endpoint.recv(now_us, &mut datagrams[0], meta, &mut server.app);
    assert_eq!(outcome, RecvOutcome::Forward { worker: 1 });
    assert_eq!(net.loads.load(1), 1);
    let inboxes: Vec<UdpInbox> = inboxes;
    assert!(!forward(&mut net.servers[0].endpoint, &inboxes, &datagrams[0], meta, 1));
    assert_eq!(net.loads.load(1), 0);
  }
}

// Ruling T14-e: a worker that has had no connection for a while trims its pools, once.
#[cfg_attr(miri, ignore)]
#[test]
fn idle_worker_trims_its_pools() {
  assert_eq!(IDLE_TRIM_AFTER, Duration::from_secs(1));
  let mut opts = Opts::new("idle");
  opts.hooks.idle_trim_after = Some(Duration::from_millis(100));
  let served = serve(opts);
  served.wait_stats(|el| el[0].idle_trims == 1);
  let mut client = Client::connect(served.addr);
  assert_eq!(client.get("/baseline2?a=1&b=1", &[]).body, b"2");
  let now_us = client.now_us();
  client.conn.close_app(now_us, 0x100);
  client.step(Duration::from_millis(1));
  client.wait_server(&served, |el| el[0].conns == 0 && el[0].idle_trims == 2);
  std::thread::sleep(Duration::from_millis(300));
  assert_eq!(served.worker(0).idle_trims, 2);
}

// Brief step 1 (zero allocations after warm-up): once warm, a round of requests (inline routes,
// static files by reference and parked handlers) allocates nothing on the thread of the worker.
#[cfg_attr(miri, ignore)]
#[test]
fn framework_steady_state_allocates_nothing_after_warmup() {
  static WORKER: AtomicU64 = AtomicU64::new(0);
  let mut opts = Opts::new("alloc");
  std::fs::write(opts.root.join("a.css"), vec![b'c'; 5_000]).unwrap();
  std::fs::write(opts.root.join("a.css.br"), vec![b'b'; 3_000]).unwrap();
  opts.count = Some(&WORKER);
  let served = serve(opts);
  let mut client = Client::connect(served.addr);
  let accept = [(&b"accept-encoding"[..], &b"br;q=1, gzip;q=0.8"[..])];
  let round = |client: &mut Client, requests: usize| {
    let mut pending = Vec::new();
    let mut sent = 0;
    while sent < requests || !pending.is_empty() {
      while sent < requests && pending.len() < 16 {
        let id = match sent % 4 {
          0 => client.request(b"GET", "/baseline2?a=1&b=1", &[]),
          1 => client.request(b"GET", "/static/a.css", &accept),
          2 => client.request(b"GET", "/static/a.css", &[]),
          _ => client.request(b"GET", "/sleep?ms=1", &[]),
        };
        pending.push(id);
        sent += 1;
      }
      client.step(Duration::from_millis(2));
      pending.retain(|id| {
        if client.done(*id) {
          let log = client.app.streams.remove(&id.0).unwrap();
          assert!(log.data.len() > 4, "{id:?}");
          false
        } else {
          true
        }
      });
    }
  };
  round(&mut client, 400);
  // As many requests at once as the measured round can have: the pools reach the sizes that it
  // may need. Parked ones hold their buffers at once (requests answered inline reuse one), with a
  // path longer than any of the round and its field
  for (path, extra) in [
    ("/sleep?ms=20&padding=0123456789", &accept[..]),
    ("/static/a.css", &accept[..]),
    ("/static/a.css", &[]),
  ] {
    let ids: Vec<StreamId> = (0..16).map(|_| client.request(b"GET", path, extra)).collect();
    for id in ids {
      let _rsp = client.wait(id);
      let _log = client.app.streams.remove(&id.0);
    }
  }
  // The static files are checked against the disk once a second: once more here, not in the
  // measured round
  std::thread::sleep(Duration::from_millis(1100));
  round(&mut client, 100);
  let before = WORKER.load(Ordering::Relaxed);
  let begin = Instant::now();
  round(&mut client, 400);
  let allocations = WORKER.load(Ordering::Relaxed) - before;
  assert!(begin.elapsed() < Duration::from_millis(900), "{:?}", begin.elapsed());
  assert_eq!(allocations, 0);
  assert!(served.errors().is_empty(), "{:?}", served.errors());
}

// `run_local` serves one worker on the runtime of the current thread, and returns on shutdown.
#[cfg_attr(miri, ignore)]
#[test]
fn run_local_serves_on_the_current_runtime() {
  let signal = ShutdownSignal::new();
  let (bound_tx, bound_rx) = mpsc::channel();
  let mut fw = Http3ServerFramework::<(), fn(crate::Error), UringExecutor, _, _, _>::new(
    UringExecutor::default(),
    ChaCha20::from_std_random().unwrap(),
    server_tls_config(),
  )
  .unwrap()
  .set_shutdown(signal.clone(), Duration::from_secs(1))
  .set_udp_params(UdpParams { reuseport: false, ..UdpParams::new() });
  fw.test = TestHooks { bound: Some(bound_tx), ..TestHooks::default() };
  let run = std::thread::spawn(move || {
    let router = HttpRouter::paths(crate::paths!(("/baseline2", get(baseline2))))?;
    UringRuntime::new()?.block_on(fw.run_local("127.0.0.1:0", router))
  });
  let addr = bound_rx.recv_timeout(TIMEOUT).unwrap();
  let mut client = Client::connect(addr);
  assert_eq!(client.get("/baseline2?a=20&b=22", &[]).body, b"42");
  signal.trigger();
  assert!(client.run_until(|el| el.peer_close().is_some()));
  run.join().unwrap().unwrap();
}

// Spec section 5.2: the order of the CPUs that workers are pinned to lists each CPU of the process
// once, the first thread of each physical core before the others; a thread pinned to one runs
// there only.
#[cfg_attr(miri, ignore)]
#[test]
fn workers_are_pinned_physical_cores_first() {
  let allowed = affinity::allowed();
  let order = cpu_order();
  let mut sorted = order.clone();
  sorted.sort_unstable();
  assert_eq!(sorted, allowed);
  let first_of_core = |cpu: usize| {
    let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
    let list = std::fs::read_to_string(path).unwrap_or_default();
    list
      .trim()
      .split([',', '-'])
      .next()
      .and_then(|el| el.parse::<usize>().ok())
      .is_none_or(|el| el == cpu)
  };
  let firsts = order.iter().take_while(|el| first_of_core(**el)).count();
  assert!(order[firsts..].iter().all(|el| !first_of_core(*el)), "{order:?}");
  let cpu = order[0];
  std::thread::spawn(move || {
    affinity::pin(cpu).unwrap();
    assert_eq!(affinity::allowed(), [cpu]);
  })
  .join()
  .unwrap();
}
