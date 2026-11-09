//! The framework end to end, over UDP on loopback: a QUIC client of tests (the client connection
//! of `quic::testing`, whose application collects what arrives on every stream) against workers
//! run by [`Http3ServerFramework::run_in_threads`].

use crate::{
  collections::{ArrayVectorCopy, VectorUsize},
  executor::{Runtime as _, UdpInbox, UdpParams, UringExecutor, UringRuntime, UringUdpSocket},
  futures::Sleep,
  http::{
    AutoStream, Header, KnownHeaderName, ManualStream, MsgBufferString, MsgDataMut as _, Request,
    Response as HttpResponse, ShutdownSignal, StaticFiles, StatusCode,
    http2_server_framework::{
      Endpoint, EndpointNode, Get, HttpRouter, Middleware, RouteMatch, State, VerbatimParams, get,
      post,
    },
    http3_server_framework::{
      Http3ManualStream, Http3ServerFramework, Http3Stats, Http3WorkerStats,
      endpoint_task::{IDLE_TRIM_AFTER, affinity, cpu_order, forward},
      router_handler::{SlotPoll, TaskSlots},
    },
  },
  http3::{
    H3FrameTy, H3Params, decode_frame_header,
    testing::{Response, headers_frame, response_of},
  },
  misc::SharedBytes,
  quic::{
    Cid, ConnHandle, ConnParams, ConnState, DatagramMeta, QuicParams, RecvOutcome, SteeringProgram,
    StreamId, decode_varint,
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
  ops::ControlFlow,
  pin::Pin,
  sync::atomic::Ordering,
  task::{Context, Poll, Waker},
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
  /// Each idle trim of a worker pushes the sizes of its pools before and after it.
  pub(crate) trims: Option<Arc<Mutex<Vec<(PoolSizes, PoolSizes)>>>>,
}

/// The sizes of the pools of a worker that an idle trim frees down: free connection states of the
/// QUIC pools, TLS handshake states of the thread and boxes of the HTTP/3 connection layer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PoolSizes {
  /// Free states of QUIC connections.
  pub(crate) quic_conns: usize,
  /// Free TLS handshake states of the thread.
  pub(crate) tls_states: usize,
  /// Free boxes of HTTP/3 connections.
  pub(crate) h3_conns: usize,
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

async fn manual(_: ManualStream<(), Http3ManualStream>) -> crate::Result<()> {
  Ok(())
}

/// Answers any method with `status`, `content-type: text/plain` and `body`.
#[derive(Clone, Copy)]
struct Status {
  body: &'static [u8],
  status: StatusCode,
}

impl<D, E, S> Endpoint<D, E, S> for Status
where
  E: From<crate::Error>,
{
  async fn auto(
    &self,
    auto_stream: &mut AutoStream<D>,
    _: (u8, &[RouteMatch]),
  ) -> Result<StatusCode, E> {
    let msg = &mut auto_stream.req.msg_data;
    msg.clear();
    msg.body.extend_from_copyable_slice(self.body)?;
    let content_type = KnownHeaderName::ContentType.into();
    msg.headers.push_from_iter(Header::from_name_and_value(content_type, ["text/plain"]))?;
    Ok(self.status)
  }
}

impl<D, E, S> EndpointNode<D, E, S> for Status
where
  E: From<crate::Error>,
{
  const IS_ROUTER: bool = false;

  fn paths_indices(
    &self,
    _: ArrayVectorCopy<RouteMatch, 4>,
    _: &mut VectorUsize<ArrayVectorCopy<RouteMatch, 4>>,
  ) -> crate::Result<()> {
    Ok(())
  }
}

/// Adds `server: rimu-ws` to every response, and answers `/blocked` with 403 itself.
struct ServerHeader;

impl Middleware<(), crate::Error> for ServerHeader {
  type Aux = ();

  fn aux(&self) -> Self::Aux {}

  async fn req(
    &self,
    _: &mut (),
    _: &mut Self::Aux,
    req: &mut Request<MsgBufferString>,
  ) -> crate::Result<ControlFlow<StatusCode, ()>> {
    if req.msg_data.uri.path() == "/blocked" {
      req.msg_data.clear();
      return Ok(ControlFlow::Break(StatusCode::Forbidden));
    }
    Ok(ControlFlow::Continue(()))
  }

  async fn res(
    &self,
    _: &mut (),
    _: &mut Self::Aux,
    res: HttpResponse<&mut MsgBufferString>,
  ) -> crate::Result<ControlFlow<StatusCode, ()>> {
    let server = KnownHeaderName::Server.into();
    res.msg_data.headers.push_from_iter(Header::from_name_and_value(server, ["rimu-ws"]))?;
    Ok(ControlFlow::Continue(()))
  }
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

// `content_length`, `date` and `rfc9110`: what the test asks of the framework, if anything; `None`
// leaves the default of the framework.
struct Opts {
  content_length: Option<bool>,
  count: Option<&'static AtomicU64>,
  date: Option<bool>,
  drain: Duration,
  h3: H3Params,
  hooks: TestHooks,
  record: bool,
  rfc9110: Option<bool>,
  root: PathBuf,
  workers: usize,
  zerocopy: bool,
}

impl Opts {
  fn new(name: &str) -> Self {
    Self {
      content_length: None,
      count: None,
      date: None,
      drain: Duration::from_secs(1),
      h3: H3Params::default(),
      hooks: TestHooks::default(),
      record: false,
      rfc9110: None,
      root: static_dir(name),
      workers: 1,
      zerocopy: false,
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
  .set_h3_params(opts.h3)
  .set_local_runtimes(NonZeroUsize::new(opts.workers))
  .set_pin_workers(false)
  .set_shutdown(signal.clone(), opts.drain)
  .set_udp_params(UdpParams { reuseport, zerocopy: opts.zerocopy, ..UdpParams::new() })
  .set_local_runtime_cb(move || {
    if let Some(elem) = count {
      _count_allocations_in(elem);
    }
    UringRuntime::new()
  });
  if let Some(value) = opts.rfc9110 {
    fw = fw.set_rfc9110_headers(value);
  }
  if let Some(value) = opts.content_length {
    fw = fw.set_content_length(value);
  }
  if let Some(value) = opts.date {
    fw = fw.set_date(value);
  }
  fw.test = TestHooks { bound: Some(bound_tx), ..opts.hooks };
  let stats = fw.stats();
  let addr =
    if reuseport { format!("127.0.0.1:{}", free_port()) } else { "127.0.0.1:0".to_string() };
  let probe =
    Probe { files: StaticFiles::new(&opts.root).unwrap(), record: opts.record, seen: seen.clone() };
  let run = std::thread::spawn(move || {
    let paths = crate::paths!(
      ("/baseline2", get(baseline2)),
      ("/blocked", get(baseline2)),
      ("/hello", Status { body: b"hello", status: StatusCode::Ok }),
      ("/manual", get(manual)),
      ("/no-content", Status { body: b"x", status: StatusCode::NoContent }),
      ("/not-modified", Status { body: b"x", status: StatusCode::NotModified }),
      ("/panic", get(panics)),
      ("/sleep", get(sleep)),
      ("/sleep-panic", get(sleep_then_panic)),
      ("/static/{*file}", Get(probe)),
      ("/upload", post(upload)),
    );
    let router = HttpRouter::new(paths, ServerHeader)?;
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

  /// Sends what the connection has to send.
  fn flush(&mut self) {
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
// the endpoint, `content-length` and `date`; a path with no route gets 404. Decision Q2: the
// default leaves `content-length` and `date` out, so this test asks for the RFC 9110 fields.
#[cfg_attr(miri, ignore)]
#[test]
fn baseline2_route_answers_2() {
  let mut opts = Opts::new("baseline2");
  opts.rfc9110 = Some(true);
  let served = serve(opts);
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
  let worker = served.worker(0);
  assert_eq!(worker.requests, 3);
  // The packet counters of task 15: packets carry the datagrams, the ACK-only ones are a part
  assert!(worker.datagrams_out > 0 && worker.packets_out >= worker.datagrams_out, "{worker:?}");
  assert!(worker.ack_only_out <= worker.packets_out, "{worker:?}");
  // Ruling T19-a: the datagrams leave in trains; the stream bytes of the responses, written by
  // copy, fit in the bytes of the datagrams; every flush that owed an acknowledgment carried it
  assert!(worker.trains_out > 0 && worker.trains_out <= worker.datagrams_out, "{worker:?}");
  assert!(worker.stream_bytes_out > 0 && worker.stream_bytes_out < worker.bytes_out, "{worker:?}");
  assert!(worker.stream_bytes_copied > 0, "{worker:?}");
  assert_eq!(worker.fin_flushes_acked, worker.fin_flushes_ack_owed, "{worker:?}");
  assert_eq!(worker.fin_flushes_owed_and_acked, worker.fin_flushes_ack_owed, "{worker:?}");
  assert_eq!((worker.zc_sends, worker.zc_fallbacks), (0, 0), "{worker:?}");
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
  // The test checks the `content-length` of the `.br` twin, which only the RFC 9110 fields carry
  opts.rfc9110 = Some(true);
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

// Ruling T19-b: with zero-copy sends, static files of several trains arrive whole, request after
// request, and every train went zero-copy (or, on a kernel that refuses, the worker fell back to
// copying once, and they arrive all the same).
#[cfg_attr(miri, ignore)]
#[test]
fn static_files_arrive_whole_with_zero_copy_sends() {
  let mut opts = Opts::new("zerocopy");
  opts.zerocopy = true;
  let files: Vec<(String, Vec<u8>)> = [1_000usize, 70_000, 300_000]
    .iter()
    .enumerate()
    .map(|(idx, len)| {
      let bytes: Vec<u8> = (0..*len).map(|el| ((el * 7 + idx) % 253) as u8).collect();
      (format!("f{idx}.bin"), bytes)
    })
    .collect();
  for (name, bytes) in &files {
    std::fs::write(opts.root.join(name), bytes).unwrap();
  }
  let served = serve(opts);
  let mut client = Client::connect(served.addr);
  for _ in 0..4 {
    for (name, bytes) in &files {
      let rsp = client.get(&format!("/static/{name}"), &[]);
      assert_eq!(status(&rsp), b"200");
      assert!(rsp.body == *bytes, "{name}: {} bytes of {}", rsp.body.len(), bytes.len());
    }
  }
  served.wait_stats(|el| el[0].requests == 12);
  let worker = served.worker(0);
  if worker.zc_fallbacks == 0 {
    assert!(worker.zc_sends > 0, "{worker:?}");
    assert!(worker.zc_sends <= worker.trains_out, "{worker:?}");
  } else {
    assert_eq!((worker.zc_fallbacks, worker.zc_sends), (1, 0), "{worker:?}");
  }
  // The bodies went by reference: written by copy are the fields only
  assert!(worker.stream_bytes_copied < 1_000, "{worker:?}");
  assert!(worker.stream_bytes_out >= 4 * 371_000, "{worker:?}");
  assert!(served.errors().is_empty(), "{:?}", served.errors());
}

// Decision Q2 (fix in passing of task 16): with the default fields the `.br` twin of a file still
// carries `content-encoding: br` and `vary: accept-encoding` (and `content-type`), and neither
// `content-length` nor `date`.
#[cfg_attr(miri, ignore)]
#[test]
fn static_file_br_twin_in_default_mode() {
  let opts = Opts::new("brtwin-default");
  std::fs::write(opts.root.join("a.css"), vec![b'c'; 6_000]).unwrap();
  std::fs::write(opts.root.join("a.css.br"), vec![b'b'; 2_500]).unwrap();
  let served = serve(opts);
  let mut client = Client::connect(served.addr);
  let accept = [(&b"accept-encoding"[..], &b"br;q=1, gzip;q=0.8"[..])];
  let rsp = client.get("/static/a.css", &accept);
  assert_eq!(status(&rsp), b"200");
  assert_eq!(rsp.field(b"content-encoding"), Some(&b"br"[..]));
  assert_eq!(rsp.field(b"vary"), Some(&b"accept-encoding"[..]));
  assert_eq!(rsp.field(b"content-type"), Some(&b"text/css"[..]));
  assert_eq!((rsp.field(b"content-length"), rsp.field(b"date")), (None, None));
  assert_eq!(rsp.body, vec![b'b'; 2_500]);
  assert!(served.errors().is_empty(), "{:?}", served.errors());
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

// Brief step 1: `set_date(true)` sends `date` (RFC 9110 section 6.6.1) as an IMF-fixdate, and
// `set_date(false)` does not (decision Q2: the default does not either).
#[cfg_attr(miri, ignore)]
#[test]
fn date_header_toggles() {
  let mut opts = Opts::new("date-on");
  opts.date = Some(true);
  let served = serve(opts);
  let mut client = Client::connect(served.addr);
  let rsp = client.get("/baseline2?a=1&b=1", &[]);
  let date = rsp.field(b"date").unwrap();
  assert_eq!(date.len(), 29);
  assert!(date.ends_with(b" GMT") && date[3] == b',', "{date:?}");
  drop((client, served));
  let mut opts = Opts::new("date-off");
  opts.date = Some(false);
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
  // Each connection is on the worker that its CID names, which served its request
  for (idx, worker) in served.stats.workers().iter().enumerate() {
    let on_it = clients.iter().filter(|el| usize::from(el.conn.peer_cid().as_slice()[0]) == idx);
    let on_it = u64::try_from(on_it.count()).unwrap();
    assert_eq!((worker.conns, worker.requests), (on_it, on_it), "worker {idx}: {worker:?}");
  }
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

// Ruling T16-b (carried from task 14): a datagram that the kernel coalesced (GRO) and that goes to
// another worker is handed over segment by segment, each within an inbox entry; the place that the
// first Initial packet took on that worker is counted once (each later segment that carries a
// place takes one more, which the other worker gives back when it opens nothing).
#[cfg_attr(miri, ignore)]
#[test]
fn coalesced_datagram_is_forwarded_segment_by_segment() {
  let mut net = Net::new(2, QuicParams::default(), &TestApp::default());
  net.loads.placed(0);
  let client = net.add_split_client(1500);
  let datagrams = net.client_datagrams(client);
  assert_eq!(datagrams.len(), 2);
  let segment = datagrams[0].len();
  assert!(datagrams[1].len() <= segment);
  let coalesced: Vec<u8> = datagrams.concat();
  assert!(coalesced.len() > UdpInbox::DATAGRAM_LEN);
  let peer = net.clients[client].addr;
  let meta =
    DatagramMeta { peer, local: None, segment_size: Some(u16::try_from(segment).unwrap()) };
  let now_us = net.now_us;
  let server = &mut net.servers[0];
  let outcome = server.endpoint.recv(now_us, &mut coalesced.clone(), meta, &mut server.app);
  assert_eq!(outcome, RecvOutcome::Forward { worker: 1 });
  assert_eq!(net.loads.load(1), 1);
  let received = UringRuntime::new().unwrap().block_on(async {
    let params = UdpParams { reuseport: false, ..UdpParams::new() };
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let socket = UringUdpSocket::bind(local, &params).unwrap();
    let inboxes = vec![socket.inbox(), socket.inbox()];
    assert!(forward(&mut net.servers[0].endpoint, &inboxes, &coalesced, meta, 1));
    let mut got = Vec::new();
    core::future::poll_fn(|cx| {
      let _count = socket.poll_inbox(cx, &mut |datagram, meta| got.push((datagram.to_vec(), meta)));
      Poll::Ready(())
    })
    .await;
    got
  });
  assert_eq!(received.len(), 2);
  for ((datagram, got_meta), sent) in received.iter().zip(&datagrams) {
    assert_eq!(datagram, sent);
    assert_eq!(*got_meta, DatagramMeta { segment_size: None, ..meta });
  }
  // The other worker opens one connection from them, and its place is counted once
  assert_eq!(net.loads.load(1), 2);
  for (mut datagram, meta) in received {
    let server = &mut net.servers[1];
    server.endpoint.recv_forwarded(now_us, &mut datagram, meta, &mut server.app);
  }
  assert_eq!(net.servers[1].endpoint.stats().conns, 1);
  assert_eq!(net.loads.load(1), 1);
}

// Ruling T14-e: a worker that has had no connection for a while trims its pools, once per idle
// period: the free QUIC connection states, the TLS handshake states of the thread and the boxes of
// the HTTP/3 connections that eight connections at once left go down to a few.
#[cfg_attr(miri, ignore)]
#[test]
fn idle_worker_trims_its_pools() {
  assert_eq!(IDLE_TRIM_AFTER, Duration::from_secs(1));
  let trims = Arc::new(Mutex::new(Vec::new()));
  let mut opts = Opts::new("idle");
  opts.hooks.idle_trim_after = Some(Duration::from_millis(100));
  opts.hooks.trims = Some(trims.clone());
  let served = serve(opts);
  served.wait_stats(|el| el[0].idle_trims == 1);
  // Eight handshakes at once: each Initial leaves before any handshake ends
  let mut clients: Vec<Client> = (0..8).map(|_| Client::new(served.addr)).collect();
  for client in &mut clients {
    client.flush();
  }
  let begin = Instant::now();
  while !clients.iter().all(|el| el.conn.state() == ConnState::Confirmed) {
    assert!(begin.elapsed() < TIMEOUT, "no handshake");
    for client in &mut clients {
      client.step(Duration::from_millis(1));
    }
  }
  for client in &mut clients {
    assert_eq!(client.get("/baseline2?a=1&b=1", &[]).body, b"2");
    let now_us = client.now_us();
    client.conn.close_app(now_us, 0x100);
    client.step(Duration::from_millis(1));
  }
  served.wait_stats(|el| el[0].conns == 0 && el[0].idle_trims == 2);
  std::thread::sleep(Duration::from_millis(300));
  assert_eq!(served.worker(0).idle_trims, 2);
  let (before, after) = trims.lock().unwrap()[1];
  assert!(before.quic_conns > after.quic_conns && after.quic_conns <= 4, "{before:?} {after:?}");
  assert!(before.tls_states > after.tls_states && after.tls_states <= 4, "{before:?} {after:?}");
  assert!(before.h3_conns > after.h3_conns && after.h3_conns <= 4, "{before:?} {after:?}");
}

// Brief step 1 (zero allocations after warm-up): once warm, a round of requests (inline routes,
// static files by reference and parked handlers) allocates nothing on the thread of the worker,
// with the default fields (what the HttpArena entry serves) and with the RFC 9110 ones (the most
// the framework does per response: `date` and `content-length` encoded too). Fix in passing of
// task 16: the default mode too.
#[cfg_attr(miri, ignore)]
#[test]
fn framework_steady_state_allocates_nothing_after_warmup() {
  static DEFAULT: AtomicU64 = AtomicU64::new(0);
  static RFC9110: AtomicU64 = AtomicU64::new(0);
  steady_state_allocates_nothing(None, &DEFAULT);
  steady_state_allocates_nothing(Some(true), &RFC9110);
}

fn steady_state_allocates_nothing(rfc9110: Option<bool>, worker: &'static AtomicU64) {
  let mut opts = Opts::new(if rfc9110.is_some() { "alloc-rfc9110" } else { "alloc-default" });
  opts.rfc9110 = rfc9110;
  std::fs::write(opts.root.join("a.css"), vec![b'c'; 5_000]).unwrap();
  std::fs::write(opts.root.join("a.css.br"), vec![b'b'; 3_000]).unwrap();
  opts.count = Some(worker);
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
  let before = worker.load(Ordering::Relaxed);
  let begin = Instant::now();
  round(&mut client, 400);
  let allocations = worker.load(Ordering::Relaxed) - before;
  assert!(begin.elapsed() < Duration::from_millis(900), "{:?}", begin.elapsed());
  assert_eq!(allocations, 0, "rfc9110 {rfc9110:?}");
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
  let allowed = affinity::allowed().unwrap();
  let order = cpu_order().unwrap();
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
    assert_eq!(affinity::allowed().unwrap(), [cpu]);
  })
  .join()
  .unwrap();
}

// Fix X1: a worker that can not bind its socket ends the server with the error of the bind, never
// with the error of a worker that stopped waiting for it.
#[cfg_attr(miri, ignore)]
#[test]
fn startup_failure_reports_the_bind_error() {
  let held = UdpSocket::bind("127.0.0.1:0").unwrap();
  let addr = held.local_addr().unwrap().to_string();
  for _ in 0..5 {
    let fw = Http3ServerFramework::<(), fn(crate::Error), UringExecutor, _, _, _>::new(
      UringExecutor::default(),
      ChaCha20::from_std_random().unwrap(),
      server_tls_config(),
    )
    .unwrap()
    .set_local_runtimes(NonZeroUsize::new(8))
    .set_pin_workers(false);
    let router = HttpRouter::paths(crate::paths!(("/baseline2", get(baseline2)))).unwrap();
    let err = fw.run_in_threads(&addr, router).unwrap_err();
    assert!(
      matches!(&err, crate::Error::Io(el) if el.kind() == std::io::ErrorKind::AddrInUse),
      "{err:?}"
    );
  }
}

/// A future that waits until it is polled again after its first poll, keeping its waker.
struct Gate {
  polled: bool,
  wakers: Arc<Mutex<Vec<Waker>>>,
}

impl Future for Gate {
  type Output = ();

  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
    if self.polled {
      return Poll::Ready(());
    }
    self.polled = true;
    self.wakers.lock().unwrap().push(cx.waker().clone());
    Poll::Pending
  }
}

// Fix X2: the parked slots can all be woken at once: the queue of woken slots has room for every
// slot, so that a wake allocates nothing and is never lost, and each slot is polled again.
#[cfg_attr(miri, ignore)]
#[test]
fn every_parked_slot_wakes_at_once_without_allocating() {
  static WAKES: AtomicU64 = AtomicU64::new(0);
  static OTHERS: AtomicU64 = AtomicU64::new(0);
  const SLOTS: usize = 64;
  let wakers = Arc::new(Mutex::new(Vec::new()));
  let mut slots = TaskSlots::new();
  for nth in 0..SLOTS {
    let fut = Gate { polled: false, wakers: wakers.clone() };
    let idx = slots.insert(fut, ConnHandle::default(), StreamId(4 * nth as u64)).unwrap();
    assert!(matches!(slots.poll(idx), SlotPoll::Pending));
  }
  let wakers = core::mem::take(&mut *wakers.lock().unwrap());
  assert_eq!(wakers.len(), SLOTS);
  _count_allocations_in(&WAKES);
  for waker in &wakers {
    waker.wake_by_ref();
  }
  _count_allocations_in(&OTHERS);
  assert_eq!(WAKES.load(Ordering::Relaxed), 0);
  let mut woken = VectorUsize::new();
  slots.take_woken(&mut woken).unwrap();
  let mut indexes: Vec<u32> = woken.iter().copied().collect();
  indexes.sort_unstable();
  indexes.dedup();
  assert_eq!(indexes.len(), SLOTS);
  for idx in indexes {
    assert!(matches!(slots.poll(idx), SlotPoll::Done(())));
  }
  assert_eq!(slots.wakes_lost(), 0);
}

// Ruling T14-i (RFC 9110 sections 9.3.2, 8.6, 15.3.5 and 15.4.5): a response to HEAD has the fields
// that GET gets, `content-length` included, and no content; 204 has neither content nor
// `content-length`; 304 has no content. The GET asserts `content-length`, which the default
// leaves out (decision Q2), so the test asks for the RFC 9110 fields.
#[cfg_attr(miri, ignore)]
#[test]
fn head_204_and_304_carry_no_content() {
  let mut opts = Opts::new("no-content");
  opts.rfc9110 = Some(true);
  let served = serve(opts);
  let mut client = Client::connect(served.addr);
  let get = client.get("/hello", &[]);
  assert_eq!((get.field(b"content-length"), get.body.as_slice()), (Some(&b"5"[..]), &b"hello"[..]));
  let id = client.request(b"HEAD", "/hello", &[]);
  let head = client.wait(id);
  assert_eq!(status(&head), b"200");
  assert_eq!(head.field(b"content-length"), Some(&b"5"[..]));
  assert_eq!(head.field(b"content-type"), Some(&b"text/plain"[..]));
  assert_eq!((head.frames.as_slice(), head.body.as_slice()), (&[0x01][..], &b""[..]));
  for path in ["/no-content", "/not-modified"] {
    for method in [&b"GET"[..], b"HEAD"] {
      let id = client.request(method, path, &[]);
      let rsp = client.wait(id);
      assert_eq!(rsp.field(b"content-length"), None, "{path}");
      assert_eq!((rsp.frames.as_slice(), rsp.body.as_slice()), (&[0x01][..], &b""[..]), "{path}");
    }
  }
  assert_eq!(status(&client.get("/no-content", &[])), b"204");
  assert_eq!(status(&client.get("/not-modified", &[])), b"304");
  assert!(served.errors().is_empty(), "{:?}", served.errors());
}

// Ruling T14-j: `set_content_length(false)` leaves `content-length` out of responses with content
// (HTTP/3 frames the body), and a response to HEAD keeps it; `set_content_length(true)` puts it
// in (decision Q2: the default leaves it out).
#[cfg_attr(miri, ignore)]
#[test]
fn content_length_toggles() {
  let mut opts = Opts::new("length-on");
  opts.content_length = Some(true);
  let served = serve(opts);
  let mut client = Client::connect(served.addr);
  assert_eq!(client.get("/baseline2?a=1&b=1", &[]).field(b"content-length"), Some(&b"1"[..]));
  drop((client, served));
  let mut opts = Opts::new("length-off");
  opts.content_length = Some(false);
  let served = serve(opts);
  let mut client = Client::connect(served.addr);
  let rsp = client.get("/baseline2?a=1&b=1", &[]);
  assert_eq!((rsp.field(b"content-length"), rsp.body.as_slice()), (None, &b"2"[..]));
  let id = client.request(b"HEAD", "/hello", &[]);
  let head = client.wait(id);
  assert_eq!((head.field(b"content-length"), head.body.as_slice()), (Some(&b"5"[..]), &b""[..]));
}

// Decision Q2: by default a response carries `:status` and `content-type` only, like the HttpArena
// HTTP/3 leaders (cnetmod, zix): no `date`, no `content-length` (the 404 and the 200 both), and a
// response to HEAD keeps `content-length` (ruling T14-i).
#[cfg_attr(miri, ignore)]
#[test]
fn default_headers_are_status_and_content_type_only() {
  let served = serve(Opts::new("lean-default"));
  let mut client = Client::connect(served.addr);
  let rsp = client.get("/baseline2?a=1&b=1", &[]);
  assert_eq!((status(&rsp), rsp.body.as_slice()), (&b"200"[..], &b"2"[..]));
  assert_eq!(rsp.field(b"content-type"), Some(&b"text/plain"[..]));
  assert_eq!((rsp.field(b"date"), rsp.field(b"content-length")), (None, None));
  let mut names: Vec<&[u8]> = rsp.fields.iter().map(|el| el.0.as_slice()).collect();
  names.sort_unstable();
  assert_eq!(names, [&b":status"[..], b"content-type", b"server"], "{names:?}");
  let rsp = client.get("/nothing-here", &[]);
  assert_eq!(
    (status(&rsp), rsp.field(b"date"), rsp.field(b"content-length")),
    (&b"404"[..], None, None)
  );
  let id = client.request(b"HEAD", "/hello", &[]);
  let head = client.wait(id);
  assert_eq!((head.field(b"date"), head.field(b"content-length")), (None, Some(&b"5"[..])));
  assert!(served.errors().is_empty(), "{:?}", served.errors());
}

// Decision Q2: `set_rfc9110_headers(true)` turns on `date` (RFC 9110 section 6.6.1) and
// `content-length` (section 8.6) together.
#[cfg_attr(miri, ignore)]
#[test]
fn rfc9110_flag_adds_date_and_content_length() {
  let mut opts = Opts::new("rfc-flag");
  opts.rfc9110 = Some(true);
  let served = serve(opts);
  let mut client = Client::connect(served.addr);
  let rsp = client.get("/baseline2?a=1&b=1", &[]);
  assert_eq!((status(&rsp), rsp.body.as_slice()), (&b"200"[..], &b"2"[..]));
  assert_eq!(rsp.field(b"content-length"), Some(&b"1"[..]));
  let date = rsp.field(b"date").unwrap();
  assert!(date.len() == 29 && date.ends_with(b" GMT"), "{date:?}");
  assert_eq!(rsp.field(b"content-type"), Some(&b"text/plain"[..]));
  let id = client.request(b"HEAD", "/hello", &[]);
  assert_eq!(client.wait(id).field(b"content-length"), Some(&b"5"[..]));
  assert!(served.errors().is_empty(), "{:?}", served.errors());
}

// Fix X6: a manual-mode route answers 500 on HTTP/3, with OperationModeMismatch to the error
// callback; the middlewares of the router run around the endpoints, and can answer themselves.
#[cfg_attr(miri, ignore)]
#[test]
fn manual_routes_and_middlewares_on_h3() {
  let served = serve(Opts::new("manual"));
  let mut client = Client::connect(served.addr);
  assert_eq!(status(&client.get("/manual", &[])), b"500");
  let errors = served.errors();
  assert!(errors.len() == 1 && errors[0].contains("OperationModeMismatch"), "{errors:?}");
  let rsp = client.get("/baseline2?a=1&b=1", &[]);
  assert_eq!((rsp.field(b"server"), rsp.body.as_slice()), (Some(&b"rimu-ws"[..]), &b"2"[..]));
  let rsp = client.get("/blocked", &[]);
  assert_eq!((status(&rsp), rsp.field(b"server")), (&b"403"[..], Some(&b"rimu-ws"[..])));
  assert!(rsp.body.is_empty());
}

// Data whose clones are counted.
#[derive(Debug)]
struct Counted(&'static AtomicU64);

impl Clone for Counted {
  fn clone(&self) -> Self {
    let _ = self.0.fetch_add(1, Ordering::Relaxed);
    Self(self.0)
  }
}

async fn counted(state: State<'_, Counted>) -> crate::Result<VerbatimParams> {
  state.req.msg_data.clear();
  state.req.msg_data.body.extend_from_copyable_slice(b"counted")?;
  Ok(VerbatimParams(StatusCode::Ok))
}

// Rulings T16-a and T16-e (EC2 profile: the clone and drop of the data of each request, an `Arc`
// shared by every worker, took 7 % of the cycles of baseline-h3): with `set_reuse_data(true)` a
// worker keeps the clones of its data that its requests used and gives them to its next requests,
// so that a request clones nothing in the steady state; without it each request clones the data,
// as HTTP/2 does.
#[cfg_attr(miri, ignore)]
#[test]
fn requests_reuse_the_clones_of_the_data_only_when_asked() {
  static REUSED: AtomicU64 = AtomicU64::new(0);
  static FRESH: AtomicU64 = AtomicU64::new(0);
  for (fresh, clones) in [(false, &REUSED), (true, &FRESH)] {
    let signal = ShutdownSignal::new();
    let (bound_tx, bound_rx) = mpsc::channel();
    let mut fw = Http3ServerFramework::<(), fn(crate::Error), UringExecutor, _, _, _>::new(
      UringExecutor::default(),
      ChaCha20::from_std_random().unwrap(),
      server_tls_config(),
    )
    .unwrap()
    .set_data(Counted(clones))
    .set_reuse_data(!fresh)
    .set_local_runtimes(NonZeroUsize::new(1))
    .set_pin_workers(false)
    .set_shutdown(signal.clone(), Duration::from_millis(100))
    .set_udp_params(UdpParams { reuseport: false, ..UdpParams::new() });
    fw.test = TestHooks { bound: Some(bound_tx), ..TestHooks::default() };
    let run = std::thread::spawn(move || {
      let router = HttpRouter::paths(crate::paths!(("/counted", get(counted))))?;
      fw.run_in_threads("127.0.0.1:0", router)
    });
    let addr = bound_rx.recv_timeout(TIMEOUT).expect("the server did not bind");
    let mut client = Client::connect(addr);
    assert_eq!(client.get("/counted", &[]).body, b"counted");
    let before = clones.load(Ordering::Relaxed);
    for _ in 0..16 {
      assert_eq!(client.get("/counted", &[]).body, b"counted");
    }
    let made = clones.load(Ordering::Relaxed) - before;
    assert_eq!(made, if fresh { 16 } else { 0 }, "fresh {fresh}");
    drop(client);
    signal.trigger();
    run.join().unwrap().unwrap();
  }
}

// Ruling T18-c: the field sections that the worker decoded, and those that its decode memo
// replayed, reach the stats: the same request eight times on one connection decodes its head once
// and replays it seven times. A connection of its own starts with an empty memo.
#[cfg_attr(miri, ignore)]
#[test]
fn qpack_sections_and_memo_hits_are_counted() {
  let served = serve(Opts::new("qpack-memo"));
  let mut client = Client::connect(served.addr);
  for _ in 0..8 {
    assert_eq!(client.get("/baseline2?a=1&b=1", &[]).body, b"2");
  }
  served.wait_stats(|el| el[0].requests == 8);
  let worker = served.worker(0);
  assert_eq!((worker.qpack_sections, worker.qpack_memo_hits), (8, 7), "{worker:?}");
  let mut other = Client::connect(served.addr);
  assert_eq!(other.get("/baseline2?a=1&b=1", &[]).body, b"2");
  served.wait_stats(|el| el[0].requests == 9);
  let worker = served.worker(0);
  assert_eq!((worker.qpack_sections, worker.qpack_memo_hits), (9, 7), "{worker:?}");
  assert!(served.errors().is_empty(), "{:?}", served.errors());
}

// Ruling T16-c: every counter of a worker, the ones of the measurement of spec section 2.1 (and
// task 18's QPACK counters, task 19's transfer counters) included, comes back from the cell that
// the worker stores it in as it was stored.
#[test]
fn worker_stats_round_trip_through_their_cell() {
  let stats = Http3WorkerStats {
    ack_only_out: 1,
    bytes_out: 27,
    cid_steering: true,
    conns: 2,
    data_blocked_in: 3,
    datagrams_in: 4,
    datagrams_out: 5,
    fin_flushes: 6,
    fin_flushes_ack_owed: 28,
    fin_flushes_acked: 7,
    fin_flushes_owed_and_acked: 36,
    fins_out: 8,
    forward_dropped: 9,
    forwarded: 10,
    frames_resent: 11,
    frames_resent_acked: 39,
    handler_panics: 12,
    idle_trims: 13,
    pacer_holds: 29,
    packets_lost: 14,
    packets_out: 15,
    park_refused: 16,
    parked: 17,
    pool_bytes: 37,
    pool_bytes_peak: 38,
    pto_probes: 18,
    qpack_memo_hits: 19,
    qpack_sections: 20,
    requests: 21,
    retries: 22,
    stateless_resets: 23,
    stream_bytes_copied: 30,
    stream_bytes_out: 31,
    stream_data_blocked_in: 24,
    streams_blocked_in: 25,
    trains_out: 32,
    udp_send_errors: 26,
    zc_copied: 33,
    zc_fallbacks: 34,
    zc_sends: 35,
  };
  let cell = crate::http::http3_server_framework::StatsCell::default();
  cell.store(&stats);
  assert_eq!(cell.load(), stats);
}

// Data that counts the requests that saw it: its clone is an independent copy.
#[derive(Clone, Debug, Default)]
struct Visits(u64);

async fn visits(state: State<'_, Visits>) -> crate::Result<VerbatimParams> {
  state.data.0 += 1;
  let seen = state.data.0;
  state.req.msg_data.clear();
  std::io::Write::write_fmt(&mut state.req.msg_data.body, format_args!("{seen}"))?;
  Ok(VerbatimParams(StatusCode::Ok))
}

// The bodies of four requests in a row to a worker whose handler counts, in its data, the requests
// that saw it; `reuse`: what is asked of `set_reuse_data`, `None` for the default.
fn visits_seen(reuse: Option<bool>) -> Vec<Vec<u8>> {
  let signal = ShutdownSignal::new();
  let (bound_tx, bound_rx) = mpsc::channel();
  let mut fw = Http3ServerFramework::<(), fn(crate::Error), UringExecutor, _, _, _>::new(
    UringExecutor::default(),
    ChaCha20::from_std_random().unwrap(),
    server_tls_config(),
  )
  .unwrap()
  .set_data(Visits::default())
  .set_local_runtimes(NonZeroUsize::new(1))
  .set_pin_workers(false)
  .set_shutdown(signal.clone(), Duration::from_millis(100))
  .set_udp_params(UdpParams { reuseport: false, ..UdpParams::new() });
  if let Some(elem) = reuse {
    fw = fw.set_reuse_data(elem);
  }
  fw.test = TestHooks { bound: Some(bound_tx), ..TestHooks::default() };
  let run = std::thread::spawn(move || {
    let router = HttpRouter::paths(crate::paths!(("/visits", get(visits))))?;
    fw.run_in_threads("127.0.0.1:0", router)
  });
  let addr = bound_rx.recv_timeout(TIMEOUT).expect("the server did not bind");
  let mut client = Client::connect(addr);
  let bodies = (0..4).map(|_| client.get("/visits", &[]).body).collect();
  drop(client);
  signal.trigger();
  run.join().unwrap().unwrap();
  bodies
}

// Ruling T16-e (spec section 5.10: the routes of HTTP/2 run on HTTP/3 unchanged): by default each
// request gets a fresh clone of the data, as on HTTP/2, so what a handler changes in its data is
// never seen by a later request; with `set_reuse_data(true)` the worker hands a clone that a
// request used to the next one, and the change is seen (the documented hazard of the opt-in).
#[cfg_attr(miri, ignore)]
#[test]
fn data_changes_stay_with_their_request_unless_reused() {
  let fresh: Vec<Vec<u8>> = (0..4).map(|_| b"1".to_vec()).collect();
  assert_eq!(visits_seen(None), fresh);
  assert_eq!(visits_seen(Some(false)), fresh);
  let reused: Vec<Vec<u8>> = (1..=4).map(|el: u8| vec![b'0' + el]).collect();
  assert_eq!(visits_seen(Some(true)), reused);
}

// Ruling T16-a (fields validated once): a request whose fields are ASCII reaches its handler
// without a second check; one with obs-text that is UTF-8 too, after the check; one whose obs-text
// is not UTF-8 is answered with 400, as before.
#[cfg_attr(miri, ignore)]
#[test]
fn field_values_beyond_ascii_are_checked_once_more() {
  let served = serve(Opts::new("obs-text"));
  let mut client = Client::connect(served.addr);
  let ascii = client.get("/baseline2?a=1&b=1", &[(&b"x-a"[..], &b"plain"[..])]);
  assert_eq!((status(&ascii), ascii.body.as_slice()), (&b"200"[..], &b"2"[..]));
  let utf8 = client.get("/baseline2?a=1&b=1", &[(&b"x-a"[..], "café".as_bytes())]);
  assert_eq!((status(&utf8), utf8.body.as_slice()), (&b"200"[..], &b"2"[..]));
  let bad = client.get("/baseline2?a=1&b=1", &[(&b"x-a"[..], &b"caf\xe9"[..])]);
  assert_eq!(status(&bad), b"400");
}
