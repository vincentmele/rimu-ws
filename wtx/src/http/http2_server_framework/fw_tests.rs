//! The framework's connection management end to end on io_uring: the connection cap, the
//! handshake deadline, idle connections, shutdown and error reporting.

use crate::{
  executor::{Runtime as _, UringExecutor, UringParams, UringRuntime},
  futures::Sleep,
  http::{
    HttpRecvParams, ShutdownSignal, StatusCode,
    http2_server_framework::{
      Http2ServerFramework, HttpRouter, conn_driver::tests::{Frames, complete_len}, get,
    },
  },
  http2::conn::{
    scan::PREFACE,
    test_frames::{headers_req, parse_all, settings},
  },
  net::TcpParams,
  rng::{ChaCha20, CryptoSeedableRng},
  sync::Arc,
  tests::_uri,
  tls::TlsConfig,
};
use alloc::{
  format,
  string::{String, ToString as _},
  vec::Vec,
};
use core::{num::NonZeroUsize, time::Duration};
use std::{
  io::{Read as _, Write as _},
  net::TcpStream,
  sync::Mutex,
  thread::JoinHandle,
  time::Instant,
};

const GOAWAY: u8 = 7;
const HEADERS: u8 = 1;
const RST_STREAM: u8 = 3;

#[derive(Default)]
struct Opts {
  handshake_timeout: Option<Option<Duration>>,
  idle_timeout: Option<Option<Duration>>,
  max_connections: Option<NonZeroUsize>,
  shutdown: Option<(ShutdownSignal, Duration)>,
}

struct Served {
  addr: String,
  errors: Arc<Mutex<Vec<String>>>,
  run: JoinHandle<crate::Result<()>>,
}

async fn hello() -> crate::Result<StatusCode> {
  Ok(StatusCode::Ok)
}

async fn slow() -> crate::Result<StatusCode> {
  Sleep::new(Duration::from_millis(100))?.await?;
  Ok(StatusCode::Ok)
}

/// `/` and `/slow` (100 ms) on one runtime, plaintext, with `opts` applied.
fn serve(opts: Opts) -> Served {
  let uri = _uri();
  let addr = String::from(uri.hostname_with_implied_port().0) + ":" + &uri.port().unwrap().to_string();
  let errors = Arc::new(Mutex::new(Vec::new()));
  let thread_errors = errors.clone();
  let server_addr = addr.clone();
  let run = std::thread::spawn(move || {
    let router = HttpRouter::paths(crate::paths!(("/", get(hello)), ("/slow", get(slow))))?;
    let error_cb = move |err: crate::Error| thread_errors.lock().unwrap().push(format!("{err:?}"));
    let mut fw = Http2ServerFramework::<(), fn(crate::Error), UringExecutor, _, _, _>::new(
      UringExecutor::default(),
      ChaCha20::from_std_random()?,
      TlsConfig::plaintext(),
    )?
    .set_error_cb(error_cb)
    .set_http_recv_params(HttpRecvParams::with_default_params())
    .set_local_runtimes(NonZeroUsize::new(1))
    .set_tcp_params(TcpParams::default().set_reuse_port(Some(false)))
    .set_max_connections(opts.max_connections);
    if let Some(elem) = opts.handshake_timeout {
      fw = fw.set_handshake_timeout(elem);
    }
    if let Some(elem) = opts.idle_timeout {
      fw = fw.set_idle_timeout(elem);
    }
    if let Some((signal, drain)) = opts.shutdown {
      fw = fw.set_shutdown(signal, drain);
    }
    fw.run_in_threads(&server_addr, router)
  });
  for _ in 0..200 {
    if TcpStream::connect(&addr).is_ok() {
      return Served { addr, errors, run };
    }
    std::thread::sleep(Duration::from_millis(10));
  }
  panic!("the server did not start");
}

/// A client past the preface and SETTINGS.
fn connect(addr: &str) -> TcpStream {
  let mut stream = TcpStream::connect(addr).unwrap();
  stream.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
  let mut opening = PREFACE.to_vec();
  opening.extend(settings(&[]));
  stream.write_all(&opening).unwrap();
  stream
}

/// Frames until `done` holds, the peer closes (`true`) or `timeout` passes.
fn read(stream: &mut TcpStream, timeout: Duration, done: impl Fn(&Frames) -> bool) -> (Frames, bool) {
  let deadline = Instant::now() + timeout;
  let mut buffer = Vec::new();
  let mut frames = Frames::new();
  let mut chunk = [0; 16 * 1024];
  while !done(&frames) && Instant::now() < deadline {
    match stream.read(&mut chunk) {
      Ok(0) => return (frames, true),
      Ok(n) => {
        buffer.extend_from_slice(&chunk[..n]);
        let complete = complete_len(&buffer);
        frames.extend(parse_all(&buffer[..complete]));
        let _ = buffer.drain(..complete);
      }
      Err(err)
        if matches!(err.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
      Err(_) => return (frames, true),
    }
  }
  (frames, false)
}

fn answered(frames: &Frames, stream: u32) -> bool {
  frames.iter().any(|el| el.0 == HEADERS && el.2 == stream)
}

fn go_away(frames: &Frames) -> Option<(u32, u32)> {
  frames.iter().find(|el| el.0 == GOAWAY).map(|el| {
    let last = u32::from_be_bytes(el.3[0..4].try_into().unwrap()) & 0x7FFF_FFFF;
    (last, u32::from_be_bytes(el.3[4..8].try_into().unwrap()))
  })
}

#[test]
fn fw_max_connections() {
  let served = serve(Opts { max_connections: NonZeroUsize::new(2), ..Opts::default() });
  let mut clients = Vec::new();
  for _ in 0..2 {
    let mut client = connect(&served.addr);
    client.write_all(&headers_req(1, "GET", "/", &[], true)).unwrap();
    let (frames, _) = read(&mut client, Duration::from_secs(5), |frames| answered(frames, 1));
    assert!(answered(&frames, 1), "{frames:?}");
    clients.push(client);
  }
  let mut third = connect(&served.addr);
  let _rslt = third.write_all(&headers_req(1, "GET", "/", &[], true));
  let (frames, closed) = read(&mut third, Duration::from_secs(5), |_| false);
  assert!(closed, "the third connection stayed open");
  assert!(!answered(&frames, 1), "{frames:?}");
  assert!(served.errors.lock().unwrap().iter().any(|el| el.contains("TooManyConnections")));
}

#[test]
fn fw_handshake_timeout_preface() {
  let timeout = Duration::from_millis(200);
  let served = serve(Opts { handshake_timeout: Some(Some(timeout)), ..Opts::default() });
  let mut silent = TcpStream::connect(&served.addr).unwrap();
  silent.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
  let begin = Instant::now();
  let (_, closed) = read(&mut silent, Duration::from_secs(5), |_| false);
  let elapsed = begin.elapsed();
  assert!(closed, "a client that sent nothing stayed connected");
  assert!(elapsed >= timeout * 3 / 4 && elapsed < Duration::from_secs(2), "{elapsed:?}");
  // A client that sends its preface in time is served past the deadline.
  let mut client = connect(&served.addr);
  std::thread::sleep(timeout * 2);
  client.write_all(&headers_req(1, "GET", "/", &[], true)).unwrap();
  let (frames, _) = read(&mut client, Duration::from_secs(5), |frames| answered(frames, 1));
  assert!(answered(&frames, 1), "{frames:?}");
}

#[test]
fn fw_idle_timeout_goaway() {
  let idle = Duration::from_millis(300);
  let served = serve(Opts { idle_timeout: Some(Some(idle)), ..Opts::default() });
  let mut client = connect(&served.addr);
  client.write_all(&headers_req(1, "GET", "/", &[], true)).unwrap();
  let (frames, _) = read(&mut client, Duration::from_secs(5), |frames| answered(frames, 1));
  assert!(answered(&frames, 1), "{frames:?}");
  let begin = Instant::now();
  let (frames, closed) = read(&mut client, Duration::from_secs(5), |_| false);
  let elapsed = begin.elapsed();
  assert_eq!(go_away(&frames), Some((1, 0)), "{frames:?}");
  assert!(closed, "no close after the GOAWAY");
  assert!(elapsed >= idle * 3 / 4 && elapsed < Duration::from_secs(2), "{elapsed:?}");
}

#[test]
fn fw_shutdown_drains() {
  let signal = ShutdownSignal::new();
  let opts = Opts { shutdown: Some((signal.clone(), Duration::from_secs(3))), ..Opts::default() };
  let served = serve(opts);
  let mut client = connect(&served.addr);
  client.write_all(&headers_req(1, "GET", "/slow", &[], true)).unwrap();
  std::thread::sleep(Duration::from_millis(30));
  signal.trigger();
  let (frames, _) = read(&mut client, Duration::from_secs(5), |frames| go_away(frames).is_some());
  assert_eq!(go_away(&frames).map(|el| el.1), Some(0), "{frames:?}");
  let _rslt = client.write_all(&headers_req(3, "GET", "/", &[], true));
  let (rest, _) = read(&mut client, Duration::from_secs(5), |frames| answered(frames, 1));
  let all: Frames = frames.into_iter().chain(rest).collect();
  assert!(answered(&all, 1), "the stream in flight wasn't answered: {all:?}");
  let refused = all.iter().any(|el| el.0 == RST_STREAM && el.2 == 3)
    || go_away(&all).is_some_and(|el| el.0 < 3);
  assert!(refused && !answered(&all, 3), "{all:?}");
  let begin = Instant::now();
  while !served.run.is_finished() && begin.elapsed() < Duration::from_secs(5) {
    std::thread::sleep(Duration::from_millis(10));
  }
  assert!(served.run.is_finished(), "run didn't return");
  served.run.join().unwrap().unwrap();
}

#[test]
fn fw_error_cb_reports_protocol_error() {
  let served = serve(Opts::default());
  let mut client = connect(&served.addr);
  // Stream ids a client opens are odd.
  client.write_all(&headers_req(2, "GET", "/", &[], true)).unwrap();
  let (frames, _) = read(&mut client, Duration::from_secs(5), |frames| go_away(frames).is_some());
  assert_eq!(go_away(&frames).map(|el| el.1), Some(1), "{frames:?}");
  let begin = Instant::now();
  while served.errors.lock().unwrap().is_empty() && begin.elapsed() < Duration::from_secs(2) {
    std::thread::sleep(Duration::from_millis(10));
  }
  let errors = served.errors.lock().unwrap().clone();
  assert!(errors.iter().any(|el| el.contains("Http2")), "{errors:?}");
}

// Two servers on one runtime thread: shutting one down sends GOAWAY to its connections only, and
// the other keeps serving, its connections and new ones alike.
#[test]
fn fw_shutdown_reaches_only_its_server() {
  let addr = || {
    let uri = _uri();
    String::from(uri.hostname_with_implied_port().0) + ":" + &uri.port().unwrap().to_string()
  };
  let (addr_a, addr_b) = (addr(), addr());
  let signal = ShutdownSignal::new();
  let (thread_a, thread_b, thread_signal) = (addr_a.clone(), addr_b.clone(), signal.clone());
  let _jh = std::thread::spawn(move || -> crate::Result<()> {
    let runtime = Arc::new(UringRuntime::with_params(UringParams::default())?);
    let fw = || {
      Ok::<_, crate::Error>(
        Http2ServerFramework::<(), fn(crate::Error), UringExecutor, _, _, _>::new(
          UringExecutor::default(),
          ChaCha20::from_std_random()?,
          TlsConfig::plaintext(),
        )?
        .set_tcp_params(TcpParams::default().set_reuse_port(Some(false))),
      )
    };
    let router = || HttpRouter::paths(crate::paths!(("/", get(hello)), ("/slow", get(slow))));
    let (server_a, server_b) = (fw()?.set_shutdown(thread_signal, Duration::from_secs(3)), fw()?);
    let (router_a, router_b) = (router()?, router()?);
    let rt = runtime.clone();
    runtime.block_on(async move {
      let rt_b = rt.clone();
      let _jh = crate::executor::Executor::spawn_local(
        &UringExecutor::default(),
        async move { server_b.run_local(&thread_b, router_b, rt_b).await },
        &rt,
      );
      server_a.run_local(&thread_a, router_a, rt).await
    })
  });
  for addr in [&addr_a, &addr_b] {
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).is_err() {
      assert!(Instant::now() < deadline, "{addr} did not start");
      std::thread::sleep(Duration::from_millis(10));
    }
  }
  let mut client_a = connect(&addr_a);
  client_a.write_all(&headers_req(1, "GET", "/slow", &[], true)).unwrap();
  let mut client_b = connect(&addr_b);
  client_b.write_all(&headers_req(1, "GET", "/", &[], true)).unwrap();
  let (frames, _) = read(&mut client_b, Duration::from_secs(5), |frames| answered(frames, 1));
  assert!(answered(&frames, 1), "{frames:?}");
  signal.trigger();
  let (frames, _) = read(&mut client_a, Duration::from_secs(5), |frames| go_away(frames).is_some());
  assert!(go_away(&frames).is_some(), "the server shutting down sent no GOAWAY: {frames:?}");
  client_b.write_all(&headers_req(3, "GET", "/", &[], true)).unwrap();
  let (frames, _) = read(&mut client_b, Duration::from_secs(5), |frames| answered(frames, 3));
  assert!(go_away(&frames).is_none() && answered(&frames, 3), "the other server: {frames:?}");
  let mut late_b = connect(&addr_b);
  late_b.write_all(&headers_req(1, "GET", "/", &[], true)).unwrap();
  let (frames, _) = read(&mut late_b, Duration::from_secs(5), |frames| answered(frames, 1));
  assert!(go_away(&frames).is_none() && answered(&frames, 1), "a new connection: {frames:?}");
}
