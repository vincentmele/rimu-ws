//! The driver against a raw-frame client: a std socket in a thread, the server on an io_uring
//! runtime.

use crate::{
  collections::VectorUsize,
  executor::{Runtime as _, UringParams, UringRuntime, UringTcpListener, UringTcpStream},
  futures::Sleep,
  http::{
    HttpRecvParams, MsgBufferString, Protocol, Request, StatusCode,
    http2_server_framework::conn_driver::{Route, StreamDispatcher, drive_conn},
  },
  http2::{
    ServerStream,
    conn::{
    Http2Conn,
    scan::PREFACE,
    test_frames::{data, frame, headers_req, parse_all, settings},
    },
  },
  net::{StreamCommon, StreamReader, StreamWriter, TcpListener as _, TcpParams},
  rng::Xorshift64,
  sync::Arc,
  tests::_uri,
};
use alloc::{
  boxed::Box,
  rc::Rc,
  string::{String, ToString as _},
  vec,
  vec::Vec,
};
use core::{
  cell::Cell,
  pin::Pin,
  sync::atomic::{AtomicBool, Ordering},
  time::Duration,
};
use std::{
  net::TcpStream,
  sync::mpsc,
  time::Instant,
};

pub(crate) type Frames = Vec<(u8, u8, u32, Vec<u8>)>;
type AutoOut = super::AutoOutput;

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const RST_STREAM: u8 = 3;
const WINDOW_UPDATE: u8 = 8;

/// Handlers by path: `/` answers `ok`, `/slow` sleeps 20 ms, `/park` never finishes (and sets
/// `dropped` when dropped), `/panic` panics, `/echo` answers the length of the request body,
/// `/big` answers 1 MiB.
struct TestDispatcher {
  dropped: Arc<AtomicBool>,
}

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
  fn drop(&mut self) {
    self.0.store(true, Ordering::SeqCst);
  }
}

impl StreamDispatcher for TestDispatcher {
  type AutoFut = Pin<Box<dyn Future<Output = AutoOut>>>;
  type Matches = ();

  fn route(&self, _: &str) -> Route<()> {
    Route::Auto(())
  }

  fn manual(&self, _: ServerStream, _: Request<MsgBufferString>, (): ()) {}

  fn auto(&self, mut req: Request<MsgBufferString>, _: Option<Protocol>, _: Option<()>) -> Self::AutoFut {
    let dropped = self.dropped.clone();
    Box::pin(async move {
      let path = String::from(req.msg_data.uri.path());
      let body: Vec<u8> = match path.as_str() {
        "/slow" => {
          Sleep::new(Duration::from_millis(20)).unwrap().await.unwrap();
          b"slow".to_vec()
        }
        "/park" => {
          let _flag = DropFlag(dropped);
          core::future::pending::<()>().await;
          Vec::new()
        }
        "/panic" => panic!("handler panic"),
        "/echo" => req.msg_data.body.len().to_string().into_bytes(),
        "/big" => vec![7; 1 << 20],
        _ => b"ok".to_vec(),
      };
      req.msg_data.body.clear();
      req.msg_data.body.extend_from_copyable_slice(&body).unwrap();
      (req, None, Ok(StatusCode::Ok))
    })
  }
}

/// A stream that counts its writes.
struct Counting {
  inner: UringTcpStream,
  writes: Rc<Cell<usize>>,
}

impl StreamCommon for Counting {}

impl StreamReader for Counting {
  async fn read(
    &mut self,
    bytes: crate::collections::MaybeUninitSlice<'_, u8>,
  ) -> crate::Result<Option<core::num::NonZeroUsize>> {
    self.inner.read(bytes).await
  }

  fn try_read(
    &mut self,
    bytes: crate::collections::MaybeUninitSlice<'_, u8>,
  ) -> crate::Result<crate::net::TryRead> {
    self.inner.try_read(bytes)
  }

  async fn readable(&mut self) -> crate::Result<()> {
    self.inner.readable().await
  }
}

impl StreamWriter for Counting {
  async fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
    self.writes.set(self.writes.get() + 1);
    self.inner.write_all(bytes).await
  }

  async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<()> {
    self.writes.set(self.writes.get() + 1);
    self.inner.write_all_vectored(bytes).await
  }

  fn try_write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<bool> {
    let rslt = self.inner.try_write_all_vectored(bytes)?;
    if rslt {
      self.writes.set(self.writes.get() + 1);
    }
    Ok(rslt)
  }

  fn try_send_owned(&mut self, bytes: &mut Vec<u8>) -> crate::Result<bool> {
    let rslt = self.inner.try_send_owned(bytes)?;
    if rslt {
      self.writes.set(self.writes.get() + 1);
    }
    Ok(rslt)
  }
}

struct Served {
  addr: String,
  dropped: Arc<AtomicBool>,
  /// The driver's result and the number of writes it made.
  done: mpsc::Receiver<(crate::Result<()>, usize)>,
}

/// One connection served by `drive_conn` on a fresh runtime in its own thread.
fn serve(hp: HttpRecvParams) -> Served {
  let uri = _uri();
  let addr = String::from(uri.hostname_with_implied_port().0) + ":" + &uri.port().unwrap().to_string();
  let dropped = Arc::new(AtomicBool::new(false));
  let (tx, done) = mpsc::channel();
  let (ready_tx, ready_rx) = mpsc::channel();
  let server_addr = addr.clone();
  let server_dropped = dropped.clone();
  let _jh = std::thread::spawn(move || {
    let runtime = UringRuntime::with_params(UringParams::default()).unwrap();
    runtime.block_on(async move {
      let listener =
        UringTcpListener::bind(server_addr.as_str(), TcpParams::default().set_reuse_port(Some(false)))
          .await
          .unwrap();
      ready_tx.send(()).unwrap();
      let (stream, peer) = listener.accept(TcpParams::default()).await.unwrap();
      let writes = Rc::new(Cell::new(0));
      let mut counting = Counting { inner: stream, writes: writes.clone() };
      let conn = Http2Conn::<false>::new(hp, &mut Xorshift64::from(9u64));
      let dispatcher = TestDispatcher { dropped: server_dropped };
      let rslt = drive_conn(&mut counting, conn, &dispatcher, peer.ip()).await;
      tx.send((rslt, writes.get())).unwrap();
    });
  });
  ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
  Served { addr, dropped, done }
}

/// A raw-frame HTTP/2 client.
pub(crate) struct Client {
  buffer: Vec<u8>,
  stream: TcpStream,
}

impl Client {
  pub(crate) fn connect(addr: &str, extra_settings: &[(u16, u32)]) -> Self {
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let mut this = Self { buffer: Vec::new(), stream };
    let mut opening = PREFACE.to_vec();
    opening.extend(settings(extra_settings));
    this.send(&opening);
    this
  }

  pub(crate) fn send(&mut self, bytes: &[u8]) {
    std::io::Write::write_all(&mut self.stream, bytes).unwrap();
  }

  /// Every frame that arrives until `done` holds of all of them, or `timeout` passes.
  pub(crate) fn read_until(&mut self, timeout: Duration, mut done: impl FnMut(&Frames) -> bool) -> Frames {
    let deadline = Instant::now() + timeout;
    let mut frames = Frames::new();
    let mut chunk = [0; 65_536];
    while !done(&frames) && Instant::now() < deadline {
      match std::io::Read::read(&mut self.stream, &mut chunk) {
        Ok(0) => break,
        Ok(n) => {
          self.buffer.extend_from_slice(&chunk[..n]);
          let complete = complete_len(&self.buffer);
          frames.extend(parse_all(&self.buffer[..complete]));
          let _ = self.buffer.drain(..complete);
        }
        Err(err)
          if matches!(err.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
        Err(_) => break,
      }
    }
    frames
  }
}

/// Bytes of whole frames at the start of `bytes`.
pub(crate) fn complete_len(bytes: &[u8]) -> usize {
  let mut idx = 0;
  while let Some(header) = bytes.get(idx..idx + 9) {
    let len = usize::try_from(u32::from_be_bytes([0, header[0], header[1], header[2]])).unwrap();
    if bytes.len() < idx + 9 + len {
      break;
    }
    idx += 9 + len;
  }
  idx
}

/// Streams whose response ended, in the order they ended.
pub(crate) fn ended(frames: &Frames) -> Vec<u32> {
  frames
    .iter()
    .filter(|el| (el.0 == DATA || el.0 == HEADERS) && el.1 & 1 == 1)
    .map(|el| el.2)
    .collect()
}

pub(crate) fn body_of(frames: &Frames, stream: u32) -> Vec<u8> {
  frames.iter().filter(|el| el.0 == DATA && el.2 == stream).flat_map(|el| el.3.clone()).collect()
}

pub(crate) fn status_of(frames: &Frames, stream: u32) -> Option<u8> {
  // `:status` comes first, as a static-table index: 0x88 is 200, 0x8e is 500.
  frames.iter().find(|el| el.0 == HEADERS && el.2 == stream).map(|el| el.3[0])
}

#[test]
fn server_inline_ready_one_write() {
  let served = serve(HttpRecvParams::with_default_params().set_max_concurrent_streams_num(128));
  let mut client = Client::connect(&served.addr, &[]);
  let mut batch = Vec::new();
  for idx in 0..100u32 {
    batch.extend(headers_req(2 * idx + 1, "GET", "/", &[], true));
  }
  client.send(&batch);
  let frames = client.read_until(Duration::from_secs(5), |frames| ended(frames).len() == 100);
  assert_eq!(ended(&frames).len(), 100);
  assert!(frames.iter().filter(|el| el.0 == DATA).all(|el| el.3 == b"ok"));
  drop(client);
  let (rslt, writes) = served.done.recv_timeout(Duration::from_secs(5)).unwrap();
  assert!(rslt.is_ok(), "{rslt:?}");
  // The SETTINGS of the first turn, the 100 responses, and at most one more if the requests
  // arrived in two reads.
  assert!(writes <= 3, "{writes} writes for 100 responses");
}

#[test]
fn server_parked_handler_answered_later() {
  let served = serve(HttpRecvParams::with_default_params());
  let mut client = Client::connect(&served.addr, &[]);
  let mut batch = headers_req(1, "GET", "/slow", &[], true);
  for idx in 1..=10u32 {
    batch.extend(headers_req(2 * idx + 1, "GET", "/", &[], true));
  }
  client.send(&batch);
  let frames = client.read_until(Duration::from_secs(5), |frames| ended(frames).len() == 11);
  let order = ended(&frames);
  assert_eq!(order.len(), 11, "{order:?}");
  assert_eq!(*order.last().unwrap(), 1, "the slow handler finishes last: {order:?}");
  assert_eq!(body_of(&frames, 1), b"slow");
}

#[test]
fn server_reset_drops_parked_handler() {
  let served = serve(HttpRecvParams::with_default_params());
  let mut client = Client::connect(&served.addr, &[]);
  client.send(&headers_req(1, "GET", "/park", &[], true));
  let _ = client.read_until(Duration::from_millis(200), |_| false);
  assert!(!served.dropped.load(Ordering::SeqCst));
  let mut input = frame(RST_STREAM, 0, 1, &8u32.to_be_bytes());
  input.extend(headers_req(3, "GET", "/", &[], true));
  client.send(&input);
  let frames = client.read_until(Duration::from_secs(5), |frames| ended(frames).contains(&3));
  assert!(served.dropped.load(Ordering::SeqCst), "the parked future was not dropped");
  assert!(frames.iter().all(|el| el.2 != 1), "{frames:?}");
}

#[test]
fn server_handler_panic_isolated() {
  let served = serve(HttpRecvParams::with_default_params());
  let mut client = Client::connect(&served.addr, &[]);
  let mut batch = headers_req(1, "GET", "/panic", &[], true);
  for idx in 1..=9u32 {
    batch.extend(headers_req(2 * idx + 1, "GET", "/", &[], true));
  }
  client.send(&batch);
  let frames = client.read_until(Duration::from_secs(5), |frames| ended(frames).len() == 10);
  assert_eq!(ended(&frames).len(), 10);
  assert_eq!(status_of(&frames, 1), Some(0x8e), "500 for the panicking stream");
  for idx in 1..=9u32 {
    assert_eq!(status_of(&frames, 2 * idx + 1), Some(0x88));
  }
  client.send(&headers_req(21, "GET", "/", &[], true));
  let frames = client.read_until(Duration::from_secs(5), |frames| ended(frames).contains(&21));
  assert_eq!(body_of(&frames, 21), b"ok");
}

#[test]
fn server_auto_body_larger_than_window() {
  let served = serve(HttpRecvParams::with_default_params().set_initial_window_len(65_535));
  let mut client = Client::connect(&served.addr, &[]);
  client.send(&headers_req(1, "POST", "/echo", &[], false));
  let body = vec![1u8; 200 * 1024];
  let (mut sent, mut conn_window, mut stream_window) = (0usize, 65_535i64, 65_535i64);
  let mut frames = Frames::new();
  let deadline = Instant::now() + Duration::from_secs(5);
  while sent < body.len() {
    assert!(Instant::now() < deadline, "the server stopped opening its window at {sent} bytes");
    let room = usize::try_from(conn_window.min(stream_window).min(16_384)).unwrap_or(0);
    if room == 0 {
      let got = client.read_until(Duration::from_millis(100), |frames| {
        frames.iter().any(|el| el.0 == WINDOW_UPDATE)
      });
      for el in &got {
        if el.0 == WINDOW_UPDATE {
          let increment = i64::from(u32::from_be_bytes(el.3[..4].try_into().unwrap()));
          if el.2 == 0 { conn_window += increment } else { stream_window += increment }
        }
      }
      frames.extend(got);
      continue;
    }
    let n = room.min(body.len() - sent);
    let end = sent + n == body.len();
    client.send(&data(1, &body[sent..sent + n], end));
    sent += n;
    conn_window -= n as i64;
    stream_window -= n as i64;
  }
  frames.extend(client.read_until(Duration::from_secs(5), |frames| ended(frames).contains(&1)));
  assert_eq!(body_of(&frames, 1), b"204800");
}

#[test]
fn limit_send_queue_closes() {
  let hp = HttpRecvParams::with_default_params().set_max_send_queue_len(4 << 20);
  let served = serve(hp);
  // A window large enough that only the queue cap stops the server, and a client that never
  // reads.
  let mut client = Client::connect(&served.addr, &[(4, 0x7FFF_FFFF)]);
  let mut batch = frame(WINDOW_UPDATE, 0, 0, &0x7FFF_0000u32.to_be_bytes());
  for idx in 0..32u32 {
    batch.extend(headers_req(2 * idx + 1, "GET", "/big", &[], true));
  }
  client.send(&batch);
  let (rslt, _) = served.done.recv_timeout(Duration::from_secs(10)).expect("the server closed");
  assert!(rslt.is_err(), "{rslt:?}");
  drop(client);
}

#[test]
fn date_header_on_responses() {
  let served = serve(HttpRecvParams::with_default_params());
  let mut client = Client::connect(&served.addr, &[]);
  client.send(&headers_req(1, "GET", "/", &[], true));
  let frames = client.read_until(Duration::from_secs(5), |frames| ended(frames).contains(&1));
  let block = frames.iter().find(|el| el.0 == HEADERS).unwrap().3.clone();
  let mut dec = crate::http2::hpack_decoder::HpackDecoder::new();
  dec.set_max_bytes(4096);
  let mut names = VectorUsize::<String>::new();
  dec
    .decode(&block, |(_, name, _)| {
      names.push(String::from(name.str())).unwrap();
      Ok(())
    })
    .unwrap();
  assert!(names.iter().any(|el| el == "date"), "{:?}", names.as_slice());
}

#[test]
fn server_tls_preface_with_finished_uses_ktls() {
  use crate::{
    executor::StdRuntime,
    tests::{_PUBLIC_KEY, _ROOT_CA, _SECRET_KEY},
    tls::{TlsAcceptor, TlsConfig, TlsConnectorBuilder},
  };
  let ulp = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_ulp").unwrap_or_default();
  let offered = ulp.split_whitespace().any(|el| el == "tls");
  let uri = _uri();
  let (host, port) = uri.hostname_with_implied_port();
  let addr = alloc::format!("{host}:{port}");
  let client_uri = uri.clone();
  let client = std::thread::spawn(move || {
    StdRuntime::new().block_on(async move {
      let mut rng = <crate::rng::ChaCha20 as crate::rng::CryptoSeedableRng>::from_std_random().unwrap();
      let mut config = TlsConfig::from_trust_anchors_pem([_ROOT_CA]).unwrap();
      crate::http::push_h2_alpn(&mut config).unwrap();
      let mut tls_stream = loop {
        let connector = TlsConnectorBuilder::std(client_uri.clone()).build(&config, &mut rng).await;
        if let Ok(elem) = connector {
          break elem.connect().await.unwrap().tls_stream;
        }
        std::thread::sleep(Duration::from_millis(5));
      };
      // The preface and the first request go out right behind the client's Finished.
      let mut opening = PREFACE.to_vec();
      opening.extend(settings(&[]));
      opening.extend(headers_req(1, "GET", "/", &[], true));
      tls_stream.write_all(&opening).await.unwrap();
      let mut got = Vec::new();
      let mut answered = 0;
      let mut next_id = 3;
      let mut buf = [0u8; 16 * 1024];
      while answered < 8 {
        let len = tls_stream.read(buf.as_mut_slice().into()).await.unwrap().unwrap();
        got.extend_from_slice(&buf[..len.get()]);
        let complete = complete_len(&got);
        let frames = parse_all(&got[..complete]);
        let _ = got.drain(..complete);
        for _ in ended(&frames) {
          answered += 1;
          if next_id < 16 {
            tls_stream.write_all(&headers_req(next_id, "GET", "/", &[], true)).await.unwrap();
            next_id += 2;
          }
        }
      }
      answered
    })
  });
  let runtime = UringRuntime::with_params(UringParams::default()).unwrap();
  let kernel = runtime.block_on(async {
    let listener = UringTcpListener::bind(addr.as_str(), TcpParams::default().set_reuse_port(Some(false)))
      .await
      .unwrap();
    let (stream, peer) = listener.accept(TcpParams::default()).await.unwrap();
    let mut rng = <crate::rng::ChaCha20 as crate::rng::CryptoSeedableRng>::from_std_random().unwrap();
    let mut config = TlsConfig::from_keys_pem(_PUBLIC_KEY, _SECRET_KEY).unwrap();
    crate::http::push_h2_alpn(&mut config).unwrap();
    let mut tls_stream = TlsAcceptor::new(&config, &mut rng, stream).accept().await.unwrap().tls_stream;
    let conn = Http2Conn::<false>::new(HttpRecvParams::with_default_params(), &mut Xorshift64::from(5u64));
    let dispatcher = TestDispatcher { dropped: Arc::new(AtomicBool::new(false)) };
    let _rslt = drive_conn(&mut tls_stream, conn, &dispatcher, peer.ip()).await;
    tls_stream.is_kernel_tls()
  });
  assert_eq!(client.join().unwrap(), 8);
  assert_eq!(kernel, offered, "kernel TLS offered: {offered}");
}

// With user-space TLS a read is a future that waits for the peer: a handler that parks and wakes
// meanwhile must still get its response out, without the client sending anything more.
#[test]
fn server_userspace_tls_parked_handler_answers() {
  use crate::{
    executor::StdRuntime,
    tests::{_PUBLIC_KEY, _ROOT_CA, _SECRET_KEY},
    tls::{TlsAcceptor, TlsConfig, TlsConnectorBuilder},
  };
  let uri = _uri();
  let (host, port) = uri.hostname_with_implied_port();
  let addr = alloc::format!("{host}:{port}");
  let client_uri = uri.clone();
  let (done_tx, done_rx) = mpsc::channel();
  let _client = std::thread::spawn(move || {
    StdRuntime::new().block_on(async move {
      let mut rng = <crate::rng::ChaCha20 as crate::rng::CryptoSeedableRng>::from_std_random().unwrap();
      let mut config = TlsConfig::from_trust_anchors_pem([_ROOT_CA]).unwrap();
      crate::http::push_h2_alpn(&mut config).unwrap();
      let mut tls_stream = loop {
        let connector = TlsConnectorBuilder::std(client_uri.clone()).build(&config, &mut rng).await;
        if let Ok(elem) = connector {
          break elem.connect().await.unwrap().tls_stream;
        }
        std::thread::sleep(Duration::from_millis(5));
      };
      let mut opening = PREFACE.to_vec();
      opening.extend(settings(&[]));
      opening.extend(frame(4, 1, 0, &[]));
      opening.extend(headers_req(1, "GET", "/slow", &[], true));
      tls_stream.write_all(&opening).await.unwrap();
      let mut got = Vec::new();
      let mut buf = [0u8; 16 * 1024];
      loop {
        let len = tls_stream.read(buf.as_mut_slice().into()).await.unwrap().unwrap();
        got.extend_from_slice(&buf[..len.get()]);
        let complete = complete_len(&got);
        if ended(&parse_all(&got[..complete])).contains(&1) {
          break;
        }
      }
      done_tx.send(()).unwrap();
    });
  });
  let _server = std::thread::spawn(move || {
    let runtime = UringRuntime::with_params(UringParams::default()).unwrap();
    runtime.block_on(async {
      let listener = UringTcpListener::bind(addr.as_str(), TcpParams::default().set_reuse_port(Some(false)))
        .await
        .unwrap();
      let (stream, peer) = listener.accept(TcpParams::default()).await.unwrap();
      let mut rng = <crate::rng::ChaCha20 as crate::rng::CryptoSeedableRng>::from_std_random().unwrap();
      let mut config = TlsConfig::from_keys_pem(_PUBLIC_KEY, _SECRET_KEY).unwrap();
      crate::http::push_h2_alpn(&mut config).unwrap();
      *config.kernel_tls_mut() = false;
      let mut tls_stream = TlsAcceptor::new(&config, &mut rng, stream).accept().await.unwrap().tls_stream;
      let conn = Http2Conn::<false>::new(HttpRecvParams::with_default_params(), &mut Xorshift64::from(5u64));
      let dispatcher = TestDispatcher { dropped: Arc::new(AtomicBool::new(false)) };
      let _rslt = drive_conn(&mut tls_stream, conn, &dispatcher, peer.ip()).await;
    });
  });
  assert!(done_rx.recv_timeout(Duration::from_secs(5)).is_ok(), "no response to the parked handler");
}
