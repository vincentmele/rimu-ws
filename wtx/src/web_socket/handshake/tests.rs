macro_rules! call_tests {
  (($method:ident, $ws:expr), $($struct:ident),+ $(,)?) => {
    $(
      $struct::$method($ws).await;
      Sleep::new(Duration::from_millis(200)).unwrap().await.unwrap();
    )+
  };
}

use crate::{
  collections::VectorUsize,
  executor::StdRuntime,
  futures::Sleep,
  rng::{ChaCha20, CryptoSeedableRng},
  sync::{Arc, AtomicBool},
  tests::_uri,
  tls::{PlaintextCtx, TlsAcceptor, TlsConfig, TlsConnectorBuilder},
  web_socket::{
    Frame, OpCode, WebSocket, WebSocketAcceptor, WebSocketConnector, WebSocketPayloadOrigin,
    WsCompression, web_socket_compression::NegotiatedWsCompression,
  },
};
use core::{sync::atomic::Ordering, time::Duration};
use std::net::{TcpListener, TcpStream};

static HAS_SERVER_FINISHED: AtomicBool = AtomicBool::new(false);

type LocalWebSocket<NC, const IS_CLIENT: bool> = WebSocket<NC, TcpStream, PlaintextCtx, IS_CLIENT>;

#[cfg_attr(miri, ignore)]
#[cfg(feature = "zlib-rs")]
#[test]
fn compressed() {
  let runtime = Arc::new(StdRuntime::new());
  let runtime_fut0 = runtime.clone();
  let runtime_fut1 = runtime.clone();
  let runtime_fut2 = runtime.clone();
  runtime.block_on(async {
    use crate::web_socket::web_socket_compression::ZlibRs;
    do_test_client_and_server_frames(((), false), (ZlibRs::default(), false), runtime_fut0).await;
    Sleep::new(Duration::from_millis(200)).unwrap().await.unwrap();
    do_test_client_and_server_frames((ZlibRs::default(), false), ((), false), runtime_fut1).await;
    Sleep::new(Duration::from_millis(200)).unwrap().await.unwrap();
    do_test_client_and_server_frames(
      (ZlibRs::default(), false),
      (ZlibRs::default(), false),
      runtime_fut2,
    )
    .await;
  });
}

#[cfg_attr(miri, ignore)]
#[test]
fn uncompressed() {
  let runtime = Arc::new(StdRuntime::new());
  let runtime_fut = runtime.clone();
  runtime.block_on(do_test_client_and_server_frames(((), false), ((), false), runtime_fut));
}

#[cfg_attr(miri, ignore)]
#[test]
fn uncompressed_no_masking() {
  let runtime = Arc::new(StdRuntime::new());
  let runtime_fut = runtime.clone();
  runtime.block_on(do_test_client_and_server_frames(((), true), ((), true), runtime_fut));
}

async fn do_test_client_and_server_frames<CC, SC>(
  (client_compression, client_no_masking): (CC, bool),
  (server_compression, server_no_masking): (SC, bool),
  runtime: Arc<StdRuntime>,
) where
  CC: WsCompression<true> + Send,
  CC::NegotiatedCompression: Send,
  SC: WsCompression<false> + Send + 'static,
  SC::NegotiatedCompression: Send,
  for<'nc> &'nc SC::NegotiatedCompression: Send,
{
  let uri = _uri();

  let listener = TcpListener::bind(uri.hostname_with_implied_port()).unwrap();
  let _fut = runtime
    .spawn(async move {
      let (stream, _) = listener.accept().unwrap();
      let mut ws = WebSocketAcceptor::default()
        .set_compression(server_compression)
        .set_no_masking(server_no_masking)
        .accept(TlsAcceptor::new(
          &TlsConfig::plaintext(),
          &mut ChaCha20::from_std_random().unwrap(),
          stream,
        ))
        .await
        .unwrap();
      call_tests!(
        (server, &mut ws),
        FragmentedText,
        LargeFragmentedText,
        PingAndText,
        PingBetweenFragmentedText,
        TwoPings,
        BufferedEcho,
        // Last,
        HelloAndGoodbye,
      );
      HAS_SERVER_FINISHED.store(true, Ordering::Relaxed);
    })
    .unwrap();

  let mut ws = WebSocketConnector::default()
    .set_compression(client_compression)
    .set_no_masking(client_no_masking)
    .connect(
      TlsConnectorBuilder::std(uri)
        .build(&TlsConfig::plaintext(), &mut ChaCha20::from_std_random().unwrap())
        .await
        .unwrap(),
    )
    .await
    .unwrap();
  call_tests!(
    (client, &mut ws),
    FragmentedText,
    LargeFragmentedText,
    PingAndText,
    PingBetweenFragmentedText,
    TwoPings,
    BufferedEcho,
    // Last,
    HelloAndGoodbye,
  );

  let mut has_server_finished = false;
  for _ in 0..15 {
    let local_has_server_finished = HAS_SERVER_FINISHED.load(Ordering::Relaxed);
    if local_has_server_finished {
      has_server_finished = local_has_server_finished;
      break;
    }
    Sleep::new(Duration::from_millis(200)).unwrap().await.unwrap();
  }
  if !has_server_finished {
    panic!("Server didn't finish");
  }
}

trait Test<NC> {
  async fn client(ws: &mut LocalWebSocket<NC, true>);

  async fn server(ws: &mut LocalWebSocket<NC, false>);
}

struct FragmentedText;
impl<NC> Test<NC> for FragmentedText
where
  NC: NegotiatedWsCompression,
{
  async fn client(ws: &mut LocalWebSocket<NC, true>) {
    ws.write_frame(&mut Frame::new_unfin(OpCode::Text, &mut [b'1']).unwrap()).await.unwrap();
    ws.write_frame(&mut Frame::new_fin(OpCode::Continuation, &mut [b'2', b'3']).unwrap())
      .await
      .unwrap();
  }

  async fn server(ws: &mut LocalWebSocket<NC, false>) {
    let mut buffer = VectorUsize::new();
    let text = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
    assert_eq!((OpCode::Text, "123".as_bytes()), (text.op_code(), &**text.payload()));
  }
}

// Sixteen texts with a ping in the middle, echoed through the write queue: the first half with
// `WebSocket` itself, the second with the `split_mut` parts. The pong has to come out after the
// eight echoes queued in front of it.
struct BufferedEcho;
impl<NC> Test<NC> for BufferedEcho
where
  NC: NegotiatedWsCompression,
{
  async fn client(ws: &mut LocalWebSocket<NC, true>) {
    for idx in 0u8..16 {
      if idx == 8 {
        ws.write_frame(&mut Frame::new_fin(OpCode::Ping, *b"p").unwrap()).await.unwrap();
      }
      ws.write_frame(&mut Frame::new_fin(OpCode::Text, [b'a' + idx]).unwrap()).await.unwrap();
    }
    let mut buffer = VectorUsize::new();
    for idx in 0u8..16 {
      if idx == 8 {
        let pong = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
        assert_eq!((OpCode::Pong, &b"p"[..]), (pong.op_code(), &**pong.payload()));
      }
      let text = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
      assert_eq!((OpCode::Text, &[b'a' + idx][..]), (text.op_code(), &**text.payload()));
    }
  }

  async fn server(ws: &mut LocalWebSocket<NC, false>) {
    let mut buffer = VectorUsize::new();
    for idx in 0u8..8 {
      let text = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
      assert_eq!((OpCode::Text, &[b'a' + idx][..]), (text.op_code(), &**text.payload()));
      let mut payload = [b'a' + idx];
      ws.write_frame_buffered(&mut Frame::new_fin(OpCode::Text, &mut payload).unwrap())
        .await
        .unwrap();
    }
    let ping = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
    assert_eq!(OpCode::Ping, ping.op_code());
    let (mut common, mut reader, mut writer) = ws.split_mut();
    for idx in 8u8..16 {
      let mut text = reader
        .read_frame(&mut buffer, &mut common, WebSocketPayloadOrigin::Adaptive)
        .await
        .unwrap();
      assert_eq!((OpCode::Text, &[b'a' + idx][..]), (text.op_code(), &**text.payload()));
      writer.write_frame_buffered(&mut common, &mut text).await.unwrap();
    }
    writer.flush(&mut common).await.unwrap();
  }
}

struct HelloAndGoodbye;
impl<NC> Test<NC> for HelloAndGoodbye
where
  NC: NegotiatedWsCompression,
{
  async fn client(ws: &mut LocalWebSocket<NC, true>) {
    let mut buffer = VectorUsize::new();
    let hello = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
    assert_eq!((OpCode::Text, "Hello!".as_bytes()), (hello.op_code(), &**hello.payload()));
    ws.write_frame(&mut Frame::new_fin(OpCode::Text, *b"Goodbye!").unwrap()).await.unwrap();
    assert_eq!(
      ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive)
        .await
        .unwrap()
        .payload()
        .get(2..),
      Some(&b"PS: s2"[..])
    );
  }

  async fn server(ws: &mut LocalWebSocket<NC, false>) {
    let mut buffer = VectorUsize::new();
    ws.write_frame(&mut Frame::new_fin(OpCode::Text, *b"Hello!").unwrap()).await.unwrap();
    assert_eq!(
      ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap().payload(),
      b"Goodbye!"
    );
    let ps = [3, 232, 80, 83, 58, 32, 115, 50];
    ws.write_frame(&mut Frame::new_fin(OpCode::Close, ps).unwrap()).await.unwrap();
  }
}

struct LargeFragmentedText;
impl<NC> Test<NC> for LargeFragmentedText
where
  NC: NegotiatedWsCompression,
{
  async fn client(ws: &mut LocalWebSocket<NC, true>) {
    let bytes = || VectorUsize::from_vec(alloc::vec![b'1'; 256 * 1024]).unwrap();
    ws.write_frame(&mut Frame::new_unfin(OpCode::Text, &mut bytes()).unwrap()).await.unwrap();
    ws.write_frame(&mut Frame::new_unfin(OpCode::Continuation, &mut bytes()).unwrap())
      .await
      .unwrap();
    ws.write_frame(&mut Frame::new_unfin(OpCode::Continuation, &mut bytes()).unwrap())
      .await
      .unwrap();
    ws.write_frame(&mut Frame::new_unfin(OpCode::Continuation, &mut bytes()).unwrap())
      .await
      .unwrap();
    ws.write_frame(&mut Frame::new_unfin(OpCode::Continuation, &mut bytes()).unwrap())
      .await
      .unwrap();
    ws.write_frame(&mut Frame::new_unfin(OpCode::Continuation, &mut bytes()).unwrap())
      .await
      .unwrap();
    ws.write_frame(&mut Frame::new_unfin(OpCode::Continuation, &mut bytes()).unwrap())
      .await
      .unwrap();
    ws.write_frame(&mut Frame::new_unfin(OpCode::Continuation, &mut bytes()).unwrap())
      .await
      .unwrap();
    ws.write_frame(&mut Frame::new_unfin(OpCode::Continuation, &mut bytes()).unwrap())
      .await
      .unwrap();
    ws.write_frame(&mut Frame::new_fin(OpCode::Continuation, &mut bytes()).unwrap()).await.unwrap();
  }

  async fn server(ws: &mut LocalWebSocket<NC, false>) {
    let mut buffer = VectorUsize::new();
    let text = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
    assert_eq!(
      (
        OpCode::Text,
        VectorUsize::from_vec(alloc::vec![b'1'; 10 * 256 * 1024]).unwrap().as_slice().len()
      ),
      (text.op_code(), text.payload().len())
    );
  }
}

struct PingAndText;
impl<NC> Test<NC> for PingAndText
where
  NC: NegotiatedWsCompression,
{
  async fn client(ws: &mut LocalWebSocket<NC, true>) {
    let mut buffer = VectorUsize::new();
    ws.write_frame(&mut Frame::new_fin(OpCode::Ping, *b"123").unwrap()).await.unwrap();
    ws.write_frame(&mut Frame::new_fin(OpCode::Text, *b"ipat").unwrap()).await.unwrap();
    assert_eq!(
      OpCode::Pong,
      ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap().op_code()
    );
  }

  async fn server(ws: &mut LocalWebSocket<NC, false>) {
    let mut buffer = VectorUsize::new();
    let frame = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
    assert_eq!((OpCode::Ping, "123".as_bytes()), (frame.op_code(), &**frame.payload()));
    let frame = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
    assert_eq!((OpCode::Text, "ipat".as_bytes()), (frame.op_code(), &**frame.payload()));
  }
}

struct PingBetweenFragmentedText;
impl<NC> Test<NC> for PingBetweenFragmentedText
where
  NC: NegotiatedWsCompression,
{
  async fn client(ws: &mut LocalWebSocket<NC, true>) {
    let mut buffer = VectorUsize::new();
    ws.write_frame(&mut Frame::new_unfin(OpCode::Text, &mut [b'1']).unwrap()).await.unwrap();
    ws.write_frame(&mut Frame::new_fin(OpCode::Ping, &mut [b'9']).unwrap()).await.unwrap();
    ws.write_frame(&mut Frame::new_fin(OpCode::Continuation, &mut [b'2', b'3']).unwrap())
      .await
      .unwrap();
    assert_eq!(
      OpCode::Pong,
      ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap().op_code()
    );
  }

  async fn server(ws: &mut LocalWebSocket<NC, false>) {
    let mut buffer = VectorUsize::new();
    let frame = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
    assert_eq!((OpCode::Ping, "9".as_bytes()), (frame.op_code(), &**frame.payload()));
    let frame = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
    assert_eq!((OpCode::Text, "123".as_bytes()), (frame.op_code(), &**frame.payload()));
  }
}

struct TwoPings;
impl<NC> Test<NC> for TwoPings
where
  NC: NegotiatedWsCompression,
{
  async fn client(ws: &mut LocalWebSocket<NC, true>) {
    let mut buffer = VectorUsize::new();
    ws.write_frame(&mut Frame::new_fin(OpCode::Ping, *b"0").unwrap()).await.unwrap();
    ws.write_frame(&mut Frame::new_fin(OpCode::Ping, *b"1").unwrap()).await.unwrap();
    let zero = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
    assert_eq!((OpCode::Pong, "0".as_bytes()), (zero.op_code(), &**zero.payload()));
    let one = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
    assert_eq!((OpCode::Pong, "1".as_bytes()), (one.op_code(), &**one.payload()));
    ws.write_frame(&mut Frame::new_fin(OpCode::Text, *b"2").unwrap()).await.unwrap();
  }

  async fn server(ws: &mut LocalWebSocket<NC, false>) {
    let mut buffer = VectorUsize::new();
    let zero = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
    assert_eq!((OpCode::Ping, "0".as_bytes()), (zero.op_code(), &**zero.payload()));
    let one = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
    assert_eq!((OpCode::Ping, "1".as_bytes()), (one.op_code(), &**one.payload()));
    let two = ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap();
    assert_eq!((OpCode::Text, "2".as_bytes()), (two.op_code(), &**two.payload()));
  }
}

// ---- Upgrade requests a public server gets: what it must refuse, and how much it may read.

/// Whether the server upgraded `input`, what it answered, and how many bytes it read.
fn serve(input: &[u8], chunk: usize) -> (bool, std::string::String, usize) {
  let served = crate::web_socket::handshake_check::serve(input, chunk);
  let answer = std::string::String::from_utf8_lossy(&served.answer).into_owned();
  (served.upgraded, answer, served.read)
}

// Each case the fuzzer starts from passes its oracle.
#[test]
fn fuzz_oracle_holds_for_the_seed_cases() {
  let mut endless = std::vec![1];
  endless.extend_from_slice(b"GET / HTTP/1.1\r\nX: ");
  endless.resize(64 * 1024, b'a');
  let mut valid = std::vec![3];
  valid.extend(request("GET / HTTP/1.1", &refs(&valid_headers())));
  for case in [std::vec![], std::vec![0], endless, valid, b"\xffGET".to_vec()] {
    crate::web_socket::handshake_check::check_bytes(&case);
  }
}

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

fn request(request_line: &str, headers: &[&str]) -> std::vec::Vec<u8> {
  let mut out = std::format!("{request_line}\r\n");
  for header in headers {
    out.push_str(header);
    out.push_str("\r\n");
  }
  out.push_str("\r\n");
  out.into_bytes()
}

fn valid_headers() -> std::vec::Vec<std::string::String> {
  std::vec![
    "Host: example.com".into(),
    "Upgrade: websocket".into(),
    "Connection: Upgrade".into(),
    std::format!("Sec-WebSocket-Key: {KEY}"),
    "Sec-WebSocket-Version: 13".into(),
  ]
}

fn without(name: &str) -> std::vec::Vec<std::string::String> {
  valid_headers().into_iter().filter(|el| !el.starts_with(name)).collect()
}

fn refs(headers: &[std::string::String]) -> std::vec::Vec<&str> {
  headers.iter().map(std::string::String::as_str).collect()
}

#[test]
fn a_valid_request_is_upgraded() {
  let headers = valid_headers();
  let (upgraded, answer, _) = serve(&request("GET / HTTP/1.1", &refs(&headers)), 1024);
  assert!(upgraded, "{answer}");
  assert!(answer.starts_with("HTTP/1.1 101"), "{answer}");
  assert!(answer.contains(ACCEPT), "{answer}");
}

// Firefox sends `Connection: keep-alive, Upgrade`; header names and tokens are case-insensitive.
#[test]
fn tokens_in_lists_and_any_case_are_upgraded() {
  let mut headers = without("Connection");
  headers.retain(|el| !el.starts_with("Upgrade"));
  headers.push("connection: keep-alive, Upgrade".into());
  headers.push("UPGRADE: WebSocket".into());
  let (upgraded, answer, _) = serve(&request("GET /chat HTTP/1.1", &refs(&headers)), 7);
  assert!(upgraded, "{answer}");
  assert!(answer.contains(ACCEPT), "{answer}");
}

// RFC 6455 4.2.1: each of these gets a 400, not a 101.
#[test]
fn requests_rfc_6455_refuses_get_a_400() {
  let short_key = {
    let mut headers = without("Sec-WebSocket-Key");
    headers.push("Sec-WebSocket-Key: AAAAAAAAAAA=".into());
    headers
  };
  let not_base64 = {
    let mut headers = without("Sec-WebSocket-Key");
    headers.push("Sec-WebSocket-Key: !!!!!!!!!!!!!!!!!!!!!!==".into());
    headers
  };
  let cases: [(&str, &str, std::vec::Vec<std::string::String>); 8] = [
    ("no Upgrade", "GET / HTTP/1.1", without("Upgrade")),
    ("no Connection", "GET / HTTP/1.1", without("Connection")),
    ("no Host", "GET / HTTP/1.1", without("Host")),
    ("no key", "GET / HTTP/1.1", without("Sec-WebSocket-Key")),
    ("short key", "GET / HTTP/1.1", short_key),
    ("key not base64", "GET / HTTP/1.1", not_base64),
    ("HTTP/1.0", "GET / HTTP/1.0", valid_headers()),
    ("POST", "POST / HTTP/1.1", valid_headers()),
  ];
  for (name, request_line, headers) in cases {
    let (upgraded, answer, _) = serve(&request(request_line, &refs(&headers)), 1024);
    assert!(!upgraded, "{name}: {answer}");
    assert!(answer.starts_with("HTTP/1.1 400"), "{name}: {answer}");
  }
}

// RFC 6455 4.4: the 400 for another version names the one the server speaks.
#[test]
fn another_version_gets_a_400_naming_13() {
  let mut headers = without("Sec-WebSocket-Version");
  headers.push("Sec-WebSocket-Version: 8".into());
  let (upgraded, answer, _) = serve(&request("GET / HTTP/1.1", &refs(&headers)), 1024);
  assert!(!upgraded, "{answer}");
  assert!(answer.starts_with("HTTP/1.1 400"), "{answer}");
  assert!(answer.contains("Sec-WebSocket-Version: 13"), "{answer}");
  let (upgraded, answer, _) = serve(&request("GET / HTTP/1.1", &refs(&without("Sec-WebSocket-Version"))), 1024);
  assert!(!upgraded && answer.contains("Sec-WebSocket-Version: 13"), "{answer}");
}

// A request that never ends is refused once it passes the cap, not read to the end: a server
// that kept reading would hold, and re-parse, as much as the client sent.
#[test]
fn an_endless_request_is_refused_at_the_cap() {
  let mut input = b"GET / HTTP/1.1\r\nHost: x\r\nX-Pad: ".to_vec();
  input.resize(input.len() + (1 << 20), b'a');
  let (upgraded, answer, read) = serve(&input, 1024);
  assert!(!upgraded);
  assert!(answer.starts_with("HTTP/1.1 431"), "{answer}");
  assert!(read <= 2 * super::MAX_REQUEST_LEN, "read {read} bytes");
}

// Proxies and CDNs add headers: a few dozen are upgraded, hundreds get a 431.
#[test]
fn header_count_is_generous_but_bounded() {
  let mut headers = valid_headers();
  headers.extend((0..40).map(|idx| std::format!("X-Forwarded-{idx}: 10.0.0.{idx}")));
  let (upgraded, answer, _) = serve(&request("GET / HTTP/1.1", &refs(&headers)), 1024);
  assert!(upgraded, "{answer}");
  headers.extend((0..200).map(|idx| std::format!("X-Many-{idx}: v")));
  let (upgraded, answer, _) = serve(&request("GET / HTTP/1.1", &refs(&headers)), 1024);
  assert!(!upgraded);
  assert!(answer.starts_with("HTTP/1.1 431"), "{answer}");
}

// Malformed HTTP gets a 400, not a silent close.
#[test]
fn malformed_http_gets_a_400() {
  let mut input = request("GET / HTTP/1.1", &refs(&valid_headers()));
  input.splice(16..16, b"a header without a colon\r\n".iter().copied());
  let (upgraded, answer, _) = serve(&input, 1024);
  assert!(!upgraded);
  assert!(answer.starts_with("HTTP/1.1 400"), "{answer}");
}

// Requests arrive in pieces over a real network: every split upgrades.
#[test]
fn a_request_split_across_reads_is_upgraded() {
  let input = request("GET / HTTP/1.1", &refs(&valid_headers()));
  for chunk in [1, 2, 3, 7, 100, 1024] {
    let (upgraded, answer, _) = serve(&input, chunk);
    assert!(upgraded, "chunk {chunk}: {answer}");
    assert!(answer.contains(ACCEPT), "chunk {chunk}: {answer}");
  }
}

/// Connects a client to a server thread that answers the upgrade with `respond(key)`, written a
/// byte at a time when `trickle`.
fn connect_to(respond: fn(&str) -> std::string::String, trickle: bool) -> bool {
  use std::io::{Read, Write};
  let uri = _uri();
  let listener = TcpListener::bind(uri.hostname_with_implied_port()).unwrap();
  let server = std::thread::spawn(move || {
    let (mut stream, _) = listener.accept().unwrap();
    stream.set_nodelay(true).unwrap();
    let mut head = std::vec::Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap() == 1 {
      head.push(byte[0]);
    }
    let head = std::string::String::from_utf8(head).unwrap();
    let key = std::string::String::from(
      head.lines().find_map(|el| el.strip_prefix("Sec-WebSocket-Key: ")).unwrap().trim(),
    );
    let res = respond(&key);
    if trickle {
      for byte in res.as_bytes() {
        stream.write_all(&[*byte]).unwrap();
        std::thread::sleep(Duration::from_micros(200));
      }
    } else {
      stream.write_all(res.as_bytes()).unwrap();
    }
    std::thread::sleep(Duration::from_millis(100));
  });
  let connected = StdRuntime::new().block_on(async {
    WebSocketConnector::default()
      .connect(
        TlsConnectorBuilder::std(uri)
          .build(&TlsConfig::plaintext(), &mut ChaCha20::from_std_random().unwrap())
          .await
          .unwrap(),
      )
      .await
      .is_ok()
  });
  server.join().unwrap();
  connected
}

fn res101(accept: &str) -> std::string::String {
  std::format!(
    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
  )
}

// RFC 6455 4.1: the client checks the server's answer to its key, and its Upgrade and Connection.
#[cfg_attr(miri, ignore)]
#[test]
fn client_checks_the_servers_answer() {
  let right = |key: &str| {
    let mut buffer = [0; 30];
    res101(crate::misc::from_utf8_basic(super::derived_key(&mut buffer, key.as_bytes())).unwrap())
  };
  assert!(connect_to(right, false));
  // Responses arrive in pieces too.
  assert!(connect_to(right, true));
  assert!(!connect_to(|_| res101("c29tZXRoaW5nIGVsc2UgZW50aXJlbHk="), false));
  let no_upgrade = |key: &str| {
    let mut buffer = [0; 30];
    let accept = crate::misc::from_utf8_basic(super::derived_key(&mut buffer, key.as_bytes())).unwrap();
    std::format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n")
  };
  assert!(!connect_to(no_upgrade, false));
}
