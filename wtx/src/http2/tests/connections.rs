use crate::{
  collections::VectorUsize,
  executor::{StdRuntime, UringExecutor},
  http::{
    Header, Headers, HttpRecvParams, MsgBufferString, MsgData, MsgDataMut, ReqBuilder, StatusCode,
    http2_server_framework::{Http2ServerFramework, HttpRouter, State, VerbatimParams, get},
  },
  http2::{Http2, Http2Buffer, Http2ErrorCode},
  net::{Stream as _, TcpParams, UriRef, UriString},
  rng::{ChaCha20, CryptoSeedableRng, SeedableRng, Xorshift64},
  tests::_uri,
  tls::{PlaintextCtx, TlsConfig, TlsConnectorBuilder},
};
use alloc::string::{String, ToString as _};
use core::{num::NonZeroUsize, time::Duration};
use std::net::TcpStream;

// FIXME(MIRI): socket support
#[cfg_attr(miri, ignore)]
#[test]
fn connections() {
  let runtime = StdRuntime::new();
  let uri = _uri();
  server(&uri, &runtime);
  let client_fut = client(&uri, &runtime);
  runtime.block_on(client_fut);
}

async fn client(uri: &UriString, runtime: &StdRuntime) {
  let mut msg_buffer = MsgBufferString::default();
  msg_buffer.headers.reserve(6).unwrap();
  let tls_stream = TlsConnectorBuilder::std(uri)
    .build(&TlsConfig::plaintext(), ChaCha20::from_std_random().unwrap())
    .await
    .unwrap()
    .connect()
    .await
    .unwrap()
    .tls_stream;
  let (frame_header, mut http2) = Http2::connect(
    Http2Buffer::new(&mut Xorshift64::from_simple_seed().unwrap()),
    HttpRecvParams::with_optioned_params(),
    tls_stream.into_split().unwrap(),
  )
  .await
  .unwrap();
  let _jh = runtime.spawn(frame_header).unwrap();

  let uri_ref = uri.to_ref();

  msg_buffer = stream_client(&mut http2, msg_buffer, uri_ref).await;
  _0(msg_buffer.body(), msg_buffer.headers());

  msg_buffer.clear();
  msg_buffer.headers.push_from_iter(Header::from_name_and_value("123", ["456"])).unwrap();
  msg_buffer = stream_client(&mut http2, msg_buffer, uri_ref).await;
  _1(msg_buffer.body(), msg_buffer.headers());

  msg_buffer.clear();
  msg_buffer.body.extend_from_copyable_slice(b"123").unwrap();
  msg_buffer = stream_client(&mut http2, msg_buffer, uri_ref).await;
  _2(msg_buffer.body(), msg_buffer.headers());

  msg_buffer.clear();
  msg_buffer.body.extend_from_copyable_slice(b"123").unwrap();
  msg_buffer.headers.push_from_iter(Header::from_name_and_value("123", ["456"])).unwrap();
  msg_buffer = stream_client(&mut http2, msg_buffer, uri_ref).await;
  _3(msg_buffer.body(), msg_buffer.headers());

  http2.send_go_away(Http2ErrorCode::NoError).await;

  crate::futures::Sleep::new(Duration::from_millis(100)).unwrap().await.unwrap();
}

/// The framework on an io_uring runtime in its own thread, echoing each request's headers and
/// body.
fn server(uri: &UriString, _runtime: &StdRuntime) {
  async fn echo(_: State<'_, ()>) -> crate::Result<VerbatimParams> {
    Ok(VerbatimParams(StatusCode::Ok))
  }
  let addr = String::from(uri.hostname_with_implied_port().0) + ":"
    + &uri.port().unwrap_or(80).to_string();
  let server_addr = addr.clone();
  let _jh = std::thread::spawn(move || {
    let router = HttpRouter::paths(crate::paths!(("/", get(echo)))).unwrap();
    Http2ServerFramework::<(), fn(crate::Error), UringExecutor, _, _, _>::new(
      UringExecutor::default(),
      ChaCha20::from_std_random().unwrap(),
      TlsConfig::plaintext(),
    )
    .unwrap()
    .set_http_recv_params(HttpRecvParams::with_optioned_params())
    .set_local_runtimes(NonZeroUsize::new(1))
    .set_tcp_params(TcpParams::default().set_reuse_port(Some(false)))
    .run_in_threads(&server_addr, router)
    .unwrap();
  });
  for _ in 0..200 {
    if TcpStream::connect(&addr).is_ok() {
      return;
    }
    std::thread::sleep(Duration::from_millis(10));
  }
  panic!("the server did not start");
}

async fn stream_client(
  client: &mut Http2<TcpStream, PlaintextCtx, true>,
  msg_buffer: MsgBufferString,
  uri: UriRef<'_>,
) -> MsgBufferString {
  let mut stream = client.stream().await.unwrap();
  let rb = ReqBuilder::get((msg_buffer.body.as_ref(), &msg_buffer.headers, uri));
  let _ = stream.send_req(&mut VectorUsize::new(), rb.into_request()).await.unwrap();
  stream.recv_res().await.unwrap().1
}

// The server echoes the request's fields and body, and adds `content-length` and `date`.
fn has_echoed_field(headers: &Headers) -> bool {
  headers.iter().any(|el| el.name == "123" && el.value == "456")
}

#[track_caller]
fn _0(body: &[u8], headers: &Headers) {
  assert_eq!(body.len(), 0);
  assert!(!has_echoed_field(headers));
}
#[track_caller]
fn _1(body: &[u8], headers: &Headers) {
  assert_eq!(body.len(), 0);
  assert!(has_echoed_field(headers));
}
#[track_caller]
fn _2(body: &[u8], headers: &Headers) {
  assert_eq!(body.len(), 3);
  assert!(!has_echoed_field(headers));
}
#[track_caller]
fn _3(body: &[u8], headers: &Headers) {
  assert_eq!(body.len(), 3);
  assert!(has_echoed_field(headers));
}
