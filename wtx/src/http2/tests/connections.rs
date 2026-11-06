use crate::{
  collections::VectorUsize,
  executor::{StdRuntime, UringExecutor},
  http::{
    Header, Headers, HttpRecvParams, MsgBufferString, MsgData, MsgDataMut, ReqBuilder, StatusCode,
    http2_server_framework::{Http2ServerFramework, HttpRouter, State, VerbatimParams, get},
  },
  http2::{Http2, Http2Buffer, Http2ErrorCode, Http2RecvStatus},
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
  let addr =
    String::from(uri.hostname_with_implied_port().0) + ":" + &uri.port().unwrap_or(80).to_string();
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

async fn connect_client(
  uri: &UriString,
  runtime: &StdRuntime,
) -> Http2<TcpStream, PlaintextCtx, true> {
  let tls_stream = TlsConnectorBuilder::std(uri)
    .build(&TlsConfig::plaintext(), ChaCha20::from_std_random().unwrap())
    .await
    .unwrap()
    .connect()
    .await
    .unwrap()
    .tls_stream;
  let (conn_task, http2) = Http2::connect(
    Http2Buffer::new(&mut Xorshift64::from_simple_seed().unwrap()),
    HttpRecvParams::with_optioned_params(),
    tls_stream.into_split().unwrap(),
  )
  .await
  .unwrap();
  let _jh = runtime.spawn(conn_task).unwrap();
  http2
}

// 50 streams open at once on one connection, from 4 tasks; each gets its own body back.
#[cfg_attr(miri, ignore)]
#[test]
fn client_many_concurrent_streams() {
  let runtime = StdRuntime::new();
  let uri = _uri();
  server(&uri, &runtime);
  runtime.block_on(async {
    let http2 = connect_client(&uri, &runtime).await;
    let mut handles = alloc::vec::Vec::new();
    for task in 0..4u32 {
      let client = http2.clone();
      let uri = uri.clone();
      let len = if task < 2 { 13 } else { 12 };
      handles.push(
        runtime
          .spawn(async move {
            let mut streams = alloc::vec::Vec::new();
            for idx in 0..len {
              let body = alloc::format!("task{task}-req{idx}");
              let mut stream = client.stream().await.unwrap();
              let headers = Headers::new();
              let rb = ReqBuilder::get((body.as_bytes(), &headers, uri.to_ref()));
              let _ = stream.send_req(&mut VectorUsize::new(), rb.into_request()).await.unwrap();
              streams.push((body, stream));
            }
            for (body, mut stream) in streams {
              let (status, msg) = stream.recv_res().await.unwrap();
              assert!(matches!(status, Http2RecvStatus::Eos(StatusCode::Ok)), "{status:?}");
              assert_eq!(msg.body.as_slice(), body.as_bytes());
            }
            len
          })
          .unwrap(),
      );
    }
    let mut total = 0;
    for handle in handles {
      total += handle.await;
    }
    assert_eq!(total, 50);
  });
}

// 10 requests through a pool of one go over a single TCP connection.
#[cfg_attr(miri, ignore)]
#[test]
fn client_pool_reuses_connection() {
  use crate::http::{HttpClient as _, http2_client_pool::Http2ClientPoolBuilder};
  use std::sync::atomic::{AtomicUsize, Ordering};
  let runtime = StdRuntime::new();
  let uri = _uri();
  server(&uri, &runtime);
  let target =
    String::from(uri.hostname_with_implied_port().0) + ":" + &uri.port().unwrap_or(80).to_string();
  let accepts = std::sync::Arc::new(AtomicUsize::new(0));
  let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
  let proxy_uri = UriString::new(alloc::format!("http://{}", listener.local_addr().unwrap()));
  {
    let accepts = accepts.clone();
    let _jh = std::thread::spawn(move || {
      for conn in listener.incoming() {
        let Ok(down) = conn else { break };
        let _ = accepts.fetch_add(1, Ordering::SeqCst);
        let up = TcpStream::connect(&target).unwrap();
        let (mut down_r, mut up_w) = (down.try_clone().unwrap(), up.try_clone().unwrap());
        let _jh = std::thread::spawn(move || std::io::copy(&mut down_r, &mut up_w));
        let (mut up_r, mut down_w) = (up, down);
        let _jh = std::thread::spawn(move || std::io::copy(&mut up_r, &mut down_w));
      }
    });
  }
  runtime.block_on(async {
    let pool = Http2ClientPoolBuilder::new(
      crate::executor::StdExecutor::default(),
      1,
      ChaCha20::from_std_random().unwrap(),
      TlsConfig::plaintext(),
    )
    .unwrap()
    .build();
    for idx in 0..10u8 {
      let body = [idx];
      let headers = Headers::new();
      let rb = ReqBuilder::get((&body[..], &headers, proxy_uri.to_ref()));
      let res = pool.send_req_recv_res(&mut VectorUsize::new(), rb.into_request()).await.unwrap();
      assert_eq!(res.msg_data.body.as_slice(), &body);
    }
  });
  assert_eq!(accepts.load(Ordering::SeqCst), 1);
}

// The server resets the stream while `recv_res` waits: the waiter wakes with `ClosedStream`.
#[cfg_attr(miri, ignore)]
#[test]
fn client_server_reset_wakes_waiter() {
  use crate::http2::conn::test_frames::{frame, settings};
  use std::io::{Read as _, Write as _};
  let runtime = StdRuntime::new();
  let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
  let uri = UriString::new(alloc::format!("http://{}", listener.local_addr().unwrap()));
  let _jh = std::thread::spawn(move || {
    let (mut sock, _) = listener.accept().unwrap();
    let mut out = settings(&[]);
    out.extend(frame(4, 1, 0, &[]));
    sock.write_all(&out).unwrap();
    // Read until the HEADERS of stream 1 has arrived.
    let mut buf = alloc::vec::Vec::new();
    let mut chunk = [0; 4096];
    loop {
      let n = sock.read(&mut chunk).unwrap();
      assert!(n > 0, "the client closed early");
      buf.extend_from_slice(&chunk[..n]);
      let mut rest = buf.get(24..).unwrap_or_default();
      let mut seen = false;
      while let [a, b, c, ty, _, s0, s1, s2, s3, tail @ ..] = rest {
        let len = usize::from(*a) << 16 | usize::from(*b) << 8 | usize::from(*c);
        let id = u32::from_be_bytes([*s0, *s1, *s2, *s3]) & 0x7FFF_FFFF;
        if tail.len() < len {
          break;
        }
        seen |= *ty == 1 && id == 1;
        rest = &tail[len..];
      }
      if seen {
        break;
      }
    }
    std::thread::sleep(Duration::from_millis(100));
    sock.write_all(&frame(3, 0, 1, &8u32.to_be_bytes())).unwrap();
    std::thread::sleep(Duration::from_secs(2));
  });
  runtime.block_on(async {
    let http2 = connect_client(&uri, &runtime).await;
    let mut stream = http2.stream().await.unwrap();
    let headers = Headers::new();
    let rb = ReqBuilder::get((&b""[..], &headers, uri.to_ref()));
    let _ = stream.send_req(&mut VectorUsize::new(), rb.into_request()).await.unwrap();
    let (status, _) = stream.recv_res().await.unwrap();
    assert!(matches!(status, Http2RecvStatus::ClosedStream(_)), "{status:?}");
  });
}

// The client on tokio, against the server on io_uring. Run alone: `--features "$FEAT,tokio"`.
#[cfg(feature = "tokio")]
#[cfg_attr(miri, ignore)]
#[test]
fn client_on_tokio_smoke() {
  use crate::http::HttpClient as _;
  let uri = _uri();
  server(&uri, &StdRuntime::new());
  let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
  rt.block_on(async {
    let tls_stream = TlsConnectorBuilder::tokio(&uri)
      .build(&TlsConfig::plaintext(), ChaCha20::from_std_random().unwrap())
      .await
      .unwrap()
      .connect()
      .await
      .unwrap()
      .tls_stream;
    let (conn_task, http2) = Http2::connect(
      Http2Buffer::default(),
      HttpRecvParams::with_optioned_params(),
      tls_stream.into_split().unwrap(),
    )
    .await
    .unwrap();
    let _jh = tokio::spawn(conn_task);
    let headers = Headers::new();
    let rb = ReqBuilder::get((&b"tokio"[..], &headers, uri.to_ref()));
    let res = http2.send_req_recv_res(&mut VectorUsize::new(), rb.into_request()).await.unwrap();
    assert_eq!(res.msg_data.body.as_slice(), b"tokio");
  });
}
