//! The framework end to end on io_uring: manual streams, WebSocket over HTTP/2, kernel TLS.

use crate::{
  collections::VectorUsize,
  executor::UringExecutor,
  http::{
    Headers, HttpRecvParams, ManualStream, StatusCode,
    http2_server_framework::{
      Http2ServerFramework, HttpRouter, conn_driver::tests::{Client, body_of, ended}, post,
      web_socket,
    },
  },
  http2::{
    Http2RecvStatus, ServerStream, WebSocketOverStream,
    conn::test_frames::{data, headers_req},
  },
  net::TcpParams,
  rng::{ChaCha20, CryptoSeedableRng, Xorshift64},
  tests::_uri,
  tls::TlsConfig,
  web_socket::{Frame, OpCode},
};
use alloc::{
  string::{String, ToString as _},
  vec,
};
use core::{num::NonZeroUsize, time::Duration};

/// Starts `router` on one io_uring runtime in its own thread; returns `host:port`.
fn start<EN>(hrc: HttpRecvParams, router: HttpRouter<(), EN, crate::Error, (), ServerStream>) -> String
where
  EN: crate::http::http2_server_framework::EndpointNode<(), crate::Error, ServerStream>
    + Send
    + Sync
    + 'static,
{
  let uri = _uri();
  let addr = String::from(uri.hostname_with_implied_port().0) + ":" + &uri.port().unwrap().to_string();
  let server_addr = addr.clone();
  let _jh = std::thread::spawn(move || {
    Http2ServerFramework::<(), fn(crate::Error), UringExecutor, _, _, _>::new(
      UringExecutor::default(),
      ChaCha20::from_std_random().unwrap(),
      TlsConfig::plaintext(),
    )
    .unwrap()
    .set_error_cb((|err: crate::Error| std::eprintln!("uring_tests server: {err:?}")) as fn(crate::Error))
    .set_http_recv_params(hrc)
    .set_local_runtimes(NonZeroUsize::new(1))
    .set_tcp_params(TcpParams::default().set_reuse_port(Some(false)))
    .run_in_threads(&server_addr, router)
    .unwrap();
  });
  for _ in 0..200 {
    if std::net::TcpStream::connect(&addr).is_ok() {
      return addr;
    }
    std::thread::sleep(Duration::from_millis(10));
  }
  panic!("the server did not start");
}

#[test]
fn framework_manual_stream_echo() {
  async fn echo(mut ms: ManualStream<(), ServerStream>) -> crate::Result<()> {
    let mut body = VectorUsize::new();
    loop {
      match ms.stream.recv_data(&mut body).await? {
        Http2RecvStatus::Ongoing(()) => {}
        Http2RecvStatus::Eos(()) => break,
        _ => return Ok(()),
      }
    }
    let _ = ms.stream.send_headers(&Headers::new(), false, StatusCode::Ok).await?;
    let third = body.len() / 3;
    let _ = ms.stream.send_data(&body[..third], false).await?;
    let _ = ms.stream.send_data(&body[third..2 * third], false).await?;
    let _ = ms.stream.send_data(&body[2 * third..], true).await?;
    Ok(())
  }
  let router = HttpRouter::paths(crate::paths!(("/echo", post(echo)))).unwrap();
  let addr = start(HttpRecvParams::with_optioned_params(), router);
  let mut client = Client::connect(&addr, &[]);
  let mut input = headers_req(1, "POST", "/echo", &[], false);
  input.extend(data(1, b"hello ", false));
  input.extend(data(1, b"manual ", false));
  input.extend(data(1, b"stream", true));
  client.send(&input);
  let frames = client.read_until(Duration::from_secs(5), |frames| ended(frames).contains(&1));
  assert_eq!(body_of(&frames, 1), b"hello manual stream");
}

#[test]
fn framework_web_socket_over_h2() {
  async fn ws(ms: ManualStream<(), ServerStream>) -> crate::Result<()> {
    let mut ws = WebSocketOverStream::new(&Headers::new(), false, Xorshift64::from(1u64), ms.stream)
      .await?;
    let mut buffer = VectorUsize::new();
    let frame = ws.read_frame(&mut buffer).await?;
    let mut payload: VectorUsize<u8> = VectorUsize::from_copyable_slice(&frame.payload()[..])?;
    ws.write_frame(&mut Frame::new_fin(OpCode::Text, payload.as_slice_mut())?).await?;
    Ok(())
  }
  let router = HttpRouter::paths(crate::paths!(("/ws", web_socket(ws)))).unwrap();
  let addr = start(HttpRecvParams::with_optioned_params().set_enable_connect_protocol(true), router);
  let mut client = Client::connect(&addr, &[]);
  let headers = headers_req(
    1,
    "CONNECT",
    "/ws",
    &[(":protocol", "websocket"), ("sec-websocket-version", "13")],
    false,
  );
  client.send(&headers);
  // A masked text frame with "ping".
  let mask = [1, 2, 3, 4];
  let mut ws_frame = vec![0x81, 0x80 | 4];
  ws_frame.extend_from_slice(&mask);
  ws_frame.extend(b"ping".iter().enumerate().map(|(idx, byte)| byte ^ mask[idx % 4]));
  client.send(&data(1, &ws_frame, false));
  let frames = client.read_until(Duration::from_secs(5), |frames| {
    body_of(frames, 1).windows(4).any(|el| el == b"ping")
  });
  let body = body_of(&frames, 1);
  assert_eq!(&body[..2], &[0x81, 4], "{body:?}");
  assert_eq!(&body[2..6], b"ping");
}
