//! Frame-level WebSocket protocol tests in the shape Autobahn's fuzzing client runs them: a
//! raw client sends crafted frames to a real echo server, and the tests assert what comes
//! back — an echo for what is valid, a close carrying the right code for what is not.

use crate::{
  collections::VectorUsize,
  executor::StdRuntime,
  rng::{ChaCha20, CryptoSeedableRng},
  tests::_uri,
  tls::{TlsAcceptor, TlsConfig},
  web_socket::{Frame, WebSocketAcceptor, WebSocketPayloadOrigin},
};
use core::time::Duration;
use std::{
  io::{Read, Write},
  net::{TcpListener, TcpStream},
  vec::Vec,
};

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// Runs the handshake and then sends `bytes` to a real echo server, returning everything it
/// sends back until the connection ends.
fn session(bytes: &[u8]) -> Vec<u8> {
  session_with(bytes, false)
}

/// [`session`], with the frame bytes sent one at a time when `chop` is set.
fn session_with(bytes: &[u8], chop: bool) -> Vec<u8> {
  let uri = _uri();
  let listener = TcpListener::bind(uri.hostname_with_implied_port()).unwrap();
  let server = std::thread::spawn(move || {
    let (stream, _) = listener.accept().unwrap();
    StdRuntime::new().block_on(async {
      let mut ws = WebSocketAcceptor::default()
        .set_no_masking(false)
        .accept(TlsAcceptor::new(
          &TlsConfig::plaintext(),
          &mut ChaCha20::from_std_random().unwrap(),
          stream,
        ))
        .await
        .unwrap();
      let mut buffer = VectorUsize::new();
      loop {
        // The frame borrows the WebSocket, so its opcode and payload are copied out before
        // anything is written back.
        let (op_code, payload) =
          match ws.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await {
            Ok(frame) => (frame.op_code(), frame.payload().to_vec()),
            Err(_) => break,
          };
        if op_code.is_close() {
          break;
        }
        if !op_code.is_control() {
          let mut payload = VectorUsize::from_vec(payload).unwrap();
          ws.write_frame(&mut Frame::new_fin(op_code, &mut payload).unwrap()).await.unwrap();
        }
      }
    });
  });
  let mut client = TcpStream::connect(uri.hostname_with_implied_port()).unwrap();
  client.set_nodelay(true).unwrap();
  client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
  let head = std::format!(
    "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n"
  )
  .into_bytes();
  client.write_all(&head).unwrap();
  if chop {
    for byte in bytes {
      client.write_all(&[*byte]).unwrap();
      std::thread::sleep(Duration::from_millis(5));
    }
  } else {
    client.write_all(bytes).unwrap();
  }
  // The 101 comes back first; the frame bytes follow it.
  let mut head_end = Vec::new();
  let mut byte = [0; 1];
  while !head_end.ends_with(b"\r\n\r\n") && client.read(&mut byte).unwrap_or(0) == 1 {
    head_end.push(byte[0]);
  }
  let mut got = Vec::new();
  let mut buf = [0; 8192];
  while let Ok(len @ 1..) = client.read(&mut buf) {
    got.extend_from_slice(&buf[..len]);
  }
  server.join().unwrap();
  got
}

/// XORs `payload` with `mask` in place, the way RFC 6455 5.3 spreads a client mask.
fn mask(payload: &mut [u8], mask: [u8; 4]) {
  for (idx, byte) in payload.iter_mut().enumerate() {
    *byte ^= mask[idx % 4];
  }
}

/// A masked client frame with a 7-bit length, so payloads of up to 125 bytes.
fn frame(op_code: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
  let mask_bytes = [1, 2, 3, 4];
  let mut out =
    std::vec![u8::from(fin) << 7 | op_code, 0x80 | u8::try_from(payload.len()).unwrap()];
  out.extend_from_slice(&mask_bytes);
  let mut data = payload.to_vec();
  mask(&mut data, mask_bytes);
  out.extend_from_slice(&data);
  out
}

/// A masked client frame with a 16-bit length.
fn frame_16(op_code: u8, payload: &[u8]) -> Vec<u8> {
  let mask_bytes = [1, 2, 3, 4];
  let mut out = std::vec![0x80 | op_code, 0x80 | 126];
  out.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());
  out.extend_from_slice(&mask_bytes);
  let mut data = payload.to_vec();
  mask(&mut data, mask_bytes);
  out.extend_from_slice(&data);
  out
}

/// A masked client frame with a 64-bit length.
fn frame_64(op_code: u8, payload: &[u8]) -> Vec<u8> {
  let mask_bytes = [1, 2, 3, 4];
  let mut out = std::vec![0x80 | op_code, 0x80 | 127];
  out.extend(u64::try_from(payload.len()).unwrap().to_be_bytes());
  out.extend_from_slice(&mask_bytes);
  let mut data = payload.to_vec();
  mask(&mut data, mask_bytes);
  out.extend_from_slice(&data);
  out
}

/// A masked close frame carrying `code`.
fn close(code: u16) -> Vec<u8> {
  frame(0x8, true, &code.to_be_bytes())
}

/// A masked close frame with an arbitrary payload, for Autobahn 7.x shapes over 125 bytes.
fn close_frame(payload: &[u8]) -> Vec<u8> {
  let mut out = std::vec![0x88];
  if payload.len() <= 125 {
    out.push(0x80 | payload.len() as u8);
  } else {
    out.push(0x80 | 126);
    out.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());
  }
  out.extend_from_slice(&[1, 2, 3, 4]);
  out.extend(payload.iter().enumerate().map(|(idx, el)| el ^ [1, 2, 3, 4][idx % 4]));
  out
}

/// The close code of the first server frame in `bytes`, which arrive unmasked.
fn first_close_code(bytes: &[u8]) -> Option<u16> {
  if bytes.first() != Some(&0x88) || !bytes.get(1).is_some_and(|el| *el >= 2) {
    return None;
  }
  Some(u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]))
}

// Autobahn 5.x and gorilla: every one of these protocol errors is answered with a close 1002.
#[test]
fn protocol_errors_get_close_1002() {
  let mut ping_of_126 = [0x89, 0xFE, 0x00, 0x7E, 1, 2, 3, 4].to_vec();
  ping_of_126.extend(std::iter::repeat_n(b'p', 126));
  for (name, bytes) in [
    ("unmasked text", [0x81, 0x02, b'h', b'i'].to_vec()),
    ("rsv1 without negotiation", [0xC1, 0x82, 1, 2, 3, 4, 2, 2].to_vec()),
    ("reserved opcode 3", [0x83, 0x82, 1, 2, 3, 4, 2, 2].to_vec()),
    ("fragmented ping", frame(0x9, false, b"x")),
    ("ping of 126", ping_of_126),
    ("continuation without a start", frame(0x0, true, b"x")),
    ("text during fragmentation", [frame(0x1, false, b"a"), frame(0x1, false, b"b")].concat()),
  ] {
    let got = session(&bytes);
    assert_eq!(first_close_code(&got), Some(1002), "{name}");
  }
}

// Autobahn 6.x: invalid UTF-8 in a text frame, whole or across fragments, is a close 1007.
#[test]
fn invalid_utf8_gets_close_1007() {
  for payload in
    [b"\x80".as_slice(), b"\xc0\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xfe", b"\xff"]
  {
    let got = session(&frame(0x1, true, payload));
    assert_eq!(first_close_code(&got), Some(1007), "{payload:?}");
  }
  // An invalid octet in the continuation fails the message as a whole.
  let got = session(&[frame(0x1, false, b"\xce"), frame(0x0, true, b"\xba\x80")].concat());
  assert_eq!(first_close_code(&got), Some(1007));
  // A code point cut short at the final fragment is incomplete, not valid.
  let got = session(&[frame(0x1, false, b"\xce"), frame(0x0, true, b"")].concat());
  assert_eq!(first_close_code(&got), Some(1007));
}

// Autobahn 6.x also insists the valid-but-unusual are echoed, not refused.
#[test]
fn valid_but_unusual_utf8_is_echoed() {
  for payload in [b"\xef\xbf\xbe".as_slice(), b"\xf4\x8f\xbf\xbf", b"\xf0\xa4\xad\xa2", b"\xce\xba"]
  {
    let got = session(&[frame(0x1, true, payload), close(1000)].concat());
    assert!(got.starts_with(&[0x81, payload.len() as u8]), "{payload:?}: {got:02x?}");
    assert!(got[..2 + payload.len()].ends_with(payload));
  }
  // A code point split across fragments reassembles.
  let got = session(&[frame(0x1, false, b"\xce"), frame(0x0, true, b"\xba"), close(1000)].concat());
  assert!(got.starts_with(&[0x81, 2, 0xce, 0xba]), "{got:02x?}");
}

// Autobahn 7.x: the close matrix. Length 0 or a 125-byte payload with an allowed code closes
// cleanly; length 1, an oversized payload, or a code that must not appear on the wire is a
// 1002; allowed codes are echoed.
#[test]
fn close_frame_matrix() {
  // An empty close is answered with an empty close or a close 1000.
  let got = session(&[0x88, 0x80, 1, 2, 3, 4]);
  assert!(
    got.first() == Some(&0x88) && (got.get(1) == Some(&0) || first_close_code(&got) == Some(1000)),
    "{got:02x?}"
  );
  let got = session(&[0x88, 0x81, 1, 2, 3, 4, 0x03 ^ 1]);
  assert_eq!(first_close_code(&got), Some(1002));
  let mut with_reason = 1000u16.to_be_bytes().to_vec();
  with_reason.extend(std::iter::repeat_n(b'r', 123));
  let got = session(&close_frame(&with_reason));
  assert_eq!(first_close_code(&got), Some(1000));
  let mut oversized = 1000u16.to_be_bytes().to_vec();
  oversized.extend(std::iter::repeat_n(b'r', 124));
  let got = session(&close_frame(&oversized));
  assert_eq!(first_close_code(&got), Some(1002));
  for code in [0, 999, 1004, 1014, 5000] {
    let got = session(&close(code));
    assert_eq!(first_close_code(&got), Some(1002), "{code}");
  }
  for code in [1005, 1006, 1015, 1016, 2999] {
    let got = session(&close(code));
    assert_eq!(first_close_code(&got), Some(1002), "{code}");
  }
  for code in [1001, 1003, 1010, 3999, 4000, 4999] {
    let got = session(&close(code));
    assert_eq!(first_close_code(&got), Some(code), "{code}");
  }
}

// Autobahn 7.1.5: a close reason that is not UTF-8 is refused like a text payload.
#[test]
fn close_reason_invalid_utf8_gets_close_1007() {
  let mut payload = 1000u16.to_be_bytes().to_vec();
  payload.extend_from_slice(b"\xed\xa0\x80");
  let got = session(&close_frame(&payload));
  assert_eq!(first_close_code(&got), Some(1007));
}

// Autobahn 2.x: pings of both boundary sizes are answered with an exact pong, in order, and an
// unsolicited pong draws no reply.
#[test]
fn ping_battery() {
  let got = session(&[frame(0x9, true, b""), close(1000)].concat());
  assert!(got.starts_with(&[0x8A, 0]), "{got:02x?}");
  let ping = std::iter::repeat_n(b'p', 125).collect::<Vec<_>>();
  let got = session(&[frame(0x9, true, &ping), close(1000)].concat());
  assert!(got.starts_with(&[0x8A, 125]), "{got:02x?}");
  assert!(got[..2 + 125].ends_with(&ping));
  let ten_pings =
    (0..10).map(|idx| frame(0x9, true, &[b'0' + idx])).chain(core::iter::once(close(1000)));
  let got = session(&ten_pings.collect::<Vec<_>>().concat());
  for idx in 0..10u8 {
    let at = (2 + 1) * idx as usize;
    assert_eq!(&got[at..at + 3], &[0x8A, 1, b'0' + idx], "{got:02x?}");
  }
  // A pong nobody asked for is ignored; the close behind it is still answered.
  let got = session(&[frame(0xA, true, b"p"), close(1000)].concat());
  assert_eq!(got, [0x88, 0x02, 0x03, 0xe8], "{got:02x?}");
}

// Autobahn 7.1.2-7.1.4: whatever arrives after a close is ignored, and the close is echoed.
#[test]
fn post_close_traffic_is_ignored() {
  let got = session(&[close(1000), frame(0x9, true, b"p"), frame(0x1, true, b"x")].concat());
  assert_eq!(got, [0x88, 0x02, 0x03, 0xe8], "{got:02x?}");
}

// Autobahn 1.1.1: a zero-length text frame is a text frame.
#[test]
fn zero_length_text_is_echoed() {
  let got = session(&[frame(0x1, true, b""), close(1000)].concat());
  assert!(got.starts_with(&[0x81, 0]), "{got:02x?}");
}

// Autobahn 1.1.5/9.1: 65536 bytes behind a 64-bit length echo.
#[test]
fn text_of_65536_is_echoed() {
  let payload = std::iter::repeat_n(b'z', 65536).collect::<Vec<_>>();
  let got = session(&[frame_64(0x1, &payload), close(1000)].concat());
  assert!(got.starts_with(&[0x81, 127, 0, 0, 0, 0, 0, 1, 0, 0]), "{:02x?}", got.get(..16));
  // The whole payload came back, then the close.
  assert!(got.get(10..10 + 65536).is_some_and(|el| el == payload), "{} bytes back", got.len());
}

// RFC 6455 5.2 has the sender use the minimal length field; a receiver is not made to refuse a
// longer one, and this one doesn't, by choice: five bytes behind a 16-bit length are echoed.
#[test]
fn non_minimal_length_is_accepted() {
  let got = session(&[frame_16(0x1, b"hello"), close(1000)].concat());
  assert!(got.starts_with(&[0x81, 5, b'h', b'e', b'l', b'l', b'o']), "{got:02x?}");
}

// Autobahn's chopped-delivery cases: a frame that arrives one byte at a time is still read.
#[test]
fn frame_chopped_into_pieces() {
  let got = session_with(&[frame(0x1, true, b"hello"), close(1000)].concat(), true);
  assert!(got.starts_with(&[0x81, 5, b'h', b'e', b'l', b'l', b'o']), "{got:02x?}");
}
