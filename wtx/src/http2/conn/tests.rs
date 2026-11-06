use crate::{
  collections::ArrayVectorCopy,
  http::HttpRecvParams,
  http2::{
    Http2ErrorCode,
    conn::{
      ConnEvent, Http2Conn,
      scan::PREFACE,
      test_frames::{data, frame, headers_req, parse_all, settings},
    },
  },
  rng::Xorshift64,
};
use alloc::vec::Vec;

type Frames = Vec<(u8, u8, u32, Vec<u8>)>;

const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;

pub(crate) fn server(hp: HttpRecvParams) -> Http2Conn<false> {
  Http2Conn::new(hp, &mut Xorshift64::from(7u64))
}

/// Everything the connection has queued, as raw bytes, and marks it written.
pub(crate) fn take_output<const IS_CLIENT: bool>(conn: &mut Http2Conn<IS_CLIENT>) -> Vec<u8> {
  let mut out = Vec::new();
  while conn.has_output() {
    let mut slices = ArrayVectorCopy::<&[u8], 16>::new();
    conn.output(&mut slices);
    let mut len = 0;
    for slice in slices.iter() {
      out.extend_from_slice(slice);
      len += slice.len();
    }
    conn.advance_output(len);
  }
  out
}

pub(crate) fn take_frames<const IS_CLIENT: bool>(conn: &mut Http2Conn<IS_CLIENT>) -> Frames {
  parse_all(&take_output(conn))
}

pub(crate) fn events<const IS_CLIENT: bool>(conn: &mut Http2Conn<IS_CLIENT>) -> Vec<ConnEvent> {
  let mut out = Vec::new();
  while let Some(elem) = conn.poll_event() {
    out.push(elem);
  }
  out
}

/// A server past the preface and both SETTINGS exchanges, with its output drained.
pub(crate) fn ready_server(hp: HttpRecvParams) -> Http2Conn<false> {
  let mut conn = server(hp);
  let mut input = PREFACE.to_vec();
  input.extend(settings(&[]));
  input.extend(frame(SETTINGS, 1, 0, &[]));
  assert_eq!(conn.feed(&input).unwrap(), input.len());
  let _ = take_output(&mut conn);
  let _ = events(&mut conn);
  conn
}

fn go_away_code(frames: &Frames) -> Option<(u32, u32)> {
  frames.iter().find(|el| el.0 == GOAWAY).map(|el| {
    let last = u32::from_be_bytes(el.3[0..4].try_into().unwrap()) & 0x7FFF_FFFF;
    let code = u32::from_be_bytes(el.3[4..8].try_into().unwrap());
    (last, code)
  })
}

fn rst_code(frames: &Frames, stream: u32) -> Option<u32> {
  frames
    .iter()
    .find(|el| el.0 == RST_STREAM && el.2 == stream)
    .map(|el| u32::from_be_bytes(el.3[0..4].try_into().unwrap()))
}

#[test]
fn conn_server_initial_output() {
  let hp = HttpRecvParams::with_default_params().set_initial_window_len(1 << 20);
  let mut conn = server(hp);
  let frames = take_frames(&mut conn);
  assert_eq!(frames.len(), 2, "{frames:?}");
  assert_eq!((frames[0].0, frames[0].1, frames[0].2), (SETTINGS, 0, 0));
  let mut values = Vec::new();
  for pair in frames[0].3.chunks(6) {
    values.push((
      u16::from_be_bytes([pair[0], pair[1]]),
      u32::from_be_bytes([pair[2], pair[3], pair[4], pair[5]]),
    ));
  }
  assert!(values.contains(&(4, 1 << 20)), "{values:?}");
  assert!(values.contains(&(3, hp.max_concurrent_streams_num())), "{values:?}");
  assert_eq!((frames[1].0, frames[1].2), (WINDOW_UPDATE, 0));
  let increment = u32::from_be_bytes(frames[1].3[0..4].try_into().unwrap());
  assert_eq!(increment, (1 << 20) - 65_535);
}

#[test]
fn conn_preface_split() {
  let mut conn = server(HttpRecvParams::with_default_params());
  let _ = take_output(&mut conn);
  let mut input = PREFACE.to_vec();
  input.extend(settings(&[(4, 1000)]));
  let mut buffer = Vec::new();
  for byte in input {
    buffer.push(byte);
    let consumed = conn.feed(&buffer).unwrap();
    let _ = buffer.drain(..consumed);
  }
  assert!(buffer.is_empty());
  let frames = take_frames(&mut conn);
  assert_eq!(frames, [(SETTINGS, 1, 0, Vec::new())]);
}

#[test]
fn conn_settings_ack_and_ping_ack() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let payload = [1, 2, 3, 4, 5, 6, 7, 8];
  let input = frame(PING, 0, 0, &payload);
  assert_eq!(conn.feed(&input).unwrap(), input.len());
  assert_eq!(take_frames(&mut conn), [(PING, 1, 0, payload.to_vec())]);
}

#[test]
fn conn_window_update_on_closed_stream_ignored() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let input = headers_req(1, "GET", "/", &[], true);
  assert_eq!(conn.feed(&input).unwrap(), input.len());
  assert!(matches!(events(&mut conn)[..], [ConnEvent::Headers { end_stream: true, .. }]));
  conn.close_stream_for_test(1);
  let _ = take_output(&mut conn);
  let mut input = frame(WINDOW_UPDATE, 0, 1, &100u32.to_be_bytes());
  input.extend(frame(RST_STREAM, 0, 1, &8u32.to_be_bytes()));
  assert_eq!(conn.feed(&input).unwrap(), input.len());
  assert_eq!(take_frames(&mut conn), Frames::new());
  assert!(events(&mut conn).is_empty());
}

#[test]
fn conn_data_on_closed_stream_rst() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let input = headers_req(1, "GET", "/", &[], true);
  let _ = conn.feed(&input).unwrap();
  conn.close_stream_for_test(1);
  let _ = take_output(&mut conn);
  let _ = events(&mut conn);
  let input = data(1, b"late", false);
  assert_eq!(conn.feed(&input).unwrap(), input.len());
  let frames = take_frames(&mut conn);
  assert_eq!(rst_code(&frames, 1), Some(5), "{frames:?}");
  assert_eq!(go_away_code(&frames), None);
  let input = headers_req(3, "GET", "/", &[], true);
  assert_eq!(conn.feed(&input).unwrap(), input.len());
  assert!(matches!(events(&mut conn)[..], [ConnEvent::Headers { .. }]));
}

#[test]
fn conn_headers_on_closed_stream_goaway() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let _ = conn.feed(&headers_req(1, "GET", "/", &[], true)).unwrap();
  conn.close_stream_for_test(1);
  let _ = take_output(&mut conn);
  assert!(conn.feed(&headers_req(1, "GET", "/", &[], true)).is_err());
  let frames = take_frames(&mut conn);
  assert_eq!(go_away_code(&frames), Some((1, 5)), "{frames:?}");
}

#[test]
fn conn_even_stream_id_from_client_goaway() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  assert!(conn.feed(&headers_req(2, "GET", "/", &[], true)).is_err());
  let frames = take_frames(&mut conn);
  assert_eq!(go_away_code(&frames).map(|el| el.1), Some(1), "{frames:?}");
}

#[test]
fn conn_graceful_go_away() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let _ = conn.feed(&headers_req(1, "GET", "/", &[], true)).unwrap();
  let _ = events(&mut conn);
  conn.go_away(Http2ErrorCode::NoError);
  let frames = take_frames(&mut conn);
  assert_eq!(go_away_code(&frames), Some((1, 0)), "{frames:?}");
  let input = headers_req(3, "GET", "/", &[], true);
  assert_eq!(conn.feed(&input).unwrap(), input.len());
  let frames = take_frames(&mut conn);
  assert_eq!(rst_code(&frames, 3), Some(7), "{frames:?}");
  assert!(events(&mut conn).is_empty());
  assert_eq!(conn.open_streams(), 1);
}
