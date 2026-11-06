use crate::{
  collections::{ArrayVectorCopy, VectorUsize},
  http::{Header, Headers, HttpRecvParams, Method, MsgBufferStr, MsgBufferString, StatusCode, U31},
  http2::{
    Http2ErrorCode,
    conn::{
      ConnEvent, Http2Conn,
      body::{Body, SharedBytes},
      scan::PREFACE,
      test_frames::{data, frame, headers_req, parse_all, settings},
    },
    hpack_decoder::HpackDecoder,
    hpack_encoder::HpackEncoder,
    hpack_header::HpackHeaderBasic,
  },
  net::Uri,
  rng::Xorshift64,
  sync::Arc,
};
use alloc::{
  string::{String, ToString as _},
  vec,
  vec::Vec,
};
use core::time::Duration;

type Frames = Vec<(u8, u8, u32, Vec<u8>)>;

const DATA: u8 = 0;
const HEADERS: u8 = 1;
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

fn decode_block(dec: &mut HpackDecoder, block: &[u8]) -> Vec<(String, String)> {
  let mut out = Vec::new();
  dec
    .decode(block, |(_, name, value)| {
      out.push((name.str().to_string(), value.to_string()));
      Ok(())
    })
    .unwrap();
  out
}

fn response_decoder() -> HpackDecoder {
  let mut dec = HpackDecoder::new();
  dec.set_max_bytes(4096);
  dec
}

#[test]
fn conn_get_request_event_and_msg() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let _ = conn.feed(&headers_req(1, "GET", "/a?x=1", &[], true)).unwrap();
  assert_eq!(
    events(&mut conn),
    [ConnEvent::Headers { end_stream: true, stream_id: U31::from_u32(1) }]
  );
  assert_eq!(conn.msg_mut(U31::from_u32(1)).unwrap().uri.path(), "/a");
  assert_eq!(conn.method(U31::from_u32(1)), Some(Method::Get));
}

#[test]
fn conn_post_body_across_feeds() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let mut input = headers_req(1, "POST", "/p", &[], false);
  input.extend(data(1, b"hel", false));
  input.extend(data(1, b"lo", true));
  let mut buffer = Vec::new();
  for byte in input {
    buffer.push(byte);
    let consumed = conn.feed(&buffer).unwrap();
    let _ = buffer.drain(..consumed);
  }
  let id = U31::from_u32(1);
  assert_eq!(
    events(&mut conn),
    [
      ConnEvent::Headers { end_stream: false, stream_id: id },
      ConnEvent::Data { end_stream: false, stream_id: id },
      ConnEvent::Data { end_stream: true, stream_id: id },
    ]
  );
  assert_eq!(conn.msg_mut(id).unwrap().body.as_slice(), b"hello");
}

#[test]
fn conn_response_one_pass() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let _ = conn.feed(&headers_req(1, "GET", "/", &[], true)).unwrap();
  let id = U31::from_u32(1);
  let mut msg = MsgBufferString::default();
  msg.body.extend_from_copyable_slice(b"2").unwrap();
  conn.send_response(id, StatusCode::Ok, &mut msg).unwrap();
  let frames = take_frames(&mut conn);
  assert_eq!(frames.len(), 2, "{frames:?}");
  assert_eq!((frames[0].0, frames[0].1 & 0b101, frames[0].2), (HEADERS, 0b100, 1));
  assert_eq!((frames[1].0, frames[1].1, frames[1].2, &frames[1].3[..]), (DATA, 1, 1, &b"2"[..]));
  let fields = decode_block(&mut response_decoder(), &frames[0].3);
  assert!(fields.contains(&(":status".into(), "200".into())), "{fields:?}");
  assert!(fields.contains(&("content-length".into(), "1".into())), "{fields:?}");
  assert_eq!(conn.open_streams(), 0);
}

#[test]
fn conn_response_waits_for_window() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let _ = conn.feed(&settings(&[(4, 10)])).unwrap();
  let _ = conn.feed(&headers_req(1, "GET", "/", &[], true)).unwrap();
  let _ = take_output(&mut conn);
  let id = U31::from_u32(1);
  let mut msg = MsgBufferString::default();
  msg.body.extend_from_copyable_slice(&[b'x'; 25]).unwrap();
  conn.send_response(id, StatusCode::Ok, &mut msg).unwrap();
  let frames = take_frames(&mut conn);
  let sent: usize = frames.iter().filter(|el| el.0 == DATA).map(|el| el.3.len()).sum();
  assert_eq!(sent, 10, "{frames:?}");
  assert_eq!(conn.stream_send_pending(id), 15);
  let mut input = frame(WINDOW_UPDATE, 0, 1, &20u32.to_be_bytes());
  input.extend(frame(WINDOW_UPDATE, 0, 0, &20u32.to_be_bytes()));
  let _ = conn.feed(&input).unwrap();
  assert!(events(&mut conn).contains(&ConnEvent::SendCapacity { stream_id: id }));
  let frames = take_frames(&mut conn);
  let data_frames: Vec<_> = frames.iter().filter(|el| el.0 == DATA).collect();
  assert_eq!(data_frames.iter().map(|el| el.3.len()).sum::<usize>(), 15);
  assert_eq!(data_frames.last().unwrap().1 & 1, 1);
  assert_eq!(conn.stream_send_pending(id), 0);
}

#[test]
fn conn_shared_body_by_reference() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let _ = conn.feed(&settings(&[(4, 1 << 20)])).unwrap();
  let _ = conn.feed(&frame(WINDOW_UPDATE, 0, 0, &(1u32 << 20).to_be_bytes())).unwrap();
  let _ = conn.feed(&headers_req(1, "GET", "/", &[], true)).unwrap();
  let _ = take_output(&mut conn);
  let id = U31::from_u32(1);
  let shared = SharedBytes::new(Arc::from(vec![7u8; 40 * 1024].into_boxed_slice()));
  let range = shared.as_slice().as_ptr_range();
  conn.send_headers(id, Some(StatusCode::Ok), &Headers::new(), false).unwrap();
  conn.send_data(id, Body::Shared(shared), true).unwrap();
  let mut slices = ArrayVectorCopy::<&[u8], 16>::new();
  conn.output(&mut slices);
  assert!(slices.iter().any(|el| range.contains(&el.as_ptr())));
  let frames = take_frames(&mut conn);
  assert_eq!(frames.iter().filter(|el| el.0 == DATA).count(), 3, "{frames:?}");
}

#[test]
fn conn_release_capacity_coalesced() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let mut input = headers_req(1, "POST", "/", &[], false);
  input.extend(data(1, &[0; 300], false));
  let _ = conn.feed(&input).unwrap();
  let _ = take_output(&mut conn);
  let id = U31::from_u32(1);
  for _ in 0..3 {
    conn.release_capacity(id, 100).unwrap();
  }
  let frames = take_frames(&mut conn);
  let updates: Vec<_> = frames.iter().filter(|el| el.0 == WINDOW_UPDATE && el.2 == 1).collect();
  assert_eq!(updates.len(), 1, "{frames:?}");
  assert_eq!(u32::from_be_bytes(updates[0].3[..4].try_into().unwrap()), 300);
}

#[test]
fn conn_settings_shrink_window_goes_negative() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let _ = conn.feed(&settings(&[(4, 10)])).unwrap();
  let _ = conn.feed(&headers_req(1, "GET", "/", &[], true)).unwrap();
  let _ = take_output(&mut conn);
  let id = U31::from_u32(1);
  let body: Vec<u8> = (0..100u8).collect();
  let mut msg = MsgBufferString::default();
  msg.body.extend_from_copyable_slice(&body).unwrap();
  conn.send_response(id, StatusCode::Ok, &mut msg).unwrap();
  let mut received: Vec<u8> = Vec::new();
  let mut collect = |conn: &mut Http2Conn<false>| {
    for el in take_frames(conn) {
      if el.0 == DATA {
        received.extend_from_slice(&el.3);
      }
    }
  };
  collect(&mut conn);
  let _ = conn.feed(&settings(&[(4, 0)])).unwrap();
  let _ = conn.feed(&frame(WINDOW_UPDATE, 0, 1, &5u32.to_be_bytes())).unwrap();
  collect(&mut conn);
  let _ = conn.feed(&frame(WINDOW_UPDATE, 0, 1, &200u32.to_be_bytes())).unwrap();
  collect(&mut conn);
  assert_eq!(received, body);
}

#[test]
fn conn_client_request_response() {
  let mut client =
    Http2Conn::<true>::new(HttpRecvParams::with_default_params(), &mut Xorshift64::from(3u64));
  let mut input = settings(&[]);
  input.extend(frame(SETTINGS, 1, 0, &[]));
  let _ = client.feed(&input).unwrap();
  let _ = take_output(&mut client);
  let id = client.open_stream().unwrap();
  assert_eq!(id, U31::from_u32(1));
  let msg = MsgBufferStr::from_uri(Uri::new("http://localhost/x"));
  client.send_request(id, Method::Get, &msg, true).unwrap();
  let frames = take_frames(&mut client);
  assert_eq!((frames[0].0, frames[0].2), (HEADERS, 1));
  let mut enc = HpackEncoder::new(&mut Xorshift64::from(5u64));
  let mut block = VectorUsize::new();
  enc.encode(&mut block, 3, [(HpackHeaderBasic::StatusCode(StatusCode::Ok), "200")], []).unwrap();
  let mut response = frame(HEADERS, 0b100, 1, &block);
  response.extend(data(1, b"ok", true));
  let _ = client.feed(&response).unwrap();
  assert_eq!(
    events(&mut client),
    [
      ConnEvent::Headers { end_stream: false, stream_id: id },
      ConnEvent::Data { end_stream: true, stream_id: id },
    ]
  );
  assert_eq!(client.msg_mut(id).unwrap().body.as_slice(), b"ok");
}

/// A server whose peer allows a 4096-byte HPACK table, so responses index their fields.
fn indexing_server() -> Http2Conn<false> {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let _ = conn.feed(&settings(&[(1, 4096)])).unwrap();
  let _ = take_output(&mut conn);
  conn
}

fn plain_response(conn: &mut Http2Conn<false>, stream: u32) -> Vec<u8> {
  let _ = conn.feed(&headers_req(stream, "GET", "/", &[], true)).unwrap();
  let _ = events(conn);
  let mut msg = MsgBufferString::default();
  msg.headers.push_from_iter(Header::from_name_and_value("content-type", ["text/plain"])).unwrap();
  msg.headers.push_from_iter(Header::from_name_and_value("server", ["rimu-ws"])).unwrap();
  msg.body.extend_from_copyable_slice(b"2").unwrap();
  conn.send_response(U31::from_u32(stream), StatusCode::Ok, &mut msg).unwrap();
  let frames = take_frames(conn);
  frames.into_iter().find(|el| el.0 == HEADERS).unwrap().3
}

#[test]
fn conn_header_cache_hit_same_bytes() {
  let mut conn = indexing_server();
  let first = plain_response(&mut conn, 1);
  let second = plain_response(&mut conn, 3);
  let generation = conn.hpack_generation();
  let third = plain_response(&mut conn, 5);
  assert_ne!(first, second, "the first response indexes its fields, the second refers to them");
  assert_eq!(second, third);
  assert_eq!(conn.hpack_generation(), generation);
  assert_eq!(conn.header_cache_hits(), 1);
  let mut dec = response_decoder();
  for block in [&first, &second, &third] {
    let fields = decode_block(&mut dec, block);
    assert!(fields.contains(&("content-type".into(), "text/plain".into())), "{fields:?}");
    assert!(fields.contains(&("content-length".into(), "1".into())), "{fields:?}");
  }
}

#[test]
fn conn_header_cache_invalid_after_table_size_change() {
  let mut conn = indexing_server();
  let mut blocks =
    vec![plain_response(&mut conn, 1), plain_response(&mut conn, 3), plain_response(&mut conn, 5)];
  assert_eq!(conn.header_cache_hits(), 1);
  let _ = conn.feed(&settings(&[(1, 0)])).unwrap();
  let _ = take_output(&mut conn);
  let after = plain_response(&mut conn, 7);
  assert_eq!(after[0], 0x20, "a dynamic table size update to 0 comes first: {after:?}");
  blocks.push(after);
  blocks.push(plain_response(&mut conn, 9));
  let mut dec = response_decoder();
  for block in &blocks {
    let fields = decode_block(&mut dec, block);
    assert!(fields.contains(&(":status".into(), "200".into())), "{fields:?}");
    assert!(fields.contains(&("server".into(), "rimu-ws".into())), "{fields:?}");
  }
}

fn secs(value: f64) -> Duration {
  Duration::from_secs_f64(value)
}

#[test]
fn limit_rapid_reset_goaway() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let mut failed = false;
  for idx in 0..201u32 {
    let id = 2 * idx + 1;
    let mut input = headers_req(id, "GET", "/", &[], false);
    input.extend(frame(RST_STREAM, 0, id, &8u32.to_be_bytes()));
    let at = secs(f64::from(idx) / 1000.0);
    if conn.feed_at(&input, at).is_err() {
      failed = true;
      break;
    }
  }
  assert!(failed);
  assert_eq!(go_away_code(&take_frames(&mut conn)).map(|el| el.1), Some(11));

  let mut conn = ready_server(HttpRecvParams::with_default_params());
  for idx in 0..200u32 {
    let id = 2 * idx + 1;
    let mut input = headers_req(id, "GET", "/", &[], false);
    input.extend(frame(RST_STREAM, 0, id, &8u32.to_be_bytes()));
    conn.feed_at(&input, secs(f64::from(idx) * 11.0 / 200.0)).unwrap();
  }
  assert_eq!(go_away_code(&take_frames(&mut conn)), None);
}

#[test]
fn limit_continuation_flood() {
  let block = {
    let full = headers_req(1, "GET", "/", &[("x-a", "1"), ("x-b", "2"), ("x-c", "3")], true);
    full[9..].to_vec()
  };
  let chunks: Vec<&[u8]> = block.chunks(block.len().div_ceil(6)).collect();
  assert_eq!(chunks.len(), 6);
  // HEADERS plus 5 CONTINUATIONs is one too many.
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let mut input = frame(HEADERS, 1, 1, chunks[0]);
  for (idx, chunk) in chunks[1..].iter().enumerate() {
    input.extend(frame(9, if idx == 4 { 4 } else { 0 }, 1, chunk));
  }
  assert!(conn.feed(&input).is_err());
  assert_eq!(go_away_code(&take_frames(&mut conn)).map(|el| el.1), Some(11));
  // HEADERS plus 4 CONTINUATIONs is accepted.
  let chunks: Vec<&[u8]> = block.chunks(block.len().div_ceil(5)).collect();
  assert_eq!(chunks.len(), 5);
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let mut input = frame(HEADERS, 1, 1, chunks[0]);
  for (idx, chunk) in chunks[1..].iter().enumerate() {
    input.extend(frame(9, if idx == 3 { 4 } else { 0 }, 1, chunk));
  }
  conn.feed(&input).unwrap();
  assert!(matches!(events(&mut conn)[..], [ConnEvent::Headers { .. }]));
}

#[test]
fn limit_ping_flood() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let mut failed = false;
  for idx in 0..1001u32 {
    if conn.feed_at(&frame(PING, 0, 0, &[0; 8]), secs(f64::from(idx) / 2000.0)).is_err() {
      failed = true;
      break;
    }
  }
  assert!(failed);
  assert_eq!(go_away_code(&take_frames(&mut conn)).map(|el| el.1), Some(11));
}

#[test]
fn limit_header_list_size() {
  let mut conn = ready_server(HttpRecvParams::with_default_params().set_max_headers_len(300));
  let big = "v".repeat(200);
  conn.feed(&headers_req(1, "GET", "/", &[("x-big", &big)], true)).unwrap();
  let frames = take_frames(&mut conn);
  let headers = frames.iter().find(|el| el.0 == HEADERS && el.2 == 1).expect("a 431 response");
  let fields = decode_block(&mut response_decoder(), &headers.3);
  assert!(fields.contains(&(":status".into(), "431".into())), "{fields:?}");
  assert!(events(&mut conn).is_empty());
  conn.feed(&headers_req(3, "GET", "/", &[], true)).unwrap();
  assert!(matches!(events(&mut conn)[..], [ConnEvent::Headers { .. }]));
}

#[test]
fn limit_body_len() {
  let hp = HttpRecvParams::with_default_params().set_max_body_len(10);
  let mut conn = ready_server(hp);
  let mut input = headers_req(1, "POST", "/", &[], false);
  input.extend(data(1, &[0; 11], true));
  input.extend(headers_req(3, "GET", "/", &[], true));
  conn.feed(&input).unwrap();
  let frames = take_frames(&mut conn);
  assert_eq!(rst_code(&frames, 1), Some(8), "{frames:?}");
  assert_eq!(go_away_code(&frames), None);
  assert!(
    events(&mut conn)
      .contains(&ConnEvent::Headers { end_stream: true, stream_id: U31::from_u32(3) })
  );
}

#[test]
fn limit_conn_buffered() {
  let hp = HttpRecvParams::with_default_params().set_max_conn_buffered_len(1000);
  let mut conn = ready_server(hp);
  let mut input = Vec::new();
  for id in [1, 3, 5] {
    input.extend(headers_req(id, "POST", "/", &[], false));
    input.extend(data(id, &[0; 400], false));
  }
  conn.feed(&input).unwrap();
  let frames = take_frames(&mut conn);
  assert_eq!(rst_code(&frames, 1), None);
  assert_eq!(rst_code(&frames, 3), None);
  assert_eq!(rst_code(&frames, 5), Some(7), "{frames:?}");
}

#[test]
fn limit_send_queue() {
  let hp = HttpRecvParams::with_default_params().set_max_send_queue_len(1000);
  let mut conn = ready_server(hp);
  conn.feed(&settings(&[(4, 0)])).unwrap();
  let mut queued = 0;
  let mut failed = false;
  for id in (1..40).step_by(2) {
    conn.feed(&headers_req(id, "GET", "/", &[], true)).unwrap();
    let mut msg = MsgBufferString::default();
    msg.body.extend_from_copyable_slice(&[1; 100]).unwrap();
    if conn.send_response(U31::from_u32(id), StatusCode::Ok, &mut msg).is_err() {
      failed = true;
      break;
    }
    queued += 100;
  }
  assert!(failed, "queued {queued} bytes without an error");
  assert!(queued <= 1000);
}

#[test]
fn limit_concurrent_streams() {
  let hp = HttpRecvParams::with_default_params().set_max_concurrent_streams_num(2);
  let mut conn = ready_server(hp);
  for id in [1, 3, 5] {
    conn.feed(&headers_req(id, "GET", "/", &[], true)).unwrap();
  }
  let frames = take_frames(&mut conn);
  assert_eq!(rst_code(&frames, 5), Some(7), "{frames:?}");
  assert_eq!(conn.open_streams(), 2);
}

// A client stream stays in the table after both sides end, until the handle finishes it; it no
// longer counts against the server's limit. Finishing an unended stream resets it.
#[test]
fn conn_client_finish_stream() {
  let mut client =
    Http2Conn::<true>::new(HttpRecvParams::with_default_params(), &mut Xorshift64::from(3u64));
  assert!(!client.peer_settings_seen());
  let mut input = settings(&[]);
  input.extend(frame(SETTINGS, 1, 0, &[]));
  let _ = client.feed(&input).unwrap();
  assert!(client.peer_settings_seen());
  let _ = take_output(&mut client);
  let done = client.open_stream().unwrap();
  let msg = MsgBufferStr::from_uri(Uri::new("http://localhost/x"));
  client.send_request(done, Method::Get, &msg, true).unwrap();
  let open = client.open_stream().unwrap();
  client.send_request(open, Method::Get, &msg, false).unwrap();
  let _ = take_output(&mut client);
  let mut enc = HpackEncoder::new(&mut Xorshift64::from(5u64));
  let mut block = VectorUsize::new();
  enc.encode(&mut block, 3, [(HpackHeaderBasic::StatusCode(StatusCode::Ok), "200")], []).unwrap();
  let _ = client.feed(&frame(HEADERS, 0b101, 1, &block)).unwrap();
  let _ = events(&mut client);
  assert_eq!((client.open_streams(), client.active_streams()), (2, 1));
  assert_eq!(client.status(done), Some(StatusCode::Ok));
  client.finish_stream(done, true);
  assert!(take_frames(&mut client).is_empty());
  client.finish_stream(open, true);
  let frames = take_frames(&mut client);
  assert_eq!(
    (frames[0].0, frames[0].2, frames[0].3.as_slice()),
    (RST_STREAM, 3, &8u32.to_be_bytes()[..])
  );
  assert_eq!((client.open_streams(), client.active_streams()), (0, 0));
}

// A client's GOAWAY does not end the server's side: it keeps answering until the client closes,
// so no unread frame makes the close a TCP reset.
#[test]
fn conn_peer_go_away_keeps_serving() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let mut input = frame(GOAWAY, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]);
  input.extend(frame(PING, 0, 0, b"h2spec\0\0"));
  let _ = conn.feed(&input).unwrap();
  let _ = events(&mut conn);
  let frames = take_frames(&mut conn);
  assert_eq!((frames[0].0, frames[0].1), (PING, 1));
  assert!(!conn.is_closed());
}

// The default limit leaves h2load's `-m 100` (and browsers' ~100) room on one connection.
#[test]
fn conn_default_settings_allow_128_streams() {
  let mut conn = server(HttpRecvParams::with_default_params());
  let frames = take_frames(&mut conn);
  let advertised = frames[0].3.chunks(6).find_map(|pair| {
    (u16::from_be_bytes([pair[0], pair[1]]) == 3)
      .then(|| u32::from_be_bytes([pair[2], pair[3], pair[4], pair[5]]))
  });
  assert_eq!(advertised, Some(128));
}

// The output handed on as one buffer is exactly what the slices give; putting it back restores
// it, and a buffer given while the output is empty and holds none is the one written into next.
#[test]
fn conn_take_output_is_the_queued_bytes() {
  fn respond(conn: &mut Http2Conn<false>, stream: u32) {
    let _ = conn.feed(&headers_req(stream, "GET", "/", &[], true)).unwrap();
    let _ = events(conn);
    let mut msg = MsgBufferString::default();
    msg.body.extend_from_copyable_slice(b"hello").unwrap();
    conn.send_response(U31::from_u32(stream), StatusCode::Ok, &mut msg).unwrap();
  }
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  respond(&mut conn, 1);
  assert!(conn.has_output());
  let taken = conn.take_output(Vec::with_capacity(7)).unwrap();
  assert!(!conn.has_output());
  let spare = conn.untake_output(taken.clone());
  assert_eq!(spare.capacity(), 7);
  assert!(conn.has_output());
  assert_eq!(conn.take_output(Vec::new()).unwrap(), taken);
  conn.give_output_buffer(Vec::with_capacity(4096));
  respond(&mut conn, 3);
  assert!(conn.has_output());
  let next = conn.take_output(Vec::new()).unwrap();
  assert!(next.capacity() >= 4096);
  assert_eq!(parse_all(&next).iter().map(|el| (el.0, el.2)).collect::<Vec<_>>(), [(HEADERS, 3), (DATA, 3)]);
}
