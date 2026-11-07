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
  sized_response(conn, stream, 1)
}

/// The header block of a `text/plain` response of `len` bytes.
fn sized_response(conn: &mut Http2Conn<false>, stream: u32, len: usize) -> Vec<u8> {
  let _ = conn.feed(&headers_req(stream, "GET", "/", &[], true)).unwrap();
  let _ = events(conn);
  let mut msg = MsgBufferString::default();
  msg.headers.push_from_iter(Header::from_name_and_value("content-type", ["text/plain"])).unwrap();
  msg.headers.push_from_iter(Header::from_name_and_value("server", ["rimu-ws"])).unwrap();
  msg.body.extend_from_copyable_slice(&vec![b'2'; len]).unwrap();
  conn.send_response(U31::from_u32(stream), StatusCode::Ok, &mut msg).unwrap();
  let frames = take_frames(conn);
  frames.into_iter().find(|el| el.0 == HEADERS).unwrap().3
}

// A content-length that repeats the previous one goes into the dynamic table, so a server
// answering with one length (a fixed body) sends it as one index byte from then on.
#[test]
fn conn_repeated_content_length_indexed() {
  let mut conn = indexing_server();
  let blocks: Vec<_> = [1, 3, 5, 7].into_iter().map(|el| plain_response(&mut conn, el)).collect();
  assert!(blocks[0].ends_with(&[0x0F, 0x0D, 1, b'1']), "{:x?}", blocks[0]);
  // After the three fields by index: the repeat, added to the table (static name 28).
  assert_eq!(blocks[1].get(3), Some(&0x5C), "{:x?}", blocks[1]);
  assert_eq!(blocks[2], blocks[3]);
  assert_eq!(blocks[3].len(), 4, ":status, content-type, server and content-length, by index");
  let mut dec = response_decoder();
  for block in &blocks {
    let fields = decode_block(&mut dec, block);
    assert!(fields.contains(&("content-length".into(), "1".into())), "{fields:?}");
  }
}

// Lengths that change from one response to the next stay out of the dynamic table.
#[test]
fn conn_changing_content_length_not_indexed() {
  let mut conn = indexing_server();
  let _ = sized_response(&mut conn, 1, 1);
  let generation = conn.hpack_generation();
  for (idx, len) in [2, 1, 2, 1, 2].into_iter().enumerate() {
    let block = sized_response(&mut conn, 3 + 2 * u32::try_from(idx).unwrap(), len);
    assert!(block.ends_with(&[0x0F, 0x0D, 1, b'0' + len as u8]), "{block:x?}");
  }
  assert_eq!(conn.hpack_generation(), generation);
}

#[test]
fn conn_header_cache_hit_same_bytes() {
  let mut conn = indexing_server();
  let first = plain_response(&mut conn, 1);
  // Refers to the first's fields and adds the repeated content-length to the table.
  let second = plain_response(&mut conn, 3);
  let third = plain_response(&mut conn, 5);
  let generation = conn.hpack_generation();
  let fourth = plain_response(&mut conn, 7);
  assert_ne!(first, second, "the first response indexes its fields, the second refers to them");
  assert_eq!(third, fourth);
  assert_eq!(conn.hpack_generation(), generation);
  assert_eq!(conn.header_cache_hits(), 1);
  let mut dec = response_decoder();
  for block in [&first, &second, &third, &fourth] {
    let fields = decode_block(&mut dec, block);
    assert!(fields.contains(&("content-type".into(), "text/plain".into())), "{fields:?}");
    assert!(fields.contains(&("content-length".into(), "1".into())), "{fields:?}");
  }
}

#[test]
fn conn_header_cache_invalid_after_table_size_change() {
  let mut conn = indexing_server();
  let mut blocks: Vec<_> = [1, 3, 5, 7].into_iter().map(|el| plain_response(&mut conn, el)).collect();
  assert_eq!(conn.header_cache_hits(), 1);
  let _ = conn.feed(&settings(&[(1, 0)])).unwrap();
  let _ = take_output(&mut conn);
  let after = plain_response(&mut conn, 9);
  assert_eq!(after[0], 0x20, "a dynamic table size update to 0 comes first: {after:?}");
  blocks.push(after);
  blocks.push(plain_response(&mut conn, 11));
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
  assert_eq!(
    parse_all(&next).iter().map(|el| (el.0, el.2)).collect::<Vec<_>>(),
    [(HEADERS, 3), (DATA, 3)]
  );
}

// A request block repeated byte for byte replays its decode, with the same fields.
#[test]
fn conn_decode_memo_replays_identical_block() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  // GET http://a/x with `user-agent: t`, all literal without indexing: the table never changes.
  let block = [
    0x82, 0x86, 0x04, 0x02, b'/', b'x', 0x01, 0x01, b'a', 0x00, 0x0a, b'u', b's', b'e', b'r', b'-',
    b'a', b'g', b'e', b'n', b't', 0x01, b't',
  ];
  let mut decoded = Vec::new();
  // The first block also applies the table size the SETTINGS announced, so it is not kept; the
  // second is, and the third replays it.
  for id in [1u32, 3, 5] {
    let _ = conn.feed(&frame(HEADERS, 0b101, id, &block)).unwrap();
    let _ = events(&mut conn);
    let msg = conn.msg_mut(U31::from_u32(id)).unwrap();
    let headers: Vec<(String, String)> =
      msg.headers.iter().map(|el| (el.name.to_string(), el.value.to_string())).collect();
    decoded.push((msg.uri.as_str().to_string(), headers, conn.method(U31::from_u32(id))));
  }
  assert_eq!(conn.decode_memo_hits(), 1);
  assert_eq!(decoded[0], decoded[2]);
  assert_eq!(decoded[1], decoded[2]);
  assert_eq!(decoded[2].0, "http://a/x");
  assert_eq!(decoded[2].1, [("user-agent".to_string(), "t".to_string())]);
}

// A block that refers to the dynamic table decodes afresh once the table changed: index 62 names
// another entry after a new insert, and the memo must not answer with the old one.
#[test]
fn conn_decode_memo_follows_table_changes() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let authority = |conn: &mut Http2Conn<false>, id: u32| {
    conn.msg_mut(U31::from_u32(id)).unwrap().uri.authority().to_string()
  };
  // :authority "a" with incremental indexing: it becomes dynamic index 62.
  let insert_a = [0x82, 0x86, 0x84, 0x41, 0x01, b'a'];
  let insert_b = [0x82, 0x86, 0x84, 0x41, 0x01, b'b'];
  let refer = [0x82, 0x86, 0x84, 0xbe];
  let mut id = 1;
  for block in [&insert_a[..], &refer, &refer] {
    let _ = conn.feed(&frame(HEADERS, 0b101, id, block)).unwrap();
    let _ = events(&mut conn);
    assert_eq!(authority(&mut conn, id), "a");
    id += 2;
  }
  assert_eq!(conn.decode_memo_hits(), 1);
  let _ = conn.feed(&frame(HEADERS, 0b101, id, &insert_b)).unwrap();
  let _ = events(&mut conn);
  id += 2;
  let _ = conn.feed(&frame(HEADERS, 0b101, id, &refer)).unwrap();
  let _ = events(&mut conn);
  assert_eq!(authority(&mut conn, id), "b");
  assert_eq!(conn.decode_memo_hits(), 1);
}

#[test]
fn conn_response_shared_body() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let _ = conn.feed(&settings(&[(4, 1 << 20)])).unwrap();
  let _ = conn.feed(&frame(WINDOW_UPDATE, 0, 0, &(1u32 << 20).to_be_bytes())).unwrap();
  let _ = conn.feed(&headers_req(1, "GET", "/", &[], true)).unwrap();
  let _ = take_output(&mut conn);
  let id = U31::from_u32(1);
  let shared = SharedBytes::new(Arc::from(vec![7u8; 40 * 1024].into_boxed_slice()));
  let range = shared.as_slice().as_ptr_range();
  let mut msg = MsgBufferString::default();
  msg.headers.push_from_iter(Header::from_name_and_value("content-type", ["text/css"])).unwrap();
  conn.send_response_shared(id, StatusCode::Ok, &mut msg, shared).unwrap();
  assert_eq!(msg.headers.headers_len(), 0);
  let mut slices = ArrayVectorCopy::<&[u8], 16>::new();
  conn.output(&mut slices);
  assert!(slices.iter().any(|el| range.contains(&el.as_ptr())));
  let frames = take_frames(&mut conn);
  assert_eq!(frames[0].0, HEADERS, "{frames:?}");
  let fields = decode_block(&mut response_decoder(), &frames[0].3);
  assert!(fields.contains(&("content-type".into(), "text/css".into())), "{fields:?}");
  assert!(fields.contains(&("content-length".into(), "40960".into())), "{fields:?}");
  let data_frames: Vec<_> = frames.iter().filter(|el| el.0 == DATA).collect();
  assert_eq!(data_frames.iter().map(|el| el.3.len()).collect::<Vec<_>>(), [16384, 16384, 8192]);
  assert!(data_frames.iter().all(|el| el.3.iter().all(|byte| *byte == 7)));
  assert_eq!(data_frames.last().unwrap().1 & 1, 1);
  assert_eq!(conn.open_streams(), 0);
}

#[test]
fn conn_shared_bodies_do_not_count_toward_the_send_queue() {
  let shared = SharedBytes::new(Arc::from(vec![1u8; 4000].into_boxed_slice()));
  let own_response = |conn: &mut Http2Conn<false>, id: u32| {
    conn.feed(&headers_req(id, "GET", "/", &[], true)).unwrap();
    let mut msg = MsgBufferString::default();
    msg.body.extend_from_copyable_slice(&[1; 600]).unwrap();
    conn.send_response(U31::from_u32(id), StatusCode::Ok, &mut msg)
  };
  // Closed windows: the shared bodies wait on their streams. Open ones: they wait in the output.
  for window in [0, 1 << 20] {
    let hp = HttpRecvParams::with_default_params().set_max_send_queue_len(1000);
    let mut conn = ready_server(hp);
    conn.feed(&settings(&[(4, window)])).unwrap();
    conn.feed(&frame(WINDOW_UPDATE, 0, 0, &(1u32 << 20).to_be_bytes())).unwrap();
    let _ = take_output(&mut conn);
    for id in (1..20).step_by(2) {
      conn.feed(&headers_req(id, "GET", "/", &[], true)).unwrap();
      let mut msg = MsgBufferString::default();
      conn
        .send_response_shared(U31::from_u32(id), StatusCode::Ok, &mut msg, shared.clone())
        .unwrap();
    }
    assert!(conn.has_output());
    own_response(&mut conn, 21).unwrap();
    // Own bytes still count: with closed windows the first 600 are still queued.
    if window == 0 {
      assert!(own_response(&mut conn, 23).is_err());
    }
  }
}

// RFC 9113 §5.1: frames on a stream this side reset may already have been on their way; they are
// ignored, not answered with another RST_STREAM, and DATA still counts toward the connection
// window, which is handed back.
#[test]
fn conn_frames_after_our_reset_are_ignored() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let _ = conn.feed(&headers_req(1, "POST", "/", &[], false)).unwrap();
  let id = U31::from_u32(1);
  // Answered before the request body ended: RST_STREAM(NO_ERROR) tells the client to stop.
  let mut msg = MsgBufferString::default();
  conn.send_response(id, StatusCode::Ok, &mut msg).unwrap();
  let frames = take_frames(&mut conn);
  assert_eq!(rst_code(&frames, 1), Some(0), "{frames:?}");
  // The client's body was already on its way, and its trailers.
  let mut input = data(1, &[7; 1000], false);
  input.extend(frame(WINDOW_UPDATE, 0, 1, &100u32.to_be_bytes()));
  input.extend(data(1, &[7; 1000], false));
  input.extend(headers_req(1, "POST", "/", &[], true));
  let _ = conn.feed(&input).unwrap();
  let frames = take_frames(&mut conn);
  assert_eq!(rst_code(&frames, 1), None, "{frames:?}");
  assert!(!frames.iter().any(|el| el.0 == GOAWAY), "{frames:?}");
  let returned: u32 = frames
    .iter()
    .filter(|el| el.0 == WINDOW_UPDATE && el.2 == 0)
    .map(|el| u32::from_be_bytes(el.3[..4].try_into().unwrap()))
    .sum();
  assert!(returned >= 2000, "connection window handed back: {returned} {frames:?}");
  // A stream the client itself ended still errors.
  let _ = conn.feed(&headers_req(3, "GET", "/", &[], true)).unwrap();
  let mut msg = MsgBufferString::default();
  conn.send_response(U31::from_u32(3), StatusCode::Ok, &mut msg).unwrap();
  let _ = take_frames(&mut conn);
  let _ = conn.feed(&data(3, b"late", false)).unwrap();
  let frames = take_frames(&mut conn);
  assert_eq!(rst_code(&frames, 3), Some(5), "{frames:?}");
}

// A response header block larger than the peer's frame size goes out as HEADERS plus
// CONTINUATIONs, each within the frame size, and decodes whole (cnetmod never splits).
#[test]
fn conn_large_response_headers_use_continuation() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let _ = conn.feed(&headers_req(1, "GET", "/", &[], true)).unwrap();
  let big: String = (0..40_000u32).map(|el| char::from(b'a' + (el * 7 % 26) as u8)).collect();
  let mut msg = MsgBufferString::default();
  msg.headers.push_from_iter(Header::from_name_and_value("x-big", [big.as_str()])).unwrap();
  conn.send_response(U31::from_u32(1), StatusCode::Ok, &mut msg).unwrap();
  let frames = take_frames(&mut conn);
  let block_frames: Vec<_> =
    frames.iter().filter(|el| el.2 == 1 && (el.0 == HEADERS || el.0 == 9)).collect();
  assert!(block_frames.len() >= 2, "{}", block_frames.len());
  assert_eq!(block_frames[0].0, HEADERS);
  assert!(block_frames[1..].iter().all(|el| el.0 == 9));
  let (last, rest) = block_frames.split_last().unwrap();
  assert_eq!(last.1 & 4, 4);
  assert!(rest.iter().all(|el| el.1 & 4 == 0));
  assert!(block_frames.iter().all(|el| el.3.len() <= 16_384));
  let block: Vec<u8> = block_frames.iter().flat_map(|el| el.3.clone()).collect();
  let fields = decode_block(&mut response_decoder(), &block);
  assert!(fields.contains(&("x-big".into(), big)));
}

// A request header block split over HEADERS and two CONTINUATIONs, cut inside fields, decodes as
// one block (zix decoded each fragment on its own).
#[test]
fn conn_header_block_split_mid_field() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let full = headers_req(1, "GET", "/split/path", &[("x-field", "a-value-that-gets-cut")], true);
  let block = &full[9..];
  let path_at = block.windows(6).position(|el| el == b"/split").unwrap() + 3;
  let field_at = block.windows(7).position(|el| el == b"a-value").unwrap() + 4;
  let mut input = frame(HEADERS, 1, 1, &block[..path_at]);
  input.extend(frame(9, 0, 1, &block[path_at..field_at]));
  input.extend(frame(9, 4, 1, &block[field_at..]));
  conn.feed(&input).unwrap();
  assert_eq!(
    events(&mut conn),
    [ConnEvent::Headers { end_stream: true, stream_id: U31::from_u32(1) }]
  );
  let msg = conn.msg_mut(U31::from_u32(1)).unwrap();
  assert_eq!(msg.uri.path(), "/split/path");
  assert_eq!(msg.headers.get_by_name(b"x-field").map(|el| el.value), Some("a-value-that-gets-cut"));
}

// Inserts into a full dynamic table evict the oldest entries, and indexed references afterwards
// resolve against what is left (zix dropped the insert and fell out of step with the peer).
#[test]
fn hpack_decoder_evicts_when_full() {
  let entry = |idx: usize| (alloc::format!("n{idx:03}"), alloc::format!("{idx:0>96}"));
  let mut dec = HpackDecoder::new();
  dec.set_max_bytes(4096);
  let mut block = Vec::new();
  for idx in 0..40 {
    let (name, value) = entry(idx);
    block.push(0x40);
    block.push(u8::try_from(name.len()).unwrap());
    block.extend(name.as_bytes());
    block.push(u8::try_from(value.len()).unwrap());
    block.extend(value.as_bytes());
  }
  assert_eq!(decode_block(&mut dec, &block).len(), 40);
  // Each entry counts 4 + 96 + 32 = 132 bytes: 31 fit in 4096, entries 9 to 39. The newest is
  // index 62, the oldest kept 92.
  assert_eq!(decode_block(&mut dec, &[0x80 | 62, 0x80 | 92]), [entry(39), entry(9)]);
  assert!(dec.decode(&[0x80 | 93], |_| Ok(())).is_err());
}

// A request whose content-length is already past `max_body_len` is answered 413 at its headers,
// and reset with NO_ERROR so the client stops sending, instead of after its body has been
// received up to the limit.
#[test]
fn conn_content_length_over_max_body_refused() {
  let hp = HttpRecvParams::with_default_params().set_max_body_len(1000);
  let mut conn = ready_server(hp);
  let _ = conn.feed(&headers_req(1, "POST", "/", &[("content-length", "1001")], false)).unwrap();
  let frames = take_frames(&mut conn);
  let headers = frames.iter().find(|el| el.0 == HEADERS && el.2 == 1).expect("a response");
  let fields = decode_block(&mut response_decoder(), &headers.3);
  assert!(fields.contains(&(":status".into(), "413".into())), "{fields:?}");
  assert_eq!(rst_code(&frames, 1), Some(0), "{frames:?}");
  assert!(!events(&mut conn).iter().any(|el| matches!(el, ConnEvent::Headers { .. })));
  // At the limit, it's taken.
  let _ = conn.feed(&headers_req(3, "POST", "/", &[("content-length", "1000")], false)).unwrap();
  assert_eq!(rst_code(&take_frames(&mut conn), 3), None);
}

// A connection between turns holds no output buffer: the driver takes it back once the output is
// written, so thousands of idle connections don't each keep the last output's buffer.
#[test]
fn conn_idle_output_buffer_taken_back() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let _ = conn.feed(&headers_req(1, "GET", "/", &[], true)).unwrap();
  let mut msg = MsgBufferString::default();
  msg.body.extend_from_copyable_slice(&[1; 1000]).unwrap();
  // Output pending: nothing to take back.
  conn.send_response(U31::from_u32(1), StatusCode::Ok, &mut msg).unwrap();
  assert!(conn.take_idle_output_buffer().is_none());
  let _ = take_output(&mut conn);
  let buffer = conn.take_idle_output_buffer().expect("the written output's buffer");
  assert!(buffer.capacity() >= 1000 && buffer.is_empty());
  assert!(conn.take_idle_output_buffer().is_none());
  // A buffer given back is used for the next output.
  let ptr = buffer.as_ptr();
  conn.give_output_buffer(buffer);
  let _ = conn.feed(&headers_req(3, "GET", "/", &[], true)).unwrap();
  let mut msg = MsgBufferString::default();
  conn.send_response(U31::from_u32(3), StatusCode::Ok, &mut msg).unwrap();
  let mut slices = ArrayVectorCopy::<&[u8], 16>::new();
  conn.output(&mut slices);
  assert_eq!(slices[0].as_ptr(), ptr);
}

// With an event budget, feeding stops at the frame that reaches it, so a server can answer a few
// requests before it decodes the next ones.
#[test]
fn conn_feed_some_stops_at_the_event_budget() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let first = headers_req(1, "GET", "/", &[], true);
  let mut input = first.clone();
  input.extend(headers_req(3, "GET", "/", &[], true));
  input.extend(headers_req(5, "GET", "/", &[], true));
  assert_eq!(conn.feed_some_at(&input, Duration::ZERO, 1).unwrap(), first.len());
  assert_eq!(events(&mut conn).len(), 1);
  let rest = input.get(first.len()..).unwrap();
  assert_eq!(conn.feed_some_at(rest, Duration::ZERO, usize::MAX).unwrap(), rest.len());
  assert_eq!(events(&mut conn).len(), 2);
}

// Answered between feeds, each request opens the slot the previous one freed: a batch of requests
// keeps one stream slot, still in cache, instead of one cold slot per request.
#[test]
fn conn_requests_answered_between_feeds_share_a_slot() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let mut input = Vec::new();
  for idx in 0..10u32 {
    input.extend(headers_req(2 * idx + 1, "GET", "/", &[], true));
  }
  let mut offset = 0;
  while offset < input.len() {
    offset += conn.feed_some_at(input.get(offset..).unwrap(), Duration::ZERO, 1).unwrap();
    for event in events(&mut conn) {
      let ConnEvent::Headers { stream_id, .. } = event else { continue };
      let mut msg = MsgBufferString::default();
      conn.send_response(stream_id, StatusCode::Ok, &mut msg).unwrap();
    }
  }
  assert_eq!(conn.stream_slots(), 1);
}

// A feed that reaches its event budget on the input's last frame still announces the connection
// window that input used: no later feed may come to do it.
#[test]
fn conn_feed_some_budget_on_the_last_frame_opens_the_window() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let _ = conn.feed(&headers_req(1, "POST", "/", &[], false)).unwrap();
  let _ = events(&mut conn);
  let _ = take_frames(&mut conn);
  let mut input = Vec::new();
  for _ in 0..4 {
    input.extend(data(1, &[7; 1000], false));
  }
  assert_eq!(conn.feed_some_at(&input, Duration::ZERO, 4).unwrap(), input.len());
  let frames = take_frames(&mut conn);
  assert!(
    frames.iter().any(|el| el.0 == WINDOW_UPDATE && el.2 == 0 && el.3 == 4000u32.to_be_bytes()),
    "no connection WINDOW_UPDATE of 4000: {frames:?}"
  );
}

// A header block split over frames is buffered only up to `max_headers_len`: a raw block is never
// larger than the header list it decodes to, so a bigger one ends the connection instead of being
// buffered whole (HEADERS + 8 CONTINUATIONs of 16 MiB frames would be 144 MiB).
#[test]
fn conn_header_block_over_the_limit_is_not_buffered() {
  let hp = HttpRecvParams::with_optioned_params();
  let limit = usize::try_from(hp.max_headers_len()).unwrap();
  let half = vec![0x82; limit / 2 + 1];
  let mut conn = ready_server(hp);
  let mut input = frame(HEADERS, 0, 1, &half);
  input.extend(frame(9, 0, 1, &half));
  assert!(conn.feed(&input).is_err());
  assert_eq!(go_away_code(&take_frames(&mut conn)).map(|el| el.1), Some(11));
  let mut conn = ready_server(hp);
  assert!(conn.feed(&frame(HEADERS, 0, 1, &vec![0x82; limit + 1])).is_err());
  assert_eq!(go_away_code(&take_frames(&mut conn)).map(|el| el.1), Some(11));
}

// Streams that close while waiting for the connection window leave the queue of blocked streams:
// a client that never opens the window, and keeps opening and resetting streams, does not grow it.
#[test]
fn conn_closed_streams_leave_the_blocked_queue() {
  let mut conn = ready_server(HttpRecvParams::with_permissive_params());
  let _ = conn.feed(&headers_req(1, "GET", "/", &[], true)).unwrap();
  let mut msg = MsgBufferString::default();
  msg.body.extend_from_copyable_slice(&vec![1; 65_535]).unwrap();
  conn.send_response(U31::from_u32(1), StatusCode::Ok, &mut msg).unwrap();
  let _ = take_output(&mut conn);
  for idx in 0..1000u32 {
    let id = 3 + 2 * idx;
    let _ = conn.feed(&headers_req(id, "GET", "/", &[], true)).unwrap();
    let _ = events(&mut conn);
    let mut msg = MsgBufferString::default();
    msg.body.extend_from_copyable_slice(&[1; 10]).unwrap();
    conn.send_response(U31::from_u32(id), StatusCode::Ok, &mut msg).unwrap();
    let _ = conn.feed(&frame(3, 0, id, &8u32.to_be_bytes())).unwrap();
    let _ = events(&mut conn);
    let _ = take_output(&mut conn);
  }
  assert_eq!(conn.open_streams(), 0);
  assert!(conn.blocked_len() <= 32, "{} ids blocked with no stream open", conn.blocked_len());
}

// Resets the peer provokes count against the same budget as the ones it sends (MadeYouReset,
// CVE-2025-8671): a WINDOW_UPDATE of 0 on each new stream makes the server reset it, and past the
// budget the connection ends.
#[test]
fn limit_provoked_resets_goaway() {
  let mut conn = ready_server(HttpRecvParams::with_default_params());
  let mut failed = false;
  for idx in 0..201u32 {
    let id = 2 * idx + 1;
    let mut input = headers_req(id, "GET", "/", &[], false);
    input.extend(frame(WINDOW_UPDATE, 0, id, &0u32.to_be_bytes()));
    let at = secs(f64::from(idx) / 1000.0);
    if conn.feed_at(&input, at).is_err() {
      failed = true;
      break;
    }
    let _ = events(&mut conn);
  }
  assert!(failed, "201 provoked resets within the window and the connection still stands");
  assert_eq!(go_away_code(&take_frames(&mut conn)).map(|el| el.1), Some(11));
}

// A stream whose body is consumed as it arrives (manual mode, WebSocket over HTTP/2) is limited by
// what it holds, not by what it ever received: 1.25 MiB through a stream with a 1 MiB limit,
// consumed 16 KiB at a time, is not reset.
#[test]
fn conn_consumed_body_does_not_count_against_the_limits() {
  let hp = HttpRecvParams::with_default_params();
  assert_eq!(hp.max_body_len(), 1 << 20);
  let mut conn = ready_server(hp);
  let _ = conn.feed(&headers_req(1, "POST", "/", &[], false)).unwrap();
  let _ = events(&mut conn);
  let id = U31::from_u32(1);
  for _ in 0..80 {
    let _ = conn.feed(&data(1, &[5; 16 * 1024], false)).unwrap();
    let _ = events(&mut conn);
    let n = conn.msg_mut(id).unwrap().body.len();
    conn.msg_mut(id).unwrap().body.clear();
    conn.consume_body(id, n);
    conn.release_capacity(id, u32::try_from(n).unwrap()).unwrap();
    let frames = take_frames(&mut conn);
    assert_eq!(rst_code(&frames, 1), None, "{frames:?}");
  }
  assert_eq!(conn.open_streams(), 1);
}
