use crate::{
  http3::{
    H3App, H3ConnState, H3Params, H3Settings,
    qpack_check::wire,
    testing::{
      GET, H3Net, PRIORITY_UPDATE, TestHandler, client_settings, connected, control_stream,
      data_frame, frame, h3_net, headers_frame, open_uni, reset, resets, response, resume, send,
      server_close, server_control_frames, server_state, server_streams, stop_sending, stops,
      varint, write,
    },
  },
  quic::{
    ConnState, Frame, PacketTy, QuicConn, QuicLimits, QuicParams, StreamId, parse_header,
    testing::encode_frames,
  },
  rng::ChaCha20,
  sync::AtomicU64,
  tls::SkCtx,
};
use alloc::{format, vec, vec::Vec};
use core::sync::atomic::Ordering;

const OK: &[u8] = b"hello";
// A PTO of the initial RTT, three times: the closing period
const CLOSING_US: u64 = 3 * (333_000 + 4 * 166_500 + 25_000);
// Static table indices (RFC 9204 Appendix A)
const AUTHORITY: u64 = 0;
const PATH_ROOT: u64 = 1;
const METHOD_GET: u64 = 17;
const SCHEME_HTTPS: u64 = 23;
const USER_AGENT: u64 = 95;

fn dynamic_params() -> H3Params {
  H3Params { qpack_max_table_capacity: 4096, qpack_blocked_streams: 16, ..H3Params::default() }
}

// The fields of a request of `method` for `path` with `extra` fields.
fn request_fields<'any>(
  method: &'any [u8],
  path: &'any [u8],
  extra: &[(&'any [u8], &'any [u8])],
) -> Vec<(&'any [u8], &'any [u8])> {
  let mut fields: Vec<(&[u8], &[u8])> = vec![
    (b":method", method),
    (b":scheme", b"https"),
    (b":authority", b"localhost"),
    (b":path", path),
  ];
  fields.extend_from_slice(extra);
  fields
}

// A HEADERS frame of `GET /path` whose `:authority` is the dynamic entry of absolute index 0, and
// whose other fields follow `refs`: (dynamic absolute index, or static name and value).
fn dynamic_request(ric: u64, path: &[u8], dynamic: &[u64]) -> Vec<u8> {
  let mut section = Vec::new();
  wire::prefix(&mut section, ric, ric, 128);
  wire::indexed(&mut section, true, METHOD_GET);
  wire::indexed(&mut section, true, SCHEME_HTTPS);
  wire::indexed(&mut section, false, ric - 1);
  wire::name_ref(&mut section, true, false, PATH_ROOT, path, false);
  for abs in dynamic {
    wire::indexed(&mut section, false, ric - 1 - abs);
  }
  frame(0x01, &section)
}

// The encoder stream of a client: its type and the capacity.
fn encoder_stream(capacity: u64) -> Vec<u8> {
  let mut out = vec![0x02];
  wire::set_capacity(&mut out, capacity);
  out
}

fn status(net: &H3Net, client: usize, id: StreamId) -> Option<Vec<u8>> {
  response(net, client, id).and_then(|el| el.field(b":status").map(<[u8]>::to_vec))
}

fn handler(net: &H3Net) -> &TestHandler {
  &net.servers[0].app.handler
}

// Brief step 1: a GET is answered with HEADERS, DATA and the FIN in one STREAM frame.
#[cfg_attr(miri, ignore)]
#[test]
fn get_request_answered_with_one_stream_frame() {
  let (mut net, client) = connected(H3Params::default(), &TestHandler::new(OK));
  let id = send(&mut net, client, &headers_frame(&GET), true);
  net.run();
  let rsp = response(&net, client, id).unwrap();
  // In order, a STREAM frame is one delivery: the whole response came in one, with its FIN
  assert_eq!(rsp.calls.len(), 1, "{:?}", rsp.calls);
  assert!(rsp.calls[0].1 && rsp.fin);
  assert_eq!(rsp.frames, [0x01, 0x00]);
  assert_eq!(rsp.field(b":status"), Some(&b"200"[..]));
  assert_eq!(rsp.field(b"content-type"), Some(&b"text/plain"[..]));
  assert_eq!(rsp.body, OK);
  let seen = &handler(&net).seen;
  assert_eq!(seen.len(), 1);
  assert_eq!(
    (&*seen[0].method, &*seen[0].scheme, &*seen[0].authority, &*seen[0].path),
    (&b"GET"[..], &b"https"[..], &b"localhost"[..], &b"/"[..])
  );
  assert!(seen[0].fields.is_empty() && seen[0].body.is_empty());
  assert_eq!(seen[0].stream, id.0);
  assert_eq!(server_state(&net, client, H3ConnState::live_requests), 0);
  assert_eq!(server_close(&net, client), None);
}

// Brief step 1: both sides send their SETTINGS first on their control streams; the server opens
// its QPACK encoder and decoder streams, on which nothing follows the type until it is needed.
#[cfg_attr(miri, ignore)]
#[test]
fn settings_exchanged_and_qpack_streams_open() {
  let params =
    H3Params { qpack_max_table_capacity: 4096, qpack_blocked_streams: 100, ..H3Params::default() };
  let (mut net, client) = connected(params, &TestHandler::new(OK));
  let ours = H3Settings { max_field_section_size: Some(8192), ..client_settings() };
  let _ = open_uni(&mut net, client, &control_stream(ours));
  net.run();
  let streams = server_streams(&net, client);
  assert_eq!(streams.iter().map(|el| el.0).collect::<Vec<_>>(), [0x00, 0x02, 0x03]);
  let expected = H3Settings {
    qpack_max_table_capacity: 4096,
    qpack_blocked_streams: 100,
    max_field_section_size: Some(16 * 1024),
  };
  let mut settings = [0u8; 64];
  let len = expected.encode(&mut settings).unwrap();
  assert_eq!(streams[0].1, &settings[..len]);
  assert!(streams[1].1.is_empty() && streams[2].1.is_empty());
  // Critical streams: never finished
  let logs = &net.clients[client].app.streams;
  assert!(logs.iter().filter(|(id, _)| **id & 0b11 == 0b11).all(|(_, log)| !log.fin));
  assert_eq!(server_state(&net, client, H3ConnState::peer_settings), Some(ours));
  assert_eq!(server_close(&net, client), None);
}

// Brief step 1: a POST whose body comes in DATA frames over many STREAM frames, which cut frame
// headers and the HEADERS frame (retained bytes), reaches the handler whole.
#[cfg_attr(miri, ignore)]
#[test]
fn post_with_body_reaches_handler() {
  let (mut net, client) = connected(H3Params::default(), &TestHandler::new(OK));
  let body: Vec<u8> = (0..300_000u32).map(|el| (el % 251) as u8).collect();
  let len = format!("{}", body.len());
  let extra: [(&[u8], &[u8]); 2] =
    [(b"content-length", len.as_bytes()), (b"content-type", b"application/octet-stream")];
  let mut request = headers_frame(&request_fields(b"POST", b"/upload", &extra));
  for chunk in body.chunks(100_000) {
    request.extend_from_slice(&data_frame(chunk));
  }
  let id = send(&mut net, client, &request[..7], false);
  net.run();
  let mut at = 7;
  for piece in [5, 1000, 4093, 150_000] {
    let end = (at + piece).min(request.len());
    write(&mut net, client, id, &request[at..end], false);
    net.run();
    at = end;
  }
  assert!(handler(&net).seen.is_empty());
  write(&mut net, client, id, &request[at..], true);
  net.run_for(1024);
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  let seen = &handler(&net).seen;
  assert_eq!(seen.len(), 1);
  assert_eq!((&*seen[0].method, &*seen[0].path), (&b"POST"[..], &b"/upload"[..]));
  assert_eq!(
    seen[0].fields,
    extra.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect::<Vec<_>>()
  );
  assert!(seen[0].body == body);
  assert_eq!(server_state(&net, client, H3ConnState::live_requests), 0);
}

// Brief step 1 and ruling T13-f: malformed requests (RFC 9114 sections 4.1.2 and 4.3) are stream
// errors H3_MESSAGE_ERROR; the connection serves on.
#[cfg_attr(miri, ignore)]
#[test]
fn invalid_pseudo_headers_get_h3_message_error() {
  let (mut net, client) = connected(H3Params::default(), &TestHandler::new(OK));
  let get = |extra: &[(&[u8], &[u8])]| headers_frame(&request_fields(b"GET", b"/", extra));
  let mut cl_mismatch = headers_frame(&request_fields(b"POST", b"/", &[(b"content-length", b"5")]));
  cl_mismatch.extend_from_slice(&data_frame(b"abc"));
  let mut pseudo_trailer = get(&[]);
  pseudo_trailer.extend_from_slice(&headers_frame(&[(b":path", b"/x")]));
  let cases: Vec<Vec<u8>> = vec![
    // No :method, no :path, an empty :path
    headers_frame(&[(b":scheme", b"https"), (b":authority", b"localhost"), (b":path", b"/")]),
    headers_frame(&[(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"localhost")]),
    headers_frame(&request_fields(b"GET", b"", &[])),
    // A pseudo-header field that requests do not have, a response one, one twice
    get(&[(b":foo", b"bar")]),
    headers_frame(&[(b":status", b"200"), GET[0], GET[1], GET[2], GET[3]]),
    get(&[(b":method", b"POST")]),
    // A pseudo-header field after a field
    headers_frame(&[GET[0], (b"accept", b"*/*"), GET[1], GET[2], GET[3]]),
    // http without an authority, an authority that the host contradicts, userinfo
    headers_frame(&[(b":method", b"GET"), (b":scheme", b"http"), (b":path", b"/")]),
    get(&[(b"host", b"example.com")]),
    headers_frame(&[GET[0], GET[1], (b":authority", b"user@localhost"), GET[3]]),
    // CONNECT with :scheme and :path, an invalid method
    headers_frame(&request_fields(b"CONNECT", b"/", &[])),
    headers_frame(&request_fields(b"GE T", b"/", &[])),
    // Fields specific to a connection, a TE that is not "trailers"
    get(&[(b"connection", b"close")]),
    get(&[(b"transfer-encoding", b"chunked")]),
    get(&[(b"te", b"gzip")]),
    // Values that field-content does not allow, a name that is not a token
    get(&[(b"x-bad", b" leading")]),
    get(&[(b"x-bad", b"a\r\nb")]),
    get(&[(b"x bad", b"a")]),
    // A content-length that the body contradicts, or that is not a number
    cl_mismatch,
    get(&[(b"content-length", b"1x")]),
    // A pseudo-header field in the trailers
    pseudo_trailer,
  ];
  for (nth, case) in cases.iter().enumerate() {
    let id = send(&mut net, client, case, true);
    net.run();
    assert!(
      resets(&net, client).contains(&(id.0, 0x10e)),
      "case {nth}: {:?}",
      resets(&net, client)
    );
    assert_eq!(server_close(&net, client), None, "case {nth}");
  }
  assert_eq!(handler(&net).count, 0);
  assert_eq!(server_state(&net, client, H3ConnState::live_requests), 0);
  // Well formed: answered (TE: trailers is allowed, so is CONNECT without :scheme and :path)
  let id = send(&mut net, client, &get(&[(b"te", b"trailers")]), true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  let connect = [(b":method" as &[u8], b"CONNECT" as &[u8]), (b":authority", b"localhost:443")];
  let id = send(&mut net, client, &headers_frame(&connect), true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
}

// Brief step 1: field names are lowercase in HTTP/3 (RFC 9114 section 4.2).
#[cfg_attr(miri, ignore)]
#[test]
fn uppercase_header_name_rejected() {
  let (mut net, client) = connected(H3Params::default(), &TestHandler::new(OK));
  let request = headers_frame(&request_fields(b"GET", b"/", &[(b"User-Agent", b"curl")]));
  let id = send(&mut net, client, &request, true);
  net.run();
  assert!(resets(&net, client).contains(&(id.0, 0x10e)));
  assert_eq!(handler(&net).count, 0);
  let request = headers_frame(&request_fields(b"GET", b"/", &[(b"user-agent", b"curl")]));
  let id = send(&mut net, client, &request, true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(handler(&net).seen[0].fields, [(b"user-agent".to_vec(), b"curl".to_vec())]);
}

// Brief step 1: the control stream of the peer is critical (RFC 9114 section 6.2.1).
#[cfg_attr(miri, ignore)]
#[test]
fn closing_control_stream_is_connection_error() {
  let (mut net, client) = connected(H3Params::default(), &TestHandler::new(OK));
  let control = open_uni(&mut net, client, &control_stream(client_settings()));
  net.run();
  assert_eq!(server_close(&net, client), None);
  write(&mut net, client, control, b"", true);
  net.run();
  assert_eq!(server_close(&net, client), Some((true, 0x104)));
  assert_eq!(net.clients[client].conn.state(), ConnState::Draining);
}

// Brief step 1 and ruling T13-f: unknown frames on a request stream are skipped, wherever they
// are (RFC 9114 section 9).
#[cfg_attr(miri, ignore)]
#[test]
fn unknown_frame_on_request_stream_ignored() {
  let (mut net, client) = connected(H3Params::default(), &TestHandler::new(OK));
  let mut request = frame(0x21, b"grease");
  request.extend_from_slice(&headers_frame(&request_fields(
    b"POST",
    b"/",
    &[(b"content-length", b"3")],
  )));
  request.extend_from_slice(&frame(0x1f * 7 + 0x21, b""));
  request.extend_from_slice(&data_frame(b"a"));
  request.extend_from_slice(&frame(PRIORITY_UPDATE, b"\x00u=1"));
  request.extend_from_slice(&data_frame(b"bc"));
  request.extend_from_slice(&headers_frame(&[(b"x-trailer", b"t")]));
  request.extend_from_slice(&frame(0x4242, &[7; 300]));
  let id = send(&mut net, client, &request, true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(handler(&net).seen[0].body, b"abc");
  assert_eq!(server_close(&net, client), None);
}

// Brief step 1 and ruling T13-d: on shutdown the server sends GOAWAY with the first request
// stream that it did not accept, refuses the ones from there on, lets the ones in flight finish
// and then closes with H3_NO_ERROR.
#[cfg_attr(miri, ignore)]
#[test]
fn goaway_on_shutdown_then_drain() {
  let (mut net, client) = connected(H3Params::default(), &TestHandler::new(OK));
  let _ = open_uni(&mut net, client, &control_stream(client_settings()));
  let parked = send(&mut net, client, &headers_frame(&request_fields(b"GET", b"/park", &[])), true);
  net.run();
  assert!(response(&net, client, parked).is_none());
  let now_us = net.now_us;
  let server = &mut net.servers[0];
  server.endpoint.begin_shutdown(now_us, &mut server.app);
  net.run();
  let goaways: Vec<_> =
    server_control_frames(&net, client).into_iter().filter(|el| el.0 == 0x07).collect();
  assert_eq!(goaways, [(0x07, varint(parked.0 + 4))]);
  assert_eq!(server_close(&net, client), None);
  // From the GOAWAY on: refused, the client asked to stop (it is still sending: no FIN)
  let late = send(&mut net, client, &headers_frame(&GET), false);
  net.run();
  assert!(resets(&net, client).contains(&(late.0, 0x10b)));
  assert!(stops(&net, client).contains(&(late.0, 0x10b)));
  assert_eq!(handler(&net).count, 1);
  assert_eq!(server_close(&net, client), None);
  // The request in flight is answered, and then the connection closes
  resume(&mut net, client, parked);
  net.run();
  let rsp = response(&net, client, parked).unwrap();
  assert_eq!((rsp.field(b":status"), rsp.body.as_slice()), (Some(&b"200"[..]), &b"resumed"[..]));
  assert_eq!(server_close(&net, client), Some((true, 0x100)));
  assert_eq!(net.clients[client].conn.state(), ConnState::Draining);
  // Only one GOAWAY was ever sent
  let goaways = server_control_frames(&net, client).into_iter().filter(|el| el.0 == 0x07).count();
  assert_eq!(goaways, 1);
}

// Ruling T13-d: what has not drained when the grace period ends is closed by the endpoint, with
// the shutdown code.
#[cfg_attr(miri, ignore)]
#[test]
fn shutdown_grace_closes_what_did_not_drain() {
  let limits = QuicLimits { shutdown_app_code: 0x0102, ..QuicLimits::default() };
  let quic = QuicParams::default().set_limits(limits);
  let mut net = h3_net(quic, H3Params::default(), &TestHandler::new(OK));
  let client = net.add_client();
  net.run();
  let parked = send(&mut net, client, &headers_frame(&request_fields(b"GET", b"/park", &[])), true);
  net.run();
  let now_us = net.now_us;
  let server = &mut net.servers[0];
  server.endpoint.begin_shutdown(now_us, &mut server.app);
  net.run();
  net.advance(1_999_000);
  net.run();
  assert_eq!(server_close(&net, client), None);
  assert!(response(&net, client, parked).is_none());
  net.advance(1_000);
  net.run();
  assert_eq!(server_close(&net, client), Some((true, 0x0102)));
  // The default application closes at once (ruling T10-b, unchanged): the quic endpoint tests
}

// Brief step 1: a request that the handler parks is answered once resumed; the others go on
// meanwhile.
#[cfg_attr(miri, ignore)]
#[test]
fn parked_request_resumes() {
  let (mut net, client) = connected(H3Params::default(), &TestHandler::new(OK));
  let parked = send(&mut net, client, &headers_frame(&request_fields(b"GET", b"/park", &[])), true);
  net.run();
  assert!(response(&net, client, parked).is_none());
  assert_eq!(handler(&net).parked, [parked]);
  assert_eq!(server_state(&net, client, H3ConnState::live_requests), 1);
  let other = send(&mut net, client, &headers_frame(&GET), true);
  net.run();
  assert_eq!(status(&net, client, other).as_deref(), Some(&b"200"[..]));
  resume(&mut net, client, parked);
  net.run();
  let rsp = response(&net, client, parked).unwrap();
  assert_eq!(rsp.calls.len(), 1);
  assert_eq!((rsp.field(b":status"), rsp.body.as_slice()), (Some(&b"200"[..]), &b"resumed"[..]));
  assert_eq!(handler(&net).resumed, 1);
  assert_eq!(server_state(&net, client, H3ConnState::live_requests), 0);
}

// Brief step 1 and ruling T13-e: with a dynamic table, a client indexes `:authority` and
// `user-agent`; its instructions may arrive cut, a section may arrive before the inserts it needs
// (blocked, then decoded) and repeated sections replay from the memo.
#[cfg_attr(miri, ignore)]
#[test]
fn qpack_dynamic_requests_decode_when_capacity_set() {
  let params =
    H3Params { qpack_max_table_capacity: 4096, qpack_blocked_streams: 100, ..H3Params::default() };
  let (mut net, client) = connected(params, &TestHandler::new(OK));
  let _ = open_uni(&mut net, client, &control_stream(client_settings()));
  let mut encoder = encoder_stream(4096);
  wire::insert_name_ref(&mut encoder, true, AUTHORITY, b"localhost", true);
  wire::insert_name_ref(&mut encoder, true, USER_AGENT, b"h2load nghttp2/1.66.0", false);
  // The second insert arrives in two pieces
  let cut = encoder.len() - 5;
  let enc = open_uni(&mut net, client, &encoder[..cut]);
  net.run();
  write(&mut net, client, enc, &encoder[cut..], false);
  net.run();
  let request = dynamic_request(2, b"/", &[1]);
  let id = send(&mut net, client, &request, true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  let seen = handler(&net).seen[0].clone();
  assert_eq!(seen.authority, b"localhost");
  assert_eq!(seen.fields, [(b"user-agent".to_vec(), b"h2load nghttp2/1.66.0".to_vec())]);
  // The decoder stream of the server: an Insert Count Increment after each piece, then the
  // Section Acknowledgment of the request
  let decoder_out = server_streams(&net, client)[2].1.clone();
  assert_eq!(decoder_out, [0x01, 0x01, 0x80 | u8::try_from(id.0).unwrap()]);
  // A section that needs an insert that did not arrive: blocked, then answered once it does
  let blocked = dynamic_request(3, b"/later", &[1, 2]);
  let id = send(&mut net, client, &blocked, true);
  net.run();
  assert!(response(&net, client, id).is_none());
  assert_eq!(server_state(&net, client, H3ConnState::live_requests), 1);
  let mut more = Vec::new();
  wire::insert_literal(&mut more, b"x-trace", b"abc", false);
  write(&mut net, client, enc, &more, false);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  let seen = handler(&net).seen[1].clone();
  assert_eq!(seen.path, b"/later");
  assert_eq!(seen.fields[1], (b"x-trace".to_vec(), b"abc".to_vec()));
  // Repeated byte for byte: replayed
  let hits = server_state(&net, client, H3ConnState::memo_hits);
  for _ in 0..3 {
    let id = send(&mut net, client, &request, true);
    net.run();
    assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  }
  assert_eq!(server_state(&net, client, H3ConnState::memo_hits), hits + 3);
  assert_eq!(handler(&net).seen[4].fields, handler(&net).seen[0].fields);
  assert_eq!(server_close(&net, client), None);
}

// Brief step 1 (spec section 5.4): once warm, a second round of 64 clients of 64 streams each
// allocates nothing in the server.
#[cfg_attr(miri, ignore)]
#[test]
fn h3_steady_state_allocates_nothing_after_warmup() {
  static OTHERS: AtomicU64 = AtomicU64::new(0);
  static SERVER: AtomicU64 = AtomicU64::new(0);
  const CLIENTS: usize = 64;
  const STREAMS: usize = 64;
  const REQUESTS: usize = 4 * STREAMS;
  let handler = TestHandler { record: false, ..TestHandler::new(OK) };
  let mut net = h3_net(QuicParams::default(), H3Params::default(), &handler);
  net.count((&SERVER, &OTHERS));
  let request = headers_frame(&GET);
  let control = control_stream(client_settings());
  let round = |net: &mut H3Net| {
    let first = net.clients.len();
    for _ in 0..CLIENTS {
      let _ = net.add_client();
    }
    net.run();
    for idx in first..first + CLIENTS {
      assert_eq!(net.clients[idx].conn.state(), ConnState::Confirmed);
      let _ = open_uni(net, idx, &control);
    }
    let done = net.run_requests_from(first, REQUESTS, STREAMS, &request);
    assert_eq!(done, (CLIENTS * REQUESTS) as u64);
    for idx in first..first + CLIENTS {
      let now_us = net.now_us;
      net.clients[idx].conn.close_app(now_us, 0x100);
    }
    net.run();
    net.advance(CLOSING_US);
    assert_eq!(net.servers[0].endpoint.stats().conns, 0);
  };
  round(&mut net);
  let before = SERVER.load(Ordering::Relaxed);
  assert!(before > 0);
  round(&mut net);
  let allocations = SERVER.load(Ordering::Relaxed) - before;
  assert_eq!(allocations, 0, "{allocations} allocations in the second round");
  assert_eq!(net.servers[0].app.handler.count, (2 * CLIENTS * REQUESTS) as u64);
}

// Ruling T13-a: the inline state fits in 160 bytes and a connection with it in 4 KiB; a box that
// comes back from the pool has a new decoder table and an empty memo, so another connection's
// fields never replay.
#[cfg_attr(miri, ignore)]
#[test]
fn pooled_state_is_reset_between_connections() {
  let inline = size_of::<H3ConnState>();
  let conn = size_of::<QuicConn<H3App<TestHandler>, ChaCha20, SkCtx>>();
  assert!(inline <= 160 && conn <= 4096, "{inline} {conn}");
  let mut net = h3_net(QuicParams::default(), dynamic_params(), &TestHandler::new(OK));
  let conn_with = |net: &mut H3Net, value: &[u8]| {
    let client = net.add_client();
    net.run();
    let mut encoder = encoder_stream(4096);
    wire::insert_name_ref(&mut encoder, true, AUTHORITY, b"localhost", false);
    wire::insert_literal(&mut encoder, b"x-token", value, false);
    let _ = open_uni(net, client, &encoder);
    net.run();
    client
  };
  let first = conn_with(&mut net, b"secret-a");
  let request = dynamic_request(2, b"/", &[1]);
  let id = send(&mut net, first, &request, true);
  net.run();
  assert_eq!(status(&net, first, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(handler(&net).seen[0].fields, [(b"x-token".to_vec(), b"secret-a".to_vec())]);
  let now_us = net.now_us;
  net.clients[first].conn.close_app(now_us, 0x100);
  net.run();
  net.advance(CLOSING_US);
  assert_eq!(net.servers[0].app.pooled(), 1);
  // The same bytes on the next connection, which takes the same box
  let second = conn_with(&mut net, b"public-b");
  assert_eq!(net.servers[0].app.pooled(), 0);
  let id = send(&mut net, second, &request, true);
  net.run();
  assert_eq!(status(&net, second, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(handler(&net).seen[1].fields, [(b"x-token".to_vec(), b"public-b".to_vec())]);
  assert_eq!(server_state(&net, second, H3ConnState::memo_hits), 0);
}

// Ruling T13-b: a HEADERS frame cut over STREAM frames is read whole, by retained bytes up to
// 4 KiB and in the head buffer of the request above; a field section over the limit is answered
// with 431 and a body over the limit with 413, the client being asked to stop with H3_NO_ERROR.
#[cfg_attr(miri, ignore)]
#[test]
fn split_heads_and_oversized_requests() {
  let params = H3Params { max_request_body: 1000, ..H3Params::default() };
  let (mut net, client) = connected(params, &TestHandler::new(OK));
  let long = vec![b'v'; 6000];
  let request = headers_frame(&request_fields(b"GET", b"/", &[(b"x-long", &long)]));
  let id = send(&mut net, client, &request[..2500], false);
  net.run();
  write(&mut net, client, id, &request[2500..5000], false);
  net.run();
  write(&mut net, client, id, &request[5000..], true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(handler(&net).seen[0].fields, [(b"x-long".to_vec(), long.clone())]);
  // 16 KiB counted with 32 bytes per field (RFC 9114 section 4.2.2): the pseudo-header fields take
  // 175, `x-edge` 38 and its value the rest
  let at_limit = vec![b'w'; 16_384 - 175 - 38];
  let request = headers_frame(&request_fields(b"GET", b"/", &[(b"x-edge", &at_limit)]));
  let id = send(&mut net, client, &request, true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  let over = vec![b'w'; 16_384 - 175 - 38 + 1];
  let request = headers_frame(&request_fields(b"GET", b"/", &[(b"x-edge", &over)]));
  let id = send(&mut net, client, &request, true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"431"[..]));
  assert!(response(&net, client, id).unwrap().fin);
  assert!(stops(&net, client).contains(&(id.0, 0x100)));
  // A HEADERS frame whose payload alone is over the limit: 431 before anything is decoded
  let huge = vec![b'h'; 20_000];
  let id = send(
    &mut net,
    client,
    &headers_frame(&request_fields(b"GET", b"/", &[(b"x-huge", &huge)])),
    true,
  );
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"431"[..]));
  // A content-length over the limit: 413 at once; a body that goes past it without one: 413
  let mut request = headers_frame(&request_fields(b"POST", b"/", &[(b"content-length", b"2000")]));
  request.extend_from_slice(&data_frame(&[1; 2000]));
  let id = send(&mut net, client, &request, true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"413"[..]));
  assert!(stops(&net, client).contains(&(id.0, 0x100)));
  let mut request = headers_frame(&request_fields(b"POST", b"/", &[]));
  request.extend_from_slice(&data_frame(&[1; 600]));
  request.extend_from_slice(&data_frame(&[2; 600]));
  let id = send(&mut net, client, &request, true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"413"[..]));
  assert_eq!(handler(&net).count, 2);
  // The connection serves on, and keeps nothing of them
  let id = send(&mut net, client, &headers_frame(&GET), true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(server_state(&net, client, H3ConnState::live_requests), 0);
  assert_eq!(server_close(&net, client), None);
}

// Ruling T13-b: the RESET_STREAM that answers the STOP_SENDING of a 413 or 431 does not reset the
// answer, whose FIN may not be acknowledged yet: here it is lost, and sent again.
#[cfg_attr(miri, ignore)]
#[test]
fn refusal_is_not_cut_by_the_reset_that_answers_it() {
  let params = H3Params { max_request_body: 1000, ..H3Params::default() };
  let (mut net, client) = connected(params, &TestHandler::new(OK));
  let head = headers_frame(&request_fields(b"POST", b"/", &[(b"content-length", b"2000")]));
  let id = send(&mut net, client, &head, false);
  for mut datagram in net.client_datagrams(client) {
    let _ = net.deliver_to_server(client, &mut datagram);
  }
  // The 413 and the STOP_SENDING are lost; the client resets its request meanwhile
  assert!(!net.server_datagrams(0).is_empty());
  let final_size = u64::try_from(head.len()).unwrap();
  let reset_frame = Frame::ResetStream { id: id.0, code: 0x10c, final_size };
  net.clients[client].conn.queue_test_frames(&encode_frames(&[reset_frame]));
  for mut datagram in net.client_datagrams(client) {
    let _ = net.deliver_to_server(client, &mut datagram);
  }
  net.run();
  for _ in 0..16 {
    if response(&net, client, id).is_some_and(|el| el.fin) {
      break;
    }
    assert!(net.advance_to_next_event());
    net.run();
  }
  assert!(!resets(&net, client).iter().any(|el| el.0 == id.0), "{:?}", resets(&net, client));
  let rsp = response(&net, client, id).unwrap();
  assert_eq!(rsp.field(b":status"), Some(&b"413"[..]));
  assert!(rsp.fin);
  assert_eq!(server_close(&net, client), None);
}

// Ruling T13-b and review focus 4: a POST larger than the stream window, from a client that never
// sends DATA_BLOCKED, completes: credit comes back as the body is read.
#[cfg_attr(miri, ignore)]
#[test]
fn post_larger_than_stream_window_completes_without_blocked_frames() {
  let params = H3Params { max_request_body: 2 << 20, ..H3Params::default() };
  let (mut net, client) = connected(params, &TestHandler::new(OK));
  net.clients[client].conn.streams_mut().never_send_blocked_frames();
  let body: Vec<u8> = (0..(3 << 19) as u32).map(|el| (el % 253) as u8).collect();
  let len = format!("{}", body.len());
  let mut request =
    headers_frame(&request_fields(b"POST", b"/big", &[(b"content-length", len.as_bytes())]));
  request.extend_from_slice(&data_frame(&body));
  let id = send(&mut net, client, &request, true);
  net.run_for(8192);
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  assert!(handler(&net).seen[0].body == body);
  assert_eq!(net.clients[client].conn.streams().blocked_frames_sent(), 0);
}

// Ruling T13-c: the decoder stream output of a turn leaves in one write, at the flush; the budget
// of encoder instructions is a turn's, renewed at each flush.
#[cfg_attr(miri, ignore)]
#[test]
fn decoder_stream_written_once_per_flush_and_budget_per_turn() {
  let (mut net, client) = connected(dynamic_params(), &TestHandler::new(OK));
  let mut encoder = encoder_stream(4096);
  wire::insert_name_ref(&mut encoder, true, AUTHORITY, b"localhost", false);
  let enc = open_uni(&mut net, client, &encoder);
  net.run();
  let decoder_id = 11;
  let calls = net.clients[client].app.streams[&decoder_id].calls.len();
  let request = dynamic_request(1, b"/", &[]);
  // Ten requests in one flush of the client, read in one turn of the server
  let ids: Vec<StreamId> = (0..10).map(|_| send(&mut net, client, &request, true)).collect();
  net.run();
  assert!(ids.iter().all(|id| status(&net, client, *id).as_deref() == Some(&b"200"[..])));
  let log = &net.clients[client].app.streams[&decoder_id];
  assert_eq!(log.calls.len(), calls + 1, "{:?}", log.calls);
  assert_eq!(log.calls.last().unwrap().0, 10);
  // 2 * 4096 / 32 + 64 = 320 instructions a turn
  let batch = |count: usize| {
    let mut out = Vec::new();
    for _ in 0..count {
      wire::insert_name_ref(&mut out, true, AUTHORITY, b"localhost", false);
    }
    out
  };
  write(&mut net, client, enc, &batch(300), false);
  net.run();
  write(&mut net, client, enc, &batch(300), false);
  net.run();
  assert_eq!(server_close(&net, client), None);
  write(&mut net, client, enc, &batch(400), false);
  net.run();
  assert_eq!(server_close(&net, client), Some((true, 0x107)));
}

// Ruling T13-e: an encoder instruction longer than what is retained is kept whole; a request
// stream that is reset while its section is blocked is cancelled on the decoder stream; with no
// dynamic table, an insert is an encoder stream error.
#[cfg_attr(miri, ignore)]
#[test]
fn qpack_obligations() {
  let params = H3Params { qpack_max_table_capacity: 16_384, ..dynamic_params() };
  let (mut net, client) = connected(params, &TestHandler::new(OK));
  let long = vec![b'z'; 6000];
  let mut encoder = encoder_stream(16_384);
  wire::insert_name_ref(&mut encoder, true, AUTHORITY, b"localhost", false);
  wire::insert_literal(&mut encoder, b"x-long", &long, false);
  let enc = open_uni(&mut net, client, &encoder[..2000]);
  net.run();
  for range in [2000..4000, 4000..encoder.len()] {
    write(&mut net, client, enc, &encoder[range], false);
    net.run();
  }
  // 16,384 / 32 = 512 entries: the encoded Required Insert Count wraps at 1,024
  let mut section = Vec::new();
  wire::prefix(&mut section, 2, 2, 512);
  wire::indexed(&mut section, true, METHOD_GET);
  wire::indexed(&mut section, true, SCHEME_HTTPS);
  wire::indexed(&mut section, false, 1);
  wire::indexed(&mut section, true, PATH_ROOT);
  wire::indexed(&mut section, false, 0);
  let id = send(&mut net, client, &frame(0x01, &section), true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(handler(&net).seen[0].fields, [(b"x-long".to_vec(), long)]);
  // Blocked, then reset by the client: a Stream Cancellation, and nothing kept
  let mut section = Vec::new();
  wire::prefix(&mut section, 3, 3, 512);
  wire::indexed(&mut section, true, METHOD_GET);
  wire::indexed(&mut section, false, 0);
  let blocked = send(&mut net, client, &frame(0x01, &section), false);
  net.run();
  assert_eq!(server_state(&net, client, H3ConnState::live_requests), 1);
  reset(&mut net, client, blocked, 0x10c);
  net.run();
  assert_eq!(server_state(&net, client, H3ConnState::live_requests), 0);
  let decoder_out = server_streams(&net, client)[2].1.clone();
  assert_eq!(decoder_out.last(), Some(&(0x40 | u8::try_from(blocked.0).unwrap())));
  assert!(resets(&net, client).contains(&(blocked.0, 0x10c)));
  assert_eq!(server_close(&net, client), None);
  // No dynamic table: an insert is an error of the encoder stream
  let (mut net, client) = connected(H3Params::default(), &TestHandler::new(OK));
  let mut encoder = vec![0x02];
  wire::insert_name_ref(&mut encoder, true, AUTHORITY, b"localhost", false);
  let _ = open_uni(&mut net, client, &encoder);
  net.run();
  assert_eq!(server_close(&net, client), Some((true, 0x201)));
}

// Ruling T13-f: what RFC 9114 makes a connection error closes the connection with its code.
#[cfg_attr(miri, ignore)]
#[test]
fn connection_errors_of_rfc_9114() {
  type Case = (&'static str, u64, fn(&mut H3Net, usize));
  let cases: [Case; 18] = [
    ("second control stream", 0x103, |net, c| {
      let _ = open_uni(net, c, &control_stream(client_settings()));
      net.run();
      let _ = open_uni(net, c, &control_stream(client_settings()));
    }),
    ("control stream without SETTINGS first", 0x10a, |net, c| {
      let _ = open_uni(net, c, &[&[0x00][..], &frame(0x07, &varint(0))].concat());
    }),
    ("second SETTINGS", 0x105, |net, c| {
      let settings = control_stream(client_settings());
      let _ = open_uni(net, c, &[&settings[..], &settings[1..]].concat());
    }),
    ("DATA on the control stream", 0x105, |net, c| {
      let _ =
        open_uni(net, c, &[&control_stream(client_settings())[..], &data_frame(b"x")].concat());
    }),
    ("HTTP/2 frame type on the control stream", 0x105, |net, c| {
      let _ =
        open_uni(net, c, &[&control_stream(client_settings())[..], &frame(0x06, b"")].concat());
    }),
    ("push stream of a client", 0x103, |net, c| {
      let _ = open_uni(net, c, &[0x01, 0x00]);
    }),
    ("second encoder stream", 0x103, |net, c| {
      let _ = open_uni(net, c, &[0x02]);
      net.run();
      let _ = open_uni(net, c, &[0x02]);
    }),
    ("DATA before HEADERS", 0x105, |net, c| {
      let _ = send(net, c, &[&data_frame(b"x")[..], &headers_frame(&GET)].concat(), true);
    }),
    ("SETTINGS on a request stream", 0x105, |net, c| {
      let _ = send(net, c, &[&headers_frame(&GET)[..], &frame(0x04, b"")].concat(), true);
    }),
    ("HTTP/2 frame type on a request stream", 0x105, |net, c| {
      let _ = send(net, c, &[&frame(0x02, b"")[..], &headers_frame(&GET)].concat(), true);
    }),
    ("DATA after the trailers", 0x105, |net, c| {
      let request = [
        &headers_frame(&request_fields(b"POST", b"/", &[]))[..],
        &headers_frame(&[(b"x-t", b"1")]),
        &data_frame(b"x"),
      ]
      .concat();
      let _ = send(net, c, &request, true);
    }),
    ("frame cut by the FIN", 0x106, |net, c| {
      let _ = send(net, c, &headers_frame(&GET)[..5], true);
    }),
    ("CANCEL_PUSH without MAX_PUSH_ID", 0x108, |net, c| {
      let _ = open_uni(
        net,
        c,
        &[&control_stream(client_settings())[..], &frame(0x03, &varint(0))].concat(),
      );
    }),
    ("MAX_PUSH_ID lowered", 0x108, |net, c| {
      let frames = [&frame(0x0d, &varint(5))[..], &frame(0x0d, &varint(3))].concat();
      let _ = open_uni(net, c, &[&control_stream(client_settings())[..], &frames].concat());
    }),
    ("encoder stream finished", 0x104, |net, c| {
      let id = open_uni(net, c, &[0x02]);
      net.run();
      write(net, c, id, b"", true);
    }),
    ("decoder stream reset", 0x104, |net, c| {
      let id = open_uni(net, c, &[0x03]);
      net.run();
      reset(net, c, id, 0x10c);
    }),
    ("STOP_SENDING on the control stream of the server", 0x104, |net, c| {
      stop_sending(net, c, StreamId(3), 0x100);
    }),
    ("Section Acknowledgment of a static-only encoder", 0x202, |net, c| {
      let _ = open_uni(net, c, &[0x03, 0x80]);
    }),
  ];
  for (name, code, case) in cases {
    let (mut net, client) = connected(H3Params::default(), &TestHandler::new(OK));
    case(&mut net, client);
    net.run();
    assert_eq!(server_close(&net, client), Some((true, code)), "{name}");
  }
}

// Ruling T13-f: unknown frames, settings and stream types, PRIORITY_UPDATE and the push frames of
// a client that allows pushes are ignored; a request that ends without a head is incomplete.
#[cfg_attr(miri, ignore)]
#[test]
fn unknown_and_ignored_elements() {
  let (mut net, client) = connected(H3Params::default(), &TestHandler::new(OK));
  // SETTINGS with unknown identifiers (0x21 is GREASE, 0x33 H3_DATAGRAM)
  let mut control = vec![0x00];
  control.extend_from_slice(&frame(0x04, &[0x01, 0x00, 0x21, 0x05, 0x33, 0x01]));
  for elem in [
    frame(PRIORITY_UPDATE, b"\x00u=1"),
    frame(0x21, b""),
    frame(0x0d, &varint(10)),
    frame(0x03, &varint(3)),
    frame(0x07, &varint(8)),
    frame(0x7fff, &[0; 5000]),
  ] {
    control.extend_from_slice(&elem);
  }
  let _ = open_uni(&mut net, client, &control);
  let unknown = open_uni(&mut net, client, &[0x21, 1, 2, 3]);
  net.run();
  assert!(stops(&net, client).contains(&(unknown.0, 0x103)));
  let settings = server_state(&net, client, H3ConnState::peer_settings);
  assert_eq!(settings, Some(client_settings()));
  let id = send(&mut net, client, &frame(0x21, b"x"), true);
  net.run();
  assert!(resets(&net, client).contains(&(id.0, 0x10d)));
  let id = send(&mut net, client, &headers_frame(&GET), true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(server_close(&net, client), None);
}

// A POST of `path` that announces `len` bytes of body, with `body`.
fn post(path: &[u8], len: usize, body: &[u8]) -> Vec<u8> {
  let len = format!("{len}");
  let mut request =
    headers_frame(&request_fields(b"POST", path, &[(b"content-length", len.as_bytes())]));
  if !body.is_empty() {
    request.extend_from_slice(&data_frame(body));
  }
  request
}

fn buffered(net: &H3Net, client: usize) -> usize {
  server_state(net, client, H3ConnState::buffered)
}

// Fix V1 (ruling T13-g): the request buffers of a connection hold at most
// `max_buffered_body_per_conn`: a request that would take more is answered with 413, the others go
// on.
#[cfg_attr(miri, ignore)]
#[test]
fn buffered_requests_are_capped_per_connection() {
  const CAP: usize = 1_000_000;
  let params = H3Params {
    max_buffered_body_per_conn: CAP as u32,
    max_request_body: 600_000,
    ..H3Params::default()
  };
  let (mut net, client) = connected(params, &TestHandler::new(OK));
  let body: Vec<u8> = (0..400_000u32).map(|el| (el % 249) as u8).collect();
  let first = send(&mut net, client, &post(b"/a", body.len(), &body), false);
  net.run_for(1024);
  assert!(buffered(&net, client) <= CAP);
  let second = send(&mut net, client, &post(b"/b", body.len(), &body), false);
  net.run_for(1024);
  assert!(buffered(&net, client) <= CAP, "{}", buffered(&net, client));
  let third = send(&mut net, client, &post(b"/c", body.len(), &body), false);
  net.run_for(1024);
  assert!(buffered(&net, client) <= CAP, "{}", buffered(&net, client));
  assert_eq!(status(&net, client, third).as_deref(), Some(&b"413"[..]));
  assert!(response(&net, client, first).is_none() && response(&net, client, second).is_none());
  for id in [first, second] {
    write(&mut net, client, id, b"", true);
  }
  net.run();
  assert_eq!(status(&net, client, first).as_deref(), Some(&b"200"[..]));
  assert_eq!(status(&net, client, second).as_deref(), Some(&b"200"[..]));
  assert!(handler(&net).seen.iter().all(|el| el.body == body));
  assert_eq!(handler(&net).count, 2);
  // What they held is given back: only small buffers stay
  assert!(buffered(&net, client) <= 64 * 1024, "{}", buffered(&net, client));
  let id = send(&mut net, client, &headers_frame(&GET), true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(server_close(&net, client), None);
}

// Fix V1: requests that never finish and the buffers that finished requests leave can not make the
// connection hold more than the cap; what finished requests leave is freed for a large request.
#[cfg_attr(miri, ignore)]
#[test]
fn unfinished_and_finished_requests_cannot_pin_more_than_the_cap() {
  const CAP: usize = 1_000_000;
  let params = H3Params {
    max_buffered_body_per_conn: CAP as u32,
    max_request_body: 600_000,
    ..H3Params::default()
  };
  let (mut net, client) = connected(params, &TestHandler::new(OK));
  let large: Vec<u8> = vec![7; 300_000];
  for _ in 0..2 {
    let id = send(&mut net, client, &post(b"/done", large.len(), &large), true);
    net.run_for(1024);
    assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  }
  // Fifty requests that never finish (no FIN), with 15,000 bytes of body each
  let small = vec![3; 15_000];
  let pending: Vec<StreamId> =
    (0..50).map(|_| send(&mut net, client, &post(b"/slow", small.len(), &small), false)).collect();
  net.run_for(1024);
  assert!(buffered(&net, client) <= CAP, "{}", buffered(&net, client));
  assert!(pending.iter().all(|id| response(&net, client, *id).is_none()));
  let id = send(&mut net, client, &post(b"/big", large.len(), &large), true);
  net.run_for(1024);
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"413"[..]));
  assert!(buffered(&net, client) <= CAP);
  // Once they are abandoned, what they leave makes room again
  for id in &pending {
    reset(&mut net, client, *id, 0x10c);
  }
  net.run();
  assert_eq!(server_state(&net, client, H3ConnState::live_requests), 0);
  let id = send(&mut net, client, &post(b"/big", large.len(), &large), true);
  net.run_for(1024);
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  assert!(buffered(&net, client) <= CAP);
  assert_eq!(server_close(&net, client), None);
}

// Fix V2 (ruling T13-h): a graceful close waits until the last response is acknowledged: lost, it
// is sent again first.
#[cfg_attr(miri, ignore)]
#[test]
fn graceful_close_waits_for_the_last_response_to_be_acknowledged() {
  let (mut net, client) = connected(H3Params::default(), &TestHandler::new(OK));
  let parked = send(&mut net, client, &headers_frame(&request_fields(b"GET", b"/park", &[])), true);
  net.run();
  let now_us = net.now_us;
  let server = &mut net.servers[0];
  server.endpoint.begin_shutdown(now_us, &mut server.app);
  net.run();
  resume(&mut net, client, parked);
  // The datagram with the response is lost
  net.clients[client].deaf = true;
  let _ = net.step();
  net.clients[client].deaf = false;
  assert!(response(&net, client, parked).is_none());
  for _ in 0..32 {
    if server_close(&net, client).is_some() {
      break;
    }
    assert!(net.advance_to_next_event());
    net.run();
  }
  let rsp = response(&net, client, parked).unwrap();
  assert_eq!((rsp.fin, rsp.body.as_slice()), (true, &b"resumed"[..]));
  assert_eq!(server_close(&net, client), Some((true, 0x100)));
}

// Fix V2 (ruling T13-h): the GOAWAY covers the streams that QUIC opened, and those that brought no
// request by the time the others are answered are refused with H3_REQUEST_REJECTED before the
// close, never dropped: one opened by a later one, one whose data waits for its start.
#[cfg_attr(miri, ignore)]
#[test]
fn graceful_close_refuses_the_streams_it_never_read() {
  let (mut net, client) = connected(H3Params::default(), &TestHandler::new(OK));
  let now_us = net.now_us;
  let (implicit, answered, waiting) = net
    .client_ctx(client, now_us, |cx| {
      let implicit = cx.open_bidi()?;
      let answered = cx.open_bidi()?;
      cx.write(answered, &headers_frame(&GET), true)?;
      let waiting = cx.open_bidi()?;
      Ok::<_, crate::Error>((implicit, answered, waiting))
    })
    .unwrap();
  net.run();
  // The start of the third request is lost; what follows arrives and waits for it
  let request = headers_frame(&GET);
  write(&mut net, client, waiting, &request[..5], false);
  let _lost = net.client_datagrams(client);
  write(&mut net, client, waiting, &request[5..], false);
  net.run();
  assert!(response(&net, client, waiting).is_none());
  assert_eq!(status(&net, client, answered).as_deref(), Some(&b"200"[..]));
  let now_us = net.now_us;
  let server = &mut net.servers[0];
  server.endpoint.begin_shutdown(now_us, &mut server.app);
  net.run();
  let goaways: Vec<_> =
    server_control_frames(&net, client).into_iter().filter(|el| el.0 == 0x07).collect();
  assert_eq!(goaways, [(0x07, varint(waiting.0 + 4))]);
  let resets = resets(&net, client);
  assert!(resets.contains(&(implicit.0, 0x10b)), "{resets:?}");
  assert!(resets.contains(&(waiting.0, 0x10b)), "{resets:?}");
  assert_eq!(server_close(&net, client), Some((true, 0x100)));
}

// Fix V3: decoder-stream output is written while the stream has little unsent, so a client that
// never gives credit on our decoder stream meets the bound of the decoder (H3_EXCESSIVE_LOAD)
// instead of growing the memory of the server.
#[cfg_attr(miri, ignore)]
#[test]
fn decoder_stream_output_without_credit_is_bounded() {
  let mut net = h3_net(QuicParams::default(), dynamic_params(), &TestHandler::new(OK));
  net.client_params.stream_window = 256;
  let client = net.add_client();
  // The server's decoder stream: its third unidirectional stream
  net.clients[client].app.hold = Some(11);
  net.run();
  let mut encoder = encoder_stream(4096);
  wire::insert_name_ref(&mut encoder, true, AUTHORITY, b"localhost", false);
  let _ = open_uni(&mut net, client, &encoder);
  net.run();
  let request = dynamic_request(1, b"/", &[]);
  let mut sent = 0;
  while server_close(&net, client).is_none() && sent < 12_000 {
    for _ in 0..64 {
      let _ = send(&mut net, client, &request, true);
      sent += 1;
    }
    net.run();
    let logs = &mut net.clients[client].app.streams;
    logs.retain(|id, log| !(log.fin && *id & 0b11 == 0));
  }
  assert_eq!(server_close(&net, client), Some((true, 0x107)), "{sent} requests");
}

// Fix V4: an entry keeps small buffers only once its request is done, a pooled box too, the pool
// has a byte budget, an idle trim frees it down, and the response buffer stays small.
#[cfg_attr(miri, ignore)]
#[test]
fn request_buffers_and_the_pool_stay_small() {
  let params = H3Params { max_request_body: 2 << 20, ..H3Params::default() };
  let mut net = h3_net(QuicParams::default(), params, &TestHandler::new(&[9; 100_000]));
  let mut clients = Vec::new();
  for _ in 0..6 {
    let client = net.add_client();
    net.run();
    let body = vec![5; 500_000];
    let id = send(&mut net, client, &post(b"/up", body.len(), &body), true);
    net.run_for(1024);
    assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
    let long = vec![b'v'; 10_000];
    let request = headers_frame(&request_fields(b"GET", b"/", &[(b"x-long", &long)]));
    let id = send(&mut net, client, &request, true);
    net.run_for(1024);
    assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
    assert!(buffered(&net, client) <= 32 * 1024, "{}", buffered(&net, client));
    clients.push(client);
  }
  // The responses of 100,000 bytes went through the response buffer, which stays small
  assert!(net.servers[0].app.scratch_bytes() <= 32 * 1024);
  for client in clients {
    let now_us = net.now_us;
    net.clients[client].conn.close_app(now_us, 0x100);
  }
  net.run();
  net.advance(CLOSING_US);
  let app = &net.servers[0].app;
  assert_eq!(app.pooled(), 6);
  assert!(app.pooled_bytes() <= 6 * 64 * 1024, "{}", app.pooled_bytes());
  assert!(app.pooled_bytes() <= H3App::<TestHandler>::POOL_BYTES);
  net.servers[0].app.trim_idle();
  let app = &net.servers[0].app;
  assert!(app.pooled() <= H3App::<TestHandler>::IDLE_POOLED, "{}", app.pooled());
  assert!(app.pooled_bytes() <= 2 << 20);
  assert!(app.scratch_bytes() == 0);
}

// Fix V5: a box that goes back to the pool holds no state of its connection: no dynamic table
// entry, no kept section, no request.
#[cfg_attr(miri, ignore)]
#[test]
fn pooled_box_holds_no_request_state() {
  let (mut net, client) = connected(dynamic_params(), &TestHandler::new(OK));
  let mut encoder = encoder_stream(4096);
  wire::insert_name_ref(&mut encoder, true, AUTHORITY, b"localhost", false);
  let _ = open_uni(&mut net, client, &encoder);
  net.run();
  let id = send(&mut net, client, &dynamic_request(1, b"/", &[]), true);
  let _parked =
    send(&mut net, client, &headers_frame(&request_fields(b"GET", b"/park", &[])), true);
  let _unfinished = send(&mut net, client, &post(b"/slow", 100, &[1; 10]), false);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(server_state(&net, client, H3ConnState::live_requests), 2);
  let now_us = net.now_us;
  net.clients[client].conn.close_app(now_us, 0x100);
  net.run();
  net.advance(CLOSING_US);
  assert_eq!(net.servers[0].app.pooled(), 1);
  assert!(net.servers[0].app.pool_is_clear());
}

// Fix V6: RFC 9114 sections 4.2 and 4.3.1: fields of a connection, `content-length` that
// disagrees with itself, `host` twice or against `:authority`, userinfo in `host` or
// `:authority`: all stream errors H3_MESSAGE_ERROR.
#[cfg_attr(miri, ignore)]
#[test]
fn authority_host_and_connection_fields_are_message_errors() {
  let (mut net, client) = connected(H3Params::default(), &TestHandler::new(OK));
  let get = |extra: &[(&[u8], &[u8])]| headers_frame(&request_fields(b"GET", b"/", extra));
  let cases: Vec<Vec<u8>> = vec![
    get(&[(b"keep-alive", b"timeout=5")]),
    get(&[(b"proxy-connection", b"keep-alive")]),
    get(&[(b"upgrade", b"websocket")]),
    get(&[(b"content-length", b"5"), (b"content-length", b"6")]),
    get(&[(b"host", b"localhost"), (b"host", b"localhost")]),
    get(&[(b"host", b"other")]),
    get(&[(b"host", b"user@localhost")]),
    headers_frame(&[
      (b":method", b"GET"),
      (b":scheme", b"http"),
      (b":path", b"/"),
      (b"host", b"u@h"),
    ]),
    headers_frame(&[(b":method", b"CONNECT"), (b":authority", b"user@localhost:443")]),
  ];
  for (nth, case) in cases.iter().enumerate() {
    let id = send(&mut net, client, case, true);
    net.run();
    assert!(resets(&net, client).contains(&(id.0, 0x10e)), "case {nth}");
  }
  assert_eq!(handler(&net).count, 0);
  // The same fields well formed are answered
  let id =
    send(&mut net, client, &get(&[(b"host", b"localhost"), (b"content-length", b"0")]), true);
  net.run();
  assert_eq!(status(&net, client, id).as_deref(), Some(&b"200"[..]));
  assert_eq!(server_close(&net, client), None);
}

// The packet types of the packets of a datagram to the server.
fn packet_types(datagram: &[u8]) -> Vec<PacketTy> {
  let mut rslt = Vec::new();
  let mut rest = datagram;
  while let Ok(header) = parse_header(rest, 8) {
    rslt.push(header.ty);
    rest = &rest[header.packet_end..];
    if rest.is_empty() {
      break;
    }
  }
  rslt
}

// Fix V7 (review focus 1): the client's Finished and its first request, coalesced in one
// datagram, are served in that turn: the handler runs on that datagram and the next flush of the
// server carries the response.
#[cfg_attr(miri, ignore)]
#[test]
fn first_request_coalesced_with_finished_is_answered_in_that_turn() {
  let mut net = h3_net(QuicParams::default(), H3Params::default(), &TestHandler::new(OK));
  let client = net.add_client();
  for mut datagram in net.client_datagrams(client) {
    let _ = net.deliver_to_server(client, &mut datagram);
  }
  for (_, mut datagram) in net.server_datagrams(0) {
    net.deliver_to_client(client, &mut datagram);
  }
  let id = send(&mut net, client, &headers_frame(&GET), true);
  let mut datagrams = net.client_datagrams(client);
  let idx = datagrams
    .iter()
    .position(|el| {
      let types = packet_types(el);
      types.contains(&PacketTy::Handshake) && types.last() == Some(&PacketTy::OneRtt)
    })
    .unwrap();
  for datagram in &mut datagrams[..=idx] {
    assert_eq!(handler(&net).count, 0);
    let _ = net.deliver_to_server(client, datagram);
  }
  assert_eq!(handler(&net).count, 1);
  for (_, mut datagram) in net.server_datagrams(0) {
    net.deliver_to_client(client, &mut datagram);
  }
  let rsp = response(&net, client, id).unwrap();
  assert_eq!((rsp.field(b":status"), rsp.fin), (Some(&b"200"[..]), true));
}
