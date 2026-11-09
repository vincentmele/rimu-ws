use crate::{
  quic::{
    Cid, ConnState, DatagramMeta, Frame, PacketTy, QuicLimits, QuicParams, RecvOutcome,
    cid_table::FORWARDED_TTL_US,
    parse_header,
    testing::{Behavior, Net, NetRoute, TestApp, encode_frames},
    token::RETRY_TOKEN_LIFETIME_US,
  },
  sync::AtomicU64,
};
use alloc::{vec, vec::Vec};
use core::{
  net::{IpAddr, Ipv4Addr, SocketAddr},
  sync::atomic::Ordering,
};

const RESPONSE: &[u8] = b"ok";
// A PTO of the initial RTT, three times: the closing period
const CLOSING_US: u64 = 3 * (333_000 + 4 * 166_500 + 25_000);

fn net(workers: u8, params: QuicParams) -> Net {
  Net::new(workers, params, &TestApp::new(Behavior::Respond(RESPONSE)))
}

fn limits(f: impl FnOnce(&mut QuicLimits)) -> QuicParams {
  let mut limits = QuicLimits::default();
  f(&mut limits);
  QuicParams::default().set_limits(limits)
}

// The address of a peer that no client of a net has.
fn stranger(port: u16) -> DatagramMeta {
  let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port);
  DatagramMeta { peer, local: None, segment_size: None }
}

// The CID that the client sends to, the one of the server once the handshake started.
fn server_cid(net: &Net, client: usize) -> Vec<u8> {
  net.clients[client].conn.peer_cid().as_slice().to_vec()
}

fn confirmed(net: &Net, client: usize) -> bool {
  net.clients[client].conn.state() == ConnState::Confirmed
}

// A long header packet of an unknown version, padded to `len` bytes.
fn unknown_version(len: usize) -> Vec<u8> {
  let mut datagram = vec![0; len];
  datagram[..5].copy_from_slice(&[0xc0, 0x1a, 0x2a, 0x3a, 0x4a]);
  datagram[5] = 8;
  datagram[6..14].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
  datagram[14] = 4;
  datagram[15..19].copy_from_slice(&[9, 9, 9, 9]);
  datagram
}

// A short header packet to `dcid` of `len` bytes, of random-looking bytes.
fn short_packet(dcid: &[u8], len: usize) -> Vec<u8> {
  let mut datagram: Vec<u8> =
    (0..len).map(|el| u8::try_from(el % 256).unwrap().wrapping_mul(31).wrapping_add(7)).collect();
  datagram[0] = 0x43;
  datagram[1..1 + dcid.len()].copy_from_slice(dcid);
  datagram
}

// Clients whose first flight reached the server but who hear nothing back: their handshakes stay
// open.
fn stalled_clients(net: &mut Net, count: usize) -> Vec<usize> {
  let clients: Vec<usize> = (0..count).map(|_| net.add_client()).collect();
  for &idx in &clients {
    net.clients[idx].deaf = true;
  }
  net.run();
  for &idx in &clients {
    // Nothing more from them
    net.clients[idx].mute = true;
  }
  clients
}

// Rule (spec section 5.2): one endpoint serves many clients, each with many requests at once.
#[cfg_attr(miri, ignore)]
#[test]
fn endpoint_serves_many_clients() {
  let mut net = net(1, QuicParams::default());
  for _ in 0..64 {
    let _ = net.add_client();
  }
  net.run();
  assert!((0..64).all(|el| confirmed(&net, el)));
  assert_eq!(net.run_requests(64, 64, b"GET /"), 64 * 64);
  let stats = net.servers[0].endpoint.stats();
  assert_eq!((stats.conns, stats.half_open), (64, 0));
  assert_eq!(net.servers[0].endpoint.our_cids(), 64);
  assert!(stats.datagrams_in > 0 && stats.datagrams_out > 0 && stats.packets_out > 0);
  assert_eq!(net.loads.load(0), 64);
}

// Rule (RFC 9000 sections 6.1 and 14.1, ruling T10-f): a long header of an unknown version in a
// datagram of 1200 bytes or more gets a Version Negotiation packet, rate-limited; a shorter one,
// or one of version 1, gets nothing.
#[cfg_attr(miri, ignore)]
#[test]
fn unknown_version_gets_version_negotiation() {
  let mut net = net(1, limits(|el| el.stateless_reset_per_sec = 3));
  let _ = net.deliver_meta(&mut unknown_version(1199), stranger(1));
  assert!(net.server_datagrams(0).is_empty());
  let _ = net.deliver_meta(&mut unknown_version(1200), stranger(1));
  let out = net.server_datagrams(0);
  assert_eq!(out.len(), 1);
  let (peer, vn) = &out[0];
  assert_eq!(*peer, stranger(1).peer);
  let header = parse_header(vn, 8).unwrap();
  assert_eq!(header.ty, PacketTy::VersionNegotiation);
  // The CIDs swapped, version 1 offered
  assert_eq!((header.dcid, header.scid), (&[9, 9, 9, 9][..], &[1, 2, 3, 4, 5, 6, 7, 8][..]));
  assert_eq!(&vn[vn.len() - 4..], &[0, 0, 0, 1]);
  // A version 1 Initial, even undecryptable, never gets one
  let mut v1 = unknown_version(1200);
  v1[1..5].copy_from_slice(&[0, 0, 0, 1]);
  let _ = net.deliver_meta(&mut v1, stranger(1));
  assert!(net.server_datagrams(0).is_empty());
  // Rate-limited: two more in this second, then none
  for _ in 0..5 {
    let _ = net.deliver_meta(&mut unknown_version(1300), stranger(2));
  }
  assert_eq!(net.server_datagrams(0).len(), 2);
  net.advance(1_000_000);
  let _ = net.deliver_meta(&mut unknown_version(1300), stranger(2));
  assert_eq!(net.server_datagrams(0).len(), 1);
}

// Rule (RFC 9000 section 10.3, ruling T10-g): a short header packet for an unknown CID of this
// worker, in a datagram of at least 41 bytes, gets a stateless reset: shorter than the datagram,
// at most 40 bytes so that it never makes another one, random but for its fixed bits and the
// token of the CID, rate-limited. The token is the one of the transport parameters of a
// connection with that CID.
#[cfg_attr(miri, ignore)]
#[test]
fn unknown_short_cid_gets_stateless_reset_rate_limited() {
  let mut net = net(1, limits(|el| el.stateless_reset_per_sec = 4));
  let cid = [0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7];
  let token = net.keys.reset_token(&cid).unwrap();
  let _ = net.deliver_meta(&mut short_packet(&cid, 40), stranger(1));
  assert!(net.server_datagrams(0).is_empty());
  let mut resets = Vec::new();
  for len in [41, 43, 100] {
    let _ = net.deliver_meta(&mut short_packet(&cid, len), stranger(1));
    let out = net.server_datagrams(0);
    assert_eq!(out.len(), 1, "{len}");
    let reset = out[0].1.clone();
    assert!(reset.len() < len && reset.len() <= 40 && reset.len() >= 21, "{len}: {}", reset.len());
    assert_eq!(reset[0] & 0xc0, 0x40);
    assert_eq!(&reset[reset.len() - 16..], &token);
    resets.push(reset);
  }
  // Random bytes: two resets of the same size differ but for the token
  let random = resets[1].len() - 16;
  assert_ne!(resets[1][1..random], resets[2][1..random]);
  assert_eq!(net.servers[0].endpoint.stats().resets, 3);
  // The budget of the second is spent after one more
  for _ in 0..3 {
    let _ = net.deliver_meta(&mut short_packet(&cid, 100), stranger(1));
  }
  assert_eq!(net.server_datagrams(0).len(), 1);
  net.advance(1_000_000);
  let _ = net.deliver_meta(&mut short_packet(&cid, 100), stranger(1));
  assert_eq!(net.server_datagrams(0).len(), 1);
  // A connection advertises the token of its CID
  let client = net.add_client();
  net.run();
  let cid = server_cid(&net, client);
  let advertised = net.clients[client].conn.test_client().unwrap().peer_reset_token;
  assert_eq!(advertised, Some(net.keys.reset_token(&cid).unwrap()));
}

// Rule (spec section 5.12, ruling T10-h): with as many handshakes under way as
// `retry_above_half_open`, the next client gets a Retry; with its token it completes, its address
// validated, and the transport parameters carry the CIDs of the Retry (which the client checks).
#[cfg_attr(miri, ignore)]
#[test]
fn retry_switches_on_above_half_open_threshold() {
  let mut net = net(1, QuicParams::default());
  let _stalled = stalled_clients(&mut net, 64);
  assert_eq!(net.servers[0].endpoint.stats().half_open, 64);
  assert_eq!(net.servers[0].endpoint.stats().retries, 0);
  let client = net.add_client();
  net.run();
  let stats = net.servers[0].endpoint.stats();
  assert_eq!(stats.retries, 1);
  assert!(confirmed(&net, client));
  assert_eq!(stats.half_open, 64);
  assert_eq!(stats.conns, 65);
  let retry = net.clients[client].conn.test_client().unwrap();
  let retry_scid = retry.retry_scid.unwrap();
  assert!(!retry.retry_token.is_empty());
  // The connection took the CID of the Retry, with the index of the worker
  assert_eq!(server_cid(&net, client), retry_scid.as_slice());
  assert_eq!(retry_scid.as_slice()[0], 0);
  let conn = net.servers[0].endpoint.conn(retry_scid.as_slice()).unwrap();
  assert!(conn.address_validated());
}

// Rule (ruling T10-h): a token that is expired, of another peer or tampered with drops the
// Initial packet, which gets no second Retry; a valid token is taken above the threshold of
// Retry.
#[cfg_attr(miri, ignore)]
#[test]
fn invalid_or_expired_retry_tokens_drop_the_initial() {
  let mut net = net(1, limits(|el| el.retry_above_half_open = 0));
  let client = net.add_client();
  let mut first = net.client_datagrams(client);
  let _ = net.deliver_to_server(client, &mut first[0]);
  let mut retry = net.server_datagrams(0);
  assert_eq!(retry.len(), 1);
  assert_eq!(parse_header(&retry[0].1, 8).unwrap().ty, PacketTy::Retry);
  net.deliver_to_client(client, &mut retry[0].1);
  let with_token = net.client_datagrams(client);
  assert!(!parse_header(&with_token[0], 8).unwrap().token.is_empty());
  // From another peer: dropped
  let _ = net.deliver_meta(&mut with_token[0].clone(), stranger(9));
  assert!(net.server_datagrams(0).is_empty());
  // Tampered with: dropped
  let mut tampered = with_token[0].clone();
  let at = 1 + 4 + 1 + 8 + 1 + 8 + 1 + 20;
  tampered[at] ^= 1;
  let _ = net.deliver_to_server(client, &mut tampered);
  assert!(net.server_datagrams(0).is_empty());
  // Expired: dropped
  net.now_us += RETRY_TOKEN_LIFETIME_US;
  let _ = net.deliver_to_server(client, &mut with_token[0].clone());
  assert!(net.server_datagrams(0).is_empty());
  assert_eq!(net.servers[0].endpoint.stats().retries, 1);
  assert_eq!(net.servers[0].endpoint.stats().conns, 0);
  // In time, from the client: taken, above the threshold of Retry, which is not sent twice
  net.now_us -= 1;
  let _ = net.deliver_to_server(client, &mut with_token[0].clone());
  assert_eq!(net.servers[0].endpoint.stats().conns, 1);
  net.run();
  assert!(confirmed(&net, client));
  assert_eq!(net.servers[0].endpoint.stats().retries, 1);
}

// Rule (spec section 5.12): past `max_half_open_per_worker` handshakes under way, the first
// Initial packets of new clients are dropped, Retry or not, until one of them is done.
#[cfg_attr(miri, ignore)]
#[test]
fn initials_dropped_above_hard_cap() {
  let mut net = net(
    1,
    limits(|el| {
      el.max_half_open_per_worker = 4;
      el.retry_above_half_open = 4;
    }),
  );
  let stalled = stalled_clients(&mut net, 4);
  assert_eq!(net.servers[0].endpoint.stats().half_open, 4);
  let late = net.add_client();
  let mut first = net.client_datagrams(late);
  let _ = net.deliver_to_server(late, &mut first[0]);
  assert!(net.server_datagrams(0).is_empty(), "no Retry, no Initial");
  assert_eq!(net.servers[0].endpoint.stats().conns, 4);
  // One of them completes: room for the next
  net.clients[stalled[0]].deaf = false;
  net.clients[stalled[0]].mute = false;
  assert!(net.advance_to_next_event());
  net.run();
  assert!(confirmed(&net, stalled[0]));
  assert_eq!(net.servers[0].endpoint.stats().half_open, 3);
  assert!(net.advance_to_next_event());
  net.run();
  assert!(confirmed(&net, late));
}

// Rule (spec section 5.12): a client that does not complete its handshake within ten seconds
// of its first Initial packet loses its connection.
#[cfg_attr(miri, ignore)]
#[test]
fn handshake_deadline_closes_slow_client() {
  let mut net = net(1, QuicParams::default());
  let _slow = stalled_clients(&mut net, 1);
  let fine = net.add_client();
  net.run();
  assert!(confirmed(&net, fine));
  assert_eq!(net.servers[0].endpoint.stats().half_open, 1);
  net.advance(9_999_000);
  assert_eq!(net.servers[0].endpoint.stats().conns, 2);
  // At most a tick late
  net.advance(1_000);
  net.advance(250);
  let stats = net.servers[0].endpoint.stats();
  assert_eq!((stats.conns, stats.half_open), (1, 0));
  assert_eq!(net.servers[0].app.closed, 1);
  assert_eq!(net.loads.load(0), 1);
}

// Rule (spec section 5.11): the first Initial packet of a client that reaches a worker with more
// connections than another goes to that one, which makes the connection with its own index in
// byte 0 of its CID.
#[cfg_attr(miri, ignore)]
#[test]
fn first_initial_forwarded_to_least_loaded_worker() {
  let mut net = net(2, QuicParams::default());
  net.route = NetRoute::Worker(0);
  let first = net.add_client();
  net.run();
  assert!(confirmed(&net, first));
  // Worker 0 had no more connections than worker 1: kept
  assert_eq!(server_cid(&net, first)[0], 0);
  assert_eq!((net.loads.load(0), net.loads.load(1)), (1, 0));
  let second = net.add_client();
  let mut initial = net.client_datagrams(second);
  assert_eq!(net.deliver_to_server(second, &mut initial[0]), RecvOutcome::Forward { worker: 1 });
  net.route = NetRoute::Steer;
  net.run();
  assert!(confirmed(&net, second));
  assert_eq!(server_cid(&net, second)[0], 1);
  assert_eq!(net.servers[0].endpoint.stats().forwarded, 1);
  assert_eq!(net.servers[1].endpoint.stats().conns, 1);
  assert_eq!((net.loads.load(0), net.loads.load(1)), (1, 1));
}

// Review focus 2: a ClientHello in two Initial packets whose first one went to another worker
// sends the second one there too, and a retransmission of the first, even after the loads
// changed; two seconds later the forward is forgotten.
#[cfg_attr(miri, ignore)]
#[test]
fn second_initial_follows_forwarded_first() {
  let mut net = net(2, QuicParams::default());
  net.route = NetRoute::Worker(0);
  let first = net.add_client();
  net.run();
  assert!(confirmed(&net, first));
  let split = net.add_split_client(1500);
  let mut flight = net.client_datagrams(split);
  assert_eq!(flight.len(), 2, "the ClientHello spans two datagrams");
  assert_eq!(net.deliver_to_server(split, &mut flight[0]), RecvOutcome::Forward { worker: 1 });
  // Worker 1 is now as loaded as worker 0, which would keep a new client: this one follows
  assert_eq!((net.loads.load(0), net.loads.load(1)), (1, 1));
  assert_eq!(net.deliver_to_server(split, &mut flight[1]), RecvOutcome::Forward { worker: 1 });
  let mut again = flight[0].clone();
  assert_eq!(net.deliver_to_server(split, &mut again), RecvOutcome::Forward { worker: 1 });
  net.route = NetRoute::Steer;
  net.run();
  assert!(confirmed(&net, split));
  assert_eq!(server_cid(&net, split)[0], 1);
  assert_eq!(net.servers[0].endpoint.stats().conns, 1);
  assert_eq!(net.servers[1].endpoint.stats().conns, 1);
  net.route = NetRoute::Worker(0);
  net.advance(FORWARDED_TTL_US);
  let mut late = flight[0].clone();
  assert_eq!(net.deliver_to_server(split, &mut late), RecvOutcome::Done);
}

// Rule (spec section 5.4): our CIDs have 8 bytes, the index of the worker first; while steering
// is on, a connection has one CID and the server sends no NEW_CONNECTION_ID.
#[cfg_attr(miri, ignore)]
#[test]
fn our_cids_have_worker_byte_and_one_cid_per_conn_when_steering() {
  let mut net = net(3, QuicParams::default().set_balance(false));
  let clients: Vec<usize> = (0..12).map(|_| net.add_client()).collect();
  net.run();
  let _ = net.run_requests(4, 4, b"GET /");
  let mut per_worker = [0usize; 3];
  for &idx in &clients {
    assert!(confirmed(&net, idx));
    let cid = server_cid(&net, idx);
    assert_eq!(cid.len(), 8);
    let worker = usize::from(cid[0]);
    assert!(worker < 3);
    per_worker[worker] += 1;
    assert!(net.servers[worker].endpoint.conn(&cid).is_some());
    assert_eq!(net.clients[idx].conn.test_client().unwrap().new_connection_ids, 0);
  }
  for (worker, count) in per_worker.iter().enumerate() {
    assert_eq!(net.servers[worker].endpoint.our_cids(), *count);
    assert_eq!(net.servers[worker].endpoint.stats().conns as usize, *count);
  }
}

// Rule (spec section 5.12): floods of PING, PATH_CHALLENGE and NEW_CONNECTION_ID frames close the
// connection past their budgets, with the application code of excessive load (ruling T7-c), and
// the ACK ranges past `max_ack_ranges` are ignored: the pools of the worker are as they were.
#[cfg_attr(miri, ignore)]
#[test]
fn frame_flood_budgets_close_connection() {
  let excessive = QuicLimits::default().excessive_load_app_code;
  let mut new_cids = Vec::new();
  for seq in 1..=17u64 {
    let cid = [0xc0, u8::try_from(seq).unwrap(), 0, 0, 0, 0, 0, 0];
    let token = [u8::try_from(seq).unwrap(); 16];
    new_cids.extend_from_slice(&encode_frames(&[Frame::NewConnectionId {
      seq,
      retire_prior_to: seq,
      cid: &cid,
      reset_token: &token,
    }]));
  }
  let floods: [(&str, Vec<u8>); 3] = [
    ("PING", encode_frames(&[Frame::Ping; 65])),
    ("PATH_CHALLENGE", encode_frames(&[Frame::PathChallenge([1; 8]); 17])),
    ("NEW_CONNECTION_ID", new_cids),
  ];
  for (name, flood) in floods {
    let mut net = net(1, QuicParams::default());
    let client = net.add_client();
    net.run();
    let cid = server_cid(&net, client);
    net.clients[client].conn.queue_test_frames(&flood);
    let mut datagrams = net.client_datagrams(client);
    for datagram in &mut datagrams {
      let _ = net.deliver_to_server(client, datagram);
    }
    let conn = net.servers[0].endpoint.conn(&cid).unwrap();
    assert_eq!(conn.close_code(), Some((true, excessive)), "{name}");
    net.run();
    // The NEW_CONNECTION_ID frames moved the server to CIDs that the client of tests does not
    // take packets on
    if name != "NEW_CONNECTION_ID" {
      assert_eq!(net.clients[client].conn.state(), ConnState::Draining, "{name}");
    }
  }
  // An ACK frame of more than 256 ranges is processed for its first 256 ranges only: the
  // connection goes on and the worker holds no more than it did.
  let mut net = net(1, QuicParams::default());
  let client = net.add_client();
  net.run();
  let _ = net.run_requests(700, 1, b"GET /");
  net.run();
  let cid = server_cid(&net, client);
  let sent = net.servers[0].endpoint.conn(&cid).unwrap().stats().packets_out;
  // Below the next packet number of the 1-RTT space; ranges of one packet after a gap of one, as
  // many as fit above packet number zero
  let largest = sent - 10;
  let ranges = (largest / 2 - 1).min(499);
  assert!(ranges > 256, "{largest}");
  let before = net.servers[0].endpoint.pools().frame_refs.live_chunks();
  let mut ack = vec![0x02];
  let mut put = |value: u64| {
    let mut buffer = [0; 8];
    let len = crate::quic::encode_varint(value, &mut buffer).unwrap();
    ack.extend_from_slice(&buffer[..len]);
  };
  for value in [largest, 0, ranges, 0] {
    put(value);
  }
  for _ in 0..ranges {
    put(0);
    put(0);
  }
  net.clients[client].conn.queue_test_frames(&ack);
  let mut datagrams = net.client_datagrams(client);
  assert!(!datagrams.is_empty());
  for datagram in &mut datagrams {
    let _ = net.deliver_to_server(client, datagram);
  }
  let conn = net.servers[0].endpoint.conn(&cid).unwrap();
  assert_eq!(conn.close_code(), None);
  assert_eq!(conn.state(), ConnState::Confirmed);
  assert!(net.servers[0].endpoint.pools().frame_refs.live_chunks() <= before);
}

// Rule (spec section 5.4): once the pools of a worker are warm, a second round of 64 clients of
// 4,096 requests each allocates nothing in the endpoint but what ring takes for an RSA signature,
// at most 9 per handshake (the test certificate is ECDSA: none).
#[cfg_attr(miri, ignore)]
#[test]
fn endpoint_steady_state_allocates_nothing_after_warmup() {
  static OTHERS: AtomicU64 = AtomicU64::new(0);
  static SERVER: AtomicU64 = AtomicU64::new(0);
  const CLIENTS: usize = 64;
  const REQUESTS: usize = 4096;
  let mut net = net(1, QuicParams::default());
  net.count((&SERVER, &OTHERS));
  let round = |net: &mut Net| {
    let first = net.clients.len();
    // The clients share the thread, and so the pools of TLS states, of the server: in batches of
    // 32, the handshakes of both sides hold at most the 64 that a thread keeps
    for _ in 0..2 {
      for _ in 0..CLIENTS / 2 {
        let _ = net.add_client();
      }
      net.run();
    }
    assert!((first..first + CLIENTS).all(|el| confirmed(net, el)));
    let done = net.run_requests_from(first, REQUESTS, 256, b"GET /");
    assert_eq!(done, (CLIENTS * REQUESTS) as u64);
    for idx in first..first + CLIENTS {
      let now_us = net.now_us;
      net.clients[idx].conn.close_app(now_us, 0);
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
  assert!(allocations <= 9 * CLIENTS as u64, "{allocations}");
  assert_eq!(allocations, 0, "{allocations} allocations in {CLIENTS} handshakes");
}

// Ruling T10-a: the keys of the stateless packets are those of the process: a Retry token that a
// worker issued opens with the keys of another one.
#[cfg_attr(miri, ignore)]
#[test]
fn endpoint_keys_are_shared_by_the_workers() {
  let mut net = net(2, limits(|el| el.retry_above_half_open = 0).set_balance(false));
  net.route = NetRoute::Worker(0);
  let client = net.add_client();
  let mut first = net.client_datagrams(client);
  let original_dcid = parse_header(&first[0], 8).unwrap().dcid.to_vec();
  let _ = net.deliver_to_server(client, &mut first[0]);
  let retry = net.server_datagrams(0);
  assert_eq!(retry.len(), 1);
  let header = parse_header(&retry[0].1, 8).unwrap();
  let peer = net.clients[client].addr;
  let keys = net.servers[1].endpoint.keys();
  let odcid = keys.open_retry_token(header.token, peer, net.now_us, header.scid);
  assert_eq!(odcid, Some(Cid::new(&original_dcid).unwrap()));
}

// Ruling T10-b: shutting down closes every connection with the shutdown code and drops the
// Initial packets of new clients.
#[cfg_attr(miri, ignore)]
#[test]
fn shutdown_closes_with_its_code_and_drops_new_initials() {
  let mut net = net(1, QuicParams::default());
  let clients: Vec<usize> = (0..3).map(|_| net.add_client()).collect();
  net.run();
  let now_us = net.now_us;
  let server = &mut net.servers[0];
  server.endpoint.begin_shutdown(now_us, &mut server.app);
  let code = QuicLimits::default().shutdown_app_code;
  for &idx in &clients {
    let cid = server_cid(&net, idx);
    assert_eq!(net.servers[0].endpoint.conn(&cid).unwrap().close_code(), Some((true, code)));
  }
  net.run();
  assert!(clients.iter().all(|el| net.clients[*el].conn.state() == ConnState::Draining));
  let late = net.add_client();
  let mut first = net.client_datagrams(late);
  let _ = net.deliver_to_server(late, &mut first[0]);
  assert!(net.server_datagrams(0).is_empty());
  net.advance(CLOSING_US);
  assert_eq!(net.servers[0].endpoint.stats().conns, 0);
  assert_eq!(net.servers[0].app.closed, 3);
}

// Ruling T10-e: a short header packet for an unknown CID that names another worker goes to that
// worker, not to a stateless reset, and so does a long header packet to one of its CIDs; a
// forwarded datagram is not forwarded again.
#[cfg_attr(miri, ignore)]
#[test]
fn unknown_cids_of_another_worker_are_forwarded() {
  let mut net = net(2, QuicParams::default().set_balance(false));
  let cid = [1, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7];
  let mut short = short_packet(&cid, 100);
  let now_us = net.now_us;
  let server = &mut net.servers[0];
  let outcome = server.endpoint.recv(now_us, &mut short, stranger(1), &mut server.app);
  assert_eq!(outcome, RecvOutcome::Forward { worker: 1 });
  assert!(net.server_datagrams(0).is_empty());
  // On worker 1 it is unknown and names it: a reset
  let server = &mut net.servers[1];
  server.endpoint.recv_forwarded(now_us, &mut short, stranger(1), &mut server.app);
  assert_eq!(net.server_datagrams(1).len(), 1);
  // A forwarded datagram that names another worker is dropped
  let server = &mut net.servers[1];
  let mut back = short_packet(&[0, 1, 2, 3, 4, 5, 6, 7], 100);
  server.endpoint.recv_forwarded(now_us, &mut back, stranger(1), &mut server.app);
  assert!(net.server_datagrams(1).is_empty());
  // A Handshake packet to a CID of worker 1
  let mut handshake = vec![0u8; 100];
  handshake[..6].copy_from_slice(&[0xe0, 0, 0, 0, 1, 8]);
  handshake[6..14].copy_from_slice(&cid);
  handshake[14] = 0;
  handshake[15..17].copy_from_slice(&(0x4000u16 | 80).to_be_bytes());
  let server = &mut net.servers[0];
  let outcome = server.endpoint.recv(now_us, &mut handshake, stranger(1), &mut server.app);
  assert_eq!(outcome, RecvOutcome::Forward { worker: 1 });
  // An unknown CID of this worker in a long header gets nothing
  handshake[6] = 0;
  let outcome = server.endpoint.recv(now_us, &mut handshake, stranger(1), &mut server.app);
  assert_eq!(outcome, RecvOutcome::Done);
  assert!(net.server_datagrams(0).is_empty());
  assert_eq!(net.servers[0].endpoint.stats().forwarded, 2);
}

// Carried rule 1: a datagram that the kernel coalesced is split into its segments, each
// processed alone: the two Initial packets of a long ClientHello, coalesced, open one connection.
#[cfg_attr(miri, ignore)]
#[test]
fn coalesced_datagrams_are_split_into_segments() {
  let mut net = net(1, QuicParams::default());
  let client = net.add_split_client(1500);
  let flight = net.client_datagrams(client);
  assert_eq!(flight.len(), 2);
  let segment = flight[0].len();
  let mut gro = flight.concat();
  let meta = DatagramMeta {
    peer: net.clients[client].addr,
    local: None,
    segment_size: Some(u16::try_from(segment).unwrap()),
  };
  assert_eq!(net.deliver_meta(&mut gro, meta), RecvOutcome::Done);
  assert_eq!(net.servers[0].endpoint.stats().datagrams_in, 2);
  net.run();
  assert!(confirmed(&net, client));
}

// Carried rule 4: the counters of the endpoint keep what its connections sent after they close.
#[cfg_attr(miri, ignore)]
#[test]
fn endpoint_stats_keep_closed_connections() {
  let mut net = net(1, QuicParams::default());
  let client = net.add_client();
  net.run();
  let _ = net.run_requests(16, 16, b"GET /");
  let open = net.servers[0].endpoint.stats();
  let now_us = net.now_us;
  net.clients[client].conn.close_app(now_us, 0);
  net.run();
  net.advance(CLOSING_US);
  let closed = net.servers[0].endpoint.stats();
  assert_eq!(closed.conns, 0);
  assert!(open.packets_out > 0 && closed.packets_out >= open.packets_out);
  assert!(closed.datagrams_out >= open.datagrams_out && closed.ack_only_out >= open.ack_only_out);
  assert!(closed.datagrams_in > open.datagrams_in);
}

// Carried rule 8: an arena with no room keeps what is owed for the next flush, the stateless
// packets first.
#[cfg_attr(miri, ignore)]
#[test]
fn full_arena_keeps_what_is_owed() {
  use crate::quic::{FlushOutcome, TxArena};
  let mut net = net(1, QuicParams::default());
  let client = net.add_client();
  let mut first = net.client_datagrams(client);
  let _ = net.deliver_to_server(client, &mut first[0]);
  let _ = net.deliver_meta(&mut unknown_version(1200), stranger(1));
  let now_us = net.now_us;
  let server = &mut net.servers[0];
  let mut small = TxArena::new(100).unwrap();
  assert_eq!(server.endpoint.flush(now_us, &mut small, &mut server.app), FlushOutcome::ArenaFull);
  // The Version Negotiation packet fit, alone
  let trains: Vec<_> = small.pending().map(|el| el.peer).collect();
  assert_eq!(trains, [stranger(1).peer]);
  // The Initial of the server goes with the next flush
  let out = net.server_datagrams(0);
  let addr = net.clients[client].addr;
  assert!(!out.is_empty() && out.iter().all(|el| el.0 == addr));
}

// Spec section 5.11: without CID steering, the packets of a client that follow its first one
// reach the worker that got it, by the hash of their addresses: it keeps the client.
#[cfg_attr(miri, ignore)]
#[test]
fn no_balancing_without_steering() {
  let mut net = net(2, QuicParams::default().set_cid_steering(false));
  net.route = NetRoute::Worker(0);
  let first = net.add_client();
  net.run();
  let second = net.add_client();
  net.run();
  assert!(confirmed(&net, first) && confirmed(&net, second));
  assert_eq!((server_cid(&net, first)[0], server_cid(&net, second)[0]), (0, 0));
  assert_eq!(net.servers[0].endpoint.stats().forwarded, 0);
  assert_eq!((net.loads.load(0), net.loads.load(1)), (2, 0));
}

// Spec section 5.12: a worker holds at most `max_conns_per_worker` connections; the first Initial
// packet of one more client is dropped, without a Retry.
#[cfg_attr(miri, ignore)]
#[test]
fn initials_dropped_at_the_connection_cap() {
  let mut net = net(1, QuicParams::default().set_max_conns_per_worker(2));
  let clients: Vec<usize> = (0..2).map(|_| net.add_client()).collect();
  net.run();
  assert!(clients.iter().all(|el| confirmed(&net, *el)));
  let late = net.add_client();
  let mut first = net.client_datagrams(late);
  let _ = net.deliver_to_server(late, &mut first[0]);
  assert!(net.server_datagrams(0).is_empty());
  assert_eq!(net.servers[0].endpoint.stats().conns, 2);
  // Room again once one closes
  let now_us = net.now_us;
  net.clients[clients[0]].conn.close_app(now_us, 0);
  net.run();
  net.advance(CLOSING_US);
  assert_eq!(net.servers[0].endpoint.stats().conns, 1);
  let _ = net.deliver_to_server(late, &mut first[0].clone());
  net.run();
  assert!(confirmed(&net, late));
}
