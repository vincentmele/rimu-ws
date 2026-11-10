use crate::{
  quic::{
    Cid, ConnState, DatagramMeta, EndpointKeys, Frame, PacketTy, QuicLimits, QuicParams,
    RecvOutcome, TxArena,
    cid_table::FORWARDED_TTL_US,
    parse_header,
    testing::{Behavior, Net, NetRoute, TestApp, TestEndpoint, encode_frames, server_tls_config},
    token::RETRY_TOKEN_LIFETIME_US,
  },
  rng::ChaCha20,
  sync::{Arc, AtomicU64},
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
  // Random bytes: two resets differ but for the token (lengths differ too, review L9: the bytes
  // after the first one that every reset has, at least 21 bytes long, are compared)
  assert_ne!(resets[1][1..5], resets[2][1..5]);
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
  let floods: [(&str, Vec<Vec<u8>>); 3] = [
    // Ruling T21-g: the PINGs a second are 64 plus 2 per smoothed RTT, at most 16,384, and the
    // RTT of this network is tiny: 17,000 PINGs, 1,000 to a packet, close the connection
    // whatever the RTT is
    ("PING", vec![encode_frames(&vec![Frame::Ping; 1000]); 17]),
    ("PATH_CHALLENGE", vec![encode_frames(&[Frame::PathChallenge([1; 8]); 17])]),
    ("NEW_CONNECTION_ID", vec![new_cids]),
  ];
  for (name, flood) in floods {
    let mut net = net(1, QuicParams::default());
    let client = net.add_client();
    net.run();
    let cid = server_cid(&net, client);
    for packet in &flood {
      net.clients[client].conn.queue_test_frames(packet);
      let mut datagrams = net.client_datagrams(client);
      for datagram in &mut datagrams {
        let _ = net.deliver_to_server(client, datagram);
      }
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
    // All at once, as the benchmark does: the clients share the thread, and so the TLS pools, of
    // the server, which keep as many as 256 handshakes (ruling T10-l)
    for _ in 0..CLIENTS {
      let _ = net.add_client();
    }
    net.run();
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

// An Initial packet of version 1 to `dcid`, of `len` bytes, that nothing opens.
fn garbage_initial(dcid: &[u8; 8], len: usize) -> Vec<u8> {
  let mut datagram = vec![0x5au8; len];
  datagram[..6].copy_from_slice(&[0xc3, 0, 0, 0, 1, 8]);
  datagram[6..14].copy_from_slice(dcid);
  datagram[14] = 8;
  datagram[15..23].copy_from_slice(&[7; 8]);
  // No token, then a Length that covers the rest
  datagram[23] = 0;
  let length = u16::try_from(len - 26).unwrap() | 0x4000;
  datagram[24..26].copy_from_slice(&length.to_be_bytes());
  datagram
}

// The datagrams that an endpoint of a test flushed, taken out of `tx`.
fn flushed(endpoint: &mut TestEndpoint, app: &mut TestApp, now_us: u64) -> Vec<Vec<u8>> {
  let mut tx = TxArena::new(TxArena::DEFAULT_BYTES).unwrap();
  let _ = endpoint.flush(now_us, &mut tx, app);
  let mut rslt = Vec::new();
  loop {
    let next =
      tx.pending().next().map(|el| (el.id, el.bytes.to_vec(), usize::from(el.segment_size)));
    let Some((id, bytes, segment)) = next else {
      break;
    };
    tx.mark_submitted(id);
    tx.release(id);
    rslt.extend(bytes.chunks(segment).map(<[u8]>::to_vec));
  }
  rslt
}

// Ruling T10-l: a burst of 128 handshakes at once, then another one, allocates nothing in the
// endpoint the second time but what ring takes for an RSA signature (the test certificate is
// ECDSA: none). The clients share the thread, and so its TLS pools: 256 handshakes at once.
#[cfg_attr(miri, ignore)]
#[test]
fn handshake_bursts_allocate_nothing_after_warmup() {
  static OTHERS: AtomicU64 = AtomicU64::new(0);
  static SERVER: AtomicU64 = AtomicU64::new(0);
  const BURST: usize = 128;
  let mut net = net(1, limits(|el| el.retry_above_half_open = 256));
  net.count((&SERVER, &OTHERS));
  let burst = |net: &mut Net| {
    let first = net.clients.len();
    for _ in 0..BURST {
      let _ = net.add_client();
    }
    net.run();
    assert!((first..first + BURST).all(|el| confirmed(net, el)));
    assert_eq!(net.servers[0].endpoint.stats().retries, 0);
    for idx in first..first + BURST {
      let now_us = net.now_us;
      net.clients[idx].conn.close_app(now_us, 0);
    }
    net.run();
    net.advance(CLOSING_US);
    assert_eq!(net.servers[0].endpoint.stats().conns, 0);
  };
  burst(&mut net);
  let before = SERVER.load(Ordering::Relaxed);
  burst(&mut net);
  let allocations = SERVER.load(Ordering::Relaxed) - before;
  assert!(allocations <= 9 * BURST as u64, "{allocations}");
  assert_eq!(allocations, 0, "{allocations} allocations in {BURST} handshakes");
}

// Ruling T10-m: 64 first Initial packets that reach one worker of four in one batch, before any
// other worker processed what it got, spread over the four: the load of a worker counts the
// connections placed on it, not only those that it opened.
#[cfg_attr(miri, ignore)]
#[test]
fn first_initials_in_one_batch_spread_over_the_workers() {
  let mut net = net(4, QuicParams::default());
  let clients: Vec<usize> = (0..64).map(|_| net.add_client()).collect();
  let mut forwards = Vec::new();
  for &idx in &clients {
    let mut datagram = net.client_datagrams(idx).remove(0);
    let meta = DatagramMeta { peer: net.clients[idx].addr, local: None, segment_size: None };
    let now_us = net.now_us;
    let server = &mut net.servers[0];
    if let RecvOutcome::Forward { worker } =
      server.endpoint.recv(now_us, &mut datagram, meta, &mut server.app)
    {
      forwards.push((worker, datagram, meta));
    }
  }
  for (worker, mut datagram, meta) in forwards {
    let now_us = net.now_us;
    let server = &mut net.servers[usize::from(worker)];
    server.endpoint.recv_forwarded(now_us, &mut datagram, meta, &mut server.app);
  }
  net.run();
  assert!(clients.iter().all(|el| confirmed(&net, *el)));
  for worker in 0..4u8 {
    let conns = net.servers[usize::from(worker)].endpoint.stats().conns;
    assert!((15..=17).contains(&conns), "worker {worker}: {conns}");
    assert_eq!(net.loads.load(worker), conns);
  }
}

// Ruling T10-m: every way in which a placement opens no connection gives it back: a forwarded
// datagram that the caller could not hand over, a target that shuts down, answers with a Retry,
// has no room for a handshake or a connection, or opens nothing in the datagram; and the same on
// the worker that received it.
#[cfg_attr(miri, ignore)]
#[test]
fn placements_that_open_nothing_are_given_back() {
  // A net whose worker 0 is the busier one: the first Initial packets that reach it go to worker 1
  let busy = |params: QuicParams| {
    let mut net = net(2, params);
    net.route = NetRoute::Worker(0);
    net.loads.placed(0);
    net
  };
  let first_initial = |net: &mut Net| {
    let client = net.add_client();
    let datagram = net.client_datagrams(client).remove(0);
    let meta = DatagramMeta { peer: net.clients[client].addr, local: None, segment_size: None };
    (datagram, meta)
  };
  let forward = |net: &mut Net, datagram: &mut Vec<u8>, meta: DatagramMeta| {
    let now_us = net.now_us;
    let server = &mut net.servers[0];
    assert_eq!(
      server.endpoint.recv(now_us, datagram, meta, &mut server.app),
      RecvOutcome::Forward { worker: 1 }
    );
    assert_eq!((net.loads.load(0), net.loads.load(1)), (1, 1), "placed on worker 1");
  };
  let deliver = |net: &mut Net, datagram: &mut Vec<u8>, meta: DatagramMeta| {
    let now_us = net.now_us;
    let server = &mut net.servers[1];
    server.endpoint.recv_forwarded(now_us, datagram, meta, &mut server.app);
  };
  // The inbox of the target was full
  let mut net = busy(QuicParams::default());
  let (mut datagram, meta) = first_initial(&mut net);
  forward(&mut net, &mut datagram, meta);
  net.servers[0].endpoint.forward_dropped(&datagram, 1);
  assert_eq!((net.loads.load(0), net.loads.load(1)), (1, 0), "inbox full");
  // The target refuses, in each of its ways
  let refusals: [(&str, QuicParams); 4] = [
    ("Retry", limits(|el| el.retry_above_half_open = 0)),
    ("half-open cap", limits(|el| el.max_half_open_per_worker = 0)),
    ("connection cap", QuicParams::default().set_max_conns_per_worker(0)),
    ("shutdown", QuicParams::default()),
  ];
  for (name, params) in refusals {
    let mut net = busy(params);
    if name == "shutdown" {
      let now_us = net.now_us;
      let target = &mut net.servers[1];
      target.endpoint.begin_shutdown(now_us, &mut target.app);
    }
    let (mut datagram, meta) = first_initial(&mut net);
    forward(&mut net, &mut datagram, meta);
    deliver(&mut net, &mut datagram, meta);
    assert_eq!((net.loads.load(0), net.loads.load(1)), (1, 0), "{name}");
    assert_eq!(net.servers[1].endpoint.stats().conns, 0, "{name}");
  }
  // A first datagram that opens nothing on the target
  let mut net = busy(QuicParams::default());
  let mut garbage = garbage_initial(&[9; 8], 1200);
  let meta = stranger(7);
  forward(&mut net, &mut garbage, meta);
  deliver(&mut net, &mut garbage, meta);
  assert_eq!((net.loads.load(0), net.loads.load(1)), (1, 0), "undecryptable");
  // On the worker that received them: Retry, half-open cap, shutdown, nothing that opens
  for case in 0..4 {
    let params = match case {
      0 => limits(|el| el.retry_above_half_open = 0),
      1 => limits(|el| el.max_half_open_per_worker = 0),
      _ => QuicParams::default(),
    };
    let mut net = self::net(1, params);
    if case == 2 {
      let now_us = net.now_us;
      let server = &mut net.servers[0];
      server.endpoint.begin_shutdown(now_us, &mut server.app);
    }
    let (mut datagram, meta) = if case == 3 {
      (garbage_initial(&[9; 8], 1200), stranger(7))
    } else {
      first_initial(&mut net)
    };
    let _ = net.deliver_meta(&mut datagram, meta);
    assert_eq!(net.loads.load(0), 0, "case {case}");
    assert_eq!(net.servers[0].endpoint.stats().conns, 0, "case {case}");
  }
}

// Ruling T10-o: two endpoints whose generators come from one generator of the process draw
// other numbers: other CIDs and other nonces of their Retry tokens for the same Initial packet.
#[cfg_attr(miri, ignore)]
#[test]
fn endpoints_from_one_parent_draw_different_numbers() {
  let mut parent = ChaCha20::from_key([1; 32]);
  let keys = Arc::new(EndpointKeys::new(&mut parent));
  let params = limits(|el| el.retry_above_half_open = 0);
  let mut make = || {
    TestEndpoint::new(
      params,
      0,
      1,
      Arc::new(server_tls_config()),
      &mut parent,
      None,
      Arc::clone(&keys),
    )
    .unwrap()
  };
  let (mut first, mut second) = (make(), make());
  let mut net = net(1, QuicParams::default());
  let client = net.add_client();
  let datagram = net.client_datagrams(client).remove(0);
  let meta = DatagramMeta { peer: net.clients[client].addr, local: None, segment_size: None };
  let mut retries = Vec::new();
  for endpoint in [&mut first, &mut second] {
    let mut app = TestApp::default();
    let _ = endpoint.recv(net.now_us, &mut datagram.clone(), meta, &mut app);
    let out = flushed(endpoint, &mut app, net.now_us);
    assert_eq!(out.len(), 1);
    let header = parse_header(&out[0], 8).unwrap();
    assert_eq!(header.ty, PacketTy::Retry);
    retries.push((header.scid.to_vec(), header.token[..12].to_vec()));
  }
  assert_ne!(retries[0].0, retries[1].0, "the CIDs");
  assert_ne!(retries[0].1, retries[1].1, "the nonces of the tokens");
}

// Review L6: a slot whose connection was owed a flush, then ended, and which a new connection
// took again in the same turn, is flushed once.
#[cfg_attr(miri, ignore)]
#[test]
fn a_slot_taken_again_in_one_turn_is_flushed_once() {
  let mut net = net(1, QuicParams::default().set_max_conns_per_worker(1));
  let first = net.add_client();
  net.run();
  let cid = server_cid(&net, first);
  let now_us = net.now_us;
  net.clients[first].conn.close_app(now_us, 0);
  net.run();
  assert_eq!(net.servers[0].endpoint.conn(&cid).unwrap().state(), ConnState::Draining);
  // A late datagram: owed a flush, which does not come before the end of the draining period
  let _ = net.deliver_to_server(first, &mut short_packet(&cid, 60));
  assert_eq!(net.servers[0].endpoint.dirty_len(), 1);
  net.advance(CLOSING_US);
  assert_eq!(net.servers[0].endpoint.stats().conns, 0);
  let second = net.add_client();
  let mut initial = net.client_datagrams(second).remove(0);
  let _ = net.deliver_to_server(second, &mut initial);
  assert_eq!(net.servers[0].endpoint.stats().conns, 1);
  assert_eq!(net.servers[0].endpoint.dirty_len(), 1);
  net.run();
  assert!(confirmed(&net, second));
}

// Review L7: a first Initial packet in which nothing opens leaves no connection and makes no
// call of the application, which never saw it.
#[cfg_attr(miri, ignore)]
#[test]
fn undecryptable_first_initials_make_no_app_callback() {
  let mut net = net(1, QuicParams::default());
  for idx in 0..8u8 {
    let _ = net.deliver_meta(&mut garbage_initial(&[idx; 8], 1200), stranger(9));
  }
  let server = &net.servers[0];
  assert_eq!((server.app.closed, server.app.established), (0, 0));
  assert_eq!((server.endpoint.stats().conns, server.endpoint.stats().half_open), (0, 0));
  assert!(net.server_datagrams(0).is_empty());
}

// Review L9: the length of a stateless reset is unpredictable, from 21 bytes up to one byte less
// than what it answers and at most 40; one byte less than an answered datagram of up to 43 bytes,
// as RFC 9000 section 10.3 asks, as far as the cap of 40 lets it.
#[cfg_attr(miri, ignore)]
#[test]
fn stateless_reset_lengths_are_unpredictable_within_bounds() {
  let mut net = net(1, limits(|el| el.stateless_reset_per_sec = 100_000));
  let cid = [0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7];
  for len in [41, 42, 43, 44, 60, 100, 1200] {
    let mut lengths = Vec::new();
    for _ in 0..64 {
      let _ = net.deliver_meta(&mut short_packet(&cid, len), stranger(1));
      let out = net.server_datagrams(0);
      assert_eq!(out.len(), 1);
      lengths.push(out[0].1.len());
    }
    let max = (len - 1).min(40);
    assert!(lengths.iter().all(|el| (21..=max).contains(el)), "{len}: {lengths:?}");
    if len <= 43 {
      assert!(lengths.iter().all(|el| *el == max), "{len}: {lengths:?}");
    } else {
      lengths.sort_unstable();
      lengths.dedup();
      assert!(lengths.len() > 4, "{len}: {lengths:?}");
    }
  }
}

// Review L10: a datagram that goes to another worker counts there, once, and as forwarded here.
#[cfg_attr(miri, ignore)]
#[test]
fn forwarded_datagrams_count_once() {
  let mut net = net(2, QuicParams::default());
  net.route = NetRoute::Worker(0);
  net.loads.placed(0);
  let client = net.add_client();
  let mut initial = net.client_datagrams(client).remove(0);
  assert_eq!(net.deliver_to_server(client, &mut initial), RecvOutcome::Forward { worker: 1 });
  let (here, there) = (net.servers[0].endpoint.stats(), net.servers[1].endpoint.stats());
  assert_eq!((here.datagrams_in, here.forwarded), (0, 1));
  assert_eq!((there.datagrams_in, there.conns), (1, 1));
}

// Ruling T14-d: a handler that answers later reaches its connection through the handle of the
// connection, which its context gives; a handle whose connection is gone, or whose slot holds the
// next connection, reaches nothing and the closure is not run.
#[cfg_attr(miri, ignore)]
#[test]
fn with_conn_reaches_the_connection_of_a_handle_and_ignores_a_stale_one() {
  let mut net = net(1, QuicParams::default());
  let client = net.add_client();
  net.run();
  let handle = net.servers[0].endpoint.handle_of(&server_cid(&net, client)).unwrap();
  let now_us = net.now_us;
  let server = &mut net.servers[0];
  let seen = server.endpoint.with_conn(now_us, handle, &mut server.app, |_, cx| cx.handle());
  assert_eq!(seen, Some(handle));
  // The connection closes and its slot takes the next one
  net.clients[client].conn.close_app(now_us, 0);
  net.run();
  net.advance(CLOSING_US);
  assert_eq!(net.servers[0].endpoint.stats().conns, 0);
  let next = net.add_client();
  net.run();
  let next_handle = net.servers[0].endpoint.handle_of(&server_cid(&net, next)).unwrap();
  assert_eq!(next_handle.slot, handle.slot);
  assert_ne!(next_handle, handle);
  let now_us = net.now_us;
  let server = &mut net.servers[0];
  let mut ran = false;
  assert!(server.endpoint.with_conn(now_us, handle, &mut server.app, |_, _| ran = true).is_none());
  assert!(!ran);
}

// Ruling T16-c (spec section 2.1): the endpoint sums the counters of its connections that the
// measurement asserts by: responses finished (STREAM FINs), the flushes that finished one and
// those of them that carried the acknowledgment of the requests, the BLOCKED frames received,
// losses, probe timeouts and STREAM frames sent again.
#[cfg_attr(miri, ignore)]
#[test]
fn endpoint_sums_the_counters_of_the_measurement() {
  let mut net = net(1, QuicParams::default());
  for _ in 0..4 {
    let _ = net.add_client();
  }
  net.run();
  let before = net.servers[0].endpoint.stats();
  assert_eq!(net.run_requests(64, 64, b"GET /"), 4 * 64);
  let stats = net.servers[0].endpoint.stats();
  assert_eq!(stats.fins_out - before.fins_out, 4 * 64);
  let flushes = stats.fin_flushes - before.fin_flushes;
  assert!(flushes > 0 && flushes <= 4 * 64, "{stats:?}");
  // Each answer leaves with the acknowledgment of the packets of its requests
  assert_eq!(stats.fin_flushes_acked - before.fin_flushes_acked, flushes, "{stats:?}");
  let blocked = (stats.data_blocked_in, stats.stream_data_blocked_in, stats.streams_blocked_in);
  assert_eq!(blocked, (0, 0, 0));
  assert_eq!((stats.packets_lost, stats.pto_probes, stats.frames_resent), (0, 0, 0));
  assert_eq!(stats.frames_resent_acked, 0);
  // Ruling T19-a: every flush that finished a response and owed an acknowledgment carried it;
  // the datagram bytes and the stream bytes of the responses, written by copy, are summed
  assert_eq!(stats.fin_flushes_ack_owed - before.fin_flushes_ack_owed, flushes, "{stats:?}");
  let owed_acked = stats.fin_flushes_owed_and_acked - before.fin_flushes_owed_and_acked;
  assert_eq!(owed_acked, flushes, "{stats:?}");
  let response = RESPONSE.len() as u64;
  assert_eq!(stats.stream_bytes_out - before.stream_bytes_out, 4 * 64 * response, "{stats:?}");
  assert_eq!(stats.stream_bytes_copied - before.stream_bytes_copied, 4 * 64 * response);
  let bytes = stats.bytes_out - before.bytes_out;
  let datagrams = stats.datagrams_out - before.datagrams_out;
  assert!(bytes > 4 * 64 * response && bytes <= datagrams * 1472, "{stats:?}");
  assert_eq!(stats.pacer_holds, 0, "{stats:?}");
}

// Ruling T16-b: a flush writes the connections in the order in which they came to have something
// to send, or, with `flush_in_slot_order`, in the order of their slots.
#[cfg_attr(miri, ignore)]
#[test]
fn flush_order_is_arrival_or_slot() {
  for slot_order in [false, true] {
    let mut net = net(1, QuicParams::default().set_flush_in_slot_order(slot_order));
    let (first, second) = (net.add_client(), net.add_client());
    net.run();
    assert!(confirmed(&net, first) && confirmed(&net, second));
    // The second client's request arrives first
    for client in [second, first] {
      net.client_ctx(client, net.now_us, |cx| {
        let id = cx.open_bidi().unwrap();
        cx.write(id, b"GET /", true).unwrap();
      });
      for mut datagram in net.client_datagrams(client) {
        let _ = net.deliver_to_server(client, &mut datagram);
      }
    }
    let peers: Vec<u16> = net.server_datagrams(0).iter().map(|el| el.0.port()).collect();
    let ports = [50_000 + first as u16, 50_000 + second as u16];
    let expected = if slot_order { ports.to_vec() } else { vec![ports[1], ports[0]] };
    assert_eq!(peers, expected, "slot order {slot_order}");
  }
}

// Task 20 fix 1: the slots of the connections are made a chunk at a time, up to the cap, and an
// idle worker frees them keeping the generations above those of the slots it freed.
#[test]
fn slot_table_grows_a_chunk_at_a_time_and_clear_keeps_handles_stale() {
  use super::{SLOT_CHUNK, Slot, SlotTable};
  use crate::tls::SkCtx;
  let mut table = SlotTable::<TestApp, ChaCha20, SkCtx>::new(2 * SLOT_CHUNK + 1);
  assert!(table.chunks.is_empty() && table.get(0).is_none());
  for nth in 0..=SLOT_CHUNK {
    table.push(Slot { generation: 7 + nth as u32, ..Slot::EMPTY }).unwrap();
  }
  // 17 slots are two chunks, each with room for its slots reserved whole
  assert_eq!((table.len(), table.chunks.len()), (SLOT_CHUNK + 1, 2));
  assert!(table.chunks.iter().all(|el| el.capacity() == SLOT_CHUNK));
  assert_eq!(table.get(SLOT_CHUNK).map(|el| el.generation), Some(7 + SLOT_CHUNK as u32));
  assert!(table.get(SLOT_CHUNK + 1).is_none());
  for _ in SLOT_CHUNK + 1..2 * SLOT_CHUNK + 1 {
    table.push(Slot::EMPTY).unwrap();
  }
  assert!(table.push(Slot::EMPTY).is_err(), "past the cap");
  let before = table.get(0).map(|el| &raw const *el);
  table.get_mut(0).unwrap().dirty = true;
  assert_eq!(before, table.get(0).map(|el| &raw const *el), "a slot never moves");
  table.clear();
  assert_eq!((table.len(), table.chunks.len()), (0, 0));
  // No handle of before names a slot made after: its generation was 7 + SLOT_CHUNK at most
  assert_eq!(table.generation_floor, 8 + SLOT_CHUNK as u32);
}

// Rule (RFC 9000 section 10.2.3, RFC 9001 section 4.8; h3spec): the first Initial packet of a client
// whose handshake data is refused, for its transport parameters (TRANSPORT_PARAMETER_ERROR) or
// its TLS (no_application_protocol, an alert of RFC 9001 section 4.8), is answered with a
// CONNECTION_CLOSE with that code, in an Initial packet, and not dropped without a word. The
// connection then drains like any other that closed.
#[cfg_attr(miri, ignore)]
#[test]
fn rejected_first_initial_is_answered_with_connection_close() {
  // (the ALPN of the client, its transport parameters, the code that is expected)
  let cases: [(&'static [u8], fn(&mut crate::quic::TransportParams), u64); 2] = [
    // The server requires the CID of the Initial packets in the parameters (RFC 9000 section 7.3)
    (b"h3", |el| el.initial_source_connection_id = None, 0x08),
    // 0x100 + no_application_protocol (120)
    (b"h2", |_| {}, 0x178),
  ];
  for (alpn, tp, code) in cases {
    let mut net = net(1, QuicParams::default());
    net.client_alpn = alpn;
    net.client_tp = tp;
    let client = net.add_client();
    let mut first = net.client_datagrams(client);
    let _ = net.deliver_to_server(client, &mut first[0]);
    let out = net.server_datagrams(0);
    assert_eq!(out.len(), 1, "{code:#x}");
    assert_eq!(parse_header(&out[0].1, 8).unwrap().ty, PacketTy::Initial);
    assert_eq!(net.servers[0].endpoint.stats().conns, 1);
    net.deliver_to_client(client, &mut out[0].1.clone());
    assert_eq!(net.clients[client].conn.state(), ConnState::Draining);
    assert_eq!(net.clients[client].conn.test_client().unwrap().peer_close, Some((false, code)));
    net.advance(CLOSING_US);
    assert_eq!(net.servers[0].endpoint.stats().conns, 0);
  }
}

// Rule (review I-2): a connection kept to say that a first Initial was refused is a half-open one
// until it has drained, as a handshake that has not finished: a flood of such Initials from many
// addresses fills `half_open`, gets the Retry above `retry_above_half_open` and is refused at
// `max_half_open_per_worker`, as a flood of ordinary half-open handshakes is; and the slots are
// released once they drained.
#[cfg_attr(miri, ignore)]
#[test]
fn refused_initials_count_as_half_open_until_they_drain() {
  let mut net =
    net(1, limits(|el| {
      el.retry_above_half_open = 4;
      el.max_half_open_per_worker = 6;
    }));
  net.client_tp = |el| el.initial_source_connection_id = None;
  let mut retries = 0;
  for _ in 0..12 {
    let client = net.add_client();
    let mut first = net.client_datagrams(client);
    let _ = net.deliver_to_server(client, &mut first[0]);
    for (_, datagram) in net.server_datagrams(0) {
      if parse_header(&datagram, 8).unwrap().ty == PacketTy::Retry {
        retries += 1;
      }
    }
  }
  let stats = net.servers[0].endpoint.stats();
  // Four refused Initials held a slot each, the other eight got a Retry
  assert_eq!((stats.half_open, stats.conns, retries), (4, 4, 8));
  net.advance(CLOSING_US);
  let stats = net.servers[0].endpoint.stats();
  assert_eq!((stats.half_open, stats.conns), (0, 0));
}

// Rule (spec sections 5.4 and 5.11, RFC 9000 section 9.3): a NAT that gives a client another
// address keeps its connection on the worker that its CID names, with CID steering on: the
// packets that come from the new address reach that worker, nothing is forwarded, the worker
// sends to the new address once it is validated and the requests go on.
#[cfg_attr(miri, ignore)]
#[test]
fn rebinding_stays_on_the_same_worker_with_cid_steering() {
  let mut net = net(4, QuicParams::default());
  let client = net.add_client();
  net.run();
  assert!(confirmed(&net, client));
  assert_eq!(net.run_requests(10, 4, b"GET /"), 10);
  let cid = server_cid(&net, client);
  let worker = usize::from(cid[0]);
  let forwarded: u64 = net.servers.iter().map(|el| el.endpoint.stats().forwarded).sum();
  let moved = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 41_000);
  net.clients[client].addr = moved;
  assert_eq!(net.run_requests(100, 4, b"GET /"), 100);
  for (idx, server) in net.servers.iter().enumerate() {
    assert_eq!(server.endpoint.stats().conns, u32::from(idx == worker), "worker {idx}");
  }
  let now: u64 = net.servers.iter().map(|el| el.endpoint.stats().forwarded).sum();
  assert_eq!(now, forwarded);
  let conn = net.servers[worker].endpoint.conn(&cid).unwrap();
  assert_eq!(conn.peer_addr(), moved);
  assert!(conn.address_validated());
}

// Rule (review of task 22, deferred minor): a connection that closes while its handshake lasts
// keeps its deadline for the count of half-open handshakes, but its timer is not armed at that
// deadline once it passed: it fires at the end of the closing period, not at every tick.
#[cfg_attr(miri, ignore)]
#[test]
fn past_handshake_deadline_is_not_rearmed_while_closing() {
  let mut net = net(1, QuicParams::default().set_handshake_timeout_ms(100));
  net.client_alpn = b"h2";
  let client = net.add_client();
  let mut first = net.client_datagrams(client);
  let _ = net.deliver_to_server(client, &mut first[0]);
  assert_eq!(net.server_datagrams(0).len(), 1);
  assert_eq!(net.servers[0].endpoint.stats().half_open, 1);
  net.advance(200_000);
  let stats = net.servers[0].endpoint.stats();
  assert_eq!((stats.conns, stats.half_open), (1, 1));
  // The end of the closing period, about three PTOs of the initial RTT after the close, and not
  // the next tick of the wheel
  let next = net.servers[0].endpoint.next_deadline().unwrap();
  assert!(next > net.now_us + 1_000_000, "the timer fires at {next}, at {}", net.now_us);
  net.advance(250);
  assert_eq!(net.servers[0].endpoint.next_deadline(), Some(next));
  net.advance(CLOSING_US);
  let stats = net.servers[0].endpoint.stats();
  assert_eq!((stats.conns, stats.half_open), (0, 0));
}
