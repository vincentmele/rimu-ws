//! Servers of two workers driven by datagrams from many addresses, for the fuzzer and for tests.
//!
//! The bytes of the input are read as a script. The datagrams are made here: Initial packets that
//! the server opens (their keys come from the destination CID) with a genuine or damaged
//! ClientHello, in new flows and as the answer to a Retry, repeated and coalesced, 1-RTT packets
//! to the CIDs of the server and to CIDs that are not its own, packets of unknown versions, and
//! any bytes; from eight addresses, two of which are real client connections that complete their
//! handshakes if nothing stops them, and that a NAT moves to another port or IP address now and
//! then (RFC 9000 section 9.3): a real client gets what is sent to its current address only. Retry
//! is on for part of the scripts (the limits on handshakes are small ones). The script also lets
//! time pass and shuts the server down.
//!
//! Whatever the script is, the endpoints must hold these:
//!
//! - they never panic;
//! - before an address is validated (a Retry token of it came back, its handshake completed, or the
//!   server validated the new address of a real client) the server sends it at most three times
//!   the bytes it received from it (RFC 9000 sections 8.1 and 9.3.1), counted on the datagrams that
//!   leave;
//! - the handshakes under way and the connections stay within the limits, and the first never
//!   exceed the second;
//! - a CONNECTION_CLOSE that a connection owes has an error code of RFC 9000 section 20.1 or one
//!   of the codes that the limits name;
//! - once the endpoints are aborted, no connection and no CID is left.

use crate::{
  quic::{
    Cid, ConnParams, DatagramMeta, Endpoint, EndpointKeys, FlushOutcome, PacketTy, QuicLimits,
    QuicParams, QuicConn, RecvOutcome, Space, TxArena, VARINT_MAX, WorkerLoads, encode_varint,
    initial_keys, parse_header, protect,
    conn::check::{FuzzApp, Input, server_config},
  },
  rng::{ChaCha20, Rng as _},
  sync::Arc,
  tls::{QuicTls, SkCtx, UnverifiedCtx},
};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const SERVER_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8443);
const MAX_ACTIONS: usize = 128;
const WORKERS: u8 = 2;
/// The ClientHellos that are made once per script.
const HELLOS: usize = 4;
/// The addresses of the clients that the script has: the first two are real clients.
const PEERS: u8 = 8;

type Server = Endpoint<FuzzApp, ChaCha20, SkCtx>;
type Client = QuicConn<FuzzApp, ChaCha20, UnverifiedCtx, true>;

/// The address that a NAT gives real client `idx` for `nth` 1 (another port) or 2 (another IP
/// address), or the one of its handshake for 0.
fn rebound(idx: u8, nth: u8) -> SocketAddr {
  let first = peer(idx);
  match nth % 3 {
    0 => first,
    1 => SocketAddr::new(first.ip(), first.port().wrapping_add(1_000)),
    _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, idx)), first.port()),
  }
}

fn peer(idx: u8) -> SocketAddr {
  let idx = idx % PEERS;
  let ip = if idx % 3 == 2 {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, u16::from(idx)))
  } else {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, idx))
  };
  SocketAddr::new(ip, 40_000 + u16::from(idx))
}

/// What the server and one address have exchanged.
#[derive(Clone, Copy, Debug, Default)]
struct Flow {
  received: u64,
  sent: u64,
  validated: bool,
}

/// A Retry that was sent to an address: where to go and the token to bring.
#[derive(Clone, Debug)]
struct RetryOf {
  hello: usize,
  scid: Vec<u8>,
  token: Vec<u8>,
  retry_scid: Vec<u8>,
}

struct Harness {
  // The addresses of the two real clients now
  client_addrs: [SocketAddr; 2],
  clients: Vec<(u8, Client, FuzzApp)>,
  client_pools: crate::quic::pools::QuicPools,
  client_tx: TxArena,
  flows: BTreeMap<SocketAddr, Flow>,
  hellos: Vec<(Vec<u8>, Vec<u8>)>,
  known_cids: Vec<Vec<u8>>,
  last: Vec<u8>,
  limits: QuicLimits,
  max_conns: u32,
  now_us: u64,
  retries: BTreeMap<SocketAddr, RetryOf>,
  rng: ChaCha20,
  servers: Vec<(Server, FuzzApp, TxArena)>,
  shut: bool,
}

fn put_varint(out: &mut Vec<u8>, value: u64) {
  let mut buffer = [0; 8];
  let len = encode_varint(value.min(VARINT_MAX), &mut buffer).unwrap();
  out.extend_from_slice(&buffer[..len]);
}

/// An Initial packet of a client to `dcid` from `scid` with `token`, packet number `pn`, whose
/// CRYPTO frame carries `crypto` at `offset`, padded to 1,200 bytes if `pad`.
fn initial_packet(
  (dcid, scid): (&[u8], &[u8]),
  token: &[u8],
  pn: u32,
  (offset, crypto): (u64, &[u8]),
  pad: bool,
) -> Vec<u8> {
  let mut payload = vec![0x06];
  put_varint(&mut payload, offset);
  put_varint(&mut payload, crypto.len() as u64);
  payload.extend_from_slice(crypto);
  let mut out = vec![0xc3, 0, 0, 0, 1];
  out.push(u8::try_from(dcid.len()).unwrap_or(0));
  out.extend_from_slice(dcid);
  out.push(u8::try_from(scid.len()).unwrap_or(0));
  out.extend_from_slice(scid);
  put_varint(&mut out, token.len() as u64);
  out.extend_from_slice(token);
  let header_len = out.len() + 2 + 4;
  let payload_len =
    if pad { payload.len().max(1200usize.saturating_sub(header_len + 16)) } else { payload.len() };
  let length = u16::try_from(4 + payload_len + 16).unwrap_or(0) | 0x4000;
  out.extend_from_slice(&length.to_be_bytes());
  let pn_offset = out.len();
  out.extend_from_slice(&pn.to_be_bytes());
  out.extend_from_slice(&payload);
  out.resize(pn_offset + 4 + payload_len + 16, 0);
  let Ok(keys) = initial_keys(dcid, false) else {
    return out;
  };
  match protect(&keys.local, &mut out, pn_offset, u64::from(pn), 4, payload_len) {
    Ok(len) => out.truncate(len),
    Err(_) => {}
  }
  out
}

impl Harness {
  fn new(input: &mut Input<'_>) -> Self {
    let mut rng = ChaCha20::from_key([input.byte(); 32]);
    let mut limits = QuicLimits::default();
    limits.retry_above_half_open = [0, 2, 64][usize::from(input.byte() % 3)];
    limits.max_half_open_per_worker = [3, 8, 256][usize::from(input.byte() % 3)];
    limits.stateless_reset_per_sec = [1, 5, 100][usize::from(input.byte() % 3)];
    let max_conns = [4, 16, 256][usize::from(input.byte() % 3)];
    let params = QuicParams::default()
      .set_limits(limits)
      .set_max_conns_per_worker(max_conns)
      .set_cid_steering(input.byte() % 4 != 0)
      .set_balance(input.byte() % 2 == 0)
      .set_handshake_timeout_ms(if input.byte() % 2 == 0 { 500 } else { 10_000 });
    let keys = Arc::new(EndpointKeys::new(&mut rng));
    let loads = Arc::new(WorkerLoads::new(WORKERS));
    let tls = server_config();
    let servers = (0..WORKERS)
      .map(|worker| {
        let endpoint = Endpoint::new(
          params,
          worker,
          WORKERS,
          Arc::clone(&tls),
          &mut rng,
          Some(Arc::clone(&loads)),
          Arc::clone(&keys),
        )
        .unwrap();
        (endpoint, FuzzApp::default(), TxArena::new(TxArena::DEFAULT_BYTES).unwrap())
      })
      .collect();
    let mut hellos = Vec::new();
    for _ in 0..HELLOS {
      let mut cid = [0; 8];
      rng.fill_slice(&mut cid);
      let mut tp = [0; 256];
      let len = ConnParams::default()
        .transport_params(Cid::new(&cid).unwrap(), None)
        .encode(&mut tp)
        .unwrap();
      let tls: QuicTls<true, ChaCha20, UnverifiedCtx> =
        QuicTls::new_client("localhost", b"h3", &tp[..len], &mut rng).unwrap();
      let hello = tls.output(Space::Initial).to_vec();
      hellos.push((cid.to_vec(), hello));
    }
    Self {
      client_addrs: [peer(0), peer(1)],
      clients: Vec::new(),
      client_pools: crate::quic::pools::QuicPools::new(),
      client_tx: TxArena::new(64 * 1500).unwrap(),
      flows: BTreeMap::new(),
      hellos,
      known_cids: Vec::new(),
      last: Vec::new(),
      limits,
      max_conns,
      now_us: 1_000_000,
      retries: BTreeMap::new(),
      rng,
      servers,
      shut: false,
    }
  }

  /// Gives `datagram` from `from` to the worker that the CID picks, and to the one it forwards to.
  fn deliver(&mut self, datagram: &mut Vec<u8>, from: SocketAddr, validated: bool) {
    self.last.clone_from(datagram);
    let flow = self.flows.entry(from).or_default();
    flow.received = flow.received.saturating_add(datagram.len() as u64);
    flow.validated |= validated;
    let byte = if datagram.first().is_some_and(|el| el & 0x80 != 0) { 6 } else { 1 };
    let worker = datagram.get(byte).map_or(0, |el| usize::from(*el) % usize::from(WORKERS));
    let meta = DatagramMeta { peer: from, local: None, segment_size: None };
    let now_us = self.now_us;
    let Some((server, app, _)) = self.servers.get_mut(worker) else {
      return;
    };
    let rslt = server.recv(now_us, datagram, meta, app);
    if let RecvOutcome::Forward { worker } = rslt
      && let Some((target, app, _)) = self.servers.get_mut(usize::from(worker))
    {
      target.recv_forwarded(now_us, datagram, meta, app);
    }
  }

  /// Flushes both workers; their datagrams go to the real clients or are looked at.
  fn flush(&mut self) {
    let now_us = self.now_us;
    for idx in 0..self.servers.len() {
      for _ in 0..4 {
        let Some((server, app, tx)) = self.servers.get_mut(idx) else {
          break;
        };
        let outcome = server.flush(now_us, tx, app);
        let mut out = Vec::new();
        loop {
          let next = tx.pending().next().map(|train| {
            let segment = usize::from(train.segment_size).max(1);
            for datagram in train.bytes.chunks(segment) {
              out.push((train.peer, datagram.to_vec()));
            }
            train.id
          });
          let Some(id) = next else {
            break;
          };
          tx.mark_submitted(id);
          tx.release(id);
        }
        for (to, mut datagram) in out {
          self.sent(to, &mut datagram);
        }
        if outcome == FlushOutcome::Done {
          break;
        }
      }
    }
  }

  /// A datagram of the server to `to`.
  fn sent(&mut self, to: SocketAddr, datagram: &mut Vec<u8>) {
    let flow = self.flows.entry(to).or_default();
    flow.sent = flow.sent.saturating_add(datagram.len() as u64);
    if let Ok(header) = parse_header(datagram, 8) {
      match header.ty {
        PacketTy::Initial => {
          if self.known_cids.len() < 64 {
            self.known_cids.push(header.scid.to_vec());
          }
        }
        PacketTy::Retry => {
          let hello = self.hellos.iter().position(|el| !el.1.is_empty()).unwrap_or(0);
          let scid = self.hellos.get(hello).map(|el| el.0.clone()).unwrap_or_default();
          let retry = RetryOf {
            hello,
            scid,
            token: header.token.to_vec(),
            retry_scid: header.scid.to_vec(),
          };
          let _old = self.retries.insert(to, retry);
        }
        _ => {}
      }
    }
    // The real clients get what is theirs, at their address now
    let now_us = self.now_us;
    let addrs = self.client_addrs;
    for (idx, client, app) in &mut self.clients {
      if addrs.get(usize::from(*idx)) == Some(&to) {
        let meta = DatagramMeta { peer: SERVER_ADDR, local: None, segment_size: None };
        let _rslt =
          client.recv_datagram(now_us, datagram, meta, app, &mut self.client_pools);
      }
    }
  }

  fn client_step(&mut self, input: &mut Input<'_>) {
    let which = input.byte() % 2;
    if !self.clients.iter().any(|el| el.0 == which) {
      let mut cid = [0; 8];
      let mut original = [0; 8];
      self.rng.fill_slice(&mut cid);
      self.rng.fill_slice(&mut original);
      let (cid, original) = (Cid::new(&cid).unwrap(), Cid::new(&original).unwrap());
      let params = ConnParams::default();
      let mut tp = [0; 256];
      let len = params.transport_params(cid, None).encode(&mut tp).unwrap();
      let tls = QuicTls::new_client("localhost", b"h3", &tp[..len], &mut self.rng).unwrap();
      if let Ok(conn) = QuicConn::new_client(
        &params,
        cid,
        original,
        SERVER_ADDR,
        tls,
        self.now_us,
        &mut self.client_pools,
      ) {
        self.clients.push((which, conn, FuzzApp::default()));
      }
    }
    let now_us = self.now_us;
    let mut out = Vec::new();
    for (idx, client, app) in &mut self.clients {
      if *idx != which {
        continue;
      }
      if input.byte() % 4 == 0 {
        client.with_ctx(now_us, &mut self.client_pools, |cx| {
          if let Ok(id) = cx.open_bidi() {
            let _rslt = cx.write(id, b"GET /", true);
          }
        });
      }
      // A NAT rebinding now and then
      if input.byte().is_multiple_of(8)
        && let Some(addr) = self.client_addrs.get_mut(usize::from(which))
      {
        *addr = rebound(which, input.byte());
      }
      let _rslt = client.flush(now_us, &mut self.client_tx, app, &mut self.client_pools);
      loop {
        let next = self.client_tx.pending().next().map(|train| {
          for datagram in train.bytes.chunks(usize::from(train.segment_size).max(1)) {
            out.push(datagram.to_vec());
          }
          train.id
        });
        let Some(id) = next else {
          break;
        };
        self.client_tx.mark_submitted(id);
        self.client_tx.release(id);
      }
    }
    let from = self.client_addrs.get(usize::from(which)).copied().unwrap_or_else(|| peer(which));
    for mut datagram in out {
      // A real client completes its handshake: the address of it is validated, another one once
      // the server validated it
      self.deliver(&mut datagram, from, from == peer(which));
      self.note_validated();
    }
  }

  // The addresses of the real clients that the server validated: that of the path of a connection
  // if it is, and the last validated one while it is not.
  fn note_validated(&mut self) {
    for (_, client, _) in &self.clients {
      for (server, _, _) in &self.servers {
        let Some(conn) = server.conn(client.peer_cid().as_slice()) else {
          continue;
        };
        let current = conn.address_validated().then(|| conn.peer_addr());
        for addr in current.into_iter().chain(conn.last_valid_peer()) {
          self.flows.entry(addr).or_default().validated = true;
        }
      }
    }
  }

  fn hello(&mut self, input: &mut Input<'_>) -> (Vec<u8>, Vec<u8>) {
    let idx = usize::from(input.byte()) % self.hellos.len();
    let (cid, mut hello) = self.hellos.get(idx).cloned().unwrap_or_default();
    if input.byte() % 4 == 3 {
      let at = usize::from(input.u16());
      let len = hello.len().max(1);
      if let Some(byte) = hello.get_mut(at % len) {
        *byte ^= input.byte() | 1;
      }
    }
    if input.byte() % 8 == 7 {
      hello.truncate(usize::from(input.u16()) % hello.len().max(1));
    }
    (cid, hello)
  }

  fn action(&mut self, input: &mut Input<'_>) {
    let from = peer(input.byte());
    match input.byte() % 16 {
      // A new flow: an Initial packet of a ClientHello
      0..=3 => {
        let (scid, hello) = self.hello(input);
        let mut dcid = [0; 20];
        self.rng.fill_slice(&mut dcid);
        let len = 8 + usize::from(input.byte()) % 13;
        let token = if input.byte() % 8 == 7 { input.sized(40).to_vec() } else { Vec::new() };
        let scid = if input.byte() % 8 == 7 { input.sized(21).to_vec() } else { scid };
        let pad = input.byte() % 8 != 7;
        let mut datagram =
          initial_packet((&dcid[..len], &scid), &token, 0, (0, &hello), pad);
        self.deliver(&mut datagram, from, false);
      }
      // The Initial packet that follows a Retry, with its token and its CID
      4 | 5 => {
        let Some(retry) = self.retries.get(&from).cloned() else {
          return;
        };
        let hello = self.hellos.get(retry.hello).map(|el| el.1.clone()).unwrap_or_default();
        let token = if input.byte() % 8 == 7 { input.sized(80).to_vec() } else { retry.token };
        let mut datagram =
          initial_packet((&retry.retry_scid, &retry.scid), &token, 1, (0, &hello), true);
        self.deliver(&mut datagram, from, true);
      }
      // The same datagram again, from the same address or another one
      6 => {
        let mut datagram = self.last.clone();
        let from = if input.byte() % 2 == 0 { from } else { peer(input.byte()) };
        self.deliver(&mut datagram, from, false);
      }
      // 1-RTT bytes to a CID of the server, with another worker maybe, or to one that is not
      7 | 8 => {
        let mut cid = match input.byte() % 3 {
          0 => self.known_cids.get(usize::from(input.byte())).cloned().unwrap_or_default(),
          1 => vec![input.byte() % WORKERS; 8],
          _ => vec![input.byte(); 8],
        };
        if let Some(first) = cid.first_mut()
          && input.byte() % 2 == 0
        {
          *first = input.byte() % WORKERS;
        }
        let mut datagram = vec![input.byte() | 0x40];
        datagram.extend_from_slice(&cid);
        let len = usize::from(input.u16()) % 1400;
        datagram.extend_from_slice(input.take(len));
        datagram.resize(datagram.len().max(usize::from(input.byte())), 0x5a);
        self.deliver(&mut datagram, from, false);
      }
      // A long header of a version that is not 1
      9 => {
        let mut datagram = vec![0xc0, input.byte(), input.byte(), input.byte(), input.byte(), 8];
        datagram.extend_from_slice(&[input.byte(); 8]);
        datagram.push(4);
        datagram.extend_from_slice(&[input.byte(); 4]);
        datagram.resize(1100 + usize::from(input.byte()), 0);
        self.deliver(&mut datagram, from, false);
      }
      // Two Initial packets in a datagram
      10 => {
        let (scid, hello) = self.hello(input);
        let dcid = [input.byte(); 8];
        let mut datagram = initial_packet((&dcid, &scid), &[], 0, (0, &hello), false);
        let second = initial_packet((&dcid, &scid), &[], 1, (0, &hello), true);
        datagram.extend(second);
        self.deliver(&mut datagram, from, false);
      }
      // Any bytes
      11 => {
        let mut datagram = input.sized(255).to_vec();
        datagram.extend_from_slice(input.sized(255));
        self.deliver(&mut datagram, from, false);
      }
      // The datagrams that are owed
      12 | 13 => self.flush(),
      // A real client
      14 => {
        self.client_step(input);
        self.flush();
      }
      // Time, and the end of the server
      _ => {
        let us = match input.byte() % 4 {
          0 => 1_000,
          1 => 100_000,
          2 => 600_000,
          _ => 20_000_000,
        };
        self.now_us = self.now_us.saturating_add(us);
        let now_us = self.now_us;
        for (server, app, _) in &mut self.servers {
          server.on_timeout(now_us, app);
        }
        for (_, client, app) in &mut self.clients {
          client.on_timeout(now_us, app, &mut self.client_pools);
        }
        self.flush();
        if input.byte() % 32 == 0 && !self.shut {
          self.shut = true;
          for (server, app, _) in &mut self.servers {
            server.begin_shutdown(now_us, app);
          }
        }
      }
    }
  }

  fn check(&mut self) {
    self.note_validated();
    for (server, _, _) in &self.servers {
      let stats = server.stats();
      assert!(stats.half_open <= stats.conns, "{stats:?}");
      assert!(stats.conns <= self.max_conns, "{} conns", stats.conns);
      assert!(
        stats.half_open <= self.limits.max_half_open_per_worker,
        "{} half-open",
        stats.half_open
      );
      for cid in &self.known_cids {
        let Some(conn) = server.conn(cid) else {
          continue;
        };
        if let Some((app, code)) = conn.close_code() {
          if app {
            assert!(code == 0x100 || code == self.limits.excessive_load_app_code, "{code:#x}");
          } else {
            assert!(code <= 0x10 || (0x100..=0x1ff).contains(&code), "{code:#x}");
          }
        }
      }
    }
    for (addr, flow) in &self.flows {
      assert!(
        flow.validated || flow.sent <= flow.received.saturating_mul(3),
        "{} bytes sent to {addr} for {} received",
        flow.sent,
        flow.received
      );
    }
  }

  fn tally(&self, reach: &mut Reach) {
    let (mut conns, mut half_open) = (0, 0);
    for (server, _, _) in &self.servers {
      let stats = server.stats();
      conns += stats.conns;
      half_open += stats.half_open;
      reach.resets = reach.resets.max(stats.resets);
      reach.retries = reach.retries.max(stats.retries);
    }
    reach.peak_conns = reach.peak_conns.max(conns);
    reach.peak_half_open = reach.peak_half_open.max(half_open);
    let confirmed = self
      .clients
      .iter()
      .filter(|el| el.1.state() == crate::quic::ConnState::Confirmed)
      .count();
    reach.confirmed = reach.confirmed.max(u32::try_from(confirmed).unwrap_or(0));
  }

  fn finish(&mut self) {
    for (_, client, app) in &mut self.clients {
      client.abort(app, &mut self.client_pools);
    }
    for (server, app, _) in &mut self.servers {
      server.abort_all(app);
      let stats = server.stats();
      assert_eq!((stats.conns, stats.half_open, server.our_cids()), (0, 0, 0));
    }
  }
}

/// Runs the bytes as a script against two endpoints, panicking if they break a rule of the
/// module.
#[inline]
pub fn run(data: &[u8]) {
  let _reach = run_reach(data);
}

/// What a script got the endpoints to do: Retry packets, stateless resets and Version Negotiation
/// packets sent, connections that were open at once, and real clients that were confirmed.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Reach {
  pub(crate) confirmed: u32,
  pub(crate) peak_conns: u32,
  pub(crate) peak_half_open: u32,
  pub(crate) resets: u64,
  pub(crate) retries: u64,
}

pub(crate) fn run_reach(data: &[u8]) -> Reach {
  let mut reach = Reach::default();
  let mut input = Input::new(data);
  let mut harness = Harness::new(&mut input);
  for _ in 0..MAX_ACTIONS {
    if input.is_empty() {
      break;
    }
    harness.action(&mut input);
    harness.check();
    harness.tally(&mut reach);
  }
  harness.flush();
  harness.check();
  harness.tally(&mut reach);
  harness.finish();
  reach
}

#[cfg(test)]
mod tests {
  use super::run;
  use alloc::vec::Vec;

  // What the scripts of the directory in `FUZZ_CORPUS` reach, by hand:
  // `FUZZ_CORPUS=wtx-fuzz/corpus/quic_endpoint cargo test ... -- --ignored corpus_reach`.
  #[ignore = "reads a corpus"]
  #[test]
  fn corpus_reach() {
    let dir = std::env::var("FUZZ_CORPUS").unwrap();
    let (mut files, mut confirmed, mut retried, mut reset, mut refused_peak) = (0, 0, 0, 0, 0);
    let mut peak = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
      let reach = super::run_reach(&std::fs::read(entry.unwrap().path()).unwrap());
      files += 1;
      confirmed += u32::from(reach.confirmed > 0);
      retried += u32::from(reach.retries > 0);
      reset += u32::from(reach.resets > 0);
      refused_peak += u32::from(reach.peak_half_open > 2);
      peak = peak.max(reach.peak_conns);
    }
    std::println!(
      "{files} scripts: {confirmed} with a confirmed client, {retried} with a Retry, {reset} with a stateless reset, {refused_peak} with more than 2 half-open at once, {peak} connections at most"
    );
  }

  // The input that stopped the first run of the target: the datagrams of an Initial packet of one
  // flow repeated from other addresses counted for the limit of the first address, which was sent
  // 3,693 bytes for 1,200 (RFC 9000 section 8.1).
  #[cfg_attr(miri, ignore)]
  #[test]
  fn datagrams_repeated_from_other_addresses_do_not_raise_the_limit() {
    let hex = concat!(
      "0601bcc5cee99605000076000000020202020101ffffb66a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a696969696969",
      "696969696969696969696969696969296969696969696969696969696969696969696969696969696969696969696969",
      "6969696969696969696969696a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a",
      "6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6969696a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6ab6b6b6b6",
      "b6b6b6b6b6b6b6b6b6b6b6000c030003000000b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6",
      "b6b6b6b6b6b6b6b6b6b6b72fb6b6b6b6b6b6bfb6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b637b6b6",
      "b6b6b6b6b4b6b6ffff00000c000f0300000f0300000f0100000f0200007e",
    );
    let data: Vec<u8> = (0..hex.len() / 2)
      .map(|idx| u8::from_str_radix(&hex[idx * 2..idx * 2 + 2], 16).unwrap())
      .collect();
    run(&data);
  }

  // Rule: whatever the script is, the endpoints hold the rules of the module.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn generated_scripts_do_not_break_the_endpoints() {
    let mut state = 0x1234_5678_9abc_def1u64;
    let mut next = || {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      state
    };
    for _ in 0..200 {
      let len = usize::try_from(next() % 500).unwrap();
      let data: Vec<u8> = (0..len).map(|_| u8::try_from(next() & 0xff).unwrap()).collect();
      run(&data);
    }
  }
}
