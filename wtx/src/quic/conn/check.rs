//! A client and a server connection driven by generated input, for the fuzzer and for tests.
//!
//! The bytes of the input are read as a script of actions: the datagrams of a real client
//! connection, delivered as they are or damaged, Initial packets that are made here (their keys
//! come from the destination CID, so the server opens them) with frames and ClientHello pieces,
//! 1-RTT and Handshake packets made with the keys of the client, with any frame, operations of the
//! application of the client (open, write, reset, stop sending, close), the passage of time, and
//! NAT rebindings: the client's address changes among four (two IP addresses, two ports), it gets
//! what the server sends to its current address only, and copies of its datagrams arrive first from
//! another address, as an on-path attacker sends them (RFC 9000 section 9.3.2).
//!
//! Whatever the script is, the server connection must hold these:
//!
//! - it never panics;
//! - it never sends more than three times the bytes it received before the address of the client
//!   is validated (RFC 9000 section 8.1), on its current path, and to every address, counted on the
//!   datagrams that leave until the server validated that address (sections 8.2.2, 9.3.1 and
//!   21.1.1.2);
//! - a CONNECTION_CLOSE of the transport that it owes has an error code of RFC 9000 section 20.1,
//!   which includes the TLS alerts of RFC 9001 section 4.8;
//! - the application is told once that the connection is established and once that it is closed;
//! - if the script only did what a correct client does (the datagrams delivered as they are, the
//!   operations of the application, time), the server does not close with an error.

use crate::{
  quic::{
    Cid, ConnCtx, ConnParams, ConnState, DatagramMeta, FlushOutcome, QuicApp, QuicConn, Space,
    StreamId, TransportParams, TxArena, VARINT_MAX, encode_varint, initial_keys, pools::QuicPools,
    protect,
  },
  rng::{ChaCha20, Rng as _},
  sync::Arc,
  tls::{QuicTls, SkCtx, TlsConfig, UnverifiedCtx},
};
use alloc::{
  collections::{BTreeMap, BTreeSet},
  vec,
  vec::Vec,
};
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

const CERT: &[u8] = include_bytes!("../../../../.certs/cert.pem");
const KEY: &[u8] = include_bytes!("../../../../.certs/key.pem");
const CLIENT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 50_000);
/// The addresses that a NAT gives the client: the first one, another port, another IP address and
/// both.
const CLIENT_ADDRS: [SocketAddr; 4] = [
  CLIENT_ADDR,
  SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 50_001),
  SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 50_000),
  SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 50_001),
];
const SERVER_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8443);
const ARENA_BYTES: usize = 64 * 1500;
/// The actions of a script, at most.
const MAX_ACTIONS: usize = 96;
/// The round trips of the settling at the end of a script, at most.
const MAX_ROUNDS: usize = 64;

std::thread_local! {
  static CONFIG: Arc<TlsConfig<SkCtx>> = Arc::new(TlsConfig::from_keys_pem(CERT, KEY).unwrap());
}

/// The TLS configuration of the test certificate, made once for each thread.
pub(crate) fn server_config() -> Arc<TlsConfig<SkCtx>> {
  CONFIG.with(Arc::clone)
}

/// The bytes of a script.
pub(crate) struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
  pub(crate) const fn new(bytes: &'a [u8]) -> Self {
    Self(bytes)
  }

  pub(crate) const fn is_empty(&self) -> bool {
    self.0.is_empty()
  }

  /// The next byte, zero once there are none.
  pub(crate) fn byte(&mut self) -> u8 {
    match self.0.split_first() {
      Some((first, rest)) => {
        self.0 = rest;
        *first
      }
      None => 0,
    }
  }

  /// The next `len` bytes, or the ones that are left.
  pub(crate) fn take(&mut self, len: usize) -> &'a [u8] {
    let (head, rest) = self.0.split_at(len.min(self.0.len()));
    self.0 = rest;
    head
  }

  /// The next byte as a length of at most `modulus - 1`, and then that many bytes.
  pub(crate) fn sized(&mut self, modulus: usize) -> &'a [u8] {
    let len = usize::from(self.byte()) % modulus;
    self.take(len)
  }

  pub(crate) fn u16(&mut self) -> u16 {
    u16::from_be_bytes([self.byte(), self.byte()])
  }

  /// A number, often one that sits at a boundary of the protocol.
  pub(crate) fn number(&mut self) -> u64 {
    match self.byte() % 12 {
      0 => 0,
      1 => 1,
      2 => u64::from(self.byte()),
      3 => u64::from(self.u16()),
      4 => u64::from(self.u16()) << 16 | u64::from(self.u16()),
      5 => (1 << 14) - 1,
      6 => 1 << 14,
      7 => (1 << 30) - 1,
      8 => (1 << 62) - 1,
      9 => 1 << 20,
      10 => u64::from(self.byte()) << 8,
      _ => u64::from(self.byte() % 8),
    }
  }

  /// A stream id: of the first streams of each kind, or any.
  pub(crate) fn stream_id(&mut self) -> u64 {
    match self.byte() % 10 {
      0 => 0,
      1 => 4,
      2 => 8,
      3 => 2,
      4 => 6,
      5 => 1,
      6 => 3,
      7 => 7,
      8 => u64::from(self.byte() % 64),
      _ => self.number(),
    }
  }
}

fn put_varint(out: &mut Vec<u8>, value: u64) {
  let mut buffer = [0; 8];
  let len = encode_varint(value.min(VARINT_MAX), &mut buffer).unwrap();
  out.extend_from_slice(&buffer[..len]);
}

/// The application of both sides of a [`Duo`] when HTTP/3 is not on top: what it does with the
/// data of a stream depends on its `mode`.
#[derive(Debug, Default)]
pub(crate) struct FuzzApp {
  pub(crate) calls: u64,
  pub(crate) closed: u32,
  pub(crate) established: u32,
  /// The streams that ended, if `record`.
  pub(crate) fins: BTreeSet<u64>,
  pub(crate) mode: u8,
  /// If what arrives is kept in `streams` (the first 1 MiB of it).
  pub(crate) record: bool,
  pub(crate) streams: BTreeMap<u64, Vec<u8>>,
}

impl QuicApp for FuzzApp {
  type ConnState = ();

  fn on_established(&mut self, cx: &mut ConnCtx<'_, ()>) -> crate::Result<()> {
    self.established = self.established.wrapping_add(1);
    if self.mode & 0b1000 != 0 {
      let id = cx.open_uni()?;
      cx.write(id, b"\x00fuzz", false)?;
    }
    Ok(())
  }

  fn on_stream_data(
    &mut self,
    cx: &mut ConnCtx<'_, ()>,
    id: StreamId,
    data: &[u8],
    fin: bool,
  ) -> crate::Result<()> {
    self.calls = self.calls.wrapping_add(1);
    if self.record {
      let kept: usize = self.streams.values().map(Vec::len).sum();
      if kept < 1 << 20 {
        self.streams.entry(id.0).or_default().extend_from_slice(data);
      }
      if fin {
        let _new = self.fins.insert(id.0);
      }
    }
    match self.mode % 6 {
      // Echo
      1 => {
        let _rslt = cx.write(id, data, fin);
      }
      // Answer at the end
      2 => {
        if fin {
          let _rslt = cx.write(id, b"ok", true);
        }
      }
      // Hold the last bytes until more come
      3 => {
        if !fin {
          cx.retain(data.len().min(100))?;
        }
      }
      // Fail now and then
      4 => {
        if self.calls % 7 == 0 {
          return Err(crate::Error::ProgrammingError);
        }
      }
      // Answer with much, and ask the peer to stop sending now and then
      5 => {
        if fin {
          let _rslt = cx.write(id, &[0x5a; 3000], true);
        } else if self.calls % 3 == 0 {
          cx.stop_sending(id, 7);
        }
      }
      _ => {}
    }
    Ok(())
  }

  fn on_stream_reset(
    &mut self,
    cx: &mut ConnCtx<'_, ()>,
    id: StreamId,
    code: u64,
  ) -> crate::Result<()> {
    if self.mode & 0b10000 != 0 {
      cx.reset(id, code);
    }
    Ok(())
  }

  fn on_stop_sending(&mut self, _: &mut ConnCtx<'_, ()>, _: StreamId, _: u64) -> crate::Result<()> {
    Ok(())
  }

  fn on_closed(&mut self, _: &mut ()) {
    self.closed = self.closed.wrapping_add(1);
  }
}

/// What a script got the server connection to do, for the report of what the corpus reaches.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Reach {
  /// The handshake was confirmed.
  pub(crate) confirmed: bool,
  /// The server connection closed with this CONNECTION_CLOSE (application, code).
  pub(crate) close: Option<(bool, u64)>,
  /// The server answered the client with at least one datagram.
  pub(crate) answered: bool,
  /// The server received 1-RTT packets that carried a key update.
  pub(crate) key_update: bool,
}

/// A client and a server that exchange datagrams through their arenas, on a clock of their own.
pub(crate) struct Duo<A>
where
  A: QuicApp,
{
  pub(crate) c_app: FuzzApp,
  pub(crate) client: QuicConn<FuzzApp, ChaCha20, UnverifiedCtx, true>,
  // The address of the client now
  client_addr: SocketAddr,
  c_pools: QuicPools,
  // What the server and each address exchanged: (received, sent, validated)
  flows: BTreeMap<SocketAddr, (u64, u64, bool)>,
  c_tx: TxArena,
  hello: Vec<u8>,
  pub(crate) now_us: u64,
  original_dcid: Cid,
  pub(crate) s_app: A,
  pub(crate) server: QuicConn<A, ChaCha20, SkCtx, false>,
  pub(crate) s_pools: QuicPools,
  s_tx: TxArena,
  server_cid: Cid,
  /// What the script got the server to do so far.
  pub(crate) reach: Reach,
  /// What the client has done that a correct client does not: the server may close with an error.
  pub(crate) tainted: bool,
}

/// The parameters of connections for the byte `preset`: the defaults, small windows and few
/// streams, key updates all the time, no pacing and a short idle timeout.
fn params(preset: u8) -> ConnParams {
  let mut rslt = ConnParams::default();
  match preset % 4 {
    1 => {
      rslt.stream_window = 4096;
      rslt.conn_window = 16 * 1024;
      rslt.max_streams_bidi = 4;
      rslt.max_streams_uni = 4;
    }
    2 => {
      rslt.stream_window = 1 << 16;
      rslt.conn_window = 1 << 18;
      rslt.key_update_threshold = 12;
    }
    3 => {
      rslt.pacing = false;
      rslt.max_idle_timeout_ms = 2_000;
      rslt.bodies_round_robin = true;
    }
    _ => {}
  }
  rslt
}

impl<A> Duo<A>
where
  A: QuicApp,
{
  /// A client whose first datagram is not sent yet, and the server connection that it opens.
  /// `seed` seeds the random numbers, `presets` choose the parameters of the client and of the
  /// server and `dcid_len` is the length of the first destination CID, 8 to 20.
  pub(crate) fn new(seed: u8, presets: (u8, u8), dcid_len: u8, server_app: A) -> Self {
    let now_us = 1_000_000;
    let mut rng = ChaCha20::from_key([seed; 32]);
    let mut client_cid = [0; 8];
    let mut original = [0; 20];
    let original_len = 8 + usize::from(dcid_len) % 13;
    rng.fill_slice(&mut client_cid);
    rng.fill_slice(&mut original);
    let client_cid = Cid::new(&client_cid).unwrap();
    let original_dcid = Cid::new(&original[..original_len]).unwrap();
    let mut server_cid = [0; 8];
    rng.fill_slice(&mut server_cid[1..]);
    let server_cid = Cid::new(&server_cid).unwrap();

    let (client_params, server_params) = (params(presets.0), params(presets.1));
    let mut c_pools = QuicPools::new();
    let mut tp = [0; 256];
    let len = client_params.transport_params(client_cid, None).encode(&mut tp).unwrap();
    let tls = QuicTls::new_client("localhost", b"h3", &tp[..len], &mut rng).unwrap();
    let client = QuicConn::new_client(
      &client_params,
      client_cid,
      original_dcid,
      SERVER_ADDR,
      tls,
      now_us,
      &mut c_pools,
    )
    .unwrap();
    let hello =
      client.tls.as_ref().map(|el| el.output(Space::Initial).to_vec()).unwrap_or_default();

    let mut s_pools = QuicPools::new();
    let mut server_tp: TransportParams =
      server_params.transport_params(server_cid, Some(original_dcid));
    server_tp.stateless_reset_token = Some([7; 16]);
    let len = server_tp.encode(&mut tp).unwrap();
    let config = CONFIG.with(Arc::clone);
    let tls = QuicTls::new(&config, &tp[..len], &mut rng).unwrap();
    let meta = DatagramMeta { peer: CLIENT_ADDR, local: None, segment_size: None };
    let server = QuicConn::new_server(
      &server_params,
      server_cid,
      original_dcid.as_slice(),
      meta,
      tls,
      now_us,
      &mut s_pools,
      false,
    )
    .unwrap();
    Self {
      c_app: FuzzApp::default(),
      client,
      client_addr: CLIENT_ADDR,
      c_pools,
      flows: BTreeMap::new(),
      c_tx: TxArena::new(ARENA_BYTES).unwrap(),
      hello,
      now_us,
      original_dcid,
      s_app: server_app,
      server,
      s_pools,
      s_tx: TxArena::new(ARENA_BYTES).unwrap(),
      server_cid,
      reach: Reach::default(),
      tainted: false,
    }
  }

  fn take(tx: &mut TxArena) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut rslt = Vec::new();
    loop {
      let next = tx.pending().next().map(|train| {
        let peer = train.peer;
        let segment = usize::from(train.segment_size).max(1);
        rslt.extend(train.bytes.chunks(segment).map(|el| (peer, el.to_vec())));
        train.id
      });
      let Some(id) = next else {
        return rslt;
      };
      tx.mark_submitted(id);
      tx.release(id);
    }
  }

  /// The datagrams that the client has to send.
  pub(crate) fn flush_client(&mut self) -> Vec<Vec<u8>> {
    let mut rslt = Vec::new();
    for _ in 0..4 {
      let outcome =
        self.client.flush(self.now_us, &mut self.c_tx, &mut self.c_app, &mut self.c_pools);
      rslt.extend(Self::take(&mut self.c_tx).into_iter().map(|el| el.1));
      if outcome == FlushOutcome::Done {
        break;
      }
    }
    rslt
  }

  /// The datagrams that the server has to send, with the addresses that they go to.
  pub(crate) fn flush_server(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut rslt = Vec::new();
    for _ in 0..4 {
      let outcome =
        self.server.flush(self.now_us, &mut self.s_tx, &mut self.s_app, &mut self.s_pools);
      for (to, datagram) in Self::take(&mut self.s_tx) {
        let flow = self.flows.entry(to).or_default();
        flow.1 = flow.1.saturating_add(datagram.len() as u64);
        rslt.push((to, datagram));
      }
      if outcome == FlushOutcome::Done {
        break;
      }
    }
    rslt
  }

  /// Gives the first datagram of the client to the server.
  pub(crate) fn start(&mut self) {
    for mut datagram in self.flush_client() {
      self.to_server(&mut datagram);
    }
  }

  /// Runs `f` with the context of the connection of the client, as its application does outside
  /// of the callbacks.
  pub(crate) fn with_client_ctx<R>(
    &mut self,
    now_us: u64,
    f: impl FnOnce(&mut ConnCtx<'_, ()>) -> R,
  ) -> R {
    self.client.with_ctx(now_us, &mut self.c_pools, f)
  }

  /// The CONNECTION_CLOSE that the server owes, while it is closing: (application, code).
  pub(crate) fn server_close(&self) -> Option<(bool, u64)> {
    (self.server.state() == ConnState::Closing)
      .then_some((self.server.close.app, self.server.close.code))
  }

  /// Gives `datagram` to the server, from the address of the client.
  pub(crate) fn to_server(&mut self, datagram: &mut [u8]) {
    self.to_server_from(datagram, self.client_addr);
  }

  /// Gives `datagram` to the server, from `from`.
  fn to_server_from(&mut self, datagram: &mut [u8], from: SocketAddr) {
    let flow = self.flows.entry(from).or_default();
    flow.0 = flow.0.saturating_add(datagram.len() as u64);
    let meta = DatagramMeta { peer: from, local: None, segment_size: None };
    let _rslt =
      self.server.recv_datagram(self.now_us, datagram, meta, &mut self.s_app, &mut self.s_pools);
    self.note_validated();
  }

  // The addresses that the server validated so far: that of its path if it is, and the last
  // validated one while it is not.
  fn note_validated(&mut self) {
    let server = &self.server;
    let current = server.address_validated.then_some(server.peer);
    let last = server.last_valid_peer();
    for addr in current.into_iter().chain(last) {
      self.flows.entry(addr).or_default().2 = true;
    }
  }

  /// Gives `datagram`, which the server sent to `to`, to the client, if that is its address now.
  pub(crate) fn to_client(&mut self, to: SocketAddr, datagram: &mut [u8]) {
    if to != self.client_addr {
      return;
    }
    let meta = DatagramMeta { peer: SERVER_ADDR, local: None, segment_size: None };
    let _rslt =
      self.client.recv_datagram(self.now_us, datagram, meta, &mut self.c_app, &mut self.c_pools);
  }

  /// Moves the clock forward by `us` and runs what is due on both sides.
  pub(crate) fn advance(&mut self, us: u64) {
    self.now_us = self.now_us.saturating_add(us);
    self.client.on_timeout(self.now_us, &mut self.c_app, &mut self.c_pools);
    self.server.on_timeout(self.now_us, &mut self.s_app, &mut self.s_pools);
  }

  /// Exchanges what both sides have to send, as it is, until nothing moves; at most `rounds`
  /// times.
  pub(crate) fn exchange(&mut self, rounds: usize) {
    for _ in 0..rounds {
      let mut to_server = self.flush_client();
      let mut to_client = self.flush_server();
      if to_server.is_empty() && to_client.is_empty() {
        return;
      }
      for datagram in &mut to_server {
        self.to_server(datagram);
      }
      for (to, datagram) in &mut to_client {
        self.to_client(*to, datagram);
      }
    }
  }

  /// [`Self::exchange`], jumping to the next timer when it is quiet; at most `rounds` times.
  pub(crate) fn settle(&mut self, rounds: usize) {
    for _ in 0..rounds {
      let mut to_server = self.flush_client();
      let mut to_client = self.flush_server();
      if to_server.is_empty() && to_client.is_empty() {
        let next =
          [self.client.next_deadline(), self.server.next_deadline()].into_iter().flatten().min();
        match next {
          Some(at) if at > self.now_us => self.advance(at - self.now_us),
          Some(_) => self.advance(1),
          None => return,
        }
        continue;
      }
      for datagram in &mut to_server {
        self.to_server(datagram);
      }
      for (to, datagram) in &mut to_client {
        self.to_client(*to, datagram);
      }
    }
  }

  /// A packet of the client, made here: `payload` in `space`, to `dcid` from `scid`, with the
  /// packet number `pn_shift` away from the next one of the client, `pn_len` bytes of it, and
  /// padded to 1,200 bytes if `pad`. The keys are those of the client, or, for an Initial packet
  /// whose keys are gone, the ones that the destination CID of the first flight gives. `None` if
  /// there are no keys.
  fn packet(
    &mut self,
    space: Space,
    (dcid, scid): (&Cid, &Cid),
    token: &[u8],
    (pn_shift, pn_len): (i8, usize),
    reserved: u8,
    (payload, pad): (&[u8], bool),
  ) -> Option<Vec<u8>> {
    let conn = &mut self.client;
    let key_phase = conn.key.local_phase;
    let sp = super::space_mut(&mut conn.data, &mut conn.handshake, space);
    let (next, derived) = match &sp {
      Some(sp) => (sp.sent.next_pn(), None),
      None if space == Space::Initial => {
        (0, Some(initial_keys(self.original_dcid.as_slice(), false).ok()?))
      }
      None => return None,
    };
    let pn = next.saturating_add_signed(i64::from(pn_shift));
    let pn_len = pn_len.clamp(1, 4);
    let mut out = vec![0; 2048 + payload.len()];
    let (header_len, pn_offset, length_at) =
      super::write_header(&mut out, space, dcid, scid, (pn, pn_len), key_phase, token)?;
    out[0] |= reserved;
    let mut payload_len = payload.len();
    if pad {
      payload_len = payload_len.max(1200usize.saturating_sub(header_len + 16));
    }
    out.get_mut(header_len..header_len + payload.len())?.copy_from_slice(payload);
    if let Some(at) = length_at {
      let length = u16::try_from(pn_len + payload_len + 16).ok()? | 0x4000;
      out.get_mut(at..at + 2)?.copy_from_slice(&length.to_be_bytes());
    }
    let keys = match (sp, &derived) {
      (Some(sp), _) => {
        if pn_shift == 0 {
          // As if the client had sent it
          sp.sent.skip();
        }
        sp.keys.as_ref()?
      }
      (None, Some(keys)) => keys,
      (None, None) => return None,
    };
    let len = protect(&keys.local, &mut out, pn_offset, pn, pn_len, payload_len).ok()?;
    out.truncate(len);
    Some(out)
  }

  /// The frames of the next action of `input`, as bytes.
  fn frames(&self, input: &mut Input<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    let count = 1 + usize::from(input.byte() % 5);
    for _ in 0..count {
      match input.byte() % 26 {
        0 => out.resize(out.len() + usize::from(input.byte() % 64), 0),
        1 | 2 => out.push(0x01),
        3 => {
          // ACK, with ECN counts or not, and some ranges
          let ecn = input.byte() & 1;
          out.push(0x02 | ecn);
          put_varint(&mut out, input.number());
          put_varint(&mut out, u64::from(input.byte()));
          let ranges = input.byte() % 4;
          put_varint(&mut out, u64::from(ranges));
          put_varint(&mut out, u64::from(input.byte() % 8));
          for _ in 0..ranges {
            put_varint(&mut out, u64::from(input.byte() % 8));
            put_varint(&mut out, u64::from(input.byte() % 8));
          }
          if ecn == 1 {
            for _ in 0..3 {
              put_varint(&mut out, u64::from(input.byte()));
            }
          }
        }
        4 => {
          out.push(0x04);
          put_varint(&mut out, input.stream_id());
          put_varint(&mut out, input.number());
          put_varint(&mut out, input.number());
        }
        5 => {
          out.push(0x05);
          put_varint(&mut out, input.stream_id());
          put_varint(&mut out, input.number());
        }
        6..=8 => {
          // CRYPTO: a piece of the ClientHello, damaged or not, or any bytes
          out.push(0x06);
          let (from, len) = (usize::from(input.u16()), usize::from(input.byte()));
          let from = from % self.hello.len().max(1);
          let mut data: Vec<u8> = if input.byte() % 4 == 0 {
            input.take(len).to_vec()
          } else {
            self.hello.get(from..).unwrap_or_default().iter().take(len.max(8)).copied().collect()
          };
          if input.byte() % 4 == 0 {
            let at = usize::from(input.u16());
            let len = data.len().max(1);
            if let Some(byte) = data.get_mut(at % len) {
              *byte ^= input.byte() | 1;
            }
          }
          let offset = if input.byte() % 3 == 0 { input.number() } else { from as u64 };
          put_varint(&mut out, offset);
          put_varint(&mut out, data.len() as u64);
          out.extend_from_slice(&data);
        }
        9 => {
          out.push(0x07);
          let data = input.sized(40);
          put_varint(&mut out, data.len() as u64);
          out.extend_from_slice(data);
        }
        10..=12 => {
          // STREAM with an offset, a length and a FIN or not
          let flags = input.byte() & 0b111;
          out.push(0x08 | flags);
          put_varint(&mut out, input.stream_id());
          if flags & 0b100 != 0 {
            put_varint(&mut out, input.number());
          }
          let data = input.sized(256);
          if flags & 0b010 != 0 {
            let announced = if input.byte() % 16 == 0 { input.number() } else { data.len() as u64 };
            put_varint(&mut out, announced);
          }
          out.extend_from_slice(data);
        }
        13 => {
          out.push(0x10);
          put_varint(&mut out, input.number());
        }
        14 => {
          out.push(0x11);
          put_varint(&mut out, input.stream_id());
          put_varint(&mut out, input.number());
        }
        15 => {
          out.push(0x12 | (input.byte() & 1));
          put_varint(&mut out, input.number());
        }
        16 => {
          out.push(0x14);
          put_varint(&mut out, input.number());
        }
        17 => {
          out.push(0x15);
          put_varint(&mut out, input.stream_id());
          put_varint(&mut out, input.number());
        }
        18 => {
          out.push(0x16 | (input.byte() & 1));
          put_varint(&mut out, input.number());
        }
        19 => {
          out.push(0x18);
          put_varint(&mut out, input.number());
          put_varint(&mut out, input.number());
          let len = match input.byte() % 8 {
            0 => 0,
            1 => 21,
            _ => 8,
          };
          out.push(len);
          out.extend(core::iter::repeat_n(input.byte(), usize::from(len)));
          out.extend_from_slice(&[input.byte(); 16]);
        }
        20 => {
          out.push(0x19);
          put_varint(&mut out, input.number());
        }
        21 => {
          out.push(0x1a | (input.byte() & 1));
          out.extend_from_slice(&[input.byte(); 8]);
        }
        22 => {
          let app = input.byte() & 1;
          out.push(0x1c | app);
          put_varint(&mut out, input.number());
          if app == 0 {
            put_varint(&mut out, input.number());
          }
          let reason = input.sized(20);
          put_varint(&mut out, reason.len() as u64);
          out.extend_from_slice(reason);
        }
        23 => out.push(0x1e),
        24 => {
          // An unknown frame type
          put_varint(&mut out, input.number());
          out.extend_from_slice(input.sized(16));
        }
        _ => out.extend_from_slice(input.sized(256)),
      }
    }
    out
  }

  /// Damages `datagram` as `input` says: a byte flipped, a cut, a longer tail, a header byte
  /// changed or nothing left.
  fn damage(input: &mut Input<'_>, datagram: &mut Vec<u8>) {
    let at = usize::from(input.u16());
    let len = datagram.len().max(1);
    match input.byte() % 5 {
      0 => {
        if let Some(byte) = datagram.get_mut(at % len) {
          *byte ^= input.byte() | 1;
        }
      }
      1 => datagram.truncate(at % len),
      2 => datagram.extend_from_slice(input.sized(256)),
      3 => {
        if let Some(byte) = datagram.get_mut(at % len.min(32)) {
          *byte = input.byte();
        }
      }
      _ => datagram.clear(),
    }
  }

  /// Runs one action of `input`.
  pub(crate) fn action(&mut self, input: &mut Input<'_>) {
    match input.byte() % 14 {
      // The datagrams of the client, as they are
      0 => {
        for mut datagram in self.flush_client() {
          self.to_server(&mut datagram);
        }
      }
      // The same after a NAT rebinding of the client, which a correct client goes through
      1 => {
        if let Some(addr) = CLIENT_ADDRS.get(usize::from(input.byte() % 4)) {
          self.client_addr = *addr;
        }
        for mut datagram in self.flush_client() {
          self.to_server(&mut datagram);
        }
      }
      // The datagrams of the server, as they are
      2 | 3 => {
        for (to, mut datagram) in self.flush_server() {
          self.to_client(to, &mut datagram);
        }
      }
      // The datagrams of the client, damaged, repeated or lost
      4 => {
        self.tainted = true;
        for mut datagram in self.flush_client() {
          match input.byte() % 4 {
            0 => {}
            1 => Self::damage(input, &mut datagram),
            // A copy first, from the same address or from another one (RFC 9000 section 9.3.2)
            2 => {
              let mut twice = datagram.clone();
              let from = CLIENT_ADDRS.get(usize::from(input.byte() % 4)).copied();
              self.to_server_from(&mut twice, from.unwrap_or(self.client_addr));
            }
            _ => continue,
          }
          self.to_server(&mut datagram);
        }
      }
      // An Initial packet that the server opens, to the CID of the first flight or to another
      5 | 6 => {
        self.tainted = true;
        let dcid = match input.byte() % 4 {
          0 => self.server_cid,
          1 => Cid::new(input.sized(21)).unwrap_or_default(),
          _ => self.original_dcid,
        };
        let scid = if input.byte() % 2 == 0 {
          self.client.local_cid
        } else {
          Cid::new(&[input.byte(); 8]).unwrap_or_default()
        };
        let token = input.sized(4).to_vec();
        let pn_shift = i8::try_from(i16::from(input.byte() % 5) - 2).unwrap_or(0);
        let pn_len = usize::from(input.byte() % 5);
        let reserved = if input.byte() % 8 == 0 { 0x0c } else { 0 };
        let pad = input.byte() % 8 != 0;
        let payload = self.frames(input);
        if let Some(mut datagram) = self.packet(
          Space::Initial,
          (&dcid, &scid),
          &token,
          (pn_shift, pn_len),
          reserved,
          (&payload, pad),
        ) {
          self.to_server(&mut datagram);
        }
      }
      // Handshake and 1-RTT packets with the keys of the client
      7..=9 => {
        self.tainted = true;
        let space = if input.byte() % 4 == 0 { Space::Handshake } else { Space::Data };
        let dcid = if self.client.peer_cid_known { self.client.peer_cid } else { self.server_cid };
        let scid = self.client.local_cid;
        let pn_shift = i8::try_from(i16::from(input.byte() % 5) - 2).unwrap_or(0);
        let pn_len = usize::from(input.byte() % 5);
        let reserved = if input.byte() % 16 == 0 { 0x18 } else { 0 };
        let payload = self.frames(input);
        if let Some(mut datagram) =
          self.packet(space, (&dcid, &scid), &[], (pn_shift, pn_len), reserved, (&payload, false))
        {
          self.to_server(&mut datagram);
        }
      }
      // Bytes behind a short header to the CID of the server
      10 => {
        self.tainted = true;
        let mut datagram = vec![input.byte() | 0x40];
        datagram.extend_from_slice(self.server_cid.as_slice());
        let len = usize::from(input.u16() % 1400);
        datagram.extend_from_slice(input.take(len));
        self.to_server(&mut datagram);
      }
      // The application of the client
      11 => self.client_app(input),
      // Time
      12 => {
        let us = match input.byte() % 6 {
          0 => 1,
          1 => u64::from(input.byte()) * 100,
          2 => u64::from(input.u16()) * 100,
          3 => 25_000 + u64::from(input.byte()),
          4 => 1_000_000 + u64::from(input.u16()) * 10,
          _ => 31_000_000,
        };
        self.advance(us);
        self.settle(4);
      }
      // Round trips of what both sides have to send
      _ => self.exchange(usize::from(input.byte() % 8) + 1),
    }
  }

  /// An operation of the application of the client.
  fn client_app(&mut self, input: &mut Input<'_>) {
    let now_us = self.now_us;
    let op = input.byte() % 8;
    let id = input.stream_id();
    let fin = input.byte() % 2 == 0;
    let data = input.sized(2048).to_vec();
    let mode = input.byte();
    self.client.with_ctx(now_us, &mut self.c_pools, |cx| match op {
      0 => {
        if let Ok(id) = cx.open_bidi() {
          let _rslt = cx.write(id, &data, fin);
        }
      }
      1 => {
        if let Ok(id) = cx.open_uni() {
          let _rslt = cx.write(id, &data, fin);
        }
      }
      2 => {
        let _rslt = cx.write(StreamId(id), &data, fin);
      }
      3 => cx.reset(StreamId(id), u64::from(mode)),
      4 => cx.stop_sending(StreamId(id), u64::from(mode)),
      5 => cx.close(u64::from(mode), data.get(..data.len().min(8)).unwrap_or_default()),
      _ => {
        if let Ok(id) = cx.open_bidi() {
          // Enough bytes to run into the windows of the server
          let _rslt = cx.write(id, &[0x42; 6000], fin);
        }
      }
    });
    self.c_app.mode = mode;
  }

  /// Checks what must hold of the server whatever the script is.
  pub(crate) fn check(&mut self) {
    let server = &self.server;
    self.reach.confirmed |= server.state() == ConnState::Confirmed;
    self.reach.answered |= server.stats().datagrams_out > 0;
    self.reach.key_update |= server.key.remote_phase;
    if let Some(close) = self.server_close() {
      self.reach.close.get_or_insert(close);
    }
    let server = &self.server;
    if server.state() == ConnState::Closing && !server.close.app {
      let code = server.close.code;
      assert!(
        code <= 0x10 || (0x100..=0x1ff).contains(&code),
        "the server owes a CONNECTION_CLOSE with the code {code:#x}"
      );
      assert!(self.tainted, "the server closed ({code:#x}) after a script of a correct client");
    }
    if matches!(server.state(), ConnState::Handshake | ConnState::Confirmed | ConnState::Closing)
      && !server.address_validated
    {
      assert!(
        server.bytes_sent <= server.bytes_received.saturating_mul(3),
        "{} bytes sent for {} received",
        server.bytes_sent,
        server.bytes_received
      );
    }
    // An address that the server validated takes anything from then on
    self.note_validated();
    for (addr, (received, sent, validated)) in &self.flows {
      assert!(
        *validated || *sent <= received.saturating_mul(3),
        "{sent} bytes sent to {addr} for {received} received"
      );
    }
    assert!(self.c_app.closed <= 1 && self.c_app.established <= 1);
  }

  /// Gives everything back to the pools.
  pub(crate) fn finish(&mut self) {
    self.client.abort(&mut self.c_app, &mut self.c_pools);
    self.server.abort(&mut self.s_app, &mut self.s_pools);
  }

  /// Runs `input` as a script, checking after each action, and settles.
  pub(crate) fn script(&mut self, input: &mut Input<'_>) {
    for _ in 0..MAX_ACTIONS {
      if input.is_empty() {
        break;
      }
      self.action(input);
      self.check();
    }
    self.settle(MAX_ROUNDS);
    self.check();
  }
}

/// Runs the bytes as a script against a client and a server connection, panicking if the server
/// breaks a rule of the module.
#[inline]
pub fn run(data: &[u8]) {
  let _reach = run_reach(data);
}

/// [`run`], with what the script got the server to do and the calls of its application for stream
/// data.
pub(crate) fn run_reach(data: &[u8]) -> (Reach, u64) {
  let mut input = Input::new(data);
  let seed = input.byte();
  let presets = (input.byte(), input.byte());
  let dcid_len = input.byte();
  let mode = input.byte();
  let mut duo = Duo::new(seed, presets, dcid_len, FuzzApp { mode, ..FuzzApp::default() });
  // The application fails now and then in this mode: the server closes with an error
  duo.tainted = mode % 6 == 4;
  // The first datagram of the client, as it is, unless the script makes the Initial packets
  if mode & 0x80 == 0 {
    duo.start();
  } else {
    duo.tainted = true;
  }
  duo.script(&mut input);
  let rslt = (duo.reach, duo.s_app.calls);
  duo.finish();
  rslt
}

#[cfg(test)]
mod tests {
  use super::{Duo, FuzzApp, Space, put_varint, run};
  use crate::quic::ConnState;
  use alloc::vec::Vec;

  // Rule: a client that is not tainted completes the handshake with the server.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn faithful_exchange_confirms_both_sides() {
    let mut duo = Duo::new(1, (0, 0), 0, FuzzApp::default());
    duo.start();
    duo.exchange(16);
    assert_eq!(
      (duo.client.state(), duo.server.state()),
      (ConnState::Confirmed, ConnState::Confirmed)
    );
    assert_eq!((duo.c_app.established, duo.s_app.established), (1, 1));
    duo.check();
    duo.finish();
  }

  // Rule: an Initial packet that the script makes is opened by the server, and the CRYPTO frame in
  // it, a ClientHello in two pieces out of order, reaches the TLS bridge: the server answers with
  // its flight, which the real client then takes to complete the handshake.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn crafted_initial_packets_reach_the_tls_bridge() {
    let mut duo = Duo::new(2, (0, 0), 4, FuzzApp::default());
    let (client_cid, original) = (duo.client.local_cid, duo.original_dcid);
    let hello = duo.hello.clone();
    assert!(hello.len() > 100);
    let (head, tail) = hello.split_at(hello.len() / 2);
    for (offset, piece) in [(head.len(), tail), (0, head)] {
      let mut frame = Vec::from([0x06]);
      put_varint(&mut frame, offset as u64);
      put_varint(&mut frame, piece.len() as u64);
      frame.extend_from_slice(piece);
      let mut datagram = duo
        .packet(Space::Initial, (&original, &client_cid), &[], (0, 4), 0, (&frame, true))
        .unwrap();
      assert!(datagram.len() >= 1200);
      duo.to_server(&mut datagram);
      if offset != 0 {
        // Nothing but an acknowledgment
        let sent: usize = duo.flush_server().iter().map(|el| el.1.len()).sum();
        assert!(sent < 100, "the second half alone gives {sent} bytes");
      }
    }
    assert!(!duo.flush_server().is_empty(), "the whole ClientHello gives the flight of the server");
    duo.finish();
  }

  // What the scripts of the directory in `FUZZ_CORPUS` reach: run by hand to tell what a corpus
  // covers, `FUZZ_CORPUS=wtx-fuzz/corpus/quic_conn cargo test ... -- --ignored corpus_reach`.
  #[ignore = "reads a corpus"]
  #[test]
  fn corpus_reach() {
    let dir = std::env::var("FUZZ_CORPUS").unwrap();
    let mut tally = std::collections::BTreeMap::<alloc::string::String, u32>::new();
    let mut files = 0u32;
    for entry in std::fs::read_dir(dir).unwrap() {
      let data = std::fs::read(entry.unwrap().path()).unwrap();
      let (reach, calls) = super::run_reach(&data);
      files += 1;
      let mut hit = |name: alloc::string::String| *tally.entry(name).or_default() += 1;
      if reach.confirmed {
        hit("handshake confirmed".into());
      }
      if reach.answered {
        hit("server answered".into());
      }
      if reach.key_update {
        hit("peer key phase flipped".into());
      }
      if calls > 0 {
        hit("stream data reached the application".into());
      }
      match reach.close {
        Some((app, code)) => hit(alloc::format!("close app={app} code={code:#x}")),
        None => hit("no close owed".into()),
      }
    }
    std::println!("{files} scripts");
    for (name, count) in &tally {
      std::println!("{count:6} {name}");
    }
  }

  // Rule: whatever the script is, the server holds the rules of the module.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn generated_scripts_do_not_break_the_server() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      state
    };
    for round in 0..300 {
      let len = usize::try_from(next() % 600).unwrap();
      let mut data: Vec<u8> = (0..len).map(|_| u8::try_from(next() & 0xff).unwrap()).collect();
      if round % 2 == 0 {
        // The actions that a correct client takes: its datagrams, the server's, time and its own
        // application, and the first datagram as it is
        for (idx, byte) in data.iter_mut().enumerate().skip(5) {
          if idx % 2 == 0 {
            *byte = [0, 2, 13, 11][idx % 4];
          }
        }
        if let Some(mode) = data.get_mut(4) {
          *mode &= 0x7f;
        }
      }
      run(&data);
    }
  }
}
