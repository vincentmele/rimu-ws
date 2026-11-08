//! In-process harness for connection tests: a client and a server connection joined by a fake
//! network ([`Link`]) and a fake clock.
//!
//! Datagrams go from the [`TxArena`] of one side to [`QuicConn::recv_datagram`] of the other,
//! copied through a buffer that is allocated once. Each side has its own pools and arena, so that a
//! test can watch the allocations of the server alone (see [`LinkOpts::counters`]).

use crate::{
  quic::{
    Cid, ConnParams, DatagramMeta, FlushOutcome, QuicApp, QuicConn, TxArena, pools::QuicPools,
  },
  rng::{ChaCha20, Rng as _},
  sync::{Arc, AtomicU64},
  tests::{_PUBLIC_KEY, _SECRET_KEY, _count_allocations_in},
  tls::{CipherSuite, QuicTls, SkCtx, TlsConfig, TlsCtxSk, UnverifiedCtx},
};
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

/// The address of the client of a [`Link`].
pub(crate) const CLIENT_ADDR: SocketAddr =
  SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 50_000);
/// The address of the server of a [`Link`].
pub(crate) const SERVER_ADDR: SocketAddr =
  SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8443);
// A transport parameter id reserved for greasing (RFC 9000 section 18.1), which peers skip
const GREASE_PARAM: u8 = 27;
// The size of the arenas of a link
const ARENA_BYTES: usize = 64 * 1500;
const MAX_STEPS: usize = 64;

/// The connection of the client of a [`Link`].
pub(crate) type ClientConn = QuicConn<TestApp, ChaCha20, UnverifiedCtx, true>;
/// The connection of the server of a [`Link`].
pub(crate) type ServerConn = QuicConn<TestApp, ChaCha20, SkCtx, false>;

/// An application that counts what the connection tells it.
#[derive(Debug, Default)]
pub(crate) struct TestApp {
  /// Calls of [`QuicApp::on_closed`].
  pub(crate) closed: u32,
  /// Calls of [`QuicApp::on_established`].
  pub(crate) established: u32,
}

impl QuicApp for TestApp {
  type ConnState = ();

  fn on_established(&mut self, _state: &mut ()) -> crate::Result<()> {
    self.established = self.established.wrapping_add(1);
    Ok(())
  }

  fn on_closed(&mut self, _state: &mut ()) {
    self.closed = self.closed.wrapping_add(1);
  }
}

/// The pools and the arena of a side, which can outlive a [`Link`].
#[derive(Debug)]
pub(crate) struct Parts {
  /// See [`QuicPools`].
  pub(crate) pools: QuicPools,
  /// See [`TxArena`].
  pub(crate) tx: TxArena,
}

impl Parts {
  /// Empty pools and a small arena.
  pub(crate) fn new() -> Self {
    Self { pools: QuicPools::new(), tx: TxArena::new(ARENA_BYTES).unwrap() }
  }
}

/// How to build a [`Link`].
#[derive(Clone, Debug)]
pub(crate) struct LinkOpts {
  /// The parameters of the client.
  pub(crate) client: ConnParams,
  /// The allocation counters of the server and of everything else, if allocations are counted.
  pub(crate) counters: Option<(&'static AtomicU64, &'static AtomicU64)>,
  /// Seeds the random numbers of the link.
  pub(crate) seed: u8,
  /// The parameters of the server.
  pub(crate) server: ConnParams,
  /// The TLS configuration of the server, made once and shared.
  pub(crate) server_config: Arc<TlsConfig<SkCtx>>,
  /// Bytes of an unknown transport parameter that the server sends, to make its flight longer.
  pub(crate) server_tp_padding: usize,
}

impl LinkOpts {
  /// Default parameters on both sides, with a server that offers only `suite` if given.
  pub(crate) fn new(suite: Option<CipherSuite>) -> Self {
    Self {
      client: ConnParams::default(),
      counters: None,
      seed: 1,
      server: ConnParams::default(),
      server_config: server_config(suite),
      server_tp_padding: 0,
    }
  }
}

/// One side of a [`Link`].
#[derive(Debug)]
pub(crate) struct Side<TCX, const IS_CLIENT: bool> {
  /// Its address.
  pub(crate) addr: SocketAddr,
  /// The application.
  pub(crate) app: TestApp,
  /// The connection.
  pub(crate) conn: QuicConn<TestApp, ChaCha20, TCX, IS_CLIENT>,
  // The counter of this side and the one of everything else
  counters: Option<(&'static AtomicU64, &'static AtomicU64)>,
  /// Pools and arena.
  pub(crate) parts: Parts,
}

impl<TCX, const IS_CLIENT: bool> Side<TCX, IS_CLIENT>
where
  TCX: TlsCtxSk,
{
  /// Flushes the connection into its arena.
  pub(crate) fn flush(&mut self, now_us: u64) -> FlushOutcome {
    self.enter();
    let rslt = self.conn.flush(now_us, &mut self.parts.tx, &mut self.app, &mut self.parts.pools);
    self.leave();
    rslt
  }

  /// Runs the timers of the connection.
  pub(crate) fn on_timeout(&mut self, now_us: u64) {
    self.enter();
    self.conn.on_timeout(now_us, &mut self.app, &mut self.parts.pools);
    self.leave();
  }

  /// Gives `datagram`, from `from`, to the connection.
  pub(crate) fn recv(&mut self, now_us: u64, datagram: &mut [u8], from: SocketAddr) {
    self.enter();
    let meta = DatagramMeta { peer: from, local: None, segment_size: None };
    let _rslt =
      self.conn.recv_datagram(now_us, datagram, meta, &mut self.app, &mut self.parts.pools);
    self.leave();
  }

  /// The datagrams that the arena holds, taken out of it.
  pub(crate) fn take_datagrams(&mut self) -> Vec<Vec<u8>> {
    let mut rslt = Vec::new();
    loop {
      let next = self.parts.tx.pending().next().map(|train| {
        rslt.extend(train.bytes.chunks(usize::from(train.segment_size)).map(<[u8]>::to_vec));
        train.id
      });
      let Some(id) = next else {
        return rslt;
      };
      self.parts.tx.mark_submitted(id);
      self.parts.tx.release(id);
    }
  }

  fn enter(&self) {
    if let Some((own, _)) = self.counters {
      _count_allocations_in(own);
    }
  }

  fn leave(&self) {
    if let Some((_, others)) = self.counters {
      _count_allocations_in(others);
    }
  }
}

/// A client and a server that exchange datagrams through their arenas, and a fake clock.
#[derive(Debug)]
pub(crate) struct Link {
  /// The client.
  pub(crate) client: Side<UnverifiedCtx, true>,
  /// The time of the fake clock.
  pub(crate) now_us: u64,
  scratch: Vec<u8>,
  /// The server.
  pub(crate) server: Side<SkCtx, false>,
}

impl Link {
  /// A client whose first datagram opened a server connection, which received it.
  pub(crate) fn new(opts: &LinkOpts) -> Self {
    Self::with_parts(opts, Parts::new(), Parts::new())
  }

  /// [`Self::new`] with pools and arenas that were used before.
  pub(crate) fn with_parts(opts: &LinkOpts, client_parts: Parts, server_parts: Parts) -> Self {
    let now_us = 1_000_000;
    let mut rng = ChaCha20::from_key([opts.seed; 32]);
    let mut client_cid = [0; 8];
    let mut original_dcid = [0; 8];
    rng.fill_slice(&mut client_cid);
    rng.fill_slice(&mut original_dcid);
    let client_cid = Cid::new(&client_cid).unwrap();
    let original_dcid = Cid::new(&original_dcid).unwrap();
    let mut client = Side {
      addr: CLIENT_ADDR,
      app: TestApp::default(),
      conn: client_conn(&opts.client, client_cid, original_dcid, &mut rng, now_us),
      counters: None,
      parts: client_parts,
    };
    assert_eq!(client.flush(now_us), FlushOutcome::Done);
    let mut first = client.take_datagrams();
    assert_eq!(first.len(), 1, "the first flight of the client is one datagram");
    // As the endpoint does: a server CID with the index of the worker in its first byte
    let mut server_cid = [0; 8];
    rng.fill_slice(&mut server_cid[1..]);
    let server_cid = Cid::new(&server_cid).unwrap();
    let server_seed = rng.next_value();
    let counters = opts.counters;
    if let Some((own, _)) = counters {
      _count_allocations_in(own);
    }
    let conn = server_conn(opts, server_cid, original_dcid, server_seed, now_us);
    if let Some((_, others)) = counters {
      _count_allocations_in(others);
    }
    let mut server =
      Side { addr: SERVER_ADDR, app: TestApp::default(), conn, counters, parts: server_parts };
    server.recv(now_us, &mut first[0], CLIENT_ADDR);
    Self { client, now_us, scratch: Vec::with_capacity(1 << 16), server }
  }

  /// Moves the clock forward by `us` and runs the timers that are due.
  pub(crate) fn advance(&mut self, us: u64) {
    self.now_us = self.now_us.wrapping_add(us);
    self.client.on_timeout(self.now_us);
    self.server.on_timeout(self.now_us);
  }

  /// The pools and arenas, for the next link.
  pub(crate) fn into_parts(self) -> (Parts, Parts) {
    (self.client.parts, self.server.parts)
  }

  /// Flushes both sides and delivers what they sent, until nothing moves anymore.
  pub(crate) fn run(&mut self) {
    for _ in 0..MAX_STEPS {
      if !self.step() {
        return;
      }
    }
    panic!("the link did not settle");
  }

  /// Flushes the client and the server, delivering what each sent to the other. Returns `false` if
  /// neither sent anything.
  pub(crate) fn step(&mut self) -> bool {
    let _ = self.client.flush(self.now_us);
    let to_server = self.deliver_to_server();
    let _ = self.server.flush(self.now_us);
    let to_client = self.deliver_to_client();
    to_server > 0 || to_client > 0
  }

  /// Delivers to the client what the server has in its arena. Returns the number of datagrams.
  pub(crate) fn deliver_to_client(&mut self) -> usize {
    transfer(self.now_us, &mut self.scratch, &mut self.server, &mut self.client)
  }

  /// Delivers to the server what the client has in its arena. Returns the number of datagrams.
  pub(crate) fn deliver_to_server(&mut self) -> usize {
    transfer(self.now_us, &mut self.scratch, &mut self.client, &mut self.server)
  }
}

/// A client connection on the client mode of the TLS stack, which sends its first Initial packet
/// to [`SERVER_ADDR`] with `original_dcid`.
pub(crate) fn client_conn(
  params: &ConnParams,
  local_cid: Cid,
  original_dcid: Cid,
  rng: &mut ChaCha20,
  now_us: u64,
) -> ClientConn {
  let mut tp = [0; 256];
  let len = params.transport_params(local_cid, None).encode(&mut tp).unwrap();
  let tls =
    QuicTls::new_client("localhost", b"h3", &tp[..len], ChaCha20::from_key(seed(rng))).unwrap();
  QuicConn::new_client(params, local_cid, original_dcid, SERVER_ADDR, tls, now_us).unwrap()
}

/// The TLS configuration of the test certificate, offering only `suite` if given.
pub(crate) fn server_config(suite: Option<CipherSuite>) -> Arc<TlsConfig<SkCtx>> {
  let mut config = TlsConfig::from_keys_pem(_PUBLIC_KEY, _SECRET_KEY).unwrap();
  if let Some(elem) = suite {
    let suites = config.cipher_suites_mut();
    suites.clear();
    suites.push(elem).unwrap();
  }
  Arc::new(config)
}

fn seed(rng: &mut ChaCha20) -> [u8; 32] {
  let mut rslt = [0; 32];
  rng.fill_slice(&mut rslt);
  rslt
}

// The connection that the endpoint makes for the first Initial packet of a client.
fn server_conn(
  opts: &LinkOpts,
  local_cid: Cid,
  original_dcid: Cid,
  seed: u32,
  now_us: u64,
) -> ServerConn {
  let mut tp = [0; 256];
  let len = opts.server.transport_params(local_cid, Some(original_dcid)).encode(&mut tp).unwrap();
  let mut key = [0; 32];
  key[..4].copy_from_slice(&seed.to_le_bytes());
  let rng = ChaCha20::from_key(key);
  let tls = if opts.server_tp_padding == 0 {
    QuicTls::new(&opts.server_config, &tp[..len], rng).unwrap()
  } else {
    let mut padded = tp[..len].to_vec();
    let padding = u16::try_from(opts.server_tp_padding).unwrap();
    padded.push(GREASE_PARAM);
    padded.extend_from_slice(&(0x4000 | padding).to_be_bytes());
    padded.resize(padded.len() + opts.server_tp_padding, 0x5a);
    QuicTls::new(&opts.server_config, &padded, rng).unwrap()
  };
  let meta = DatagramMeta { peer: CLIENT_ADDR, local: None, segment_size: None };
  QuicConn::new_server(&opts.server, local_cid, original_dcid.as_slice(), meta, tls, now_us)
    .unwrap()
}

// Moves the trains of `from` into `to`, one datagram at a time.
fn transfer<A, const AC: bool, B, const BC: bool>(
  now_us: u64,
  scratch: &mut Vec<u8>,
  from: &mut Side<A, AC>,
  to: &mut Side<B, BC>,
) -> usize
where
  A: TlsCtxSk,
  B: TlsCtxSk,
{
  let mut datagrams = 0;
  loop {
    let next = from.parts.tx.pending().next().map(|train| {
      scratch.clear();
      scratch.extend_from_slice(train.bytes);
      (train.id, usize::from(train.segment_size))
    });
    let Some((id, segment_size)) = next else {
      break;
    };
    from.parts.tx.mark_submitted(id);
    from.parts.tx.release(id);
    for datagram in scratch.chunks_mut(segment_size) {
      to.recv(now_us, datagram, from.addr);
      datagrams += 1;
    }
  }
  datagrams
}
