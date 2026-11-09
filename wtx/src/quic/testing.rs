//! In-process harness for connection tests: a client and a server connection joined by a fake
//! network ([`Link`]) and a fake clock.
//!
//! Datagrams go from the [`TxArena`] of one side to [`QuicConn::recv_datagram`] of the other,
//! copied through a buffer that is allocated once. Each side has its own pools and arena, so that a
//! test can watch the allocations of the server alone (see [`LinkOpts::counters`]).
//!
//! With an [`Impairment`], the link is a lossy network instead: datagrams take time to arrive and
//! some are dropped, delivered out of order or twice ([`Link::step_impaired`]), and the clock moves
//! to the next arrival or timer when nothing else happens ([`Link::advance_to_next_event`]).

use crate::{
  quic::{
    BodyRef, Cid, ConnCtx, ConnParams, DatagramMeta, FlushOutcome, Frame, FrameWriter, QuicApp,
    QuicConn, QuicError, StreamId, TransportErrorCode, TransportParams, TxArena, pools::QuicPools,
  },
  rng::{ChaCha20, Rng as _},
  sync::{Arc, AtomicU64},
  tests::{_PUBLIC_KEY, _SECRET_KEY, _count_allocations_in},
  tls::{CipherSuite, QuicTls, SkCtx, TlsConfig, TlsCtxSk, UnverifiedCtx},
};
use alloc::{collections::BTreeMap, vec, vec::Vec};
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

/// What a lossy [`Link`] does to the datagrams that it carries, in each direction, with random
/// numbers from `seed`: each one takes `delay_us` to arrive, and is dropped, delivered after the
/// ones sent after it or delivered twice with these probabilities.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Impairment {
  /// The probability that a datagram is dropped.
  pub(crate) drop: f32,
  /// The probability that a datagram arrives after some sent after it.
  pub(crate) reorder: f32,
  /// The probability that a datagram arrives twice.
  pub(crate) duplicate: f32,
  /// The one-way delay.
  pub(crate) delay_us: u64,
  /// Seeds the random numbers.
  pub(crate) seed: u64,
}

impl Impairment {
  /// No faults, `delay_us` of one-way delay.
  pub(crate) const fn delay(delay_us: u64) -> Self {
    Self { drop: 0.0, reorder: 0.0, duplicate: 0.0, delay_us, seed: 1 }
  }
}

/// What a [`TestApp`] does with the data that arrives on a stream.
#[derive(Clone, Debug, Default)]
pub(crate) enum Behavior {
  /// Keeps everything in [`TestApp::streams`].
  #[default]
  Collect,
  /// Writes back what arrives, with the FIN when it arrives.
  Echo,
  /// Answers each request, once its FIN arrived, with these bytes and the FIN.
  Respond(&'static [u8]),
  /// Answers each request, once its FIN arrived, with these bytes and then the body, by
  /// reference, with the FIN.
  RespondBody(&'static [u8], BodyRef),
  /// By stream index modulo 3: `small` written by copy, the body by reference, `large` written by
  /// copy, with the FIN.
  Mixed {
    /// For the streams of index 0 modulo 3.
    small: &'static [u8],
    /// For the streams of index 1 modulo 3.
    body: BodyRef,
    /// For the streams of index 2 modulo 3.
    large: &'static [u8],
  },
  /// Keeps the lines (ended by `\n`, or by the FIN) in [`TestApp::lines`], and retains what is
  /// left of a line until the rest of it arrives.
  Lines,
  /// [`Self::Lines`] that only counts the lines, in [`TestApp::line_count`], and answers each
  /// request with `ok` and the FIN once its FIN arrived: it allocates nothing.
  LineCount,
}

/// How a [`TestApp`] fails on the first data that arrives.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Fail {
  /// With an error that closes with this transport code.
  Transport(TransportErrorCode),
  /// With an error that is not a QUIC close.
  Other,
  /// By closing with this application code, without an error.
  AppClose(u64),
}

/// What arrived on a stream, for [`Behavior::Collect`].
#[derive(Clone, Debug, Default)]
pub(crate) struct StreamLog {
  /// The bytes, in order.
  pub(crate) data: Vec<u8>,
  /// If the FIN arrived.
  pub(crate) fin: bool,
  /// The length and the FIN of every call.
  pub(crate) calls: Vec<(usize, bool)>,
}

/// An application that does what its [`Behavior`] says and counts what the connection tells it.
#[derive(Clone, Debug, Default)]
pub(crate) struct TestApp {
  /// What it does with the data that arrives.
  pub(crate) behavior: Behavior,
  /// Calls of [`QuicApp::on_closed`].
  pub(crate) closed: u32,
  /// Calls of [`QuicApp::on_established`].
  pub(crate) established: u32,
  /// How it fails, if it does.
  pub(crate) fail: Option<Fail>,
  /// Calls of [`QuicApp::on_stream_data`].
  pub(crate) calls: u64,
  /// The calls of [`QuicApp::on_stream_data`] that succeed before [`Self::fail`] applies.
  pub(crate) fail_after: u64,
  /// FINs that arrived.
  pub(crate) fins: u64,
  /// If it is the application of the server of a [`Link`], which sets it: the server answers a
  /// reset of the peer with a reset of its own sending part.
  pub(crate) is_server: bool,
  /// The lines of [`Behavior::LineCount`].
  pub(crate) line_count: u64,
  /// The lines of [`Behavior::Lines`].
  pub(crate) lines: Vec<Vec<u8>>,
  /// Calls of [`QuicApp::on_stream_reset`].
  pub(crate) resets: Vec<(StreamId, u64)>,
  /// Calls of [`QuicApp::on_stop_sending`].
  pub(crate) stops: Vec<(StreamId, u64)>,
  /// What arrived, by stream, for [`Behavior::Collect`].
  pub(crate) streams: BTreeMap<u64, StreamLog>,
  /// Opens a unidirectional stream once established and writes these bytes on it.
  pub(crate) uni_on_established: Option<&'static [u8]>,
  /// The stream of [`Self::uni_on_established`].
  pub(crate) uni: Option<StreamId>,
}

impl TestApp {
  /// An application with this behavior.
  pub(crate) fn new(behavior: Behavior) -> Self {
    Self { behavior, ..Self::default() }
  }
}

impl QuicApp for TestApp {
  type ConnState = ();

  fn on_established(&mut self, cx: &mut ConnCtx<'_, ()>) -> crate::Result<()> {
    self.established = self.established.wrapping_add(1);
    if let Some(bytes) = self.uni_on_established {
      let id = cx.open_uni()?;
      cx.write(id, bytes, false)?;
      self.uni = Some(id);
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
    if let Some(fail) = self.fail.filter(|_| self.calls > self.fail_after) {
      return match fail {
        Fail::Transport(code) => Err(crate::Error::QuicClose(code, QuicError::InvalidFrame)),
        Fail::Other => Err(crate::Error::ProgrammingError),
        Fail::AppClose(code) => {
          cx.close(code, b"bye");
          Ok(())
        }
      };
    }
    if fin {
      self.fins = self.fins.wrapping_add(1);
    }
    match &self.behavior {
      Behavior::Collect => {
        let log = self.streams.entry(id.0).or_default();
        log.data.extend_from_slice(data);
        log.fin |= fin;
        log.calls.push((data.len(), fin));
      }
      Behavior::Echo => match cx.write(id, data, fin) {
        // The peer asked for no more (STOP_SENDING)
        Err(crate::Error::Quic(QuicError::StreamClosed)) => {}
        rslt => rslt?,
      },
      Behavior::Respond(bytes) => {
        if fin {
          cx.write(id, bytes, true)?;
        }
      }
      Behavior::RespondBody(head, body) => {
        if fin {
          cx.write(id, head, false)?;
          cx.write_body(id, body.clone(), true)?;
        }
      }
      Behavior::Mixed { small, body, large } => {
        if fin {
          match id.index() % 3 {
            0 => cx.write(id, small, true)?,
            1 => cx.write_body(id, body.clone(), true)?,
            _ => cx.write(id, large, true)?,
          }
        }
      }
      Behavior::LineCount => {
        let lines = data.iter().filter(|el| **el == b'\n').count();
        self.line_count = self.line_count.wrapping_add(u64::try_from(lines).unwrap_or(0));
        let tail = data.iter().rev().take_while(|el| **el != b'\n').count();
        if fin {
          cx.write(id, b"ok", true)?;
        } else {
          cx.retain(tail)?;
        }
      }
      Behavior::Lines => {
        let mut start = 0;
        while let Some(pos) =
          data.get(start..).and_then(|el| el.iter().position(|byte| *byte == b'\n'))
        {
          self.lines.push(data[start..start + pos].to_vec());
          start += pos + 1;
        }
        if fin {
          if start < data.len() {
            self.lines.push(data[start..].to_vec());
          }
        } else {
          cx.retain(data.len() - start)?;
        }
      }
    }
    Ok(())
  }

  fn on_stream_reset(
    &mut self,
    cx: &mut ConnCtx<'_, ()>,
    id: StreamId,
    code: u64,
  ) -> crate::Result<()> {
    self.resets.push((id, code));
    if self.is_server {
      // What would have answered the request is not wanted anymore
      cx.reset(id, code);
    }
    Ok(())
  }

  fn on_stop_sending(
    &mut self,
    _cx: &mut ConnCtx<'_, ()>,
    id: StreamId,
    code: u64,
  ) -> crate::Result<()> {
    self.stops.push((id, code));
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

  // What takes the place of parts that were moved out.
  fn placeholder() -> Self {
    Self { pools: QuicPools::new(), tx: TxArena::new(0).unwrap() }
  }
}

/// How to build a [`Link`].
#[derive(Clone, Debug)]
pub(crate) struct LinkOpts {
  /// The parameters of the client.
  pub(crate) client: ConnParams,
  /// The application of the client.
  pub(crate) client_app: TestApp,
  /// Changes the transport parameters that the client sends.
  pub(crate) client_tp: fn(&mut TransportParams),
  /// The allocation counters of the server and of everything else, if allocations are counted.
  pub(crate) counters: Option<(&'static AtomicU64, &'static AtomicU64)>,
  /// Seeds the random numbers of the link.
  pub(crate) seed: u8,
  /// The parameters of the server.
  pub(crate) server: ConnParams,
  /// The application of the server.
  pub(crate) server_app: TestApp,
  /// The TLS configuration of the server, made once and shared.
  pub(crate) server_config: Arc<TlsConfig<SkCtx>>,
  /// Changes the transport parameters that the server sends.
  pub(crate) server_tp: fn(&mut TransportParams),
  /// Bytes of an unknown transport parameter that the server sends, to make its flight longer.
  pub(crate) server_tp_padding: usize,
}

impl LinkOpts {
  /// Default parameters on both sides, with a server that offers only `suite` if given.
  pub(crate) fn new(suite: Option<CipherSuite>) -> Self {
    Self {
      client: ConnParams::default(),
      client_app: TestApp::default(),
      client_tp: |_| {},
      counters: None,
      seed: 1,
      server: ConnParams::default(),
      server_app: TestApp::default(),
      server_config: server_config(suite),
      server_tp: |_| {},
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
  /// Aborts the connection if it is not closed.
  pub(crate) fn abort(&mut self) {
    self.enter();
    self.conn.abort(&mut self.app, &mut self.parts.pools);
    self.leave();
  }

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

  /// Runs `f` with the context of the connection, as the application does outside of the
  /// callbacks.
  pub(crate) fn with_ctx<R>(
    &mut self,
    now_us: u64,
    f: impl FnOnce(&mut ConnCtx<'_, ()>) -> R,
  ) -> R {
    self.enter();
    let rslt = self.conn.with_ctx(now_us, &mut self.parts.pools, f);
    self.leave();
    rslt
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
  /// Drops the datagrams for which it returns `true`: (to the server, the datagram).
  pub(crate) filter: Option<fn(bool, &[u8]) -> bool>,
  // Datagrams on their way: (arrival, order of sending, to the server, the datagram)
  flying: Vec<(u64, u64, bool, Vec<u8>)>,
  // Buffers of datagrams that arrived, for the next ones
  free: Vec<Vec<u8>>,
  impairment: Option<Impairment>,
  /// The time of the fake clock.
  pub(crate) now_us: u64,
  rng: u64,
  scratch: Vec<u8>,
  sent: u64,
  /// The server.
  pub(crate) server: Side<SkCtx, false>,
}

impl Link {
  /// A client whose first datagram opened a server connection, which received it.
  pub(crate) fn new(opts: &LinkOpts) -> Self {
    Self::with_parts(opts, Parts::new(), Parts::new())
  }

  /// [`Self::new`] with pools and arenas that were used before.
  pub(crate) fn with_parts(
    opts: &LinkOpts,
    mut client_parts: Parts,
    mut server_parts: Parts,
  ) -> Self {
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
      app: opts.client_app.clone(),
      conn: client_conn(
        &opts.client,
        client_cid,
        original_dcid,
        &mut rng,
        now_us,
        &mut client_parts.pools,
        opts.client_tp,
      ),
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
    let conn =
      server_conn(opts, server_cid, original_dcid, server_seed, now_us, &mut server_parts.pools);
    if let Some((_, others)) = counters {
      _count_allocations_in(others);
    }
    let app = TestApp { is_server: true, ..opts.server_app.clone() };
    let mut server = Side { addr: SERVER_ADDR, app, conn, counters, parts: server_parts };
    server.recv(now_us, &mut first[0], CLIENT_ADDR);
    Self {
      client,
      filter: None,
      flying: Vec::new(),
      free: Vec::new(),
      impairment: None,
      now_us,
      rng: 0,
      scratch: Vec::with_capacity(1 << 16),
      sent: 0,
      server,
    }
  }

  /// Makes the link lossy from now on (see [`Self::step_impaired`]).
  pub(crate) fn impair(&mut self, impairment: Impairment) {
    self.impairment = Some(impairment);
    self.rng = impairment.seed ^ 0x9e37_79b9_7f4a_7c15;
  }

  /// Moves the clock to the next arrival of a datagram or timer of a connection and runs the
  /// timers that are due. Returns `false` if there is none.
  pub(crate) fn advance_to_next_event(&mut self) -> bool {
    let arrival = self.flying.iter().map(|el| el.0).min();
    let timers = [self.client.conn.next_deadline(), self.server.conn.next_deadline()];
    let Some(next) = timers.into_iter().flatten().chain(arrival).min() else {
      return false;
    };
    self.now_us = self.now_us.max(next);
    self.client.on_timeout(self.now_us);
    self.server.on_timeout(self.now_us);
    true
  }

  /// One round of a lossy link: both sides flush, what they sent goes on its way, impaired, and
  /// what is due arrives. Returns `false` if nothing was sent and nothing arrived.
  pub(crate) fn step_impaired(&mut self) -> bool {
    let _ = self.client.flush(self.now_us);
    let mut moved = self.send_impaired(true);
    let _ = self.server.flush(self.now_us);
    moved |= self.send_impaired(false);
    loop {
      let due = self
        .flying
        .iter()
        .enumerate()
        .filter(|(_, el)| el.0 <= self.now_us)
        .min_by_key(|(_, el)| (el.0, el.1))
        .map(|(idx, _)| idx);
      let Some(idx) = due else {
        break;
      };
      let (_, _, to_server, mut datagram) = self.flying.swap_remove(idx);
      if to_server {
        self.server.recv(self.now_us, &mut datagram, CLIENT_ADDR);
      } else {
        self.client.recv(self.now_us, &mut datagram, SERVER_ADDR);
      }
      self.free.push(datagram);
      moved = true;
    }
    moved
  }

  /// The datagrams that are on their way.
  pub(crate) fn flying(&self) -> usize {
    self.flying.len()
  }

  fn random(&mut self) -> f32 {
    // xorshift64*
    self.rng ^= self.rng >> 12;
    self.rng ^= self.rng << 25;
    self.rng ^= self.rng >> 27;
    let value = self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d);
    (value >> 40) as f32 / (1u64 << 24) as f32
  }

  // Puts what a side sent on its way
  fn send_impaired(&mut self, from_client: bool) -> bool {
    let Some(impairment) = self.impairment else {
      return false;
    };
    let mut moved = false;
    loop {
      let side_tx = if from_client { &mut self.client.parts.tx } else { &mut self.server.parts.tx };
      let next = side_tx.pending().next().map(|train| {
        self.scratch.clear();
        self.scratch.extend_from_slice(train.bytes);
        (train.id, usize::from(train.segment_size))
      });
      let Some((id, segment_size)) = next else {
        break;
      };
      side_tx.mark_submitted(id);
      side_tx.release(id);
      let mut at = 0;
      while at < self.scratch.len() {
        let end = (at + segment_size).min(self.scratch.len());
        moved = true;
        let filtered = self.filter.is_some_and(|el| el(from_client, &self.scratch[at..end]));
        let copies = if filtered || self.random() < impairment.drop {
          0
        } else if self.random() < impairment.duplicate {
          2
        } else {
          1
        };
        for _ in 0..copies {
          let mut arrival = self.now_us + impairment.delay_us;
          if self.random() < impairment.reorder {
            arrival += 1 + (self.random() * (impairment.delay_us + 1) as f32) as u64;
          }
          let mut datagram = self.free.pop().unwrap_or_default();
          datagram.clear();
          datagram.extend_from_slice(&self.scratch[at..end]);
          self.sent += 1;
          self.flying.push((arrival, self.sent, from_client, datagram));
        }
        at = end;
      }
    }
    moved
  }

  /// Moves the clock forward by `us` and runs the timers that are due.
  pub(crate) fn advance(&mut self, us: u64) {
    self.now_us = self.now_us.wrapping_add(us);
    self.client.on_timeout(self.now_us);
    self.server.on_timeout(self.now_us);
  }

  /// The pools and arenas, for the next link, once both connections are aborted (if they are not
  /// closed) and the arenas emptied.
  pub(crate) fn into_parts(mut self) -> (Parts, Parts) {
    self.abort();
    // What is still in the arenas is not for the next link
    let _ = self.client.take_datagrams();
    let _ = self.server.take_datagrams();
    (
      core::mem::replace(&mut self.client.parts, Parts::placeholder()),
      core::mem::replace(&mut self.server.parts, Parts::placeholder()),
    )
  }

  /// Aborts the connections that are not closed.
  pub(crate) fn abort(&mut self) {
    self.client.abort();
    self.server.abort();
  }

  /// Flushes both sides and delivers what they sent, until nothing moves anymore.
  pub(crate) fn run(&mut self) {
    self.run_for(MAX_STEPS);
  }

  /// [`Self::run`] for at most `max_steps` steps.
  pub(crate) fn run_for(&mut self, max_steps: usize) {
    for _ in 0..max_steps {
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

impl Drop for Link {
  fn drop(&mut self) {
    self.abort();
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
  pools: &mut QuicPools,
  change_tp: fn(&mut TransportParams),
) -> ClientConn {
  let mut tp = [0; 256];
  let mut params_tp = params.transport_params(local_cid, None);
  change_tp(&mut params_tp);
  let len = params_tp.encode(&mut tp).unwrap();
  let tls =
    QuicTls::new_client("localhost", b"h3", &tp[..len], ChaCha20::from_key(seed(rng))).unwrap();
  QuicConn::new_client(params, local_cid, original_dcid, SERVER_ADDR, tls, now_us, pools).unwrap()
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
  pools: &mut QuicPools,
) -> ServerConn {
  let mut tp = [0; 256];
  let mut params_tp = opts.server.transport_params(local_cid, Some(original_dcid));
  (opts.server_tp)(&mut params_tp);
  let len = params_tp.encode(&mut tp).unwrap();
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
  QuicConn::new_server(&opts.server, local_cid, original_dcid.as_slice(), meta, tls, now_us, pools)
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

/// What [`run_lossy_requests`] measured.
#[derive(Debug)]
pub(crate) struct LossyRun {
  /// The datagrams that the link carried.
  pub(crate) datagrams: u64,
  /// The time on the clock that the requests took.
  pub(crate) elapsed_us: u64,
  /// The longest time on the clock in which no data reached the client.
  pub(crate) longest_stall_us: u64,
  /// The responses, in the order of the requests.
  pub(crate) responses: Vec<Vec<u8>>,
}

/// Sends `requests` from the client of the lossy `link` (see [`Link::impair`]), at most
/// `concurrent` at once, each with its FIN, until every response has its FIN. Panics if that takes
/// more than `max_us` on the clock, or if nothing is left to happen before.
pub(crate) fn run_lossy_requests(
  link: &mut Link,
  requests: &[Vec<u8>],
  concurrent: usize,
  max_us: u64,
) -> LossyRun {
  let start = link.now_us;
  let sent_before = link.sent;
  let mut pending: Vec<(usize, StreamId)> = Vec::new();
  let mut responses = vec![Vec::new(); requests.len()];
  let (mut opened, mut done) = (0, 0);
  let (mut last_progress, mut calls, mut longest_stall_us) = (start, link.client.app.calls, 0);
  loop {
    let mut idx = 0;
    while let Some(&(nth, id)) = pending.get(idx) {
      if link.client.app.streams.get(&id.0).is_some_and(|el| el.fin) {
        let log = link.client.app.streams.remove(&id.0).unwrap_or_default();
        responses[nth] = log.data;
        let _ = pending.swap_remove(idx);
        done += 1;
      } else {
        idx += 1;
      }
    }
    if done == requests.len() {
      break;
    }
    while pending.len() < concurrent && opened < requests.len() {
      let now_us = link.now_us;
      let bytes = &requests[opened];
      let rslt = link.client.with_ctx(now_us, |cx| {
        let id = cx.open_bidi()?;
        cx.write(id, bytes, true)?;
        Ok::<_, crate::Error>(id)
      });
      match rslt {
        Ok(id) => {
          pending.push((opened, id));
          opened += 1;
        }
        Err(crate::Error::Quic(QuicError::StreamsBlocked)) => break,
        Err(err) => panic!("request {opened}: {err:?}"),
      }
    }
    if !link.step_impaired() {
      assert!(
        link.advance_to_next_event(),
        "{done} of {} requests done, then nothing",
        requests.len()
      );
    }
    if link.client.app.calls != calls {
      calls = link.client.app.calls;
      last_progress = link.now_us;
    }
    longest_stall_us = longest_stall_us.max(link.now_us - last_progress);
    let elapsed = link.now_us - start;
    assert!(elapsed <= max_us, "{done} of {} requests done in {elapsed} us", requests.len());
    for conn in [link.client.conn.state(), link.server.conn.state()] {
      assert!(
        matches!(conn, crate::quic::ConnState::Handshake | crate::quic::ConnState::Confirmed),
        "{conn:?} after {done} requests"
      );
    }
  }
  LossyRun {
    datagrams: link.sent - sent_before,
    elapsed_us: link.now_us - start,
    longest_stall_us,
    responses,
  }
}

/// The frames, one after the other, as a packet carries them.
pub(crate) fn encode_frames(frames: &[Frame<'_>]) -> Vec<u8> {
  let mut buffer = vec![0; 1 << 16];
  let mut writer = FrameWriter::new(&mut buffer);
  for frame in frames {
    assert!(writer.write_frame(frame), "{frame:?}");
  }
  let len = writer.len();
  buffer.truncate(len);
  buffer
}
