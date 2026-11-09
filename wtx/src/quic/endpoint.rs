//! The QUIC endpoint of a worker (spec sections 5.2, 5.4, 5.11 and 5.12): its connections, the
//! connection IDs that lead to them, the packets that need no connection, the limits on
//! handshakes, the timers and the placement of new connections on the workers.
//!
//! # Receiving
//!
//! A datagram that the kernel coalesced is split into its segments first. A segment goes, by the
//! destination connection ID of its first packet, to the connection that has it, or that was
//! opened by an Initial packet sent to it while the handshake lasts. What no connection has:
//!
//! - an unknown version gets a Version Negotiation packet, in a datagram of 1200 bytes or more
//!   (ruling T10-f);
//! - a connection ID of ours that names another worker goes to that worker
//!   ([`RecvOutcome::Forward`], ruling T10-e), once: a forwarded datagram is never forwarded again.
//!   That is a short header, a long header other than Initial, or an Initial packet with a token,
//!   whose destination is a CID of ours; an Initial packet without a token is sent by a client to
//!   a CID that it chose at random, which could look like one of another worker: it is taken for a
//!   first Initial packet (with CID steering on, a later Initial packet to our CID reaches the
//!   worker that it names);
//! - the first Initial packet of a client goes, while CID steering is on, to the worker with the
//!   fewest connections if that one has fewer than this one (spec section 5.11), which is
//!   remembered for two seconds so that the Initial packets that follow go there too. The worker
//!   that decides counts the connection on the other one at once, so that a burst spreads; the
//!   other one gives it back if the datagram opens nothing there (ruling T10-m), and so does
//!   [`Endpoint::forward_dropped`] for a datagram that could not be handed over. Or it is
//!   dropped if the worker has as many connections as it can, or as many handshakes under way as
//!   [`QuicLimits::max_half_open_per_worker`], or gets a Retry if it has as many as
//!   [`QuicLimits::retry_above_half_open`], or opens a connection, which the endpoint drops at
//!   once if nothing in the datagram opened;
//! - an Initial packet with the token of a Retry opens a connection if the token is valid, with
//!   the address of the client validated, and is dropped if it is not (ruling T10-h);
//! - a short header packet to an unknown connection ID of this worker gets a stateless reset,
//!   rate-limited, smaller than what it answers and at most 40 bytes, in answer to a datagram of
//!   41 bytes or more only, so that it never answers one of ours (ruling T10-g).
//!
//! # Sending and timers
//!
//! [`Endpoint::flush`] writes the stateless packets, then flushes every connection that received,
//! timed out or was written to, once, and arms its timer in the wheel with its next deadline, or
//! the end of its handshake if earlier. [`Endpoint::on_timeout`] runs the connections whose timer
//! fired, and drops those whose handshake took longer than [`QuicParams::handshake_timeout_ms`].
//!
//! [`QuicLimits::retry_above_half_open`]: crate::quic::QuicLimits::retry_above_half_open
//! [`QuicLimits::max_half_open_per_worker`]: crate::quic::QuicLimits::max_half_open_per_worker

use crate::{
  collections::Vector,
  quic::{
    Cid, ConnCtx, ConnHandle, ConnParams, ConnState, DatagramMeta, FlushOutcome, PacketTy, QuicApp,
    QuicConn, QuicParams, TxArena,
    cid_table::{CID_LEN, CidTable, ConnRef},
    limits::RateBudget,
    parse_header,
    pools::QuicPools,
    timer_wheel::TimerWheel,
    token::{EndpointKeys, RESET_TOKEN_LEN, RETRY_TOKEN_LEN},
    write_retry, write_version_negotiation,
  },
  rng::{CryptoRng, CryptoSeedableRng},
  sync::{Arc, AtomicU32},
  tls::{QuicTls, TlsConfig, TlsCtxSk},
};
use core::{
  hint::cold_path,
  net::{IpAddr, Ipv4Addr, SocketAddr},
  sync::atomic::Ordering,
};

// The fixed bits of a stateless reset, which looks like a short header packet
const FIXED_BIT: u8 = 0x40;
// The smallest datagram that can carry the first Initial packet of a client (RFC 9000 section
// 14.1), or that an unknown version is answered for (ruling T10-f)
const MIN_INITIAL_DATAGRAM: usize = 1200;
// The destination CID of the first Initial packet of a client has at least 8 bytes (RFC 9000
// section 7.2)
const MIN_FIRST_DCID_LEN: usize = 8;
// A stateless reset has 5 bytes before its token (RFC 9000 section 10.3)
const MIN_RESET_LEN: usize = 5 + RESET_TOKEN_LEN;
// Our stateless resets have at most 40 bytes and answer datagrams of at least 41: never one of
// ours (ruling T10-g)
const MAX_RESET_LEN: usize = 40;
// A stateless reset that answers a datagram of at most this is one byte shorter than it
const SHORT_TRIGGER_LEN: usize = 43;
const NO_SLOT: u32 = u32::MAX;
// Room for a Retry while its integrity tag is computed: a 20-byte original destination CID and
// its length, the first byte, the version, two CIDs of 20 bytes and their lengths, the token
// and the tag
const STATELESS_LEN: usize = 21 + 1 + 4 + 21 + 21 + RETRY_TOKEN_LEN + 16;
// The stateless packets that wait for a flush
const STATELESS_QUEUE: usize = 16;
// The transport parameters of a connection
const TP_LEN: usize = 256;

/// What [`Endpoint::recv`] did with a datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecvOutcome {
  /// The datagram was processed, or dropped.
  Done,
  /// The datagram belongs to the worker `worker`: the caller gives it, as it is, with its
  /// metadata, to [`Endpoint::recv_forwarded`] of that worker.
  Forward {
    /// The index of the worker.
    worker: u8,
  },
}

/// Counters of an endpoint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EndpointStats {
  /// Connections, those whose handshake is under way included.
  pub(crate) conns: u32,
  /// Connections whose handshake is under way.
  pub(crate) half_open: u32,
  /// Datagrams received, each segment of a coalesced one counted.
  pub(crate) datagrams_in: u64,
  /// Datagrams sent.
  pub(crate) datagrams_out: u64,
  /// Packets sent.
  pub(crate) packets_out: u64,
  /// Packets sent that were not ack-eliciting, other than CONNECTION_CLOSE.
  pub(crate) ack_only_out: u64,
  /// STREAM frames sent with the FIN of their stream, the first time: responses finished.
  pub(crate) fins_out: u64,
  /// Flushes of a connection that sent a FIN.
  pub(crate) fin_flushes: u64,
  /// Of [`Self::fin_flushes`], those that carried an ACK frame of the 1-RTT space.
  pub(crate) fin_flushes_acked: u64,
  /// Of [`Self::fin_flushes`], those that started with an acknowledgment owed (ruling T19-d).
  pub(crate) fin_flushes_ack_owed: u64,
  /// Of [`Self::fin_flushes_ack_owed`], those that carried an ACK frame.
  pub(crate) fin_flushes_owed_and_acked: u64,
  /// Bytes of the datagrams sent.
  pub(crate) bytes_out: u64,
  /// Bytes of stream data written into packets, those sent again included (ruling T19-a).
  pub(crate) stream_bytes_out: u64,
  /// Bytes that applications wrote to streams by copy (ruling T19-a).
  pub(crate) stream_bytes_copied: u64,
  /// Flushes that stopped with ack-eliciting data that the pacer held back.
  pub(crate) pacer_holds: u64,
  /// DATA_BLOCKED frames received.
  pub(crate) data_blocked_in: u64,
  /// STREAM_DATA_BLOCKED frames received.
  pub(crate) stream_data_blocked_in: u64,
  /// STREAMS_BLOCKED frames received.
  pub(crate) streams_blocked_in: u64,
  /// Packets declared lost.
  pub(crate) packets_lost: u64,
  /// Probe timeouts that fired.
  pub(crate) pto_probes: u64,
  /// STREAM frames sent again.
  pub(crate) frames_resent: u64,
  /// Retry packets sent.
  pub(crate) retries: u64,
  /// Datagrams handed to another worker: a datagram that the kernel coalesced (GRO) counts once
  /// here, and arrives at that worker as its segments, one inbox entry each.
  pub(crate) forwarded: u64,
  /// Stateless resets sent.
  pub(crate) resets: u64,
}

/// The connections of each worker of a process, which places a new connection on the worker
/// that has the fewest (spec section 5.11). Touched when a connection opens or closes only.
#[derive(Debug)]
pub struct WorkerLoads {
  counts: [AtomicU32; 256],
  workers: u8,
}

impl WorkerLoads {
  /// No connections on `workers` workers, at least one.
  #[inline]
  pub fn new(workers: u8) -> Self {
    Self { counts: [const { AtomicU32::new(0) }; 256], workers: workers.max(1) }
  }

  /// The worker with the fewest connections, the first of them if several have as few.
  #[inline]
  pub fn least_loaded(&self) -> u8 {
    let mut rslt = (0u8, u32::MAX);
    for worker in 0..self.workers {
      let load = self.load(worker);
      if load < rslt.1 {
        rslt = (worker, load);
      }
    }
    rslt.0
  }

  /// The connections of `worker`.
  #[inline]
  pub fn load(&self, worker: u8) -> u32 {
    self.counts.get(usize::from(worker)).map_or(u32::MAX, |el| el.load(Ordering::Relaxed))
  }

  /// The number of workers.
  #[inline]
  pub const fn workers(&self) -> u8 {
    self.workers
  }

  // A connection placed on `worker` closed, or did not open. The count never goes below zero.
  // A loop of `compare_exchange_weak`, which `core` and `portable-atomic` both have (review N1).
  fn closed(&self, worker: u8) {
    let Some(elem) = self.counts.get(usize::from(worker)) else {
      return;
    };
    let mut current = elem.load(Ordering::Relaxed);
    while let Some(next) = current.checked_sub(1) {
      match elem.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => break,
        Err(actual) => current = actual,
      }
    }
  }

  /// One more connection placed on `worker`.
  #[inline]
  pub(crate) fn placed(&self, worker: u8) {
    self.opened(worker);
  }

  // A connection of `worker` opened
  fn opened(&self, worker: u8) {
    if let Some(elem) = self.counts.get(usize::from(worker)) {
      let _ = elem.fetch_add(1, Ordering::Relaxed);
    }
  }
}

/// The endpoint of a worker. See the [module documentation](self).
///
/// Its connections hold resources of its pools: call [`Self::abort_all`] before dropping it,
/// which otherwise ends them without telling the application.
pub(crate) struct Endpoint<A, RNG, TCX>
where
  A: QuicApp,
{
  cids: CidTable,
  conn_params: ConnParams,
  // The connections to flush, once each
  dirty: Vector<usize, u32>,
  // The connections whose timer fired, for `on_timeout`
  fired: Vector<usize, u32>,
  // The first free slot, the others linked from it
  free: u32,
  half_open: u32,
  keys: Arc<EndpointKeys>,
  live: u32,
  loads: Option<Arc<WorkerLoads>>,
  params: QuicParams,
  // The datagram that is processed carries a place that the worker that forwarded it counted on
  // this one (ruling T10-m)
  placement: bool,
  pools: QuicPools,
  reset_budget: RateBudget,
  rng: RNG,
  shutdown: bool,
  // When the connections that drain themselves after a shutdown are closed, if they are not yet
  shutdown_deadline_us: Option<u64>,
  // Room for every connection is reserved once, so that a connection never moves
  slots: Vector<usize, Slot<A, RNG, TCX>>,
  stateless: StatelessQueue,
  stats: EndpointStats,
  timers: TimerWheel,
  tls: Arc<TlsConfig<TCX>>,
  vn_budget: RateBudget,
  worker: u8,
  workers: u8,
}

impl<A, RNG, TCX> Endpoint<A, RNG, TCX>
where
  A: QuicApp,
  RNG: CryptoRng + CryptoSeedableRng,
  TCX: TlsCtxSk,
{
  /// The endpoint of worker `worker` of `workers`, which serves with `tls`. Its CIDs, tokens and
  /// the random numbers of its handshakes come from a generator of its own, seeded from `rng`, the
  /// generator of the process (ruling T10-o): two endpoints that copied one generator would make
  /// the same CIDs and, under the keys of the process, the same nonces of Retry tokens. The keys
  /// of its stateless packets are those of the process (ruling T10-a), and so are the loads of
  /// the workers, if new connections are balanced.
  #[inline]
  pub(crate) fn new<R>(
    params: QuicParams,
    worker: u8,
    workers: u8,
    tls: Arc<TlsConfig<TCX>>,
    rng: &mut R,
    loads: Option<Arc<WorkerLoads>>,
    keys: Arc<EndpointKeys>,
  ) -> crate::Result<Self>
  where
    R: CryptoRng,
  {
    let mut rng = RNG::from_crypto_rng(rng)?;
    if worker >= workers {
      return Err(crate::Error::ProgrammingError);
    }
    let conns = usize::try_from(params.max_conns_per_worker()).unwrap_or(usize::MAX);
    let half_open = usize::try_from(params.limits().max_half_open_per_worker).unwrap_or(usize::MAX);
    Ok(Self {
      cids: CidTable::new(conns, half_open.min(conns), &mut rng)?,
      conn_params: params.conn_params(),
      dirty: Vector::with_exact_capacity(conns)?,
      fired: Vector::with_exact_capacity(conns)?,
      free: NO_SLOT,
      half_open: 0,
      keys,
      live: 0,
      loads,
      params,
      placement: false,
      pools: QuicPools::new(),
      reset_budget: RateBudget::default(),
      rng,
      shutdown: false,
      shutdown_deadline_us: None,
      slots: Vector::with_exact_capacity(conns)?,
      stateless: StatelessQueue::new(),
      stats: EndpointStats::default(),
      timers: TimerWheel::new(conns, 0)?,
      tls,
      vn_budget: RateBudget::default(),
      worker,
      workers,
    })
  }

  /// Ends every connection at once, without a CONNECTION_CLOSE, for an endpoint that is
  /// dropped.
  #[inline]
  pub(crate) fn abort_all(&mut self, app: &mut A) {
    for idx in 0..self.slots_len() {
      self.remove(idx, app);
    }
  }

  /// Closes every connection with an application CONNECTION_CLOSE of
  /// [`crate::quic::QuicLimits::shutdown_app_code`] and drops the Initial packets of new
  /// clients from now on (ruling T10-b). The connections end after their closing period.
  ///
  /// An established connection whose application drains it itself ([`QuicApp::on_shutdown`],
  /// ruling T13-d) stays open until the application closes it, or until
  /// [`crate::quic::QuicLimits::shutdown_grace_ms`] passed, when it is closed as the others.
  #[inline]
  pub(crate) fn begin_shutdown(&mut self, now_us: u64, app: &mut A) {
    self.shutdown = true;
    let limits = *self.params.limits();
    let grace_us = limits.shutdown_grace_ms.saturating_mul(1_000);
    self.shutdown_deadline_us = Some(now_us.saturating_add(grace_us));
    for idx in 0..self.slots_len() {
      let Self { pools, slots, .. } = self;
      let Some(conn) = slots.get_mut(idx).and_then(|el| el.conn.as_mut()) else {
        continue;
      };
      if !matches!(conn.state(), ConnState::Handshake | ConnState::Confirmed) {
        continue;
      }
      if !conn.on_shutdown(now_us, app, pools)
        && matches!(conn.state(), ConnState::Handshake | ConnState::Confirmed)
      {
        conn.close_app(now_us, limits.shutdown_app_code);
      }
      self.after_event(idx, app);
    }
  }

  /// Writes into `tx` what is owed: the stateless packets first, then what every connection that
  /// received, timed out or was written to since the last flush has to send, once each. With
  /// [`FlushOutcome::ArenaFull`], what did not fit waits for the next flush.
  #[inline]
  pub(crate) fn flush(&mut self, now_us: u64, tx: &mut TxArena, app: &mut A) -> FlushOutcome {
    while let Some(packet) = self.stateless.front() {
      let len = usize::from(packet.len);
      let Some(buffer) = tx.begin(packet.peer, packet.local, len) else {
        return FlushOutcome::ArenaFull;
      };
      let (Some(dst), Some(src)) = (buffer.get_mut(..len), packet.bytes.get(..len)) else {
        return FlushOutcome::ArenaFull;
      };
      dst.copy_from_slice(src);
      tx.commit(len);
      self.stats.datagrams_out = self.stats.datagrams_out.wrapping_add(1);
      self.stats.packets_out = self.stats.packets_out.wrapping_add(1);
      match packet.kind {
        StatelessKind::Reset => self.stats.resets = self.stats.resets.wrapping_add(1),
        StatelessKind::Retry => self.stats.retries = self.stats.retries.wrapping_add(1),
        StatelessKind::VersionNegotiation => {}
      }
      self.stateless.pop();
    }
    if self.params.flush_in_slot_order() {
      self.dirty.as_slice_mut().sort_unstable();
    }
    let mut done = 0usize;
    while let Some(idx) = self.dirty.get(done).copied() {
      let Self { pools, slots, stats, .. } = self;
      if let Some(slot) = slots.get_mut(usize::try_from(idx).unwrap_or(usize::MAX))
        && let Some(conn) = slot.conn.as_mut()
      {
        let rslt = conn.flush(now_us, tx, app, pools);
        // What it sent counts once it is closed too (carried rule 4)
        let tally = Tally::of(conn);
        tally.add_since(&slot.sent, stats);
        slot.sent = tally;
        if rslt == FlushOutcome::ArenaFull {
          // This one and the ones after it stay dirty
          let len = self.dirty.len();
          self.dirty.as_slice_mut().copy_within(done.., 0);
          self.dirty.truncate(len.wrapping_sub(done));
          return FlushOutcome::ArenaFull;
        }
        slot.dirty = false;
        self.arm(idx);
      } else if let Some(slot) = slots.get_mut(usize::try_from(idx).unwrap_or(usize::MAX)) {
        slot.dirty = false;
      }
      done = done.wrapping_add(1);
    }
    self.dirty.clear();
    FlushOutcome::Done
  }

  /// When [`Self::on_timeout`] is due, if ever.
  #[inline]
  pub(crate) fn next_deadline(&self) -> Option<u64> {
    self.timers.next_expiry()
  }

  /// Runs the timers that are due at `now_us`. A flush is due after it.
  #[inline]
  pub(crate) fn on_timeout(&mut self, now_us: u64, app: &mut A) {
    let Self { fired, timers, .. } = self;
    fired.clear();
    timers.expire(now_us, |idx| {
      let _rslt = fired.push(idx);
    });
    let mut nth = 0usize;
    while let Some(idx) = self.fired.get(nth).copied() {
      nth = nth.wrapping_add(1);
      let slot_idx = usize::try_from(idx).unwrap_or(usize::MAX);
      let Some(slot) = self.slots.get_mut(slot_idx) else {
        continue;
      };
      let late = slot.handshake_deadline_us.is_some_and(|el| now_us >= el);
      let Some(conn) = slot.conn.as_mut() else {
        continue;
      };
      if late && conn.state() == ConnState::Handshake {
        // A handshake that took too long (spec section 5.12): its resources go back now
        self.remove(slot_idx, app);
        continue;
      }
      if self.shutdown_deadline_us.is_some_and(|el| now_us >= el)
        && matches!(conn.state(), ConnState::Handshake | ConnState::Confirmed)
      {
        // The grace period of a shutdown is over (ruling T13-d)
        conn.close_app(now_us, self.params.limits().shutdown_app_code);
      }
      conn.on_timeout(now_us, app, &mut self.pools);
      self.after_event(slot_idx, app);
      self.arm(idx);
    }
    self.fired.clear();
  }

  /// Takes `datagram`, which came with `meta`: a datagram that the kernel coalesced (generic
  /// receive offload) is split into its segments of `meta.segment_size` bytes, each processed
  /// alone (carried rule 1). Returns [`RecvOutcome::Forward`] if the datagram is for another
  /// worker, which its first segment decides: the segments of a coalesced datagram come from one
  /// peer.
  #[inline]
  pub(crate) fn recv(
    &mut self,
    now_us: u64,
    datagram: &mut [u8],
    meta: DatagramMeta,
    app: &mut A,
  ) -> RecvOutcome {
    self.recv_segments(now_us, datagram, meta, app, true)
  }

  /// Takes `datagram`, which another worker received and returned [`RecvOutcome::Forward`] for:
  /// it is not forwarded again.
  #[inline]
  pub(crate) fn recv_forwarded(
    &mut self,
    now_us: u64,
    datagram: &mut [u8],
    meta: DatagramMeta,
    app: &mut A,
  ) {
    let _outcome = self.recv_segments(now_us, datagram, meta, app, false);
  }

  /// The caller could not hand `datagram`, which [`Self::recv`] returned
  /// [`RecvOutcome::Forward`] for, to `worker` (its inbox was full): the place that the datagram
  /// took on that worker, if it was the first Initial packet of a client, is given back (ruling
  /// T10-m).
  #[inline]
  pub(crate) fn forward_dropped(&mut self, datagram: &[u8], worker: u8) {
    if carries_placement(datagram)
      && let Some(loads) = &self.loads
    {
      loads.closed(worker);
    }
  }

  /// The caller hands `segment`, a segment after the first of a coalesced datagram that
  /// [`Self::recv`] returned [`RecvOutcome::Forward`] for, to `worker` apart: if it is a first
  /// Initial packet, it takes a place on that worker as the first one did, which that worker gives
  /// back if it opens nothing (and [`Self::forward_dropped`] if it can not be handed over).
  #[inline]
  pub(crate) fn forward_segment(&mut self, segment: &[u8], worker: u8) {
    if carries_placement(segment)
      && let Some(loads) = &self.loads
    {
      loads.placed(worker);
    }
  }

  /// The counters of the endpoint.
  #[inline]
  pub(crate) fn stats(&self) -> EndpointStats {
    EndpointStats { conns: self.live, half_open: self.half_open, ..self.stats }
  }

  /// Frees all but a few entries of the pools of the worker, if it has no connection: for a worker
  /// that has been idle a while (spec section 5.4).
  #[inline]
  pub(crate) fn trim_idle(&mut self) {
    if self.live == 0 {
      self.pools.trim_idle();
    }
  }

  /// Runs `f` with `app` and the context of the connection of `handle` ([`ConnCtx::handle`]),
  /// as a handler that answers later does (ruling T14-d), and has the connection flushed with the
  /// next flush. `None`, and `f` is not run, if the connection is gone: a stale handle is ignored.
  #[inline]
  pub(crate) fn with_conn<R>(
    &mut self,
    now_us: u64,
    handle: ConnHandle,
    app: &mut A,
    f: impl FnOnce(&mut A, &mut ConnCtx<'_, A::ConnState>) -> R,
  ) -> Option<R> {
    let idx = self.lookup(Some(ConnRef { generation: handle.generation, slot: handle.slot }))?;
    let Self { pools, slots, .. } = self;
    let conn = slots.get_mut(idx)?.conn.as_mut()?;
    let rslt = conn.with_ctx(now_us, pools, |cx| f(app, cx));
    self.after_event(idx, app);
    Some(rslt)
  }

  // A connection received or timed out: the end of its handshake, its end, a flush that is due.
  fn after_event(&mut self, idx: usize, app: &mut A) {
    let Some(slot) = self.slots.get_mut(idx) else {
      return;
    };
    let Some(state) = slot.conn.as_ref().map(QuicConn::state) else {
      return;
    };
    if state != ConnState::Handshake && slot.handshake_deadline_us.take().is_some() {
      self.half_open = self.half_open.saturating_sub(1);
      // The client sends to our CID from now on
      if let Some(elem) = slot.original_dcid.take() {
        self.cids.remove_original(&elem);
      }
    }
    if state == ConnState::Closed {
      self.remove(idx, app);
      return;
    }
    self.mark_dirty(idx);
  }

  // A free slot, if one is left.
  fn alloc_slot(&mut self) -> Option<usize> {
    if self.free != NO_SLOT {
      let idx = usize::try_from(self.free).ok()?;
      self.free = self.slots.get(idx)?.next_free;
      return Some(idx);
    }
    let idx = self.slots.len();
    if idx >= self.slots.capacity() {
      return None;
    }
    self.slots.push(Slot::EMPTY).ok()?;
    Some(idx)
  }

  // Arms the timer of the connection of slot `idx` with its next deadline, or the end of its
  // handshake if that comes first.
  fn arm(&mut self, idx: u32) {
    let Some(slot) = self.slots.get(usize::try_from(idx).unwrap_or(usize::MAX)) else {
      return;
    };
    let deadline = slot.conn.as_ref().and_then(QuicConn::next_deadline);
    // A connection that drains itself after a shutdown is closed at the end of the grace period
    let open = slot
      .conn
      .as_ref()
      .is_some_and(|el| matches!(el.state(), ConnState::Handshake | ConnState::Confirmed));
    let grace = self.shutdown_deadline_us.filter(|_| open);
    let deadline = deadline.into_iter().chain(slot.handshake_deadline_us).chain(grace).min();
    self.timers.arm(idx, deadline);
  }

  // The datagram `chunk` to the connection of slot `idx`; a connection that it opens (`fresh`)
  // and that nothing in it opened for is dropped at once.
  fn deliver(
    &mut self,
    now_us: u64,
    idx: usize,
    chunk: &mut [u8],
    meta: DatagramMeta,
    fresh: bool,
    app: &mut A,
  ) {
    let Self { pools, slots, .. } = self;
    let Some(conn) = slots.get_mut(idx).and_then(|el| el.conn.as_mut()) else {
      return;
    };
    let _rslt = conn.recv_datagram(now_us, chunk, meta, app, pools);
    if fresh && conn.stats().packets_in == 0 {
      // The application never saw it (review L7)
      conn.discard(pools);
      self.release_slot(idx);
      return;
    }
    self.after_event(idx, app);
  }

  // The first Initial packet of a client (RFC 9000 section 7.2), sent to `dcid` from `scid`, in
  // a datagram of `len` bytes.
  fn first_initial(
    &mut self,
    now_us: u64,
    (len, dcid, scid): (usize, &[u8], &[u8]),
    meta: DatagramMeta,
    may_forward: bool,
  ) -> Route {
    if self.shutdown || len < MIN_INITIAL_DATAGRAM || dcid.len() < MIN_FIRST_DCID_LEN {
      return Route::Done;
    }
    // An Initial packet that follows one that went elsewhere goes there too, with a place that
    // the connection that it opens takes, or that the worker gives back
    if let Some(worker) = self.cids.get_forwarded(dcid, now_us) {
      if !may_forward {
        return Route::Done;
      }
      if let Some(loads) = &self.loads {
        loads.placed(worker);
      }
      return Route::Forward(worker);
    }
    // Without steering, the packets of the client that follow would come back here by the hash
    // of their addresses: they stay (spec section 5.11)
    if may_forward
      && self.params.balance()
      && self.params.cid_steering()
      && let Some(loads) = &self.loads
    {
      let target = loads.least_loaded();
      if target != self.worker
        && target < self.workers
        && loads.load(target) < loads.load(self.worker)
      {
        if let Ok(elem) = Cid::new(dcid) {
          self.cids.insert_forwarded(elem, target, now_us);
        }
        // Counted now, so that the first Initial packets that follow spread (ruling T10-m)
        loads.placed(target);
        return Route::Forward(target);
      }
    }
    let limits = self.params.limits();
    if !self.has_room() || self.half_open >= limits.max_half_open_per_worker {
      return Route::Done;
    }
    if self.half_open >= limits.retry_above_half_open {
      self.queue_retry(now_us, dcid, scid, meta);
      return Route::Done;
    }
    let Ok(original) = Cid::new(dcid) else {
      return Route::Done;
    };
    self.open(now_us, dcid, (None, original, None), meta)
  }

  // An Initial packet with a token, sent to `dcid`, which names this worker.
  fn initial_with_token(
    &mut self,
    now_us: u64,
    (len, dcid, scid, token): (usize, &[u8], &[u8], &[u8]),
    meta: DatagramMeta,
    may_forward: bool,
  ) -> Route {
    // Not a token of ours, maybe one of NEW_TOKEN from another server: as if there was none
    if token.len() != RETRY_TOKEN_LEN {
      return self.first_initial(now_us, (len, dcid, scid), meta, may_forward);
    }
    if self.shutdown
      || len < MIN_INITIAL_DATAGRAM
      || !self.has_room()
      || self.half_open >= self.params.limits().max_half_open_per_worker
    {
      return Route::Done;
    }
    // An invalid or expired token: no second Retry (ruling T10-h)
    let Some(original) = self.keys.open_retry_token(token, meta.peer, now_us, dcid) else {
      return Route::Done;
    };
    let (Ok(local), Ok(retry_scid)) = (<[u8; CID_LEN]>::try_from(dcid), Cid::new(dcid)) else {
      return Route::Done;
    };
    self.open(now_us, dcid, (Some(local), original, Some(retry_scid)), meta)
  }

  // If a slot is free for one more connection: at most `max_conns_per_worker`.
  fn has_room(&self) -> bool {
    self.free != NO_SLOT || self.slots.len() < self.slots.capacity()
  }

  // The slot of `conn`, if its connection is still there.
  fn lookup(&self, conn: Option<ConnRef>) -> Option<usize> {
    let conn = conn?;
    let idx = usize::try_from(conn.slot).ok()?;
    let slot = self.slots.get(idx)?;
    (slot.generation == conn.generation && slot.conn.is_some()).then_some(idx)
  }

  fn mark_dirty(&mut self, idx: usize) {
    let Some(slot) = self.slots.get_mut(idx) else {
      return;
    };
    if !slot.dirty {
      slot.dirty = true;
      // Room for every slot
      let _rslt = self.dirty.push(u32::try_from(idx).unwrap_or(NO_SLOT));
    }
  }

  // A CID of ours that no connection has: the index of the worker, then random bytes.
  fn new_cid(&mut self) -> [u8; CID_LEN] {
    loop {
      let mut cid = [self.worker; CID_LEN];
      if let Some(rest) = cid.get_mut(1..) {
        self.rng.fill_slice(rest);
      }
      if self.cids.get(&cid).is_none() {
        return cid;
      }
    }
  }

  // Opens the connection of an Initial packet of a client sent to `client_dcid`: the first one,
  // or the one with the token of a Retry, whose source CID becomes ours. Returns where the
  // packet goes.
  fn open(
    &mut self,
    now_us: u64,
    client_dcid: &[u8],
    (local, original, retry_scid): (Option<[u8; CID_LEN]>, Cid, Option<Cid>),
    meta: DatagramMeta,
  ) -> Route {
    let local = local.unwrap_or_else(|| self.new_cid());
    let Ok(local_cid) = Cid::new(&local) else {
      return Route::Done;
    };
    let Ok(mut conn) = self.make_conn(now_us, client_dcid, local_cid, original, retry_scid, meta)
    else {
      cold_path();
      return Route::Done;
    };
    let Some(idx) = self.alloc_slot() else {
      let mut conn = conn;
      conn.discard(&mut self.pools);
      return Route::Done;
    };
    let Some(slot) = self.slots.get_mut(idx) else {
      return Route::Done;
    };
    let conn_ref =
      ConnRef { generation: slot.generation, slot: u32::try_from(idx).unwrap_or(NO_SLOT) };
    conn.set_handle(ConnHandle { generation: conn_ref.generation, slot: conn_ref.slot });
    let timeout_us = self.params.handshake_timeout_ms().saturating_mul(1_000);
    *slot = Slot {
      conn: Some(conn),
      // A slot that waits in the dirty list stays there once (review L6)
      dirty: slot.dirty,
      generation: slot.generation,
      handshake_deadline_us: Some(now_us.saturating_add(timeout_us)),
      local_cid: local,
      next_free: NO_SLOT,
      original_dcid: None,
      sent: Tally::ZERO,
    };
    self.half_open = self.half_open.wrapping_add(1);
    self.live = self.live.wrapping_add(1);
    // A connection that a forwarded first Initial packet opens was counted by the worker that
    // forwarded it
    if !core::mem::take(&mut self.placement)
      && let Some(loads) = &self.loads
    {
      loads.opened(self.worker);
    }
    // The client sends its Initial packets to the CID that it chose until it learns ours
    let mapped = retry_scid.is_some() || self.cids.insert_original(original, conn_ref);
    if retry_scid.is_none()
      && mapped
      && let Some(slot) = self.slots.get_mut(idx)
    {
      slot.original_dcid = Some(original);
    }
    if !mapped || !self.cids.insert(&local, conn_ref) {
      // The caps on connections and handshakes leave room: never here
      cold_path();
      if let Some(conn) = self.slots.get_mut(idx).and_then(|el| el.conn.as_mut()) {
        conn.discard(&mut self.pools);
      }
      self.release_slot(idx);
      return Route::Done;
    }
    Route::Conn { idx, fresh: true }
  }

  fn make_conn(
    &mut self,
    now_us: u64,
    client_dcid: &[u8],
    local_cid: Cid,
    original: Cid,
    retry_scid: Option<Cid>,
    meta: DatagramMeta,
  ) -> crate::Result<QuicConn<A, RNG, TCX>> {
    let mut tp = self.conn_params.transport_params(local_cid, Some(original));
    tp.stateless_reset_token = Some(self.keys.reset_token(local_cid.as_slice())?);
    tp.retry_source_connection_id = retry_scid;
    let mut buffer = [0; TP_LEN];
    let len = tp.encode(&mut buffer)?;
    let tls = QuicTls::new(&self.tls, buffer.get(..len).unwrap_or_default(), &mut self.rng)?;
    let validated = retry_scid.is_some();
    let params = &self.conn_params;
    QuicConn::new_server(
      params,
      local_cid,
      client_dcid,
      meta,
      tls,
      now_us,
      &mut self.pools,
      validated,
    )
  }

  // A Retry in answer to the first Initial packet of a client, sent to `dcid` from `scid`, whose
  // source CID is a new CID of ours that the connection will have.
  fn queue_retry(&mut self, now_us: u64, dcid: &[u8], scid: &[u8], meta: DatagramMeta) {
    let Ok(original) = Cid::new(dcid) else {
      return;
    };
    let retry_scid = self.new_cid();
    let mut token = [0; RETRY_TOKEN_LEN];
    let Self { keys, rng, stateless, .. } = self;
    if keys.seal_retry_token(rng, meta.peer, now_us, &original, &retry_scid, &mut token).is_err() {
      return;
    }
    let Some(packet) = stateless.push(meta, StatelessKind::Retry) else {
      return;
    };
    match write_retry(scid, &retry_scid, dcid, &token, &mut packet.bytes) {
      Ok(len) => packet.len = u16::try_from(len).unwrap_or(0),
      Err(_err) => stateless.cancel_last(),
    }
  }

  // A stateless reset for our CID `dcid`, in answer to a datagram of `len` bytes.
  fn queue_reset(&mut self, now_us: u64, len: usize, dcid: &[u8], meta: DatagramMeta) {
    if len <= MAX_RESET_LEN {
      return;
    }
    // One byte less than a datagram of up to 43 bytes (RFC 9000 section 10.3), as far as the cap
    // lets it; else a length that does not tell a reset of ours (review L9)
    let reset_len = if len <= SHORT_TRIGGER_LEN {
      len.wrapping_sub(1).min(MAX_RESET_LEN)
    } else {
      let span =
        u32::try_from(MAX_RESET_LEN.wrapping_sub(MIN_RESET_LEN).wrapping_add(1)).unwrap_or(1);
      let pick = u32::from_be_bytes(self.rng.u8_4()) % span;
      MIN_RESET_LEN.wrapping_add(usize::try_from(pick).unwrap_or(0))
    };
    if !self.reset_budget.take(self.params.limits().stateless_reset_per_sec, now_us) {
      return;
    }
    let Ok(token) = self.keys.reset_token(dcid) else {
      return;
    };
    let Self { rng, stateless, .. } = self;
    let Some(packet) = stateless.push(meta, StatelessKind::Reset) else {
      return;
    };
    let token_at = reset_len.wrapping_sub(RESET_TOKEN_LEN);
    if let Some(random) = packet.bytes.get_mut(..token_at) {
      rng.fill_slice(random);
    }
    if let Some(first) = packet.bytes.first_mut() {
      *first = FIXED_BIT | (*first & 0x3f);
    }
    if let Some(dst) = packet.bytes.get_mut(token_at..reset_len) {
      dst.copy_from_slice(&token);
    }
    packet.len = u16::try_from(reset_len).unwrap_or(0);
  }

  // A Version Negotiation packet in answer to a long header packet of an unknown version sent to
  // `dcid` from `scid`, in a datagram of `len` bytes.
  fn queue_version_negotiation(
    &mut self,
    now_us: u64,
    (len, dcid, scid): (usize, &[u8], &[u8]),
    meta: DatagramMeta,
  ) {
    if len < MIN_INITIAL_DATAGRAM
      || !self.vn_budget.take(self.params.limits().stateless_reset_per_sec, now_us)
    {
      return;
    }
    let Some(packet) = self.stateless.push(meta, StatelessKind::VersionNegotiation) else {
      return;
    };
    match write_version_negotiation(scid, dcid, &mut packet.bytes) {
      0 => self.stateless.cancel_last(),
      written => packet.len = u16::try_from(written).unwrap_or(0),
    }
  }

  fn recv_segments(
    &mut self,
    now_us: u64,
    datagram: &mut [u8],
    meta: DatagramMeta,
    app: &mut A,
    may_forward: bool,
  ) -> RecvOutcome {
    let segment = meta.segment_size.map_or(datagram.len(), usize::from).max(1);
    // The worker that forwarded the first Initial packet of a client counted a connection here
    // (ruling T10-m): the connection that the datagram opens takes it, or it is given back
    self.placement = !may_forward && carries_placement(datagram);
    let meta = DatagramMeta { segment_size: None, ..meta };
    for (nth, chunk) in datagram.chunks_mut(segment).enumerate() {
      match self.route(now_us, chunk, meta, may_forward && nth == 0) {
        Route::Conn { idx, fresh } => {
          self.stats.datagrams_in = self.stats.datagrams_in.wrapping_add(1);
          self.deliver(now_us, idx, chunk, meta, fresh, app);
        }
        // Counted by the worker that receives it (review L10)
        Route::Forward(worker) => {
          self.stats.forwarded = self.stats.forwarded.wrapping_add(1);
          return RecvOutcome::Forward { worker };
        }
        Route::Done => self.stats.datagrams_in = self.stats.datagrams_in.wrapping_add(1),
      }
    }
    if core::mem::take(&mut self.placement)
      && let Some(loads) = &self.loads
    {
      loads.closed(self.worker);
    }
    RecvOutcome::Done
  }

  // Where the datagram `chunk` goes: see the module documentation. With `may_forward` false, what
  // is for another worker is dropped.
  fn route(&mut self, now_us: u64, chunk: &[u8], meta: DatagramMeta, may_forward: bool) -> Route {
    let Some(first) = chunk.first() else {
      return Route::Done;
    };
    let len = chunk.len();
    if first & 0x80 == 0 {
      let Some(dcid) = chunk.get(1..CID_LEN.wrapping_add(1)) else {
        return Route::Done;
      };
      if let Some(idx) = self.lookup(self.cids.get(dcid)) {
        return Route::Conn { idx, fresh: false };
      }
      if let Some(worker) = self.other_worker(dcid) {
        return if may_forward { Route::Forward(worker) } else { Route::Done };
      }
      self.queue_reset(now_us, len, dcid, meta);
      return Route::Done;
    }
    let Ok(header) = parse_header(chunk, CID_LEN) else {
      return Route::Done;
    };
    match header.ty {
      PacketTy::UnknownVersion => {
        self.queue_version_negotiation(now_us, (len, header.dcid, header.scid), meta);
        return Route::Done;
      }
      // Packets of servers
      PacketTy::Retry | PacketTy::VersionNegotiation => return Route::Done,
      PacketTy::Handshake | PacketTy::Initial | PacketTy::OneRtt | PacketTy::ZeroRtt => {}
    }
    let known = self.cids.get(header.dcid).or_else(|| self.cids.get_original(header.dcid));
    if let Some(idx) = self.lookup(known) {
      return Route::Conn { idx, fresh: false };
    }
    let is_initial = header.ty == PacketTy::Initial;
    if is_initial && header.token.is_empty() {
      return self.first_initial(now_us, (len, header.dcid, header.scid), meta, may_forward);
    }
    // The CID that the server chose, of another worker (ruling T10-e)
    if let Some(worker) = self.other_worker(header.dcid) {
      return if may_forward { Route::Forward(worker) } else { Route::Done };
    }
    if is_initial {
      let fields = (len, header.dcid, header.scid, header.token);
      return self.initial_with_token(now_us, fields, meta, may_forward);
    }
    Route::Done
  }

  // The worker that a CID of ours names, if it is not this one.
  fn other_worker(&self, cid: &[u8]) -> Option<u8> {
    let worker = *cid.first().filter(|_| cid.len() == CID_LEN)?;
    (worker != self.worker && worker < self.workers).then_some(worker)
  }

  // Gives the connection of slot `idx` up, aborted if it is not closed, and the slot back.
  fn remove(&mut self, idx: usize, app: &mut A) {
    let Some(conn) = self.slots.get_mut(idx).and_then(|el| el.conn.as_mut()) else {
      return;
    };
    conn.abort(app, &mut self.pools);
    self.release_slot(idx);
  }

  // The slot `idx`, whose connection is closed, goes back with what refers to it.
  fn release_slot(&mut self, idx: usize) {
    let free = self.free;
    let Some(slot) = self.slots.get_mut(idx) else {
      return;
    };
    if slot.conn.take().is_none() {
      return;
    }
    self.cids.remove(&slot.local_cid);
    if let Some(elem) = slot.original_dcid.take() {
      self.cids.remove_original(&elem);
    }
    if slot.handshake_deadline_us.take().is_some() {
      self.half_open = self.half_open.saturating_sub(1);
    }
    slot.generation = slot.generation.wrapping_add(1);
    slot.next_free = free;
    let idx_u32 = u32::try_from(idx).unwrap_or(NO_SLOT);
    self.free = idx_u32;
    self.timers.arm(idx_u32, None);
    self.live = self.live.saturating_sub(1);
    if let Some(loads) = &self.loads {
      loads.closed(self.worker);
    }
  }

  fn slots_len(&self) -> usize {
    self.slots.len()
  }
}

impl<A, RNG, TCX> core::fmt::Debug for Endpoint<A, RNG, TCX>
where
  A: QuicApp,
{
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Endpoint")
      .field("stats", &self.stats)
      .field("worker", &self.worker)
      .field("workers", &self.workers)
      .finish_non_exhaustive()
  }
}

impl<A, RNG, TCX> Drop for Endpoint<A, RNG, TCX>
where
  A: QuicApp,
{
  #[inline]
  fn drop(&mut self) {
    // The connections that `abort_all` did not end go with the pools, without the application
    let Self { loads, pools, slots, worker, .. } = self;
    for slot in slots.as_slice_mut() {
      if let Some(conn) = slot.conn.as_mut() {
        conn.discard(pools);
        if let Some(elem) = loads {
          elem.closed(*worker);
        }
      }
    }
  }
}

// If `datagram`, which went to another worker, is a first Initial packet of a client, for which
// the worker that forwarded it counted a connection on the other one: a long header Initial packet
// without a token (the others that are forwarded are sent to CIDs of ours).
fn carries_placement(datagram: &[u8]) -> bool {
  datagram.first().is_some_and(|el| el & 0x80 != 0)
    && parse_header(datagram, CID_LEN)
      .is_ok_and(|el| el.ty == PacketTy::Initial && el.token.is_empty())
}

// Where a datagram goes.
enum Route {
  // To the connection of this slot, opened for it if `fresh`
  Conn { idx: usize, fresh: bool },
  // Dropped, or answered with a stateless packet
  Done,
  Forward(u8),
}

// The place of a connection, kept with what the endpoint knows of it.
struct Slot<A, RNG, TCX>
where
  A: QuicApp,
{
  conn: Option<QuicConn<A, RNG, TCX>>,
  dirty: bool,
  generation: u32,
  // While the handshake is under way, when it must end
  handshake_deadline_us: Option<u64>,
  local_cid: [u8; CID_LEN],
  next_free: u32,
  // The destination CID of the first Initial packet of the client, while it maps to the slot
  original_dcid: Option<Cid>,
  // What the counters of the connection had at the last flush
  sent: Tally,
}

impl<A, RNG, TCX> Slot<A, RNG, TCX>
where
  A: QuicApp,
{
  const EMPTY: Self = Self {
    conn: None,
    dirty: false,
    generation: 0,
    handshake_deadline_us: None,
    local_cid: [0; CID_LEN],
    next_free: NO_SLOT,
    original_dcid: None,
    sent: Tally::ZERO,
  };
}

/// The counters of a connection that the endpoint sums: read at each flush of the connection, and
/// what grew since the last one added to [`EndpointStats`]. What a connection counts after its
/// last flush (a frame received just before it closes) is not summed.
#[derive(Clone, Copy, Debug)]
struct Tally([u64; 18]);

impl Tally {
  const ZERO: Self = Self([0; 18]);

  fn of<A, RNG, TCX>(conn: &QuicConn<A, RNG, TCX>) -> Self
  where
    A: QuicApp,
    RNG: CryptoRng + CryptoSeedableRng,
    TCX: TlsCtxSk,
  {
    let el = conn.stats();
    let (fins_out, frames_resent) = conn.stream_tally();
    let (stream_bytes_out, stream_bytes_copied) = conn.stream_bytes();
    Self([
      el.datagrams_out,
      el.packets_out,
      el.ack_only_out,
      fins_out,
      el.fin_flushes,
      el.fin_flushes_acked,
      el.data_blocked_in,
      el.stream_data_blocked_in,
      el.streams_blocked_in,
      el.packets_lost,
      el.pto_probes,
      frames_resent,
      el.fin_flushes_ack_owed,
      el.bytes_out,
      stream_bytes_out,
      stream_bytes_copied,
      el.pacer_holds,
      el.fin_flushes_owed_and_acked,
    ])
  }

  // Adds to `stats` what grew since `before`.
  fn add_since(&self, before: &Self, stats: &mut EndpointStats) {
    let fields = [
      &mut stats.datagrams_out,
      &mut stats.packets_out,
      &mut stats.ack_only_out,
      &mut stats.fins_out,
      &mut stats.fin_flushes,
      &mut stats.fin_flushes_acked,
      &mut stats.data_blocked_in,
      &mut stats.stream_data_blocked_in,
      &mut stats.streams_blocked_in,
      &mut stats.packets_lost,
      &mut stats.pto_probes,
      &mut stats.frames_resent,
      &mut stats.fin_flushes_ack_owed,
      &mut stats.bytes_out,
      &mut stats.stream_bytes_out,
      &mut stats.stream_bytes_copied,
      &mut stats.pacer_holds,
      &mut stats.fin_flushes_owed_and_acked,
    ];
    for ((field, now), then) in fields.into_iter().zip(self.0).zip(before.0) {
      *field = field.wrapping_add(now.wrapping_sub(then));
    }
  }
}

#[derive(Clone, Copy, Debug)]
enum StatelessKind {
  Reset,
  Retry,
  VersionNegotiation,
}

// A packet that needs no connection, sent before the packets of the connections.
#[derive(Clone, Copy, Debug)]
struct StatelessPacket {
  bytes: [u8; STATELESS_LEN],
  kind: StatelessKind,
  len: u16,
  local: Option<IpAddr>,
  peer: SocketAddr,
}

// The stateless packets that wait for a flush: one more than it holds is not sent.
#[derive(Debug)]
struct StatelessQueue {
  first: usize,
  len: usize,
  packets: [StatelessPacket; STATELESS_QUEUE],
}

impl StatelessQueue {
  const fn new() -> Self {
    let empty = StatelessPacket {
      bytes: [0; STATELESS_LEN],
      kind: StatelessKind::Reset,
      len: 0,
      local: None,
      peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };
    Self { first: 0, len: 0, packets: [empty; STATELESS_QUEUE] }
  }

  // Takes back the packet that was pushed last.
  const fn cancel_last(&mut self) {
    self.len = self.len.saturating_sub(1);
  }

  fn front(&self) -> Option<&StatelessPacket> {
    if self.len == 0 {
      return None;
    }
    self.packets.get(self.first)
  }

  fn pop(&mut self) {
    if self.len > 0 {
      self.first = self.first.wrapping_add(1) % STATELESS_QUEUE;
      self.len = self.len.wrapping_sub(1);
    }
  }

  // Room for a packet to the peer of `meta`, from the address that it sent to, if the queue is
  // not full.
  fn push(&mut self, meta: DatagramMeta, kind: StatelessKind) -> Option<&mut StatelessPacket> {
    if self.len >= STATELESS_QUEUE {
      return None;
    }
    let idx = self.first.wrapping_add(self.len) % STATELESS_QUEUE;
    self.len = self.len.wrapping_add(1);
    let packet = self.packets.get_mut(idx)?;
    packet.kind = kind;
    packet.len = 0;
    packet.local = meta.local;
    packet.peer = meta.peer;
    Some(packet)
  }
}

#[cfg(test)]
impl<A, RNG, TCX> Endpoint<A, RNG, TCX>
where
  A: QuicApp,
{
  /// The connection that `cid`, one of ours, leads to.
  pub(crate) fn conn(&self, cid: &[u8]) -> Option<&QuicConn<A, RNG, TCX>> {
    let conn = self.cids.get(cid)?;
    let slot = self.slots.get(usize::try_from(conn.slot).ok()?)?;
    slot.conn.as_ref().filter(|_| slot.generation == conn.generation)
  }

  /// The entries of the list of connections to flush.
  pub(crate) fn dirty_len(&self) -> usize {
    self.dirty.len()
  }

  /// The keys of the stateless packets.
  pub(crate) const fn keys(&self) -> &Arc<EndpointKeys> {
    &self.keys
  }

  /// The CIDs of the table of our CIDs.
  pub(crate) const fn our_cids(&self) -> usize {
    self.cids.len()
  }

  /// The pools of the worker.
  pub(crate) const fn pools(&self) -> &QuicPools {
    &self.pools
  }
}

#[cfg(test)]
impl<A, RNG, TCX> Endpoint<A, RNG, TCX>
where
  A: QuicApp,
  RNG: CryptoRng + CryptoSeedableRng,
  TCX: TlsCtxSk,
{
  /// [`Self::with_conn`] for the connection that `cid`, one of ours, leads to.
  pub(crate) fn with_cid<R>(
    &mut self,
    now_us: u64,
    cid: &[u8],
    app: &mut A,
    f: impl FnOnce(&mut A, &mut ConnCtx<'_, A::ConnState>) -> R,
  ) -> Option<R> {
    let conn = self.cids.get(cid)?;
    self.with_conn(now_us, ConnHandle { generation: conn.generation, slot: conn.slot }, app, f)
  }

  /// The handle of the connection that `cid`, one of ours, leads to.
  pub(crate) fn handle_of(&self, cid: &[u8]) -> Option<ConnHandle> {
    let conn = self.cids.get(cid)?;
    Some(ConnHandle { generation: conn.generation, slot: conn.slot })
  }

  /// The pools of the worker, for tests that run them out.
  pub(crate) const fn pools_mut(&mut self) -> &mut QuicPools {
    &mut self.pools
  }
}

#[cfg(test)]
mod tests;
