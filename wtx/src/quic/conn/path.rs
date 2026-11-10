//! Path validation and NAT rebinding (RFC 9000 sections 8.2 and 9, spec sections 5.4, 5.11 and
//! 10 Q1).
//!
//! A server takes a new address of its client once the handshake is confirmed, when the
//! highest-numbered packet so far comes from it and is not a probing one (RFC 9000 section 9.3):
//! it sends to that address from then on, at most three times what it received from it until the
//! address is validated (sections 8.1 and 9.3.1), and validates it with a PATH_CHALLENGE of
//! unpredictable data in a datagram of 1200 bytes, or as large as that limit lets it be, followed
//! once that one is answered by a second one in 1200 bytes (section 8.2.1). The path that was left
//! is challenged once too (section 9.3.3). The CID stays: a rebinding is no migration of the
//! client's choice, and the server has one CID (spec section 5.4), which also keeps every packet on
//! the worker that the CID names (spec section 5.11). A new IP address resets congestion control,
//! the RTT estimate and the datagram size, and the packets in flight on the old path leave the bytes
//! that the window counts and give no RTT sample; a new port only keeps all that (section 9.4).
//!
//! The validation is abandoned three times the larger of the PTO and the PTO of a new path
//! (kInitialRtt) after it started (section 8.2.4): the connection goes back to the last validated
//! path, with the state that it had there (section 9.3.2), or ends silently if there is none. It
//! goes back at once, without a validation, when a later non-probing packet comes from that path
//! again (sections 9.3 and 9.3.3). A packet of an earlier number that comes from the old address
//! after the switch moves nothing.
//!
//! A probing packet (PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID and PADDING frames only)
//! from another address moves nothing: its PATH_CHALLENGE is answered on the path it came from, in
//! a datagram of its own, at most three times what came from that address (section 8.2.2). Only the
//! latest challenge is answered, as on the current path, within the same budget.
//!
//! Before the handshake is confirmed the address does not change: packets from elsewhere are
//! processed but count nothing for the amplification limit (task 22).
//!
//! The state of the paths lives with the seldom used state of the connection ([`Paths`]), apart
//! from the fields of the current path: nothing is allocated.

use crate::{
  crypto::AEAD_TAG_LEN,
  quic::{
    DatagramMeta, Frame, FrameWriter, QuicApp, Space, TxArena,
    cc::{NewReno, Pacer},
    conn::{ConnState, INITIAL_MAX_DATAGRAM, MIN_DATAGRAM_LEN, OpenPacket, QuicConn, write_header},
    pmtud::Pmtud,
    pn_len_for,
    pools::QuicPools,
    recovery::RttEstimator,
    sent::{FrameRefRange, SentKind},
  },
  rng::{CryptoRng, CryptoSeedableRng},
  tls::{TlsCtxSk, next_rng},
};
use core::{
  fmt::{Debug, Formatter},
  hint::cold_path,
  net::{IpAddr, SocketAddr},
};

// The PATH_CHALLENGE frames of the validation of the current path whose answer is still taken:
// the latest ones sent
const CHALLENGES: usize = 4;
// The shortest 1-RTT packet that carries a PATH_CHALLENGE or a PATH_RESPONSE: the first byte, a
// CID of 20 bytes at most, a packet number of 4 bytes at most, the frame and the tag
const OFF_PATH_MIN_LEN: usize = 1 + 20 + 4 + PATH_FRAME_LEN + AEAD_TAG_LEN;
/// A PATH_CHALLENGE or PATH_RESPONSE frame: its type and its data.
pub(super) const PATH_FRAME_LEN: usize = 9;

/// The paths of a connection of a server, in its seldom used state: the validation of the current
/// path, the last validated one, the answer to a probe of another path. See the
/// [module documentation](self).
#[derive(Clone, Copy)]
pub(crate) struct Paths {
  // The PATH_CHALLENGE frames sent on the current path while its validation lasts, each with new
  // data (RFC 9000 section 13.3), the answer to any of which validates the address: the latest
  // `CHALLENGES` of them, in a ring
  challenges: [Option<SentChallenge>; CHALLENGES],
  // The slot of the latest one, and of the next one
  challenge_last: usize,
  challenge_next: usize,
  // A PATH_CHALLENGE is to be sent on the current path, a new one if one was lost
  challenge_owed: bool,
  // When the validation is abandoned
  deadline_us: Option<u64>,
  // The last validated path, while the current one is not
  last_valid: Option<ValidPath>,
  // The PATH_CHALLENGE that the path that was left is owed (RFC 9000 section 9.3.3)
  old_challenge: Option<Challenge>,
  // The max_udp_payload_size of the peer, for path MTU discovery on a new path
  peer_max_udp_payload_size: u64,
  // The address that the latest PATH_CHALLENGE from elsewhere came from, and what was exchanged
  // with it
  probe: Option<Probe>,
  // Congestion control and the RTT estimate were reset since the last validated path was left
  reset: bool,
  // What the data of the challenges comes from, drawn from the generator of the handshake
  seed: [u8; 32],
}

impl Paths {
  /// No path but the one of the handshake.
  pub(crate) const fn new() -> Self {
    Self {
      challenges: [None; CHALLENGES],
      challenge_last: 0,
      challenge_next: 0,
      challenge_owed: false,
      deadline_us: None,
      last_valid: None,
      old_challenge: None,
      peer_max_udp_payload_size: 0,
      probe: None,
      reset: false,
      seed: [0; 32],
    }
  }

  /// If a PATH_CHALLENGE is to be sent on the current path.
  pub(super) const fn challenge_due(&self) -> bool {
    self.challenge_owed
  }

  /// The data of the PATH_CHALLENGE that is written into a packet now: new, from the CSPRNG, and
  /// outstanding from now on.
  pub(super) fn take_challenge<RNG>(&mut self) -> crate::Result<[u8; 8]>
  where
    RNG: CryptoRng + CryptoSeedableRng,
  {
    let data = next_challenge::<RNG>(&mut self.seed)?;
    let slot = self.challenge_next % CHALLENGES;
    if let Some(elem) = self.challenges.get_mut(slot) {
      *elem = Some(SentChallenge { data, full: false });
    }
    self.challenge_last = slot;
    self.challenge_next = slot.wrapping_add(1) % CHALLENGES;
    self.challenge_owed = false;
    Ok(data)
  }

  /// The packet with the latest PATH_CHALLENGE went in a datagram of `len` bytes: its answer
  /// validates the path MTU if that is 1200 bytes or more (RFC 9000 section 8.2.1).
  pub(super) fn on_challenge_datagram(&mut self, len: usize) {
    if let Some(Some(elem)) = self.challenges.get_mut(self.challenge_last) {
      elem.full = len >= MIN_DATAGRAM_LEN;
    }
  }

  /// A packet with a PATH_CHALLENGE was lost: a new one is owed while the validation lasts.
  pub(super) const fn on_challenge_lost(&mut self) {
    if self.deadline_us.is_some() {
      self.challenge_owed = true;
    }
  }

  /// The transport parameters of the peer arrived.
  pub(super) const fn set_peer_max_udp_payload_size(&mut self, value: u64) {
    self.peer_max_udp_payload_size = value;
  }

  /// The handshake is confirmed: the seed of the challenges.
  pub(super) const fn set_seed(&mut self, seed: [u8; 32]) {
    self.seed = seed;
  }

  /// The address of the last validated path, while the current one is not validated.
  #[cfg(any(test, feature = "_fuzz-conn"))]
  pub(super) fn last_valid_peer(&self) -> Option<SocketAddr> {
    self.last_valid.map(|el| el.peer)
  }

  // The validation of the current path is over, or abandoned.
  const fn end_validation(&mut self) {
    self.challenges = [None; CHALLENGES];
    self.challenge_owed = false;
    self.deadline_us = None;
  }

  // The validation of the current path starts, or its second stage, until `deadline_us`.
  const fn start_validation(&mut self, deadline_us: u64) {
    self.challenge_owed = true;
    self.deadline_us = Some(deadline_us);
  }

  // If `data` is that of an outstanding challenge of the current path: whether that one went in
  // 1200 bytes.
  fn answered(&self, data: [u8; 8]) -> Option<bool> {
    self.challenges.iter().flatten().find(|el| el.data == data).map(|el| el.full)
  }
}

impl Debug for Paths {
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Paths")
      .field("deadline_us", &self.deadline_us)
      .field("last_valid", &self.last_valid.map(|el| el.peer))
      .field("probe", &self.probe.map(|el| el.peer))
      .finish_non_exhaustive()
  }
}

// A PATH_CHALLENGE sent on the current path.
#[derive(Clone, Copy, Debug)]
struct SentChallenge {
  data: [u8; 8],
  // In a datagram of 1200 bytes or more
  full: bool,
}

// A PATH_CHALLENGE for an address that is not the one of the current path.
#[derive(Clone, Copy, Debug)]
struct Challenge {
  data: [u8; 8],
  local: Option<IpAddr>,
  peer: SocketAddr,
}

// Another address that sent a PATH_CHALLENGE, a probe or the path that the connection left: what
// came from it and what went to it, unless it is validated.
#[derive(Clone, Copy, Debug)]
struct Probe {
  local: Option<IpAddr>,
  peer: SocketAddr,
  received: u64,
  sent: u64,
  validated: bool,
}

// A validated path and the state that the connection had on it.
#[derive(Clone, Copy, Debug)]
struct ValidPath {
  cc: NewReno,
  local: Option<IpAddr>,
  max_datagram: usize,
  peer: SocketAddr,
  pmtud: Pmtud,
  rtt: RttEstimator,
}

/// What the packets of one datagram showed of its path.
#[derive(Clone, Copy, Debug)]
pub(super) struct RxPath {
  /// A PATH_CHALLENGE came in the datagram.
  pub(super) challenged: bool,
  /// The handshake was confirmed when the datagram arrived.
  pub(super) confirmed: bool,
  /// The datagram came from the address of the current path.
  pub(super) from_peer: bool,
  /// A non-probing packet that is the highest-numbered so far came from another address.
  pub(super) migrate: bool,
  /// The packet being processed has a non-probing frame (RFC 9000 section 9.1).
  pub(super) non_probing: bool,
}

/// If `a` and `b` are the same IP address and port.
pub(super) fn same_addr(a: &SocketAddr, b: &SocketAddr) -> bool {
  a.ip() == b.ip() && a.port() == b.port()
}

// Unpredictable data for a PATH_CHALLENGE, from a generator made from `seed`, which moves on.
fn next_challenge<RNG>(seed: &mut [u8; 32]) -> crate::Result<[u8; 8]>
where
  RNG: CryptoRng + CryptoSeedableRng,
{
  Ok(next_rng::<RNG>(seed)?.u8_8())
}

impl<A, RNG, TCX, const IS_CLIENT: bool> QuicConn<A, RNG, TCX, IS_CLIENT>
where
  A: QuicApp,
  RNG: CryptoRng + CryptoSeedableRng,
  TCX: TlsCtxSk,
{
  /// What a datagram that came with `meta` is to the paths, before its packets are processed.
  pub(super) fn rx_path(&self, meta: &DatagramMeta) -> RxPath {
    RxPath {
      challenged: false,
      confirmed: self.state == ConnState::Confirmed,
      from_peer: IS_CLIENT || same_addr(&meta.peer, &self.peer),
      migrate: false,
      non_probing: false,
    }
  }

  /// The packets of a datagram of `len` bytes that came with `meta` from another address than
  /// the one of the current path were processed, which `rx` tells of.
  pub(super) fn after_other_address(
    &mut self,
    now_us: u64,
    rx: &RxPath,
    meta: &DatagramMeta,
    len: u64,
  ) -> crate::Result<()> {
    if rx.migrate && rx.confirmed {
      return self.migrate(now_us, rx, meta, len);
    }
    let Some(cold) = self.cold.as_deref_mut() else {
      return Ok(());
    };
    let paths = &mut cold.paths;
    if let Some(probe) = paths.probe.as_mut().filter(|el| same_addr(&el.peer, &meta.peer)) {
      probe.received = probe.received.saturating_add(len);
    } else if rx.challenged {
      let (local, peer) = (meta.local, meta.peer);
      paths.probe = Some(Probe { local, peer, received: len, sent: 0, validated: false });
    }
    Ok(())
  }

  /// When the validation of the current path is abandoned, if one is under way.
  pub(super) fn path_deadline(&self) -> Option<u64> {
    self.cold.as_deref().and_then(|el| el.paths.deadline_us)
  }

  /// The validation of the current path is abandoned (RFC 9000 sections 8.2.4 and 9.3.2): the
  /// connection goes back to the last validated path, with its state, or ends silently if there is
  /// none. Returns whether it ended.
  pub(super) fn on_path_timeout(&mut self, app: &mut A, pools: &mut QuicPools) -> bool {
    let Some(cold) = self.cold.as_deref_mut() else {
      return false;
    };
    cold.stats.path_validation_failures = cold.stats.path_validation_failures.wrapping_add(1);
    let paths = &mut cold.paths;
    paths.end_validation();
    let restore = core::mem::take(&mut paths.reset);
    let Some(valid) = paths.last_valid.take() else {
      // A path that answered its first challenge but not the one of 1200 bytes keeps going
      if self.address_validated {
        return false;
      }
      cold_path();
      self.enter_closed(app, pools);
      return true;
    };
    self.set_path(valid.peer, valid.local, true, (0, 0));
    if restore {
      self.restore_path_state(&valid);
    }
    false
  }

  /// A PATH_RESPONSE with `data` arrived, on any path (RFC 9000 section 8.2.3).
  pub(super) fn on_path_response(&mut self, now_us: u64, data: [u8; 8]) -> crate::Result<()> {
    let timeout = self.validation_timeout_us();
    let Some(cold) = self.cold.as_deref_mut() else {
      return Ok(());
    };
    let paths = &mut cold.paths;
    let Some(full) = paths.answered(data) else {
      return Ok(());
    };
    let first = !self.address_validated;
    if first {
      self.address_validated = true;
      // The amplification limit may have held the timer
      self.recovery.timer_stale = true;
    }
    if full {
      paths.end_validation();
      paths.last_valid = None;
      paths.reset = false;
      cold.stats.paths_validated = cold.stats.paths_validated.wrapping_add(1);
    } else if first {
      // The address is validated but not the path MTU: a second validation, in 1200 bytes now
      // that no limit holds it (RFC 9000 section 8.2.1)
      paths.start_validation(now_us.saturating_add(timeout));
    } else if !paths.challenges.iter().flatten().any(|el| el.full) {
      // Another small one answered, and none of 1200 bytes is outstanding
      paths.challenge_owed = true;
    }
    Ok(())
  }

  /// Writes the datagram that goes to an address other than the one of the current path, if one
  /// is owed: the PATH_CHALLENGE of the path that was left, or the PATH_RESPONSE to a probe.
  /// Returns whether one was written or given up, which the caller follows with another round.
  pub(super) fn flush_off_path(
    &mut self,
    now_us: u64,
    tx: &mut TxArena,
    pools: &mut QuicPools,
    batched: bool,
  ) -> bool {
    let Some((peer, local, size)) = self.off_path_due() else {
      return false;
    };
    // Too short for the frame: the answer does not go (RFC 9000 section 8.2.2)
    if size < OFF_PATH_MIN_LEN {
      self.give_up_off_path();
      return true;
    }
    let Some((start, buffer)) = tx.begin_at(peer, local, size) else {
      return false;
    };
    if buffer.len() < size {
      return false;
    }
    let waiting = pools.hp_batch.len();
    match self.write_off_path(now_us, buffer, size, batched.then_some(start), pools) {
      Ok(0) => {
        pools.hp_batch.truncate(waiting);
        self.give_up_off_path();
      }
      Ok(len) => {
        tx.commit(len);
        if pools.hp_batch.is_full() {
          self.protect_batch(now_us, tx, pools);
        }
      }
      Err(err) => {
        cold_path();
        pools.hp_batch.truncate(waiting);
        self.close_on_error(now_us, &err);
      }
    }
    true
  }

  /// Where the datagram that goes to an address other than the one of the current path goes, if
  /// one is owed, and its size: 1200 bytes, or what the amplification limit of a probing address
  /// leaves.
  pub(super) fn off_path_due(&self) -> Option<(SocketAddr, Option<IpAddr>, usize)> {
    if IS_CLIENT
      || !matches!(self.state, ConnState::Handshake | ConnState::Confirmed)
      || self.data.keys.is_none()
    {
      return None;
    }
    let paths = &self.cold.as_deref()?.paths;
    if let Some(elem) = &paths.old_challenge {
      return Some((elem.peer, elem.local, MIN_DATAGRAM_LEN));
    }
    if self.path_response.is_some() && self.path_response_off {
      let probe = paths.probe.as_ref()?;
      let allowed = if probe.validated {
        u64::MAX
      } else {
        probe.received.saturating_mul(3).saturating_sub(probe.sent)
      };
      let size = usize::try_from(allowed).unwrap_or(usize::MAX).min(MIN_DATAGRAM_LEN);
      return Some((probe.peer, probe.local, size));
    }
    None
  }

  // What `off_path_due` gives can not go: it is not owed anymore.
  fn give_up_off_path(&mut self) {
    if let Some(cold) = self.cold.as_deref_mut()
      && cold.paths.old_challenge.take().is_some()
    {
      return;
    }
    self.path_response = None;
    self.path_response_off = false;
  }

  // The peer moved to the address of `meta`, from which `len` bytes came (RFC 9000 section 9.3).
  fn migrate(
    &mut self,
    now_us: u64,
    rx: &RxPath,
    meta: &DatagramMeta,
    len: u64,
  ) -> crate::Result<()> {
    let timeout = self.validation_timeout_us();
    let ip_changed = meta.peer.ip() != self.peer.ip();
    let (peer, local, validated) = (self.peer, self.local, self.address_validated);
    let saved = ValidPath {
      cc: self.recovery.cc,
      local,
      max_datagram: self.max_datagram,
      peer,
      pmtud: self.pmtud,
      rtt: self.recovery.rtt,
    };
    let Some(cold) = self.cold.as_deref_mut() else {
      return Ok(());
    };
    cold.stats.migrations = cold.stats.migrations.wrapping_add(1);
    let paths = &mut cold.paths;
    // A probe of this address is the new path, with what it exchanged
    let probe = paths.probe.filter(|el| same_addr(&el.peer, &meta.peer));
    if probe.is_some() {
      paths.probe = None;
    }
    if self.path_response.is_some() {
      if !self.path_response_off {
        // It answers a challenge of the path that is left, where it goes, as to a probe, within
        // what the amplification limit of that path leaves (RFC 9000 section 8.2.2)
        let (received, sent) = (self.bytes_received, self.bytes_sent);
        paths.probe = Some(Probe { local, peer, received, sent, validated });
        self.path_response_off = true;
      } else if rx.challenged || probe.is_some() {
        self.path_response_off = false;
      }
      // Otherwise it answers a probe of another address, where it still goes
    }
    if let Some(valid) = paths.last_valid.filter(|el| same_addr(&el.peer, &meta.peer)) {
      // Back to the last validated path, at once and with its state (RFC 9000 sections 9.3 and
      // 9.3.3)
      let restore = core::mem::take(&mut paths.reset);
      paths.end_validation();
      paths.last_valid = None;
      paths.old_challenge = None;
      self.set_path(meta.peer, meta.local, true, (0, 0));
      if restore {
        self.restore_path_state(&valid);
      }
      return Ok(());
    }
    paths.end_validation();
    paths.start_validation(now_us.saturating_add(timeout));
    if validated {
      // The path that is left is the last validated one, and it is challenged (RFC 9000 section
      // 9.3.3). A path that was not validated yet is abandoned, without a challenge: what it may
      // be sent is bounded by what it sent
      paths.last_valid = Some(saved);
      paths.reset = false;
      let data = next_challenge::<RNG>(&mut paths.seed)?;
      paths.old_challenge = Some(Challenge { data, local, peer });
    }
    paths.reset |= ip_changed;
    let peer_max_udp_payload_size = paths.peer_max_udp_payload_size;
    let (received, sent) = probe.map_or((0, 0), |el| (el.received, el.sent));
    self.set_path(meta.peer, meta.local, false, (received.saturating_add(len), sent));
    if ip_changed {
      // Ruling T23-m: keep the PING allowance the (now previous) validated path had until the new
      // path has an RTT sample, computed before the RTT estimate is reset below.
      self.ping_allowance_floor = self.ping_allowance();
      // RFC 9000 section 9.4
      self.retag_in_flight();
      self.recovery.cc = NewReno::new(INITIAL_MAX_DATAGRAM);
      self.recovery.rtt = RttEstimator::new();
      self.recovery.pacer = Pacer::new();
      self.recovery.pacer_release_us = None;
      self.max_datagram = INITIAL_MAX_DATAGRAM;
      self.pmtud.restart(peer_max_udp_payload_size, &meta.peer, INITIAL_MAX_DATAGRAM);
    }
    Ok(())
  }

  // The state that the connection had on `valid`, to which it goes back. The packets in flight
  // were sent on the path that it leaves.
  fn restore_path_state(&mut self, valid: &ValidPath) {
    self.retag_in_flight();
    self.recovery.cc = valid.cc;
    self.recovery.rtt = valid.rtt;
    self.recovery.pacer = Pacer::new();
    self.recovery.pacer_release_us = None;
    self.max_datagram = valid.max_datagram;
    self.pmtud = valid.pmtud;
  }

  // The packets in flight on the path that is left: out of the bytes that congestion control
  // counts, and no RTT sample (RFC 9000 section 9.4). They stay in flight for loss detection, and
  // their frames are owed again if they are lost.
  fn retag_in_flight(&mut self) {
    let Self { data, recovery, .. } = self;
    let (base, next) = (data.sent.base(), data.sent.next_pn());
    for pn in base..next {
      if let Some(record) = data.sent.get_mut(pn)
        && record.kind == SentKind::InFlight
      {
        recovery.on_gone(record);
        record.kind = SentKind::OffPath;
      }
    }
  }

  // Packets go to `peer` from `local` from now on, with `received` and `sent` bytes so far for
  // the amplification limit, unless the address is `validated`.
  fn set_path(
    &mut self,
    peer: SocketAddr,
    local: Option<IpAddr>,
    validated: bool,
    (received, sent): (u64, u64),
  ) {
    self.peer = peer;
    self.local = local;
    self.address_validated = validated;
    self.bytes_received = received;
    self.bytes_sent = sent;
    self.recovery.pto_count = 0;
    self.recovery.timer_stale = true;
  }

  // Three times the larger of the current PTO and the PTO of a new path (RFC 9000 section
  // 8.2.4).
  fn validation_timeout_us(&self) -> u64 {
    let new_path = RttEstimator::new().pto_base_us().saturating_add(self.peer_max_ack_delay_us());
    self.pto_us().max(new_path).saturating_mul(3)
  }

  // A 1-RTT packet of the PATH_CHALLENGE of the path that was left, or of the PATH_RESPONSE to a
  // probe, and PADDING, in a datagram of `size` bytes: ack-eliciting, in flight but not counted by
  // congestion control. Returns its length, zero if it can not go.
  // `hp_at`: where `buffer` starts in the arena, if the header protection waits for a batch.
  fn write_off_path(
    &mut self,
    now_us: u64,
    buffer: &mut [u8],
    size: usize,
    hp_at: Option<usize>,
    pools: &mut QuicPools,
  ) -> crate::Result<usize> {
    let old = self.cold.as_deref().and_then(|el| el.paths.old_challenge);
    let frame = match (old, self.path_response) {
      (Some(elem), _) => Frame::PathChallenge(elem.data),
      (None, Some(data)) => Frame::PathResponse(data),
      (None, None) => return Ok(0),
    };
    let (dcid, scid, key_phase) = (self.peer_cid, self.local_cid, self.key.local_phase);
    let sp = &mut self.data;
    if sp.keys.is_none() || !sp.sent.reserve(pools) {
      return Ok(0);
    }
    let pn = sp.sent.next_pn();
    let pn_len = pn_len_for(pn, sp.largest_acked);
    let Some(buffer) = buffer.get_mut(..size) else {
      return Ok(0);
    };
    let Some((header_len, pn_offset, _)) =
      write_header(buffer, Space::Data, &dcid, &scid, (pn, pn_len), key_phase, &[])
    else {
      return Ok(0);
    };
    let payload_len = size.saturating_sub(header_len).saturating_sub(AEAD_TAG_LEN);
    let Some(payload) = buffer.get_mut(header_len..header_len.wrapping_add(payload_len)) else {
      return Ok(0);
    };
    payload.fill(0);
    if !FrameWriter::new(payload).write_frame(&frame) {
      return Ok(0);
    }
    let packet = OpenPacket {
      ack_eliciting: true,
      challenge: false,
      frames: FrameRefRange::EMPTY,
      full_datagram: false,
      header_len,
      length_at: None,
      mtu_probe: false,
      off_path: true,
      padded: true,
      payload_len,
      pn,
      pn_len,
      pn_offset,
      space: Space::Data,
      start: 0,
    };
    let len = self.seal(now_us, buffer, &packet, hp_at.map(|el| (el, &mut pools.hp_batch)))?;
    let len_u64 = u64::try_from(len).unwrap_or(u64::MAX);
    let is_challenge = old.is_some();
    if !is_challenge {
      self.path_response = None;
      self.path_response_off = false;
    }
    if let Some(cold) = self.cold.as_deref_mut() {
      let stats = &mut cold.stats;
      stats.bytes_out = stats.bytes_out.wrapping_add(len_u64);
      stats.datagrams_out = stats.datagrams_out.wrapping_add(1);
      if is_challenge {
        cold.paths.old_challenge = None;
        stats.path_challenges_out = stats.path_challenges_out.wrapping_add(1);
      } else if let Some(probe) = cold.paths.probe.as_mut() {
        probe.sent = probe.sent.saturating_add(len_u64);
      }
    }
    Ok(len)
  }
}

#[cfg(test)]
mod tests {
  use crate::{
    quic::{
      ConnState, Space,
      cc::{CongestionControl as _, NewReno},
      recovery::INITIAL_RTT_US,
      testing::{Behavior, CLIENT_ADDR, Impairment, Link, LinkOpts, TestApp, run_lossy_requests},
    },
    sync::AtomicU64,
    tests::_count_allocations_in,
  };
  use alloc::{vec, vec::Vec};
  use core::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::atomic::Ordering,
  };

  const PING: [u8; 1] = [0x01];
  // The address that a NAT gives the client after a rebinding: another IP address
  const MOVED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 50_000);
  // A rebinding that changes only the port
  const REPORTED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 50_001);
  static BIG: [u8; 30_000] = [b'x'; 30_000];

  fn settled(opts: &LinkOpts) -> Link {
    let mut link = Link::new(opts);
    link.run();
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    assert_eq!(link.client.conn.state(), ConnState::Confirmed);
    link
  }

  fn requests(count: usize) -> Vec<Vec<u8>> {
    (0..count).map(|el| alloc::format!("request {el}").into_bytes()).collect()
  }

  // A 1-RTT packet of the client with `payload`, which can be anything, made with its keys and
  // the next packet number of the client, which skips it.
  fn client_packet(link: &mut Link, payload: &[u8]) -> Vec<u8> {
    let conn = &mut link.client.conn;
    let (dcid, scid, phase) = (conn.peer_cid, conn.local_cid, conn.key.local_phase);
    let sp = super::super::space_mut(&mut conn.data, &mut conn.handshake, Space::Data).unwrap();
    let pn = sp.sent.next_pn();
    sp.sent.skip();
    let mut out = vec![0; 2048 + payload.len()];
    let (header_len, pn_offset, _) =
      super::super::write_header(&mut out, Space::Data, &dcid, &scid, (pn, 4), phase, &[]).unwrap();
    out[header_len..header_len + payload.len()].copy_from_slice(payload);
    let keys = sp.keys.as_ref().unwrap();
    let len = crate::quic::protect(&keys.local, &mut out, pn_offset, pn, 4, payload.len()).unwrap();
    out.truncate(len);
    out
  }

  // A datagram of the client with a PING, which is not delivered: its length is that of the
  // datagram.
  fn ping(link: &mut Link) -> Vec<u8> {
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    let mut datagrams = link.client.take_datagrams();
    assert_eq!(datagrams.len(), 1);
    datagrams.pop().unwrap()
  }

  // A PING of the client, with what else it has to send, to the server from `from`. Returns the
  // bytes of its datagrams.
  fn ping_from(link: &mut Link, from: SocketAddr) -> u64 {
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    link.client.take_datagrams().into_iter().map(|el| to_server(link, el, from)).sum()
  }

  // Gives `datagram` to the server, from `from`. Returns its length.
  fn to_server(link: &mut Link, mut datagram: Vec<u8>, from: SocketAddr) -> u64 {
    link.server.recv(link.now_us, &mut datagram, from);
    datagram.len() as u64
  }

  // Flushes the server: the bytes of its datagrams to `to`, which are dropped, as all the others.
  fn server_bytes_to(link: &mut Link, to: SocketAddr) -> u64 {
    let _ = link.server.flush(link.now_us);
    link.server.take_datagrams_to().iter().filter(|el| el.0 == to).map(|el| el.1.len() as u64).sum()
  }

  // Rule (RFC 9000 sections 9.3 and 8.2): after the confirmation, the client keeps its CID and the
  // NAT gives it another address, while requests are under way. The server sends to the new
  // address from the first non-probing packet that comes from it, challenges it, and the old path
  // too (section 9.3.3); the client answers the challenge, the new path is validated and the
  // requests go on, none lost and without a stall.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn nat_rebinding_switches_the_path_after_validation() {
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Respond(b"ok"));
    let mut link = settled(&opts);
    link.impair(Impairment::delay(5_000));
    let before = run_lossy_requests(&mut link, &requests(20), 4, 2_000_000);
    assert!(before.responses.iter().all(|el| el == b"ok"));
    // Requests in flight when the NAT rebinds
    let mut in_flight = Vec::new();
    for _ in 0..4 {
      let id = link.client.with_ctx(link.now_us, |cx| {
        let id = cx.open_bidi().unwrap();
        cx.write(id, b"in flight", true).unwrap();
        id
      });
      in_flight.push(id);
    }
    let _ = link.step_impaired();
    link.client.addr = MOVED;
    // The next datagram of the client comes from the new address
    link.client.conn.queue_test_frames(&PING);
    let _ = link.client.flush(link.now_us);
    let datagrams = link.client.take_datagrams();
    assert!(!datagrams.is_empty());
    for datagram in datagrams {
      let _ = to_server(&mut link, datagram, MOVED);
    }
    assert_eq!(link.server.conn.peer, MOVED);
    assert!(!link.server.conn.address_validated);
    let _ = link.server.flush(link.now_us);
    let out = link.server.take_datagrams_to();
    assert!(
      out.iter().any(|el| el.0 == MOVED),
      "{:?}",
      out.iter().map(|el| el.0).collect::<Vec<_>>()
    );
    // The previous path is challenged as well (RFC 9000 section 9.3.3)
    assert!(out.iter().any(|el| el.0 == CLIENT_ADDR));
    for (to, mut datagram) in out {
      if to == MOVED {
        link.client.recv(link.now_us, &mut datagram, crate::quic::testing::SERVER_ADDR);
      }
    }
    // The client got a PATH_CHALLENGE, which it answers
    assert!(link.client.conn.path_response.is_some());
    while link.step_impaired() || link.flying() > 0 {
      if link.flying() > 0 {
        let _ = link.advance_to_next_event();
      }
    }
    assert_eq!(link.server.conn.peer, MOVED);
    assert!(link.server.conn.address_validated);
    // The first challenge went in a datagram that the amplification limit kept below 1200 bytes:
    // a second one of 1200 bytes validated the path MTU, and the validation is over
    let stats = *link.server.conn.stats();
    assert_eq!(
      (stats.migrations, stats.paths_validated, stats.path_validation_failures),
      (1, 1, 0)
    );
    assert!(stats.path_challenges_out >= 3, "{stats:?}");
    assert_eq!(link.server.conn.path_deadline(), None);
    // Nothing of the requests in flight was lost
    for id in in_flight {
      let log = link.client.app.streams.remove(&id.0).unwrap();
      assert_eq!((log.data.as_slice(), log.fin), (b"ok".as_slice(), true));
    }
    let after = run_lossy_requests(&mut link, &requests(100), 8, 2_000_000);
    assert!(after.responses.iter().all(|el| el == b"ok"));
    assert!(after.longest_stall_us <= 100_000, "{}", after.longest_stall_us);
    assert_eq!(link.server.conn.peer, MOVED);
  }

  // Rule (RFC 9000 sections 9.3.1 and 21.1.1.2): until the new address is validated the server
  // sends to it at most three times what it received from it, however much it has to send.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn unvalidated_new_path_is_limited_to_three_times_received() {
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Respond(&BIG));
    let mut link = settled(&opts);
    link.client.addr = MOVED;
    let _id = link.client.with_ctx(link.now_us, |cx| {
      let id = cx.open_bidi().unwrap();
      cx.write(id, b"large", true).unwrap();
      id
    });
    let _ = link.client.flush(link.now_us);
    let mut received = 0;
    for datagram in link.client.take_datagrams() {
      received += to_server(&mut link, datagram, MOVED);
    }
    assert_eq!(link.server.conn.peer, MOVED);
    // The client hears nothing on its new address: no PATH_RESPONSE comes
    let mut sent = 0;
    for _ in 0..16 {
      sent += server_bytes_to(&mut link, MOVED);
      link.advance(20_000);
    }
    assert!(sent > 0 && sent <= 3 * received, "{sent} bytes sent for {received} received");
    // Each datagram from the address lets three times its size more go
    let more = ping_from(&mut link, MOVED);
    let mut again = 0;
    for _ in 0..16 {
      again += server_bytes_to(&mut link, MOVED);
      link.advance(20_000);
    }
    assert!(again > 0, "nothing more after {more} bytes received");
    assert!(sent + again <= 3 * (received + more), "{} for {}", sent + again, received + more);
    assert!(!link.server.conn.address_validated);
  }

  // Rule (RFC 9000 sections 9.1 and 8.2.2): a packet of probing frames only from a new address
  // (PATH_CHALLENGE and PADDING) does not move the path: the PATH_RESPONSE goes to the address that
  // the challenge came from, padded to 1200 bytes if the amplification limit of that address lets
  // it, and nothing else does.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn probing_packet_from_a_new_address_does_not_switch_the_path() {
    let mut link = settled(&LinkOpts::new(None));
    let elsewhere = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 50_000);
    for (from, padding, expected) in [(MOVED, 1100usize, None), (elsewhere, 0, Some(3))] {
      let mut payload = vec![0x1a, 1, 2, 3, 4, 5, 6, 7, 8];
      payload.resize(9 + padding, 0);
      let packet = client_packet(&mut link, &payload);
      let received = to_server(&mut link, packet, from);
      assert_eq!(link.server.conn.peer, CLIENT_ADDR);
      assert!(link.server.conn.address_validated);
      let _ = link.server.flush(link.now_us);
      let out = link.server.take_datagrams_to();
      let to_moved: Vec<_> = out.iter().filter(|el| el.0 == from).collect();
      assert_eq!(
        to_moved.len(),
        1,
        "{:?}",
        out.iter().map(|el| (el.0, el.1.len())).collect::<Vec<_>>()
      );
      let len = to_moved[0].1.len() as u64;
      match expected {
        None => assert_eq!(len, 1200),
        Some(factor) => assert!(len <= factor * received, "{len} for {received}"),
      }
      // A 1-RTT packet that the client opens
      let opened = link.client.conn.stats().packets_in;
      let mut datagram = to_moved[0].1.clone();
      link.client.recv(link.now_us, &mut datagram, crate::quic::testing::SERVER_ADDR);
      assert_eq!(link.client.conn.stats().packets_in, opened + 1);
      link.run();
      assert_eq!(link.server.conn.peer, CLIENT_ADDR);
    }
  }

  // Rule (RFC 9000 sections 8.2.4 and 9.3.2): a new path that is not validated within three
  // times the larger of the PTO and the PTO of a new path (kInitialRtt) is abandoned: the server
  // sends to the last validated address again, with the congestion state of that path.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn failed_path_validation_reverts_to_the_old_path() {
    let mut link = settled(&LinkOpts::new(None));
    let (cwnd, srtt) = (link.server.conn.cwnd(), link.server.conn.smoothed_rtt_us());
    let start = link.now_us;
    let _ = ping_from(&mut link, MOVED);
    assert_eq!(link.server.conn.peer, MOVED);
    // 3 x max(PTO, PTO of kInitialRtt), the latter larger on the fake clock
    let timeout = 3 * (INITIAL_RTT_US + 4 * INITIAL_RTT_US / 2 + 25_000);
    // Nothing comes from the new address: the server alone
    while link.now_us + 100_000 < start + timeout {
      link.now_us += 100_000;
      link.server.on_timeout(link.now_us);
      let _ = link.server.flush(link.now_us);
      let _ = link.server.take_datagrams();
    }
    assert_eq!(link.server.conn.peer, MOVED);
    link.now_us = start + timeout;
    link.server.on_timeout(link.now_us);
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    assert_eq!(link.server.conn.peer, CLIENT_ADDR);
    assert!(link.server.conn.address_validated);
    assert_eq!((link.server.conn.cwnd(), link.server.conn.smoothed_rtt_us()), (cwnd, srtt));
    assert_eq!(link.server.conn.stats().path_validation_failures, 1);
    link.run();
    link.client.conn.queue_test_frames(&PING);
    link.run();
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    assert_eq!(link.server.conn.peer, CLIENT_ADDR);
  }

  // Rule (RFC 9000 section 9.3): the path changes only for the highest-numbered non-probing
  // packet: one that the old address sent earlier and that arrives after the switch does not
  // move it back.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn reordered_old_packet_does_not_switch_back() {
    let mut link = settled(&LinkOpts::new(None));
    let (first, second) = (ping(&mut link), ping(&mut link));
    let _ = to_server(&mut link, second, MOVED);
    assert_eq!(link.server.conn.peer, MOVED);
    let packets = link.server.conn.stats().packets_in;
    let _ = to_server(&mut link, first, CLIENT_ADDR);
    // Processed, but the path stays
    assert_eq!(link.server.conn.stats().packets_in, packets + 1);
    assert_eq!(link.server.conn.peer, MOVED);
    assert!(!link.server.conn.address_validated);
  }

  // Rule (RFC 9000 sections 9.3, 9.3.2 and 9.3.3): a later non-probing packet from the old,
  // validated address moves the path back to it at once, without a validation, with the
  // congestion state of that path.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn later_packet_from_old_address_switches_back() {
    let mut link = settled(&LinkOpts::new(None));
    let (cwnd, srtt) = (link.server.conn.cwnd(), link.server.conn.smoothed_rtt_us());
    let (first, second) = (ping(&mut link), ping(&mut link));
    let _ = to_server(&mut link, first, MOVED);
    assert_eq!(link.server.conn.peer, MOVED);
    let _ = to_server(&mut link, second, CLIENT_ADDR);
    assert_eq!(link.server.conn.peer, CLIENT_ADDR);
    assert!(link.server.conn.address_validated);
    assert_eq!((link.server.conn.cwnd(), link.server.conn.smoothed_rtt_us()), (cwnd, srtt));
    link.run();
    assert_eq!(link.server.conn.peer, CLIENT_ADDR);
  }

  // The congestion state of a settled link with an RTT of 20 ms, a window that grew and packets
  // of the server in flight.
  fn busy_link() -> Link {
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Respond(&BIG));
    let mut link = settled(&opts);
    link.impair(Impairment::delay(10_000));
    let run = run_lossy_requests(&mut link, &requests(8), 4, 5_000_000);
    assert_eq!(run.responses.len(), 8);
    // A response in flight
    let _id = link.client.with_ctx(link.now_us, |cx| {
      let id = cx.open_bidi().unwrap();
      cx.write(id, b"large", true).unwrap();
      id
    });
    let _ = link.client.flush(link.now_us);
    for datagram in link.client.take_datagrams() {
      let _ = to_server(&mut link, datagram, CLIENT_ADDR);
    }
    let _ = link.server.flush(link.now_us);
    let _ = link.server.take_datagrams();
    assert!(link.server.conn.bytes_in_flight() > 0);
    assert!(link.server.conn.cwnd() > NewReno::new(1200).window());
    assert!(link.server.conn.smoothed_rtt_us() < INITIAL_RTT_US);
    link
  }

  // Rule (RFC 9000 section 9.4): a rebinding that changes only the port of the client keeps the
  // congestion controller and the RTT estimate.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn port_only_change_keeps_congestion_state() {
    let mut link = busy_link();
    let conn = &link.server.conn;
    let state = (conn.cwnd(), conn.smoothed_rtt_us(), conn.bytes_in_flight(), conn.max_datagram());
    let _ = ping_from(&mut link, REPORTED);
    let conn = &link.server.conn;
    assert_eq!(conn.peer, REPORTED);
    assert_eq!(
      (conn.cwnd(), conn.smoothed_rtt_us(), conn.bytes_in_flight(), conn.max_datagram()),
      state
    );
  }

  // Rule (RFC 9000 section 9.4): a new IP address of the client resets the congestion controller
  // and the RTT estimate to their initial values, and the packets in flight on the old path do not
  // count against the window of the new one. The datagram size starts over at 1200 bytes.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn address_change_resets_congestion_and_rtt() {
    let mut link = busy_link();
    let _ = ping_from(&mut link, MOVED);
    let conn = &link.server.conn;
    assert_eq!(conn.peer, MOVED);
    assert_eq!(conn.cwnd(), NewReno::new(1200).window());
    assert_eq!(conn.smoothed_rtt_us(), INITIAL_RTT_US);
    assert_eq!(conn.bytes_in_flight(), 0);
    assert_eq!(conn.max_datagram(), 1200);
  }

  // Rule (RFC 9000 section 9): no path change before the handshake is confirmed. The second
  // flight of the client, its Finished and a request, from another address, completes the
  // handshake but leaves the address of the connection as it was.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn no_path_change_before_handshake_confirmation() {
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Respond(b"ok"));
    let mut link = Link::new(&opts);
    let _ = link.server.flush(link.now_us);
    assert!(link.deliver_to_client() > 0);
    let _id = link.client.with_ctx(link.now_us, |cx| {
      let id = cx.open_bidi().unwrap();
      cx.write(id, b"early", true).unwrap();
      id
    });
    let _ = link.client.flush(link.now_us);
    for datagram in link.client.take_datagrams() {
      assert_eq!(link.server.conn.state(), ConnState::Handshake);
      let _ = to_server(&mut link, datagram, MOVED);
    }
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    assert_eq!(link.server.conn.peer, CLIENT_ADDR);
    link.run();
    assert_eq!(link.client.conn.state(), ConnState::Confirmed);
    assert_eq!(link.server.conn.peer, CLIENT_ADDR);
  }

  // Zero allocation after warm-up (spec section 5.4): rebindings and their validations, once the
  // pools of the server are warm, allocate nothing on the server.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn rebinding_allocates_nothing_after_warmup() {
    static OTHERS: AtomicU64 = AtomicU64::new(0);
    static SERVER: AtomicU64 = AtomicU64::new(0);
    let mut opts = LinkOpts::new(None);
    opts.counters = Some((&SERVER, &OTHERS));
    _count_allocations_in(&OTHERS);
    let mut link = settled(&opts);
    let round = |link: &mut Link| {
      for addr in [MOVED, REPORTED, CLIENT_ADDR] {
        // Apart enough that the client takes the challenges within its budget for them
        link.advance(1_000_000);
        link.client.addr = addr;
        link.client.conn.queue_test_frames(&PING);
        link.run();
        assert_eq!(link.server.conn.peer, addr);
        assert!(link.server.conn.address_validated);
        assert_eq!(link.server.conn.path_deadline(), None);
      }
    };
    round(&mut link);
    round(&mut link);
    let before = SERVER.load(Ordering::Relaxed);
    round(&mut link);
    let allocations = SERVER.load(Ordering::Relaxed) - before;
    assert_eq!(allocations, 0, "{allocations} allocations in three rebindings");
    assert_eq!(link.server.conn.stats().migrations, 9);
  }

  // The PATH_CHALLENGE and PATH_RESPONSE data of the datagrams of the server to `to`, which the
  // client opens with its keys without taking them: (challenges, responses).
  fn path_frames(
    link: &Link,
    out: &[(SocketAddr, Vec<u8>)],
    to: SocketAddr,
  ) -> (Vec<[u8; 8]>, Vec<[u8; 8]>) {
    let (mut challenges, mut responses) = (Vec::new(), Vec::new());
    let keys = link.client.conn.data.keys.as_ref().unwrap();
    for (_, datagram) in out.iter().filter(|el| el.0 == to) {
      let mut packet = datagram.clone();
      let header = crate::quic::parse_header(&packet, 8).unwrap();
      let pn_offset = header.pn_offset;
      let largest = link.client.conn.data.recv.largest();
      let (pn, pn_len, _) =
        crate::quic::remove_header_protection(keys.remote.hp(), &mut packet, pn_offset, largest)
          .unwrap();
      let header_len = pn_offset + pn_len;
      let payload = crate::quic::open_payload(
        keys.remote.aead(),
        keys.remote.iv(),
        &mut packet,
        header_len,
        pn,
      )
      .unwrap();
      for frame in crate::quic::FrameReader::new(payload, Space::Data) {
        match frame.unwrap() {
          crate::quic::Frame::PathChallenge(data) => challenges.push(data),
          crate::quic::Frame::PathResponse(data) => responses.push(data),
          _ => {}
        }
      }
    }
    (challenges, responses)
  }

  // A packet of the client of a PING padded to about 1200 bytes, from `from`: room for a challenge
  // of 1200 bytes under the amplification limit.
  fn padded_ping_from(link: &mut Link, from: SocketAddr) -> u64 {
    let mut payload = vec![0; 1150];
    payload[0] = 0x01;
    let packet = client_packet(link, &payload);
    to_server(link, packet, from)
  }

  // The client moved to MOVED, from which its first datagram is a small PING: the first challenge
  // goes in a datagram that the amplification limit keeps below 1200 bytes. Returns its data.
  fn rebound_with_a_small_challenge(link: &mut Link) -> [u8; 8] {
    let _ = ping_from(link, MOVED);
    assert_eq!(link.server.conn.peer, MOVED);
    let _ = link.server.flush(link.now_us);
    let out = link.server.take_datagrams_to();
    assert!(out.iter().filter(|el| el.0 == MOVED).all(|el| el.1.len() < 1200));
    let (challenges, _) = path_frames(link, &out, MOVED);
    assert_eq!(challenges.len(), 1);
    challenges[0]
  }

  // The challenge of the current path is declared lost and sent again, now in 1200 bytes, which a
  // padded PING from the new address leaves room for. Returns its data.
  fn challenge_sent_again(link: &mut Link) -> [u8; 8] {
    let _ = padded_ping_from(link, MOVED);
    link.server.conn.declare_in_flight_lost(&mut link.server.parts.pools);
    let _ = link.server.flush(link.now_us);
    let out = link.server.take_datagrams_to();
    let (challenges, _) = path_frames(link, &out, MOVED);
    assert_eq!(
      challenges.len(),
      1,
      "{:?}",
      out.iter().map(|el| (el.0, el.1.len())).collect::<Vec<_>>()
    );
    assert!(out.iter().any(|el| el.0 == MOVED && el.1.len() >= 1200));
    challenges[0]
  }

  // The client answers `data` from MOVED.
  fn respond(link: &mut Link, data: [u8; 8]) {
    let mut payload = vec![0x1b];
    payload.extend_from_slice(&data);
    let packet = client_packet(link, &payload);
    let _ = to_server(link, packet, MOVED);
  }

  // Rule (RFC 9000 section 13.3): a PATH_CHALLENGE that is sent again has a new payload.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn retransmitted_challenge_carries_new_data() {
    let mut link = settled(&LinkOpts::new(None));
    let first = rebound_with_a_small_challenge(&mut link);
    let again = challenge_sent_again(&mut link);
    assert_ne!(first, again);
  }

  // Rule (RFC 9000 sections 8.2.1 and 8.2.3): the answer to the challenge that went in a datagram
  // below 1200 bytes validates the address, not the path MTU, even when a copy of that challenge
  // went in 1200 bytes later: the validation goes on, with a challenge of 1200 bytes owed.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn response_to_the_small_challenge_does_not_validate_the_path_mtu() {
    let mut link = settled(&LinkOpts::new(None));
    let small = rebound_with_a_small_challenge(&mut link);
    let _full = challenge_sent_again(&mut link);
    respond(&mut link, small);
    let conn = &link.server.conn;
    assert!(conn.address_validated);
    assert_eq!(conn.stats().paths_validated, 0);
    assert!(conn.path_deadline().is_some());
    assert!(conn.cold.as_deref().unwrap().paths.challenge_owed);
  }

  // Rule (RFC 9000 sections 8.2.3 and 13.3): the answer to any challenge that is still outstanding
  // validates the address; the answer to the one of 1200 bytes validates the path MTU too.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn response_to_any_outstanding_challenge_validates_the_address() {
    for answer_small in [true, false] {
      let mut link = settled(&LinkOpts::new(None));
      let small = rebound_with_a_small_challenge(&mut link);
      let full = challenge_sent_again(&mut link);
      respond(&mut link, if answer_small { small } else { full });
      let conn = &link.server.conn;
      assert!(conn.address_validated, "{answer_small}");
      assert_eq!(conn.stats().paths_validated, u64::from(!answer_small));
      assert_eq!(conn.path_deadline().is_none(), !answer_small);
    }
  }

  // Rule (RFC 9000 section 8.2.2): a PATH_CHALLENGE that came on the path that the connection then
  // leaves is still answered, on that path.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn pending_path_response_survives_a_migration() {
    let mut link = settled(&LinkOpts::new(None));
    let mut payload = vec![0x1a, 9, 8, 7, 6, 5, 4, 3, 2];
    payload.resize(1100, 0);
    let packet = client_packet(&mut link, &payload);
    let _ = to_server(&mut link, packet, CLIENT_ADDR);
    assert_eq!(link.server.conn.path_response, Some([9, 8, 7, 6, 5, 4, 3, 2]));
    // The NAT rebinds before the server sends anything
    let _ = ping_from(&mut link, MOVED);
    assert_eq!(link.server.conn.peer, MOVED);
    let _ = link.server.flush(link.now_us);
    let out = link.server.take_datagrams_to();
    let (_, to_old) = path_frames(&link, &out, CLIENT_ADDR);
    let (_, to_new) = path_frames(&link, &out, MOVED);
    assert_eq!(to_old, [[9, 8, 7, 6, 5, 4, 3, 2]]);
    assert!(to_new.is_empty());
    assert_eq!(link.server.conn.path_response, None);
  }

  // Spec section 5.4 (review finding 11): the size of a connection and of its seldom used state,
  // which holds the paths, as this build lays them out (a test build: the production connection
  // is smaller, see the const assert next to `SizeProbeApp`).
  #[test]
  fn connection_and_cold_state_sizes() {
    use crate::quic::conn::{ConnCold, Paths, SizeProbeApp};
    let conn =
      size_of::<crate::quic::QuicConn<SizeProbeApp, crate::rng::ChaCha20, crate::tls::SkCtx>>();
    let (cold, paths) = (size_of::<ConnCold>(), size_of::<Paths>());
    std::eprintln!("sizes: QuicConn {conn} B, ConnCold {cold} B, of which Paths {paths} B");
    assert!(conn <= 4096, "{conn}");
    assert!(cold <= 1024, "{cold}");
  }
}
