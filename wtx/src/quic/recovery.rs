//! Loss recovery (RFC 9002): the RTT estimator, loss detection by packet and time thresholds,
//! persistent congestion, and the state of congestion control and pacing that a connection keeps
//! inline (ruling T9-c). The probe timeout, which needs the three packet number spaces, is the
//! connection's ([`crate::quic::conn`]).
//!
//! A lost packet keeps its record, out of flight, and its frames are queued again: STREAM and
//! CRYPTO data by range, control frames as owed bits with their current values. An acknowledgment
//! that arrives late for such a packet still marks its data acknowledged, so that the queued
//! copies are cut down to what is still missing and nothing acknowledged is sent again.

use crate::quic::{
  cc::{CongestionControl, NewReno, Pacer},
  sent::{SentKind, SentPacket, SentRing},
};

/// The timer granularity (RFC 9002 section 6.1.2).
pub(crate) const GRANULARITY_US: u64 = 1_000;
/// The RTT before a sample (RFC 9002 section 6.2.2).
pub(crate) const INITIAL_RTT_US: u64 = 333_000;
/// Packets acknowledged after one that make it lost (RFC 9002 section 6.1.1).
pub(crate) const PACKET_THRESHOLD: u64 = 3;
// RFC 9002 section 7.6.1
const PERSISTENT_CONGESTION_THRESHOLD: u64 = 3;

/// The RTT estimator of RFC 9002 section 5.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RttEstimator {
  /// When the first sample was taken.
  pub(crate) first_sample_us: Option<u64>,
  /// The latest sample.
  pub(crate) latest_us: u64,
  /// The smallest sample.
  pub(crate) min_us: u64,
  /// The variation.
  pub(crate) rttvar_us: u64,
  /// The smoothed RTT.
  pub(crate) smoothed_us: u64,
}

impl RttEstimator {
  /// No sample yet: the initial RTT.
  #[inline]
  pub(crate) const fn new() -> Self {
    Self {
      first_sample_us: None,
      latest_us: 0,
      min_us: 0,
      rttvar_us: INITIAL_RTT_US / 2,
      smoothed_us: INITIAL_RTT_US,
    }
  }

  /// The time that loss detection waits for a packet that later ones overtook: 9/8 of the larger
  /// of the latest and the smoothed RTT, at least the granularity (RFC 9002 section 6.1.2).
  #[inline]
  pub(crate) const fn loss_delay_us(&self) -> u64 {
    let rtt = if self.latest_us > self.smoothed_us { self.latest_us } else { self.smoothed_us };
    let delay = rtt.saturating_mul(9) / 8;
    if delay > GRANULARITY_US { delay } else { GRANULARITY_US }
  }

  /// How long losses must span to be persistent congestion, with the `max_ack_delay` of the peer
  /// (RFC 9002 section 7.6.1).
  #[inline]
  pub(crate) const fn persistent_congestion_us(&self, max_ack_delay_us: u64) -> u64 {
    self
      .pto_base_us()
      .saturating_add(max_ack_delay_us)
      .saturating_mul(PERSISTENT_CONGESTION_THRESHOLD)
  }

  /// The duration of a probe timeout before backoff, without the `max_ack_delay` of the peer.
  #[inline]
  pub(crate) const fn pto_base_us(&self) -> u64 {
    let variance = self.rttvar_us.saturating_mul(4);
    let variance = if variance > GRANULARITY_US { variance } else { GRANULARITY_US };
    self.smoothed_us.saturating_add(variance)
  }

  /// Persistent congestion is established: the smallest RTT is the newest sample from now on
  /// (RFC 9002 section 5.2, review J6).
  #[inline]
  pub(crate) const fn on_persistent_congestion(&mut self) {
    self.min_us = self.latest_us;
  }

  /// Takes the sample `latest_us`, at `now_us`, of a packet that the peer acknowledged after
  /// `ack_delay_us`, which counts up to `max_ack_delay_us` once the handshake is `confirmed`
  /// (RFC 9002 section 5.3).
  #[inline]
  pub(crate) fn update(
    &mut self,
    latest_us: u64,
    ack_delay_us: u64,
    max_ack_delay_us: u64,
    confirmed: bool,
    now_us: u64,
  ) {
    self.latest_us = latest_us;
    if self.first_sample_us.is_none() {
      self.first_sample_us = Some(now_us);
      self.min_us = latest_us;
      self.smoothed_us = latest_us;
      self.rttvar_us = latest_us / 2;
      return;
    }
    self.min_us = self.min_us.min(latest_us);
    let ack_delay = if confirmed { ack_delay_us.min(max_ack_delay_us) } else { ack_delay_us };
    // The delay counts unless it makes the sample smaller than the smallest one
    let adjusted = match latest_us.checked_sub(ack_delay) {
      Some(elem) if elem >= self.min_us => elem,
      _ => latest_us,
    };
    let variation = self.smoothed_us.abs_diff(adjusted);
    self.rttvar_us = self.rttvar_us.saturating_mul(3).saturating_add(variation) / 4;
    self.smoothed_us = self.smoothed_us.saturating_mul(7).saturating_add(adjusted) / 8;
  }
}

/// The recovery and congestion state that a connection keeps inline.
#[derive(Debug)]
pub(crate) struct Recovery {
  /// The bytes of the packets in flight that congestion control counts.
  pub(crate) bytes_in_flight: u64,
  /// Congestion control.
  pub(crate) cc: NewReno,
  // The most bytes in flight since the last acknowledgment: if the window was used, so that it
  // may grow (RFC 9002 section 7.8)
  in_flight_high: u64,
  /// When the loss detection timer fires, if it is armed.
  pub(crate) loss_timer_us: Option<u64>,
  /// Pacing.
  pub(crate) pacer: Pacer,
  /// When the pacer lets the next packet in flight go, if it held one back.
  pub(crate) pacer_release_us: Option<u64>,
  /// Probes owed after a probe timeout, in the space `probe_space`.
  pub(crate) probes: u8,
  /// See [`Self::probes`].
  pub(crate) probe_space: crate::quic::Space,
  /// Probe timeouts in a row.
  pub(crate) pto_count: u32,
  /// The RTT estimator.
  pub(crate) rtt: RttEstimator,
  /// What arms the loss detection timer changed: it is set again.
  pub(crate) timer_stale: bool,
}

impl Recovery {
  /// Nothing sent yet, with datagrams of `max_datagram` bytes.
  #[inline]
  pub(crate) const fn new(max_datagram: usize) -> Self {
    Self {
      bytes_in_flight: 0,
      cc: NewReno::new(max_datagram),
      in_flight_high: 0,
      loss_timer_us: None,
      pacer: Pacer::new(),
      pacer_release_us: None,
      probes: 0,
      probe_space: crate::quic::Space::Initial,
      pto_count: 0,
      rtt: RttEstimator::new(),
      timer_stale: false,
    }
  }

  /// If a packet of `max_datagram` bytes in flight fits in the window, which `max_in_flight`
  /// caps.
  #[inline]
  pub(crate) fn can_send(&self, max_in_flight: usize, max_datagram: usize) -> bool {
    let size = u64::try_from(max_datagram).unwrap_or(u64::MAX);
    let window = u64::try_from(self.window(max_in_flight)).unwrap_or(u64::MAX);
    self.bytes_in_flight.saturating_add(size) <= window
  }

  /// `packet` was acknowledged: it leaves the bytes in flight. The window grows later, once loss
  /// detection ran for the same acknowledgment ([`Self::grow`]).
  #[inline]
  pub(crate) fn on_acked(&mut self, packet: &SentPacket) {
    if packet.counts_for_congestion() {
      self.bytes_in_flight = self.bytes_in_flight.saturating_sub(u64::from(packet.size));
    }
  }

  /// The window grows by what an acknowledgment acknowledged, once loss detection ran for it (RFC
  /// 9002 appendices A.7 and B.5, review J1): `since_recovery`, the bytes of the packets sent after
  /// `recovery_start_us`, the recovery period when it arrived, and the newest send time of them;
  /// `all`, the same of every packet that congestion control counts. If the acknowledgment started
  /// a recovery period, they were all sent before it and nothing grows; if it showed persistent
  /// congestion, which ends recovery (appendix B.8), they all count. A window that was not used,
  /// or above `max_in_flight`, which caps what is used (review J2), does not grow.
  #[inline]
  pub(crate) fn grow(
    &mut self,
    since_recovery: (usize, Option<u64>),
    all: (usize, Option<u64>),
    recovery_start_us: Option<u64>,
    now_us: u64,
    max_in_flight: usize,
  ) {
    let start = self.cc.recovery_start_us();
    let (bytes, newest) = if start == recovery_start_us {
      since_recovery
    } else if start.is_none() {
      all
    } else {
      return;
    };
    let Some(newest_us) = newest else {
      return;
    };
    let cwnd = self.cc.window();
    let used = u64::try_from(cwnd).unwrap_or(u64::MAX);
    if cwnd < max_in_flight && self.in_flight_high.saturating_mul(2) >= used {
      self.cc.on_acked(bytes, newest_us, now_us);
    }
  }

  /// An acknowledgment was processed.
  #[inline]
  pub(crate) fn on_ack_done(&mut self) {
    self.in_flight_high = self.bytes_in_flight;
    self.timer_stale = true;
  }

  /// `packet` is out of flight: lost, or its space discarded.
  #[inline]
  pub(crate) fn on_gone(&mut self, packet: &SentPacket) {
    if packet.counts_for_congestion() {
      self.bytes_in_flight = self.bytes_in_flight.saturating_sub(u64::from(packet.size));
    }
  }

  /// `packet` was sent.
  #[inline]
  pub(crate) fn on_sent(&mut self, packet: &SentPacket) {
    if packet.counts_for_congestion() {
      self.bytes_in_flight = self.bytes_in_flight.saturating_add(u64::from(packet.size));
      self.in_flight_high = self.in_flight_high.max(self.bytes_in_flight);
      self.cc.on_sent(usize::from(packet.size));
    }
    if packet.ack_eliciting {
      self.timer_stale = true;
    }
  }

  /// The congestion window, at most `max_in_flight`.
  #[inline]
  pub(crate) fn window(&self, max_in_flight: usize) -> usize {
    self.cc.window().min(max_in_flight)
  }
}

/// What [`detect_lost`] found.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Losses {
  /// When the oldest packet that is not lost yet becomes lost by the time threshold, if one does.
  pub(crate) loss_time_us: Option<u64>,
  /// When the newest packet that was declared lost and that congestion control counts was sent.
  pub(crate) newest_lost_us: Option<u64>,
  /// If the losses show persistent congestion (RFC 9002 section 7.6.2).
  pub(crate) persistent: bool,
}

/// Declares lost the packets of `sent`, up to `largest_acked`, that it acknowledged three later
/// ones or that were sent more than `loss_delay_us` before `now_us` (RFC 9002 section 6.1): each
/// one is given to `on_lost`, as it was, and kept out of flight.
///
/// `persistent` is when the first RTT sample was taken and how long losses must span to be
/// persistent congestion: two ack-eliciting packets sent after the sample and that far apart are
/// declared lost with nothing between them acknowledged.
#[inline]
pub(crate) fn detect_lost(
  sent: &mut SentRing,
  largest_acked: u64,
  now_us: u64,
  loss_delay_us: u64,
  persistent: Option<(u64, u64)>,
  mut on_lost: impl FnMut(u64, SentPacket),
) -> Losses {
  let mut rslt = Losses::default();
  let lost_send_time = now_us.checked_sub(loss_delay_us);
  let last = largest_acked.min(sent.next_pn().saturating_sub(1));
  // When the first ack-eliciting packet of the current run of losses was sent
  let mut run_start: Option<u64> = None;
  let mut pn = sent.base();
  while pn <= last {
    let Some(packet) = sent.get_mut(pn) else {
      // Acknowledged: the run of losses ends
      run_start = None;
      pn = pn.wrapping_add(1);
      continue;
    };
    if packet.kind == SentKind::Lost {
      pn = pn.wrapping_add(1);
      continue;
    }
    let by_time = lost_send_time.is_some_and(|elem| packet.time_us <= elem);
    if !by_time && largest_acked < pn.saturating_add(PACKET_THRESHOLD) {
      // The packets after this one are newer still
      rslt.loss_time_us = Some(packet.time_us.saturating_add(loss_delay_us));
      break;
    }
    let lost = *packet;
    packet.kind = SentKind::Lost;
    if lost.counts_for_congestion() {
      rslt.newest_lost_us = rslt.newest_lost_us.max(Some(lost.time_us));
      if let Some((first_sample, duration)) = persistent
        && lost.ack_eliciting
        && lost.time_us > first_sample
      {
        match run_start {
          None => run_start = Some(lost.time_us),
          Some(start) => rslt.persistent |= lost.time_us.saturating_sub(start) >= duration,
        }
      }
    }
    on_lost(pn, lost);
    pn = pn.wrapping_add(1);
  }
  rslt
}

#[cfg(test)]
mod tests {
  use crate::{
    quic::{
      ConnState,
      testing::{
        Behavior, Impairment, Link, LinkOpts, LossyRun, Parts, TestApp, run_lossy_requests,
      },
    },
    sync::AtomicU64,
    tests::_count_allocations_in,
  };
  use alloc::vec::Vec;
  use core::sync::atomic::Ordering;

  // 5% of the datagrams of each direction dropped, 5% reordered and 5% duplicated, with 10 ms of
  // one-way delay
  fn lossy(seed: u64) -> Impairment {
    Impairment { drop: 0.05, reorder: 0.05, duplicate: 0.05, delay_us: 10_000, seed }
  }

  // Requests of 1 to 400 bytes, and one of 2 MiB in the middle
  fn requests(count: usize, body: usize) -> Vec<Vec<u8>> {
    (0..count)
      .map(|nth| {
        let len = if nth == count / 2 { body } else { 1 + nth * 37 % 400 };
        (0..len).map(|el| (el * 31 + nth) as u8).collect()
      })
      .collect()
  }

  // 2,000 requests and a body of 2 MiB, echoed by the server, over a lossy link from the first
  // datagram on, handshake included
  fn lossy_transfer(seed: u64) -> (Link, LossyRun) {
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Echo);
    let mut link = Link::new(&opts);
    link.impair(lossy(seed));
    let requests = requests(2000, 2 << 20);
    let run = run_lossy_requests(&mut link, &requests, 64, 120_000_000);
    for (nth, response) in run.responses.iter().enumerate() {
      assert!(*response == requests[nth], "seed {seed}: request {nth} came back otherwise");
    }
    (link, run)
  }

  fn check_lossy_transfer(seed: u64) -> LossyRun {
    let (link, run) = lossy_transfer(seed);
    assert!(
      run.longest_stall_us <= 2_000_000,
      "seed {seed}: a stall of {} us",
      run.longest_stall_us
    );
    for state in [link.server.conn.state(), link.client.conn.state()] {
      assert_eq!(state, ConnState::Confirmed, "seed {seed}");
    }
    run
  }

  // Every byte of 2,000 requests and of a body of 2 MiB comes back over a link that drops,
  // reorders and duplicates 5% of the datagrams, and nothing stalls for more than 2 s of the clock.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn transfer_completes_under_5pct_loss_reorder_dup() {
    for seed in [1, 2, 3] {
      let _run = check_lossy_transfer(seed);
    }
  }

  // The same with 20 seeds, run once by hand (`--ignored`): it prints each one.
  #[cfg_attr(miri, ignore)]
  #[ignore = "20 seeds: run once by hand"]
  #[test]
  fn transfer_completes_under_5pct_loss_reorder_dup_twenty_seeds() {
    for seed in 1..=20 {
      let run = check_lossy_transfer(seed);
      std::eprintln!(
        "seed {seed}: ok, {} us of clock, longest stall {} us, {} datagrams",
        run.elapsed_us,
        run.longest_stall_us,
        run.datagrams
      );
    }
  }

  // Lost stream data goes again, and only the parts that were not acknowledged: across the lossy
  // run, which declares packets lost that arrive later (reordering) and acknowledges them late,
  // no range that was acknowledged is sent again.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn no_spurious_retransmit_of_acknowledged_ranges() {
    for seed in [4, 5] {
      let (link, _run) = lossy_transfer(seed);
      for (side, conn) in
        [("server", link.server.conn.streams()), ("client", link.client.conn.streams())]
      {
        let (retransmitted, resent_acked) = conn.retransmissions();
        assert!(retransmitted > 0, "seed {seed}: the {side} sent nothing again");
        assert_eq!(resent_acked, 0, "seed {seed}: the {side} sent acknowledged ranges again");
      }
      // Packets were declared lost that were acknowledged after that
      assert!(link.server.conn.stats().late_acks > 0, "seed {seed}");
    }
  }

  // The last packet of a response is lost and nothing follows it: the probe timeout of the
  // server fires, its probe is acknowledged, and the acknowledgment makes the lost packet lost
  // by the time threshold, which sends it again. The response completes within a PTO and two
  // round trips.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn pto_probe_after_tail_loss() {
    const RESPONSE: &[u8; 3000] = &[b'r'; 3000];
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Respond(RESPONSE));
    let mut link = Link::new(&opts);
    link.impair(Impairment::delay(10_000));
    while link.server.conn.state() != ConnState::Confirmed
      || link.client.conn.state() != ConnState::Confirmed
      || link.flying() > 0
    {
      if !link.step_impaired() {
        assert!(link.advance_to_next_event());
      }
    }
    // The server drops the last datagram of its response, once
    link.filter = Some(|to_server, datagram| !to_server && datagram.len() < 1000);
    let now_us = link.now_us;
    let id = link
      .client
      .with_ctx(now_us, |cx| {
        let id = cx.open_bidi()?;
        cx.write(id, b"GET /", true)?;
        Ok::<_, crate::Error>(id)
      })
      .unwrap();
    let start = link.now_us;
    let mut dropped = false;
    while !link.client.app.streams.get(&id.0).is_some_and(|el| el.fin) {
      if !link.step_impaired() {
        if link.filter.is_some() && link.flying() == 0 {
          // The tail is gone: the server only has its timer left
          link.filter = None;
          dropped = true;
          assert!(link.server.conn.pto_count() == 0);
        }
        assert!(link.advance_to_next_event(), "nothing left to happen");
      }
      assert!(link.now_us - start < 5_000_000, "the response never completed");
    }
    assert!(dropped);
    assert_eq!(link.client.app.streams[&id.0].data, RESPONSE);
    // The probe fired once: an RTT of 20 ms gives a PTO of about 20 + 4 * 10 + 25 ms
    assert!(link.server.conn.stats().pto_probes > 0);
    let elapsed = link.now_us - start;
    assert!(elapsed < 400_000, "{elapsed} us");
    assert_eq!(link.server.conn.pto_count(), 0, "an acknowledgment resets the backoff");
  }

  // A long blackout: every packet of the server is lost for more than three PTOs, probes
  // included. The acknowledgment that ends it declares lost two ack-eliciting packets sent more
  // than the persistent congestion duration apart, with nothing acknowledged between them, and
  // the window collapses to two datagrams (RFC 9002 section 7.6). The transfer then completes.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn persistent_congestion_collapses_window() {
    let body: alloc::rc::Rc<[u8]> = (0..400_000u32).map(|el| el as u8).collect();
    let mut opts = LinkOpts::new(None);
    let response = crate::quic::BodyRef::new(body.clone(), 0..400_000).unwrap();
    opts.server_app = TestApp::new(Behavior::RespondBody(b"", response));
    let mut link = Link::new(&opts);
    link.impair(Impairment::delay(10_000));
    let now_us = link.now_us;
    while link.server.conn.state() != ConnState::Confirmed || link.flying() > 0 {
      if !link.step_impaired() {
        assert!(link.advance_to_next_event());
      }
    }
    let id = link
      .client
      .with_ctx(link.now_us.max(now_us), |cx| {
        let id = cx.open_bidi()?;
        cx.write(id, b"GET /", true)?;
        Ok::<_, crate::Error>(id)
      })
      .unwrap();
    // Until the window grew past its initial size
    let initial = link.server.conn.cwnd();
    while link.server.conn.cwnd() < 2 * initial {
      if !link.step_impaired() {
        assert!(link.advance_to_next_event());
      }
    }
    let mss = link.server.conn.max_datagram();
    link.filter = Some(|to_server, _| !to_server);
    let blackout = link.now_us;
    while link.now_us - blackout < 3_000_000 {
      if !link.step_impaired() {
        assert!(link.advance_to_next_event());
      }
    }
    assert!(link.server.conn.pto_count() >= 3, "{}", link.server.conn.pto_count());
    link.filter = None;
    let mut lowest = usize::MAX;
    while !link.client.app.streams.get(&id.0).is_some_and(|el| el.fin) {
      if !link.step_impaired() {
        assert!(link.advance_to_next_event());
      }
      lowest = lowest.min(link.server.conn.cwnd());
      assert!(link.now_us - blackout < 30_000_000, "the transfer never completed");
    }
    // The window went to its minimum, two datagrams. Persistent congestion ends recovery (RFC 9002
    // appendix B.8), so the packets that the same acknowledgment acknowledged, the probes, grow it
    // at once (appendix B.5, after loss detection as in appendix A.7): at most two more
    assert_eq!(link.server.conn.stats().persistent_congestions, 1);
    assert!((2 * mss..=4 * mss).contains(&lowest), "{lowest}");
    assert_eq!(link.client.app.streams[&id.0].data, &body[..]);
  }

  // A server whose response is in flight, the client having sent its request
  fn responding(body_len: u32, change: fn(&mut LinkOpts)) -> (Link, crate::quic::StreamId) {
    let body: alloc::rc::Rc<[u8]> = (0..body_len).map(|el| el as u8).collect();
    let mut opts = LinkOpts::new(None);
    let response = crate::quic::BodyRef::new(body, 0..body_len).unwrap();
    opts.server_app = TestApp::new(Behavior::RespondBody(b"", response));
    change(&mut opts);
    let mut link = Link::new(&opts);
    link.run();
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    let now_us = link.now_us;
    let id = link
      .client
      .with_ctx(now_us, |cx| {
        let id = cx.open_bidi()?;
        cx.write(id, b"GET /", true)?;
        Ok::<_, crate::Error>(id)
      })
      .unwrap();
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    (link, id)
  }

  // Review J1, RFC 9002 appendix A.7: an ACK that acknowledges packets and declares one lost
  // halves the window that was in use. The packets that it acknowledges were sent before the
  // recovery period that the loss starts, so they make it grow first by nothing.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn ack_that_declares_a_loss_halves_the_window_without_growth() {
    let (mut link, _id) = responding(100_000, |_| {});
    let cwnd = link.server.conn.cwnd();
    assert_eq!(link.server.conn.ssthresh(), usize::MAX);
    let _ = link.server.flush(link.now_us);
    let mut flight = link.server.take_datagrams();
    assert!(flight.len() >= 8, "{}", flight.len());
    // The first datagram is lost, the others arrive and one ACK reports them
    for datagram in flight.iter_mut().skip(1) {
      link.client.recv(link.now_us, datagram, crate::quic::testing::SERVER_ADDR);
    }
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    assert_eq!(link.server.conn.stats().packets_lost, 1);
    assert_eq!(link.server.conn.cwnd(), cwnd / 2);
    assert_eq!(link.server.conn.ssthresh(), cwnd / 2);
  }

  // Review J2, RFC 9002 section 7.8: a window that `max_in_flight` caps is not used beyond the
  // cap, so it does not grow far past it: a loss then reduces the bytes actually in flight.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn window_does_not_grow_past_the_in_flight_cap() {
    const CAP: usize = 32 << 10;
    static NTH: AtomicU64 = AtomicU64::new(0);
    let (mut link, id) = responding(1 << 20, |el| el.server.max_in_flight = CAP);
    link.impair(Impairment::delay(5_000));
    let mut largest = 0;
    while !link.client.app.streams.get(&id.0).is_some_and(|el| el.fin) {
      if !link.step_impaired() {
        assert!(link.advance_to_next_event());
      }
      largest = largest.max(link.server.conn.cwnd());
      assert!(link.server.conn.cwnd() <= 2 * CAP, "{}", link.server.conn.cwnd());
    }
    assert!(largest >= CAP, "{largest}");
    assert_eq!(link.server.conn.window_in_use(), CAP);
    // One datagram of the next response is lost
    NTH.store(0, Ordering::Relaxed);
    link.filter = Some(|to_server, _| !to_server && NTH.fetch_add(1, Ordering::Relaxed) == 20);
    let now_us = link.now_us;
    let id = link
      .client
      .with_ctx(now_us, |cx| {
        let id = cx.open_bidi()?;
        cx.write(id, b"GET /", true)?;
        Ok::<_, crate::Error>(id)
      })
      .unwrap();
    let lost = link.server.conn.stats().packets_lost;
    while link.server.conn.stats().packets_lost == lost {
      if !link.step_impaired() {
        assert!(link.advance_to_next_event());
      }
    }
    assert!(link.server.conn.window_in_use() < CAP, "{}", link.server.conn.window_in_use());
    while !link.client.app.streams.get(&id.0).is_some_and(|el| el.fin) {
      if !link.step_impaired() {
        assert!(link.advance_to_next_event());
      }
    }
  }

  // Review J6, RFC 9002 section 5.2: once persistent congestion is established, the smallest RTT
  // is the newest sample, so that a path that got slower is not judged by its old minimum.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn persistent_congestion_resets_min_rtt() {
    let (mut link, id) = responding(400_000, |_| {});
    link.impair(Impairment::delay(5_000));
    while link.client.app.streams.get(&id.0).is_none_or(|el| el.data.len() < 100_000) {
      if !link.step_impaired() {
        assert!(link.advance_to_next_event());
      }
    }
    assert!(link.server.conn.min_rtt_us() < 15_000);
    link.filter = Some(|to_server, _| !to_server);
    let blackout = link.now_us;
    while link.now_us - blackout < 3_000_000 {
      if !link.step_impaired() {
        assert!(link.advance_to_next_event());
      }
    }
    // The path comes back slower
    link.filter = None;
    link.impair(Impairment::delay(20_000));
    while !link.client.app.streams.get(&id.0).is_some_and(|el| el.fin) {
      if !link.step_impaired() {
        assert!(link.advance_to_next_event());
      }
    }
    assert_eq!(link.server.conn.stats().persistent_congestions, 1);
    assert!(link.server.conn.min_rtt_us() >= 35_000, "{}", link.server.conn.min_rtt_us());
  }

  // A connection that serves a lossy profile, with key updates, on pools that served the same
  // profile before: the server allocates nothing, whatever the losses make it keep, reassemble and
  // send again. The rounds are the same to the datagram (same seeds), so the counted one finds the
  // peaks of the warm-up ones.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn lossy_steady_state_allocates_nothing_after_warmup() {
    static OTHERS: AtomicU64 = AtomicU64::new(0);
    static SERVER: AtomicU64 = AtomicU64::new(0);
    let mut opts = LinkOpts::new(None);
    opts.counters = Some((&SERVER, &OTHERS));
    opts.server_app = TestApp::new(Behavior::Echo);
    opts.client.key_update_threshold = 300;
    _count_allocations_in(&OTHERS);
    let requests = requests(600, 256 << 10);
    let round = |parts: (Parts, Parts)| {
      let mut link = Link::with_parts(&opts, parts.0, parts.1);
      link.impair(lossy(7));
      let run = run_lossy_requests(&mut link, &requests, 64, 120_000_000);
      assert_eq!(run.responses, requests);
      let (retransmitted, _) = link.server.conn.streams().retransmissions();
      let stats = *link.server.conn.stats();
      assert!(retransmitted > 0 && stats.key_updates > 0 && stats.packets_lost > 0, "{stats:?}");
      link.into_parts()
    };
    let mut parts = (Parts::new(), Parts::new());
    for _ in 0..3 {
      parts = round(parts);
    }
    let before = SERVER.load(Ordering::Relaxed);
    assert!(before > 0);
    let _parts = round(parts);
    let allocations = SERVER.load(Ordering::Relaxed) - before;
    assert_eq!(allocations, 0, "{allocations} allocations in a lossy round");
  }
}
