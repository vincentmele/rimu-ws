//! Congestion control (RFC 9002 section 7) behind a trait, so that CUBIC can follow NewReno, and
//! pacing (RFC 9002 section 7.7).
//!
//! The window counts the bytes of the packets in flight, which [`crate::quic::recovery`] tracks:
//! ACK-only packets and probes of path MTU discovery are not counted (RFC 9002 section 7.7,
//! ruling T9-e). Pacing spreads the packets of a window over a round trip, at 1.25 times the
//! window per smoothed RTT, but lets a burst of one GSO train (64 datagrams by default) go at once,
//! so that a loopback or a short flight is never held back.

/// The datagrams of one GSO train: what pacing lets go at once by default, and at most.
pub(crate) const PACING_BURST_DATAGRAMS: u16 = 64;

// RFC 9002 section 7.2: the initial window is at most 14,720 bytes, at least two datagrams
const INITIAL_WINDOW_CAP: usize = 14_720;
const INITIAL_WINDOW_DATAGRAMS: usize = 10;
const MIN_WINDOW_DATAGRAMS: usize = 2;

/// A congestion controller: told what is sent, acknowledged and lost, it says how many bytes can
/// be in flight.
pub(crate) trait CongestionControl {
  /// A packet of `bytes` that counts towards the bytes in flight was sent.
  fn on_sent(&mut self, bytes: usize);

  /// A packet of `bytes` sent at `sent_time_us` was acknowledged at `now_us`, while the window was
  /// used.
  fn on_acked(&mut self, bytes: usize, sent_time_us: u64, now_us: u64);

  /// Packets were lost, the newest of them sent at `sent_time_us`: a congestion event at `now_us`
  /// unless one started after that packet was sent.
  fn on_congestion_event(&mut self, sent_time_us: u64, now_us: u64);

  /// The losses show persistent congestion (RFC 9002 section 7.6).
  fn on_persistent_congestion(&mut self);

  /// The congestion window: the bytes that can be in flight.
  fn window(&self) -> usize;
}

/// NewReno (RFC 9002 section 7.3 and appendix B): slow start, congestion avoidance and a recovery
/// period after each congestion event.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NewReno {
  // Bytes acknowledged in congestion avoidance since the window last grew
  avoidance_acked: usize,
  cwnd: usize,
  max_datagram: usize,
  // When the current recovery period started, if one did
  recovery_start_us: Option<u64>,
  ssthresh: usize,
}

impl NewReno {
  /// A controller for datagrams of `max_datagram` bytes, with the initial window.
  #[inline]
  pub(crate) const fn new(max_datagram: usize) -> Self {
    Self {
      avoidance_acked: 0,
      cwnd: initial_window(max_datagram),
      max_datagram,
      recovery_start_us: None,
      ssthresh: usize::MAX,
    }
  }

  /// The largest datagram changed (path MTU discovery): a window that was never more than the
  /// initial one takes the initial one of the new size (RFC 9002 section 7.2), and the minimum
  /// follows.
  #[inline]
  pub(crate) fn set_max_datagram(&mut self, max_datagram: usize) {
    if self.cwnd <= initial_window(self.max_datagram) && self.ssthresh == usize::MAX {
      self.cwnd = initial_window(max_datagram);
    }
    self.max_datagram = max_datagram;
    self.cwnd = self.cwnd.max(self.min_window());
  }

  fn in_recovery(&self, sent_time_us: u64) -> bool {
    self.recovery_start_us.is_some_and(|start| sent_time_us <= start)
  }

  const fn min_window(&self) -> usize {
    self.max_datagram.saturating_mul(MIN_WINDOW_DATAGRAMS)
  }

  /// The slow start threshold.
  #[inline]
  #[cfg(test)]
  pub(crate) const fn ssthresh(&self) -> usize {
    self.ssthresh
  }

  /// When the current recovery period started, if one did.
  #[inline]
  pub(crate) const fn recovery_start_us(&self) -> Option<u64> {
    self.recovery_start_us
  }
}

impl CongestionControl for NewReno {
  #[inline]
  fn on_sent(&mut self, _bytes: usize) {}

  #[inline]
  fn on_acked(&mut self, bytes: usize, sent_time_us: u64, _now_us: u64) {
    // The window does not grow with what was sent before the recovery period started
    if self.in_recovery(sent_time_us) {
      return;
    }
    if self.cwnd < self.ssthresh {
      self.cwnd = self.cwnd.saturating_add(bytes);
      return;
    }
    // One datagram for each window acknowledged
    self.avoidance_acked = self.avoidance_acked.saturating_add(bytes);
    if self.avoidance_acked >= self.cwnd {
      self.avoidance_acked = self.avoidance_acked.wrapping_sub(self.cwnd);
      self.cwnd = self.cwnd.saturating_add(self.max_datagram);
    }
  }

  #[inline]
  fn on_congestion_event(&mut self, sent_time_us: u64, now_us: u64) {
    // One reduction per round trip: losses of packets sent before the period are part of it
    if self.in_recovery(sent_time_us) {
      return;
    }
    self.recovery_start_us = Some(now_us);
    // kLossReductionFactor: 0.5
    self.ssthresh = (self.cwnd / 2).max(self.min_window());
    self.cwnd = self.ssthresh;
    self.avoidance_acked = 0;
  }

  #[inline]
  fn on_persistent_congestion(&mut self) {
    self.cwnd = self.min_window();
    self.recovery_start_us = None;
    self.avoidance_acked = 0;
  }

  #[inline]
  fn window(&self) -> usize {
    self.cwnd
  }
}

/// A token bucket that paces packets in flight: it holds one GSO train of bytes and fills at 1.25
/// times the window per smoothed RTT.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Pacer {
  last_us: u64,
  tokens: u64,
}

impl Pacer {
  /// A full bucket.
  #[inline]
  pub(crate) const fn new() -> Self {
    Self { last_us: 0, tokens: u64::MAX }
  }

  /// When a datagram of `size` bytes can leave, at `now_us`, with `window` and the smoothed RTT
  /// `srtt_us`, the bucket holding `burst` datagrams of `max_datagram` bytes (from 1 to
  /// [`PACING_BURST_DATAGRAMS`]): `None` if it can now. A smoothed RTT of zero, which only a fake
  /// clock gives, paces nothing.
  #[inline]
  pub(crate) fn release_time(
    &mut self,
    now_us: u64,
    size: usize,
    (window, srtt_us): (usize, u64),
    max_datagram: usize,
    burst: u16,
  ) -> Option<u64> {
    let burst = usize::from(burst.clamp(1, PACING_BURST_DATAGRAMS));
    let capacity = u64::try_from(max_datagram.saturating_mul(burst)).unwrap_or(u64::MAX);
    let window = u64::try_from(window).unwrap_or(u64::MAX).max(1);
    let elapsed = now_us.saturating_sub(self.last_us);
    self.last_us = self.last_us.max(now_us);
    // Bytes per microsecond: window * 5 / (4 * srtt)
    let rate_den = srtt_us.saturating_mul(4);
    let refill = if rate_den == 0 {
      u64::MAX
    } else {
      u64::try_from(
        u128::from(elapsed).saturating_mul(u128::from(window)).saturating_mul(5)
          / u128::from(rate_den),
      )
      .unwrap_or(u64::MAX)
    };
    self.tokens = self.tokens.saturating_add(refill).min(capacity);
    let size = u64::try_from(size).unwrap_or(u64::MAX);
    let missing = size.checked_sub(self.tokens).filter(|elem| *elem > 0)?;
    // The time that the missing bytes take to come, rounded up
    let wait = u128::from(missing)
      .saturating_mul(u128::from(rate_den))
      .div_ceil(u128::from(window).saturating_mul(5));
    Some(now_us.saturating_add(u64::try_from(wait).unwrap_or(u64::MAX)))
  }

  /// A datagram of `size` bytes left.
  #[inline]
  pub(crate) fn on_sent(&mut self, size: usize) {
    self.tokens = self.tokens.saturating_sub(u64::try_from(size).unwrap_or(u64::MAX));
  }
}

// RFC 9002 section 7.2: min(10 * max_datagram_size, max(14720, 2 * max_datagram_size))
const fn initial_window(max_datagram: usize) -> usize {
  let ten = max_datagram.saturating_mul(INITIAL_WINDOW_DATAGRAMS);
  let two = max_datagram.saturating_mul(MIN_WINDOW_DATAGRAMS);
  let cap = if two > INITIAL_WINDOW_CAP { two } else { INITIAL_WINDOW_CAP };
  if ten < cap { ten } else { cap }
}

#[cfg(test)]
mod tests {
  use crate::quic::cc::{CongestionControl, NewReno, PACING_BURST_DATAGRAMS, Pacer};

  // The example of RFC 9002 appendix B with datagrams of 1200 bytes: the initial window, slow
  // start, a congestion event that halves the window once for every loss of its recovery period,
  // congestion avoidance, which grows by one datagram per window, and persistent congestion.
  #[test]
  fn newreno_slow_start_and_recovery_rfc9002_appendix_b() {
    const MSS: usize = 1200;
    let mut cc = NewReno::new(MSS);
    // min(10 * 1200, max(14720, 2 * 1200)) (RFC 9002 section 7.2)
    assert_eq!(cc.window(), 12_000);
    // Larger datagrams: min(10 * 1472, 14720)
    assert_eq!(NewReno::new(1472).window(), 14_720);
    // Slow start: the window grows by what is acknowledged
    for nth in 0..10u64 {
      cc.on_sent(MSS);
      cc.on_acked(MSS, 1_000 + nth, 50_000 + nth);
    }
    assert_eq!(cc.window(), 24_000);
    // A loss: half the window, and a recovery period from now
    cc.on_congestion_event(2_000, 60_000);
    assert_eq!((cc.window(), cc.ssthresh()), (12_000, 12_000));
    // Losses and acknowledgments of packets sent before the period change nothing
    cc.on_congestion_event(59_999, 61_000);
    cc.on_acked(MSS, 60_000, 62_000);
    assert_eq!(cc.window(), 12_000);
    // Congestion avoidance after it: one datagram per window acknowledged
    for nth in 0..9u64 {
      cc.on_acked(MSS, 60_001 + nth, 70_000 + nth);
    }
    assert_eq!(cc.window(), 12_000);
    cc.on_acked(MSS, 60_100, 70_100);
    assert_eq!(cc.window(), 13_200);
    // A loss of a packet sent after the period started: a new event
    cc.on_congestion_event(70_000, 80_000);
    assert_eq!(cc.window(), 6_600);
    // Never below two datagrams, and persistent congestion goes there and ends recovery
    cc.on_congestion_event(80_001, 90_000);
    cc.on_congestion_event(90_001, 100_000);
    assert_eq!(cc.window(), 2 * MSS);
    let mut cc = NewReno::new(MSS);
    cc.on_congestion_event(1, 10);
    cc.on_persistent_congestion();
    assert_eq!(cc.window(), 2 * MSS);
    cc.on_acked(MSS, 5, 20);
    assert_eq!(cc.window(), 2 * MSS + MSS);
  }

  // A train of 64 datagrams leaves at once from a full bucket; the next one waits for the bytes
  // that the rate of 1.25 windows per RTT brings, and goes at that time.
  #[test]
  fn pacing_does_not_gate_a_single_train() {
    const MSS: usize = 1200;
    const B: u16 = PACING_BURST_DATAGRAMS;
    let (window, srtt_us) = (1_000_000, 10_000);
    let mut pacer = Pacer::new();
    let now_us = 5_000_000;
    for _ in 0..B {
      assert_eq!(pacer.release_time(now_us, MSS, (window, srtt_us), MSS, B), None);
      pacer.on_sent(MSS);
    }
    // 1200 bytes at 125 bytes per microsecond: 9.6 microseconds, rounded up
    let release = pacer.release_time(now_us, MSS, (window, srtt_us), MSS, B);
    assert_eq!(release, Some(now_us + 10));
    assert_eq!(pacer.release_time(now_us + 9, MSS, (window, srtt_us), MSS, B), Some(now_us + 10));
    assert_eq!(pacer.release_time(now_us + 10, MSS, (window, srtt_us), MSS, B), None);
    pacer.on_sent(MSS);
    // An idle connection gets its burst back, never more
    let later = now_us + 1_000_000;
    for _ in 0..B {
      assert_eq!(pacer.release_time(later, MSS, (window, srtt_us), MSS, B), None);
      pacer.on_sent(MSS);
    }
    assert!(pacer.release_time(later, MSS, (window, srtt_us), MSS, B).is_some());
    // Without an RTT sample of note (zero on a fake clock) nothing is paced
    for _ in 0..1000 {
      assert_eq!(pacer.release_time(later, MSS, (window, 0), MSS, B), None);
      pacer.on_sent(MSS);
    }
  }

  // Task 19 (ruling T19-c): a smaller burst lets that many datagrams go at once, then spreads the
  // rest at the same rate; a burst outside 1 to 64 is clamped.
  #[test]
  fn pacing_burst_caps_what_goes_at_once() {
    const MSS: usize = 1200;
    let (window, srtt_us) = (1_000_000, 10_000);
    for (asked, taken) in [(16u16, 16usize), (1, 1), (0, 1), (64, 64), (200, 64)] {
      let mut pacer = Pacer::new();
      let now_us = 5_000_000;
      for nth in 0..taken {
        let release = pacer.release_time(now_us, MSS, (window, srtt_us), MSS, asked);
        assert_eq!(release, None, "{asked}: datagram {nth}");
        pacer.on_sent(MSS);
      }
      let release = pacer.release_time(now_us, MSS, (window, srtt_us), MSS, asked);
      assert_eq!(release, Some(now_us + 10), "{asked}");
    }
  }
}
