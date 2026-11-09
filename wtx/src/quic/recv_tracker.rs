//! The packet numbers received in one packet number space, and the ACK frames that report them
//! (RFC 9000 sections 12.3 and 13.2).
//!
//! A sliding window of bitmaps holds the most recent 1024 packet numbers. Packet numbers below the
//! window, or below the ranges that an acknowledged ACK of ours reported, are not accepted again:
//! RFC 9000 section 13.2.3 allows forgetting a range only on that condition. Every packet is
//! accepted whatever the window: when it slides past packets that no ACK of ours reported yet,
//! their ranges are kept apart (at most 16, the oldest dropped first) and reported by the next
//! ACK, so the peer does not take them for lost. That rarely happens, so they are kept in a block
//! of the pools of the worker ([`RecvSpill`]) that goes back once they are reported.

use crate::quic::{FrameWriter, pools::QuicPools};
use alloc::boxed::Box;
use core::ops::RangeInclusive;

// The window: 1024 packet numbers, more than a peer sends between two flushes
const WORDS: usize = 16;
const WINDOW: u64 = 64 * WORDS as u64;
// The most ranges of an ACK frame of ours. Older ranges are not reported, as if the window ended
// before them.
const MAX_WRITTEN_RANGES: usize = 32;
// The most ranges kept for the next ACK of what slid off the window
const MAX_SPILLED: usize = 16;

/// The ranges of packet numbers that slid off the window of a [`RecvTracker`] before an ACK of
/// ours reported them: from the oldest to the newest, the first `len` of them.
#[derive(Debug)]
pub(crate) struct RecvSpill {
  len: u8,
  ranges: [(u64, u64); MAX_SPILLED],
}

/// What [`RecvTracker::write_ack`] wrote.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AckWritten {
  /// An ACK frame with every range that is reported.
  All,
  /// An ACK frame with the first range only, for want of room: the ranges after it are still owed.
  FirstRange,
}

/// See the [module documentation](self).
#[derive(Debug)]
pub(crate) struct RecvTracker {
  // Set when an ack-eliciting packet arrived that no ACK frame of ours reported yet
  ack_pending: bool,
  // The packet number of bit 0 of word 0, a multiple of 64
  base: u64,
  // Bit `n` of word `w` is the packet number `base + 64 * w + n`
  bits: [u64; WORDS],
  // The smallest packet number that is accepted, never below `base`
  floor: u64,
  largest: Option<u64>,
  // When `largest` arrived, for the ACK Delay field
  largest_time_us: u64,
  // Ranges below the window that no ACK frame of ours reported, from the pools while there are
  // some
  spilled: Option<Box<RecvSpill>>,
  // The smallest ack-eliciting packet number since the last ACK frame of ours
  unreported_low: Option<u64>,
}

impl RecvTracker {
  /// Nothing received.
  pub(crate) const fn new() -> Self {
    Self {
      ack_pending: false,
      base: 0,
      bits: [0; WORDS],
      floor: 0,
      largest: None,
      largest_time_us: 0,
      spilled: None,
      unreported_low: None,
    }
  }

  /// If an ack-eliciting packet arrived that no ACK frame of ours reported yet.
  #[inline]
  pub(crate) const fn ack_pending(&self) -> bool {
    self.ack_pending
  }

  /// If `pn` was received already, or can not be accepted anymore.
  #[inline]
  pub(crate) fn is_duplicate(&self, pn: u64) -> bool {
    if pn < self.floor {
      return true;
    }
    let Some((word, mask)) = self.position(pn) else {
      return false;
    };
    self.bits.get(word).is_some_and(|elem| elem & mask != 0)
  }

  /// The largest packet number received, if any.
  #[inline]
  pub(crate) const fn largest(&self) -> Option<u64> {
    self.largest
  }

  /// Forgets the ACK frames to come that an ACK frame of ours, which is acknowledged now, reported:
  /// the ranges up to its Largest Acknowledged (RFC 9000 section 13.2.4).
  #[inline]
  pub(crate) fn on_ack_of_our_ack(
    &mut self,
    largest_acked_in_that_ack: u64,
    pools: &mut QuicPools,
  ) {
    let floor = largest_acked_in_that_ack.saturating_add(1);
    if floor > self.floor {
      self.floor = floor;
    }
    // The ranges kept apart are below the window: those up to the acknowledged ACK go too
    let Some(spill) = self.spilled.as_deref_mut() else {
      return;
    };
    let mut kept = 0usize;
    for idx in 0..usize::from(spill.len) {
      let Some(&(start, end)) = spill.ranges.get(idx) else {
        break;
      };
      if end < floor {
        continue;
      }
      if let Some(slot) = spill.ranges.get_mut(kept) {
        *slot = (start.max(floor), end);
      }
      kept = kept.wrapping_add(1);
    }
    spill.len = u8::try_from(kept).unwrap_or(0);
    if kept == 0 {
      self.release(pools);
    }
  }

  /// Records `pn`, which arrived at `now_us` in a packet that has been processed. Returns `false`,
  /// and changes nothing, if it is a duplicate (see [`Self::is_duplicate`]).
  #[inline]
  pub(crate) fn on_packet(
    &mut self,
    pn: u64,
    ack_eliciting: bool,
    now_us: u64,
    pools: &mut QuicPools,
  ) -> bool {
    if self.is_duplicate(pn) {
      return false;
    }
    if pn >= self.base.saturating_add(WINDOW) {
      self.slide_to(pn, pools);
    }
    let Some((word, mask)) = self.position(pn) else {
      return false;
    };
    if let Some(elem) = self.bits.get_mut(word) {
      *elem |= mask;
    }
    if self.largest.is_none_or(|elem| pn > elem) {
      self.largest = Some(pn);
      self.largest_time_us = now_us;
    }
    if ack_eliciting {
      self.ack_pending = true;
      if self.unreported_low.is_none_or(|elem| pn < elem) {
        self.unreported_low = Some(pn);
      }
    }
    true
  }

  /// Notes that an ACK frame that [`Self::write_ack`] wrote with [`AckWritten::All`] was sent.
  /// One with its first range only reported less, which stays owed.
  #[inline]
  pub(crate) fn on_ack_sent(&mut self, pools: &mut QuicPools) {
    self.ack_pending = false;
    self.unreported_low = None;
    self.release(pools);
  }

  /// Gives back to the pools what is kept of the packet numbers below the window, for a space
  /// that is discarded or an ACK that reported them.
  #[inline]
  pub(crate) fn release(&mut self, pools: &mut QuicPools) {
    if let Some(mut elem) = self.spilled.take() {
      elem.len = 0;
      pools.recv_spills.give(elem);
    }
  }

  /// Writes an ACK frame of what was received, the delay since the largest packet number arrived
  /// encoded with `ack_delay_exponent`. If the frame does not fit, one with only its first range
  /// is tried. Returns `None` if nothing was written, also when there is nothing to report.
  #[inline]
  pub(crate) fn write_ack(
    &self,
    w: &mut FrameWriter<'_>,
    ack_delay_exponent: u8,
    now_us: u64,
  ) -> Option<AckWritten> {
    let largest = self.largest.filter(|elem| *elem >= self.floor)?;
    let delay = now_us.saturating_sub(self.largest_time_us) >> ack_delay_exponent.min(63);
    if w.write_ack(largest, delay, self.ranges().take(MAX_WRITTEN_RANGES)) {
      return Some(AckWritten::All);
    }
    w.write_ack(largest, delay, self.ranges().take(1)).then_some(AckWritten::FirstRange)
  }

  /// The ranges that an ACK frame would report, from the largest packet numbers to the smallest:
  /// those of the window, then those kept from below it, adjacent ones merged.
  pub(crate) fn ranges(&self) -> impl Iterator<Item = RangeInclusive<u64>> + '_ {
    let spilled = self
      .spilled
      .as_deref()
      .and_then(|el| el.ranges.get(..usize::from(el.len)))
      .unwrap_or_default();
    let mut inner =
      self.window_ranges().chain(spilled.iter().rev().map(|&(start, end)| start..=end)).peekable();
    core::iter::from_fn(move || {
      let first = inner.next()?;
      let (mut start, end) = (*first.start(), *first.end());
      while let Some(next) = inner.peek()
        && next.end().wrapping_add(1) == start
      {
        start = *next.start();
        let _ = inner.next();
      }
      Some(start..=end)
    })
  }

  // The ranges of the window, from the largest packet numbers to the smallest.
  fn window_ranges(&self) -> impl Iterator<Item = RangeInclusive<u64>> + '_ {
    let mut next = self.largest.filter(|elem| *elem >= self.floor);
    core::iter::from_fn(move || {
      let end = self.highest(next?, true)?;
      let start = self.highest(end, false).map_or(self.floor, |elem| elem.wrapping_add(1));
      next = start.checked_sub(2).filter(|elem| *elem >= self.floor);
      Some(start..=end)
    })
  }

  // The highest packet number at or below `pn`, and not below the floor, that was received (`set`)
  // or that was not.
  fn highest(&self, pn: u64, set: bool) -> Option<u64> {
    let mut pn = pn;
    loop {
      if pn < self.floor {
        return None;
      }
      let (word, bit) = self.split(pn)?;
      let raw = *self.bits.get(word)?;
      let bits = if set { raw } else { !raw };
      // The bits at or below `bit`
      let below = bits & (u64::MAX >> 63u32.wrapping_sub(bit));
      if below != 0 {
        let found = 63u32.wrapping_sub(below.leading_zeros());
        let candidate = pn.wrapping_sub(u64::from(bit.wrapping_sub(found)));
        return (candidate >= self.floor).then_some(candidate);
      }
      pn = pn.checked_sub(u64::from(bit).wrapping_add(1))?;
    }
  }

  // The smallest packet number from `pn`, and below `to`, that was received (`set`) or that was
  // not, in the window.
  fn lowest(&self, pn: u64, to: u64, set: bool) -> Option<u64> {
    let mut pn = pn;
    while pn < to {
      let (word, bit) = self.split(pn)?;
      let raw = *self.bits.get(word)?;
      let bits = (if set { raw } else { !raw }) >> bit;
      if bits != 0 {
        let found = pn.wrapping_add(u64::from(bits.trailing_zeros()));
        return (found < to).then_some(found);
      }
      pn = pn.wrapping_add(64u64.wrapping_sub(u64::from(bit)));
    }
    None
  }

  // Keeps the range `start..=end`, which is above the ranges kept so far, for the next ACK: merged
  // with the newest one if adjacent, in place of the oldest one if there is no room.
  fn push_spilled(&mut self, start: u64, end: u64, pools: &mut QuicPools) {
    let spill = self.spilled.get_or_insert_with(|| {
      pools
        .recv_spills
        .take()
        .unwrap_or_else(|| Box::new(RecvSpill { len: 0, ranges: [(0, 0); MAX_SPILLED] }))
    });
    let len = usize::from(spill.len);
    if let Some(last) = len.checked_sub(1).and_then(|idx| spill.ranges.get_mut(idx))
      && last.1.wrapping_add(1) == start
    {
      last.1 = end;
      return;
    }
    if len >= MAX_SPILLED {
      spill.ranges.copy_within(1.., 0);
      if let Some(last) = spill.ranges.last_mut() {
        *last = (start, end);
      }
      return;
    }
    if let Some(slot) = spill.ranges.get_mut(len) {
      *slot = (start, end);
      spill.len = spill.len.wrapping_add(1);
    }
  }

  // The word and the mask of `pn`, which must be in the window.
  fn position(&self, pn: u64) -> Option<(usize, u64)> {
    let (word, bit) = self.split(pn)?;
    Some((word, 1u64 << bit))
  }

  // Moves the window up so that its last word holds `pn`, dropping the oldest bits.
  fn slide_to(&mut self, pn: u64, pools: &mut QuicPools) {
    let new_base = window_base(pn);
    // What falls off the window and was not reported yet is kept apart, range by range
    if let Some(low) = self.unreported_low.filter(|elem| *elem < new_base) {
      let to = new_base.min(self.base.saturating_add(WINDOW));
      let mut from = low.max(self.floor);
      while let Some(start) = self.lowest(from, to, true) {
        let end = self.lowest(start, to, false).unwrap_or(to);
        self.push_spilled(start, end.wrapping_sub(1), pools);
        from = end;
      }
    }
    let shift = usize::try_from(new_base.wrapping_sub(self.base) / 64).unwrap_or(usize::MAX);
    if shift >= WORDS {
      self.bits = [0; WORDS];
    } else {
      self.bits.copy_within(shift.., 0);
      if let Some(elem) = self.bits.get_mut(WORDS.wrapping_sub(shift)..) {
        elem.fill(0);
      }
    }
    self.base = new_base;
    if self.floor < new_base {
      self.floor = new_base;
    }
  }

  // The word and the bit of `pn`, if it is in the window.
  fn split(&self, pn: u64) -> Option<(usize, u32)> {
    let offset = pn.checked_sub(self.base).filter(|elem| *elem < WINDOW)?;
    Some((usize::try_from(offset / 64).ok()?, u32::try_from(offset % 64).ok()?))
  }
}

// The base of a window whose last word holds `pn`.
const fn window_base(pn: u64) -> u64 {
  (pn & !63).saturating_sub(WINDOW - 64)
}

#[cfg(test)]
mod tests {
  use crate::quic::{
    Frame, FrameReader, FrameWriter, Space,
    pools::QuicPools,
    recv_tracker::{AckWritten, RecvTracker, WINDOW},
  };
  use alloc::vec::Vec;

  fn ranges(tracker: &RecvTracker) -> Vec<(u64, u64)> {
    tracker.ranges().map(|el| (*el.start(), *el.end())).collect()
  }

  // The ACK frame that the tracker writes, decoded: largest, delay and ranges.
  fn written_ack(tracker: &RecvTracker, now_us: u64) -> Option<(u64, u64, Vec<(u64, u64)>)> {
    let mut buffer = [0; 512];
    let mut w = FrameWriter::new(&mut buffer);
    tracker.write_ack(&mut w, 3, now_us)?;
    let len = w.len();
    let frame = FrameReader::new(&buffer[..len], Space::Data).next().unwrap().unwrap();
    let Frame::Ack(ack) = frame else { panic!() };
    let ranges = ack.ranges().map(|el| el.map(|range| (*range.start(), *range.end())));
    Some((ack.largest, ack.delay, ranges.map(Result::unwrap).collect()))
  }

  #[test]
  fn duplicates_are_refused() {
    let mut tracker = RecvTracker::new();
    let mut pools = QuicPools::new();
    assert!(tracker.on_packet(0, true, 0, &mut pools));
    assert!(tracker.on_packet(1, false, 0, &mut pools));
    assert!(!tracker.on_packet(0, true, 0, &mut pools));
    assert!(!tracker.on_packet(1, true, 0, &mut pools));
    assert!(tracker.is_duplicate(1) && !tracker.is_duplicate(2));
    assert_eq!(ranges(&tracker), [(0, 1)]);
  }

  #[test]
  fn ranges_are_exact_and_descending() {
    let mut tracker = RecvTracker::new();
    let mut pools = QuicPools::new();
    for pn in [0, 1, 2, 4, 5, 9, 63, 64, 65, 130, 200] {
      assert!(tracker.on_packet(pn, true, 0, &mut pools));
    }
    assert_eq!(ranges(&tracker), [(200, 200), (130, 130), (63, 65), (9, 9), (4, 5), (0, 2)]);
    let (largest, _, written) = written_ack(&tracker, 0).unwrap();
    assert_eq!(largest, 200);
    assert_eq!(written, ranges(&tracker));
  }

  #[test]
  fn ack_pending_follows_ack_eliciting_packets() {
    let mut tracker = RecvTracker::new();
    let mut pools = QuicPools::new();
    assert!(!tracker.ack_pending());
    // Nothing to report yet
    assert!(written_ack(&tracker, 0).is_none());
    tracker.on_packet(0, false, 0, &mut pools);
    assert!(!tracker.ack_pending());
    tracker.on_packet(1, true, 0, &mut pools);
    assert!(tracker.ack_pending());
    tracker.on_ack_sent(&mut pools);
    assert!(!tracker.ack_pending());
    // Writing does not change what is pending, sending does
    tracker.on_packet(2, true, 0, &mut pools);
    assert!(written_ack(&tracker, 0).is_some());
    assert!(tracker.ack_pending());
  }

  #[test]
  fn ack_delay_uses_the_exponent() {
    let mut tracker = RecvTracker::new();
    let mut pools = QuicPools::new();
    tracker.on_packet(7, true, 1_000, &mut pools);
    tracker.on_packet(3, true, 5_000, &mut pools);
    // Since the largest arrived, 8 us per unit with the exponent 3
    let (largest, delay, _) = written_ack(&tracker, 1_000 + 800).unwrap();
    assert_eq!((largest, delay), (7, 100));
  }

  #[test]
  fn ack_ranges_kept_until_our_ack_is_acked() {
    let mut tracker = RecvTracker::new();
    let mut pools = QuicPools::new();
    for pn in [0, 1, 2, 4, 5] {
      tracker.on_packet(pn, true, 0, &mut pools);
    }
    // Writing an ACK any number of times keeps every range
    for _ in 0..3 {
      assert_eq!(written_ack(&tracker, 0).unwrap().2, [(4, 5), (0, 2)]);
    }
    tracker.on_ack_sent(&mut pools);
    assert_eq!(written_ack(&tracker, 0).unwrap().2, [(4, 5), (0, 2)]);
    // Our ACK that reported up to 4 is acknowledged: only 5 is left
    tracker.on_ack_of_our_ack(4, &mut pools);
    assert_eq!(ranges(&tracker), [(5, 5)]);
    // Packet 3, never received, can not be accepted anymore
    assert!(!tracker.on_packet(3, true, 0, &mut pools));
    assert!(tracker.on_packet(6, true, 0, &mut pools));
    assert_eq!(ranges(&tracker), [(5, 6)]);
    // An older acknowledgment changes nothing
    tracker.on_ack_of_our_ack(1, &mut pools);
    assert_eq!(ranges(&tracker), [(5, 6)]);
    tracker.on_ack_of_our_ack(6, &mut pools);
    assert!(ranges(&tracker).is_empty());
    assert!(written_ack(&tracker, 0).is_none());
  }

  #[test]
  fn window_slides_and_forgets_the_oldest() {
    let mut tracker = RecvTracker::new();
    let mut pools = QuicPools::new();
    tracker.on_packet(0, true, 0, &mut pools);
    tracker.on_packet(10, true, 0, &mut pools);
    // Reported, so they can be forgotten
    tracker.on_ack_sent(&mut pools);
    assert!(tracker.on_packet(WINDOW + 70, true, 0, &mut pools));
    // The window covers WINDOW numbers up to the word of the largest
    assert_eq!(ranges(&tracker), [(WINDOW + 70, WINDOW + 70)]);
    assert!(tracker.is_duplicate(10) && tracker.is_duplicate(127));
    assert!(tracker.on_packet(128, true, 0, &mut pools));
    assert_eq!(ranges(&tracker), [(WINDOW + 70, WINDOW + 70), (128, 128)]);
    // A jump far ahead drops everything, once reported
    tracker.on_ack_sent(&mut pools);
    assert!(tracker.on_packet(1_000_000, true, 0, &mut pools));
    assert_eq!(ranges(&tracker), [(1_000_000, 1_000_000)]);
    assert!(tracker.is_duplicate(WINDOW + 70));
  }

  // The descending ranges of the packet numbers below `end` that `received` keeps.
  fn reference(end: u64, received: impl Fn(u64) -> bool) -> Vec<(u64, u64)> {
    let mut rslt: Vec<(u64, u64)> = Vec::new();
    for pn in (0..end).filter(|el| received(*el)) {
      match rslt.last_mut() {
        Some(last) if last.1 + 1 == pn => last.1 = pn,
        _ => rslt.push((pn, pn)),
      }
    }
    rslt.reverse();
    rslt
  }

  // 2,000 packets between two flushes, more than the window holds: every one is accepted and the
  // next ACK reports them all.
  #[test]
  fn two_thousand_packets_in_one_turn_are_all_reported() {
    let mut tracker = RecvTracker::new();
    let mut pools = QuicPools::new();
    for pn in 0..2000 {
      assert!(tracker.on_packet(pn, true, 0, &mut pools), "{pn}");
    }
    assert_eq!(ranges(&tracker), [(0, 1999)]);
    assert_eq!(written_ack(&tracker, 0).unwrap().2, [(0, 1999)]);
    // Once reported, what fell off the window is forgotten at the next slide
    tracker.on_ack_sent(&mut pools);
    assert!(tracker.on_packet(2100, true, 0, &mut pools));
    assert_eq!(ranges(&tracker), [(2100, 2100), (1088, 1999)]);
  }

  // Packet numbers that a peer skips stay gaps across slides: the ranges are exact.
  #[test]
  fn a_gappy_peer_is_reported_exactly_across_a_slide() {
    let received = |pn: u64| pn % 250 != 125;
    let mut tracker = RecvTracker::new();
    let mut pools = QuicPools::new();
    for pn in (0..2000).filter(|el| received(*el)) {
      assert!(tracker.on_packet(pn, true, 0, &mut pools), "{pn}");
    }
    let expected = reference(2000, received);
    assert_eq!(expected.len(), 9);
    assert_eq!(ranges(&tracker), expected);
    assert_eq!(written_ack(&tracker, 0).unwrap().2, expected);
  }

  // Beyond the ranges that are kept for what slid off the window, the oldest go first.
  #[test]
  fn spilled_ranges_beyond_the_cap_lose_the_oldest() {
    let received = |pn: u64| pn >= 1000 || pn % 10 != 5;
    let mut tracker = RecvTracker::new();
    let mut pools = QuicPools::new();
    for pn in (0..3000).filter(|el| received(*el)) {
      assert!(tracker.on_packet(pn, true, 0, &mut pools), "{pn}");
    }
    let expected = reference(3000, received);
    let got = ranges(&tracker);
    assert!(got.len() < expected.len());
    // The newest ranges, exactly, and none of the oldest
    assert_eq!(got, expected[..got.len()]);
    assert_eq!(got[0], (996, 2999));
    assert!(got.len() > 1 && got.last().unwrap().0 > 0);
    assert_eq!(written_ack(&tracker, 0).unwrap().2, got);
  }

  // A packet number that slid off the window is a duplicate, whether it is in a range kept for the
  // next ACK or not.
  #[test]
  fn a_duplicate_of_a_spilled_packet_is_detected() {
    let mut tracker = RecvTracker::new();
    let mut pools = QuicPools::new();
    for pn in 0..1500 {
      assert!(tracker.on_packet(pn, true, 0, &mut pools));
    }
    assert!(tracker.is_duplicate(5) && tracker.is_duplicate(511));
    assert!(!tracker.on_packet(5, true, 0, &mut pools));
    assert_eq!(ranges(&tracker), [(0, 1499)]);
    // The spilled ranges are reported once, in the ACK that is sent; then the window is left
    tracker.on_ack_sent(&mut pools);
    assert_eq!(ranges(&tracker), [(512, 1499)]);
    assert!(!tracker.on_packet(5, true, 0, &mut pools));
    // An acknowledged ACK of ours removes them too
    let mut tracker = RecvTracker::new();
    let mut pools = QuicPools::new();
    for pn in 0..1500 {
      assert!(tracker.on_packet(pn, true, 0, &mut pools));
    }
    tracker.on_ack_of_our_ack(299, &mut pools);
    assert_eq!(ranges(&tracker), [(300, 1499)]);
  }

  #[test]
  fn many_ranges_are_capped_and_a_small_buffer_gets_one() {
    let mut tracker = RecvTracker::new();
    let mut pools = QuicPools::new();
    for pn in (0..200).step_by(2) {
      tracker.on_packet(pn, true, 0, &mut pools);
    }
    assert_eq!(ranges(&tracker).len(), 100);
    let (_, _, written) = written_ack(&tracker, 0).unwrap();
    assert_eq!(written.len(), 32);
    assert_eq!(written[0], (198, 198));
    // Room for the first range only
    let mut buffer = [0; 8];
    let mut w = FrameWriter::new(&mut buffer);
    assert_eq!(tracker.write_ack(&mut w, 3, 0), Some(AckWritten::FirstRange));
    let len = w.len();
    let Frame::Ack(ack) = FrameReader::new(&buffer[..len], Space::Data).next().unwrap().unwrap()
    else {
      panic!()
    };
    let range = ack.ranges().next().unwrap().unwrap();
    assert_eq!((*range.start(), *range.end(), ack.ranges().count()), (198, 198, 1));
    // No room at all
    let mut buffer = [0; 3];
    assert!(tracker.write_ack(&mut FrameWriter::new(&mut buffer), 3, 0).is_none());
  }

  #[test]
  fn ranges_match_a_reference_set() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..200 {
      let mut tracker = RecvTracker::new();
      let mut pools = QuicPools::new();
      let mut received = Vec::new();
      for _ in 0..150 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let pn = state % 300;
        let fresh = !received.contains(&pn) && pn >= tracker.floor;
        assert_eq!(tracker.on_packet(pn, true, 0, &mut pools), fresh, "{pn}");
        if fresh {
          received.push(pn);
        }
      }
      let floor = tracker.floor;
      let mut expected: Vec<u64> = received.into_iter().filter(|el| *el >= floor).collect();
      expected.sort_unstable();
      let got: Vec<u64> =
        ranges(&tracker).into_iter().rev().flat_map(|(start, end)| start..=end).collect();
      assert_eq!(got, expected);
    }
  }
}
