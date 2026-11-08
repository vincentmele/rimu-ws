//! The packet numbers received in one packet number space, and the ACK frames that report them
//! (RFC 9000 sections 12.3 and 13.2).
//!
//! A sliding window of bitmaps holds the most recent packet numbers. Packet numbers below the
//! window, or below the ranges that an acknowledged ACK of ours reported, are not accepted again:
//! RFC 9000 section 13.2.3 allows forgetting a range only on that condition.

use crate::quic::FrameWriter;
use core::ops::RangeInclusive;

// The window: 256 packet numbers
const WORDS: usize = 4;
const WINDOW: u64 = 64 * WORDS as u64;
// The most ranges of an ACK frame of ours. Older ranges are not reported, as if the window ended
// before them.
const MAX_WRITTEN_RANGES: usize = 32;

/// See the [module documentation](self).
#[derive(Clone, Copy, Debug)]
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
  pub(crate) fn on_ack_of_our_ack(&mut self, largest_acked_in_that_ack: u64) {
    let floor = largest_acked_in_that_ack.saturating_add(1);
    if floor > self.floor {
      self.floor = floor;
    }
  }

  /// Records `pn`, which arrived at `now_us` in a packet that has been processed. Returns `false`,
  /// and changes nothing, if it is a duplicate (see [`Self::is_duplicate`]).
  #[inline]
  pub(crate) fn on_packet(&mut self, pn: u64, ack_eliciting: bool, now_us: u64) -> bool {
    if self.is_duplicate(pn) {
      return false;
    }
    if pn >= self.base.saturating_add(WINDOW) {
      self.slide_to(pn);
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
    }
    true
  }

  /// Notes that an ACK frame written by [`Self::write_ack`] was sent.
  #[inline]
  pub(crate) const fn on_ack_sent(&mut self) {
    self.ack_pending = false;
  }

  /// Writes an ACK frame of what was received, the delay since the largest packet number arrived
  /// encoded with `ack_delay_exponent`. If the frame does not fit, one with only its first range
  /// is tried. Returns `false` if nothing was written, also when there is nothing to report.
  #[inline]
  pub(crate) fn write_ack(
    &self,
    w: &mut FrameWriter<'_>,
    ack_delay_exponent: u8,
    now_us: u64,
  ) -> bool {
    let Some(largest) = self.largest.filter(|elem| *elem >= self.floor) else {
      return false;
    };
    let delay = now_us.saturating_sub(self.largest_time_us) >> ack_delay_exponent.min(63);
    w.write_ack(largest, delay, self.ranges().take(MAX_WRITTEN_RANGES))
      || w.write_ack(largest, delay, self.ranges().take(1))
  }

  /// The ranges that an ACK frame would report, from the largest packet numbers to the smallest.
  pub(crate) fn ranges(&self) -> impl Iterator<Item = RangeInclusive<u64>> + '_ {
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

  // The word and the mask of `pn`, which must be in the window.
  fn position(&self, pn: u64) -> Option<(usize, u64)> {
    let (word, bit) = self.split(pn)?;
    Some((word, 1u64 << bit))
  }

  // Moves the window up so that its last word holds `pn`, dropping the oldest bits.
  fn slide_to(&mut self, pn: u64) {
    let new_base = (pn & !63).saturating_sub(WINDOW - 64);
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

#[cfg(test)]
mod tests {
  use crate::quic::{
    Frame, FrameReader, FrameWriter, Space,
    recv_tracker::{RecvTracker, WINDOW},
  };
  use alloc::vec::Vec;

  fn ranges(tracker: &RecvTracker) -> Vec<(u64, u64)> {
    tracker.ranges().map(|el| (*el.start(), *el.end())).collect()
  }

  // The ACK frame that the tracker writes, decoded: largest, delay and ranges.
  fn written_ack(tracker: &RecvTracker, now_us: u64) -> Option<(u64, u64, Vec<(u64, u64)>)> {
    let mut buffer = [0; 512];
    let mut w = FrameWriter::new(&mut buffer);
    if !tracker.write_ack(&mut w, 3, now_us) {
      return None;
    }
    let len = w.len();
    let frame = FrameReader::new(&buffer[..len], Space::Data).next().unwrap().unwrap();
    let Frame::Ack(ack) = frame else { panic!() };
    let ranges = ack.ranges().map(|el| el.map(|range| (*range.start(), *range.end())));
    Some((ack.largest, ack.delay, ranges.map(Result::unwrap).collect()))
  }

  #[test]
  fn duplicates_are_refused() {
    let mut tracker = RecvTracker::new();
    assert!(tracker.on_packet(0, true, 0));
    assert!(tracker.on_packet(1, false, 0));
    assert!(!tracker.on_packet(0, true, 0));
    assert!(!tracker.on_packet(1, true, 0));
    assert!(tracker.is_duplicate(1) && !tracker.is_duplicate(2));
    assert_eq!(ranges(&tracker), [(0, 1)]);
  }

  #[test]
  fn ranges_are_exact_and_descending() {
    let mut tracker = RecvTracker::new();
    for pn in [0, 1, 2, 4, 5, 9, 63, 64, 65, 130, 200] {
      assert!(tracker.on_packet(pn, true, 0));
    }
    assert_eq!(ranges(&tracker), [(200, 200), (130, 130), (63, 65), (9, 9), (4, 5), (0, 2)]);
    let (largest, _, written) = written_ack(&tracker, 0).unwrap();
    assert_eq!(largest, 200);
    assert_eq!(written, ranges(&tracker));
  }

  #[test]
  fn ack_pending_follows_ack_eliciting_packets() {
    let mut tracker = RecvTracker::new();
    assert!(!tracker.ack_pending());
    // Nothing to report yet
    assert!(written_ack(&tracker, 0).is_none());
    tracker.on_packet(0, false, 0);
    assert!(!tracker.ack_pending());
    tracker.on_packet(1, true, 0);
    assert!(tracker.ack_pending());
    tracker.on_ack_sent();
    assert!(!tracker.ack_pending());
    // Writing does not change what is pending, sending does
    tracker.on_packet(2, true, 0);
    assert!(written_ack(&tracker, 0).is_some());
    assert!(tracker.ack_pending());
  }

  #[test]
  fn ack_delay_uses_the_exponent() {
    let mut tracker = RecvTracker::new();
    tracker.on_packet(7, true, 1_000);
    tracker.on_packet(3, true, 5_000);
    // Since the largest arrived, 8 us per unit with the exponent 3
    let (largest, delay, _) = written_ack(&tracker, 1_000 + 800).unwrap();
    assert_eq!((largest, delay), (7, 100));
  }

  #[test]
  fn ack_ranges_kept_until_our_ack_is_acked() {
    let mut tracker = RecvTracker::new();
    for pn in [0, 1, 2, 4, 5] {
      tracker.on_packet(pn, true, 0);
    }
    // Writing an ACK any number of times keeps every range
    for _ in 0..3 {
      assert_eq!(written_ack(&tracker, 0).unwrap().2, [(4, 5), (0, 2)]);
    }
    tracker.on_ack_sent();
    assert_eq!(written_ack(&tracker, 0).unwrap().2, [(4, 5), (0, 2)]);
    // Our ACK that reported up to 4 is acknowledged: only 5 is left
    tracker.on_ack_of_our_ack(4);
    assert_eq!(ranges(&tracker), [(5, 5)]);
    // Packet 3, never received, can not be accepted anymore
    assert!(!tracker.on_packet(3, true, 0));
    assert!(tracker.on_packet(6, true, 0));
    assert_eq!(ranges(&tracker), [(5, 6)]);
    // An older acknowledgment changes nothing
    tracker.on_ack_of_our_ack(1);
    assert_eq!(ranges(&tracker), [(5, 6)]);
    tracker.on_ack_of_our_ack(6);
    assert!(ranges(&tracker).is_empty());
    assert!(written_ack(&tracker, 0).is_none());
  }

  #[test]
  fn window_slides_and_forgets_the_oldest() {
    let mut tracker = RecvTracker::new();
    tracker.on_packet(0, true, 0);
    tracker.on_packet(10, true, 0);
    tracker.on_packet(WINDOW + 70, true, 0);
    // The window covers WINDOW numbers up to the word of the largest
    assert_eq!(ranges(&tracker), [(WINDOW + 70, WINDOW + 70)]);
    assert!(tracker.is_duplicate(10) && tracker.is_duplicate(127));
    assert!(tracker.on_packet(128, true, 0));
    assert_eq!(ranges(&tracker), [(WINDOW + 70, WINDOW + 70), (128, 128)]);
    // A jump far ahead drops everything
    tracker.on_packet(1_000_000, true, 0);
    assert_eq!(ranges(&tracker), [(1_000_000, 1_000_000)]);
    assert!(tracker.is_duplicate(WINDOW + 70));
  }

  #[test]
  fn many_ranges_are_capped_and_a_small_buffer_gets_one() {
    let mut tracker = RecvTracker::new();
    for pn in (0..200).step_by(2) {
      tracker.on_packet(pn, true, 0);
    }
    assert_eq!(ranges(&tracker).len(), 100);
    let (_, _, written) = written_ack(&tracker, 0).unwrap();
    assert_eq!(written.len(), 32);
    assert_eq!(written[0], (198, 198));
    // Room for the first range only
    let mut buffer = [0; 8];
    let mut w = FrameWriter::new(&mut buffer);
    assert!(tracker.write_ack(&mut w, 3, 0));
    let len = w.len();
    let Frame::Ack(ack) = FrameReader::new(&buffer[..len], Space::Data).next().unwrap().unwrap()
    else {
      panic!()
    };
    let range = ack.ranges().next().unwrap().unwrap();
    assert_eq!((*range.start(), *range.end(), ack.ranges().count()), (198, 198, 1));
    // No room at all
    let mut buffer = [0; 3];
    assert!(!tracker.write_ack(&mut FrameWriter::new(&mut buffer), 3, 0));
  }

  #[test]
  fn ranges_match_a_reference_set() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..200 {
      let mut tracker = RecvTracker::new();
      let mut received = Vec::new();
      for _ in 0..150 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let pn = state % 300;
        let fresh = !received.contains(&pn) && pn >= tracker.floor;
        assert_eq!(tracker.on_packet(pn, true, 0), fresh, "{pn}");
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
