//! The timers of the connections of a worker (spec section 5.2): a hashed wheel of 250 µs ticks
//! with one entry per connection, which moves when the deadline of the connection changes.
//!
//! The wheel has 4,096 buckets, about one second. A bucket holds the entries of one tick of the
//! coming second, so that every entry of a bucket that is reached is due. Entries further away
//! wait in an overflow list, and move into the wheel every half revolution, those of the
//! revolution ahead at once. A bitmap of the buckets that hold entries finds the next one in at
//! most 64 words.

use crate::collections::Vector;

/// The length of a tick.
pub(crate) const TICK_US: u64 = 250;

const BUCKETS: usize = 4096;
const BUCKETS_U64: u64 = BUCKETS as u64;
const NONE: u32 = u32::MAX;
// Where an entry is: in no list, in the overflow list or in the bucket of this number
const NOWHERE: u32 = u32::MAX;
const OVERFLOW: u32 = u32::MAX - 1;
const WORDS: usize = BUCKETS / 64;

/// See the [module documentation](self).
#[derive(Debug)]
pub(crate) struct TimerWheel {
  bitmap: [u64; WORDS],
  // The first entry of each bucket
  buckets: Vector<usize, u32>,
  // The next tick to run: every tick before it ran
  cursor: u64,
  entries: Vector<usize, Entry>,
  // The tick at which the overflow list moves into the wheel next
  next_cascade: u64,
  overflow: u32,
  // At most the tick of every entry of the overflow list
  overflow_min: u64,
}

impl TimerWheel {
  /// A wheel for `entries` entries, numbered from zero, whose clock starts at `now_us`.
  #[inline]
  pub(crate) fn new(entries: usize, now_us: u64) -> crate::Result<Self> {
    let buckets = Vector::from_cloneable_elem(BUCKETS, NONE)?;
    let all = Vector::from_cloneable_elem(
      entries,
      Entry { next: NONE, prev: NONE, place: NOWHERE, tick: 0 },
    )?;
    let cursor = now_us / TICK_US;
    Ok(Self {
      bitmap: [0; WORDS],
      buckets,
      cursor,
      entries: all,
      next_cascade: cursor.wrapping_add(BUCKETS_U64 / 2),
      overflow: NONE,
      overflow_min: u64::MAX,
    })
  }

  /// Arms entry `idx` for `deadline_us`, which runs at the first tick at or after it (at the next
  /// tick if it passed), or disarms it if `None`.
  #[inline]
  pub(crate) fn arm(&mut self, idx: u32, deadline_us: Option<u64>) {
    let Some(deadline_us) = deadline_us else {
      self.unlink(idx);
      return;
    };
    let tick = deadline_us.div_ceil(TICK_US).max(self.cursor);
    if self.entries.get(idx as usize).is_some_and(|el| el.place != NOWHERE && el.tick == tick) {
      return;
    }
    self.unlink(idx);
    self.link(idx, tick);
  }

  /// When the next entry is due, at most: the start of the tick of the first bucket that holds
  /// entries, or of the earliest entry of the overflow list.
  #[inline]
  pub(crate) fn next_expiry(&self) -> Option<u64> {
    let start = (self.cursor % BUCKETS_U64) as usize;
    let first = self.next_bucket(start).map(|bucket| {
      let ahead = (bucket.wrapping_add(BUCKETS).wrapping_sub(start)) % BUCKETS;
      self.cursor.wrapping_add(ahead as u64)
    });
    let overflow = (self.overflow != NONE).then_some(self.overflow_min);
    first.into_iter().chain(overflow).min().map(|el| el.saturating_mul(TICK_US))
  }

  /// Runs the ticks up to the one of `now_us`: `fire` gets each entry that is due, disarmed.
  #[inline]
  pub(crate) fn expire(&mut self, now_us: u64, mut fire: impl FnMut(u32)) {
    let now_tick = now_us / TICK_US;
    if now_tick < self.cursor {
      return;
    }
    let ticks = now_tick.wrapping_sub(self.cursor).saturating_add(1);
    if ticks >= BUCKETS_U64 {
      // Every entry of the wheel is due
      for bucket in 0..BUCKETS {
        self.fire_bucket(bucket, &mut fire);
      }
    } else {
      let start = (self.cursor % BUCKETS_U64) as usize;
      let mut done = 0usize;
      let ticks = ticks as usize;
      while let Some(bucket) = self.next_bucket(start.wrapping_add(done) % BUCKETS) {
        let ahead = bucket.wrapping_add(BUCKETS).wrapping_sub(start) % BUCKETS;
        if ahead >= ticks {
          break;
        }
        self.fire_bucket(bucket, &mut fire);
        done = ahead.wrapping_add(1);
        if done >= ticks {
          break;
        }
      }
    }
    self.cursor = now_tick.wrapping_add(1);
    if self.cursor >= self.next_cascade
      || self.overflow_min < self.cursor.wrapping_add(BUCKETS_U64 / 2)
    {
      self.cascade(&mut fire);
    }
  }

  // The entries of the overflow list that are due fire, those of the revolution ahead move into
  // the wheel.
  fn cascade(&mut self, fire: &mut impl FnMut(u32)) {
    self.next_cascade = self.cursor.wrapping_add(BUCKETS_U64 / 2);
    let horizon = self.cursor.wrapping_add(BUCKETS_U64);
    let mut min = u64::MAX;
    let mut idx = self.overflow;
    while let Some(entry) = self.entries.get(idx as usize).copied() {
      let next = entry.next;
      if entry.tick < self.cursor {
        self.unlink(idx);
        fire(idx);
      } else if entry.tick < horizon {
        self.unlink(idx);
        self.link(idx, entry.tick);
      } else {
        min = min.min(entry.tick);
      }
      idx = next;
    }
    self.overflow_min = min;
  }

  fn fire_bucket(&mut self, bucket: usize, fire: &mut impl FnMut(u32)) {
    while let Some(idx) = self.buckets.get(bucket).copied().filter(|el| *el != NONE) {
      self.unlink(idx);
      fire(idx);
    }
  }

  // Puts the entry, which is in no list, in the bucket or the list of `tick`, which is not before
  // the cursor.
  fn link(&mut self, idx: u32, tick: u64) {
    let place = if tick < self.cursor.wrapping_add(BUCKETS_U64) {
      (tick % BUCKETS_U64) as u32
    } else {
      self.overflow_min = self.overflow_min.min(tick);
      OVERFLOW
    };
    let head = if place == OVERFLOW {
      &mut self.overflow
    } else {
      let Some(elem) = self.buckets.get_mut(place as usize) else {
        return;
      };
      elem
    };
    let old = core::mem::replace(head, idx);
    if let Some(elem) = self.entries.get_mut(old as usize) {
      elem.prev = idx;
    }
    if let Some(elem) = self.entries.get_mut(idx as usize) {
      *elem = Entry { next: old, prev: NONE, place, tick };
    }
    if place != OVERFLOW {
      self.set_bit(place as usize, true);
    }
  }

  // The first bucket at or after `start`, in the order of the wheel, that holds entries.
  fn next_bucket(&self, start: usize) -> Option<usize> {
    let (word, bit) = (start / 64, start % 64);
    let first = self.bitmap.get(word).copied().unwrap_or(0) & (u64::MAX << bit);
    if first != 0 {
      return Some(word.wrapping_mul(64).wrapping_add(first.trailing_zeros() as usize));
    }
    for offset in 1..=WORDS {
      let at = word.wrapping_add(offset) % WORDS;
      let mut bits = self.bitmap.get(at).copied().unwrap_or(0);
      if offset == WORDS {
        // Back to the first word: the bits before `start`
        bits &= !(u64::MAX << bit);
      }
      if bits != 0 {
        return Some(at.wrapping_mul(64).wrapping_add(bits.trailing_zeros() as usize));
      }
    }
    None
  }

  fn set_bit(&mut self, bucket: usize, value: bool) {
    if let Some(word) = self.bitmap.get_mut(bucket / 64) {
      let mask = 1u64 << (bucket % 64);
      if value {
        *word |= mask;
      } else {
        *word &= !mask;
      }
    }
  }

  // Takes the entry out of its list, if it is in one.
  fn unlink(&mut self, idx: u32) {
    let Some(entry) = self.entries.get_mut(idx as usize) else {
      return;
    };
    let Entry { next, prev, place, .. } = *entry;
    if place == NOWHERE {
      return;
    }
    *entry = Entry { next: NONE, prev: NONE, place: NOWHERE, tick: 0 };
    if let Some(elem) = self.entries.get_mut(next as usize) {
      elem.prev = prev;
    }
    if let Some(elem) = self.entries.get_mut(prev as usize) {
      elem.next = next;
      return;
    }
    if place == OVERFLOW {
      self.overflow = next;
    } else {
      if let Some(head) = self.buckets.get_mut(place as usize) {
        *head = next;
      }
      if next == NONE {
        self.set_bit(place as usize, false);
      }
    }
  }
}

#[derive(Clone, Copy, Debug)]
struct Entry {
  next: u32,
  place: u32,
  prev: u32,
  tick: u64,
}

#[cfg(test)]
mod tests {
  use crate::quic::timer_wheel::{TICK_US, TimerWheel};
  use alloc::{vec, vec::Vec};

  fn fired(wheel: &mut TimerWheel, now_us: u64) -> Vec<u32> {
    let mut rslt = Vec::new();
    wheel.expire(now_us, |el| rslt.push(el));
    rslt.sort_unstable();
    rslt
  }

  // An entry fires at the first tick at or after its deadline, once, and not before.
  #[test]
  fn entries_fire_at_their_tick_and_never_early() {
    let mut wheel = TimerWheel::new(8, 0).unwrap();
    wheel.arm(0, Some(1_100));
    wheel.arm(1, Some(1_250));
    wheel.arm(2, Some(5_000));
    assert_eq!(wheel.next_expiry(), Some(1_250));
    assert!(fired(&mut wheel, 1_249).is_empty());
    assert_eq!(fired(&mut wheel, 1_250), vec![0, 1]);
    assert!(fired(&mut wheel, 1_250).is_empty());
    assert_eq!(wheel.next_expiry(), Some(5_000));
    assert_eq!(fired(&mut wheel, 9_000), vec![2]);
    assert_eq!(wheel.next_expiry(), None);
  }

  // Arming again moves the entry, disarming takes it out, a deadline that passed fires at the
  // next tick.
  #[test]
  fn rearming_moves_and_disarming_removes() {
    let mut wheel = TimerWheel::new(4, 0).unwrap();
    wheel.arm(0, Some(10_000));
    wheel.arm(0, Some(2_000));
    wheel.arm(1, Some(3_000));
    wheel.arm(1, None);
    assert_eq!(wheel.next_expiry(), Some(2_000));
    assert_eq!(fired(&mut wheel, 10_000), vec![0]);
    wheel.arm(2, Some(1));
    assert_eq!(wheel.next_expiry(), Some(10_250));
    assert_eq!(fired(&mut wheel, 10_250), vec![2]);
  }

  // Deadlines more than one revolution away wait in the overflow list, are reported by
  // `next_expiry` and fire when due, also after the clock jumped past many revolutions.
  #[test]
  fn far_deadlines_overflow_and_cascade() {
    let mut wheel = TimerWheel::new(4, 0).unwrap();
    let far = 30_000_000;
    wheel.arm(0, Some(far));
    wheel.arm(1, Some(far + 3 * TICK_US));
    wheel.arm(2, Some(2_000_000));
    assert_eq!(wheel.next_expiry(), Some(2_000_000));
    // Revolution after revolution, nothing fires before its time
    let mut now = 0;
    while now < far - TICK_US {
      now += 100_000;
      let due = fired(&mut wheel, now.min(far - TICK_US));
      if (2_000_000..2_100_000).contains(&now) {
        assert_eq!(due, vec![2]);
      } else {
        assert!(due.is_empty(), "{now}: {due:?}");
      }
    }
    assert_eq!(wheel.next_expiry(), Some(far));
    assert_eq!(fired(&mut wheel, far), vec![0]);
    assert_eq!(fired(&mut wheel, far + 3 * TICK_US), vec![1]);
    // A jump of many revolutions fires what the wheel and the overflow hold
    wheel.arm(0, Some(far + 500_000));
    wheel.arm(1, Some(far + 90_000_000));
    assert_eq!(fired(&mut wheel, far + 200_000_000), vec![0, 1]);
    assert_eq!(wheel.next_expiry(), None);
  }

  // Many entries over every bucket fire each at its own tick, in a randomized order of arming.
  #[test]
  fn many_entries_fire_at_their_ticks() {
    const N: u32 = 1000;
    let mut wheel = TimerWheel::new(N as usize, 0).unwrap();
    let deadline = |idx: u32| u64::from(idx.wrapping_mul(7919) % 5000) * TICK_US + 1;
    for idx in 0..N {
      wheel.arm(idx, Some(deadline(idx)));
    }
    let mut seen = vec![false; N as usize];
    let mut now = 0;
    while let Some(next) = wheel.next_expiry() {
      assert!(next >= now);
      now = next;
      wheel.expire(now, |idx| {
        assert!(deadline(idx) <= now && now - deadline(idx) < TICK_US, "{idx} at {now}");
        assert!(!seen[idx as usize]);
        seen[idx as usize] = true;
      });
    }
    assert!(seen.iter().all(|el| *el));
  }
}
