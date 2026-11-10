//! The connection IDs of a worker (spec section 5.4): which connection a packet is for.
//!
//! Our connection IDs have 8 bytes, the index of the worker and 7 random bytes, and are looked
//! up in an open addressing table with linear probing, sized once for every connection of the
//! worker at half load, whose values are the slot of the connection and its generation. The
//! random bytes are the hash. Deletion shifts the entries after it back, so the table never holds
//! tombstones.
//!
//! Two short-lived maps hold connection IDs that the client chose, keyed by a hash with a random
//! seed: the original destination connection ID of a connection, while its handshake lasts, and
//! the original destination connection IDs of the first Initial packets that went to another
//! worker, for two seconds, so that the Initial packets that follow go there too.

use crate::{
  collections::Vector,
  misc::random_state,
  quic::{Cid, QuicError},
  rng::Rng,
};
use alloc::collections::VecDeque;
use foldhash::fast::FixedState;
use hashbrown::HashMap;

/// The bytes of our connection IDs.
pub(crate) const CID_LEN: usize = 8;
/// How long a first Initial packet that went to another worker is remembered.
pub(crate) const FORWARDED_TTL_US: u64 = 2_000_000;

const EMPTY: u32 = u32::MAX;

/// A connection of the worker: its slot and the generation of the slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConnRef {
  /// The generation of the slot when the connection was put there.
  pub(crate) generation: u32,
  /// The slot.
  pub(crate) slot: u32,
}

/// See the [module documentation](self).
#[derive(Debug)]
pub(crate) struct CidTable {
  entries: Vector<usize, OurEntry>,
  forwarded: HashMap<Cid, (u8, u64), FixedState>,
  // The keys of `forwarded` in the order in which they expire
  forwarded_order: VecDeque<(u64, Cid)>,
  len: usize,
  mask: usize,
  max_forwarded: usize,
  original: HashMap<Cid, ConnRef, FixedState>,
}

impl CidTable {
  /// A table for `conns` connections, at most `half_open` of them in their handshake, whose maps
  /// are seeded by `rng`.
  #[inline]
  pub(crate) fn new<RNG>(conns: usize, half_open: usize, rng: &mut RNG) -> crate::Result<Self>
  where
    RNG: Rng,
  {
    let capacity = conns.saturating_mul(2).max(16).checked_next_power_of_two().unwrap_or(1 << 31);
    let empty = OurEntry { key: 0, value: ConnRef { generation: 0, slot: EMPTY } };
    let entries = Vector::from_cloneable_elem(capacity, empty)?;
    let mut original = HashMap::with_hasher(random_state(rng));
    original.try_reserve(half_open).map_err(|_err| exhausted())?;
    // As many first Initial packets in two seconds as handshakes at once
    let max_forwarded = half_open.max(16);
    let mut forwarded = HashMap::with_hasher(random_state(rng));
    forwarded.try_reserve(max_forwarded).map_err(|_err| exhausted())?;
    let mut forwarded_order = VecDeque::new();
    forwarded_order.try_reserve_exact(max_forwarded).map_err(|_err| exhausted())?;
    Ok(Self {
      entries,
      forwarded,
      forwarded_order,
      len: 0,
      mask: capacity.wrapping_sub(1),
      max_forwarded,
      original,
    })
  }

  /// Our connection IDs in the table.
  #[cfg(any(test, feature = "_fuzz-conn"))]
  pub(crate) const fn len(&self) -> usize {
    self.len
  }

  /// The connection of our connection ID `cid`.
  #[inline]
  pub(crate) fn get(&self, cid: &[u8]) -> Option<ConnRef> {
    let key = key_of(cid)?;
    let mut idx = self.home(key);
    loop {
      let entry = self.entries.get(idx)?;
      if entry.value.slot == EMPTY {
        return None;
      }
      if entry.key == key {
        return Some(entry.value);
      }
      idx = idx.wrapping_add(1) & self.mask;
    }
  }

  /// Maps our connection ID `cid` to `conn`. Returns `false` if the ID is already in the table or
  /// is not one of ours, or if the table is full.
  #[inline]
  pub(crate) fn insert(&mut self, cid: &[u8], conn: ConnRef) -> bool {
    let Some(key) = key_of(cid) else {
      return false;
    };
    // At most half full
    if self.len.wrapping_mul(2) >= self.entries.len() {
      return false;
    }
    let mut idx = self.home(key);
    loop {
      let Some(entry) = self.entries.get_mut(idx) else {
        return false;
      };
      if entry.value.slot == EMPTY {
        *entry = OurEntry { key, value: conn };
        self.len = self.len.wrapping_add(1);
        return true;
      }
      if entry.key == key {
        return false;
      }
      idx = idx.wrapping_add(1) & self.mask;
    }
  }

  /// Takes our connection ID `cid` out of the table.
  #[inline]
  pub(crate) fn remove(&mut self, cid: &[u8]) {
    let Some(key) = key_of(cid) else {
      return;
    };
    let mut idx = self.home(key);
    loop {
      let Some(entry) = self.entries.get(idx) else {
        return;
      };
      if entry.value.slot == EMPTY {
        return;
      }
      if entry.key == key {
        break;
      }
      idx = idx.wrapping_add(1) & self.mask;
    }
    // Backward shift: each entry after the hole that may move to it does
    let mut hole = idx;
    let mut next = hole.wrapping_add(1) & self.mask;
    loop {
      let Some(entry) = self.entries.get(next).copied() else {
        return;
      };
      if entry.value.slot == EMPTY {
        break;
      }
      let home = self.home(entry.key);
      // The entry stays if its home is in the cyclic range (hole, next]
      let stays =
        if hole <= next { hole < home && home <= next } else { hole < home || home <= next };
      if !stays {
        if let Some(dst) = self.entries.get_mut(hole) {
          *dst = entry;
        }
        hole = next;
      }
      next = next.wrapping_add(1) & self.mask;
    }
    if let Some(dst) = self.entries.get_mut(hole) {
      dst.value.slot = EMPTY;
    }
    self.len = self.len.saturating_sub(1);
  }

  /// The connection whose handshake started with a first Initial packet sent to `cid`.
  #[inline]
  pub(crate) fn get_original(&self, cid: &[u8]) -> Option<ConnRef> {
    self.original.get(&Cid::new(cid).ok()?).copied()
  }

  /// Maps the original destination connection ID `cid` to `conn` while its handshake lasts.
  /// Returns `false` if there is no room, which the caps on handshakes prevent.
  #[inline]
  pub(crate) fn insert_original(&mut self, cid: Cid, conn: ConnRef) -> bool {
    if self.original.len() >= self.original.capacity() && !self.original.contains_key(&cid) {
      return false;
    }
    let _prev = self.original.insert(cid, conn);
    true
  }

  /// Forgets the original destination connection ID `cid`.
  #[inline]
  pub(crate) fn remove_original(&mut self, cid: &Cid) {
    let _prev = self.original.remove(cid);
  }

  /// The worker that the first Initial packet sent to `cid` went to, if that was less than two
  /// seconds before `now_us`.
  #[inline]
  pub(crate) fn get_forwarded(&mut self, cid: &[u8], now_us: u64) -> Option<u8> {
    self.expire_forwarded(now_us);
    let (worker, expiry) = self.forwarded.get(&Cid::new(cid).ok()?).copied()?;
    (now_us < expiry).then_some(worker)
  }

  /// Remembers that the first Initial packet sent to `cid` went to `worker`, for two seconds.
  /// Once as many as it holds wait, the oldest is forgotten.
  #[inline]
  pub(crate) fn insert_forwarded(&mut self, cid: Cid, worker: u8, now_us: u64) {
    self.expire_forwarded(now_us);
    if self.forwarded_order.len() >= self.max_forwarded
      && let Some((_, oldest)) = self.forwarded_order.pop_front()
    {
      let _prev = self.forwarded.remove(&oldest);
    }
    let expiry = now_us.saturating_add(FORWARDED_TTL_US);
    if self.forwarded.insert(cid, (worker, expiry)).is_none() {
      self.forwarded_order.push_back((expiry, cid));
    }
  }

  // Forgets the forwarded IDs that expired.
  fn expire_forwarded(&mut self, now_us: u64) {
    while let Some((expiry, cid)) = self.forwarded_order.front().copied() {
      if expiry > now_us {
        break;
      }
      let _ = self.forwarded_order.pop_front();
      if self.forwarded.get(&cid).is_some_and(|el| el.1 <= now_us) {
        let _prev = self.forwarded.remove(&cid);
      }
    }
  }

  fn home(&self, key: u64) -> usize {
    // Bytes 1 to 7 of our IDs are random: the low bits are a hash
    (key as usize) & self.mask
  }
}

#[derive(Clone, Copy, Debug)]
struct OurEntry {
  key: u64,
  value: ConnRef,
}

fn exhausted() -> crate::Error {
  crate::Error::Quic(QuicError::PoolExhausted)
}

// The key of one of our connection IDs, which have 8 bytes.
fn key_of(cid: &[u8]) -> Option<u64> {
  Some(u64::from_be_bytes(cid.try_into().ok()?))
}

#[cfg(test)]
mod tests {
  use crate::{
    quic::{
      Cid,
      cid_table::{CidTable, ConnRef, FORWARDED_TTL_US},
    },
    rng::{ChaCha20, Rng as _},
  };
  use alloc::vec::Vec;

  fn conn(slot: u32) -> ConnRef {
    ConnRef { generation: slot.wrapping_mul(3), slot }
  }

  // Inserts, lookups and removals in any order keep every other entry reachable, also with
  // collisions that wrap around the end of the table.
  #[test]
  fn our_cids_insert_find_and_remove() {
    let mut rng = ChaCha20::from_key([1; 32]);
    let mut table = CidTable::new(64, 16, &mut rng).unwrap();
    let mut cids: Vec<[u8; 8]> = Vec::new();
    for idx in 0..64u32 {
      let mut cid = [0; 8];
      rng.fill_slice(&mut cid[1..]);
      // Many land on the last slots and wrap
      if idx % 3 == 0 {
        cid[7] = 0xff;
      }
      assert!(table.insert(&cid, conn(idx)));
      cids.push(cid);
    }
    assert_eq!(table.len(), 64);
    // Half full: no room for more
    assert!(!table.insert(&[9; 8], conn(99)));
    assert!(!table.insert(&cids[0], conn(5)));
    for (idx, cid) in cids.iter().enumerate() {
      assert_eq!(table.get(cid), Some(conn(idx as u32)));
    }
    for (idx, cid) in cids.iter().enumerate().filter(|(idx, _)| idx % 2 == 0) {
      table.remove(cid);
      assert_eq!(table.get(cid), None, "{idx}");
    }
    for (idx, cid) in cids.iter().enumerate() {
      let expected = (idx % 2 == 1).then(|| conn(idx as u32));
      assert_eq!(table.get(cid), expected, "{idx}");
    }
    assert_eq!(table.len(), 32);
    // IDs of another length are not ours
    assert_eq!(table.get(&cids[1][..7]), None);
    assert!(!table.insert(&[1; 9], conn(1)));
  }

  // The original destination CIDs are kept until they are removed.
  #[test]
  fn original_cids_map_to_their_connection() {
    let mut table = CidTable::new(16, 4, &mut ChaCha20::from_key([2; 32])).unwrap();
    let cid = Cid::new(&[7; 20]).unwrap();
    assert!(table.insert_original(cid, conn(3)));
    assert_eq!(table.get_original(&[7; 20]), Some(conn(3)));
    assert_eq!(table.get_original(&[7; 19]), None);
    table.remove_original(&cid);
    assert_eq!(table.get_original(&[7; 20]), None);
  }

  // A forwarded CID is remembered for two seconds; past its room, the oldest goes first.
  #[test]
  fn forwarded_cids_expire_after_two_seconds() {
    let mut table = CidTable::new(16, 16, &mut ChaCha20::from_key([3; 32])).unwrap();
    let cid = |byte: u8| Cid::new(&[byte; 8]).unwrap();
    table.insert_forwarded(cid(1), 5, 1_000);
    assert_eq!(table.get_forwarded(&[1; 8], 1_000 + FORWARDED_TTL_US - 1), Some(5));
    assert_eq!(table.get_forwarded(&[1; 8], 1_000 + FORWARDED_TTL_US), None);
    for byte in 0..17 {
      table.insert_forwarded(cid(byte), byte, 10_000_000);
    }
    assert_eq!(table.get_forwarded(&[0; 8], 10_000_000), None);
    assert_eq!(table.get_forwarded(&[16; 8], 10_000_000), Some(16));
    assert_eq!(table.get_forwarded(&[1; 8], 10_000_000), Some(1));
  }
}
