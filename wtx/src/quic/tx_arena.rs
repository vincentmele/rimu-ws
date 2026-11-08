//! The buffer that a worker builds its outgoing datagrams in, in place, grouped in trains that go
//! out with one send each (UDP generic segmentation offload).
//!
//! Datagrams are placed one after the other in a single buffer, allocated once. Consecutive
//! datagrams of the same size, to the same peer and from the same local address, form a train:
//! one contiguous run of bytes that the kernel cuts into datagrams of `segment_size` bytes, the
//! last one of which can be shorter. Space comes back once the send of a train completes.

use crate::collections::Vector;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

// The limits of the kernel for one UDP_SEGMENT send
const MAX_TRAIN_BYTES: usize = 65_535;
const MAX_TRAIN_SEGMENTS: u16 = 64;
// Bytes of the arena per train descriptor: datagrams to different peers that are shorter than
// this on average run out of descriptors before the arena runs out of bytes.
const BYTES_PER_TRAIN: usize = 600;
const MIN_TRAINS: usize = 64;

/// Identifies a train of a [`TxArena`] from [`TxArena::pending`] until [`TxArena::release`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrainId(u32);

/// Datagrams that go out in one send: all of them have `segment_size` bytes but the last one,
/// which can have fewer.
#[derive(Clone, Copy, Debug)]
pub struct TxTrain<'arena> {
  /// What [`TxArena::mark_submitted`] and [`TxArena::release`] take.
  pub id: TrainId,
  /// The datagrams, one after the other.
  pub bytes: &'arena [u8],
  /// The size of every datagram but the last one.
  pub segment_size: u16,
  /// Where the datagrams go.
  pub peer: SocketAddr,
  /// The local address that the datagrams must leave from: the one that the peer sent to.
  pub local: Option<IpAddr>,
}

/// The buffer of the outgoing datagrams of a worker. See the [module documentation](self).
#[derive(Debug)]
pub struct TxArena {
  // The datagram that `begin` handed out and that `commit` has not taken yet
  begun: Option<Begun>,
  buffer: Vector<usize, u8>,
  // The ring of trains, from the oldest at `first`, `count` of them
  count: usize,
  first: usize,
  next_id: u32,
  // If the newest train can take more datagrams
  open: bool,
  trains: Vector<usize, Train>,
}

impl TxArena {
  /// The default size: 512 datagrams of 1500 bytes.
  pub const DEFAULT_BYTES: usize = 512 * 1500;

  /// An arena of `bytes` bytes, all of them allocated now.
  #[inline]
  pub fn new(bytes: usize) -> crate::Result<Self> {
    let trains = (bytes / BYTES_PER_TRAIN).max(MIN_TRAINS);
    Ok(Self {
      begun: None,
      buffer: Vector::from_cloneable_elem(bytes, 0)?,
      count: 0,
      first: 0,
      next_id: 0,
      open: false,
      trains: Vector::from_cloneable_elem(trains, Train::EMPTY)?,
    })
  }

  /// Room for a datagram of at most `max_len` bytes to `peer`, from `local`, or `None` if the
  /// arena is full. The datagram is written into the returned bytes and then given to
  /// [`Self::commit`]; another call to this method forgets it.
  #[inline]
  pub(crate) fn begin(
    &mut self,
    peer: SocketAddr,
    local: Option<IpAddr>,
    max_len: usize,
  ) -> Option<&mut [u8]> {
    self.begun = None;
    let capacity = self.buffer.len();
    if max_len == 0 || max_len > capacity.min(MAX_TRAIN_BYTES) || self.count >= self.trains.len() {
      return None;
    }
    let (start, after_newest) = if let (Some(oldest), Some(newest)) = (self.oldest(), self.newest())
    {
      let head = newest.start.wrapping_add(newest.len);
      if newest.start >= oldest.start {
        // The occupied bytes go from the oldest train to the head: room after them or, failing
        // that, before them
        if capacity.wrapping_sub(head) >= max_len {
          (head, true)
        } else if oldest.start >= max_len {
          (0, false)
        } else {
          return None;
        }
      } else if oldest.start.wrapping_sub(head) >= max_len {
        // The newest trains are at the beginning of the buffer, before the oldest ones
        (head, true)
      } else {
        return None;
      }
    } else {
      (0, false)
    };
    self.begun = Some(Begun { after_newest, local, max_len, peer, start });
    self.buffer.get_mut(start..start.wrapping_add(max_len))
  }

  /// Takes the first `len` bytes of the datagram that [`Self::begin`] handed out. They join the
  /// newest train if it goes to the same peer from the same address, has not been submitted, has
  /// fewer than 64 datagrams and fewer than 65,535 bytes with this one, and if its datagrams have
  /// `len` bytes. A shorter datagram is the last one of its train.
  #[inline]
  pub(crate) fn commit(&mut self, len: usize) {
    let Some(begun) = self.begun.take() else {
      return;
    };
    if len == 0 {
      return;
    }
    let len = len.min(begun.max_len);
    let open = self.open;
    if let Some(newest) = self.newest_mut()
      && open
      && begun.after_newest
      && newest.state == TrainState::Pending
      && newest.peer == begun.peer
      && newest.local == begun.local
      && newest.segments < MAX_TRAIN_SEGMENTS
      && newest.len.wrapping_add(len) <= MAX_TRAIN_BYTES
      && len <= usize::from(newest.segment_size)
    {
      newest.len = newest.len.wrapping_add(len);
      newest.segments = newest.segments.wrapping_add(1);
      if len < usize::from(newest.segment_size) {
        self.open = false;
      }
      return;
    }
    let capacity = self.trains.len();
    let idx = self.first.wrapping_add(self.count) % capacity;
    let Some(slot) = self.trains.get_mut(idx) else {
      return;
    };
    *slot = Train {
      id: self.next_id,
      len,
      local: begun.local,
      peer: begun.peer,
      segment_size: u16::try_from(len).unwrap_or(u16::MAX),
      segments: 1,
      start: begun.start,
      state: TrainState::Pending,
    };
    self.next_id = self.next_id.wrapping_add(1);
    self.count = self.count.wrapping_add(1);
    self.open = true;
  }

  /// Marks the train as handed to the kernel: no datagram joins it anymore.
  #[inline]
  pub fn mark_submitted(&mut self, id: TrainId) {
    let is_newest = self.is_newest(id);
    if let Some(train) = self.train_mut(id)
      && train.state == TrainState::Pending
    {
      train.state = TrainState::Submitted;
      if is_newest {
        self.open = false;
      }
    }
  }

  /// The trains that were not submitted yet, from the oldest to the newest.
  #[inline]
  pub fn pending(&self) -> impl Iterator<Item = TxTrain<'_>> {
    let capacity = self.trains.len();
    (0..self.count).filter_map(move |offset| {
      let train = self.trains.get(self.first.wrapping_add(offset) % capacity)?;
      if train.state != TrainState::Pending {
        return None;
      }
      Some(TxTrain {
        id: TrainId(train.id),
        bytes: self.buffer.get(train.start..train.start.wrapping_add(train.len))?,
        segment_size: train.segment_size,
        peer: train.peer,
        local: train.local,
      })
    })
  }

  /// Gives the bytes of the train back once its send completed, or failed. Space is reused in the
  /// order in which trains were made, so a train that is never released holds back the ones made
  /// after it.
  #[inline]
  pub fn release(&mut self, id: TrainId) {
    if self.is_newest(id) {
      self.open = false;
    }
    if let Some(train) = self.train_mut(id) {
      train.state = TrainState::Released;
    }
    let capacity = self.trains.len();
    while self.oldest().is_some_and(|train| train.state == TrainState::Released) {
      self.first = self.first.wrapping_add(1) % capacity;
      self.count = self.count.wrapping_sub(1);
    }
  }

  fn is_newest(&self, id: TrainId) -> bool {
    self.newest().is_some_and(|train| train.id == id.0)
  }

  fn newest(&self) -> Option<&Train> {
    let last = self.count.checked_sub(1)?;
    self.trains.get(self.first.wrapping_add(last) % self.trains.len())
  }

  fn newest_mut(&mut self) -> Option<&mut Train> {
    let last = self.count.checked_sub(1)?;
    let capacity = self.trains.len();
    self.trains.get_mut(self.first.wrapping_add(last) % capacity)
  }

  fn oldest(&self) -> Option<&Train> {
    if self.count == 0 {
      return None;
    }
    self.trains.get(self.first)
  }

  fn train_mut(&mut self, id: TrainId) -> Option<&mut Train> {
    let first_id = self.oldest()?.id;
    let offset = usize::try_from(id.0.wrapping_sub(first_id)).ok()?;
    if offset >= self.count {
      return None;
    }
    let capacity = self.trains.len();
    self.trains.get_mut(self.first.wrapping_add(offset) % capacity)
  }
}

#[derive(Clone, Copy, Debug)]
struct Begun {
  // If the datagram starts where the newest train ends
  after_newest: bool,
  local: Option<IpAddr>,
  max_len: usize,
  peer: SocketAddr,
  start: usize,
}

#[derive(Clone, Copy, Debug)]
struct Train {
  id: u32,
  len: usize,
  local: Option<IpAddr>,
  peer: SocketAddr,
  segment_size: u16,
  segments: u16,
  start: usize,
  state: TrainState,
}

impl Train {
  const EMPTY: Self = Self {
    id: 0,
    len: 0,
    local: None,
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    segment_size: 0,
    segments: 0,
    start: 0,
    state: TrainState::Released,
  };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrainState {
  Pending,
  Submitted,
  Released,
}

#[cfg(test)]
mod tests {
  use crate::quic::tx_arena::{TrainId, TxArena};
  use alloc::vec::Vec;
  use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

  const A: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4433);
  const B: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 4433);

  fn push(arena: &mut TxArena, peer: SocketAddr, local: Option<IpAddr>, len: usize, fill: u8) {
    let buffer = arena.begin(peer, local, 1500).unwrap();
    buffer[..len].fill(fill);
    arena.commit(len);
  }

  // (segment size, number of bytes, peer) of each pending train
  fn trains(arena: &TxArena) -> Vec<(u16, usize, SocketAddr)> {
    arena.pending().map(|el| (el.segment_size, el.bytes.len(), el.peer)).collect()
  }

  fn ids(arena: &TxArena) -> Vec<TrainId> {
    arena.pending().map(|el| el.id).collect()
  }

  #[test]
  fn tx_arena_forms_gso_trains() {
    let mut arena = TxArena::new(TxArena::DEFAULT_BYTES).unwrap();
    for idx in 0..3 {
      push(&mut arena, A, None, 1472, idx);
    }
    push(&mut arena, A, None, 300, 3);
    assert_eq!(trains(&arena), [(1472, 3 * 1472 + 300, A)]);
    let train = arena.pending().next().unwrap();
    for (idx, segment) in train.bytes.chunks(1472).enumerate() {
      assert!(segment.iter().all(|el| usize::from(*el) == idx), "{idx}");
    }
    assert_eq!(train.bytes.len().div_ceil(1472), 4);
    // A different peer starts a new train
    push(&mut arena, B, None, 1472, 4);
    // The short datagram ended the first train: one more to A starts a third
    push(&mut arena, A, None, 1472, 5);
    assert_eq!(trains(&arena), [(1472, 3 * 1472 + 300, A), (1472, 1472, B), (1472, 1472, A)]);
  }

  #[test]
  fn trains_respect_the_segment_and_byte_limits() {
    let mut arena = TxArena::new(TxArena::DEFAULT_BYTES).unwrap();
    // 65,535 bytes at most: 44 datagrams of 1472
    for _ in 0..45 {
      push(&mut arena, A, None, 1472, 0);
    }
    assert_eq!(trains(&arena), [(1472, 44 * 1472, A), (1472, 1472, A)]);
    // 64 datagrams at most
    let mut arena = TxArena::new(TxArena::DEFAULT_BYTES).unwrap();
    for _ in 0..65 {
      push(&mut arena, A, None, 1000, 0);
    }
    assert_eq!(trains(&arena), [(1000, 64_000, A), (1000, 1000, A)]);
    // A longer datagram, another local address, or a submitted train start new trains
    let mut arena = TxArena::new(TxArena::DEFAULT_BYTES).unwrap();
    let local = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
    push(&mut arena, A, None, 1200, 0);
    push(&mut arena, A, None, 1472, 0);
    push(&mut arena, A, local, 1472, 0);
    push(&mut arena, A, local, 1472, 0);
    assert_eq!(trains(&arena), [(1200, 1200, A), (1472, 1472, A), (1472, 2944, A)]);
    assert_eq!(arena.pending().nth(2).unwrap().local, local);
    let last = *ids(&arena).last().unwrap();
    arena.mark_submitted(last);
    push(&mut arena, A, local, 1472, 0);
    assert_eq!(trains(&arena), [(1200, 1200, A), (1472, 1472, A), (1472, 1472, A)]);
  }

  #[test]
  fn begin_without_commit_writes_nothing() {
    let mut arena = TxArena::new(4 * 1500).unwrap();
    assert!(arena.begin(A, None, 1500).is_some());
    assert!(arena.begin(A, None, 1500).is_some());
    arena.commit(0);
    assert_eq!(arena.pending().count(), 0);
    // A commit without a begin does nothing either
    arena.commit(100);
    assert_eq!(arena.pending().count(), 0);
    // A datagram can not be larger than the arena or than a train
    assert!(arena.begin(A, None, 4 * 1500 + 1).is_none());
    assert!(arena.begin(A, None, 0).is_none());
    assert!(TxArena::new(70_000).unwrap().begin(A, None, 65_536).is_none());
  }

  #[test]
  fn space_comes_back_in_order_and_wraps() {
    let mut arena = TxArena::new(4 * 1000).unwrap();
    for (peer, fill) in [(A, 1), (B, 2), (A, 3), (B, 4)] {
      let buffer = arena.begin(peer, None, 1000).unwrap();
      buffer.fill(fill);
      arena.commit(1000);
    }
    assert!(arena.begin(A, None, 1000).is_none());
    let ids = ids(&arena);
    for id in &ids {
      arena.mark_submitted(*id);
    }
    assert_eq!(arena.pending().count(), 0);
    // Out of order: nothing comes back until the oldest train does
    arena.release(ids[1]);
    assert!(arena.begin(A, None, 1000).is_none());
    arena.release(ids[0]);
    // The first two come back, at the front of the buffer
    let buffer = arena.begin(A, None, 2000).unwrap();
    buffer.fill(5);
    arena.commit(2000);
    assert!(arena.begin(A, None, 1).is_none());
    let pending: Vec<_> = arena.pending().collect();
    assert_eq!(pending.len(), 1);
    assert!(pending[0].bytes.iter().all(|el| *el == 5));
    let id = pending[0].id;
    arena.release(ids[2]);
    arena.release(ids[3]);
    // Behind the newest train, room for 2000 bytes again
    arena.begin(B, None, 2000).unwrap().fill(6);
    arena.commit(2000);
    arena.release(id);
    assert_eq!(trains(&arena), [(2000, 2000, B)]);
    // Releasing what is unknown or already released changes nothing
    arena.release(id);
    arena.release(TrainId(u32::MAX));
    arena.mark_submitted(TrainId(u32::MAX));
    assert_eq!(trains(&arena), [(2000, 2000, B)]);
    // Once all is released, the arena starts over
    let last = ids_of(&arena);
    arena.release(last);
    assert!(arena.begin(A, None, 4000).is_some());
  }

  fn ids_of(arena: &TxArena) -> TrainId {
    arena.pending().next().unwrap().id
  }

  #[test]
  fn descriptors_bound_the_number_of_trains() {
    let mut arena = TxArena::new(TxArena::DEFAULT_BYTES).unwrap();
    let mut made = 0;
    let mut port = 1u16;
    while let Some(buffer) = arena.begin(SocketAddr::new(A.ip(), port), None, 60) {
      buffer.fill(0);
      arena.commit(60);
      made += 1;
      port = port.wrapping_add(1);
    }
    assert_eq!(made, TxArena::DEFAULT_BYTES / 600);
    let first = ids_of(&arena);
    arena.release(first);
    assert!(arena.begin(A, None, 60).is_some());
  }
}
