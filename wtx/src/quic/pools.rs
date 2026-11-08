//! The worker-wide pools that connections borrow their variable-sized state from (spec section
//! 5.4): grown on demand up to caps, reused without allocating once warm, and trimmed to a few
//! entries when the worker is idle.
//!
//! A connection holds indices into [`FrameRefPool`] and [`StreamSlots`], and owns what it took
//! from the free lists until it gives it back, once closed or aborted.

use crate::quic::{
  QuicError, TransportErrorCode,
  conn::HandshakeSpaces,
  sent::{FrameRef, FrameRefRange, SentPacket},
  stream::{ConnCold, StreamSlots},
  wipe,
};
use alloc::{boxed::Box, vec::Vec};
use core::hint::cold_path;

/// The bytes of the out-of-order CRYPTO data that a level buffers, the minimum of RFC 9000
/// section 7.5.
pub(crate) const CRYPTO_BUFFER_LEN: usize = 4096;
/// The size of a receive block.
pub(crate) const RX_BLOCK_LEN: usize = 4096;
/// The size of a send block.
pub(crate) const TX_BLOCK_LEN: usize = 4096;

/// Received stream data that does not fit in its slot.
pub(crate) type RxBlock = [u8; RX_BLOCK_LEN];
/// Stream data written by the application that does not fit in its slot.
pub(crate) type TxBlock = [u8; TX_BLOCK_LEN];

// References per chunk of the frame reference pool
const CHUNK_REFS: usize = 8;
// Chunks of the frame reference pool at most: 2^15 of about 200 bytes
const MAX_CHUNKS: usize = 1 << 15;
// Entries of a free list at most
const MAX_FREE: usize = 1024;
// Entries kept by an idle pool
const IDLE_KEEP: usize = 4;
const IDLE_KEEP_CHUNKS: usize = 64;
const IDLE_KEEP_SLOTS: usize = 64;
const NO_CHUNK: u32 = u32::MAX;

/// The pools of a worker. See the [module documentation](self).
#[derive(Debug)]
pub(crate) struct QuicPools {
  /// The seldom used state of a connection.
  pub(crate) conn_cold: FreeList<Box<ConnCold>>,
  /// Out-of-order CRYPTO data of a level.
  pub(crate) crypto_buffers: FreeList<Box<CryptoBuffer>>,
  /// The frames of sent packets.
  pub(crate) frame_refs: FrameRefPool,
  /// The Initial and Handshake spaces of a handshake, keys included (wiped when they come back).
  pub(crate) handshake_spaces: FreeList<Box<HandshakeSpaces>>,
  /// Received stream data that does not fit in a stream slot.
  pub(crate) rx_blocks: FreeList<Box<RxBlock>>,
  /// The records of sent packets of a packet number space.
  pub(crate) sent_rings: FreeList<Vec<Option<SentPacket>>>,
  /// The streams of every connection.
  pub(crate) stream_slots: StreamSlots,
  /// Stream data to send that does not fit in a stream slot.
  pub(crate) tx_blocks: FreeList<Box<TxBlock>>,
}

impl QuicPools {
  /// Empty pools, which allocate nothing until used.
  pub(crate) const fn new() -> Self {
    Self {
      conn_cold: FreeList::new(),
      crypto_buffers: FreeList::new(),
      frame_refs: FrameRefPool::new(MAX_CHUNKS),
      handshake_spaces: FreeList::new(),
      rx_blocks: FreeList::new(),
      sent_rings: FreeList::new(),
      stream_slots: StreamSlots::new(),
      tx_blocks: FreeList::new(),
    }
  }

  /// Frees all but a few entries of every pool, for a worker that has no connection: the frame
  /// reference pool and the stream slots only if none is in use.
  #[inline]
  pub(crate) fn trim_idle(&mut self) {
    self.conn_cold.trim(IDLE_KEEP);
    self.crypto_buffers.trim(IDLE_KEEP);
    self.frame_refs.trim_idle(IDLE_KEEP_CHUNKS);
    self.handshake_spaces.trim(IDLE_KEEP);
    self.rx_blocks.trim(IDLE_KEEP);
    self.sent_rings.trim(IDLE_KEEP);
    self.stream_slots.trim_idle(IDLE_KEEP_SLOTS);
    self.tx_blocks.trim(IDLE_KEEP);
  }
}

impl Default for QuicPools {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

/// Out-of-order CRYPTO data of an encryption level: a ring of bytes indexed by offset, with a bit
/// per byte that tells which ones arrived.
#[derive(Debug)]
pub(crate) struct CryptoBuffer {
  pub(crate) data: [u8; CRYPTO_BUFFER_LEN],
  pub(crate) have: [u64; CRYPTO_BUFFER_LEN / 64],
}

impl CryptoBuffer {
  /// A buffer from the pool, or a new one.
  #[inline]
  pub(crate) fn take(pools: &mut QuicPools) -> Box<Self> {
    pools.crypto_buffers.take().unwrap_or_else(|| {
      Box::new(Self { data: [0; CRYPTO_BUFFER_LEN], have: [0; CRYPTO_BUFFER_LEN / 64] })
    })
  }

  /// Gives `this` back to the pool, its data overwritten with zeros (handshake data).
  #[inline]
  pub(crate) fn give(mut this: Box<Self>, pools: &mut QuicPools) {
    wipe(&mut this.data);
    this.have = [0; CRYPTO_BUFFER_LEN / 64];
    pools.crypto_buffers.give(this);
  }
}

/// Owned entries of ended uses, most recent last, at most 1024 of them.
#[derive(Debug)]
pub(crate) struct FreeList<T> {
  items: Vec<T>,
}

impl<T> FreeList<T> {
  const fn new() -> Self {
    Self { items: Vec::new() }
  }

  /// Keeps `item` for the next use, or frees it if the list is full.
  #[inline]
  pub(crate) fn give(&mut self, item: T) {
    if self.items.len() < MAX_FREE {
      self.items.push(item);
    }
  }

  /// The number of entries kept.
  #[inline]
  pub(crate) fn len(&self) -> usize {
    self.items.len()
  }

  /// The most recently given entry.
  #[inline]
  pub(crate) fn take(&mut self) -> Option<T> {
    self.items.pop()
  }

  fn trim(&mut self, keep: usize) {
    let excess = self.items.len().saturating_sub(keep);
    let _ = self.items.drain(..excess);
    self.items.shrink_to(keep);
  }
}

/// The frame references of every sent packet of a worker, in chunks of eight linked from the
/// first to the last: a [`FrameRefRange`] is the first chunk, the last one and the number of
/// references.
#[derive(Debug)]
pub(crate) struct FrameRefPool {
  chunks: Vec<Chunk>,
  // The first free chunk, the others linked from it
  free: u32,
  live: usize,
  max_chunks: usize,
}

impl FrameRefPool {
  const fn new(max_chunks: usize) -> Self {
    Self { chunks: Vec::new(), free: NO_CHUNK, live: 0, max_chunks }
  }

  /// Frees the chunks of `range`, which is not used anymore.
  #[inline]
  pub(crate) fn free(&mut self, range: FrameRefRange) {
    let mut idx = range.head;
    for _ in 0..range.len().div_ceil(CHUNK_REFS) {
      let free = self.free;
      let Some(chunk) = self.chunk_mut(idx) else {
        break;
      };
      let next = chunk.next;
      chunk.next = free;
      self.free = idx;
      self.live = self.live.saturating_sub(1);
      idx = next;
    }
  }

  /// A cursor over the references of `range`, which borrows the pool only while it moves.
  #[inline]
  pub(crate) const fn cursor(range: FrameRefRange) -> FrameRefCursor {
    FrameRefCursor { idx: range.head, len: range.len(), nth: 0 }
  }

  /// The references of `range`, in the order in which they were pushed.
  #[inline]
  pub(crate) fn iter(&self, range: FrameRefRange) -> impl Iterator<Item = FrameRef> + '_ {
    let mut idx = range.head;
    let mut chunk: Option<&Chunk> = None;
    (0..range.len()).map_while(move |nth| {
      let slot = nth % CHUNK_REFS;
      if slot == 0 {
        if let Some(elem) = chunk {
          idx = elem.next;
        }
        chunk = self.chunks.get(usize::try_from(idx).ok()?);
      }
      chunk?.refs.get(slot).copied()
    })
  }

  /// The number of chunks that hold references in use.
  #[inline]
  pub(crate) const fn live_chunks(&self) -> usize {
    self.live
  }

  /// Appends `frame` to `range`. Fails if the pool is at its cap, a connection error.
  #[inline]
  pub(crate) fn push(&mut self, range: &mut FrameRefRange, frame: FrameRef) -> crate::Result<()> {
    let Some(new_len) = range.len.checked_add(1) else {
      return Err(exhausted());
    };
    let slot = range.len() % CHUNK_REFS;
    if slot == 0 {
      let idx = self.alloc()?;
      if range.len == 0 {
        range.head = idx;
      } else if let Some(tail) = self.chunk_mut(range.tail) {
        tail.next = idx;
      }
      range.tail = idx;
    }
    let Some(elem) = self.chunk_mut(range.tail).and_then(|el| el.refs.get_mut(slot)) else {
      return Err(exhausted());
    };
    *elem = frame;
    range.len = new_len;
    Ok(())
  }

  fn alloc(&mut self) -> crate::Result<u32> {
    let idx = if self.free == NO_CHUNK {
      if self.chunks.len() >= self.max_chunks {
        return Err(exhausted());
      }
      let idx = u32::try_from(self.chunks.len()).map_err(|_err| exhausted())?;
      self.chunks.push(Chunk::EMPTY);
      idx
    } else {
      let idx = self.free;
      let Some(chunk) = self.chunk_mut(idx) else {
        return Err(exhausted());
      };
      let next = chunk.next;
      chunk.next = NO_CHUNK;
      self.free = next;
      idx
    };
    self.live = self.live.wrapping_add(1);
    Ok(idx)
  }

  fn chunk_mut(&mut self, idx: u32) -> Option<&mut Chunk> {
    self.chunks.get_mut(usize::try_from(idx).ok()?)
  }

  fn trim_idle(&mut self, keep: usize) {
    if self.live != 0 {
      return;
    }
    self.chunks.truncate(keep);
    self.chunks.shrink_to(keep);
    self.free = NO_CHUNK;
    for (idx, chunk) in self.chunks.iter_mut().enumerate().rev() {
      chunk.next = self.free;
      self.free = u32::try_from(idx).unwrap_or(NO_CHUNK);
    }
  }
}

/// The references of a [`FrameRefRange`], one at a time, for a caller that needs the pools in
/// between.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameRefCursor {
  idx: u32,
  len: usize,
  nth: usize,
}

impl FrameRefCursor {
  /// The next reference, from `pool`.
  #[inline]
  pub(crate) fn next(&mut self, pool: &FrameRefPool) -> Option<FrameRef> {
    if self.nth >= self.len {
      return None;
    }
    let slot = self.nth % CHUNK_REFS;
    let chunk = pool.chunks.get(usize::try_from(self.idx).ok()?)?;
    let frame = chunk.refs.get(slot).copied()?;
    self.nth = self.nth.wrapping_add(1);
    if slot == CHUNK_REFS.wrapping_sub(1) {
      self.idx = chunk.next;
    }
    Some(frame)
  }
}

#[derive(Clone, Copy, Debug)]
struct Chunk {
  next: u32,
  refs: [FrameRef; CHUNK_REFS],
}

impl Chunk {
  const EMPTY: Self = Self { next: NO_CHUNK, refs: [FrameRef::HandshakeDone; CHUNK_REFS] };
}

#[inline(always)]
fn exhausted() -> crate::Error {
  cold_path();
  crate::Error::QuicClose(TransportErrorCode::InternalError, QuicError::PoolExhausted)
}

#[cfg(test)]
mod tests {
  use crate::quic::{
    pools::{CryptoBuffer, FrameRefPool, QuicPools},
    sent::{FrameRef, FrameRefRange},
  };
  use alloc::vec::Vec;

  fn refs(pool: &FrameRefPool, range: FrameRefRange) -> Vec<FrameRef> {
    pool.iter(range).collect()
  }

  #[test]
  fn frame_refs_span_chunks_and_are_reused() {
    let mut pool = FrameRefPool::new(16);
    let mut first = FrameRefRange::EMPTY;
    let mut second = FrameRefRange::EMPTY;
    for idx in 0..20u64 {
      pool.push(&mut first, FrameRef::Ack { largest: idx }).unwrap();
      pool.push(&mut second, FrameRef::Crypto { offset: idx, len: 1 }).unwrap();
    }
    assert_eq!(first.len(), 20);
    assert_eq!(pool.live_chunks(), 6);
    let expected: Vec<_> = (0..20).map(|el| FrameRef::Ack { largest: el }).collect();
    assert_eq!(refs(&pool, first), expected);
    let expected: Vec<_> = (0..20).map(|el| FrameRef::Crypto { offset: el, len: 1 }).collect();
    assert_eq!(refs(&pool, second), expected);
    assert!(refs(&pool, FrameRefRange::EMPTY).is_empty());
    pool.free(first);
    assert_eq!(pool.live_chunks(), 3);
    // Freed chunks are used again before the pool grows
    let chunks = pool.chunks.len();
    let mut third = FrameRefRange::EMPTY;
    for _ in 0..24 {
      pool.push(&mut third, FrameRef::HandshakeDone).unwrap();
    }
    assert_eq!(pool.chunks.len(), chunks);
    assert_eq!(refs(&pool, third), [FrameRef::HandshakeDone; 24]);
    let mut cursor = FrameRefPool::cursor(third);
    let mut count = 0;
    while let Some(frame) = cursor.next(&pool) {
      assert_eq!(frame, FrameRef::HandshakeDone);
      count += 1;
    }
    assert_eq!(count, 24);
    let mut cursor = FrameRefPool::cursor(second);
    let walked: Vec<_> = core::iter::from_fn(|| cursor.next(&pool)).collect();
    assert_eq!(walked, refs(&pool, second));
    pool.free(second);
    pool.free(third);
    assert_eq!(pool.live_chunks(), 0);
  }

  #[test]
  fn frame_ref_pool_cap_is_an_internal_error() {
    let mut pool = FrameRefPool::new(2);
    let mut range = FrameRefRange::EMPTY;
    for _ in 0..16 {
      pool.push(&mut range, FrameRef::HandshakeDone).unwrap();
    }
    assert!(matches!(
      pool.push(&mut range, FrameRef::HandshakeDone),
      Err(crate::Error::QuicClose(
        crate::quic::TransportErrorCode::InternalError,
        crate::quic::QuicError::PoolExhausted
      ))
    ));
    assert_eq!(range.len(), 16);
    pool.free(range);
    let mut range = FrameRefRange::EMPTY;
    pool.push(&mut range, FrameRef::HandshakeDone).unwrap();
  }

  #[test]
  fn idle_trim_keeps_a_few() {
    let mut pools = QuicPools::new();
    let mut range = FrameRefRange::EMPTY;
    for _ in 0..1000 {
      pools.frame_refs.push(&mut range, FrameRef::HandshakeDone).unwrap();
    }
    // In use: nothing is trimmed
    pools.trim_idle();
    assert_eq!(pools.frame_refs.chunks.len(), 125);
    pools.frame_refs.free(range);
    pools.trim_idle();
    assert_eq!(pools.frame_refs.chunks.len(), 64);
    let mut range = FrameRefRange::EMPTY;
    for _ in 0..64 * 8 {
      pools.frame_refs.push(&mut range, FrameRef::HandshakeDone).unwrap();
    }
    assert_eq!(pools.frame_refs.chunks.len(), 64);
    for _ in 0..10 {
      CryptoBuffer::give(CryptoBuffer::take(&mut pools), &mut pools);
      pools.sent_rings.give(Vec::new());
    }
    assert_eq!((pools.crypto_buffers.len(), pools.sent_rings.len()), (1, 10));
    pools.trim_idle();
    assert_eq!((pools.crypto_buffers.len(), pools.sent_rings.len()), (1, 4));
  }

  #[test]
  fn crypto_buffers_come_back_zeroed() {
    let mut pools = QuicPools::new();
    let mut buffer = CryptoBuffer::take(&mut pools);
    buffer.data.fill(0xa5);
    buffer.have[3] = 7;
    let addr = (&raw const *buffer).addr();
    CryptoBuffer::give(buffer, &mut pools);
    let buffer = CryptoBuffer::take(&mut pools);
    assert_eq!((&raw const *buffer).addr(), addr);
    assert!(buffer.data.iter().all(|el| *el == 0) && buffer.have.iter().all(|el| *el == 0));
  }
}
