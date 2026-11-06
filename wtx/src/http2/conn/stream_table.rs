//! The connection's open streams, in reusable slots.

use crate::{
  collections::{DequeUsize, VectorUsize},
  http::{Headers, Method, MsgBufferString, MsgDataMut as _, Protocol, StatusCode},
  http2::conn::body::SharedBytes,
};

/// Body bytes queued on a stream until the windows let them go.
#[derive(Debug)]
pub(crate) enum SendItem {
  /// The next `len` bytes of `Stream::owned`.
  Owned(usize),
  /// Shared bytes, sent by reference.
  Shared(SharedBytes),
}

impl SendItem {
  pub(crate) fn len(&self) -> usize {
    match self {
      Self::Owned(len) => *len,
      Self::Shared(elem) => elem.len(),
    }
  }
}

/// One open stream.
#[derive(Debug)]
pub(crate) struct Stream {
  /// The declared `content-length` of the body being received, if any.
  pub(crate) content_length: Option<usize>,
  pub(crate) id: u32,
  pub(crate) method: Option<Method>,
  /// The request (server) or response (client) being received. Its buffers are kept when the
  /// slot is freed, so the next stream reuses them.
  pub(crate) msg: MsgBufferString,
  pub(crate) protocol: Option<Protocol>,
  /// Body bytes received so far.
  pub(crate) recv_body_len: usize,
  /// The peer sent END_STREAM.
  pub(crate) recv_closed: bool,
  /// Flow-control window for what the peer sends us.
  pub(crate) recv_window: i32,
  /// The initial HEADERS have arrived (later HEADERS are trailers).
  pub(crate) recv_headers: bool,
  /// The slot holds an open stream.
  pub(crate) live: bool,
  /// We sent END_STREAM.
  pub(crate) send_closed: bool,
  /// We sent the initial HEADERS.
  pub(crate) send_headers: bool,
  /// Flow-control window for what we send. May go negative after a SETTINGS change.
  pub(crate) send_window: i32,
  /// The stream is in the connection's list of streams waiting for window.
  pub(crate) blocked: bool,
  /// Send END_STREAM once the queue drains.
  pub(crate) end_after_queue: bool,
  /// Bytes of the front queue item already sent.
  pub(crate) front_sent: usize,
  /// Copies of borrowed bodies that could not be sent at once.
  pub(crate) owned: VectorUsize<u8>,
  /// Bytes of `owned` already sent.
  pub(crate) owned_read: usize,
  /// Capacity released by the application and not yet announced in a WINDOW_UPDATE.
  pub(crate) recv_unacked: u32,
  pub(crate) send_queue: DequeUsize<SendItem>,
  /// The response status (client).
  pub(crate) status: Option<StatusCode>,
  /// Trailers to send once the queue drains, encoded only then so header blocks reach the peer in
  /// the order they were encoded.
  pub(crate) trailers: Option<Headers>,
}

impl Stream {
  fn new() -> Self {
    Self {
      content_length: None,
      id: 0,
      method: None,
      msg: MsgBufferString::default(),
      protocol: None,
      recv_body_len: 0,
      recv_closed: false,
      recv_window: 0,
      recv_headers: false,
      live: false,
      send_closed: false,
      send_headers: false,
      send_window: 0,
      blocked: false,
      end_after_queue: false,
      front_sent: 0,
      owned: VectorUsize::new(),
      owned_read: 0,
      recv_unacked: 0,
      send_queue: DequeUsize::new(),
      status: None,
      trailers: None,
    }
  }

  /// Body bytes queued and not yet sent.
  /// Of [`Self::send_pending`], the bytes the stream holds itself (not shared ones).
  pub(crate) fn send_pending_owned(&self) -> usize {
    let mut sum: usize = 0;
    for (idx, item) in self.send_queue.iter().enumerate() {
      if let SendItem::Owned(len) = item {
        let sent = if idx == 0 { self.front_sent } else { 0 };
        sum = sum.wrapping_add(len.saturating_sub(sent));
      }
    }
    sum
  }

  pub(crate) fn send_pending(&self) -> usize {
    self.send_queue.iter().map(SendItem::len).sum::<usize>().saturating_sub(self.front_sent)
  }

  fn reset(&mut self, id: u32, recv_window: i32, send_window: i32) {
    self.content_length = None;
    self.id = id;
    self.method = None;
    self.msg.clear();
    self.protocol = None;
    self.recv_body_len = 0;
    self.recv_closed = false;
    self.recv_window = recv_window;
    self.recv_headers = false;
    self.send_closed = false;
    self.send_headers = false;
    self.send_window = send_window;
    self.blocked = false;
    self.end_after_queue = false;
    self.front_sent = 0;
    self.owned.clear();
    self.owned_read = 0;
    self.recv_unacked = 0;
    self.send_queue.clear();
    self.status = None;
    self.trailers = None;
  }
}

/// Stream id → slot. Open addressing on `id >> 1` with linear probing and backward-shift
/// deletion: a peer's ids are consecutive odd (or even) numbers, so open streams land in
/// consecutive buckets and a lookup is usually one probe. Key 0 marks an empty bucket (stream 0
/// is the connection). It allocates only to grow.
#[derive(Debug)]
struct IdIndex {
  /// (stream id, slot) pairs; the length is 0 or a power of two.
  entries: VectorUsize<(u32, u32)>,
  len: usize,
  /// The farthest any entry was placed from its home bucket since the last growth. A removal
  /// only looks that far for entries to shift back: live ids are consecutive and sit in one long
  /// run of filled buckets, nearly all at home, and scanning the run to its end made each
  /// removal linear.
  max_displacement: usize,
}

impl IdIndex {
  const fn new() -> Self {
    Self { entries: VectorUsize::new(), len: 0, max_displacement: 0 }
  }

  #[inline]
  fn get(&self, id: u32) -> Option<usize> {
    if self.len == 0 {
      return None;
    }
    let entries = self.entries.as_slice();
    let mask = entries.len().wrapping_sub(1);
    let mut idx = (id >> 1) as usize & mask;
    loop {
      // SAFETY: `idx & mask < entries.len()`, a power of two
      let (key, slot) = unsafe { *entries.get_unchecked(idx) };
      if key == id {
        return Some(slot as usize);
      }
      if key == 0 {
        return None;
      }
      idx = idx.wrapping_add(1) & mask;
    }
  }

  fn insert(&mut self, id: u32, slot: usize) -> crate::Result<()> {
    if self.len.wrapping_add(1).wrapping_mul(2) > self.entries.len() {
      self.grow()?;
    }
    let entries = self.entries.as_slice_mut();
    let mask = entries.len().wrapping_sub(1);
    let home = (id >> 1) as usize & mask;
    let mut idx = home;
    loop {
      let Some(entry) = entries.get_mut(idx) else {
        return Err(crate::Error::ProgrammingError);
      };
      if entry.0 == 0 || entry.0 == id {
        if entry.0 == 0 {
          self.len = self.len.wrapping_add(1);
        }
        *entry = (id, u32::try_from(slot).unwrap_or(u32::MAX));
        self.max_displacement = self.max_displacement.max(idx.wrapping_sub(home) & mask);
        return Ok(());
      }
      idx = idx.wrapping_add(1) & mask;
    }
  }

  fn remove(&mut self, id: u32) -> Option<usize> {
    if self.len == 0 {
      return None;
    }
    let entries = self.entries.as_slice_mut();
    let mask = entries.len().wrapping_sub(1);
    let mut hole = (id >> 1) as usize & mask;
    loop {
      let (key, _) = *entries.get(hole)?;
      if key == id {
        break;
      }
      if key == 0 {
        return None;
      }
      hole = hole.wrapping_add(1) & mask;
    }
    let slot = entries.get(hole).map(|el| el.1 as usize);
    // Backward shift: later members of the probe run move into the hole unless their home
    // bucket lies (cyclically) after the hole. One more than `max_displacement` past the hole,
    // every home does.
    let mut next = hole;
    let mut distance: usize = 0;
    loop {
      next = next.wrapping_add(1) & mask;
      distance = distance.wrapping_add(1);
      if distance > self.max_displacement {
        break;
      }
      let moved = entries.get(next).copied().unwrap_or_default();
      if moved.0 == 0 {
        break;
      }
      let home = (moved.0 >> 1) as usize & mask;
      let stays = if hole <= next { hole < home && home <= next } else { hole < home || home <= next };
      if stays {
        continue;
      }
      if let Some(elem) = entries.get_mut(hole) {
        *elem = moved;
      }
      hole = next;
      distance = 0;
    }
    if let Some(elem) = entries.get_mut(hole) {
      *elem = (0, 0);
    }
    self.len = self.len.wrapping_sub(1);
    slot
  }

  #[cold]
  fn grow(&mut self) -> crate::Result<()> {
    let capacity = self.entries.len().wrapping_mul(2).max(64);
    let old = core::mem::replace(&mut self.entries, VectorUsize::from_cloneable_elem(capacity, (0, 0))?);
    self.len = 0;
    self.max_displacement = 0;
    for (key, slot) in old.iter() {
      if *key != 0 {
        self.insert(*key, *slot as usize)?;
      }
    }
    Ok(())
  }
}

/// Open streams by id. Freed slots keep their buffers for reuse.
#[derive(Debug)]
pub(crate) struct StreamTable {
  /// Body bytes received on open streams.
  buffered: usize,
  free: VectorUsize<usize>,
  ids: IdIndex,
  /// Body bytes queued on open streams and not yet sent.
  queued: usize,
  slots: VectorUsize<Stream>,
}

impl StreamTable {
  pub(crate) fn new() -> Self {
    Self {
      buffered: 0,
      free: VectorUsize::new(),
      ids: IdIndex::new(),
      queued: 0,
      slots: VectorUsize::new(),
    }
  }

  /// Body bytes received on open streams.
  pub(crate) const fn buffered(&self) -> usize {
    self.buffered
  }

  /// Body bytes queued on open streams and not yet sent, not counting shared ones.
  pub(crate) const fn queued(&self) -> usize {
    self.queued
  }

  pub(crate) const fn add_buffered(&mut self, n: usize) {
    self.buffered = self.buffered.wrapping_add(n);
  }

  pub(crate) const fn add_queued(&mut self, n: usize) {
    self.queued = self.queued.wrapping_add(n);
  }

  pub(crate) const fn sub_queued(&mut self, n: usize) {
    self.queued = self.queued.saturating_sub(n);
  }

  /// Number of open streams.
  pub(crate) const fn len(&self) -> usize {
    self.ids.len
  }

  pub(crate) fn get(&self, id: u32) -> Option<&Stream> {
    let idx = self.ids.get(id)?;
    self.slots.get(idx)
  }

  pub(crate) fn get_mut(&mut self, id: u32) -> Option<&mut Stream> {
    let idx = self.ids.get(id)?;
    self.slots.get_mut(idx)
  }

  /// Opens stream `id` in a free slot, or a new one.
  pub(crate) fn open(
    &mut self,
    id: u32,
    recv_window: i32,
    send_window: i32,
  ) -> crate::Result<&mut Stream> {
    let idx = if let Some(idx) = self.free.pop() {
      idx
    } else {
      self.slots.push(Stream::new())?;
      self.slots.len().wrapping_sub(1)
    };
    self.ids.insert(id, idx)?;
    let stream = self.slots.get_mut(idx).ok_or(crate::Error::ProgrammingError)?;
    stream.reset(id, recv_window, send_window);
    stream.live = true;
    Ok(stream)
  }

  /// Closes stream `id`, keeping its slot's buffers for the next stream.
  pub(crate) fn close(&mut self, id: u32) -> bool {
    let Some(idx) = self.ids.remove(id) else {
      return false;
    };
    if let Some(stream) = self.slots.get_mut(idx) {
      stream.live = false;
      self.buffered = self.buffered.saturating_sub(stream.recv_body_len);
      self.queued = self.queued.saturating_sub(stream.send_pending_owned());
      stream.msg.clear();
      stream.owned.clear();
      stream.send_queue.clear();
      stream.trailers = None;
    }
    let _rslt = self.free.push(idx);
    true
  }

  /// Every open stream.
  pub(crate) fn iter(&self) -> impl Iterator<Item = &Stream> {
    self.slots.iter().filter(|el| el.live)
  }

  /// Every open stream.
  pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Stream> {
    self.slots.iter_mut().filter(|el| el.live)
  }
}

#[cfg(test)]
mod tests {
  use super::IdIndex;
  use crate::rng::{Rng as _, Xorshift64};
  use std::collections::HashMap;

  // Random inserts and removes, with ids that collide modulo the table size, agree with a map.
  #[test]
  fn id_index_matches_a_map() {
    let mut rng = Xorshift64::from(17u64);
    let mut index = IdIndex::new();
    let mut model = HashMap::new();
    for step in 0..200_000u32 {
      let pick = u32::from_le_bytes(rng.u8_4());
      // Small odd ids, plus ids 128 apart to force probe runs that wrap.
      let id = if pick % 3 == 0 { 1 + 2 * (pick % 300) } else { 1 + 128 * (pick % 40) };
      if pick % 2 == 0 {
        index.insert(id, step as usize).unwrap();
        let _ = model.insert(id, step as usize);
      } else {
        assert_eq!(index.remove(id), model.remove(&id), "remove {id}");
      }
      assert_eq!(index.len, model.len());
      if step % 1000 == 0 {
        for (key, value) in &model {
          assert_eq!(index.get(*key), Some(*value));
        }
      }
    }
  }
}
