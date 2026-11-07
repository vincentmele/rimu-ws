//! The bytes a connection has queued for its peer, in order.

use crate::{
  collections::{ArrayVectorCopy, DequeUsize, VectorUsize},
  http2::conn::body::SharedBytes,
};
use alloc::vec::Vec;
use core::mem;

/// One run of queued bytes.
#[derive(Debug)]
enum Chunk {
  /// Encoded frames in `Output::bytes[start..end]`.
  Own { end: usize, start: usize },
  /// Bytes sent by reference.
  Shared(SharedBytes),
}

impl Chunk {
  fn len(&self) -> usize {
    match self {
      Self::Own { end, start } => end.wrapping_sub(*start),
      Self::Shared(elem) => elem.len(),
    }
  }
}

/// Encoded frames waiting to be written.
#[derive(Debug)]
pub(crate) struct Output {
  bytes: VectorUsize<u8>,
  chunks: DequeUsize<Chunk>,
  /// Bytes of the front chunk already written.
  front_written: usize,
  /// Bytes queued and not yet written.
  pending: usize,
  /// Of `pending`, the bytes queued by reference.
  shared: usize,
}

impl Output {
  pub(crate) const fn new() -> Self {
    Self {
      bytes: VectorUsize::new(),
      chunks: DequeUsize::new(),
      front_written: 0,
      pending: 0,
      shared: 0,
    }
  }

  /// Bytes queued and not yet written that the output holds itself: not those queued by
  /// reference, whose memory belongs to their owner.
  pub(crate) const fn owned_len(&self) -> usize {
    self.pending.wrapping_sub(self.shared)
  }

  pub(crate) const fn is_empty(&self) -> bool {
    self.pending == 0
  }

  /// Queues `bytes` after everything already queued.
  pub(crate) fn push(&mut self, bytes: &[u8]) -> crate::Result<()> {
    self.push_many(&[bytes])
  }

  /// Queues every slice of `parts`, in order.
  pub(crate) fn push_many(&mut self, parts: &[&[u8]]) -> crate::Result<()> {
    let start = self.bytes.len();
    let added = self.bytes.extend_from_copyable_slices(parts.iter().copied())?;
    if added == 0 {
      return Ok(());
    }
    let end = self.bytes.len();
    if let Some(Chunk::Own { end: last_end, .. }) = self.chunks.last_mut()
      && *last_end == start
    {
      *last_end = end;
      self.pending = self.pending.wrapping_add(added);
      return Ok(());
    }
    self.chunks.push_back(Chunk::Own { end, start })?;
    self.pending = self.pending.wrapping_add(added);
    Ok(())
  }

  /// Queues `bytes` by reference.
  pub(crate) fn push_shared(&mut self, bytes: SharedBytes) -> crate::Result<()> {
    if bytes.is_empty() {
      return Ok(());
    }
    self.pending = self.pending.wrapping_add(bytes.len());
    self.shared = self.shared.wrapping_add(bytes.len());
    self.chunks.push_back(Chunk::Shared(bytes))?;
    Ok(())
  }

  /// The queued bytes, front first, as many slices as fit in `out`.
  pub(crate) fn slices<'this>(&'this self, out: &mut ArrayVectorCopy<&'this [u8], 16>) {
    let mut skip = self.front_written;
    for chunk in self.chunks.iter() {
      let slice = match chunk {
        Chunk::Own { end, start } => self.bytes.get(start.wrapping_add(skip)..*end),
        Chunk::Shared(elem) => elem.as_slice().get(skip..),
      };
      skip = 0;
      if let Some(elem) = slice
        && !elem.is_empty()
        && out.push(elem).is_err()
      {
        return;
      }
    }
  }

  /// Takes the queued bytes as one buffer when they are a single unwritten run of own bytes (the
  /// usual case), leaving `spare`, cleared, in its place. Otherwise returns `spare`.
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn take_bytes(&mut self, spare: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
    let whole = matches!(
      (self.chunks.len(), self.chunks.get(0)),
      (1, Some(Chunk::Own { start: 0, end })) if *end == self.bytes.len()
    );
    if !whole || self.front_written != 0 {
      return Err(spare);
    }
    let mut spare_vec = spare;
    spare_vec.clear();
    let Ok(replacement) = VectorUsize::from_vec(spare_vec) else {
      return Err(Vec::new());
    };
    let bytes = mem::replace(&mut self.bytes, replacement).into_vec();
    self.chunks.clear();
    self.pending = 0;
    Ok(bytes)
  }

  /// Puts back the bytes [`Self::take_bytes`] took, with nothing queued since; returns the spare.
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn untake_bytes(&mut self, bytes: Vec<u8>) -> Vec<u8> {
    let len = bytes.len();
    let Ok(restored) = VectorUsize::from_vec(bytes) else {
      return Vec::new();
    };
    let spare = mem::replace(&mut self.bytes, restored).into_vec();
    self.chunks.clear();
    let _rslt = self.chunks.push_back(Chunk::Own { end: len, start: 0 });
    self.pending = len;
    self.front_written = 0;
    spare
  }

  /// Writes the next bytes into `buffer` (cleared) when nothing is queued and the current buffer
  /// holds no memory: a recycled, cache-warm buffer instead of a fresh allocation.
  #[cfg_attr(
    not(feature = "http2-server-framework"),
    allow(dead_code, reason = "used by the server driver")
  )]
  pub(crate) fn give_buffer(&mut self, buffer: Vec<u8>) {
    if self.pending != 0 || self.bytes.capacity() != 0 {
      return;
    }
    let mut buffer = buffer;
    buffer.clear();
    if let Ok(elem) = VectorUsize::from_vec(buffer) {
      self.bytes = elem;
    }
  }

  /// The buffer, empty, when nothing is queued: an idle connection need not hold one.
  pub(crate) fn take_idle_buffer(&mut self) -> Option<Vec<u8>> {
    if self.pending != 0 || self.bytes.capacity() == 0 {
      return None;
    }
    let mut buffer = mem::take(&mut self.bytes).into_vec();
    buffer.clear();
    self.chunks.clear();
    self.front_written = 0;
    Some(buffer)
  }

  /// Whether output would go into a buffer the output already holds.
  pub(crate) fn has_buffer(&self) -> bool {
    self.bytes.capacity() != 0
  }

  /// Marks the first `n` queued bytes as written.
  pub(crate) fn advance(&mut self, mut n: usize) {
    n = n.min(self.pending);
    self.pending = self.pending.wrapping_sub(n);
    while n > 0 {
      let Some(chunk) = self.chunks.get(0) else {
        break;
      };
      let left = chunk.len().wrapping_sub(self.front_written);
      if let Chunk::Shared(_) = chunk {
        self.shared = self.shared.saturating_sub(n.min(left));
      }
      if n < left {
        self.front_written = self.front_written.wrapping_add(n);
        break;
      }
      n = n.wrapping_sub(left);
      let _ = self.chunks.pop_front();
      self.front_written = 0;
    }
    if self.pending == 0 {
      self.bytes.clear();
      self.chunks.clear();
      self.front_written = 0;
      self.shared = 0;
    } else {
      self.compact();
    }
  }

  /// Drops the written front of `bytes` once it is most of the buffer: output that never drains
  /// all at once (a handler streaming to a slow reader) would otherwise keep every byte it wrote.
  fn compact(&mut self) {
    // The written part of an own front chunk is dropped with the rest.
    if let Some(Chunk::Own { start, .. }) = self.chunks.get_mut(0) {
      *start = start.wrapping_add(self.front_written);
      self.front_written = 0;
    }
    let Some(lo) = self.chunks.iter().find_map(|el| match el {
      Chunk::Own { start, .. } => Some(*start),
      Chunk::Shared(_) => None,
    }) else {
      self.bytes.clear();
      return;
    };
    let len = self.bytes.len();
    if lo < COMPACT_MIN || lo < len / 2 {
      return;
    }
    self.bytes.as_slice_mut().copy_within(lo..len, 0);
    self.bytes.truncate(len.wrapping_sub(lo));
    for chunk in self.chunks.iter_mut() {
      if let Chunk::Own { end, start } = chunk {
        *start = start.wrapping_sub(lo);
        *end = end.wrapping_sub(lo);
      }
    }
  }
}

/// Written bytes `Output::compact` leaves in place: moving fewer costs more than it frees.
const COMPACT_MIN: usize = 64 * 1024;

#[cfg(test)]
mod tests {
  use crate::http2::conn::output::Output;

  // Output that is written as fast as it is queued, but never all at once, keeps a bounded buffer:
  // the written front is dropped instead of piling up until the output drains.
  #[test]
  fn output_never_drained_stays_bounded() {
    let mut out = Output::new();
    out.push(&[1; 1024]).unwrap();
    for _ in 0..1024 {
      out.push(&[2; 1024]).unwrap();
      out.advance(1024);
    }
    assert_eq!(out.owned_len(), 1024);
    assert!(out.bytes.len() <= 256 * 1024, "{} bytes held for 1 KiB queued", out.bytes.len());
  }
}
