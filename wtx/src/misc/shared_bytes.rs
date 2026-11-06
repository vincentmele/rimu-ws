use crate::sync::Arc;
use alloc::boxed::Box;

/// A shared, immutable byte buffer and a range of it. An HTTP/2 connection queues it without
/// copying: the I/O loop writes straight from it. Clones share the buffer.
#[derive(Clone, Debug)]
pub struct SharedBytes {
  bytes: Arc<[u8]>,
  end: usize,
  start: usize,
}

impl SharedBytes {
  /// All of `bytes`.
  #[inline]
  pub fn new(bytes: Arc<[u8]>) -> Self {
    let end = bytes.len();
    Self { bytes, end, start: 0 }
  }

  /// Copies `bytes` into a new shared buffer.
  #[inline]
  pub fn from_slice(bytes: &[u8]) -> Self {
    Self::new(Arc::from(Box::<[u8]>::from(bytes)))
  }

  /// The bytes in `start..end` of this range, clamped to it.
  #[inline]
  pub fn slice(&self, start: usize, end: usize) -> Self {
    let new_end = self.start.saturating_add(end).min(self.end);
    let new_start = self.start.saturating_add(start).min(new_end);
    Self { bytes: self.bytes.clone(), end: new_end, start: new_start }
  }

  /// The bytes of the range.
  #[inline]
  pub fn as_slice(&self) -> &[u8] {
    self.bytes.get(self.start..self.end).unwrap_or_default()
  }

  /// Length of the range.
  #[inline]
  pub fn len(&self) -> usize {
    self.end.wrapping_sub(self.start)
  }

  /// If the range is empty.
  #[inline]
  pub fn is_empty(&self) -> bool {
    self.start == self.end
  }
}
