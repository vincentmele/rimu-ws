//! Response bodies the connection core sends: borrowed bytes it copies, or shared bytes it sends
//! by reference.

use crate::sync::Arc;
use alloc::boxed::Box;

/// A shared, immutable byte buffer and a range of it. The connection queues it without copying:
/// the I/O loop writes straight from it.
#[derive(Clone, Debug)]
pub(crate) struct SharedBytes {
  bytes: Arc<[u8]>,
  end: usize,
  start: usize,
}

impl SharedBytes {
  /// All of `bytes`.
  pub(crate) fn new(bytes: Arc<[u8]>) -> Self {
    let end = bytes.len();
    Self { bytes, end, start: 0 }
  }

  /// Copies `bytes` into a new shared buffer.
  pub(crate) fn from_slice(bytes: &[u8]) -> Self {
    Self::new(Arc::from(Box::<[u8]>::from(bytes)))
  }

  /// The bytes in `start..end` of this range, clamped to it.
  pub(crate) fn slice(&self, start: usize, end: usize) -> Self {
    let new_end = self.start.saturating_add(end).min(self.end);
    let new_start = self.start.saturating_add(start).min(new_end);
    Self { bytes: self.bytes.clone(), end: new_end, start: new_start }
  }

  pub(crate) fn as_slice(&self) -> &[u8] {
    self.bytes.get(self.start..self.end).unwrap_or_default()
  }

  pub(crate) fn len(&self) -> usize {
    self.end.wrapping_sub(self.start)
  }

  pub(crate) fn is_empty(&self) -> bool {
    self.start == self.end
  }
}

/// A body for [`super::Http2Conn::send_data`].
#[derive(Debug)]
pub(crate) enum Body<'any> {
  /// Copied into the connection's buffers.
  Borrowed(&'any [u8]),
  /// Queued by reference.
  Shared(SharedBytes),
}
