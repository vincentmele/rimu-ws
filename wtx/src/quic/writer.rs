//! A bounds-checked writer over a buffer of the caller, shared by every QUIC encoder.

use crate::quic::{
  QuicError,
  varint::{VARINT_MAX, encode_varint, varint_len},
};
use core::hint::cold_path;

/// Appends bytes to a buffer and never writes outside of it.
///
/// An operation that does not fit, or a value that a variable-length integer cannot hold, fails
/// with a [`crate::Error::Quic`] and writes nothing. The position only moves past what was
/// written.
#[derive(Debug)]
pub(crate) struct Writer<'out> {
  out: &'out mut [u8],
  pos: usize,
}

impl<'out> Writer<'out> {
  /// Starts at the beginning of `out`.
  #[inline]
  pub(crate) const fn new(out: &'out mut [u8]) -> Self {
    Self { out, pos: 0 }
  }

  /// Starts `pos` bytes after the beginning of `out`.
  #[inline]
  pub(crate) const fn at(out: &'out mut [u8], pos: usize) -> Self {
    Self { out, pos }
  }

  /// Replaces the byte at `at`, which must have been written already, with the shortest encoding
  /// of `value`. The bytes after it move forward if the encoding takes more than one byte.
  ///
  /// This allows writing a count that is only known after its elements. Fails without changes if
  /// the longer encoding does not fit.
  #[inline]
  pub(crate) fn expand_byte_into_varint(&mut self, at: usize, value: u64) -> crate::Result<()> {
    if value > VARINT_MAX {
      return Err(error(QuicError::VarintOverflow));
    }
    if at >= self.pos {
      return Err(error(QuicError::Truncated));
    }
    let extra = varint_len(value).wrapping_sub(1);
    let new_pos = self.pos.wrapping_add(extra);
    let Some(window) = self.out.get_mut(at..new_pos) else {
      return Err(error(QuicError::BufferTooSmall));
    };
    // `window` is the byte to replace, the bytes after it and room for the extra ones
    let tail_len = self.pos.wrapping_sub(at).wrapping_sub(1);
    window.copy_within(1..tail_len.wrapping_add(1), extra.wrapping_add(1));
    if encode_varint(value, window).is_none() {
      return Err(error(QuicError::BufferTooSmall));
    }
    self.pos = new_pos;
    Ok(())
  }

  /// The number of bytes that can still be written.
  #[inline]
  pub(crate) const fn remaining(&self) -> usize {
    self.out.len().saturating_sub(self.pos)
  }

  /// Forgets what was written after `pos`. Does nothing if `pos` is not before the current one.
  #[inline]
  pub(crate) const fn rewind(&mut self, pos: usize) {
    if pos < self.pos {
      self.pos = pos;
    }
  }

  /// The number of bytes written, that is, the position of the next write.
  #[inline]
  pub(crate) const fn pos(&self) -> usize {
    self.pos
  }

  /// Writes `bytes`.
  #[inline]
  pub(crate) fn put(&mut self, bytes: &[u8]) -> crate::Result<()> {
    let end = self.pos.wrapping_add(bytes.len());
    let Some(dst) = self.out.get_mut(self.pos..end) else {
      return Err(error(QuicError::BufferTooSmall));
    };
    dst.copy_from_slice(bytes);
    self.pos = end;
    Ok(())
  }

  /// Writes a single byte.
  #[inline]
  pub(crate) fn put_u8(&mut self, byte: u8) -> crate::Result<()> {
    let Some(dst) = self.out.get_mut(self.pos) else {
      return Err(error(QuicError::BufferTooSmall));
    };
    *dst = byte;
    self.pos = self.pos.wrapping_add(1);
    Ok(())
  }

  /// Writes the shortest encoding of `value`.
  #[inline]
  pub(crate) fn varint(&mut self, value: u64) -> crate::Result<()> {
    if value > VARINT_MAX {
      return Err(error(QuicError::VarintOverflow));
    }
    let Some(len) = self.out.get_mut(self.pos..).and_then(|dst| encode_varint(value, dst)) else {
      return Err(error(QuicError::BufferTooSmall));
    };
    self.pos = self.pos.wrapping_add(len);
    Ok(())
  }

  /// What was written so far.
  #[inline]
  pub(crate) fn written(&self) -> &[u8] {
    self.out.get(..self.pos).unwrap_or_default()
  }

  /// Writes `len` zeros. The buffer is not assumed to be zeroed.
  #[inline]
  pub(crate) fn zeros(&mut self, len: usize) -> crate::Result<()> {
    let end = self.pos.wrapping_add(len);
    let Some(dst) = self.out.get_mut(self.pos..end) else {
      return Err(error(QuicError::BufferTooSmall));
    };
    dst.fill(0);
    self.pos = end;
    Ok(())
  }
}

#[inline(always)]
fn error(kind: QuicError) -> crate::Error {
  cold_path();
  kind.into()
}

#[cfg(test)]
mod tests {
  use crate::{
    Error,
    quic::{QuicError, VARINT_MAX, decode_varint, writer::Writer},
  };

  #[test]
  fn writes_are_all_or_nothing() {
    let mut out = [0xaa; 4];
    let mut writer = Writer::new(&mut out);
    writer.put(&[1, 2, 3]).unwrap();
    assert!(matches!(writer.put(&[4, 5]), Err(Error::Quic(QuicError::BufferTooSmall))));
    assert!(matches!(writer.zeros(2), Err(Error::Quic(QuicError::BufferTooSmall))));
    assert!(matches!(writer.varint(15_293), Err(Error::Quic(QuicError::BufferTooSmall))));
    assert!(matches!(writer.varint(VARINT_MAX + 1), Err(Error::Quic(QuicError::VarintOverflow))));
    assert_eq!((writer.pos(), writer.remaining()), (3, 1));
    writer.put_u8(4).unwrap();
    assert!(matches!(writer.put_u8(5), Err(Error::Quic(QuicError::BufferTooSmall))));
    assert_eq!(writer.written(), &[1, 2, 3, 4]);
    assert_eq!(writer.remaining(), 0);
    assert_eq!(out, [1, 2, 3, 4]);
  }

  #[test]
  fn at_and_rewind_move_the_position() {
    let mut out = [0xaa; 8];
    let mut writer = Writer::at(&mut out, 6);
    assert_eq!(writer.remaining(), 2);
    writer.put(&[1, 2]).unwrap();
    writer.rewind(7);
    assert_eq!(writer.pos(), 7);
    // Rewinding forward is ignored
    writer.rewind(8);
    assert_eq!(writer.pos(), 7);
    writer.put_u8(3).unwrap();
    assert_eq!(out, [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 1, 3]);
    // Starting past the end leaves nothing to write
    let mut writer = Writer::at(&mut out, 9);
    assert_eq!(writer.remaining(), 0);
    assert!(writer.put(&[]).is_err());
    assert!(writer.put_u8(0).is_err());
  }

  #[test]
  fn zeros_overwrite_old_content() {
    let mut out = [0xaa; 5];
    let mut writer = Writer::new(&mut out);
    writer.put_u8(1).unwrap();
    writer.zeros(3).unwrap();
    assert_eq!(out, [1, 0, 0, 0, 0xaa]);
  }

  #[test]
  fn count_grows_to_the_length_that_it_needs() {
    for (value, len) in [(0u64, 1usize), (63, 1), (64, 2), (16_383, 2), (16_384, 4), (1 << 30, 8)] {
      let mut out = [0xaa; 32];
      let mut writer = Writer::new(&mut out);
      writer.put_u8(7).unwrap();
      let at = writer.pos();
      writer.put_u8(0).unwrap();
      writer.put(&[1, 2, 3]).unwrap();
      writer.expand_byte_into_varint(at, value).unwrap();
      assert_eq!(writer.pos(), 1 + len + 3);
      let written = writer.written();
      assert_eq!(written.first(), Some(&7));
      assert_eq!(decode_varint(&written[1..]), Some((value, len)));
      assert_eq!(&written[1 + len..], &[1, 2, 3]);
    }
  }

  #[test]
  fn count_that_does_not_fit_changes_nothing() {
    // One byte of room is just enough for a two-byte count
    let mut out = [0xaa; 6];
    let mut writer = Writer::new(&mut out);
    writer.put(&[0, 1, 2, 3, 4]).unwrap();
    writer.expand_byte_into_varint(0, 64).unwrap();
    assert_eq!(writer.written(), &[0x40, 0x40, 1, 2, 3, 4]);
    let mut out = [0xaa; 6];
    let mut writer = Writer::new(&mut out);
    writer.put(&[0, 1, 2, 3, 4]).unwrap();
    assert!(matches!(
      writer.expand_byte_into_varint(0, 16_384),
      Err(Error::Quic(QuicError::BufferTooSmall))
    ));
    assert!(matches!(
      writer.expand_byte_into_varint(0, VARINT_MAX + 1),
      Err(Error::Quic(QuicError::VarintOverflow))
    ));
    // The byte to replace must have been written
    assert!(writer.expand_byte_into_varint(5, 1).is_err());
    assert_eq!(writer.written(), &[0, 1, 2, 3, 4]);
  }
}
