use alloc::vec::Vec;

/// Writes DEFLATE's LSB-first bit stream into a byte vector: a 64-bit accumulator flushed four
/// bytes at a time, so a `put` of up to 32 bits never overflows it.
pub(crate) struct BitWriter<'out> {
  acc: u64,
  bits: u32,
  out: &'out mut Vec<u8>,
}

impl<'out> BitWriter<'out> {
  pub(crate) fn new(out: &'out mut Vec<u8>) -> Self {
    Self { acc: 0, bits: 0, out }
  }

  /// Bits written so far, counting those still in the accumulator.
  pub(crate) fn position(&self) -> u64 {
    u64::try_from(self.out.len()).unwrap_or(u64::MAX).wrapping_mul(8).wrapping_add(self.bits.into())
  }

  /// Appends the low `n` bits of `value` (`n` ≤ 32, higher bits of `value` zero).
  #[inline]
  pub(crate) fn put(&mut self, value: u32, n: u32) {
    debug_assert!(n <= 32 && (n == 32 || value >> n == 0));
    self.acc |= u64::from(value) << self.bits;
    self.bits += n;
    if self.bits >= 32 {
      self.out.extend_from_slice(&(self.acc as u32).to_le_bytes());
      self.acc >>= 32;
      self.bits -= 32;
    }
  }

  /// Pads with zero bits to the next byte boundary and moves every whole byte to the output.
  pub(crate) fn align(&mut self) {
    let pad = (8 - self.bits % 8) % 8;
    self.bits += pad;
    while self.bits >= 8 {
      self.out.push(self.acc as u8);
      self.acc >>= 8;
      self.bits -= 8;
    }
  }

  /// Bytes appended unaligned to the output; the stream must be byte-aligned.
  pub(crate) fn bytes(&mut self, bytes: &[u8]) {
    debug_assert_eq!(self.bits, 0);
    self.out.extend_from_slice(bytes);
  }

  /// Pads the last byte and returns the output.
  pub(crate) fn finish(mut self) -> &'out mut Vec<u8> {
    self.align();
    self.out
  }
}
