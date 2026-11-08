//! Variable-length integers (RFC 9000 section 16).

use core::hint::cold_path;

/// The largest value that a variable-length integer can hold: 2^62 - 1.
pub(crate) const VARINT_MAX: u64 = (1 << 62) - 1;

/// Decodes the variable-length integer at the start of `bytes`.
///
/// Returns the value and the number of bytes that it takes, or `None` if `bytes` is too short.
/// Longer encodings than necessary are valid.
#[inline]
pub(crate) fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
  let first = *bytes.first()?;
  // The two most significant bits are the base 2 logarithm of the length
  let len = 1usize << (first >> 6);
  let bits = len.wrapping_mul(8);
  let raw = if let Some(chunk) = bytes.first_chunk::<8>() {
    // The whole encoding is in the first eight bytes, so a single load is enough
    u64::from_be_bytes(*chunk) >> 64usize.wrapping_sub(bits)
  } else {
    let Some(head) = bytes.get(..len) else {
      cold_path();
      return None;
    };
    head.iter().fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte))
  };
  Some((raw & (1u64 << bits.wrapping_sub(2)).wrapping_sub(1), len))
}

/// Writes `value` at the start of `out` using the shortest encoding.
///
/// Returns the number of written bytes, or `None` if `value` is larger than [`VARINT_MAX`] or
/// `out` is too small.
#[inline]
pub(crate) fn encode_varint(value: u64, out: &mut [u8]) -> Option<usize> {
  if value > VARINT_MAX {
    cold_path();
    return None;
  }
  let len = varint_len(value);
  let Some(dst) = out.get_mut(..len) else {
    cold_path();
    return None;
  };
  let tagged = value | (u64::from(len.trailing_zeros()) << len.wrapping_mul(8).wrapping_sub(2));
  dst.copy_from_slice(tagged.to_be_bytes().get(8usize.wrapping_sub(len)..)?);
  Some(len)
}

/// The number of bytes that the shortest encoding of `value` takes.
///
/// Values larger than [`VARINT_MAX`] have no encoding, they yield eight.
#[inline]
pub(crate) const fn varint_len(value: u64) -> usize {
  if value < 1 << 6 {
    1
  } else if value < 1 << 14 {
    2
  } else if value < 1 << 30 {
    4
  } else {
    8
  }
}

#[cfg(test)]
mod tests {
  use crate::quic::varint::{VARINT_MAX, decode_varint, encode_varint, varint_len};

  #[test]
  fn varint_rfc9000_a1_examples() {
    let cases: [(&[u8], u64); 4] = [
      (&hexd!(b"c2197c5eff14e88c"), 151_288_809_941_952_652),
      (&hexd!(b"9d7f3e7d"), 494_878_333),
      (&hexd!(b"7bbd"), 15_293),
      (&hexd!(b"25"), 37),
    ];
    for (bytes, value) in cases {
      assert_eq!(decode_varint(bytes), Some((value, bytes.len())));
      assert_eq!(varint_len(value), bytes.len());
      let mut out = [0; 8];
      let len = encode_varint(value, &mut out).unwrap();
      assert_eq!(&out[..len], bytes);
    }
    // A value may be encoded with more bytes than needed
    assert_eq!(decode_varint(&hexd!(b"4025")), Some((37, 2)));
    assert_eq!(decode_varint(&hexd!(b"c000000000000025")), Some((37, 8)));
  }

  #[test]
  fn varint_bounds() {
    let mut out = [0; 8];
    assert_eq!(encode_varint(VARINT_MAX, &mut out), Some(8));
    assert_eq!(decode_varint(&out), Some((VARINT_MAX, 8)));
    assert_eq!(encode_varint(VARINT_MAX + 1, &mut out), None);
    assert_eq!(encode_varint(1 << 62, &mut out), None);
    assert_eq!(encode_varint(u64::MAX, &mut out), None);
    for (value, len) in [
      (0, 1),
      (63, 1),
      (64, 2),
      (16_383, 2),
      (16_384, 4),
      ((1 << 30) - 1, 4),
      (1 << 30, 8),
      (VARINT_MAX, 8),
    ] {
      assert_eq!(varint_len(value), len);
      assert_eq!(encode_varint(value, &mut out), Some(len));
      assert_eq!(decode_varint(&out), Some((value, len)));
      // Exactly the needed bytes
      assert_eq!(decode_varint(&out[..len]), Some((value, len)));
      // One byte less
      assert_eq!(decode_varint(&out[..len - 1]), None);
    }
  }

  #[test]
  fn varint_rejects_short_buffers() {
    assert_eq!(decode_varint(&[]), None);
    assert_eq!(decode_varint(&hexd!(b"7b")), None);
    assert_eq!(decode_varint(&hexd!(b"9d7f3e")), None);
    assert_eq!(decode_varint(&hexd!(b"c2197c5eff14e8")), None);
    let mut one = [0; 1];
    assert_eq!(encode_varint(15_293, &mut one), None);
    assert_eq!(encode_varint(37, &mut []), None);
    assert_eq!(encode_varint(37, &mut one), Some(1));
  }

  #[test]
  fn varint_ignores_trailing_bytes() {
    let mut bytes = [0xff; 12];
    bytes[0] = 0x25;
    assert_eq!(decode_varint(&bytes), Some((37, 1)));
    bytes[..2].copy_from_slice(&hexd!(b"7bbd"));
    assert_eq!(decode_varint(&bytes), Some((15_293, 2)));
  }

  #[test]
  fn varint_round_trips_every_length() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut out = [0; 8];
    for _ in 0..10_000 {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      let value = (state >> (state % 64)) & VARINT_MAX;
      let len = encode_varint(value, &mut out).unwrap();
      assert_eq!(len, varint_len(value));
      assert_eq!(decode_varint(&out), Some((value, len)));
      assert_eq!(decode_varint(&out[..len]), Some((value, len)));
    }
  }
}
