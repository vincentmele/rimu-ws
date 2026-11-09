//! Prefixed integers (RFC 7541 section 5.1), which QPACK uses unmodified with more prefix sizes
//! (RFC 9204 section 4.1.1).
//!
//! HPACK keeps its own copy for now: switching it to this one changes the HTTP/2 hot path.

use crate::http3::Http3Error;
use core::hint::cold_path;

/// The largest value that QPACK decodes: 62 bits (RFC 9204 section 4.1.1).
pub(crate) const PREFIX_INT_MAX: u64 = (1 << 62) - 1;

/// Writes `value` at the start of `out` with a prefix of `prefix_bits` bits (1 to 8). The bits of
/// the first byte above the prefix are those of `flags`.
///
/// Returns the number of written bytes, or `None` if `out` is too small (it may then be partly
/// written), `value` is larger than [`PREFIX_INT_MAX`] or `prefix_bits` is not in `1..=8`.
#[inline]
pub(crate) fn encode_prefix_int(
  value: u64,
  prefix_bits: u8,
  flags: u8,
  out: &mut [u8],
) -> Option<usize> {
  let mask = prefix_mask(prefix_bits)?;
  if value > PREFIX_INT_MAX {
    cold_path();
    return None;
  }
  let (first, rest) = out.split_first_mut()?;
  let flags = flags & !mask;
  if value < u64::from(mask) {
    *first = flags | u8::try_from(value).ok()?;
    return Some(1);
  }
  *first = flags | mask;
  let mut remaining = value.wrapping_sub(u64::from(mask));
  let mut len = 1usize;
  for byte in rest {
    len = len.wrapping_add(1);
    let low = u8::try_from(remaining & 0b0111_1111).ok()?;
    remaining >>= 7;
    if remaining == 0 {
      *byte = low;
      return Some(len);
    }
    *byte = low | 0b1000_0000;
  }
  cold_path();
  None
}

/// Reads the integer at the start of `bytes`, whose first byte holds a prefix of `prefix_bits`
/// bits (1 to 8).
///
/// Returns the value and the number of bytes that it takes, or `None` if `bytes` ends before it
/// does. Values larger than [`PREFIX_INT_MAX`], encodings longer than such a value needs and
/// prefixes outside of `1..=8` are errors.
#[inline]
pub(crate) fn decode_prefix_int(
  bytes: &[u8],
  prefix_bits: u8,
) -> crate::Result<Option<(u64, usize)>> {
  let Some(mask) = prefix_mask(prefix_bits) else {
    cold_path();
    return Err(crate::Error::Http3(Http3Error::IntegerOverflow));
  };
  let Some((first, rest)) = bytes.split_first() else {
    return Ok(None);
  };
  let mut value = u64::from(first & mask);
  if value < u64::from(mask) {
    return Ok(Some((value, 1)));
  }
  let mut shift = 0u32;
  let mut len = 1usize;
  for byte in rest {
    // Nine continuation bytes hold 63 bits: a tenth is never needed
    if shift > 56 {
      cold_path();
      return Err(crate::Error::Http3(Http3Error::IntegerOverflow));
    }
    len = len.wrapping_add(1);
    // At most 127 << 56 added to at most 2^62 - 1: no overflow
    value = value.wrapping_add(u64::from(byte & 0b0111_1111) << shift);
    if value > PREFIX_INT_MAX {
      cold_path();
      return Err(crate::Error::Http3(Http3Error::IntegerOverflow));
    }
    if byte & 0b1000_0000 == 0 {
      return Ok(Some((value, len)));
    }
    shift = shift.wrapping_add(7);
  }
  Ok(None)
}

#[inline]
fn prefix_mask(prefix_bits: u8) -> Option<u8> {
  if prefix_bits == 0 || prefix_bits > 8 {
    cold_path();
    return None;
  }
  Some(u8::MAX >> 8u8.wrapping_sub(prefix_bits))
}

#[cfg(test)]
mod tests {
  use crate::{
    Error,
    http::prefix_int::{PREFIX_INT_MAX, decode_prefix_int, encode_prefix_int},
    http3::Http3Error,
  };
  use alloc::vec::Vec;

  fn encoded(value: u64, prefix_bits: u8, flags: u8) -> Vec<u8> {
    let mut out = [0u8; 16];
    let len = encode_prefix_int(value, prefix_bits, flags, &mut out).unwrap();
    out.get(..len).unwrap().to_vec()
  }

  fn overflows(bytes: &[u8], prefix_bits: u8) -> bool {
    matches!(decode_prefix_int(bytes, prefix_bits), Err(Error::Http3(Http3Error::IntegerOverflow)))
  }

  #[test]
  fn prefix_int_rfc7541_c1_examples() {
    // C.1.1: 10 with a 5-bit prefix; the bits above the prefix are kept and ignored when read
    assert_eq!(encoded(10, 5, 0), [0x0a]);
    assert_eq!(encoded(10, 5, 0b1110_0000), [0xea]);
    assert_eq!(decode_prefix_int(&[0x0a, 0xff], 5).unwrap(), Some((10, 1)));
    assert_eq!(decode_prefix_int(&[0xea], 5).unwrap(), Some((10, 1)));
    // C.1.2: 1337 with a 5-bit prefix
    assert_eq!(encoded(1337, 5, 0), [0x1f, 0x9a, 0x0a]);
    assert_eq!(decode_prefix_int(&[0x1f, 0x9a, 0x0a, 0x00], 5).unwrap(), Some((1337, 3)));
    // C.1.3: 42 starting at an octet boundary
    assert_eq!(encoded(42, 8, 0), [0x2a]);
    assert_eq!(decode_prefix_int(&[0x2a], 8).unwrap(), Some((42, 1)));

    // The value that fills the prefix takes a zero continuation byte
    assert_eq!(encoded(31, 5, 0), [0x1f, 0x00]);
    assert_eq!(decode_prefix_int(&[0x1f, 0x00], 5).unwrap(), Some((31, 2)));
    // Too few bytes, written or read
    assert_eq!(encode_prefix_int(1337, 5, 0, &mut [0u8; 2]), None);
    assert_eq!(encode_prefix_int(1, 5, 0, &mut []), None);
    assert_eq!(decode_prefix_int(&[0x1f, 0x9a], 5).unwrap(), None);
    assert_eq!(decode_prefix_int(&[], 5).unwrap(), None);

    // 62 bits with every prefix, and not one more
    for prefix_bits in 1..=8 {
      let bytes = encoded(PREFIX_INT_MAX, prefix_bits, 0);
      assert_eq!(
        decode_prefix_int(&bytes, prefix_bits).unwrap(),
        Some((PREFIX_INT_MAX, bytes.len()))
      );
      assert_eq!(encode_prefix_int(PREFIX_INT_MAX + 1, prefix_bits, 0, &mut [0u8; 16]), None);
      for value in [0, 1, 126, 127, 128, 255, 256, 16_383, 16_384, 1 << 40] {
        let bytes = encoded(value, prefix_bits, 0);
        assert_eq!(decode_prefix_int(&bytes, prefix_bits).unwrap(), Some((value, bytes.len())));
      }
    }
    // 2^62 itself, and an encoding longer than any 62-bit value needs
    let mut too_large = alloc::vec![0x1f];
    too_large.extend_from_slice(&[0xe1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f]);
    assert!(overflows(&too_large, 5));
    let mut too_long = alloc::vec![0x1f];
    too_long.extend_from_slice(&[0x80; 9]);
    too_long.push(0x00);
    assert!(overflows(&too_long, 5));
    // Prefixes that do not exist
    assert_eq!(encode_prefix_int(1, 0, 0, &mut [0u8; 4]), None);
    assert_eq!(encode_prefix_int(1, 9, 0, &mut [0u8; 4]), None);
    assert!(decode_prefix_int(&[1], 0).is_err());
    assert!(decode_prefix_int(&[1], 9).is_err());
  }
}
