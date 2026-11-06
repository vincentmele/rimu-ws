//! JSON written straight into a byte vector, for handlers that serialize every response by hand.
//!
//! Keys and punctuation go in as literals the caller escaped once (`raw`), strings are escaped
//! while they are copied, 32 bytes a step with AVX2 or 8 with word tricks, and numbers are
//! formatted in place: integers from a two-digit table, floats with `zmij` (the shortest
//! round-trip form `serde_json` writes). Every method checks the spare capacity once for its own
//! worst case and then writes without further checks. Nothing allocates unless the vector grows.
//!
//! The output is byte for byte what `serde_json::to_writer` gives for the same values.

use crate::collections::VectorUsize;
use core::ptr;

/// Lowercase hex digits, as `serde_json` writes `\u00XX`.
const HEX: &[u8; 16] = b"0123456789abcdef";
/// `00`..`99`, two bytes a number.
const PAIRS: &[u8; 200] = b"0001020304050607080910111213141516171819\
2021222324252627282930313233343536373839\
4041424344454647484950515253545556575859\
6061626364656667686970717273747576777879\
8081828384858687888990919293949596979899";

/// What a byte becomes inside a JSON string: `0` for itself, `u` for `\u00XX`, any other byte
/// `c` for `\c` (the table `serde_json` uses).
static ESCAPE: [u8; 256] = {
  let mut table = [0; 256];
  let mut idx = 0;
  while idx < 0x20 {
    table[idx] = b'u';
    idx += 1;
  }
  table[0x08] = b'b';
  table[0x09] = b't';
  table[0x0A] = b'n';
  table[0x0C] = b'f';
  table[0x0D] = b'r';
  table[b'"' as usize] = b'"';
  table[b'\\' as usize] = b'\\';
  table
};

/// See the module documentation.
#[derive(Debug)]
pub struct JsonWriter<'buf> {
  buf: &'buf mut VectorUsize<u8>,
}

impl<'buf> JsonWriter<'buf> {
  /// Appends to `buf`.
  #[inline]
  pub const fn new(buf: &'buf mut VectorUsize<u8>) -> Self {
    Self { buf }
  }

  /// Reserves room for at least `additional` more bytes, so a known amount of output grows the
  /// vector at most once.
  #[inline]
  pub fn reserve(&mut self, additional: usize) -> crate::Result<()> {
    self.buf.reserve(additional)
  }

  /// `true` or `false`.
  #[inline]
  pub fn bool(&mut self, value: bool) -> crate::Result<()> {
    self.raw(if value { b"true" } else { b"false" })
  }

  /// A float in its shortest round-trip form; `null` when it is not finite, as `serde_json`.
  ///
  /// Values with at most two decimals and below 10^13 (prices, ratings, quantities) take a fast
  /// path: such a value is the double nearest to `cents / 100`, a decimal of at most 15
  /// significant digits, so that decimal is its shortest round-trip form and it can be printed
  /// from the integer `cents` instead of running the general algorithm.
  #[inline]
  pub fn f64(&mut self, value: f64) -> crate::Result<()> {
    if !value.is_finite() {
      return self.raw(b"null");
    }
    self.ensure(32)?;
    let magnitude = value.abs();
    if magnitude < 1e13 {
      // Whole numbers, the commonest case, need no scaling: `N.0`.
      let int = magnitude as u64;
      if int as f64 == magnitude {
        // SAFETY: 32 bytes of spare capacity were ensured; the longest output is 16 bytes.
        unsafe {
          let len = self.buf.len();
          let dst = self.buf.as_ptr_mut().add(len);
          let mut out = usize::from(value.is_sign_negative());
          if out == 1 {
            *dst = b'-';
          }
          out = out.wrapping_add(write_u64(int, dst.add(out)));
          ptr::copy_nonoverlapping(b".0".as_ptr(), dst.add(out), 2);
          self.buf.set_len(len.wrapping_add(out).wrapping_add(2));
        }
        return Ok(());
      }
      let cents = (magnitude * 100.0).round();
      if cents / 100.0 == magnitude {
        // SAFETY: 32 bytes of spare capacity were ensured; the longest output is
        // `-9999999999999.99`, 17 bytes.
        unsafe {
          let len = self.buf.len();
          let written = write_cents(value.is_sign_negative(), cents as u64, self.buf.as_ptr_mut().add(len));
          self.buf.set_len(len.wrapping_add(written));
        }
        return Ok(());
      }
    }
    let mut buffer = zmij::Buffer::new();
    let text = buffer.format_finite(value).as_bytes();
    // SAFETY: 32 bytes of spare capacity were ensured; `zmij` writes at most 24.
    unsafe {
      let len = self.buf.len();
      copy_small(text.as_ptr(), self.buf.as_ptr_mut().add(len), text.len());
      self.buf.set_len(len.wrapping_add(text.len()));
    }
    Ok(())
  }

  /// A signed integer.
  #[inline]
  pub fn i64(&mut self, value: i64) -> crate::Result<()> {
    if value < 0 {
      self.raw(b"-")?;
    }
    self.u64(value.unsigned_abs())
  }

  /// Bytes that are already JSON: keys with their quotes and colon, punctuation, literals.
  #[inline(always)]
  pub fn raw(&mut self, bytes: &[u8]) -> crate::Result<()> {
    self.ensure(bytes.len())?;
    // SAFETY: `bytes.len()` bytes of spare capacity were ensured.
    unsafe {
      let len = self.buf.len();
      ptr::copy_nonoverlapping(bytes.as_ptr(), self.buf.as_ptr_mut().add(len), bytes.len());
      self.buf.set_len(len.wrapping_add(bytes.len()));
    }
    Ok(())
  }

  /// A string, quoted and escaped.
  #[inline]
  pub fn str(&mut self, value: &str) -> crate::Result<()> {
    self.raw(b"\"")?;
    self.str_contents(value)?;
    self.raw(b"\"")
  }

  /// The escaped contents of a string, without quotes.
  #[inline]
  pub fn str_contents(&mut self, value: &str) -> crate::Result<()> {
    let src = value.as_bytes();
    // Every byte may become six (`\u00XX`) and block copies store up to 32 bytes ahead.
    self.ensure(src.len().wrapping_mul(6).wrapping_add(32))?;
    // Short strings with nothing to escape, the usual case: one check, one copy.
    if src.len() <= 32 && !has_special_short(src) {
      // SAFETY: capacity for `src.len()` bytes was ensured above.
      unsafe {
        let len = self.buf.len();
        copy_small(src.as_ptr(), self.buf.as_ptr_mut().add(len), src.len());
        self.buf.set_len(len.wrapping_add(src.len()));
      }
      return Ok(());
    }
    // SAFETY: the capacity above bounds every store: after `idx` source bytes at most `6 * idx`
    // bytes were written, and a block store writes 32 bytes from there.
    unsafe {
      let start = self.buf.len();
      let written = escape(src, self.buf.as_ptr_mut().add(start));
      self.buf.set_len(start.wrapping_add(written));
    }
    Ok(())
  }

  /// An unsigned integer.
  #[inline]
  pub fn u64(&mut self, value: u64) -> crate::Result<()> {
    self.ensure(20)?;
    // SAFETY: 20 bytes of spare capacity were ensured and `u64` has at most 20 digits.
    unsafe {
      let len = self.buf.len();
      let written = write_u64(value, self.buf.as_ptr_mut().add(len));
      self.buf.set_len(len.wrapping_add(written));
    }
    Ok(())
  }

  #[inline(always)]
  fn ensure(&mut self, additional: usize) -> crate::Result<()> {
    if self.buf.capacity().wrapping_sub(self.buf.len()) < additional {
      return self.grow(additional);
    }
    Ok(())
  }

  #[cold]
  #[inline(never)]
  fn grow(&mut self, additional: usize) -> crate::Result<()> {
    self.buf.reserve(additional.max(self.buf.capacity()))
  }
}

/// Writes `value` in decimal at `dst`, two digits a step from [`PAIRS`], and returns its length.
///
/// # Safety
///
/// `dst` is writable for 20 bytes.
#[inline(always)]
unsafe fn write_u64(value: u64, dst: *mut u8) -> usize {
  let digits = value.checked_ilog10().map_or(1, |el| el.wrapping_add(1)) as usize;
  // SAFETY: `digits <= 20` bytes are written, right to left from `dst + digits`.
  unsafe {
    let mut end = dst.add(digits);
    let mut rest = value;
    while rest >= 100 {
      let pair = usize::try_from(rest % 100).unwrap_or_default().wrapping_mul(2);
      rest /= 100;
      end = end.sub(2);
      ptr::copy_nonoverlapping(PAIRS.as_ptr().add(pair), end, 2);
    }
    if rest >= 10 {
      let pair = usize::try_from(rest).unwrap_or_default().wrapping_mul(2);
      ptr::copy_nonoverlapping(PAIRS.as_ptr().add(pair), end.sub(2), 2);
    } else {
      *end.sub(1) = b'0'.wrapping_add(u8::try_from(rest).unwrap_or_default());
    }
  }
  digits
}

/// Writes `cents / 100` as `serde_json` would: `-`, the integer part, `.`, then the decimals with
/// trailing zeros dropped but at least one (`3.0`, `4.5`, `49.99`). Returns the length.
///
/// # Safety
///
/// `dst` is writable for 17 bytes and `cents < 10^15`.
#[inline]
unsafe fn write_cents(negative: bool, cents: u64, dst: *mut u8) -> usize {
  let frac = usize::try_from(cents % 100).unwrap_or_default().wrapping_mul(2);
  // SAFETY: at most 1 + 13 + 1 + 2 bytes are written.
  unsafe {
    let mut out = usize::from(negative);
    if negative {
      *dst = b'-';
    }
    out = out.wrapping_add(write_u64(cents / 100, dst.add(out)));
    *dst.add(out) = b'.';
    ptr::copy_nonoverlapping(PAIRS.as_ptr().add(frac), dst.add(out.wrapping_add(1)), 2);
    // `x.50` is `x.5`: drop a trailing zero decimal.
    if *PAIRS.get_unchecked(frac.wrapping_add(1)) == b'0' { out.wrapping_add(2) } else { out.wrapping_add(3) }
  }
}

/// Whether a string of at most 32 bytes has a byte JSON escapes: overlapping 8-byte words for
/// 8 bytes and more (the word test marks bytes only when one truly needs escaping), the table
/// below that.
#[inline(always)]
fn has_special_short(src: &[u8]) -> bool {
  const ONES: u64 = 0x0101_0101_0101_0101;
  const HIGHS: u64 = 0x8080_8080_8080_8080;
  let len = src.len();
  if len < 8 {
    return src.iter().any(|el| ESCAPE[usize::from(*el)] != 0);
  }
  let zero = |el: u64| el.wrapping_sub(ONES) & !el & HIGHS;
  let mut idx: usize = 0;
  loop {
    let at = idx.min(len.wrapping_sub(8));
    let word = src
      .get(at..at.wrapping_add(8))
      .and_then(|el| <[u8; 8]>::try_from(el).ok())
      .map_or(0, u64::from_le_bytes);
    let hits = zero(word ^ (ONES * u64::from(b'"')))
      | zero(word ^ (ONES * u64::from(b'\\')))
      | (word.wrapping_sub(ONES * 0x20) & !word & HIGHS);
    if hits != 0 {
      return true;
    }
    idx = idx.wrapping_add(8);
    if idx >= len {
      return false;
    }
  }
}

/// Copies `len <= 32` bytes with two overlapping moves of a fixed size instead of a `memcpy`
/// call.
///
/// # Safety
///
/// `src` is readable and `dst` writable for `len` bytes, and they do not overlap.
#[inline(always)]
unsafe fn copy_small(src: *const u8, dst: *mut u8, len: usize) {
  // SAFETY: each pair of moves covers `[0, len)` with reads and writes inside it.
  unsafe {
    if len >= 16 {
      ptr::copy_nonoverlapping(src, dst, 16);
      ptr::copy_nonoverlapping(src.add(len - 16), dst.add(len - 16), 16);
    } else if len >= 8 {
      ptr::copy_nonoverlapping(src, dst, 8);
      ptr::copy_nonoverlapping(src.add(len - 8), dst.add(len - 8), 8);
    } else if len >= 4 {
      ptr::copy_nonoverlapping(src, dst, 4);
      ptr::copy_nonoverlapping(src.add(len - 4), dst.add(len - 4), 4);
    } else {
      let mut idx = 0;
      while idx < len {
        *dst.add(idx) = *src.add(idx);
        idx += 1;
      }
    }
  }
}

/// Copies `src` to `dst` escaped and returns how many bytes it wrote. Clean blocks are stored
/// whole and the scan moves past them; a block with a byte to escape is stored too, and the
/// writing resumes at that byte, so no byte is copied twice to its final place.
///
/// # Safety
///
/// `dst` is writable for `6 * src.len() + 32` bytes.
#[inline]
unsafe fn escape(src: &[u8], dst: *mut u8) -> usize {
  let len = src.len();
  let mut idx: usize = 0;
  let mut out: usize = 0;
  // SAFETY: loads read inside `src`; stores stay within the bound the caller gave (see
  // `JsonWriter::str_contents`).
  unsafe {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
      use core::arch::x86_64::{
        __m256i, _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_min_epu8, _mm256_movemask_epi8,
        _mm256_or_si256, _mm256_set1_epi8, _mm256_storeu_si256,
      };
      let quote = _mm256_set1_epi8(b'"'.cast_signed());
      let backslash = _mm256_set1_epi8(b'\\'.cast_signed());
      let control = _mm256_set1_epi8(0x1f);
      while idx.wrapping_add(32) <= len {
        let block = _mm256_loadu_si256(src.as_ptr().add(idx).cast::<__m256i>());
        _mm256_storeu_si256(dst.add(out).cast::<__m256i>(), block);
        let hits = _mm256_or_si256(
          _mm256_or_si256(_mm256_cmpeq_epi8(block, quote), _mm256_cmpeq_epi8(block, backslash)),
          // unsigned `byte <= 0x1f`: min(byte, 0x1f) == byte
          _mm256_cmpeq_epi8(_mm256_min_epu8(block, control), block),
        );
        let mask = _mm256_movemask_epi8(hits).cast_unsigned();
        if mask == 0 {
          idx = idx.wrapping_add(32);
          out = out.wrapping_add(32);
          continue;
        }
        let clean = mask.trailing_zeros() as usize;
        idx = idx.wrapping_add(clean);
        out = out.wrapping_add(clean);
        out = out.wrapping_add(escape_byte(*src.get_unchecked(idx), dst.add(out)));
        idx = idx.wrapping_add(1);
      }
    }
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGHS: u64 = 0x8080_8080_8080_8080;
    while idx.wrapping_add(8) <= len {
      let word = ptr::read_unaligned(src.as_ptr().add(idx).cast::<u64>());
      ptr::write_unaligned(dst.add(out).cast::<u64>(), word);
      let zero = |el: u64| el.wrapping_sub(ONES) & !el & HIGHS;
      // `"` and `\` XOR to zero against a repeated byte; a byte below 0x20 borrows when 0x20 is
      // subtracted. A borrow can mark bytes above a true hit, never one below it, so the lowest
      // mark is the first true one.
      let hits = zero(word ^ (ONES * u64::from(b'"')))
        | zero(word ^ (ONES * u64::from(b'\\')))
        | (word.wrapping_sub(ONES * 0x20) & !word & HIGHS);
      if hits == 0 {
        idx = idx.wrapping_add(8);
        out = out.wrapping_add(8);
        continue;
      }
      let clean = (hits.trailing_zeros() / 8) as usize;
      idx = idx.wrapping_add(clean);
      out = out.wrapping_add(clean);
      out = out.wrapping_add(escape_byte(*src.get_unchecked(idx), dst.add(out)));
      idx = idx.wrapping_add(1);
    }
    while idx < len {
      let byte = *src.get_unchecked(idx);
      if *ESCAPE.get_unchecked(usize::from(byte)) == 0 {
        *dst.add(out) = byte;
        out = out.wrapping_add(1);
      } else {
        out = out.wrapping_add(escape_byte(byte, dst.add(out)));
      }
      idx = idx.wrapping_add(1);
    }
  }
  out
}

/// Writes the escape of `byte`, which needs one, and returns its length.
///
/// # Safety
///
/// `dst` is writable for 6 bytes.
#[cold]
#[inline(never)]
unsafe fn escape_byte(byte: u8, dst: *mut u8) -> usize {
  let class = ESCAPE[usize::from(byte)];
  // SAFETY: at most 6 bytes are written.
  unsafe {
    *dst = b'\\';
    if class == b'u' {
      ptr::copy_nonoverlapping(b"u00".as_ptr(), dst.add(1), 3);
      *dst.add(4) = HEX[usize::from(byte >> 4)];
      *dst.add(5) = HEX[usize::from(byte & 0xf)];
      6
    } else {
      *dst.add(1) = class;
      2
    }
  }
}

#[cfg(all(test, feature = "serde_json"))]
mod tests {
  use crate::{collections::VectorUsize, misc::JsonWriter, rng::{Rng as _, Xorshift64}};
  use alloc::{string::String, vec::Vec};

  fn written(cb: impl FnOnce(&mut JsonWriter<'_>)) -> String {
    let mut buf = VectorUsize::new();
    cb(&mut JsonWriter::new(&mut buf));
    String::from_utf8(buf.as_slice().to_vec()).unwrap()
  }

  #[test]
  fn json_writer_strings_match_serde_json() {
    let mut rng = Xorshift64::from(7u64);
    let alphabet: Vec<char> =
      (0u8..0x80).map(char::from).chain(['é', 'ß', '東', '🎾', '\u{7f}', '/']).collect();
    for len in 0..150 {
      for _ in 0..20 {
        let text: String = (0..len)
          .map(|_| {
            let pick = usize::from(rng.u8_4()[0]);
            // Mostly plain letters, so long clean runs reach the block paths.
            if pick < 200 { char::from(b'a' + (pick % 26) as u8) } else { alphabet[pick % alphabet.len()] }
          })
          .collect();
        assert_eq!(written(|w| w.str(&text).unwrap()), serde_json::to_string(&text).unwrap(), "{text:?}");
      }
    }
    let every: String = (0u8..0x80).map(char::from).collect();
    assert_eq!(written(|w| w.str(&every).unwrap()), serde_json::to_string(&every).unwrap());
  }

  #[test]
  fn json_writer_numbers_match_serde_json() {
    let mut rng = Xorshift64::from(11u64);
    let mut ints = alloc::vec![0, 1, 9, 10, 99, 100, 999, 1000, i64::MAX, i64::MIN, -1, -10, -99];
    let mut pow: i64 = 1;
    for _ in 0..18 {
      pow *= 10;
      ints.extend([pow - 1, pow, pow + 1, -pow]);
    }
    for _ in 0..10_000 {
      ints.push(i64::from_le_bytes(rng.u8_8()) >> (rng.u8_4()[0] % 64));
    }
    for value in ints {
      assert_eq!(written(|w| w.i64(value).unwrap()), serde_json::to_string(&value).unwrap());
    }
    assert_eq!(written(|w| w.u64(u64::MAX).unwrap()), serde_json::to_string(&u64::MAX).unwrap());
    let mut floats = alloc::vec![
      0.0, -0.0, 0.1, 0.5, 1.0, 1.5, 100.0, 1e21, 1e-7, 123_456.789, f64::MAX, f64::MIN_POSITIVE,
      5e-324, 49.99, 2.675, f64::NAN, f64::INFINITY, f64::NEG_INFINITY,
    ];
    for _ in 0..10_000 {
      floats.push(f64::from_bits(u64::from_le_bytes(rng.u8_8())));
      floats.push(f64::from(rng.u8_4()[0]) * 0.37 + f64::from(u32::from_le_bytes(rng.u8_4())) / 100.0);
    }
    for value in floats {
      assert_eq!(written(|w| w.f64(value).unwrap()), serde_json::to_string(&value).unwrap(), "{value:?}");
    }
  }

  #[test]
  fn json_writer_two_decimal_floats_match_serde_json() {
    let check = |value: f64| {
      assert_eq!(written(|w| w.f64(value).unwrap()), serde_json::to_string(&value).unwrap(), "{value:?}");
    };
    for cents in 0..2_000_000u32 {
      let value = f64::from(cents) / 100.0;
      check(value);
      check(-value);
    }
    let mut rng = Xorshift64::from(13u64);
    for _ in 0..200_000 {
      let cents = u64::from_le_bytes(rng.u8_8()) % 1_000_000_000_000_000;
      check(cents as f64 / 100.0);
      check((cents % 10_000_000) as f64 / 10.0);
    }
    for value in [1e13, 9_999_999_999_999.99, 1e13 - 0.01, 0.005, 0.015, 1.005, 2.675, 1e-2, 1e-3] {
      check(value);
      check(-value);
    }
  }

  #[test]
  fn json_writer_appends_and_grows() {
    let mut buf = VectorUsize::from_copyable_slice(b"x").unwrap();
    let mut w = JsonWriter::new(&mut buf);
    for _ in 0..1000 {
      w.raw(b"{\"k\":").unwrap();
      w.str("v\"\n").unwrap();
      w.bool(true).unwrap();
    }
    assert_eq!(buf.len(), 1 + 1000 * (5 + 7 + 4));
    assert!(buf.as_slice().starts_with(b"x{\"k\":\"v\\\"\\n\"true"));
  }
}
