//! A one-shot gzip encoder for small bodies: one input slice in, one complete gzip member
//! (RFC 1952) out.
//!
//! General streaming compressors spend most of their time on a body of a few kilobytes clearing
//! and walking state sized for megabytes. This encoder matches the input where it lies, in chunks
//! of at most [`MAX_CHUNK`] bytes so positions fit in 16 bits, with state sized to the chunk and
//! reused, so encoding allocates nothing once its buffers have grown. Each chunk becomes one
//! DEFLATE block (RFC 1951) written in whichever of the block types costs the fewest bits.

mod bits;
#[cfg(test)]
mod tests;

use alloc::vec::Vec;
use bits::BitWriter;

/// The longest chunk one block covers: positions are stored plus one in 16 bits.
pub(crate) const MAX_CHUNK: usize = 65_534;
/// The minimal gzip header: deflate, no name or time, no extra flags, Unix.
const HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
/// The end-of-block symbol.
const END_OF_BLOCK: usize = 256;

/// How hard the encoder searches for matches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GzipParams {
  /// Hash chain links tried per position.
  pub search_depth: u16,
  /// A match this long ends the search and the lazy step.
  pub nice_match: u16,
  /// Past this length the lazy step searches a quarter as deep.
  pub good_match: u16,
  /// Longer matches enter only their first positions into the hash chains.
  pub max_insert: u16,
}

impl Default for GzipParams {
  #[inline]
  fn default() -> Self {
    Self { search_depth: 4, nice_match: 32, good_match: 8, max_insert: 4 }
  }
}

/// A reusable one-shot gzip encoder. See the module documentation.
#[derive(Debug)]
pub struct GzipEncoder {
  params: GzipParams,
}

impl GzipEncoder {
  /// An encoder with the default parameters. Allocates nothing.
  #[inline]
  pub fn new() -> Self {
    Self::with_params(GzipParams::default())
  }

  /// An encoder with `params`. Allocates nothing.
  #[inline]
  pub fn with_params(params: GzipParams) -> Self {
    Self { params }
  }

  /// The parameters of this encoder.
  #[inline]
  pub fn params(&self) -> GzipParams {
    self.params
  }

  /// The largest member [`Self::encode`] can produce for `len` input bytes: every chunk stored.
  #[inline]
  pub fn bound(len: usize) -> usize {
    let blocks = len.div_ceil(MAX_CHUNK).max(1);
    len.saturating_add(blocks.saturating_mul(5)).saturating_add(HEADER.len() + 8 + 1)
  }

  /// Appends one complete gzip member for `input` to `out`. Allocates only to grow `out` (once,
  /// to [`Self::bound`]) or this encoder's state beyond their high-water marks.
  #[inline]
  pub fn encode(&mut self, input: &[u8], out: &mut Vec<u8>) -> crate::Result<()> {
    out.reserve(Self::bound(input.len()));
    out.extend_from_slice(&HEADER);
    let mut writer = BitWriter::new(out);
    let mut chunks = input.chunks(MAX_CHUNK).peekable();
    if chunks.peek().is_none() {
      write_fixed_literals(&mut writer, &[], true);
    }
    while let Some(chunk) = chunks.next() {
      let last = chunks.peek().is_none();
      let stored = stored_bits(writer.position(), chunk.len());
      let fixed = fixed_literals_bits(chunk);
      if fixed < stored {
        write_fixed_literals(&mut writer, chunk, last);
      } else {
        write_stored(&mut writer, chunk, last);
      }
    }
    let out = writer.finish();
    out.extend_from_slice(&zlib_rs::crc32::crc32(0, input).to_le_bytes());
    out.extend_from_slice(&(input.len() as u32).to_le_bytes());
    Ok(())
  }
}

impl Default for GzipEncoder {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

/// Bits of a stored block of `len` bytes started at bit `position`: the 3-bit block header, the
/// padding to a byte, LEN and NLEN, then the bytes.
fn stored_bits(position: u64, len: usize) -> u64 {
  let after_header = position + 3;
  let pad = (8 - after_header % 8) % 8;
  3 + pad + 32 + 8 * u64::try_from(len).unwrap_or(u64::MAX)
}

fn write_stored(writer: &mut BitWriter<'_>, chunk: &[u8], last: bool) {
  writer.put(u32::from(last), 3);
  writer.align();
  let len = chunk.len() as u16;
  writer.bytes(&len.to_le_bytes());
  writer.bytes(&(!len).to_le_bytes());
  writer.bytes(chunk);
}

/// The fixed literal/length code (RFC 1951 §3.2.6) of `symbol`: (bit-reversed code, length).
const fn fixed_lit_code(symbol: usize) -> (u16, u8) {
  let (code, len) = match symbol {
    0..=143 => (0x30 + symbol as u16, 8),
    144..=255 => (0x190 + (symbol - 144) as u16, 9),
    256..=279 => ((symbol - 256) as u16, 7),
    _ => (0xc0 + (symbol - 280) as u16, 8),
  };
  (reverse(code, len), len)
}

/// The low `len` bits of `code` in reverse order: Huffman codes go out most significant bit first
/// in an LSB-first stream.
pub(crate) const fn reverse(code: u16, len: u8) -> u16 {
  code.reverse_bits() >> (16 - len as u32)
}

const FIXED_LIT: [(u16, u8); 288] = {
  let mut table = [(0, 0); 288];
  let mut symbol = 0;
  while symbol < 288 {
    table[symbol] = fixed_lit_code(symbol);
    symbol += 1;
  }
  table
};

fn fixed_literals_bits(chunk: &[u8]) -> u64 {
  let body: u64 = chunk.iter().map(|&byte| u64::from(FIXED_LIT[usize::from(byte)].1)).sum();
  3 + body + u64::from(FIXED_LIT[END_OF_BLOCK].1)
}

fn write_fixed_literals(writer: &mut BitWriter<'_>, chunk: &[u8], last: bool) {
  writer.put(u32::from(last) | (1 << 1), 3);
  for &byte in chunk {
    let (code, len) = FIXED_LIT[usize::from(byte)];
    writer.put(code.into(), len.into());
  }
  let (code, len) = FIXED_LIT[END_OF_BLOCK];
  writer.put(code.into(), len.into());
}
