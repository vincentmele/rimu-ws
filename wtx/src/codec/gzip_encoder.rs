//! A one-shot gzip encoder for small bodies: one input slice in, one complete gzip member
//! (RFC 1952) out.
//!
//! General streaming compressors spend most of their time on a body of a few kilobytes clearing
//! and walking state sized for megabytes. This encoder matches the input where it lies, in chunks
//! of at most [`MAX_CHUNK`] bytes so positions fit in 16 bits, with state sized to the chunk and
//! reused, so encoding allocates nothing once its buffers have grown. Each chunk becomes one
//! DEFLATE block (RFC 1951) written in whichever of the block types costs the fewest bits.

mod bits;
#[cfg(any(test, feature = "_fuzz-gzip"))]
pub mod check;
mod dynamic;
mod huffman;
mod matcher;
#[cfg(test)]
mod tests;
mod tokens;

use alloc::vec::Vec;
use bits::BitWriter;
use dynamic::Dynamic;
use matcher::Matcher;
use tokens::{DIST_XBITS, LEN_BASE, LEN_SYM, LEN_XBITS, DIST_BASE, MATCH, Tokens, dist_sym};

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
  /// One step of lazy evaluation: a match is deferred when the next position starts a longer one.
  pub lazy: bool,
}

impl Default for GzipParams {
  #[inline]
  fn default() -> Self {
    Self { search_depth: 4, nice_match: 32, good_match: 8, max_insert: 4, lazy: true }
  }
}

/// How a block was coded.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlockType {
  Stored,
  Fixed,
  Dynamic,
}

/// A reusable one-shot gzip encoder. See the module documentation.
#[derive(Debug)]
pub struct GzipEncoder {
  #[cfg(test)]
  block_types: Vec<BlockType>,
  dynamic: Dynamic,
  matcher: Matcher,
  params: GzipParams,
  tokens: Tokens,
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
    Self {
      #[cfg(test)]
      block_types: Vec::new(),
      dynamic: Dynamic::new(),
      matcher: Matcher::new(),
      params,
      tokens: Tokens::new(),
    }
  }

  /// The block types of the last [`Self::encode`].
  #[cfg(test)]
  pub(crate) fn last_block_types(&self) -> &[BlockType] {
    &self.block_types
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
    #[cfg(test)]
    self.block_types.clear();
    out.reserve(Self::bound(input.len()));
    out.extend_from_slice(&HEADER);
    let mut writer = BitWriter::new(out);
    let mut chunks = input.chunks(MAX_CHUNK).peekable();
    if chunks.peek().is_none() {
      self.tokens.clear(0);
      #[cfg(test)]
      self.block_types.push(BlockType::Fixed);
      write_fixed(&mut writer, &self.tokens, true);
    }
    while let Some(chunk) = chunks.next() {
      let last = chunks.peek().is_none();
      self.matcher.find(chunk, &self.params, &mut self.tokens);
      let stored = stored_bits(writer.position(), chunk.len());
      let fixed = fixed_bits(&self.tokens);
      let dynamic = self.dynamic.plan(&self.tokens);
      if dynamic < fixed && dynamic < stored {
        #[cfg(test)]
        self.block_types.push(BlockType::Dynamic);
        self.dynamic.write_header(&mut writer, last);
        let d = &self.dynamic;
        write_tokens(&mut writer, &self.tokens, &d.lit_code, &d.lit_len, &d.dist_code, &d.dist_len);
      } else if fixed < stored {
        #[cfg(test)]
        self.block_types.push(BlockType::Fixed);
        write_fixed(&mut writer, &self.tokens, last);
      } else {
        #[cfg(test)]
        self.block_types.push(BlockType::Stored);
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

const FIXED_LIT_CODE: [u16; 288] = {
  let mut table = [0; 288];
  let mut symbol = 0;
  while symbol < 288 {
    table[symbol] = fixed_lit_code(symbol).0;
    symbol += 1;
  }
  table
};
const FIXED_LIT_LEN: [u8; 288] = {
  let mut table = [0; 288];
  let mut symbol = 0;
  while symbol < 288 {
    table[symbol] = fixed_lit_code(symbol).1;
    symbol += 1;
  }
  table
};
/// The fixed distance codes, bit-reversed (all 5 bits long).
const FIXED_DIST_CODE: [u16; 30] = {
  let mut table = [0; 30];
  let mut sym = 0;
  while sym < 30 {
    table[sym] = reverse(sym as u16, 5);
    sym += 1;
  }
  table
};
const FIXED_DIST_LEN: [u8; 30] = [5; 30];

/// Bits of `tokens` as one fixed-code block: header, symbols, extra bits, end of block.
fn fixed_bits(tokens: &Tokens) -> u64 {
  let symbols: u64 =
    tokens.lit_freq.iter().enumerate().map(|(sym, &freq)| u64::from(freq) * u64::from(FIXED_LIT_LEN[sym])).sum();
  let distances: u64 = tokens.dist_freq.iter().map(|&freq| u64::from(freq) * 5).sum();
  3 + symbols + distances + tokens.extra_bits + u64::from(FIXED_LIT_LEN[END_OF_BLOCK])
}

fn write_fixed(writer: &mut BitWriter<'_>, tokens: &Tokens, last: bool) {
  writer.put(u32::from(last) | (1 << 1), 3);
  write_tokens(writer, tokens, &FIXED_LIT_CODE, &FIXED_LIT_LEN, &FIXED_DIST_CODE, &FIXED_DIST_LEN);
}

/// The tokens of a block in its codes, then its end of block.
#[inline(always)]
fn write_tokens(
  writer: &mut BitWriter<'_>,
  tokens: &Tokens,
  lit_code: &[u16],
  lit_len: &[u8],
  dist_code: &[u16],
  dist_len: &[u8],
) {
  for &token in &tokens.items {
    if token & MATCH == 0 {
      let sym = token as usize;
      writer.put(lit_code[sym].into(), lit_len[sym].into());
      continue;
    }
    let len = ((token >> 16) & 0xff) as usize + 3;
    let distance = (token & 0xffff) as usize + 1;
    // Each code goes out with its extra bits in one write: at most 15 + 5 and 15 + 13 bits
    let ls = usize::from(LEN_SYM[len]);
    let code_len = u32::from(lit_len[257 + ls]);
    let extra = u32::from(len as u16 - LEN_BASE[ls]);
    writer.put(u32::from(lit_code[257 + ls]) | extra << code_len, code_len + u32::from(LEN_XBITS[ls]));
    let ds = dist_sym(distance);
    let code_len = u32::from(dist_len[ds]);
    let extra = u32::from(distance as u16 - DIST_BASE[ds]);
    writer.put(u32::from(dist_code[ds]) | extra << code_len, code_len + u32::from(DIST_XBITS[ds]));
  }
  writer.put(lit_code[END_OF_BLOCK].into(), lit_len[END_OF_BLOCK].into());
}
