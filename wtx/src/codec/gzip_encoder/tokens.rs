use alloc::vec::Vec;

/// The shortest match the encoder emits: 3-byte matches rarely pay for their codes.
pub(crate) const MIN_MATCH: usize = 4;
/// DEFLATE's longest match.
pub(crate) const MAX_MATCH: usize = 258;
/// DEFLATE's longest distance.
pub(crate) const WINDOW: usize = 32_768;
/// Literal/length symbols in use (0..=285).
pub(crate) const LIT_SYMBOLS: usize = 286;
/// Distance symbols in use (0..=29).
pub(crate) const DIST_SYMBOLS: usize = 30;

pub(crate) const LEN_BASE: [u16; 29] = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
  163, 195, 227, 258,
];
pub(crate) const LEN_XBITS: [u8; 29] =
  [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
pub(crate) const DIST_BASE: [u16; 30] = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049,
  3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
pub(crate) const DIST_XBITS: [u8; 30] = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];

/// The length symbol (minus 257) of every match length 0..=258 (0..=2 unused).
pub(crate) const LEN_SYM: [u8; MAX_MATCH + 1] = {
  let mut table = [0; MAX_MATCH + 1];
  let mut sym = 0;
  while sym < 28 {
    let mut len = LEN_BASE[sym] as usize;
    while len < LEN_BASE[sym] as usize + (1 << LEN_XBITS[sym]) && len < MAX_MATCH {
      table[len] = sym as u8;
      len += 1;
    }
    sym += 1;
  }
  table[MAX_MATCH] = 28;
  table
};

/// The distance symbol of `distance - 1` below 256, then of `(distance - 1) >> 7`: past 256 the
/// symbol ranges are 128-aligned.
const DIST_SYM_LO: [u8; 256] = dist_sym_table(false);
const DIST_SYM_HI: [u8; 256] = dist_sym_table(true);

const fn dist_sym_table(hi: bool) -> [u8; 256] {
  let mut table = [0; 256];
  let mut sym = 0;
  while sym < DIST_SYMBOLS {
    let mut d = DIST_BASE[sym] as usize - 1;
    while d < DIST_BASE[sym] as usize - 1 + (1 << DIST_XBITS[sym]) {
      if !hi && d < 256 {
        table[d] = sym as u8;
      } else if hi && d >= 256 {
        table[d >> 7] = sym as u8;
      }
      d += 1;
    }
    sym += 1;
  }
  table
}

/// The distance symbol of `distance` (1..=32,768).
#[inline]
pub(crate) fn dist_sym(distance: usize) -> usize {
  let d = distance - 1;
  usize::from(if d < 256 { DIST_SYM_LO[d] } else { DIST_SYM_HI[d >> 7] })
}

/// One chunk's literals and matches, with the symbol frequencies the block coder needs.
///
/// A token is a literal byte, or `MATCH | (length - 3) << 16 | (distance - 1)`.
#[derive(Debug)]
pub(crate) struct Tokens {
  pub(crate) items: Vec<u32>,
  pub(crate) lit_freq: [u32; LIT_SYMBOLS],
  pub(crate) dist_freq: [u32; DIST_SYMBOLS],
  /// The extra bits of every length and distance, summed.
  pub(crate) extra_bits: u64,
}

pub(crate) const MATCH: u32 = 1 << 31;

impl Tokens {
  pub(crate) const fn new() -> Self {
    Self {
      items: Vec::new(),
      lit_freq: [0; LIT_SYMBOLS],
      dist_freq: [0; DIST_SYMBOLS],
      extra_bits: 0,
    }
  }

  /// Empties the tokens for a chunk of `len` bytes, keeping the buffer.
  pub(crate) fn clear(&mut self, len: usize) {
    self.items.clear();
    self.items.reserve(len.saturating_add(1));
    self.lit_freq = [0; LIT_SYMBOLS];
    self.dist_freq = [0; DIST_SYMBOLS];
    self.extra_bits = 0;
  }

  #[inline]
  pub(crate) fn literal(&mut self, byte: u8) {
    self.items.push(u32::from(byte));
    self.lit_freq[usize::from(byte)] += 1;
  }

  #[inline]
  pub(crate) fn matched(&mut self, len: usize, distance: usize) {
    debug_assert!((MIN_MATCH..=MAX_MATCH).contains(&len) && (1..=WINDOW).contains(&distance));
    self.items.push(MATCH | ((len - 3) as u32) << 16 | (distance - 1) as u32);
    let ls = usize::from(LEN_SYM[len]);
    self.lit_freq[257 + ls] += 1;
    let ds = dist_sym(distance);
    self.dist_freq[ds] += 1;
    self.extra_bits += u64::from(LEN_XBITS[ls]) + u64::from(DIST_XBITS[ds]);
  }
}
