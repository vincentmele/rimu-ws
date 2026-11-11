use crate::codec::{
  GzipParams,
  gzip_encoder::tokens::{MAX_MATCH, MIN_MATCH, Tokens, WINDOW},
};
use alloc::vec::Vec;

/// Hash chains over one chunk: `head` holds, per hash of 4 bytes, the last position plus one
/// (0: none), `prev` the position before it with the same hash. Both are reused; per chunk only
/// the head entries its hash width uses are cleared, and `prev` is written before it is read.
#[derive(Debug)]
pub(crate) struct Matcher {
  head: Vec<u16>,
  prev: Vec<u16>,
  bits: u32,
}

impl Matcher {
  pub(crate) const fn new() -> Self {
    Self { head: Vec::new(), prev: Vec::new(), bits: 8 }
  }

  /// Tokens for `chunk` (at most 65,534 bytes), greedy, with one step of lazy evaluation when
  /// `params.lazy`.
  pub(crate) fn find(&mut self, chunk: &[u8], params: &GzipParams, tokens: &mut Tokens) {
    let n = chunk.len();
    tokens.clear(n);
    self.reset(n);
    let mut t = Tables { head: &mut self.head[..1 << self.bits], prev: &mut self.prev[..n], shift: 32 - self.bits };
    let depth = u32::from(params.search_depth.max(1));
    let lazy_depth = (depth / 4).max(1);
    let nice = usize::from(params.nice_match).clamp(MIN_MATCH, MAX_MATCH);
    let good = usize::from(params.good_match);
    let max_insert = usize::from(params.max_insert.max(1));
    let last_hashed = (n + 1).saturating_sub(MIN_MATCH);
    let mut i = 0;
    while i < n {
      if i >= last_hashed {
        tokens.literal(chunk[i]);
        i += 1;
        continue;
      }
      let (len, dist) = t.search_and_insert(chunk, i, depth, nice);
      if len < MIN_MATCH {
        tokens.literal(chunk[i]);
        i += 1;
        continue;
      }
      if params.lazy && len < nice && i + 1 < last_hashed {
        let next_depth = if len >= good { lazy_depth } else { depth };
        let (len2, dist2) = t.search_and_insert(chunk, i + 1, next_depth, nice);
        if len2 > len {
          tokens.literal(chunk[i]);
          tokens.matched(len2, dist2);
          t.insert_match(chunk, i + 2, i + 1 + len2, len2, max_insert, last_hashed);
          i += 1 + len2;
          continue;
        }
        tokens.matched(len, dist);
        t.insert_match(chunk, i + 2, i + len, len, max_insert, last_hashed);
        i += len;
        continue;
      }
      tokens.matched(len, dist);
      t.insert_match(chunk, i + 1, i + len, len, max_insert, last_hashed);
      i += len;
    }
  }

  fn reset(&mut self, n: usize) {
    let bits = (usize::BITS - n.max(1).leading_zeros()).clamp(8, 15);
    let size = 1 << bits;
    if self.head.len() < size {
      self.head.resize(size, 0);
    }
    self.head[..size].fill(0);
    if self.prev.len() < n {
      self.prev.resize(n, 0);
    }
    self.bits = bits;
  }
}

/// The chunk's views of the hash tables, for the hot loop.
struct Tables<'tables> {
  head: &'tables mut [u16],
  prev: &'tables mut [u16],
  shift: u32,
}

impl Tables<'_> {
  #[inline(always)]
  fn insert(&mut self, chunk: &[u8], pos: usize) -> u16 {
    let word = u32::from_le_bytes(chunk[pos..pos + 4].try_into().unwrap_or_default());
    let h = (word.wrapping_mul(0x9e37_79b1) >> self.shift) as usize;
    let slot = &mut self.head[h];
    let first = *slot;
    *slot = (pos + 1) as u16;
    self.prev[pos] = first;
    first
  }

  /// Inserts the positions `from..to` a match covered (those below `last_hashed`), only the first
  /// `max_insert` of them when the match is longer than that.
  #[inline(always)]
  fn insert_match(
    &mut self,
    chunk: &[u8],
    from: usize,
    to: usize,
    len: usize,
    max_insert: usize,
    last_hashed: usize,
  ) {
    let end = if len > max_insert { to.min(from + max_insert) } else { to };
    for pos in from..end.min(last_hashed) {
      let _ = self.insert(chunk, pos);
    }
  }

  /// Inserts `pos` and returns the longest match for it among at most `depth` earlier positions
  /// of its chain within the window: (length, distance), length 0 when none.
  #[inline(always)]
  fn search_and_insert(&mut self, chunk: &[u8], pos: usize, depth: u32, nice: usize) -> (usize, usize) {
    let mut cand = self.insert(chunk, pos);
    let max = (chunk.len() - pos).min(MAX_MATCH);
    let (mut best, mut best_dist) = (0, 0);
    let mut left = depth;
    while cand != 0 && left > 0 {
      let c = usize::from(cand) - 1;
      let dist = pos - c;
      if dist > WINDOW {
        break;
      }
      if best < max && chunk[c + best] == chunk[pos + best] {
        let len = match_len(chunk, c, pos, max);
        if len > best {
          best = len;
          best_dist = dist;
          if len >= nice {
            break;
          }
        }
      }
      cand = self.prev[c];
      left -= 1;
    }
    (best, best_dist)
  }
}

/// How many bytes at `a` and `b` (`a < b`) agree, up to `max`, eight at a time.
#[inline(always)]
pub(crate) fn match_len(chunk: &[u8], a: usize, b: usize, max: usize) -> usize {
  let (Some(x), Some(y)) = (chunk.get(a..a + max), chunk.get(b..b + max)) else {
    return 0;
  };
  let mut len = 0;
  for (xs, ys) in x.chunks_exact(8).zip(y.chunks_exact(8)) {
    let diff = u64::from_le_bytes(xs.try_into().unwrap_or_default())
      ^ u64::from_le_bytes(ys.try_into().unwrap_or_default());
    if diff != 0 {
      return len + (diff.trailing_zeros() / 8) as usize;
    }
    len += 8;
  }
  len + x[len..].iter().zip(&y[len..]).take_while(|(l, r)| l == r).count()
}
