//! Dynamic-code blocks (RFC 1951 §3.2.7): the codes of one chunk's tokens, the run-length coded
//! code lengths, and the block's exact size in bits.

use crate::codec::gzip_encoder::{
  END_OF_BLOCK,
  huffman::{Scratch, canonical_codes, code_lengths},
  tokens::{DIST_SYMBOLS, LIT_SYMBOLS, Tokens},
};

/// The order code-length code lengths are sent in.
const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
/// Extra bits of the code-length symbols 16, 17 and 18.
const CL_XBITS: [u8; 3] = [2, 3, 7];

/// One chunk's dynamic codes and header, kept between [`Self::plan`] and [`Self::write`].
#[derive(Debug)]
pub(crate) struct Dynamic {
  pub(crate) lit_len: [u8; LIT_SYMBOLS],
  pub(crate) lit_code: [u16; LIT_SYMBOLS],
  pub(crate) dist_len: [u8; DIST_SYMBOLS],
  pub(crate) dist_code: [u16; DIST_SYMBOLS],
  cl_len: [u8; 19],
  cl_code: [u16; 19],
  /// The run-length coded lengths: (symbol, extra bits value).
  rle: [(u8, u8); LIT_SYMBOLS + DIST_SYMBOLS],
  rle_len: usize,
  hlit: usize,
  hdist: usize,
  hclen: usize,
  scratch: Scratch,
}

impl Dynamic {
  pub(crate) const fn new() -> Self {
    Self {
      lit_len: [0; LIT_SYMBOLS],
      lit_code: [0; LIT_SYMBOLS],
      dist_len: [0; DIST_SYMBOLS],
      dist_code: [0; DIST_SYMBOLS],
      cl_len: [0; 19],
      cl_code: [0; 19],
      rle: [(0, 0); LIT_SYMBOLS + DIST_SYMBOLS],
      rle_len: 0,
      hlit: 257,
      hdist: 1,
      hclen: 4,
      scratch: Scratch::new(),
    }
  }

  /// Builds the codes of `tokens` and returns the size of the block in bits, its 3-bit header and
  /// end of block included.
  pub(crate) fn plan(&mut self, tokens: &Tokens) -> u64 {
    let mut lit_freq = tokens.lit_freq;
    lit_freq[END_OF_BLOCK] = 1;
    code_lengths(&lit_freq, 15, &mut self.lit_len, &mut self.scratch);
    code_lengths(&tokens.dist_freq, 15, &mut self.dist_len, &mut self.scratch);
    if self.dist_len.iter().all(|&len| len == 0) {
      // No match: one distance code, never used, keeps every decoder content
      self.dist_len[0] = 1;
    }
    canonical_codes(&self.lit_len, &mut self.lit_code);
    canonical_codes(&self.dist_len, &mut self.dist_code);
    self.hlit = 257.max(LIT_SYMBOLS - self.lit_len.iter().rev().take_while(|&&len| len == 0).count());
    self.hdist = 1.max(DIST_SYMBOLS - self.dist_len.iter().rev().take_while(|&&len| len == 0).count());
    self.run_lengths();
    let mut cl_freq = [0u32; 19];
    for &(sym, _) in &self.rle[..self.rle_len] {
      cl_freq[usize::from(sym)] += 1;
    }
    code_lengths(&cl_freq, 7, &mut self.cl_len, &mut self.scratch);
    canonical_codes(&self.cl_len, &mut self.cl_code);
    self.hclen = 4.max(19 - CL_ORDER.iter().rev().take_while(|&&sym| self.cl_len[sym] == 0).count());
    let mut bits = 3 + 5 + 5 + 4 + 3 * self.hclen as u64;
    for &(sym, _) in &self.rle[..self.rle_len] {
      bits += u64::from(self.cl_len[usize::from(sym)]);
      if sym >= 16 {
        bits += u64::from(CL_XBITS[usize::from(sym - 16)]);
      }
    }
    for (sym, &freq) in lit_freq.iter().enumerate() {
      bits += u64::from(freq) * u64::from(self.lit_len[sym]);
    }
    for (sym, &freq) in tokens.dist_freq.iter().enumerate() {
      bits += u64::from(freq) * u64::from(self.dist_len[sym]);
    }
    bits + tokens.extra_bits
  }

  /// The code lengths of the literal/length and distance alphabets, as one sequence, run-length
  /// coded with 16 (repeat the previous 3..=6 times), 17 (3..=10 zeros) and 18 (11..=138 zeros).
  fn run_lengths(&mut self) {
    let mut seq = [0u8; LIT_SYMBOLS + DIST_SYMBOLS];
    seq[..self.hlit].copy_from_slice(&self.lit_len[..self.hlit]);
    seq[self.hlit..self.hlit + self.hdist].copy_from_slice(&self.dist_len[..self.hdist]);
    let seq = &seq[..self.hlit + self.hdist];
    let mut n = 0;
    let mut i = 0;
    while i < seq.len() {
      let len = seq[i];
      let mut run = seq[i..].iter().take_while(|&&el| el == len).count();
      i += run;
      if len == 0 {
        while run >= 11 {
          let r = run.min(138);
          self.rle[n] = (18, (r - 11) as u8);
          n += 1;
          run -= r;
        }
        if run >= 3 {
          self.rle[n] = (17, (run - 3) as u8);
          n += 1;
          run = 0;
        }
      } else {
        self.rle[n] = (len, 0);
        n += 1;
        run -= 1;
        while run >= 3 {
          let r = run.min(6);
          self.rle[n] = (16, (r - 3) as u8);
          n += 1;
          run -= r;
        }
      }
      for _ in 0..run {
        self.rle[n] = (len, 0);
        n += 1;
      }
    }
    self.rle_len = n;
  }

  /// Writes the block header that [`Self::plan`] prepared.
  pub(crate) fn write_header(&self, writer: &mut crate::codec::gzip_encoder::bits::BitWriter<'_>, last: bool) {
    writer.put(u32::from(last) | (2 << 1), 3);
    writer.put((self.hlit - 257) as u32, 5);
    writer.put((self.hdist - 1) as u32, 5);
    writer.put((self.hclen - 4) as u32, 4);
    for &sym in &CL_ORDER[..self.hclen] {
      writer.put(self.cl_len[sym].into(), 3);
    }
    for &(sym, extra) in &self.rle[..self.rle_len] {
      let s = usize::from(sym);
      writer.put(self.cl_code[s].into(), self.cl_len[s].into());
      if sym >= 16 {
        writer.put(extra.into(), CL_XBITS[s - 16].into());
      }
    }
  }
}
