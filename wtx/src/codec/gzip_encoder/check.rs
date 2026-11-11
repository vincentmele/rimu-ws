//! The gzip encoder over arbitrary bytes, for the fuzz target `gzip_encoder` and its seed test:
//! the first eight bytes choose the search parameters and how the rest splits into one to three
//! inputs, which one encoder encodes in turn. Every member must inflate to its input, stay within
//! [`GzipEncoder::bound`] and carry the right CRC32 and length.

use crate::codec::{GzipEncoder, GzipParams};
use alloc::vec::Vec;

/// See the module documentation. Panics on a broken member.
pub fn check_bytes(data: &[u8]) {
  let (head, rest) = data.split_at(data.len().min(8));
  let mut seed = [0u8; 8];
  seed[..head.len()].copy_from_slice(head);
  let field = |i: usize| u16::from_le_bytes([seed[i], seed[i + 1]]);
  let params = GzipParams {
    search_depth: field(0) % 4096 + 1,
    nice_match: field(2) % 258 + 1,
    good_match: field(4) % 258 + 1,
    max_insert: u16::from(seed[6]) % 258 + 1,
    lazy: seed[7] & 0x80 == 0,
  };
  let parts = usize::from((seed[7] & 0x7f) % 3) + 1;
  let mut encoder = GzipEncoder::with_params(params);
  let mut out = Vec::new();
  let mut start = 0;
  for part in 0..parts {
    let end = if part + 1 == parts { rest.len() } else { start + (rest.len() - start) / 2 };
    let input = &rest[start..end];
    start = end;
    out.clear();
    encoder.encode(input, &mut out).unwrap();
    assert!(out.len() <= GzipEncoder::bound(input.len()), "{} > bound {}", out.len(), input.len());
    let mut buf = alloc::vec![0u8; input.len() + 64];
    let (inflated, rc) =
      zlib_rs::decompress_slice(&mut buf, &out, zlib_rs::InflateConfig { window_bits: 31 });
    assert_eq!(rc, zlib_rs::ReturnCode::Ok, "zlib-rs refused the member");
    assert_eq!(inflated, input, "the member inflates to something else");
    let trailer = &out[out.len() - 8..];
    assert_eq!(
      u32::from_le_bytes(trailer[..4].try_into().unwrap()),
      zlib_rs::crc32::crc32(0, input)
    );
    assert_eq!(u32::from_le_bytes(trailer[4..].try_into().unwrap()), input.len() as u32);
  }
}
