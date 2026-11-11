use crate::codec::{GzipEncoder, GzipParams};
use alloc::vec::Vec;

/// A small xorshift generator: the tests are deterministic.
pub(crate) struct Rng(u64);

impl Rng {
  pub(crate) fn new(seed: u64) -> Self {
    Self(seed | 1)
  }

  pub(crate) fn next(&mut self) -> u64 {
    self.0 ^= self.0 << 13;
    self.0 ^= self.0 >> 7;
    self.0 ^= self.0 << 17;
    self.0
  }

  pub(crate) fn below(&mut self, n: usize) -> usize {
    usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap()).unwrap()
  }

  pub(crate) fn bytes(&mut self, len: usize) -> Vec<u8> {
    (0..len).map(|_| self.next().to_le_bytes()[0]).collect()
  }
}

/// JSON-like text: words from a small vocabulary with punctuation, of `len` bytes.
pub(crate) fn jsonish(rng: &mut Rng, len: usize) -> Vec<u8> {
  const WORDS: [&[u8]; 12] = [
    b"{\"id\":", b"\"name\":\"", b"Item ", b"\",\"category\":\"", b"electronics", b"\"price\":",
    b"\"quantity\":", b"\"active\":true,", b"\"tags\":[\"", b"\"rating\":{", b"}],", b"\"total\":",
  ];
  let mut out = Vec::with_capacity(len + 32);
  while out.len() < len {
    out.extend_from_slice(WORDS[rng.below(WORDS.len())]);
    out.extend_from_slice(alloc::format!("{}", rng.below(100_000)).as_bytes());
    out.push(b',');
  }
  out.truncate(len);
  out
}

/// Inflates a gzip member with both decoders, checks the trailer, and returns the payload.
#[track_caller]
pub(crate) fn inflate(member: &[u8]) -> Vec<u8> {
  assert!(member.len() >= 18, "a member has a 10-byte header and an 8-byte trailer");
  assert_eq!(&member[..10], &[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3]);
  let raw = &member[10..member.len() - 8];
  let miniz = miniz_oxide::inflate::decompress_to_vec(raw).expect("miniz_oxide inflates the deflate stream");
  let mut buf = alloc::vec![0u8; miniz.len() + 64];
  let (out, rc) = zlib_rs::decompress_slice(
    &mut buf,
    member,
    zlib_rs::InflateConfig { window_bits: 31 },
  );
  assert_eq!(rc, zlib_rs::ReturnCode::Ok, "zlib-rs inflates the gzip member");
  assert_eq!(out, &miniz[..], "both decoders agree");
  let trailer = &member[member.len() - 8..];
  let crc = u32::from_le_bytes(trailer[..4].try_into().unwrap());
  let isize = u32::from_le_bytes(trailer[4..].try_into().unwrap());
  assert_eq!(crc, zlib_rs::crc32::crc32(0, &miniz), "trailer CRC32");
  assert_eq!(isize, u32::try_from(miniz.len() & 0xffff_ffff).unwrap(), "trailer ISIZE");
  miniz
}

#[track_caller]
pub(crate) fn round_trip(encoder: &mut GzipEncoder, input: &[u8]) -> Vec<u8> {
  let mut out = Vec::new();
  encoder.encode(input, &mut out).unwrap();
  assert_eq!(inflate(&out), input);
  out
}

#[test]
fn empty_and_one_byte_inputs_round_trip() {
  let mut encoder = GzipEncoder::new();
  let _ = round_trip(&mut encoder, b"");
  let _ = round_trip(&mut encoder, b"x");
}

#[test]
fn literals_round_trip() {
  let mut rng = Rng::new(1);
  let mut encoder = GzipEncoder::new();
  for _ in 0..1_000 {
    let len = rng.below(8_001);
    let input = jsonish(&mut rng, len);
    let _ = round_trip(&mut encoder, &input);
  }
}

#[test]
fn encode_appends() {
  let mut out = b"abc".to_vec();
  GzipEncoder::new().encode(b"hello hello hello", &mut out).unwrap();
  assert_eq!(&out[..3], b"abc");
  assert_eq!(inflate(&out[3..]), b"hello hello hello");
}

#[test]
fn bound_holds() {
  let mut rng = Rng::new(2);
  let mut encoder = GzipEncoder::with_params(GzipParams::default());
  for len in [0, 1, 100, 65_534, 65_535, 200_000] {
    let input = rng.bytes(len);
    let out = round_trip(&mut encoder, &input);
    assert!(out.len() <= GzipEncoder::bound(len), "len {len}: {} > {}", out.len(), GzipEncoder::bound(len));
  }
}
