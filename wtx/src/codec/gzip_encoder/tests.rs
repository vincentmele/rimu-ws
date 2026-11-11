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

#[cfg_attr(miri, ignore = "slow under Miri; covered natively")]
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

#[cfg_attr(miri, ignore = "slow under Miri; covered natively")]
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

/// A JSON array of `items` objects shaped like the HttpArena dataset items.
pub(crate) fn dataset_json(rng: &mut Rng, items: usize) -> Vec<u8> {
  const CATEGORIES: [&str; 6] = ["electronics", "books", "garden", "toys", "sports", "food"];
  const TAGS: [&str; 8] = ["new", "sale", "popular", "eco", "premium", "limited", "gift", "classic"];
  let mut out = Vec::from(&b"{\"items\":["[..]);
  for id in 0..items {
    let price = rng.below(10_000);
    let quantity = rng.below(50) + 1;
    let item = alloc::format!(
      "{{\"id\":{id},\"name\":\"Item {id}\",\"category\":\"{}\",\"price\":{price},\"quantity\":{quantity},\
       \"active\":{},\"tags\":[\"{}\",\"{}\"],\"rating\":{{\"score\":{},\"count\":{}}},\"total\":{}}}",
      CATEGORIES[rng.below(CATEGORIES.len())],
      rng.below(2) == 0,
      TAGS[rng.below(TAGS.len())],
      TAGS[rng.below(TAGS.len())],
      rng.below(5) + 1,
      rng.below(1_000),
      price * quantity * 4,
    );
    out.extend_from_slice(item.as_bytes());
    out.push(if id + 1 == items { b']' } else { b',' });
  }
  out.extend_from_slice(alloc::format!(",\"count\":{items}}}").as_bytes());
  out
}

#[test]
fn matches_shrink_json() {
  let mut rng = Rng::new(3);
  let input = dataset_json(&mut rng, 50);
  let out = round_trip(&mut GzipEncoder::new(), &input);
  assert!(out.len() * 4 <= input.len(), "{} of {} bytes", out.len(), input.len());
}

#[cfg_attr(miri, ignore = "large inputs")]
#[test]
fn chunk_boundaries_round_trip() {
  let mut rng = Rng::new(4);
  let json = dataset_json(&mut rng, 1_500);
  let mut encoder = GzipEncoder::new();
  for len in [65_533, 65_534, 65_535, 131_068, 200_000] {
    let input: Vec<u8> = json.iter().copied().cycle().take(len).collect();
    let _ = round_trip(&mut encoder, &input);
  }
}

#[cfg_attr(miri, ignore = "large inputs")]
#[test]
fn long_runs_encode_in_linear_time() {
  let mut encoder = GzipEncoder::new();
  let _ = round_trip(&mut encoder, &alloc::vec![b'a'; 200_000]);
  let _ = round_trip(&mut encoder, &b"ab".repeat(100_000));
  let time = |len: usize, encoder: &mut GzipEncoder| {
    let input = b"ab".repeat(len / 2);
    let mut out = Vec::new();
    let begin = std::time::Instant::now();
    for _ in 0..5 {
      out.clear();
      encoder.encode(&input, &mut out).unwrap();
    }
    begin.elapsed()
  };
  let small = time(100_000, &mut encoder);
  let large = time(2_000_000, &mut encoder);
  assert!(large <= small * 20 + core::time::Duration::from_millis(50), "{small:?} vs {large:?}");
}

#[test]
fn reuse_across_sizes_has_no_stale_matches() {
  let mut rng = Rng::new(5);
  let big = dataset_json(&mut rng, 250);
  let mid = dataset_json(&mut rng, 25);
  let mut encoder = GzipEncoder::new();
  let _ = round_trip(&mut encoder, &big);
  let _ = round_trip(&mut encoder, b"tiny input");
  let _ = round_trip(&mut encoder, &mid);
  let mut out = Vec::new();
  encoder.encode(&big, &mut out).unwrap();
  out.truncate(0);
  encoder.encode(&big, &mut out).unwrap();
  assert_eq!(inflate(&out), big);
}

#[test]
fn zero_allocations_after_warm_up() {
  static ALLOCS: crate::sync::AtomicU64 = crate::sync::AtomicU64::new(0);
  let mut rng = Rng::new(6);
  let input = dataset_json(&mut rng, 25);
  let mut encoder = GzipEncoder::new();
  let mut out = Vec::new();
  encoder.encode(&input, &mut out).unwrap();
  out.clear();
  crate::tests::_count_allocations_in(&ALLOCS);
  encoder.encode(&input, &mut out).unwrap();
  crate::tests::_count_allocations_in(&crate::tests::_ALLOCATIONS);
  assert_eq!(ALLOCS.load(core::sync::atomic::Ordering::Relaxed), 0);
  assert_eq!(inflate(&out), input);
}

#[test]
fn lengths_are_limited_and_complete() {
  use crate::codec::gzip_encoder::huffman::{Scratch, code_lengths};
  let mut scratch = Scratch::new();
  let mut fib = [0u32; 40];
  fib[0] = 1;
  fib[1] = 1;
  for i in 2..fib.len() {
    fib[i] = fib[i - 1].saturating_add(fib[i - 2]);
  }
  let cases: [(&[u32], u8); 6] = [
    (&[5; 30], 15),
    (&fib[..30], 15),
    (&fib[..19], 7),
    (&[0, 0, 9, 0], 15),
    (&[3, 0, 7, 0, 0], 15),
    (&[0, 1, 0, 1000, 1, 0, 0, 2, 1, 1], 7),
  ];
  for (freq, max) in cases {
    let mut lengths = [0u8; 40];
    code_lengths(freq, max, &mut lengths[..freq.len()], &mut scratch);
    let used: alloc::vec::Vec<u8> =
      freq.iter().zip(&lengths).filter(|(f, _)| **f > 0).map(|(_, l)| *l).collect();
    assert!(used.iter().all(|&l| l >= 1 && l <= max), "{freq:?}: {lengths:?}");
    assert!(freq.iter().zip(&lengths).all(|(f, l)| (*f == 0) == (*l == 0)), "{freq:?}: {lengths:?}");
    if used.len() == 1 {
      assert_eq!(used[0], 1);
    } else {
      let kraft: u64 = used.iter().map(|&l| 1u64 << (15 - u32::from(l))).sum();
      assert_eq!(kraft, 1 << 15, "{freq:?}: {lengths:?}");
    }
  }
}

fn zlib_l6(input: &[u8]) -> usize {
  let mut buf = alloc::vec![0u8; zlib_rs::compress_bound(input.len()) + 64];
  let config = zlib_rs::DeflateConfig { window_bits: 31, ..zlib_rs::DeflateConfig::new(6) };
  let (out, rc) = zlib_rs::compress_slice(&mut buf, input, config);
  assert_eq!(rc, zlib_rs::ReturnCode::Ok);
  out.len()
}

#[cfg_attr(miri, ignore = "slow under Miri; covered natively")]
#[test]
fn json_is_within_five_percent_of_zlib_l6() {
  let mut rng = Rng::new(7);
  let mut encoder = GzipEncoder::new();
  for items in [25, 40, 50] {
    let input = dataset_json(&mut rng, items);
    let ours = round_trip(&mut encoder, &input).len();
    let zlib = zlib_l6(&input);
    assert!(ours * 100 <= zlib * 105, "{items} items: {ours} vs zlib {zlib}");
  }
}

#[cfg_attr(miri, ignore = "large inputs")]
#[test]
fn random_input_stays_within_bound() {
  let mut rng = Rng::new(8);
  let mut encoder = GzipEncoder::new();
  for _ in 0..50 {
    let len = rng.below(100_000) + 1;
    let input = rng.bytes(len);
    let out = round_trip(&mut encoder, &input);
    assert!(out.len() <= GzipEncoder::bound(len) && out.len() >= len, "{len}: {}", out.len());
  }
}

#[test]
fn block_type_is_the_cheapest() {
  use crate::codec::gzip_encoder::BlockType;
  let mut rng = Rng::new(9);
  let mut encoder = GzipEncoder::new();
  let _ = round_trip(&mut encoder, &dataset_json(&mut rng, 25));
  assert_eq!(encoder.last_block_types(), [BlockType::Dynamic]);
  let _ = round_trip(&mut encoder, b"a short text, twenty");
  assert_eq!(encoder.last_block_types(), [BlockType::Fixed]);
  let _ = round_trip(&mut encoder, &rng.bytes(4_000));
  assert_eq!(encoder.last_block_types(), [BlockType::Stored]);
}

#[cfg_attr(miri, ignore = "slow under Miri; covered natively")]
#[test]
fn check_bytes_accepts_a_seed_corpus() {
  use crate::codec::gzip_encoder::check::check_bytes;
  let mut rng = Rng::new(10);
  for _ in 0..200 {
    let len = rng.below(4_000);
    check_bytes(&rng.bytes(len));
  }
  for items in [1, 25, 50] {
    let mut data = alloc::vec![4, 0, 32, 0, 8, 0, 4, 1];
    data.extend_from_slice(&dataset_json(&mut rng, items));
    check_bytes(&data);
  }
  check_bytes(&[]);
  check_bytes(&[0xff; 9]);
}
