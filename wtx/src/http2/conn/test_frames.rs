//! Builders and a parser for raw HTTP/2 frames, for tests that talk to the connection core in
//! bytes.

use alloc::vec::Vec;

/// One frame: 9-byte header and `payload`.
pub(crate) fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
  let len = u32::try_from(payload.len()).unwrap();
  let [_, l0, l1, l2] = len.to_be_bytes();
  let mut out = Vec::with_capacity(9 + payload.len());
  out.extend_from_slice(&[l0, l1, l2, ty, flags]);
  out.extend_from_slice(&(stream & 0x7FFF_FFFF).to_be_bytes());
  out.extend_from_slice(payload);
  out
}

/// SETTINGS with the given (identifier, value) pairs.
pub(crate) fn settings(pairs: &[(u16, u32)]) -> Vec<u8> {
  let mut payload = Vec::new();
  for (id, value) in pairs {
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(&value.to_be_bytes());
  }
  frame(4, 0, 0, &payload)
}

/// A request HEADERS frame (END_HEADERS set) with every field as an HPACK literal without
/// indexing and without Huffman coding.
pub(crate) fn headers_req(
  stream: u32,
  method: &str,
  path: &str,
  extra: &[(&str, &str)],
  end_stream: bool,
) -> Vec<u8> {
  let mut block = Vec::new();
  for (name, value) in
    [(":method", method), (":scheme", "http"), (":path", path), (":authority", "localhost")]
      .into_iter()
      .chain(extra.iter().copied())
  {
    literal(&mut block, name, value);
  }
  frame(1, 0b100 | u8::from(end_stream), stream, &block)
}

/// A DATA frame.
pub(crate) fn data(stream: u32, bytes: &[u8], end_stream: bool) -> Vec<u8> {
  frame(0, u8::from(end_stream), stream, bytes)
}

/// Every complete frame in `bytes` as (type, flags, stream, payload). Panics on a trailing
/// partial frame.
pub(crate) fn parse_all(mut bytes: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
  let mut out = Vec::new();
  while !bytes.is_empty() {
    let [l0, l1, l2, ty, flags, s0, s1, s2, s3, rest @ ..] = bytes else {
      panic!("partial frame header: {bytes:?}");
    };
    let len = usize::try_from(u32::from_be_bytes([0, *l0, *l1, *l2])).unwrap();
    let stream = u32::from_be_bytes([*s0, *s1, *s2, *s3]) & 0x7FFF_FFFF;
    out.push((*ty, *flags, stream, rest[..len].to_vec()));
    bytes = &rest[len..];
  }
  out
}

fn literal(block: &mut Vec<u8>, name: &str, value: &str) {
  block.push(0);
  string(block, name.as_bytes());
  string(block, value.as_bytes());
}

fn string(block: &mut Vec<u8>, bytes: &[u8]) {
  integer(block, 0, 7, bytes.len());
  block.extend_from_slice(bytes);
}

fn integer(block: &mut Vec<u8>, first: u8, prefix: u32, mut n: usize) {
  let max = (1usize << prefix) - 1;
  if n < max {
    block.push(first | u8::try_from(n).unwrap());
    return;
  }
  block.push(first | u8::try_from(max).unwrap());
  n -= max;
  while n >= 128 {
    block.push(u8::try_from(n % 128).unwrap() | 0x80);
    n /= 128;
  }
  block.push(u8::try_from(n).unwrap());
}
