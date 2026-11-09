//! The QPACK encoder of responses: static table only, never the dynamic table (spec 5.9), so the
//! peer's decoder never blocks and never acknowledges anything.

use crate::{
  collections::VectorUsize,
  http::prefix_int::encode_prefix_int,
  http3::{
    Http3Error,
    qpack::static_table::{find_exact, find_name},
  },
};
use core::hint::cold_path;

/// Appends to `out` the encoded field section of `fields`, in their order.
///
/// The section has a Required Insert Count of 0 and a Base of 0 (RFC 9204 section 4.5.1). A field
/// whose name and value are in the static table is an indexed field line; one whose name only is
/// there a literal with a static name reference; any other a literal with a literal name.
/// Literals are written raw, without Huffman coding.
pub(crate) fn encode_static(
  fields: &[(&[u8], &[u8])],
  out: &mut VectorUsize<u8>,
) -> crate::Result<()> {
  // Required Insert Count 0; Sign 0 and Delta Base 0
  out.extend_from_copyable_slice(&[0, 0])?;
  for (name, value) in fields {
    if let Some(idx) = find_exact(name, value) {
      // Indexed Field Line, T = 1 (RFC 9204 section 4.5.2)
      push_int(out, idx.into(), 6, 0b1100_0000)?;
    } else if let Some(idx) = find_name(name) {
      // Literal Field Line with Name Reference, N = 0, T = 1 (section 4.5.4)
      push_int(out, idx.into(), 4, 0b0101_0000)?;
      push_raw_string(out, value, 8, 0)?;
    } else {
      // Literal Field Line with Literal Name, N = 0 (section 4.5.6)
      push_raw_string(out, name, 4, 0b0010_0000)?;
      push_raw_string(out, value, 8, 0)?;
    }
  }
  Ok(())
}

fn push_int(
  out: &mut VectorUsize<u8>,
  value: u64,
  prefix_bits: u8,
  flags: u8,
) -> crate::Result<()> {
  let mut buffer = [0u8; 10];
  let Some(len) = encode_prefix_int(value, prefix_bits, flags, &mut buffer) else {
    cold_path();
    return Err(crate::Error::Http3(Http3Error::IntegerOverflow));
  };
  out.extend_from_copyable_slice(buffer.get(..len).unwrap_or_default())?;
  Ok(())
}

// A string literal with a prefix of `prefix_bits` bits whose highest one, the Huffman bit, is 0
// (RFC 9204 section 4.1.2).
fn push_raw_string(
  out: &mut VectorUsize<u8>,
  bytes: &[u8],
  prefix_bits: u8,
  flags: u8,
) -> crate::Result<()> {
  let Ok(len) = u64::try_from(bytes.len()) else {
    cold_path();
    return Err(crate::Error::Http3(Http3Error::IntegerOverflow));
  };
  push_int(out, len, prefix_bits.wrapping_sub(1), flags)?;
  out.extend_from_copyable_slice(bytes)?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use crate::{
    collections::VectorUsize,
    http3::qpack::{DecodeOutcome, QpackDecoder, encode_static},
  };
  use alloc::vec::Vec;

  #[test]
  fn encode_static_round_trips_through_decoder() {
    let long = [b'x'; 200];
    let fields: [(&[u8], &[u8]); 10] = [
      // Exact static entries
      (b":status", b"200"),
      (b"content-type", b"text/plain;charset=utf-8"),
      (b"content-encoding", b"br"),
      (b"vary", b"accept-encoding"),
      // An exact entry above the 6-bit prefix (71)
      (b":status", b"500"),
      // Static names with other values, below and above the 4-bit prefix (4 and 92)
      (b"content-length", b"13"),
      (b"server", b"rimu"),
      // A name that is not in the table, with an empty value and with a value of 200 bytes
      (b"x-custom", b""),
      (b"x-custom-long-name", &long),
      (b"date", b"Mon, 09 Nov 2026 08:00:00 GMT"),
    ];
    let mut out = VectorUsize::new();
    out.extend_from_copyable_slice(b"before").unwrap();
    encode_static(&fields, &mut out).unwrap();
    // Appended after what was there; RIC 0 and Base 0, then the field lines
    let section = out.as_slice().get(6..).unwrap();
    assert_eq!(out.as_slice().get(..6).unwrap(), b"before");
    let expected_head: [u8; 7] = [0x00, 0x00, 0xd9, 0xf6, 0xea, 0xfb, 0xff];
    assert_eq!(section.get(..7).unwrap(), &expected_head);
    // 0xff 0x08: 71 = 63 + 8 in a 6-bit prefix; then `content-length: 13` as 0x54 0x02 "13"
    assert_eq!(section.get(7..12).unwrap(), &[0x08, 0x54, 0x02, b'1', b'3']);
    // `server: rimu`: 92 = 15 + 77 in a 4-bit prefix, raw value
    assert_eq!(section.get(12..19).unwrap(), &[0x5f, 0x4d, 0x04, b'r', b'i', b'm', b'u']);
    // `x-custom` with a literal name: 0x27 is 001, N=0, H=0 and 7 filling the 3-bit prefix; 8 = 7 + 1
    assert_eq!(section.get(19..21).unwrap(), &[0x27, 0x01]);

    let mut decoder = QpackDecoder::new(0, 0).unwrap();
    let mut scratch = VectorUsize::new();
    let mut decoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let outcome = decoder
      .decode(0, section, &mut scratch, &mut |name, value| {
        decoded.push((name.to_vec(), value.to_vec()));
        Ok(())
      })
      .unwrap();
    assert_eq!(outcome, DecodeOutcome::Done { referenced_dynamic: false });
    assert_eq!(decoded.len(), fields.len());
    for ((name, value), (expected_name, expected_value)) in decoded.iter().zip(fields) {
      assert_eq!((name.as_slice(), value.as_slice()), (expected_name, expected_value));
    }
    // Nothing to acknowledge
    assert_eq!(decoder.decoder_stream_output(), b"");
  }
}
