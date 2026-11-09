//! The SETTINGS frame (RFC 9114 section 7.2.4) with the parameters that this implementation uses:
//! the two of QPACK (RFC 9204 section 5) and `SETTINGS_MAX_FIELD_SECTION_SIZE`.

use crate::{
  http3::{H3ErrorCode, H3FrameTy, Http3Error, encode_frame_header},
  quic::{decode_varint, encode_varint, varint_len},
};
use core::hint::cold_path;

const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const QPACK_BLOCKED_STREAMS: u64 = 0x07;
/// Parameters of one frame that are checked for duplicates; a frame with more is refused.
const MAX_PARAMETERS: usize = 64;

/// The settings of an endpoint that this implementation reads and writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct H3Settings {
  /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (0x01).
  pub(crate) qpack_max_table_capacity: u64,
  /// `SETTINGS_QPACK_BLOCKED_STREAMS` (0x07).
  pub(crate) qpack_blocked_streams: u64,
  /// `SETTINGS_MAX_FIELD_SECTION_SIZE` (0x06), `None` for unlimited.
  pub(crate) max_field_section_size: Option<u64>,
}

impl H3Settings {
  /// The values that apply before the SETTINGS frame of the peer arrives: no dynamic table, no
  /// blocked streams, no limit on field sections.
  pub(crate) const fn new() -> Self {
    Self { qpack_max_table_capacity: 0, qpack_blocked_streams: 0, max_field_section_size: None }
  }

  /// Reads the payload of a SETTINGS frame, the bytes after its header.
  ///
  /// Parameters that this implementation does not know are ignored (RFC 9114 section 7.2.4). An
  /// identifier that appears twice, or one that HTTP/2 used and HTTP/3 reserves (0x02 to 0x05),
  /// is an `H3_SETTINGS_ERROR`; a payload that ends inside a parameter an `H3_FRAME_ERROR`.
  pub(crate) fn decode(payload: &[u8]) -> crate::Result<Self> {
    let mut settings = Self::new();
    let mut seen = [0u64; MAX_PARAMETERS];
    let mut seen_len = 0usize;
    let mut rest = payload;
    while !rest.is_empty() {
      let Some((id, id_len)) = decode_varint(rest) else {
        return Err(malformed());
      };
      let Some((value, value_len)) = decode_varint(rest.get(id_len..).unwrap_or_default()) else {
        return Err(malformed());
      };
      rest = rest.get(id_len.wrapping_add(value_len)..).unwrap_or_default();
      if seen.get(..seen_len).unwrap_or_default().contains(&id) {
        cold_path();
        return Err(crate::Error::Http3Close(
          H3ErrorCode::SettingsError,
          Http3Error::DuplicateSetting,
        ));
      }
      let Some(slot) = seen.get_mut(seen_len) else {
        cold_path();
        return Err(crate::Error::Http3Close(
          H3ErrorCode::ExcessiveLoad,
          Http3Error::TooManySettings,
        ));
      };
      *slot = id;
      seen_len = seen_len.wrapping_add(1);
      match id {
        QPACK_MAX_TABLE_CAPACITY => settings.qpack_max_table_capacity = value,
        MAX_FIELD_SECTION_SIZE => settings.max_field_section_size = Some(value),
        QPACK_BLOCKED_STREAMS => settings.qpack_blocked_streams = value,
        0x02..=0x05 => {
          cold_path();
          return Err(crate::Error::Http3Close(
            H3ErrorCode::SettingsError,
            Http3Error::ReservedSetting,
          ));
        }
        _ => {}
      }
    }
    Ok(settings)
  }

  /// Writes the whole SETTINGS frame, header included, at the start of `out`: the two QPACK
  /// parameters and, if it has a value, `SETTINGS_MAX_FIELD_SECTION_SIZE`; nothing GREASE.
  ///
  /// Returns the number of written bytes, or `None` if `out` is too small or a value does not fit
  /// in a variable-length integer.
  pub(crate) fn encode(&self, out: &mut [u8]) -> Option<usize> {
    let parameters = [
      Some((QPACK_MAX_TABLE_CAPACITY, self.qpack_max_table_capacity)),
      Some((QPACK_BLOCKED_STREAMS, self.qpack_blocked_streams)),
      self.max_field_section_size.map(|el| (MAX_FIELD_SECTION_SIZE, el)),
    ];
    let payload_len = parameters.iter().flatten().fold(0usize, |acc, (id, value)| {
      acc.wrapping_add(varint_len(*id)).wrapping_add(varint_len(*value))
    });
    let mut len = encode_frame_header(H3FrameTy::Settings, u64::try_from(payload_len).ok()?, out)?;
    for (id, value) in parameters.iter().flatten() {
      len = len.wrapping_add(encode_varint(*id, out.get_mut(len..)?)?);
      len = len.wrapping_add(encode_varint(*value, out.get_mut(len..)?)?);
    }
    Some(len)
  }
}

#[cold]
fn malformed() -> crate::Error {
  crate::Error::Http3Close(H3ErrorCode::FrameError, Http3Error::MalformedFrame)
}

#[cfg(test)]
mod tests {
  use crate::{
    Error,
    http3::{H3ErrorCode, H3FrameTy, H3Settings, Http3Error, decode_frame_header},
  };
  use alloc::vec::Vec;

  fn rejects(payload: &[u8], code: H3ErrorCode, error: Http3Error) -> bool {
    matches!(H3Settings::decode(payload), Err(Error::Http3Close(el, err)) if el == code && err == error)
  }

  #[test]
  fn h3_settings_reject_duplicates_and_h2_ids() {
    // What a server advertises, read back
    let ours = H3Settings {
      qpack_max_table_capacity: 4096,
      qpack_blocked_streams: 100,
      max_field_section_size: Some(16_384),
    };
    let mut out = [0u8; 64];
    let len = ours.encode(&mut out).unwrap();
    let frame = out.get(..len).unwrap();
    let payload = hexd!(b"0150000740640680004000");
    let mut expected = alloc::vec![0x04, 0x0b];
    expected.extend_from_slice(&payload);
    assert_eq!(frame, expected.as_slice());
    assert_eq!(decode_frame_header(frame).unwrap(), Some((H3FrameTy::Settings, 11, 2)));
    assert_eq!(H3Settings::decode(&payload).unwrap(), ours);
    // Without a field section limit, the parameter is left out
    let unlimited = H3Settings { max_field_section_size: None, ..ours };
    let len = unlimited.encode(&mut out).unwrap();
    assert_eq!(out.get(..len).unwrap(), &hexd!(b"0406015000074064"));
    assert_eq!(H3Settings::decode(out.get(2..len).unwrap()).unwrap(), unlimited);
    assert_eq!(ours.encode(&mut [0u8; 12]), None);
    // An empty payload leaves the initial values
    assert_eq!(H3Settings::decode(&[]).unwrap(), H3Settings::new());

    // The same identifier twice, known or not
    assert!(rejects(&hexd!(b"01000100"), H3ErrorCode::SettingsError, Http3Error::DuplicateSetting));
    assert!(rejects(
      &hexd!(b"060107000601"),
      H3ErrorCode::SettingsError,
      Http3Error::DuplicateSetting
    ));
    assert!(rejects(&hexd!(b"21002105"), H3ErrorCode::SettingsError, Http3Error::DuplicateSetting));
    // The identifiers of HTTP/2 that HTTP/3 reserves
    for id in [0x02, 0x03, 0x04, 0x05] {
      assert!(rejects(&[id, 0x00], H3ErrorCode::SettingsError, Http3Error::ReservedSetting));
      assert!(rejects(
        &[0x01, 0x00, id, 0x01],
        H3ErrorCode::SettingsError,
        Http3Error::ReservedSetting
      ));
    }
    // Unknown identifiers are ignored: 0x00 (reserved, never an HTTP/2 setting), 0x08
    // (ENABLE_CONNECT_PROTOCOL), 0x21 (GREASE), 0x33 (H3_DATAGRAM)
    assert_eq!(
      H3Settings::decode(&hexd!(b"0001080121053301010a")).unwrap(),
      H3Settings { qpack_max_table_capacity: 10, ..H3Settings::new() }
    );
    // A payload that ends inside a parameter
    for payload in [&[0x01][..], &[0x01, 0x40], &[0x40]] {
      assert!(rejects(payload, H3ErrorCode::FrameError, Http3Error::MalformedFrame));
    }
    // Up to 64 parameters are checked; more are refused
    let mut many = Vec::new();
    for id in 0..64u8 {
      many.extend_from_slice(&[0x40, id.wrapping_add(0x40), 0x00]);
    }
    assert_eq!(H3Settings::decode(&many).unwrap(), H3Settings::new());
    many.extend_from_slice(&[0x40, 0xa0, 0x00]);
    assert!(rejects(&many, H3ErrorCode::ExcessiveLoad, Http3Error::TooManySettings));
  }
}
