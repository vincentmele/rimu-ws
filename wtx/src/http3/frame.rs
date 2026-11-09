//! HTTP/3 frame headers (RFC 9114 section 7.1): a type and a payload length, both variable-length
//! integers.

use crate::{
  http3::{H3ErrorCode, Http3Error},
  quic::{decode_varint, encode_varint},
};
use core::hint::cold_path;

/// The type of an HTTP/3 frame (RFC 9114 section 7.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum H3FrameTy {
  /// 0x00
  Data,
  /// 0x01
  Headers,
  /// 0x03
  CancelPush,
  /// 0x04
  Settings,
  /// 0x05
  PushPromise,
  /// 0x07
  Goaway,
  /// 0x0d
  MaxPushId,
  /// A type that this implementation does not know, such as the reserved `0x1f * N + 0x21`: the
  /// frame is skipped (RFC 9114 section 9).
  Unknown(u64),
}

impl H3FrameTy {
  /// The value that goes on the wire.
  #[inline]
  pub(crate) const fn code(self) -> u64 {
    match self {
      Self::Data => 0x00,
      Self::Headers => 0x01,
      Self::CancelPush => 0x03,
      Self::Settings => 0x04,
      Self::PushPromise => 0x05,
      Self::Goaway => 0x07,
      Self::MaxPushId => 0x0d,
      Self::Unknown(code) => code,
    }
  }

  /// The type of a value that came from the wire. The types that HTTP/2 used and HTTP/3 reserves
  /// are an `H3_FRAME_UNEXPECTED` (RFC 9114 section 7.2.8).
  #[inline]
  pub(crate) fn from_code(code: u64) -> crate::Result<Self> {
    Ok(match code {
      0x00 => Self::Data,
      0x01 => Self::Headers,
      0x03 => Self::CancelPush,
      0x04 => Self::Settings,
      0x05 => Self::PushPromise,
      0x07 => Self::Goaway,
      0x0d => Self::MaxPushId,
      0x02 | 0x06 | 0x08 | 0x09 => {
        cold_path();
        return Err(crate::Error::Http3Close(
          H3ErrorCode::FrameUnexpected,
          Http3Error::ReservedFrameType,
        ));
      }
      _ => Self::Unknown(code),
    })
  }
}

/// Reads the frame header at the start of `bytes`: the type, the payload length (at most
/// 2^62 - 1) and the number of bytes of the header.
///
/// Returns `None` if `bytes` ends before the header does. The types that HTTP/2 used and HTTP/3
/// reserves (0x02, 0x06, 0x08 and 0x09) are an error, `H3_FRAME_UNEXPECTED` (RFC 9114 section
/// 7.2.8), as soon as the type is read.
#[inline]
pub(crate) fn decode_frame_header(bytes: &[u8]) -> crate::Result<Option<(H3FrameTy, u64, usize)>> {
  let Some((code, ty_len)) = decode_varint(bytes) else {
    return Ok(None);
  };
  let ty = H3FrameTy::from_code(code)?;
  let Some((len, len_len)) = decode_varint(bytes.get(ty_len..).unwrap_or_default()) else {
    return Ok(None);
  };
  Ok(Some((ty, len, ty_len.wrapping_add(len_len))))
}

/// Writes the header of a frame of type `ty` whose payload has `len` bytes at the start of `out`.
///
/// Returns the number of written bytes, or `None` if `out` is too small or a value does not fit in
/// a variable-length integer.
#[inline]
pub(crate) fn encode_frame_header(ty: H3FrameTy, len: u64, out: &mut [u8]) -> Option<usize> {
  let ty_len = encode_varint(ty.code(), out)?;
  let len_len = encode_varint(len, out.get_mut(ty_len..)?)?;
  Some(ty_len.wrapping_add(len_len))
}

#[cfg(test)]
mod tests {
  use crate::{
    Error,
    http3::{H3ErrorCode, H3FrameTy, Http3Error, decode_frame_header, encode_frame_header},
    quic::VARINT_MAX,
  };

  #[test]
  fn h3_frame_headers_decode_known_reserved_and_unknown_types() {
    let known = [
      (0x00, H3FrameTy::Data),
      (0x01, H3FrameTy::Headers),
      (0x03, H3FrameTy::CancelPush),
      (0x04, H3FrameTy::Settings),
      (0x05, H3FrameTy::PushPromise),
      (0x07, H3FrameTy::Goaway),
      (0x0d, H3FrameTy::MaxPushId),
    ];
    for (code, ty) in known {
      // The payload that follows is not read
      assert_eq!(decode_frame_header(&[code, 0x05, 0xff]).unwrap(), Some((ty, 5, 2)));
      let mut out = [0u8; 16];
      assert_eq!(encode_frame_header(ty, 5, &mut out), Some(2));
      assert_eq!(out.get(..2).unwrap(), &[code, 0x05]);
    }
    // Reserved since HTTP/2: an error before the length arrives
    for code in [0x02, 0x06, 0x08, 0x09] {
      for bytes in [&[code][..], &[code, 0x00][..]] {
        assert!(matches!(
          decode_frame_header(bytes),
          Err(Error::Http3Close(H3ErrorCode::FrameUnexpected, Http3Error::ReservedFrameType))
        ));
      }
    }
    // Reserved for greasing (0x21, 0x40, 0x1f * 5 + 0x21 = 0xbe) and unassigned types are unknown
    assert_eq!(decode_frame_header(&[0x21, 0x00]).unwrap(), Some((H3FrameTy::Unknown(0x21), 0, 2)));
    assert_eq!(
      decode_frame_header(&[0x40, 0x40, 0x03]).unwrap(),
      Some((H3FrameTy::Unknown(0x40), 3, 3))
    );
    assert_eq!(
      decode_frame_header(&[0x40, 0xbe, 0x00]).unwrap(),
      Some((H3FrameTy::Unknown(0xbe), 0, 3))
    );
    assert_eq!(decode_frame_header(&[0x0a, 0x01]).unwrap(), Some((H3FrameTy::Unknown(0x0a), 1, 2)));
    // The largest length, and headers that are not complete yet
    let mut out = [0u8; 16];
    let len = encode_frame_header(H3FrameTy::Data, VARINT_MAX, &mut out).unwrap();
    assert_eq!(len, 9);
    assert_eq!(
      decode_frame_header(out.get(..len).unwrap()).unwrap(),
      Some((H3FrameTy::Data, VARINT_MAX, 9))
    );
    for bytes in [&[][..], &[0x01], &[0x40], &[0x01, 0x40], &[0x00, 0xc0, 0, 0, 0, 0, 0, 0]] {
      assert_eq!(decode_frame_header(bytes).unwrap(), None);
    }
    // What does not fit
    assert_eq!(encode_frame_header(H3FrameTy::Data, VARINT_MAX + 1, &mut out), None);
    assert_eq!(encode_frame_header(H3FrameTy::Headers, 64, &mut [0u8; 2]), None);
  }
}
