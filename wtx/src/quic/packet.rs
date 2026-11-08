//! Packet headers (RFC 9000 section 17 and RFC 8999), packet numbers (RFC 9000 appendix A) and
//! the packets that need no connection state: Version Negotiation and Retry.

use crate::{
  crypto::{AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadKey as _, Aes128GcmKeyGlobal},
  quic::{
    MAX_CID_LEN, QuicError,
    varint::{VARINT_MAX, decode_varint},
    writer::Writer,
  },
};
use core::hint::cold_path;

/// The only version that this implementation speaks.
pub(crate) const QUIC_V1: u32 = 1;

// The first byte of a Retry packet: long header, fixed bit, type 3 and arbitrary unused bits
const RETRY_FIRST_BYTE: u8 = 0xff;
// RFC 9001 section 5.8: the key and the nonce that compute the integrity tag of version 1 Retry
// packets are public constants.
const RETRY_KEY: [u8; 16] = hexd!(b"be0c690b9f66575a1d766b54e368c84e");
const RETRY_NONCE: [u8; AEAD_NONCE_LEN] = hexd!(b"461599d35d632bf2239825bb");
// The most significant bit is set and so is the fixed bit that servers should mimic in packets
// that do not have one
const VERSION_NEGOTIATION_FIRST_BYTE: u8 = 0xc0;
// The packet number takes between one and four bytes. The header protection sample starts four
// bytes after the first of them and has 16 bytes (RFC 9001 section 5.4.2), so everything after the
// header must be at least as long as that.
const MIN_PROTECTED_LEN: usize = 4 + 16;

/// The kind of a packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketTy {
  /// Long header, carries the first CRYPTO frames and a token.
  Initial,
  /// Long header, early data.
  ZeroRtt,
  /// Long header, carries the rest of the handshake.
  Handshake,
  /// Long header, sent by servers to make a client prove its address.
  Retry,
  /// Short header, protected with the 1-RTT keys.
  OneRtt,
  /// Long header with version zero, sent by servers that do not speak the version of a client.
  VersionNegotiation,
  /// Long header of a version other than 0 and 1. Only the version, the destination CID, the
  /// source CID and `packet_end` of its [`PacketHeader`] are meaningful (RFC 8999).
  UnknownVersion,
}

/// The part of the header of a packet that is readable while header protection is still applied.
///
/// Header protection covers the low bits of the first byte and the packet number, so neither the
/// length of the packet number nor the key phase are known yet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketHeader<'datagram> {
  /// See [`PacketTy`].
  pub ty: PacketTy,
  /// The version of a long header. Short headers have none, so version 1, the only one that
  /// defines them here, is reported instead.
  pub version: u32,
  /// The destination connection ID. In short headers, it has the length that the caller expects.
  pub dcid: &'datagram [u8],
  /// The source connection ID. Short headers have none.
  pub scid: &'datagram [u8],
  /// The token of an Initial packet or of a Retry packet. Empty for everything else.
  pub token: &'datagram [u8],
  /// The index of the first byte of the packet number. For packets that have none (Retry,
  /// Version Negotiation and unknown versions), it is the same as `packet_end`.
  pub pn_offset: usize,
  /// The index after the last byte of the packet. Long headers of a known type say how long the
  /// packet is so that another packet can follow, short headers go to the end of the datagram.
  pub packet_end: usize,
}

/// Parses the header of the first packet of `datagram` without removing header protection.
///
/// `short_dcid_len` is the length of the connection IDs that this endpoint issues because short
/// headers do not carry it.
///
/// Every length is checked against the datagram. Packets that are too short to be unprotected are
/// refused, as well as version 1 packets that have the fixed bit cleared or CIDs of more than 20
/// bytes. Whether the version is supported and whether the datagram is long enough for an Initial
/// is for the caller to decide.
pub(crate) fn parse_header(
  datagram: &[u8],
  short_dcid_len: usize,
) -> crate::Result<PacketHeader<'_>> {
  let Some(&first) = datagram.first() else {
    return Err(error(QuicError::Truncated));
  };
  if first & 0x80 == 0 {
    parse_short(datagram, first, short_dcid_len)
  } else {
    parse_long(datagram, first)
  }
}

/// Reconstructs the full packet number out of its `pn_len` (1 to 4) truncated bytes, where
/// `largest` is the largest packet number received so far in the packet number space (RFC 9000
/// appendix A.3).
pub(crate) fn decode_pn(largest: Option<u64>, truncated: u64, pn_len: usize) -> u64 {
  let expected = largest.map_or(0, |elem| elem.saturating_add(1));
  let pn_win = 1u64 << pn_len.clamp(1, 4).wrapping_mul(8);
  let pn_hwin = pn_win >> 1;
  let pn_mask = pn_win.wrapping_sub(1);
  let candidate = (expected & !pn_mask) | (truncated & pn_mask);
  if candidate.saturating_add(pn_hwin) <= expected && candidate < (VARINT_MAX + 1) - pn_win {
    return candidate.wrapping_add(pn_win);
  }
  if candidate > expected.saturating_add(pn_hwin) && candidate >= pn_win {
    return candidate.wrapping_sub(pn_win);
  }
  candidate
}

/// The number of bytes (1 to 4) that the packet number `pn` should take given the largest packet
/// number that the peer acknowledged, so that the peer can decode it (RFC 9000 appendix A.2).
pub(crate) fn pn_len_for(pn: u64, largest_acked: Option<u64>) -> usize {
  let unacked = match largest_acked {
    Some(elem) => pn.wrapping_sub(elem),
    None => pn.saturating_add(1),
  };
  // One more bit to represent twice the range
  let min_bits = 64u32.wrapping_sub(unacked.leading_zeros()).wrapping_add(1);
  usize::try_from(min_bits.div_ceil(8)).unwrap_or(4).clamp(1, 4)
}

/// Writes a Version Negotiation packet that offers version 1, the only one supported.
///
/// `dcid` and `scid` are the connection IDs of the packet that is written, so, as RFC 9000
/// section 17.2.1 requires, the source CID and the destination CID of the packet that is answered,
/// in this order.
///
/// Returns the number of written bytes, which is zero if a CID has more than 255 bytes or `out` is
/// too small.
pub(crate) fn write_version_negotiation(dcid: &[u8], scid: &[u8], out: &mut [u8]) -> usize {
  write_version_negotiation_inner(dcid, scid, out).unwrap_or_default()
}

/// Writes a Retry packet (RFC 9000 section 17.2.5) with its integrity tag (RFC 9001 section 5.8).
///
/// `dcid` and `scid` are the connection IDs of the packet that is written: the source CID of the
/// client's Initial and the CID that the client must use from now on, in this order. `odcid` is
/// the destination CID of the client's Initial, which is not sent but is part of the integrity
/// tag. `out` needs `odcid.len() + 1` bytes more than the packet while the tag is computed.
///
/// Returns the number of written bytes.
pub(crate) fn write_retry(
  dcid: &[u8],
  scid: &[u8],
  odcid: &[u8],
  token: &[u8],
  out: &mut [u8],
) -> crate::Result<usize> {
  let (Ok(dcid_len), Ok(scid_len), Ok(odcid_len)) =
    (u8::try_from(dcid.len()), u8::try_from(scid.len()), u8::try_from(odcid.len()))
  else {
    return Err(error(QuicError::CidTooLong));
  };
  // Everything but the tag
  let packet_len = 1usize
    .wrapping_add(4)
    .wrapping_add(1)
    .wrapping_add(dcid.len())
    .wrapping_add(1)
    .wrapping_add(scid.len())
    .wrapping_add(token.len());
  // The tag authenticates the pseudo-packet "ODCID length, ODCID, Retry packet without tag". It
  // is built in `out`, the packet is then moved to the front and the tag is appended.
  let prefix_len = odcid.len().wrapping_add(1);
  if out.len() < prefix_len.wrapping_add(packet_len).max(packet_len.wrapping_add(AEAD_TAG_LEN)) {
    return Err(error(QuicError::BufferTooSmall));
  }
  let mut writer = Writer::new(out);
  writer.put(&[odcid_len])?;
  writer.put(odcid)?;
  writer.put(&[RETRY_FIRST_BYTE])?;
  writer.put(&QUIC_V1.to_be_bytes())?;
  writer.put(&[dcid_len])?;
  writer.put(dcid)?;
  writer.put(&[scid_len])?;
  writer.put(scid)?;
  writer.put(token)?;
  let pseudo_packet_len = writer.pos();
  let tag = Aes128GcmKeyGlobal::new(&RETRY_KEY)?.seal_in_place(
    RETRY_NONCE,
    out.get(..pseudo_packet_len).unwrap_or_default(),
    &mut [],
  )?;
  out.copy_within(prefix_len..pseudo_packet_len, 0);
  let mut writer = Writer::at(out, packet_len);
  writer.put(&tag)?;
  Ok(writer.pos())
}

#[inline(always)]
fn error(kind: QuicError) -> crate::Error {
  cold_path();
  kind.into()
}

fn parse_long(datagram: &[u8], first: u8) -> crate::Result<PacketHeader<'_>> {
  let mut cursor = Cursor { offset: 0, rest: datagram };
  cursor.take(1)?;
  let version = u32::from_be_bytes(
    *cursor.take(4)?.first_chunk::<4>().ok_or_else(|| error(QuicError::Truncated))?,
  );
  let is_v1 = version == QUIC_V1;
  if is_v1 && first & 0x40 == 0 {
    return Err(error(QuicError::InvalidFixedBit));
  }
  let dcid = cursor.take_cid(is_v1)?;
  let scid = cursor.take_cid(is_v1)?;
  let datagram_len = datagram.len();
  let ty = match version {
    0 => PacketTy::VersionNegotiation,
    QUIC_V1 => match (first >> 4) & 0b11 {
      0 => PacketTy::Initial,
      1 => PacketTy::ZeroRtt,
      2 => PacketTy::Handshake,
      _ => PacketTy::Retry,
    },
    _ => PacketTy::UnknownVersion,
  };
  let (token, pn_offset, packet_end) = match ty {
    PacketTy::Initial | PacketTy::ZeroRtt | PacketTy::Handshake => {
      let token = if ty == PacketTy::Initial {
        let len = cursor.take_varint()?;
        cursor.take(len)?
      } else {
        &[]
      };
      let length = cursor.take_varint()?;
      if length > cursor.rest.len() {
        return Err(error(QuicError::Truncated));
      }
      if length < MIN_PROTECTED_LEN {
        return Err(error(QuicError::PacketTooShort));
      }
      (token, cursor.offset, cursor.offset.wrapping_add(length))
    }
    PacketTy::Retry => {
      let Some(token_len) = cursor.rest.len().checked_sub(AEAD_TAG_LEN) else {
        return Err(error(QuicError::Truncated));
      };
      (cursor.take(token_len)?, datagram_len, datagram_len)
    }
    PacketTy::OneRtt | PacketTy::UnknownVersion | PacketTy::VersionNegotiation => {
      (&[][..], datagram_len, datagram_len)
    }
  };
  Ok(PacketHeader { ty, version, dcid, scid, token, pn_offset, packet_end })
}

fn parse_short(
  datagram: &[u8],
  first: u8,
  short_dcid_len: usize,
) -> crate::Result<PacketHeader<'_>> {
  if first & 0x40 == 0 {
    return Err(error(QuicError::InvalidFixedBit));
  }
  let Some(pn_offset) = short_dcid_len.checked_add(1) else {
    return Err(error(QuicError::Truncated));
  };
  let Some(dcid) = datagram.get(1..pn_offset) else {
    return Err(error(QuicError::Truncated));
  };
  if datagram.len().wrapping_sub(pn_offset) < MIN_PROTECTED_LEN {
    return Err(error(QuicError::PacketTooShort));
  }
  Ok(PacketHeader {
    ty: PacketTy::OneRtt,
    version: QUIC_V1,
    dcid,
    scid: &[],
    token: &[],
    pn_offset,
    packet_end: datagram.len(),
  })
}

fn write_version_negotiation_inner(
  dcid: &[u8],
  scid: &[u8],
  out: &mut [u8],
) -> crate::Result<usize> {
  let (Ok(dcid_len), Ok(scid_len)) = (u8::try_from(dcid.len()), u8::try_from(scid.len())) else {
    return Err(error(QuicError::CidTooLong));
  };
  let mut writer = Writer::new(out);
  writer.put(&[VERSION_NEGOTIATION_FIRST_BYTE])?;
  writer.put(&0u32.to_be_bytes())?;
  writer.put(&[dcid_len])?;
  writer.put(dcid)?;
  writer.put(&[scid_len])?;
  writer.put(scid)?;
  writer.put(&QUIC_V1.to_be_bytes())?;
  Ok(writer.pos())
}

/// Reads fields from the start of `rest`, which is placed `offset` bytes after the start of the
/// datagram.
struct Cursor<'bytes> {
  offset: usize,
  rest: &'bytes [u8],
}

impl<'bytes> Cursor<'bytes> {
  fn take(&mut self, len: usize) -> crate::Result<&'bytes [u8]> {
    let Some((head, tail)) = self.rest.split_at_checked(len) else {
      return Err(error(QuicError::Truncated));
    };
    self.offset = self.offset.wrapping_add(len);
    self.rest = tail;
    Ok(head)
  }

  // A length followed by that many bytes. Only version 1 limits the length.
  fn take_cid(&mut self, is_v1: bool) -> crate::Result<&'bytes [u8]> {
    let len = usize::from(self.take(1)?.first().copied().unwrap_or_default());
    if is_v1 && len > MAX_CID_LEN {
      return Err(error(QuicError::CidTooLong));
    }
    self.take(len)
  }

  // A variable-length integer that is a length.
  fn take_varint(&mut self) -> crate::Result<usize> {
    let Some((value, len)) = decode_varint(self.rest) else {
      return Err(error(QuicError::Truncated));
    };
    self.take(len)?;
    usize::try_from(value).map_err(|_| error(QuicError::Truncated))
  }
}

#[cfg(test)]
mod tests {
  use crate::{
    Error,
    quic::{
      QuicError,
      packet::{
        PacketTy, QUIC_V1, decode_pn, parse_header, pn_len_for, write_retry,
        write_version_negotiation,
      },
      varint::encode_varint,
    },
  };
  use alloc::vec::Vec;

  // RFC 9001 appendix A.2: the protected header of the client's first Initial, which has a
  // 1162-byte payload, a 4-byte packet number and a Length of 1182.
  const A2_HEADER: [u8; 18] = hexd!(b"c000000001088394c8f03e5157080000449e");
  const A2_DCID: [u8; 8] = hexd!(b"8394c8f03e515708");
  // RFC 9001 appendix A.4
  const A4_RETRY: [u8; 36] =
    hexd!(b"ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");

  fn long_header(
    first: u8,
    version: u32,
    dcid: &[u8],
    scid: &[u8],
    token: Option<&[u8]>,
    length: Option<u64>,
  ) -> Vec<u8> {
    let mut vec = Vec::new();
    vec.push(first);
    vec.extend_from_slice(&version.to_be_bytes());
    vec.push(u8::try_from(dcid.len()).unwrap());
    vec.extend_from_slice(dcid);
    vec.push(u8::try_from(scid.len()).unwrap());
    vec.extend_from_slice(scid);
    let mut buffer = [0; 8];
    if let Some(elem) = token {
      let len = encode_varint(u64::try_from(elem.len()).unwrap(), &mut buffer).unwrap();
      vec.extend_from_slice(&buffer[..len]);
      vec.extend_from_slice(elem);
    }
    if let Some(elem) = length {
      let len = encode_varint(elem, &mut buffer).unwrap();
      vec.extend_from_slice(&buffer[..len]);
    }
    vec
  }

  #[test]
  fn parse_rfc9001_a2_client_initial_header() {
    let mut datagram = A2_HEADER.to_vec();
    datagram.resize(1200, 0);
    let header = parse_header(&datagram, 8).unwrap();
    assert_eq!(header.ty, PacketTy::Initial);
    assert_eq!(header.version, QUIC_V1);
    assert_eq!(header.dcid, A2_DCID);
    assert_eq!(header.scid, []);
    assert_eq!(header.token, []);
    assert_eq!(header.pn_offset, 18);
    assert_eq!(header.packet_end, 1200);
  }

  #[test]
  fn parse_every_truncation_of_the_a2_header_without_panicking() {
    let mut datagram = A2_HEADER.to_vec();
    datagram.resize(1200, 0);
    for len in 0..datagram.len() {
      assert!(parse_header(&datagram[..len], 8).is_err(), "{len}");
    }
    assert!(parse_header(&datagram, 8).is_ok());
    // Bytes after the packet are another packet's
    datagram.resize(1500, 0xaa);
    assert_eq!(parse_header(&datagram, 8).unwrap().packet_end, 1200);
  }

  #[test]
  fn parse_coalesced_initial_and_handshake() {
    let mut datagram = long_header(0xc0, QUIC_V1, &A2_DCID, &[9, 8, 7], Some(&[1, 2]), Some(30));
    let first_len = datagram.len() + 30;
    datagram.resize(first_len, 0x11);
    datagram.extend_from_slice(&long_header(0xe0, QUIC_V1, &A2_DCID, &[9, 8, 7], None, Some(25)));
    datagram.resize(datagram.len() + 25, 0x22);

    let first = parse_header(&datagram, 8).unwrap();
    assert_eq!(first.ty, PacketTy::Initial);
    assert_eq!(first.scid, [9, 8, 7]);
    assert_eq!(first.token, [1, 2]);
    assert_eq!(first.packet_end, first_len);
    assert_eq!(first.packet_end - first.pn_offset, 30);

    let second = parse_header(&datagram[first.packet_end..], 8).unwrap();
    assert_eq!(second.ty, PacketTy::Handshake);
    assert_eq!(second.token, []);
    assert_eq!(second.packet_end - second.pn_offset, 25);
    assert_eq!(second.packet_end, datagram.len() - first_len);
  }

  #[test]
  fn parse_zero_rtt() {
    let mut datagram = long_header(0xd0, QUIC_V1, &A2_DCID, &[], None, Some(40));
    datagram.resize(datagram.len() + 40, 0);
    let header = parse_header(&datagram, 8).unwrap();
    assert_eq!(header.ty, PacketTy::ZeroRtt);
    assert_eq!(header.token, []);
  }

  #[test]
  fn parse_short_header_with_8_byte_dcid() {
    let mut datagram = Vec::new();
    datagram.push(0x43);
    datagram.extend_from_slice(&A2_DCID);
    datagram.extend_from_slice(&[0x5a; 30]);
    let header = parse_header(&datagram, 8).unwrap();
    assert_eq!(header.ty, PacketTy::OneRtt);
    assert_eq!(header.version, QUIC_V1);
    assert_eq!(header.dcid, A2_DCID);
    assert_eq!(header.scid, []);
    assert_eq!(header.token, []);
    assert_eq!(header.pn_offset, 9);
    assert_eq!(header.packet_end, datagram.len());

    // The length of the destination CID is not on the wire
    let header = parse_header(&datagram, 3).unwrap();
    assert_eq!(header.dcid, &A2_DCID[..3]);
    assert_eq!(header.pn_offset, 4);
    let header = parse_header(&datagram, 0).unwrap();
    assert_eq!(header.dcid, []);
    assert_eq!(header.pn_offset, 1);
  }

  #[test]
  fn parse_short_header_needs_room_for_the_header_protection_sample() {
    let mut datagram = Vec::new();
    datagram.push(0x40);
    datagram.extend_from_slice(&A2_DCID);
    // The sample starts 4 bytes after the packet number's first byte and has 16 bytes
    datagram.resize(9 + 19, 0);
    assert!(matches!(parse_header(&datagram, 8), Err(Error::Quic(QuicError::PacketTooShort))));
    datagram.push(0);
    assert!(parse_header(&datagram, 8).is_ok());
    assert!(matches!(parse_header(&datagram[..8], 8), Err(Error::Quic(QuicError::Truncated))));
    assert!(matches!(parse_header(&[], 8), Err(Error::Quic(QuicError::Truncated))));
  }

  #[test]
  fn parse_rejects_a_cleared_fixed_bit() {
    let mut datagram = A2_HEADER.to_vec();
    datagram.resize(1200, 0);
    datagram[0] = 0x80;
    assert!(matches!(parse_header(&datagram, 8), Err(Error::Quic(QuicError::InvalidFixedBit))));
    let short = [0x00; 40];
    assert!(matches!(parse_header(&short, 8), Err(Error::Quic(QuicError::InvalidFixedBit))));
  }

  #[test]
  fn parse_checks_every_long_header_length() {
    // CIDs of a v1 packet have at most 20 bytes
    let mut datagram = long_header(0xc0, QUIC_V1, &[0; 21], &[], Some(&[]), Some(30));
    datagram.resize(datagram.len() + 30, 0);
    assert!(matches!(parse_header(&datagram, 8), Err(Error::Quic(QuicError::CidTooLong))));
    let mut datagram = long_header(0xc0, QUIC_V1, &[], &[0; 21], Some(&[]), Some(30));
    datagram.resize(datagram.len() + 30, 0);
    assert!(matches!(parse_header(&datagram, 8), Err(Error::Quic(QuicError::CidTooLong))));
    let mut datagram = long_header(0xc0, QUIC_V1, &[0; 20], &[0; 20], Some(&[]), Some(30));
    datagram.resize(datagram.len() + 30, 0);
    assert!(parse_header(&datagram, 8).is_ok());

    // A token longer than the datagram
    let mut datagram = long_header(0xc0, QUIC_V1, &A2_DCID, &[], Some(&[0; 100]), Some(30));
    datagram.resize(datagram.len() + 30, 0);
    let cut = datagram.len() - 30 - 50;
    assert!(matches!(parse_header(&datagram[..cut], 8), Err(Error::Quic(QuicError::Truncated))));
    // A token length that is a huge varint
    let mut datagram = long_header(0xc0, QUIC_V1, &A2_DCID, &[], None, None);
    datagram.extend_from_slice(&[0xff; 8]);
    datagram.resize(datagram.len() + 40, 0);
    assert!(matches!(parse_header(&datagram, 8), Err(Error::Quic(QuicError::Truncated))));

    // A Length that exceeds what is left, or that is too small for the header protection sample
    let mut datagram = long_header(0xe0, QUIC_V1, &A2_DCID, &[], None, Some(50));
    datagram.resize(datagram.len() + 49, 0);
    assert!(matches!(parse_header(&datagram, 8), Err(Error::Quic(QuicError::Truncated))));
    datagram.push(0);
    assert!(parse_header(&datagram, 8).is_ok());
    for length in [0, 1, 19] {
      let mut datagram = long_header(0xe0, QUIC_V1, &A2_DCID, &[], None, Some(length));
      datagram.resize(datagram.len() + 40, 0);
      assert!(matches!(parse_header(&datagram, 8), Err(Error::Quic(QuicError::PacketTooShort))));
    }
    let mut datagram = long_header(0xe0, QUIC_V1, &A2_DCID, &[], None, Some(20));
    datagram.resize(datagram.len() + 20, 0);
    assert!(parse_header(&datagram, 8).is_ok());
  }

  #[test]
  fn parse_unknown_version_keeps_the_version_independent_fields() {
    // Versions other than 1 may have CIDs of up to 255 bytes
    let dcid = [7; 30];
    let mut datagram = long_header(0xc3, 0xabcd_ef01, &dcid, &[1, 2, 3], None, None);
    datagram.resize(1200, 0x99);
    let header = parse_header(&datagram, 8).unwrap();
    assert_eq!(header.ty, PacketTy::UnknownVersion);
    assert_eq!(header.version, 0xabcd_ef01);
    assert_eq!(header.dcid, dcid);
    assert_eq!(header.scid, [1, 2, 3]);
    assert_eq!(header.token, []);
    assert_eq!(header.packet_end, 1200);

    let mut datagram = long_header(0xc3, 0xabcd_ef01, &[7; 255], &[1; 255], None, None);
    datagram.truncate(datagram.len() - 1);
    assert!(matches!(parse_header(&datagram, 8), Err(Error::Quic(QuicError::Truncated))));
  }

  #[test]
  fn parse_retry_from_rfc9001_a4() {
    let header = parse_header(&A4_RETRY, 8).unwrap();
    assert_eq!(header.ty, PacketTy::Retry);
    assert_eq!(header.version, QUIC_V1);
    assert_eq!(header.dcid, []);
    assert_eq!(header.scid, hexd!(b"f067a5502a4262b5"));
    assert_eq!(header.token, b"token");
    assert_eq!(header.packet_end, A4_RETRY.len());
    // A Retry without room for the integrity tag
    assert!(matches!(
      parse_header(&A4_RETRY[..A4_RETRY.len() - 6], 8),
      Err(Error::Quic(QuicError::Truncated))
    ));
  }

  #[test]
  fn decode_pn_rfc9000_a3() {
    assert_eq!(decode_pn(Some(0xa82f_30ea), 0x9b32, 2), 0xa82f_9b32);
    // No packet was received yet
    assert_eq!(decode_pn(None, 0, 1), 0);
    assert_eq!(decode_pn(None, 0x2a, 1), 0x2a);
    assert_eq!(decode_pn(None, 0xffff_ffff, 4), 0xffff_ffff);
    // The next packet number is in the next window
    assert_eq!(decode_pn(Some(0xff), 0x01, 1), 0x101);
    // A reordered packet from the previous window
    assert_eq!(decode_pn(Some(0x100), 0xff, 1), 0xff);
    assert_eq!(decode_pn(Some(0x1_0000_0000), 0xffff_ffff, 4), 0xffff_ffff);
    // Nothing overflows
    for largest in [0, 1 << 31, (1 << 62) - 1, u64::MAX] {
      for pn_len in 1..=4 {
        for truncated in [0, 1, 0x7f, 0xff, 0xffff, 0xffff_ffff] {
          let _ = decode_pn(Some(largest), truncated, pn_len);
        }
      }
    }
  }

  #[test]
  fn pn_len_for_rfc9000_a2() {
    // 0xac5c02 with 0xabe8b3 acknowledged: 29519 packets in flight need 16 bits
    assert_eq!(pn_len_for(0xac_5c02, Some(0xab_e8b3)), 2);
    // 0xace8fe with 0xabe8b3 acknowledged: twice the 65611 in flight need 18 bits
    assert_eq!(pn_len_for(0xac_e8fe, Some(0xab_e8b3)), 3);
    assert_eq!(pn_len_for(0, None), 1);
    assert_eq!(pn_len_for(1, None), 1);
    // Without acknowledgments, the first packet number counts as unacknowledged
    assert_eq!(pn_len_for(126, None), 1);
    assert_eq!(pn_len_for(127, None), 2);
    assert_eq!(pn_len_for(127, Some(0)), 1);
    assert_eq!(pn_len_for(128, Some(0)), 2);
    assert_eq!(pn_len_for(32_767, Some(0)), 2);
    assert_eq!(pn_len_for(32_768, Some(0)), 3);
    assert_eq!(pn_len_for(1 << 23, None), 4);
    assert_eq!(pn_len_for(1 << 30, Some(0)), 4);
    // More than four bytes can not be encoded
    assert_eq!(pn_len_for((1 << 40) + 5, Some(3)), 4);
    assert_eq!(pn_len_for(u64::MAX, None), 4);
  }

  #[test]
  fn pn_len_for_and_decode_pn_agree() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    for _ in 0..10_000 {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      let largest_acked = (state >> 20) & ((1 << 40) - 1);
      let pn = largest_acked + 1 + ((state >> 3) % (1 << (state % 30)));
      let len = pn_len_for(pn, Some(largest_acked));
      let truncated = pn & ((1 << (len * 8)) - 1);
      // The peer's largest received packet number can be anywhere in [largest_acked, pn)
      assert_eq!(decode_pn(Some(largest_acked), truncated, len), pn);
      assert_eq!(decode_pn(Some(pn - 1), truncated, len), pn);
      assert_eq!(decode_pn(Some(largest_acked + (pn - largest_acked) / 2), truncated, len), pn);
    }
  }

  #[test]
  fn retry_integrity_tag_matches_rfc9001_a4() {
    let mut out = [0; 128];
    let len = write_retry(&[], &hexd!(b"f067a5502a4262b5"), &A2_DCID, b"token", &mut out).unwrap();
    assert_eq!(&out[..len], A4_RETRY);
  }

  #[test]
  fn retry_with_cids_and_a_long_token() {
    let token = [0x77; 90];
    let mut out = [0; 256];
    let len = write_retry(&[1, 2, 3], &[4; 8], &[5; 20], &token, &mut out).unwrap();
    assert_eq!(len, 1 + 4 + 1 + 3 + 1 + 8 + 90 + 16);
    let header = parse_header(&out[..len], 8).unwrap();
    assert_eq!(header.ty, PacketTy::Retry);
    assert_eq!(header.dcid, [1, 2, 3]);
    assert_eq!(header.scid, [4; 8]);
    assert_eq!(header.token, token);
    assert_eq!(header.packet_end, len);
    // The tag depends on the original destination CID
    let mut other = [0; 256];
    let other_len = write_retry(&[1, 2, 3], &[4; 8], &[6; 20], &token, &mut other).unwrap();
    assert_eq!(other_len, len);
    assert_eq!(out[..len - 16], other[..len - 16]);
    assert_ne!(out[len - 16..len], other[len - 16..len]);
  }

  #[test]
  fn retry_rejects_a_small_buffer() {
    let mut out = [0; 128];
    let needed = write_retry(&[], &[4; 8], &A2_DCID, b"token", &mut out).unwrap();
    for len in 0..needed {
      assert!(
        matches!(
          write_retry(&[], &[4; 8], &A2_DCID, b"token", &mut out[..len]),
          Err(Error::Quic(QuicError::BufferTooSmall))
        ),
        "{len}"
      );
    }
    assert_eq!(write_retry(&[], &[4; 8], &A2_DCID, b"token", &mut out[..needed]).unwrap(), needed);
    // CIDs have at most 255 bytes in the invariants
    assert!(write_retry(&[0; 256], &[], &A2_DCID, b"", &mut [0; 1024]).is_err());
    assert!(write_retry(&[], &[0; 256], &A2_DCID, b"", &mut [0; 1024]).is_err());
    assert!(write_retry(&[], &[], &[0; 256], b"", &mut [0; 1024]).is_err());
  }

  #[test]
  fn version_negotiation_lists_only_v1() {
    let mut out = [0xee; 64];
    // The client's source CID becomes the destination CID and vice versa
    let len = write_version_negotiation(&[1, 2, 3], &A2_DCID, &mut out);
    assert_eq!(len, 1 + 4 + 1 + 3 + 1 + 8 + 4);
    assert_eq!(out[0] & 0xc0, 0xc0);
    assert_eq!(out[1..5], [0, 0, 0, 0]);
    assert_eq!(out[5], 3);
    assert_eq!(out[6..9], [1, 2, 3]);
    assert_eq!(out[9], 8);
    assert_eq!(out[10..18], A2_DCID);
    assert_eq!(out[18..22], [0, 0, 0, 1]);
    assert_eq!(out[22..], [0xee; 42]);

    let header = parse_header(&out[..len], 8).unwrap();
    assert_eq!(header.ty, PacketTy::VersionNegotiation);
    assert_eq!(header.version, 0);
    assert_eq!(header.dcid, [1, 2, 3]);
    assert_eq!(header.scid, A2_DCID);
  }

  #[test]
  fn version_negotiation_reports_a_small_buffer_or_long_cids_as_zero() {
    let mut out = [0; 64];
    let len = write_version_negotiation(&[], &[], &mut out);
    assert_eq!(len, 1 + 4 + 1 + 1 + 4);
    for size in 0..len {
      assert_eq!(write_version_negotiation(&[], &[], &mut out[..size]), 0);
    }
    assert_eq!(write_version_negotiation(&[0; 256], &[], &mut [0; 1024]), 0);
    assert_eq!(write_version_negotiation(&[], &[0; 256], &mut [0; 1024]), 0);
    assert_eq!(
      write_version_negotiation(&[0; 255], &[0; 255], &mut [0; 1024]),
      1 + 4 + 1 + 255 + 1 + 255 + 4
    );
  }
}
