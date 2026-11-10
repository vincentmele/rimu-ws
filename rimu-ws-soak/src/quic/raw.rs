//! A minimal raw QUIC packet sender, built on codecs of the harness's own (ruling T23-b): QUIC
//! varints, long and short headers, the Initial secrets of RFC 9001 section 5.2, AEAD (AES-128-GCM)
//! and header protection (AES-128-ECB) for the Initial level, and the few frame encoders the abuse
//! scenarios need. It shares no code with rimu-ws, so a bug the two had in common could not hide.
//!
//! It reaches the Initial level only: 1-RTT packets need the handshake secrets, which only a full
//! TLS 1.3 exchange yields, so the scenarios that must speak 1-RTT frames are driven with `quinn`
//! (see [`super::client`]). What a library will not send — malformed first Initials, floods of
//! distinct connection attempts, fragmented CRYPTO, and short headers that cannot be decrypted —
//! lives here.

use aes::{
  Aes128,
  cipher::{BlockEncrypt as _, generic_array::GenericArray},
};
use aes_gcm::{AeadInPlace as _, Aes128Gcm, KeyInit as _};
use hkdf::Hkdf;
use sha2::Sha256;

/// RFC 9001 section 5.2: the salt that derives the Initial secrets of QUIC version 1.
const INITIAL_SALT: [u8; 20] = [
  0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
  0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC version 1.
pub const VERSION_1: u32 = 0x0000_0001;

/// The Initial keys of one side (client or server), derived from a client's destination connection
/// ID (RFC 9001 section 5.2).
#[derive(Clone)]
pub struct InitialKeys {
  key: [u8; 16],
  iv: [u8; 12],
  hp: [u8; 16],
}

/// Appends `value` to `out` as a QUIC variable-length integer (RFC 9000 section 16).
pub fn put_varint(out: &mut Vec<u8>, value: u64) {
  if value < (1 << 6) {
    out.push(value as u8);
  } else if value < (1 << 14) {
    out.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes());
  } else if value < (1 << 30) {
    out.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes());
  } else {
    out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
  }
}

fn hkdf_expand_label(secret: &[u8], label: &[u8], len: usize) -> Vec<u8> {
  // HKDF-Expand-Label (RFC 8446 section 7.1): struct { u16 length; opaque label<7..255> = "tls13 "
  // + label; opaque context<0..255> = "" }.
  let mut info = Vec::new();
  info.extend_from_slice(&(len as u16).to_be_bytes());
  let full_label = [b"tls13 ".as_slice(), label].concat();
  info.push(full_label.len() as u8);
  info.extend_from_slice(&full_label);
  info.push(0);
  let hk = Hkdf::<Sha256>::from_prk(secret).expect("prk");
  let mut out = vec![0u8; len];
  hk.expand(&info, &mut out).expect("expand");
  out
}

impl InitialKeys {
  /// Derives the client-side Initial keys for a destination connection ID.
  pub fn client(dcid: &[u8]) -> Self {
    Self::derive(dcid, b"client in")
  }

  /// Derives the server-side Initial keys (to try to remove the protection of a reply).
  pub fn server(dcid: &[u8]) -> Self {
    Self::derive(dcid, b"server in")
  }

  fn derive(dcid: &[u8], label: &[u8]) -> Self {
    let (prk, _hk) = Hkdf::<Sha256>::extract(Some(&INITIAL_SALT), dcid);
    let secret = hkdf_expand_label(&prk, label, 32);
    let key = hkdf_expand_label(&secret, b"quic key", 16);
    let iv = hkdf_expand_label(&secret, b"quic iv", 12);
    let hp = hkdf_expand_label(&secret, b"quic hp", 16);
    Self {
      key: key.try_into().expect("16"),
      iv: iv.try_into().expect("12"),
      hp: hp.try_into().expect("16"),
    }
  }

  /// The header-protection mask for a 16-byte ciphertext sample (RFC 9001 section 5.4.3).
  fn hp_mask(&self, sample: &[u8]) -> [u8; 5] {
    let cipher = Aes128::new(GenericArray::from_slice(&self.hp));
    let mut block = *GenericArray::from_slice(&sample[..16]);
    cipher.encrypt_block(&mut block);
    [block[0], block[1], block[2], block[3], block[4]]
  }

  fn nonce(&self, packet_number: u64) -> [u8; 12] {
    let mut nonce = self.iv;
    let pn = packet_number.to_be_bytes();
    for i in 0..8 {
      nonce[4 + i] ^= pn[i];
    }
    nonce
  }
}

/// Reads a QUIC varint at the start of `bytes`, returning (value, bytes consumed).
fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
  let first = *bytes.first()?;
  let len = 1usize << (first >> 6);
  let mut value = u64::from(first & 0x3f);
  for i in 1..len {
    value = (value << 8) | u64::from(*bytes.get(i)?);
  }
  Some((value, len))
}

/// Removes the protection of the first Initial packet of `datagram` (a server reply) with the
/// server-side Initial keys for `dcid` (the client's original DCID), and returns its decrypted
/// frame bytes. Used to read a handshake-level CONNECTION_CLOSE (ruling T23-j #2).
pub fn open_server_initial(dcid: &[u8], datagram: &[u8]) -> Option<Vec<u8>> {
  let keys = InitialKeys::server(dcid);
  let first = *datagram.first()?;
  if first & 0x80 == 0 || (first & 0x30) >> 4 != 0 {
    return None; // not a long-header Initial
  }
  let mut at = 1 + 4; // first byte + version
  let dcid_len = usize::from(*datagram.get(at)?);
  at = at + 1 + dcid_len;
  let scid_len = usize::from(*datagram.get(at)?);
  at = at + 1 + scid_len;
  let (token_len, token_vl) = read_varint(datagram.get(at..)?)?;
  at = at.checked_add(token_vl)?.checked_add(usize::try_from(token_len).ok()?)?;
  let (length, len_vl) = read_varint(datagram.get(at..)?)?;
  let pn_offset = at.checked_add(len_vl)?;
  let packet_end = pn_offset.checked_add(usize::try_from(length).ok()?)?;
  if packet_end > datagram.len() {
    return None;
  }
  let mut packet = datagram.get(..packet_end)?.to_vec();
  let sample_at = pn_offset.checked_add(4)?;
  let sample = packet.get(sample_at..sample_at.checked_add(16)?)?.to_vec();
  let mask = keys.hp_mask(&sample);
  let unprot_first = packet[0] ^ (mask[0] & 0x0f);
  packet[0] = unprot_first;
  let pn_len = usize::from(unprot_first & 0x03) + 1;
  let mut pn: u64 = 0;
  for i in 0..pn_len {
    let b = packet.get_mut(pn_offset + i)?;
    *b ^= mask[1 + i];
    pn = (pn << 8) | u64::from(*b);
  }
  let header_end = pn_offset + pn_len;
  let aad = packet.get(..header_end)?.to_vec();
  let mut sealed = packet.get(header_end..)?.to_vec();
  if sealed.len() < 16 {
    return None;
  }
  let tag_at = sealed.len() - 16;
  let tag = *GenericArray::from_slice(sealed.get(tag_at..)?);
  sealed.truncate(tag_at);
  let cipher = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
  let nonce = keys.nonce(pn);
  cipher
    .decrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, &mut sealed, &tag)
    .ok()?;
  Some(sealed)
}

/// Scans decrypted frame bytes for a CONNECTION_CLOSE (type 0x1c transport or 0x1d application) and
/// returns its error code. Skips PADDING, PING, ACK and CRYPTO.
pub fn connection_close_code(frames: &[u8]) -> Option<u64> {
  let mut at = 0usize;
  while at < frames.len() {
    let (ty, vl) = read_varint(frames.get(at..)?)?;
    at += vl;
    match ty {
      0x00 | 0x01 => {}
      0x1c | 0x1d => {
        let (code, _cvl) = read_varint(frames.get(at..)?)?;
        return Some(code);
      }
      0x02 | 0x03 => {
        let (_largest, a) = read_varint(frames.get(at..)?)?;
        at += a;
        let (_delay, b) = read_varint(frames.get(at..)?)?;
        at += b;
        let (count, c) = read_varint(frames.get(at..)?)?;
        at += c;
        let (_first, d) = read_varint(frames.get(at..)?)?;
        at += d;
        for _ in 0..count {
          let (_gap, g) = read_varint(frames.get(at..)?)?;
          at += g;
          let (_len, l) = read_varint(frames.get(at..)?)?;
          at += l;
        }
        if ty == 0x03 {
          for _ in 0..3 {
            let (_, e) = read_varint(frames.get(at..)?)?;
            at += e;
          }
        }
      }
      0x06 => {
        let (_off, a) = read_varint(frames.get(at..)?)?;
        at += a;
        let (dlen, b) = read_varint(frames.get(at..)?)?;
        at += b + usize::try_from(dlen).ok()?;
      }
      _ => return None,
    }
  }
  None
}

/// Builds a client Initial datagram: a single Initial packet carrying `crypto`, with a
/// four-byte packet number `pn`, padded to at least `pad_to` bytes. `crypto` is placed in a CRYPTO
/// frame at the offset given, so a fragmented ClientHello is built by two calls with a gap.
pub fn client_initial(
  dcid: &[u8],
  scid: &[u8],
  crypto_offset: u64,
  crypto: &[u8],
  pn: u32,
  pad_to: usize,
) -> Vec<u8> {
  let keys = InitialKeys::client(dcid);

  // The frame payload: a CRYPTO frame, then PADDING to make the datagram large enough.
  let mut payload = Vec::new();
  put_varint(&mut payload, 0x06); // CRYPTO
  put_varint(&mut payload, crypto_offset);
  put_varint(&mut payload, crypto.len() as u64);
  payload.extend_from_slice(crypto);

  // Header: long header, Initial (type 0b00), 4-byte packet-number length (0b11 in the low bits).
  let mut header = Vec::new();
  let first_byte = 0xc0 | 0x03;
  header.push(first_byte);
  header.extend_from_slice(&VERSION_1.to_be_bytes());
  header.push(dcid.len() as u8);
  header.extend_from_slice(dcid);
  header.push(scid.len() as u8);
  header.extend_from_slice(scid);
  put_varint(&mut header, 0); // token length 0

  // The Length field covers the packet number (4) + the encrypted payload + the 16-byte tag.
  // Pad the frame payload so the whole datagram reaches `pad_to`.
  let overhead = header.len() + 2 /* length varint, 2 bytes */ + 4 /* pn */ + 16 /* tag */;
  if overhead + payload.len() < pad_to {
    let extra = pad_to - overhead - payload.len();
    payload.resize(payload.len() + extra, 0); // PADDING frames (0x00)
  }
  let length = 4 + payload.len() + 16;
  // A two-byte length varint (0x4000 | length); the padding above sized the datagram for it.
  header.extend_from_slice(&((length as u16) | 0x4000).to_be_bytes());
  let pn_offset = header.len();
  header.extend_from_slice(&pn.to_be_bytes());

  // Seal the payload in place: nonce from the full packet number, AAD = header incl. packet number.
  let mut sealed = payload;
  let cipher = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
  let nonce = keys.nonce(u64::from(pn));
  let tag = cipher
    .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &header, &mut sealed)
    .expect("seal");
  sealed.extend_from_slice(&tag);

  // Header protection: sample the ciphertext starting four bytes after the packet number.
  let mut packet = header;
  packet.extend_from_slice(&sealed);
  let sample_start = pn_offset + 4;
  let mask = keys.hp_mask(&packet[sample_start..sample_start + 16]);
  packet[0] ^= mask[0] & 0x0f; // long header: protect the low four bits
  for i in 0..4 {
    packet[pn_offset + i] ^= mask[1 + i];
  }
  packet
}

/// The kind of a received QUIC packet, as far as the raw sender needs to tell them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyKind {
  /// A long-header Retry packet (RFC 9000 section 17.2.5): address validation was demanded.
  Retry,
  /// A long-header Initial packet (the server's handshake reply).
  Initial,
  /// A long-header Handshake or other long-header packet.
  OtherLong,
  /// A short-header (1-RTT) packet, or a stateless reset: undecryptable here.
  Short,
  /// Too short to classify.
  Unknown,
}

/// Classifies a datagram received from the server by its first byte (RFC 9000 section 17).
pub fn classify(datagram: &[u8]) -> ReplyKind {
  let Some(&first) = datagram.first() else {
    return ReplyKind::Unknown;
  };
  if first & 0x80 == 0 {
    return ReplyKind::Short;
  }
  // Long header: the type is in bits 4-5 (0b00 Initial, 0b01 0-RTT, 0b10 Handshake, 0b11 Retry).
  match (first & 0x30) >> 4 {
    0b00 => ReplyKind::Initial,
    0b11 => ReplyKind::Retry,
    _ => ReplyKind::OtherLong,
  }
}

/// A short-header (1-RTT) packet to a connection ID, with random protected bytes: the server cannot
/// decrypt it, so it must drop it or send at most a rate-limited stateless reset, never crash or
/// leak. Used by the forged-short-header flood.
pub fn forged_short(dcid: &[u8], filler: usize) -> Vec<u8> {
  let mut packet = Vec::with_capacity(1 + dcid.len() + filler);
  // Short header: fixed bit set, random protected bits.
  packet.push(0x40 | 0x01);
  packet.extend_from_slice(dcid);
  packet.resize(packet.len() + filler, 0xab);
  packet
}

// --- Minimal HTTP/3 request encoders (RFC 9114 / RFC 9204), for the oversized-heads scenario,
// which the `h3` client will not send (it refuses a field section over the peer's advertised
// SETTINGS_MAX_FIELD_SECTION_SIZE). These produce the bytes written onto `quinn` streams.

/// The opening bytes of a client control stream: the stream type (0x00) then a SETTINGS frame with
/// no settings.
pub fn h3_control_stream() -> [u8; 3] {
  [0x00, 0x04, 0x00]
}

/// The one type byte a client QPACK encoder stream opens with.
pub const H3_QPACK_ENCODER: u8 = 0x02;
/// The one type byte a client QPACK decoder stream opens with.
pub const H3_QPACK_DECODER: u8 = 0x03;

/// Appends `value` to `out` as an HPACK/QPACK prefixed integer (RFC 7541 section 5.1): the `n`-bit
/// prefix of the first byte is set, with `prefix` already in its high bits.
fn put_prefixed_int(out: &mut Vec<u8>, n: u32, prefix: u8, value: u64) {
  let max = (1u64 << n) - 1;
  if value < max {
    out.push(prefix | value as u8);
  } else {
    out.push(prefix | max as u8);
    let mut rem = value - max;
    while rem >= 128 {
      out.push((rem as u8 & 0x7f) | 0x80);
      rem >>= 7;
    }
    out.push(rem as u8);
  }
}

/// A HEADERS frame for `GET /baseline2` whose QPACK field section is oversized by a literal header
/// with a `value_len`-byte value (plus valid pseudo-headers), to trip the server's advertised
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` and draw a 431. The field section uses the static table only
/// (required insert count 0), so the server needs no QPACK dynamic state to decode it.
pub fn h3_oversized_headers_frame(value_len: usize) -> Vec<u8> {
  let mut fields = Vec::new();
  // QPACK encoded field section prefix: required insert count 0, delta base 0.
  fields.extend_from_slice(&[0x00, 0x00]);
  // :method GET — static index 17, indexed field line (1 T=1 index6).
  fields.push(0xc0 | 17);
  // :scheme https — static index 23.
  fields.push(0xc0 | 23);
  // :authority localhost — literal field line with name reference to static index 0 (01 N=0 T=1).
  fields.push(0x50);
  put_prefixed_int(&mut fields, 7, 0x00, b"localhost".len() as u64);
  fields.extend_from_slice(b"localhost");
  // :path /baseline2 — literal with name reference to static index 1.
  fields.push(0x51);
  put_prefixed_int(&mut fields, 7, 0x00, b"/baseline2".len() as u64);
  fields.extend_from_slice(b"/baseline2");
  // One oversized header, literal name + literal value (001 N=0 H=0, 3-bit name length), name "x".
  fields.push(0x20 | 1);
  fields.push(b'x');
  put_prefixed_int(&mut fields, 7, 0x00, value_len as u64);
  fields.resize(fields.len() + value_len, b'a');
  // HEADERS frame: type 0x01, length, payload.
  let mut frame = Vec::new();
  put_varint(&mut frame, 0x01);
  put_varint(&mut frame, fields.len() as u64);
  frame.extend_from_slice(&fields);
  frame
}

#[cfg(test)]
mod tests {
  use super::*;

  // RFC 9001 Appendix A.1-A.2: the client Initial keys for DCID 0x8394c8f03e515708.
  #[test]
  fn initial_keys_match_rfc9001() {
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let keys = InitialKeys::client(&dcid);
    assert_eq!(
      keys.key,
      [
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2,
        0x2d
      ]
    );
    assert_eq!(keys.iv, [0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c]);
    assert_eq!(
      keys.hp,
      [
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed,
        0xd2
      ]
    );
  }

  #[test]
  fn varint_widths() {
    let mut out = Vec::new();
    put_varint(&mut out, 37);
    assert_eq!(out, [37]);
    out.clear();
    put_varint(&mut out, 15293);
    assert_eq!(out, [0x7b, 0xbd]);
    out.clear();
    put_varint(&mut out, 494_878_333);
    assert_eq!(out, [0x9d, 0x7f, 0x3e, 0x7d]);
  }

  #[test]
  fn client_initial_is_a_large_long_header_datagram() {
    let dgram = client_initial(&[1, 2, 3, 4, 5, 6, 7, 8], &[9, 10], 0, b"hello", 0, 1200);
    assert!(dgram.len() >= 1200);
    assert_eq!(classify(&dgram), ReplyKind::Initial);
    // The fixed bit (0x40) survives header protection of the low four bits.
    assert_eq!(dgram[0] & 0xc0, 0xc0);
  }
}
