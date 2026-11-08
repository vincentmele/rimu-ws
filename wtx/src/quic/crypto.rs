//! Packet protection (RFC 9001 section 5) and key update (RFC 9001 section 6).
//!
//! Sans-I/O and allocation-free: every operation works in place on a buffer of the caller.
//!
//! # Key material
//!
//! [`DirectionalKeys`] and [`PacketKeys`] sit in pooled connection slots, so nothing derived from
//! a secret may outlive its connection in memory that the next connection reuses:
//!
//! * The expanded AEAD and header protection keys wipe themselves when dropped, and so do the raw
//!   secret, the IV and the header protection key that [`DirectionalKeys`] keeps.
//! * Wiping happens when a value is dropped, where it lives. Moving a value out of its slot leaves
//!   the key schedule behind: never `take`, `replace` or `swap` a [`DirectionalKeys`] out of a
//!   slot and then write something over it (`Option::take` on a niche only rewrites the
//!   discriminant). Assign a new value over the old one instead (`*slot = new`), which drops the
//!   old value in place, or call [`DirectionalKeys::advance`].
//! * Temporary copies that this module makes while deriving keys are wiped before returning, but
//!   what the compiler copies while moving a value (a returned [`DirectionalKeys`] on its way to
//!   the slot) and the HKDF state that a backend keeps inside of itself while deriving are out of
//!   its reach.

use crate::{
  collections::ArrayVectorCopy,
  crypto::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadKey as _, Aes128GcmKeyGlobal, Aes128HpGlobal,
    Aes256GcmKeyGlobal, Aes256HpGlobal, Chacha20HpGlobal, Chacha20Poly1305KeyGlobal, CryptoError,
    HpKey as _, MAX_HASH_LEN, drop_and_zero,
  },
  misc::zero_volatile,
  quic::{QuicError, decode_pn},
  tls::{CipherSuite, key_schedule::hkdf_expand_label},
};
use core::{
  cell::Cell,
  fmt::{Debug, Formatter},
  hint::cold_path,
  mem::ManuallyDrop,
  ops::Deref,
};

// RFC 9001 section 5.2
const INITIAL_SALT_V1: [u8; 20] = hexd!(b"38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
const INITIAL_SUITE: CipherSuite = CipherSuite::Aes128GcmSha256;
// The length of the IV, the same as the length of an AEAD nonce.
const IV_LEN: u8 = 12;
const LONG_HEADER_BIT: u8 = 0x80;
// The longest key of the supported cipher suites: AES-256 and ChaCha20.
const MAX_KEY_LEN: usize = 32;
const MAX_PN_LEN: usize = 4;
// The low bits of the first byte that header protection covers
const LONG_HEADER_MASK: u8 = 0x0f;
const SHORT_HEADER_MASK: u8 = 0x1f;
// The sample starts as if the packet number had four bytes (RFC 9001 section 5.4.2)
const SAMPLE_OFFSET: usize = MAX_PN_LEN;
const SAMPLE_LEN: usize = 16;

const _: () = {
  assert!(AEAD_NONCE_LEN == IV_LEN as usize);
  assert!(MAX_HASH_LEN >= MAX_KEY_LEN);
};

/// The AEAD of one of the supported cipher suites, with its key already expanded.
#[derive(Debug)]
pub(crate) enum QuicAead {
  Aes128(Aes128GcmKeyGlobal),
  Aes256(Aes256GcmKeyGlobal),
  Chacha(Chacha20Poly1305KeyGlobal),
}

impl QuicAead {
  /// Expands `key`, which has the key length of `suite`.
  #[inline]
  pub(crate) fn new(suite: CipherSuite, key: &[u8]) -> crate::Result<Self> {
    Ok(match suite {
      CipherSuite::Aes128GcmSha256 => Self::Aes128(Aes128GcmKeyGlobal::new(key)?),
      CipherSuite::Aes256GcmSha384 => Self::Aes256(Aes256GcmKeyGlobal::new(key)?),
      CipherSuite::Chacha20Poly1305Sha256 => Self::Chacha(Chacha20Poly1305KeyGlobal::new(key)?),
    })
  }

  #[inline]
  fn open_in_place<'data>(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &'data mut [u8],
  ) -> crate::Result<&'data mut [u8]> {
    match self {
      Self::Aes128(el) => el.open_in_place(nonce, aad, data),
      Self::Aes256(el) => el.open_in_place(nonce, aad, data),
      Self::Chacha(el) => el.open_in_place(nonce, aad, data),
    }
  }

  #[inline]
  fn seal_in_place(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
  ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
    match self {
      Self::Aes128(el) => el.seal_in_place(nonce, aad, data),
      Self::Aes256(el) => el.seal_in_place(nonce, aad, data),
      Self::Chacha(el) => el.seal_in_place(nonce, aad, data),
    }
  }
}

/// The header protection of one of the supported cipher suites, with its key already expanded.
#[derive(Debug)]
pub(crate) enum QuicHp {
  Aes128(Aes128HpGlobal),
  Aes256(Aes256HpGlobal),
  Chacha(Chacha20HpGlobal),
}

impl QuicHp {
  /// Expands `key`, which has the key length of `suite`.
  #[inline]
  pub(crate) fn new(suite: CipherSuite, key: &[u8]) -> crate::Result<Self> {
    Ok(match suite {
      CipherSuite::Aes128GcmSha256 => Self::Aes128(Aes128HpGlobal::new(key)?),
      CipherSuite::Aes256GcmSha384 => Self::Aes256(Aes256HpGlobal::new(key)?),
      CipherSuite::Chacha20Poly1305Sha256 => Self::Chacha(Chacha20HpGlobal::new(key)?),
    })
  }

  #[inline]
  fn mask(&self, sample: &[u8; SAMPLE_LEN]) -> crate::Result<[u8; 5]> {
    match self {
      Self::Aes128(el) => el.mask(sample),
      Self::Aes256(el) => el.mask(sample),
      Self::Chacha(el) => el.mask(sample),
    }
  }
}

/// Everything needed to protect the packets of one encryption level in one direction.
///
/// Dropping it overwrites the secret and everything derived from it, see the
/// [module documentation](self) for what that requires of the owner.
pub(crate) struct DirectionalKeys {
  aead: QuicAead,
  hp: QuicHp,
  // What `hp` was expanded from. Header protection keys do not change in a key update (RFC 9001
  // section 6), so the next generation expands this same key again.
  hp_key: ArrayVectorCopy<u8, MAX_KEY_LEN>,
  iv: [u8; AEAD_NONCE_LEN],
  // Packets sealed with this generation of the AEAD key, for the confidentiality limit (RFC 9001
  // section 6.6). Protecting takes `&self` and endpoints are single threaded.
  packets_sealed: Cell<u64>,
  // The traffic secret of this generation: the next one is derived from it.
  secret: ArrayVectorCopy<u8, MAX_HASH_LEN>,
  suite: CipherSuite,
}

impl DirectionalKeys {
  /// The AEAD to open the payloads of the packets that arrive.
  #[inline]
  pub(crate) const fn aead(&self) -> &QuicAead {
    &self.aead
  }

  /// The header protection of these keys.
  #[inline]
  pub(crate) const fn hp(&self) -> &QuicHp {
    &self.hp
  }

  /// The IV that is combined with the packet number to build the nonce of a packet.
  #[inline]
  pub(crate) const fn iv(&self) -> &[u8; AEAD_NONCE_LEN] {
    &self.iv
  }

  /// The number of packets that [`protect`] sealed with this generation of the keys.
  #[inline]
  pub(crate) fn packets_sealed(&self) -> u64 {
    self.packets_sealed.get()
  }

  /// The cipher suite that these keys belong to.
  #[inline]
  pub(crate) const fn suite(&self) -> CipherSuite {
    self.suite
  }

  /// Replaces these keys with those of the next generation, dropping (and so wiping) the old ones
  /// where they live. Does nothing if the next generation cannot be derived.
  #[inline]
  pub(crate) fn advance(&mut self) -> crate::Result<()> {
    *self = self.next_generation()?;
    Ok(())
  }

  /// The keys that follow these ones in a key update (RFC 9001 section 6.1): a secret derived with
  /// the label `quic ku`, and the AEAD key and IV derived from it. The header protection key is
  /// the same.
  ///
  /// The counter of sealed packets of the result starts from zero. To replace keys, prefer
  /// [`DirectionalKeys::advance`] or assign the result over the old keys, never move the old keys
  /// out of their slot.
  #[inline]
  pub(crate) fn next_generation(&self) -> crate::Result<Self> {
    let suite = self.suite;
    let hkdf = Scrub::new(suite.hkdf_from_prk(self.secret.as_slice())?);
    let secret =
      Scrub::new(hkdf_expand_label::<MAX_HASH_LEN>(None, b"quic ku", suite.hash_len(), &hkdf)?);
    Self::derive(suite, secret.as_slice(), Some(&self.hp_key))
  }

  // `hp_key` is the header protection key of the previous generation, if any
  fn derive(
    suite: CipherSuite,
    secret: &[u8],
    hp_key: Option<&ArrayVectorCopy<u8, MAX_KEY_LEN>>,
  ) -> crate::Result<Self> {
    if secret.len() != usize::from(suite.hash_len()) {
      cold_path();
      return Err(CryptoError::InvalidHashLength.into());
    }
    let key_len = suite.cipher_key_len();
    let hkdf = Scrub::new(suite.hkdf_from_prk(secret)?);
    let key = Scrub::new(hkdf_expand_label::<MAX_KEY_LEN>(None, b"quic key", key_len, &hkdf)?);
    let iv = Scrub::new(hkdf_expand_label::<AEAD_NONCE_LEN>(None, b"quic iv", IV_LEN, &hkdf)?);
    let hp_key = match hp_key {
      Some(elem) => *elem,
      None => hkdf_expand_label(None, b"quic hp", key_len, &hkdf)?,
    };
    let hp_key = Scrub::new(hp_key);
    let aead = QuicAead::new(suite, key.as_slice())?;
    let hp = QuicHp::new(suite, hp_key.as_slice())?;
    Ok(Self {
      aead,
      hp,
      hp_key: *hp_key,
      iv: iv.as_slice().try_into()?,
      packets_sealed: Cell::new(0),
      secret: ArrayVectorCopy::from_copyable_slice(secret)?,
      suite,
    })
  }
}

impl Debug for DirectionalKeys {
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("DirectionalKeys")
      .field("packets_sealed", &self.packets_sealed.get())
      .field("suite", &self.suite)
      .finish_non_exhaustive()
  }
}

impl Drop for DirectionalKeys {
  #[inline]
  fn drop(&mut self) {
    // `aead` and `hp` wipe themselves
    wipe(self.hp_key.as_slice_mut());
    wipe(&mut self.iv);
    wipe(self.secret.as_slice_mut());
  }
}

/// The keys of one encryption level.
#[derive(Debug)]
pub(crate) struct PacketKeys {
  /// Protects the packets that this endpoint sends.
  pub(crate) local: DirectionalKeys,
  /// Unprotects the packets that this endpoint receives.
  pub(crate) remote: DirectionalKeys,
}

/// The keys of the Initial packets, which anyone that sees the destination connection ID of the
/// first Initial packet of the client (`client_dcid`) can compute (RFC 9001 section 5.2).
#[inline]
pub(crate) fn initial_keys(client_dcid: &[u8], is_server: bool) -> crate::Result<PacketKeys> {
  let suite = INITIAL_SUITE;
  let hash_len = suite.hash_len();
  let initial = Scrub::new(suite.hkdf_extract(Some(&INITIAL_SALT_V1), client_dcid));
  let client =
    Scrub::new(hkdf_expand_label::<MAX_HASH_LEN>(None, b"client in", hash_len, &initial)?);
  let server =
    Scrub::new(hkdf_expand_label::<MAX_HASH_LEN>(None, b"server in", hash_len, &initial)?);
  let client = keys_from_secret(suite, client.as_slice())?;
  let server = keys_from_secret(suite, server.as_slice())?;
  Ok(if is_server {
    PacketKeys { local: server, remote: client }
  } else {
    PacketKeys { local: client, remote: server }
  })
}

/// The keys of an encryption level out of its traffic secret, which TLS provides, for the cipher
/// suite that was negotiated (RFC 9001 section 5.1). `secret` must have the length of the hash of
/// `suite`.
#[inline]
pub(crate) fn keys_from_secret(
  suite: CipherSuite,
  secret: &[u8],
) -> crate::Result<DirectionalKeys> {
  DirectionalKeys::derive(suite, secret, None)
}

/// Opens the payload of the packet in `packet`, which goes from the first byte of the packet to
/// its last, once [`remove_header_protection`] returned its packet number `pn`, which makes
/// `header_len` the length of the header up to and including the packet number.
///
/// Returns the plaintext, a prefix of `packet[header_len..]`. If anything fails the content of
/// the packet is unspecified (backends overwrite it), so, when more than one set of keys could
/// apply to a packet, choose one before calling this, using the key phase bit that
/// [`remove_header_protection`] returns, and do not try another with the same buffer. A failure
/// to authenticate is a [`crate::Error::Crypto`] and means that the packet must be dropped.
#[inline]
pub(crate) fn open_payload<'packet>(
  aead: &QuicAead,
  iv: &[u8; AEAD_NONCE_LEN],
  packet: &'packet mut [u8],
  header_len: usize,
  pn: u64,
) -> crate::Result<&'packet mut [u8]> {
  let Some((header, payload)) = packet.split_at_mut_checked(header_len) else {
    return Err(error(QuicError::PacketTooShort));
  };
  aead.open_in_place(nonce(iv, pn), header, payload)
}

/// Protects the packet in `packet`, in place.
///
/// `packet[..pn_offset + pn_len + payload_len]` is the header of the packet, the packet number
/// (`pn_len` bytes, already truncated) and the `payload_len` bytes of plaintext. It is followed by
/// at least [`AEAD_TAG_LEN`] bytes, where the tag goes, and nothing else after that is read or
/// written. The first byte and the Length field of a long header are written by the caller.
///
/// The packet number and the payload must have at least four bytes together so that there is a
/// sample for header protection (RFC 9001 section 5.4.2): shorter payloads must be padded.
///
/// Returns the length of the protected packet.
#[inline]
pub(crate) fn protect(
  keys: &DirectionalKeys,
  packet: &mut [u8],
  pn_offset: usize,
  pn: u64,
  pn_len: usize,
  payload_len: usize,
) -> crate::Result<usize> {
  if pn_offset == 0 || !(1..=MAX_PN_LEN).contains(&pn_len) {
    return Err(programming_error());
  }
  let header_len = pn_offset.saturating_add(pn_len);
  let packet_len = header_len.saturating_add(payload_len).saturating_add(AEAD_TAG_LEN);
  if packet.len() < packet_len {
    return Err(error(QuicError::BufferTooSmall));
  }
  if pn_len.saturating_add(payload_len) < SAMPLE_OFFSET {
    return Err(error(QuicError::PacketTooShort));
  }
  let Some((header, rest)) = packet.split_at_mut_checked(header_len) else {
    return Err(error(QuicError::BufferTooSmall));
  };
  let Some((payload, tail)) = rest.split_at_mut_checked(payload_len) else {
    return Err(error(QuicError::BufferTooSmall));
  };
  let Some(tag_dst) = tail.get_mut(..AEAD_TAG_LEN) else {
    return Err(error(QuicError::BufferTooSmall));
  };
  let tag = keys.aead.seal_in_place(nonce(&keys.iv, pn), header, payload)?;
  tag_dst.copy_from_slice(&tag);
  keys.packets_sealed.set(keys.packets_sealed.get().wrapping_add(1));
  let Some(protected) = packet.get_mut(..packet_len) else {
    return Err(error(QuicError::BufferTooSmall));
  };
  let mask = keys.hp.mask(&sample(protected, pn_offset)?)?;
  let Some(first) = protected.first_mut() else {
    return Err(error(QuicError::Truncated));
  };
  *first ^= mask[0] & first_byte_mask(*first);
  xor_packet_number(protected, pn_offset, pn_len, mask);
  Ok(packet_len)
}

/// Removes header protection (RFC 9001 section 5.4) from the packet in `packet`, in place.
///
/// `packet` goes from the first byte of the packet to its last one (`PacketHeader::packet_end`),
/// not to the end of the datagram, and `pn_offset` is the index of the first byte of the packet
/// number. `largest` is the largest packet number received in the packet number space, if any.
///
/// Returns the full packet number, the length of the truncated one and the first byte of the
/// packet without protection, which carries the reserved bits (that must be zero) and, in short
/// headers, the key phase. The first byte and the packet number of `packet` are overwritten
/// with the unprotected ones, so the header is `packet[..pn_offset + pn_len]`.
///
/// Nothing here authenticates: until [`open_payload`] succeeds, none of the results is trusted.
#[inline]
pub(crate) fn remove_header_protection(
  hp: &QuicHp,
  packet: &mut [u8],
  pn_offset: usize,
  largest: Option<u64>,
) -> crate::Result<(u64, usize, u8)> {
  if pn_offset == 0 {
    return Err(programming_error());
  }
  let mask = hp.mask(&sample(packet, pn_offset)?)?;
  let Some(first) = packet.first_mut() else {
    return Err(error(QuicError::Truncated));
  };
  *first ^= mask[0] & first_byte_mask(*first);
  let first = *first;
  let pn_len = usize::from(first & 0b11).wrapping_add(1);
  let truncated = xor_packet_number(packet, pn_offset, pn_len, mask);
  Ok((decode_pn(largest, truncated, pn_len), pn_len, first))
}

#[inline(always)]
fn error(kind: QuicError) -> crate::Error {
  cold_path();
  kind.into()
}

// Header protection hides only the low bits of the first byte: the header form is in the bit that
// it does not hide.
#[inline]
const fn first_byte_mask(first: u8) -> u8 {
  if first & LONG_HEADER_BIT != 0 { LONG_HEADER_MASK } else { SHORT_HEADER_MASK }
}

// The AEAD nonce is the IV with the packet number, as a 64-bit big-endian integer, xored into its
// last bytes (RFC 9001 section 5.3).
#[inline]
fn nonce(iv: &[u8; AEAD_NONCE_LEN], pn: u64) -> [u8; AEAD_NONCE_LEN] {
  let mut nonce = *iv;
  let skip = AEAD_NONCE_LEN.wrapping_sub(size_of::<u64>());
  for (elem, byte) in nonce.iter_mut().skip(skip).zip(pn.to_be_bytes()) {
    *elem ^= byte;
  }
  nonce
}

#[inline(always)]
fn programming_error() -> crate::Error {
  cold_path();
  crate::Error::ProgrammingError
}

#[inline]
fn sample(packet: &[u8], pn_offset: usize) -> crate::Result<[u8; SAMPLE_LEN]> {
  let start = pn_offset.saturating_add(SAMPLE_OFFSET);
  let end = start.saturating_add(SAMPLE_LEN);
  let Some(sample) = packet.get(start..end).and_then(|el| <[u8; SAMPLE_LEN]>::try_from(el).ok())
  else {
    return Err(error(QuicError::PacketTooShort));
  };
  Ok(sample)
}

// Xors the packet number, which has `pn_len` bytes, with the mask. Returns the result as an
// integer, which is the unprotected packet number when the mask is removed. The packet number is
// within the packet because the sample, taken four bytes after its start, fit.
#[inline]
fn xor_packet_number(packet: &mut [u8], pn_offset: usize, pn_len: usize, mask: [u8; 5]) -> u64 {
  let mut pn = 0u64;
  let end = pn_offset.saturating_add(pn_len);
  let Some(bytes) = packet.get_mut(pn_offset..end) else {
    return pn;
  };
  for (byte, mask_byte) in bytes.iter_mut().zip(mask.iter().skip(1)) {
    *byte ^= mask_byte;
  }
  for byte in bytes {
    pn = (pn << 8) | u64::from(*byte);
  }
  pn
}

/// Overwrites `bytes` with zeros in a way that the compiler cannot remove.
#[inline]
fn wipe(bytes: &mut [u8]) {
  // SAFETY: the pointer and the length come from a slice
  unsafe { zero_volatile(bytes.as_mut_ptr(), bytes.len()) };
}

/// A temporary copy of key material that is dropped, and then overwritten with zeros, when it goes
/// out of scope, in every path including the early returns of `?`.
struct Scrub<T>(ManuallyDrop<T>);

impl<T> Scrub<T> {
  #[inline]
  fn new(value: T) -> Self {
    Self(ManuallyDrop::new(value))
  }
}

impl<T> Deref for Scrub<T> {
  type Target = T;

  #[inline]
  fn deref(&self) -> &T {
    &self.0
  }
}

impl<T> Drop for Scrub<T> {
  #[inline]
  fn drop(&mut self) {
    // SAFETY: the field is only dropped here and `self` is not used after `drop`
    unsafe { drop_and_zero(&mut self.0) };
  }
}

#[cfg(test)]
mod tests {
  use crate::quic::crypto::{MAX_KEY_LEN, Scrub, wipe};
  use core::{mem::MaybeUninit, ptr, slice};

  #[test]
  fn temporary_copies_are_wiped_when_dropped() {
    let mut slot = MaybeUninit::<Scrub<[u8; 32]>>::uninit();
    slot.write(Scrub::new([0xa5; 32]));
    // SAFETY: the slot was initialized above and nothing reads it as a `Scrub` after this
    unsafe { ptr::drop_in_place(slot.as_mut_ptr()) };
    // SAFETY: the drop overwrote every byte of the slot, which has no padding
    let bytes =
      unsafe { slice::from_raw_parts(slot.as_ptr().cast::<u8>(), size_of::<Scrub<[u8; 32]>>()) };
    assert_eq!(bytes, [0; 32]);
  }

  #[test]
  fn wipe_overwrites_every_byte() {
    let mut bytes = [0xff; MAX_KEY_LEN + 1];
    wipe(bytes.get_mut(..MAX_KEY_LEN).unwrap());
    assert_eq!(bytes.get(..MAX_KEY_LEN).unwrap(), [0; MAX_KEY_LEN]);
    assert_eq!(bytes.get(MAX_KEY_LEN..).unwrap(), [0xff]);
    wipe(&mut []);
  }

  // The backends call assembly or C, which Miri cannot run
  #[cfg(not(miri))]
  mod backend {
    use crate::{
      Error,
      crypto::{AEAD_TAG_LEN, CryptoError, Hkdf as _, HkdfSha256Global, HkdfSha384Global},
      quic::{
        QuicError,
        crypto::{
          DirectionalKeys, QuicAead, QuicHp, initial_keys, keys_from_secret, open_payload, protect,
          remove_header_protection,
        },
      },
      tls::CipherSuite,
    };
    use alloc::{format, vec, vec::Vec};
    use core::{mem::MaybeUninit, ptr, slice};

    // RFC 9001 appendix A: the destination connection ID of the first Initial of the client
    const DCID: [u8; 8] = hexd!(b"8394c8f03e515708");
    // A.1
    const CLIENT_SECRET: [u8; 32] =
      hexd!(b"c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    const CLIENT_KEY: [u8; 16] = hexd!(b"1f369613dd76d5467730efcbe3b1a22d");
    const CLIENT_IV: [u8; 12] = hexd!(b"fa044b2f42a3fd3b46fb255c");
    const CLIENT_HP: [u8; 16] = hexd!(b"9f50449e04a0e810283a1e9933adedd2");
    const SERVER_SECRET: [u8; 32] =
      hexd!(b"3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
    const SERVER_KEY: [u8; 16] = hexd!(b"cf3a5331653c364c88f0f379b6067e37");
    const SERVER_IV: [u8; 12] = hexd!(b"0ac1493ca1905853b0bba03e");
    const SERVER_HP: [u8; 16] = hexd!(b"c206b8d9b9f0f37644430b490eeaa314");
    // A.2: the header of the packet without protection, with a 4-byte packet number of 2, and the
    // frames that start its payload, which PADDING frames complete to 1162 bytes
    const A2_HEADER: [u8; 22] = hexd!(b"c300000001088394c8f03e5157080000449e00000002");
    const A2_PAYLOAD_LEN: usize = 1162;
    // A.3: a 2-byte packet number of 1
    const A3_HEADER: [u8; 20] = hexd!(b"c1000000010008f067a5502a4262b50040750001");
    // A.5
    const A5_SECRET: [u8; 32] =
      hexd!(b"9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    const A5_IV: [u8; 12] = hexd!(b"e0459b3474bdd0e44a41c144");
    const A5_HP: [u8; 32] =
      hexd!(b"25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
    const A5_KEY: [u8; 32] =
      hexd!(b"c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
    const A5_KU: [u8; 32] =
      hexd!(b"1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9");
    const A5_HEADER: [u8; 4] = hexd!(b"4200bff4");
    const A5_PACKET: [u8; 21] = hexd!(b"4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
    const A5_PN: u64 = 654_360_564;
    const A2_FRAMES: [u8; 245] = hexd!(b"060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff");
    const A2_PACKET: [u8; 1200] = hexd!(b"c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934");
    const A3_PLAINTEXT: [u8; 99] = hexd!(b"02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304");
    const A3_PACKET: [u8; 135] = hexd!(b"cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee");

    const SUITES: [CipherSuite; 3] = [
      CipherSuite::Aes128GcmSha256,
      CipherSuite::Aes256GcmSha384,
      CipherSuite::Chacha20Poly1305Sha256,
    ];

    // A deterministic traffic secret of the length of the hash of `suite`
    fn secret_of(suite: CipherSuite, seed: u8) -> Vec<u8> {
      (0..suite.hash_len()).map(|el| el.wrapping_mul(7).wrapping_add(seed)).collect()
    }

    fn a2_plaintext() -> Vec<u8> {
      let mut plaintext = A2_FRAMES.to_vec();
      plaintext.resize(A2_PAYLOAD_LEN, 0);
      plaintext
    }

    // `header`, the plaintext and room for the tag
    fn unprotected(header: &[u8], payload: &[u8]) -> Vec<u8> {
      let mut packet = header.to_vec();
      packet.extend_from_slice(payload);
      packet.extend_from_slice(&[0; AEAD_TAG_LEN]);
      packet
    }

    // A short header packet with an 8-byte destination connection ID and a 4-byte packet number.
    // Returns the packet and the index of the packet number.
    fn short_packet(first: u8, pn: u64, payload: &[u8]) -> (Vec<u8>, usize) {
      let mut header = vec![first | 0b11];
      header.extend_from_slice(&DCID);
      let pn_offset = header.len();
      header.extend_from_slice(&u32::try_from(pn & 0xffff_ffff).unwrap().to_be_bytes());
      (unprotected(&header, payload), pn_offset)
    }

    // The label as built by hand, not by the code under test
    fn expand_label(suite: CipherSuite, secret: &[u8], label: &str, len: u8) -> Vec<u8> {
      let full = format!("tls13 {label}");
      let mut info = vec![0, len, u8::try_from(full.len()).unwrap()];
      info.extend_from_slice(full.as_bytes());
      info.push(0);
      let mut out = vec![0; usize::from(len)];
      match suite {
        CipherSuite::Aes128GcmSha256 | CipherSuite::Chacha20Poly1305Sha256 => {
          HkdfSha256Global::from_prk(secret).unwrap().expand(&info, &mut out).unwrap();
        }
        CipherSuite::Aes256GcmSha384 => {
          HkdfSha384Global::from_prk(secret).unwrap().expand(&info, &mut out).unwrap();
        }
      }
      out
    }

    // Both seal the same data the same way
    fn same_aead(lhs: &QuicAead, rhs: &QuicAead) -> bool {
      let mut lhs_data = [7; 20];
      let mut rhs_data = lhs_data;
      let lhs_tag = lhs.seal_in_place([3; 12], &[1, 2], &mut lhs_data).unwrap();
      let rhs_tag = rhs.seal_in_place([3; 12], &[1, 2], &mut rhs_data).unwrap();
      lhs_data == rhs_data && lhs_tag == rhs_tag
    }

    fn same_hp(lhs: &QuicHp, rhs: &QuicHp) -> bool {
      (0..8).all(|el| lhs.mask(&[el; 16]).unwrap() == rhs.mask(&[el; 16]).unwrap())
    }

    fn assert_keys(keys: &DirectionalKeys, secret: &[u8], key: &[u8], iv: &[u8], hp: &[u8]) {
      assert_eq!(keys.secret.as_slice(), secret);
      assert_eq!(keys.iv(), iv);
      assert_eq!(keys.hp_key.as_slice(), hp);
      assert!(same_hp(keys.hp(), &QuicHp::new(keys.suite(), hp).unwrap()));
      assert!(same_aead(keys.aead(), &QuicAead::new(keys.suite(), key).unwrap()));
    }

    // Protected packet -> packet number, header length and plaintext
    fn unprotect(
      keys: &DirectionalKeys,
      packet: &mut [u8],
      pn_offset: usize,
      largest: Option<u64>,
    ) -> crate::Result<(u64, Vec<u8>)> {
      let (pn, pn_len, _) = remove_header_protection(keys.hp(), packet, pn_offset, largest)?;
      let plaintext =
        open_payload(keys.aead(), keys.iv(), packet, pn_offset.wrapping_add(pn_len), pn)?.to_vec();
      Ok((pn, plaintext))
    }

    #[test]
    fn initial_secrets_match_rfc9001_a1() {
      let client = initial_keys(&DCID, false).unwrap();
      assert_keys(&client.local, &CLIENT_SECRET, &CLIENT_KEY, &CLIENT_IV, &CLIENT_HP);
      assert_keys(&client.remote, &SERVER_SECRET, &SERVER_KEY, &SERVER_IV, &SERVER_HP);
      let server = initial_keys(&DCID, true).unwrap();
      assert_keys(&server.local, &SERVER_SECRET, &SERVER_KEY, &SERVER_IV, &SERVER_HP);
      assert_keys(&server.remote, &CLIENT_SECRET, &CLIENT_KEY, &CLIENT_IV, &CLIENT_HP);
      assert_eq!(client.local.suite(), CipherSuite::Aes128GcmSha256);
      // Another connection ID, other keys
      let other = initial_keys(&[0; 8], false).unwrap();
      assert_ne!(other.local.secret.as_slice(), CLIENT_SECRET);
      assert_ne!(other.remote.secret.as_slice(), SERVER_SECRET);
      // The connection ID of any length
      assert!(initial_keys(&[], false).is_ok());
      assert!(initial_keys(&[1; 255], true).is_ok());
    }

    #[test]
    fn client_initial_protects_to_rfc9001_a2_bytes() {
      let client = initial_keys(&DCID, false).unwrap();
      let plaintext = a2_plaintext();
      let mut packet = unprotected(&A2_HEADER, &plaintext);
      let len = protect(&client.local, &mut packet, 18, 2, 4, A2_PAYLOAD_LEN).unwrap();
      assert_eq!(len, 1200);
      assert_eq!(packet, A2_PACKET);
      assert_eq!(client.local.packets_sealed(), 1);

      let server = initial_keys(&DCID, true).unwrap();
      let (pn, pn_len, first) =
        remove_header_protection(server.remote.hp(), &mut packet, 18, None).unwrap();
      assert_eq!((pn, pn_len, first), (2, 4, 0xc3));
      assert_eq!(packet.get(..22).unwrap(), A2_HEADER);
      let opened = open_payload(server.remote.aead(), server.remote.iv(), &mut packet, 22, pn);
      assert_eq!(opened.unwrap(), plaintext);
    }

    #[test]
    fn server_initial_matches_rfc9001_a3() {
      let server = initial_keys(&DCID, true).unwrap();
      let mut packet = unprotected(&A3_HEADER, &A3_PLAINTEXT);
      let len = protect(&server.local, &mut packet, 18, 1, 2, A3_PLAINTEXT.len()).unwrap();
      assert_eq!(len, 135);
      assert_eq!(packet, A3_PACKET);

      let client = initial_keys(&DCID, false).unwrap();
      let (pn, plaintext) = unprotect(&client.remote, &mut packet, 18, None).unwrap();
      assert_eq!(pn, 1);
      assert_eq!(plaintext, A3_PLAINTEXT);
    }

    #[test]
    fn chacha20_short_header_matches_rfc9001_a5() {
      let keys = keys_from_secret(CipherSuite::Chacha20Poly1305Sha256, &A5_SECRET).unwrap();
      assert_keys(&keys, &A5_SECRET, &A5_KEY, &A5_IV, &A5_HP);
      // The packet number takes 3 bytes, so no padding is needed for the sample
      let mut packet = unprotected(&A5_HEADER, &[1]);
      let len = protect(&keys, &mut packet, 1, A5_PN, 3, 1).unwrap();
      assert_eq!(len, 21);
      assert_eq!(packet, A5_PACKET);

      let (pn, plaintext) = unprotect(&keys, &mut packet, 1, Some(A5_PN - 1)).unwrap();
      assert_eq!((pn, plaintext), (A5_PN, vec![1]));
      // The secret of the next generation
      let next = keys.next_generation().unwrap();
      assert_eq!(next.secret.as_slice(), A5_KU);
      assert_eq!(next.hp_key.as_slice(), A5_HP);
    }

    #[test]
    fn secrets_use_the_quic_labels_for_every_suite() {
      for suite in SUITES {
        let secret = secret_of(suite, 1);
        let key_len = suite.cipher_key_len();
        let keys = keys_from_secret(suite, &secret).unwrap();
        let key = expand_label(suite, &secret, "quic key", key_len);
        let iv = expand_label(suite, &secret, "quic iv", 12);
        let hp = expand_label(suite, &secret, "quic hp", key_len);
        assert_keys(&keys, &secret, &key, &iv, &hp);

        let next_secret = expand_label(suite, &secret, "quic ku", suite.hash_len());
        let key = expand_label(suite, &next_secret, "quic key", key_len);
        let iv = expand_label(suite, &next_secret, "quic iv", 12);
        let next = keys.next_generation().unwrap();
        // The header protection key does not change
        assert_keys(&next, &next_secret, &key, &iv, &hp);
        assert!(same_hp(keys.hp(), next.hp()));
        assert!(!same_aead(keys.aead(), next.aead()));
        assert_ne!(keys.iv(), next.iv());
        // Generations chain
        let third = next.next_generation().unwrap();
        let third_secret = expand_label(suite, &next_secret, "quic ku", suite.hash_len());
        assert_eq!(third.secret.as_slice(), third_secret);
      }
    }

    #[test]
    fn secret_of_another_length_is_rejected() {
      for suite in SUITES {
        let hash_len = usize::from(suite.hash_len());
        for len in [0, 1, hash_len - 1, hash_len + 1, 64] {
          let rslt = keys_from_secret(suite, &vec![1; len]);
          assert!(matches!(rslt, Err(Error::Crypto(CryptoError::InvalidHashLength))), "{len}");
        }
      }
    }

    #[test]
    fn key_phase_flip_decrypts_with_next_keys() {
      for suite in SUITES {
        let secret = secret_of(suite, 9);
        let current = keys_from_secret(suite, &secret).unwrap();
        let next = current.next_generation().unwrap();
        let (sealed, pn_offset) = short_packet(0x40 | 0x04, 42, b"after the key update");
        let mut sealed = sealed;
        let len =
          protect(&next, &mut sealed, pn_offset, 42, 4, b"after the key update".len()).unwrap();
        assert_eq!(len, sealed.len());

        // The key phase is in the first byte, which is readable once header protection is removed
        // with the keys of the current generation: header protection keys do not change.
        let mut wire = sealed.clone();
        let (pn, pn_len, first) =
          remove_header_protection(current.hp(), &mut wire, pn_offset, Some(41)).unwrap();
        assert_eq!((pn, pn_len, first & 0x04), (42, 4, 0x04));
        let mut with_next_hp = sealed.clone();
        let again = remove_header_protection(next.hp(), &mut with_next_hp, pn_offset, Some(41));
        assert_eq!(again.unwrap(), (pn, pn_len, first));
        assert_eq!(wire, with_next_hp);

        let header_len = pn_offset + pn_len;
        let mut attempt = wire.clone();
        assert!(open_payload(current.aead(), current.iv(), &mut attempt, header_len, pn).is_err());
        let plaintext = open_payload(next.aead(), next.iv(), &mut wire, header_len, pn).unwrap();
        assert_eq!(plaintext, b"after the key update");

        // The generation after that opens nothing of this one, nor the other way around
        let third = next.next_generation().unwrap();
        let mut wire = sealed.clone();
        let _ = remove_header_protection(current.hp(), &mut wire, pn_offset, Some(41)).unwrap();
        assert!(open_payload(third.aead(), third.iv(), &mut wire, header_len, pn).is_err());
        let (old, pn_offset) = short_packet(0x40, 43, b"before the key update");
        let mut old = old;
        protect(&current, &mut old, pn_offset, 43, 4, b"before the key update".len()).unwrap();
        let (pn, _, first) =
          remove_header_protection(next.hp(), &mut old, pn_offset, Some(42)).unwrap();
        assert_eq!(first & 0x04, 0);
        let mut attempt = old.clone();
        assert!(open_payload(next.aead(), next.iv(), &mut attempt, header_len, pn).is_err());
        let plaintext = open_payload(current.aead(), current.iv(), &mut old, header_len, pn);
        assert_eq!(plaintext.unwrap(), b"before the key update");
      }
    }

    #[test]
    fn advance_replaces_the_keys_with_the_next_generation() {
      for suite in SUITES {
        let secret = secret_of(suite, 3);
        let mut keys = keys_from_secret(suite, &secret).unwrap();
        let next = keys.next_generation().unwrap();
        let (mut packet, pn_offset) = short_packet(0x40, 1, &[0x5a; 30]);
        protect(&keys, &mut packet, pn_offset, 1, 4, 30).unwrap();
        assert_eq!(keys.packets_sealed(), 1);
        keys.advance().unwrap();
        assert_eq!(keys.secret.as_slice(), next.secret.as_slice());
        assert!(same_aead(keys.aead(), next.aead()));
        assert_eq!(keys.iv(), next.iv());
        // A new AEAD key starts to count again
        assert_eq!(keys.packets_sealed(), 0);
        assert_eq!(keys.suite(), suite);
      }
    }

    #[test]
    fn packets_sealed_counts_only_sealed_packets() {
      let keys =
        keys_from_secret(CipherSuite::Aes128GcmSha256, &secret_of(CipherSuite::Aes128GcmSha256, 0))
          .unwrap();
      assert_eq!(keys.packets_sealed(), 0);
      for pn in 0..3 {
        let (mut packet, pn_offset) = short_packet(0x40, pn, &[1; 20]);
        protect(&keys, &mut packet, pn_offset, pn, 4, 20).unwrap();
      }
      assert_eq!(keys.packets_sealed(), 3);
      // Refused before sealing
      let (mut packet, pn_offset) = short_packet(0x40, 3, &[1; 20]);
      assert!(protect(&keys, &mut packet, pn_offset, 3, 4, 21).is_err());
      assert_eq!(keys.packets_sealed(), 3);
    }

    #[test]
    fn tampered_packet_fails_open() {
      let server = initial_keys(&DCID, true).unwrap();
      let mut packet = A2_PACKET.to_vec();
      assert!(unprotect(&server.remote, &mut packet, 18, None).is_ok());

      // (index, bit) to flip: the first byte, the connection ID (authenticated header), the
      // protected packet number, the ciphertext and the tag
      let last = A2_PACKET.len() - 1;
      for (index, bit) in [
        (0, 0x01),
        (0, 0x10),
        (8, 0x01),
        (18, 0x01),
        (21, 0x80),
        (600, 0x04),
        (last - 15, 0x80),
        (last, 0x01),
      ] {
        let mut tampered = A2_PACKET.to_vec();
        *tampered.get_mut(index).unwrap() ^= bit;
        let rslt = unprotect(&server.remote, &mut tampered, 18, None);
        assert!(matches!(rslt, Err(Error::Crypto(_))), "{index} {bit:#x}");
      }
      // Truncated: the tag is cut
      let mut tampered = A2_PACKET.to_vec();
      tampered.pop();
      assert!(unprotect(&server.remote, &mut tampered, 18, None).is_err());
      // Keys of the other direction
      let mut tampered = A2_PACKET.to_vec();
      assert!(unprotect(&server.local, &mut tampered, 18, None).is_err());
      // Another packet number in the nonce
      let mut tampered = A2_PACKET.to_vec();
      let (pn, pn_len, _) =
        remove_header_protection(server.remote.hp(), &mut tampered, 18, None).unwrap();
      let rslt =
        open_payload(server.remote.aead(), server.remote.iv(), &mut tampered, 18 + pn_len, pn + 1);
      assert!(rslt.is_err());
    }

    #[test]
    fn packets_without_a_sample_are_refused() {
      let keys = initial_keys(&DCID, false).unwrap();
      // Header protection needs 16 bytes starting 4 after the first byte of the packet number
      for len in 0..(18 + 4 + 16) {
        let mut packet = vec![0xc0; len];
        let rslt = remove_header_protection(keys.remote.hp(), &mut packet, 18, None);
        assert!(matches!(rslt, Err(Error::Quic(QuicError::PacketTooShort))), "{len}");
      }
      let mut packet = vec![0xc0; 18 + 4 + 16];
      assert!(remove_header_protection(keys.remote.hp(), &mut packet, 18, None).is_ok());
      // Not even the header
      let (pn_offset, mut packet) = (usize::MAX, vec![0; 100]);
      let rslt = remove_header_protection(keys.remote.hp(), &mut packet, pn_offset, None);
      assert!(matches!(rslt, Err(Error::Quic(QuicError::PacketTooShort))));
      let rslt = open_payload(keys.remote.aead(), keys.remote.iv(), &mut packet, 101, 0);
      assert!(matches!(rslt, Err(Error::Quic(QuicError::PacketTooShort))));
    }

    #[test]
    fn protect_refuses_what_it_cannot_do() {
      let keys =
        keys_from_secret(CipherSuite::Aes128GcmSha256, &secret_of(CipherSuite::Aes128GcmSha256, 0))
          .unwrap();
      let (packet, pn_offset) = short_packet(0x40, 7, &[1; 20]);
      let mut buffer = packet.clone();
      // The packet number has 1 to 4 bytes and the first byte is not part of it
      for (offset, pn_len) in [(pn_offset, 0), (pn_offset, 5), (0, 4)] {
        assert!(matches!(
          protect(&keys, &mut buffer, offset, 7, pn_len, 20),
          Err(Error::ProgrammingError)
        ));
      }
      // No room for the payload or for the tag
      for payload_len in [21, 36, 1 << 20, usize::MAX, usize::MAX - 12, usize::MAX - 28] {
        let rslt = protect(&keys, &mut buffer, pn_offset, 7, 4, payload_len);
        assert!(matches!(rslt, Err(Error::Quic(QuicError::BufferTooSmall))), "{payload_len}");
      }
      let rslt = protect(&keys, &mut buffer, usize::MAX - 1, 7, 4, 20);
      assert!(matches!(rslt, Err(Error::Quic(QuicError::BufferTooSmall))));
      // The sample would reach after the tag
      let mut small = vec![0x40; 1 + 1 + 2 + AEAD_TAG_LEN];
      let rslt = protect(&keys, &mut small, 1, 7, 1, 2);
      assert!(matches!(rslt, Err(Error::Quic(QuicError::PacketTooShort))));
      let mut small = vec![0x40; 1 + 1 + 3 + AEAD_TAG_LEN];
      assert!(protect(&keys, &mut small, 1, 7, 1, 3).is_ok());
      // Nothing was written by the refusals
      assert_eq!(buffer, packet);
      assert_eq!(keys.packets_sealed(), 1);
    }

    #[test]
    fn protect_seals_exactly_the_payload_it_is_told() {
      for suite in SUITES {
        let keys = keys_from_secret(suite, &secret_of(suite, 5)).unwrap();
        let payload = [0xa5; 33];
        let (mut packet, pn_offset) = short_packet(0x40, 9, &payload);
        let packet_len = packet.len();
        // Bytes that are not part of the packet: more plaintext after the tag, and a tag area with
        // content
        packet.extend_from_slice(&[0xee; 40]);
        packet.get_mut(packet_len - AEAD_TAG_LEN..packet_len).unwrap().fill(0x11);
        let len = protect(&keys, &mut packet, pn_offset, 9, 4, payload.len()).unwrap();
        assert_eq!(len, packet_len);
        assert_eq!(packet.get(len..).unwrap(), [0xee; 40]);

        let (pn, plaintext) =
          unprotect(&keys, packet.get_mut(..len).unwrap(), pn_offset, Some(8)).unwrap();
        assert_eq!((pn, plaintext.as_slice()), (9, payload.as_slice()));
      }
    }

    // Header protection hides the low 4 bits of the first byte of long headers and the low 5 of
    // short ones (RFC 9001 section 5.4.1): the form and the type of a long header stay readable.
    #[test]
    fn header_protection_covers_the_bits_that_the_rfc_says() {
      let suite = CipherSuite::Aes128GcmSha256;
      let keys = keys_from_secret(suite, &secret_of(suite, 8)).unwrap();
      // (first byte without protection, bits that must not change, bits that must change at some point)
      for (first, intact, covered) in [(0xc3, 0xf0, 0x0f), (0x43, 0xe0, 0x1f)] {
        let mut changed = 0;
        for pn in 0..64 {
          let mut packet = unprotected(&[first, 0, 0, 0, 1, 0, 0, 0, 0], &[0x5a; 40]);
          packet.get_mut(5..9).unwrap().copy_from_slice(&u32::to_be_bytes(pn));
          protect(&keys, &mut packet, 5, u64::from(pn), 4, 40).unwrap();
          let protected = *packet.first().unwrap();
          assert_eq!(protected & intact, first & intact);
          changed |= protected ^ first;
          let (got, pn_len, unprotected_first) =
            remove_header_protection(keys.hp(), &mut packet, 5, pn.checked_sub(1).map(u64::from))
              .unwrap();
          assert_eq!((got, pn_len, unprotected_first), (u64::from(pn), 4, first));
        }
        // Every covered bit was flipped by some mask
        assert_eq!(changed, covered);
      }
    }

    #[test]
    fn directional_keys_are_wiped_on_drop() {
      for suite in SUITES {
        let mut slot = MaybeUninit::<DirectionalKeys>::uninit();
        slot.write(keys_from_secret(suite, &secret_of(suite, 1)).unwrap());
        // SAFETY: the slot was initialized above
        let keys = unsafe { &*slot.as_ptr() };
        let secret = (keys.secret.as_ptr(), usize::from(keys.secret.len()));
        let hp_key = (keys.hp_key.as_ptr(), usize::from(keys.hp_key.len()));
        let iv = (keys.iv.as_ptr(), keys.iv.len());
        assert!(secret.1 >= 32 && hp_key.1 >= 16 && iv.1 == 12);
        let region = |(ptr, len): (*const u8, usize)| {
          // SAFETY: the bytes are inside of the slot, which the test owns, and were initialized
          unsafe { slice::from_raw_parts(ptr, len) }.to_vec()
        };
        assert!(region(secret).iter().any(|el| *el != 0));
        assert!(region(hp_key).iter().any(|el| *el != 0));
        assert!(region(iv).iter().any(|el| *el != 0));
        // SAFETY: the slot was initialized above and nothing reads it as a `DirectionalKeys` after
        // this
        unsafe { ptr::drop_in_place(slot.as_mut_ptr()) };
        assert_eq!(region(secret), vec![0; secret.1]);
        assert_eq!(region(hp_key), vec![0; hp_key.1]);
        assert_eq!(region(iv), vec![0; iv.1]);
      }
    }

    // Deriving the keys of a connection, and of a key update, allocates nothing either
    #[test]
    fn key_derivation_allocates_nothing() {
      use crate::{sync::AtomicU64, tests::_count_allocations_in};
      use core::sync::atomic::Ordering;

      static COUNTER: AtomicU64 = AtomicU64::new(0);
      let secrets = SUITES.map(|suite| secret_of(suite, 4));
      let round = || {
        drop(initial_keys(&DCID, true).unwrap());
        for (suite, secret) in SUITES.into_iter().zip(&secrets) {
          let keys = keys_from_secret(suite, secret).unwrap();
          drop(keys.next_generation().unwrap());
        }
      };
      round();
      _count_allocations_in(&COUNTER);
      let before = COUNTER.load(Ordering::SeqCst);
      for _ in 0..100 {
        round();
      }
      assert_eq!(COUNTER.load(Ordering::SeqCst) - before, 0);
    }

    // The keys are expanded once, protecting and unprotecting then allocate nothing
    #[cfg(not(miri))]
    #[test]
    fn protect_open_allocate_nothing() {
      use crate::{sync::AtomicU64, tests::_count_allocations_in};
      use core::sync::atomic::Ordering;

      fn allocations(suite: CipherSuite, counter: &'static AtomicU64) -> u64 {
        let secret = secret_of(suite, 2);
        let local = keys_from_secret(suite, &secret).unwrap();
        let remote = keys_from_secret(suite, &secret).unwrap();
        let mut buffer = [0u8; 1300];
        let mut round = |range: core::ops::Range<u64>| {
          for pn in range {
            buffer[0] = 0x43;
            buffer[1..9].copy_from_slice(&DCID);
            buffer[9..13].copy_from_slice(&u32::try_from(pn).unwrap().to_be_bytes());
            buffer[13..1213].fill(0x5a);
            let len = protect(&local, &mut buffer, 9, pn, 4, 1200).unwrap();
            assert_eq!(len, 1229);
            let packet = &mut buffer[..len];
            let largest = pn.checked_sub(1);
            let (got, pn_len, _) =
              remove_header_protection(remote.hp(), packet, 9, largest).unwrap();
            assert_eq!((got, pn_len), (pn, 4));
            let plaintext =
              open_payload(remote.aead(), remote.iv(), packet, 9 + pn_len, got).unwrap();
            assert_eq!(plaintext.len(), 1200);
          }
        };
        round(0..10);
        _count_allocations_in(counter);
        let before = counter.load(Ordering::SeqCst);
        round(10..1010);
        counter.load(Ordering::SeqCst) - before
      }

      static AES128: AtomicU64 = AtomicU64::new(0);
      static AES256: AtomicU64 = AtomicU64::new(0);
      static CHACHA: AtomicU64 = AtomicU64::new(0);
      assert_eq!(allocations(CipherSuite::Aes128GcmSha256, &AES128), 0, "AES-128-GCM");
      assert_eq!(allocations(CipherSuite::Aes256GcmSha384, &AES256), 0, "AES-256-GCM");
      assert_eq!(allocations(CipherSuite::Chacha20Poly1305Sha256, &CHACHA), 0, "ChaCha20-Poly1305");
    }
  }
}
