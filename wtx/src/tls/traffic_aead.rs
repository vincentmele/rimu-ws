use crate::{
  crypto::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadKey as _, Aes128GcmKeyGlobal, Aes256GcmKeyGlobal,
    Chacha20Poly1305KeyGlobal,
  },
  tls::CipherSuite,
};

/// The AEAD of one of the cipher suites of TLS 1.3, with its key already expanded: the record
/// layer of TLS and the packet protection of QUIC seal and open with one per traffic key.
///
/// The expanded key wipes itself when dropped.
#[derive(Debug)]
pub(crate) enum TrafficAead {
  Aes128(Aes128GcmKeyGlobal),
  Aes256(Aes256GcmKeyGlobal),
  Chacha(Chacha20Poly1305KeyGlobal),
}

impl TrafficAead {
  /// Expands `key`, which has the key length of `suite`.
  #[inline]
  pub(crate) fn new(suite: CipherSuite, key: &[u8]) -> crate::Result<Self> {
    Ok(match suite {
      CipherSuite::Aes128GcmSha256 => Self::Aes128(Aes128GcmKeyGlobal::new(key)?),
      CipherSuite::Aes256GcmSha384 => Self::Aes256(Aes256GcmKeyGlobal::new(key)?),
      CipherSuite::Chacha20Poly1305Sha256 => Self::Chacha(Chacha20Poly1305KeyGlobal::new(key)?),
    })
  }

  /// See [`crate::crypto::AeadKey::open_in_place`].
  #[inline]
  pub(crate) fn open_in_place<'data>(
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

  /// See [`crate::crypto::AeadKey::seal_in_place`].
  #[inline]
  pub(crate) fn seal_in_place(
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
