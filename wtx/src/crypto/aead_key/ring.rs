use crate::crypto::{
  AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadKey, Aes128GcmKeyRing, Aes256GcmKeyRing,
  Chacha20Poly1305KeyRing, CryptoError,
};
use ring::aead::{
  AES_128_GCM, AES_256_GCM, Aad, Algorithm, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey,
};

impl AeadKey for Aes128GcmKeyRing {
  const KEY_LEN: usize = 16;

  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    Ok(Self::from_key(local_new_key(&AES_128_GCM, CryptoError::InvalidAes128GcmData, key)?))
  }

  #[inline]
  fn open_in_place<'data>(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &'data mut [u8],
  ) -> crate::Result<&'data mut [u8]> {
    local_open_key(aad, data, CryptoError::InvalidAes128GcmData, &self.0, nonce)
  }

  #[inline]
  fn seal_in_place(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
  ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
    local_seal_key(aad, data, CryptoError::InvalidAes128GcmData, &self.0, nonce)
  }
}

impl AeadKey for Aes256GcmKeyRing {
  const KEY_LEN: usize = 32;

  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    Ok(Self::from_key(local_new_key(&AES_256_GCM, CryptoError::InvalidAes256GcmData, key)?))
  }

  #[inline]
  fn open_in_place<'data>(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &'data mut [u8],
  ) -> crate::Result<&'data mut [u8]> {
    local_open_key(aad, data, CryptoError::InvalidAes256GcmData, &self.0, nonce)
  }

  #[inline]
  fn seal_in_place(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
  ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
    local_seal_key(aad, data, CryptoError::InvalidAes256GcmData, &self.0, nonce)
  }
}

impl AeadKey for Chacha20Poly1305KeyRing {
  const KEY_LEN: usize = 32;

  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    Ok(Self::from_key(local_new_key(
      &CHACHA20_POLY1305,
      CryptoError::InvalidChacha20Poly1305Data,
      key,
    )?))
  }

  #[inline]
  fn open_in_place<'data>(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &'data mut [u8],
  ) -> crate::Result<&'data mut [u8]> {
    local_open_key(aad, data, CryptoError::InvalidChacha20Poly1305Data, &self.0, nonce)
  }

  #[inline]
  fn seal_in_place(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
  ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
    local_seal_key(aad, data, CryptoError::InvalidChacha20Poly1305Data, &self.0, nonce)
  }
}

common_aead_key_functions!();
