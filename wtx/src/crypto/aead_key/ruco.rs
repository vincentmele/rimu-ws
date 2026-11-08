use crate::crypto::{
  AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadKey, Aes128GcmKeyRuco, Aes256GcmKeyRuco,
  Chacha20Poly1305KeyRuco, CryptoError, aead::split_content_tag,
};
use aead::{AeadInOut as _, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;

impl AeadKey for Aes128GcmKeyRuco {
  const KEY_LEN: usize = 16;

  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    let Ok(elem) = Aes128Gcm::new_from_slice(key) else {
      core::hint::cold_path();
      return Err(CryptoError::InvalidAes128GcmData.into());
    };
    Ok(Self::from_key(elem))
  }

  #[inline]
  fn open_in_place<'data>(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &'data mut [u8],
  ) -> crate::Result<&'data mut [u8]> {
    let (content, tag) = split_content_tag(data, CryptoError::InvalidAes128GcmData)?;
    self.0.decrypt_inout_detached(&(nonce.into()), aad, content.into(), &(tag).into())?;
    Ok(content)
  }

  #[inline]
  fn seal_in_place(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
  ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
    Ok(self.0.encrypt_inout_detached(&(nonce.into()), aad, data.into())?.into())
  }
}

impl AeadKey for Aes256GcmKeyRuco {
  const KEY_LEN: usize = 32;

  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    let Ok(elem) = Aes256Gcm::new_from_slice(key) else {
      core::hint::cold_path();
      return Err(CryptoError::InvalidAes256GcmData.into());
    };
    Ok(Self::from_key(elem))
  }

  #[inline]
  fn open_in_place<'data>(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &'data mut [u8],
  ) -> crate::Result<&'data mut [u8]> {
    let (content, tag) = split_content_tag(data, CryptoError::InvalidAes256GcmData)?;
    self.0.decrypt_inout_detached(&(nonce.into()), aad, content.into(), &(tag).into())?;
    Ok(content)
  }

  #[inline]
  fn seal_in_place(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
  ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
    Ok(self.0.encrypt_inout_detached(&(nonce.into()), aad, data.into())?.into())
  }
}

impl AeadKey for Chacha20Poly1305KeyRuco {
  const KEY_LEN: usize = 32;

  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    let Ok(elem) = ChaCha20Poly1305::new_from_slice(key) else {
      core::hint::cold_path();
      return Err(CryptoError::InvalidChacha20Poly1305Data.into());
    };
    Ok(Self::from_key(elem))
  }

  #[inline]
  fn open_in_place<'data>(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &'data mut [u8],
  ) -> crate::Result<&'data mut [u8]> {
    let (content, tag) = split_content_tag(data, CryptoError::InvalidChacha20Poly1305Data)?;
    self.0.decrypt_inout_detached(&(nonce.into()), aad, content.into(), &(tag.into()))?;
    Ok(content)
  }

  #[inline]
  fn seal_in_place(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
  ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
    Ok(self.0.encrypt_inout_detached(&(nonce.into()), aad, data.into())?.into())
  }
}
