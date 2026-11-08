use crate::crypto::{
  AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadKey, Aes128GcmKeyGraviola, Aes256GcmKeyGraviola,
  Chacha20Poly1305KeyGraviola, CryptoError, aead::split_content_tag,
};
use graviola::aead::{AesGcm, ChaCha20Poly1305};

impl AeadKey for Aes128GcmKeyGraviola {
  const KEY_LEN: usize = 16;

  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    // `AesGcm::new` panics with other lengths
    if key.len() != Self::KEY_LEN {
      core::hint::cold_path();
      return Err(CryptoError::InvalidAes128GcmData.into());
    }
    Ok(Self::from_key(AesGcm::new(key)))
  }

  #[inline]
  fn open_in_place<'data>(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &'data mut [u8],
  ) -> crate::Result<&'data mut [u8]> {
    let (content, tag) = split_content_tag(data, CryptoError::InvalidAes128GcmData)?;
    self.0.decrypt(&nonce, aad, content, &tag)?;
    Ok(content)
  }

  #[inline]
  fn seal_in_place(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
  ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
    let mut tag = [0; AEAD_TAG_LEN];
    self.0.encrypt(&nonce, aad, data, &mut tag);
    Ok(tag)
  }
}

impl AeadKey for Aes256GcmKeyGraviola {
  const KEY_LEN: usize = 32;

  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    // `AesGcm::new` panics with other lengths
    if key.len() != Self::KEY_LEN {
      core::hint::cold_path();
      return Err(CryptoError::InvalidAes256GcmData.into());
    }
    Ok(Self::from_key(AesGcm::new(key)))
  }

  #[inline]
  fn open_in_place<'data>(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &'data mut [u8],
  ) -> crate::Result<&'data mut [u8]> {
    let (content, tag) = split_content_tag(data, CryptoError::InvalidAes256GcmData)?;
    self.0.decrypt(&nonce, aad, content, &tag)?;
    Ok(content)
  }

  #[inline]
  fn seal_in_place(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
  ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
    let mut tag = [0; AEAD_TAG_LEN];
    self.0.encrypt(&nonce, aad, data, &mut tag);
    Ok(tag)
  }
}

impl AeadKey for Chacha20Poly1305KeyGraviola {
  const KEY_LEN: usize = 32;

  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    let Ok(array) = <[u8; 32]>::try_from(key) else {
      core::hint::cold_path();
      return Err(CryptoError::InvalidChacha20Poly1305Data.into());
    };
    Ok(Self::from_key(ChaCha20Poly1305::new(array)))
  }

  #[inline]
  fn open_in_place<'data>(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &'data mut [u8],
  ) -> crate::Result<&'data mut [u8]> {
    let (content, tag) = split_content_tag(data, CryptoError::InvalidChacha20Poly1305Data)?;
    self.0.decrypt(&nonce, aad, content, &tag)?;
    Ok(content)
  }

  #[inline]
  fn seal_in_place(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
  ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
    let mut tag = [0; AEAD_TAG_LEN];
    self.0.encrypt(&nonce, aad, data, &mut tag);
    Ok(tag)
  }
}
