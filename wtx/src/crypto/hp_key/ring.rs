use crate::crypto::{Aes128HpRing, Aes256HpRing, Chacha20HpRing, CryptoError, HpKey};
use ring::aead::quic::{AES_128, AES_256, Algorithm, CHACHA20, HeaderProtectionKey};

impl HpKey for Aes128HpRing {
  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    Ok(Self(local_new_hp(&AES_128, key)?))
  }

  #[inline]
  fn mask(&self, sample: &[u8; 16]) -> crate::Result<[u8; 5]> {
    local_mask_hp(&self.0, sample)
  }
}

impl HpKey for Aes256HpRing {
  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    Ok(Self(local_new_hp(&AES_256, key)?))
  }

  #[inline]
  fn mask(&self, sample: &[u8; 16]) -> crate::Result<[u8; 5]> {
    local_mask_hp(&self.0, sample)
  }
}

impl HpKey for Chacha20HpRing {
  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    Ok(Self(local_new_hp(&CHACHA20, key)?))
  }

  #[inline]
  fn mask(&self, sample: &[u8; 16]) -> crate::Result<[u8; 5]> {
    local_mask_hp(&self.0, sample)
  }
}

common_hp_key_functions!();
