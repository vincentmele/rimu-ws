use crate::crypto::{Aes128HpAlr, Aes256HpAlr, Chacha20HpAlr, CryptoError, HpKey};
use aws_lc_rs::aead::quic::{AES_128, AES_256, Algorithm, CHACHA20, HeaderProtectionKey};

impl HpKey for Aes128HpAlr {
  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    Ok(Self(local_new_hp(&AES_128, key)?))
  }

  #[inline]
  fn mask(&self, sample: &[u8; 16]) -> crate::Result<[u8; 5]> {
    local_mask_hp(&self.0, sample)
  }
}

impl HpKey for Aes256HpAlr {
  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    Ok(Self(local_new_hp(&AES_256, key)?))
  }

  #[inline]
  fn mask(&self, sample: &[u8; 16]) -> crate::Result<[u8; 5]> {
    local_mask_hp(&self.0, sample)
  }
}

impl HpKey for Chacha20HpAlr {
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
