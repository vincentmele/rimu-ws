use crate::crypto::{Aes128HpRuco, Aes256HpRuco, Chacha20HpRuco, CryptoError, HpKey};
use aes::{
  Aes128, Aes256,
  cipher::{BlockCipherEncrypt, KeyInit},
};
use chacha20::{
  ChaChaCore, R20,
  cipher::{Block, KeyIvInit, StreamCipherCore},
  variants::Ietf,
};

impl HpKey for Aes128HpRuco {
  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    let Ok(elem) = Aes128::new_from_slice(key) else {
      core::hint::cold_path();
      return Err(CryptoError::InvalidHeaderProtection.into());
    };
    Ok(Self(elem))
  }

  #[inline]
  fn mask(&self, sample: &[u8; 16]) -> crate::Result<[u8; 5]> {
    let mut block = (*sample).into();
    self.0.encrypt_block(&mut block);
    Ok(first_five(block.into()))
  }
}

impl HpKey for Aes256HpRuco {
  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    let Ok(elem) = Aes256::new_from_slice(key) else {
      core::hint::cold_path();
      return Err(CryptoError::InvalidHeaderProtection.into());
    };
    Ok(Self(elem))
  }

  #[inline]
  fn mask(&self, sample: &[u8; 16]) -> crate::Result<[u8; 5]> {
    let mut block = (*sample).into();
    self.0.encrypt_block(&mut block);
    Ok(first_five(block.into()))
  }
}

impl HpKey for Chacha20HpRuco {
  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    let Ok(array) = <[u8; 32]>::try_from(key) else {
      core::hint::cold_path();
      return Err(CryptoError::InvalidHeaderProtection.into());
    };
    Ok(Self(array))
  }

  // RFC 9001 section 5.4.4: the first four bytes of the sample are the little-endian block
  // counter and the remaining twelve the nonce. The mask is the start of that block.
  //
  // The stream cipher wrapper refuses the last block of the 32-bit counter (RFC 8439 does not
  // allow the keystream to go past it) but a counter taken from a sample can be any value, so the
  // core produces the block directly. A single block is never past the end.
  #[inline]
  fn mask(&self, sample: &[u8; 16]) -> crate::Result<[u8; 5]> {
    let Some((counter, nonce)) = sample.split_first_chunk::<4>() else {
      core::hint::cold_path();
      return Err(CryptoError::InvalidHeaderProtection.into());
    };
    let nonce = <[u8; 12]>::try_from(nonce)?;
    let mut core = ChaChaCore::<R20, Ietf>::new(&self.0.into(), &nonce.into());
    core.set_block_pos(u32::from_le_bytes(*counter));
    let mut block = Block::<ChaChaCore<R20, Ietf>>::default();
    core.write_keystream_block(&mut block);
    let [a, b, c, d, e, ..] = <[u8; 64]>::from(block);
    Ok([a, b, c, d, e])
  }
}

#[inline]
fn first_five(block: [u8; 16]) -> [u8; 5] {
  let [a, b, c, d, e, ..] = block;
  [a, b, c, d, e]
}
