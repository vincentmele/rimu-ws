use crate::crypto::{AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadKey};

type Aes128GcmKeyTy = cfg_select! {
  feature = "crypto-ring" => crate::crypto::Aes128GcmKeyRing,
  feature = "crypto-graviola" => crate::crypto::Aes128GcmKeyGraviola,
  feature = "crypto-alr" => crate::crypto::Aes128GcmKeyAlr,
  feature = "crypto-ruco" => crate::crypto::Aes128GcmKeyRuco,
  _ => crate::crypto::AeadKeyDummy::<16>,
};
type Aes256GcmKeyTy = cfg_select! {
  feature = "crypto-ring" => crate::crypto::Aes256GcmKeyRing,
  feature = "crypto-graviola" => crate::crypto::Aes256GcmKeyGraviola,
  feature = "crypto-alr" => crate::crypto::Aes256GcmKeyAlr,
  feature = "crypto-ruco" => crate::crypto::Aes256GcmKeyRuco,
  _ => crate::crypto::AeadKeyDummy::<32>,
};
type Chacha20Poly1305KeyTy =
  cfg_select! {
    feature = "crypto-ring" => crate::crypto::Chacha20Poly1305KeyRing,
    feature = "crypto-graviola" => crate::crypto::Chacha20Poly1305KeyGraviola,
    feature = "crypto-alr" => crate::crypto::Chacha20Poly1305KeyAlr,
    feature = "crypto-ruco" => crate::crypto::Chacha20Poly1305KeyRuco,
    _ => crate::crypto::AeadKeyDummy::<32>,
  };

macro_rules! global {
  ($name:ident, $ty:ident) => {
    /// A structure that delegates execution to the selected crypto backend.
    #[derive(Debug)]
    pub struct $name($ty);

    impl AeadKey for $name {
      const KEY_LEN: usize = <$ty as AeadKey>::KEY_LEN;

      #[inline]
      fn new(key: &[u8]) -> crate::Result<Self> {
        Ok(Self(<$ty as AeadKey>::new(key)?))
      }

      #[inline]
      fn open_in_place<'data>(
        &self,
        nonce: [u8; AEAD_NONCE_LEN],
        aad: &[u8],
        data: &'data mut [u8],
      ) -> crate::Result<&'data mut [u8]> {
        self.0.open_in_place(nonce, aad, data)
      }

      #[inline]
      fn seal_in_place(
        &self,
        nonce: [u8; AEAD_NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
      ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
        self.0.seal_in_place(nonce, aad, data)
      }
    }
  };
}

global!(Aes128GcmKeyGlobal, Aes128GcmKeyTy);
global!(Aes256GcmKeyGlobal, Aes256GcmKeyTy);
global!(Chacha20Poly1305KeyGlobal, Chacha20Poly1305KeyTy);
