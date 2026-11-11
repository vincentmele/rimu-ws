use crate::crypto::HpKey;

type Aes128HpTy = cfg_select! {
  feature = "crypto-ring" => crate::crypto::Aes128HpRing,
  feature = "crypto-alr" => crate::crypto::Aes128HpAlr,
  feature = "crypto-ruco" => crate::crypto::Aes128HpRuco,
  // Graviola has no header protection
  _ => crate::crypto::HpKeyDummy,
};
type Aes256HpTy = cfg_select! {
  feature = "crypto-ring" => crate::crypto::Aes256HpRing,
  feature = "crypto-alr" => crate::crypto::Aes256HpAlr,
  feature = "crypto-ruco" => crate::crypto::Aes256HpRuco,
  _ => crate::crypto::HpKeyDummy,
};
type Chacha20HpTy = cfg_select! {
  feature = "crypto-ring" => crate::crypto::Chacha20HpRing,
  feature = "crypto-alr" => crate::crypto::Chacha20HpAlr,
  feature = "crypto-ruco" => crate::crypto::Chacha20HpRuco,
  _ => crate::crypto::HpKeyDummy,
};

// Final review I1: with a backend that has header protection the globals use it, whatever other
// backends are on: Graviola, which has none, must not make every QUIC handshake fail. The dummy is
// the only header protection without state.
const _: () = assert!(size_of::<crate::crypto::HpKeyDummy>() == 0);
#[cfg(any(feature = "crypto-ring", feature = "crypto-alr", feature = "crypto-ruco"))]
const _: () = assert!(
  size_of::<Aes128HpTy>() > 0 && size_of::<Aes256HpTy>() > 0 && size_of::<Chacha20HpTy>() > 0,
  "a header protection global is the dummy although a backend with header protection is on"
);

macro_rules! global {
  ($name:ident, $ty:ident) => {
    /// A structure that delegates execution to the selected crypto backend.
    #[derive(Debug)]
    pub struct $name($ty);

    impl HpKey for $name {
      #[inline]
      fn new(key: &[u8]) -> crate::Result<Self> {
        Ok(Self(<$ty as HpKey>::new(key)?))
      }

      #[inline]
      fn mask(&self, sample: &[u8; 16]) -> crate::Result<[u8; 5]> {
        self.0.mask(sample)
      }
    }
  };
}

global!(Aes128HpGlobal, Aes128HpTy);
global!(Aes256HpGlobal, Aes256HpTy);
global!(Chacha20HpGlobal, Chacha20HpTy);
