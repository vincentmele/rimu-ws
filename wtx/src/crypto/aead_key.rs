#[cfg(feature = "crypto-alr")]
mod alr;
pub(crate) mod global;
#[cfg(feature = "crypto-graviola")]
mod graviola;
#[cfg(feature = "crypto-ring")]
mod ring;
#[cfg(feature = "crypto-ruco")]
mod ruco;

use crate::crypto::{AEAD_NONCE_LEN, AEAD_TAG_LEN, dummy_crypto_call};

/// Authenticated Encryption with Associated Data bound to a key.
///
/// Unlike [`crate::crypto::Aead`], the key schedule (and any other precomputation) is expanded
/// once in [`AeadKey::new`] and reused by every call, which is what a protocol that seals and
/// opens one record per packet, like QUIC, needs.
pub trait AeadKey: Sized {
  /// Length in bytes of the key accepted by [`AeadKey::new`].
  const KEY_LEN: usize;

  /// Expands `key`, which must have exactly [`AeadKey::KEY_LEN`] bytes.
  fn new(key: &[u8]) -> crate::Result<Self>;

  /// Decrypts `data` in-place, which must contain the ciphertext followed by the
  /// [`AEAD_TAG_LEN`]-byte tag.
  ///
  /// Returns the plaintext, which is the prefix of `data` that precedes the tag. The content of
  /// `data` is unspecified if the authentication fails.
  fn open_in_place<'data>(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &'data mut [u8],
  ) -> crate::Result<&'data mut [u8]>;

  /// Encrypts the plaintext `data` in-place.
  ///
  /// The tag is not written into `data`, it is returned instead.
  fn seal_in_place(
    &self,
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    data: &mut [u8],
  ) -> crate::Result<[u8; AEAD_TAG_LEN]>;
}

/// Dummy [`AeadKey`] implementation used when no backend is enabled.
///
/// `KEY_LEN` is the length of the key of the algorithm that the instance stands for.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct AeadKeyDummy<const KEY_LEN: usize>;

impl<const KEY_LEN: usize> AeadKey for AeadKeyDummy<KEY_LEN> {
  const KEY_LEN: usize = KEY_LEN;

  #[inline]
  fn new(_: &[u8]) -> crate::Result<Self> {
    Ok(Self)
  }

  #[inline]
  fn open_in_place<'data>(
    &self,
    _: [u8; AEAD_NONCE_LEN],
    _: &[u8],
    _: &'data mut [u8],
  ) -> crate::Result<&'data mut [u8]> {
    dummy_crypto_call();
  }

  #[inline]
  fn seal_in_place(
    &self,
    _: [u8; AEAD_NONCE_LEN],
    _: &[u8],
    _: &mut [u8],
  ) -> crate::Result<[u8; AEAD_TAG_LEN]> {
    dummy_crypto_call();
  }
}

#[cfg(all(
  test,
  any(
    feature = "crypto-alr",
    feature = "crypto-graviola",
    feature = "crypto-ring",
    feature = "crypto-ruco"
  )
))]
mod tests {
  use crate::{
    crypto::{AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadKey},
    sync::AtomicU64,
    tests::_count_allocations_in,
  };
  use alloc::vec::Vec;
  use core::sync::atomic::Ordering;

  // McGrew and Viega, "The Galois/Counter Mode of Operation", test cases 4 and 16
  const GCM_AAD: [u8; 20] = hexd!(b"feedfacedeadbeeffeedfacedeadbeefabaddad2");
  const GCM_NONCE: [u8; 12] = hexd!(b"cafebabefacedbaddecaf888");
  const GCM_PLAINTEXT: [u8; 60] = hexd!(
    b"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
  );
  const AES_128_KEY: [u8; 16] = hexd!(b"feffe9928665731c6d6a8f9467308308");
  const AES_128_CIPHERTEXT: [u8; 60] = hexd!(
    b"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
  );
  const AES_128_TAG: [u8; 16] = hexd!(b"5bc94fbc3221a5db94fae95ae7121a47");
  const AES_256_KEY: [u8; 32] =
    hexd!(b"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
  const AES_256_CIPHERTEXT: [u8; 60] = hexd!(
    b"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
  );
  const AES_256_TAG: [u8; 16] = hexd!(b"76fc6ece0f4e1768cddf8853bb2d551b");
  // RFC 9001 appendix A.5: the short header packet protected with ChaCha20-Poly1305. The nonce is
  // the IV xor the packet number 654360564.
  const CHACHA_KEY: [u8; 32] =
    hexd!(b"c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
  const CHACHA_NONCE: [u8; 12] = hexd!(b"e0459b3474bdd0e46d417eb0");
  const CHACHA_AAD: [u8; 4] = hexd!(b"4200bff4");
  const CHACHA_PLAINTEXT: [u8; 1] = hexd!(b"01");
  const CHACHA_CIPHERTEXT: [u8; 1] = hexd!(b"65");
  const CHACHA_TAG: [u8; 16] = hexd!(b"5e5cd55c41f69080575d7999c25a5bfb");

  fn known_answer<K>(
    key: &[u8],
    nonce: [u8; AEAD_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &[u8],
    tag: [u8; AEAD_TAG_LEN],
  ) where
    K: AeadKey,
  {
    let key = K::new(key).unwrap();
    let mut sealed = [plaintext, &[0; AEAD_TAG_LEN]].concat();
    let (content, _) = sealed.split_at_mut(plaintext.len());
    assert_eq!(key.seal_in_place(nonce, aad, content).unwrap(), tag);
    assert_eq!(content, ciphertext);
    sealed.get_mut(plaintext.len()..).unwrap().copy_from_slice(&tag);
    assert_eq!(key.open_in_place(nonce, aad, &mut sealed).unwrap(), plaintext);
  }

  fn round_trip_and_tamper<K>()
  where
    K: AeadKey,
  {
    let key = K::new(&[7; 32][..K::KEY_LEN]).unwrap();
    let nonce = [3; AEAD_NONCE_LEN];
    let aad = [1, 2, 3, 4, 5];
    for len in [0, 1, 15, 16, 17, 1200] {
      let plaintext: Vec<u8> = (0..len).map(|el: usize| el as u8).collect();
      let mut data = plaintext.clone();
      data.extend_from_slice(&[0; AEAD_TAG_LEN]);
      let tag = key.seal_in_place(nonce, &aad, data.get_mut(..len).unwrap()).unwrap();
      if len > 0 {
        assert_ne!(data.get(..len).unwrap(), plaintext);
      }
      data.get_mut(len..).unwrap().copy_from_slice(&tag);
      let sealed = data.clone();
      assert_eq!(key.open_in_place(nonce, &aad, &mut data).unwrap(), plaintext);

      // One flipped bit in the tag, in the ciphertext, in the aad or in the nonce, or a truncated
      // packet, is rejected.
      let mut tampered = sealed.clone();
      *tampered.last_mut().unwrap() ^= 1;
      assert!(key.open_in_place(nonce, &aad, &mut tampered).is_err());
      if len > 0 {
        let mut tampered = sealed.clone();
        *tampered.first_mut().unwrap() ^= 0x80;
        assert!(key.open_in_place(nonce, &aad, &mut tampered).is_err());
      }
      let mut tampered = sealed.clone();
      assert!(key.open_in_place(nonce, &[1, 2, 3, 4, 4], &mut tampered).is_err());
      let mut tampered = sealed.clone();
      let mut other_nonce = nonce;
      other_nonce[11] ^= 1;
      assert!(key.open_in_place(other_nonce, &aad, &mut tampered).is_err());
      let mut tampered = sealed.clone();
      tampered.pop();
      assert!(key.open_in_place(nonce, &aad, &mut tampered).is_err());
    }
    // Shorter than a tag
    assert!(key.open_in_place(nonce, &aad, &mut [0; AEAD_TAG_LEN - 1]).is_err());
    assert!(key.open_in_place(nonce, &aad, &mut []).is_err());
  }

  fn another_key_is_rejected<K>()
  where
    K: AeadKey,
  {
    let sealing = K::new(&[7; 32][..K::KEY_LEN]).unwrap();
    let opening = K::new(&[8; 32][..K::KEY_LEN]).unwrap();
    let mut data = [9; 20];
    let tag = sealing.seal_in_place([0; AEAD_NONCE_LEN], &[], data.get_mut(..4).unwrap()).unwrap();
    data.get_mut(4..).unwrap().copy_from_slice(&tag);
    assert!(opening.open_in_place([0; AEAD_NONCE_LEN], &[], &mut data).is_err());
  }

  fn wrong_key_length_is_rejected<K>()
  where
    K: AeadKey,
  {
    assert!(K::new(&[]).is_err());
    assert!(K::new(&[0; 64][..K::KEY_LEN - 1]).is_err());
    assert!(K::new(&[0; 64][..K::KEY_LEN + 1]).is_err());
    assert!(K::new(&[0; 64]).is_err());
    assert!(K::new(&[0; 64][..K::KEY_LEN]).is_ok());
  }

  // The key is expanded once, then neither sealing nor opening allocates.
  fn allocations_of_seal_and_open<K>(counter: &'static AtomicU64) -> u64
  where
    K: AeadKey,
  {
    let key = K::new(&[7; 32][..K::KEY_LEN]).unwrap();
    let nonce = [3; AEAD_NONCE_LEN];
    let mut data = [5; 1200 + AEAD_TAG_LEN];
    let mut round = |count: usize| {
      for _ in 0..count {
        let tag = key.seal_in_place(nonce, &[1, 2, 3], data.get_mut(..1200).unwrap()).unwrap();
        data.get_mut(1200..).unwrap().copy_from_slice(&tag);
        assert_eq!(key.open_in_place(nonce, &[1, 2, 3], &mut data).unwrap().len(), 1200);
      }
    };
    round(10);
    _count_allocations_in(counter);
    let before = counter.load(Ordering::SeqCst);
    round(1000);
    counter.load(Ordering::SeqCst) - before
  }

  // `$allocations` is the `cfg` predicate of the allocation test
  macro_rules! suite {
    ($name:ident, $allocations:meta, $aes128:ty, $aes256:ty, $chacha:ty) => {
      mod $name {
        use super::*;

        #[test]
        fn aes128_gcm_matches_the_gcm_specification() {
          known_answer::<$aes128>(
            &AES_128_KEY,
            GCM_NONCE,
            &GCM_AAD,
            &GCM_PLAINTEXT,
            &AES_128_CIPHERTEXT,
            AES_128_TAG,
          );
        }

        #[test]
        fn aes256_gcm_matches_the_gcm_specification() {
          known_answer::<$aes256>(
            &AES_256_KEY,
            GCM_NONCE,
            &GCM_AAD,
            &GCM_PLAINTEXT,
            &AES_256_CIPHERTEXT,
            AES_256_TAG,
          );
        }

        #[test]
        fn chacha20_poly1305_matches_rfc9001_a5() {
          known_answer::<$chacha>(
            &CHACHA_KEY,
            CHACHA_NONCE,
            &CHACHA_AAD,
            &CHACHA_PLAINTEXT,
            &CHACHA_CIPHERTEXT,
            CHACHA_TAG,
          );
        }

        #[test]
        fn key_lengths() {
          assert_eq!(<$aes128 as AeadKey>::KEY_LEN, 16);
          assert_eq!(<$aes256 as AeadKey>::KEY_LEN, 32);
          assert_eq!(<$chacha as AeadKey>::KEY_LEN, 32);
          wrong_key_length_is_rejected::<$aes128>();
          wrong_key_length_is_rejected::<$aes256>();
          wrong_key_length_is_rejected::<$chacha>();
        }

        #[test]
        fn aead_key_round_trip_and_tamper() {
          round_trip_and_tamper::<$aes128>();
          round_trip_and_tamper::<$aes256>();
          round_trip_and_tamper::<$chacha>();
          another_key_is_rejected::<$aes128>();
          another_key_is_rejected::<$aes256>();
          another_key_is_rejected::<$chacha>();
        }

        #[cfg($allocations)]
        #[test]
        fn aead_key_new_once_then_seal_allocates_nothing() {
          static AES128: AtomicU64 = AtomicU64::new(0);
          static AES256: AtomicU64 = AtomicU64::new(0);
          static CHACHA: AtomicU64 = AtomicU64::new(0);
          assert_eq!(allocations_of_seal_and_open::<$aes128>(&AES128), 0, "AES-128-GCM");
          assert_eq!(allocations_of_seal_and_open::<$aes256>(&AES256), 0, "AES-256-GCM");
          assert_eq!(allocations_of_seal_and_open::<$chacha>(&CHACHA), 0, "ChaCha20-Poly1305");
        }
      }
    };
  }

  suite!(
    global,
    // Graviola allocates in debug builds, see below
    not(all(feature = "crypto-graviola", not(feature = "crypto-ring"), debug_assertions)),
    crate::crypto::Aes128GcmKeyGlobal,
    crate::crypto::Aes256GcmKeyGlobal,
    crate::crypto::Chacha20Poly1305KeyGlobal
  );
  #[cfg(feature = "crypto-alr")]
  suite!(
    alr,
    all(),
    crate::crypto::Aes128GcmKeyAlr,
    crate::crypto::Aes256GcmKeyAlr,
    crate::crypto::Chacha20Poly1305KeyAlr
  );
  #[cfg(feature = "crypto-graviola")]
  // In debug builds Graviola reads an environment variable, which allocates, every time it
  // checks a CPU feature (`low::x86_64::cpu::test_toggle`), so it is only allocation-free in
  // release builds.
  suite!(
    graviola,
    not(debug_assertions),
    crate::crypto::Aes128GcmKeyGraviola,
    crate::crypto::Aes256GcmKeyGraviola,
    crate::crypto::Chacha20Poly1305KeyGraviola
  );
  #[cfg(feature = "crypto-ring")]
  suite!(
    ring,
    all(),
    crate::crypto::Aes128GcmKeyRing,
    crate::crypto::Aes256GcmKeyRing,
    crate::crypto::Chacha20Poly1305KeyRing
  );
  #[cfg(feature = "crypto-ruco")]
  suite!(
    ruco,
    all(),
    crate::crypto::Aes128GcmKeyRuco,
    crate::crypto::Aes256GcmKeyRuco,
    crate::crypto::Chacha20Poly1305KeyRuco
  );
}
