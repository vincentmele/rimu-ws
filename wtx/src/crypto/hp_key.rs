#[cfg(feature = "crypto-alr")]
mod alr;
pub(crate) mod global;
#[cfg(feature = "crypto-ring")]
mod ring;
#[cfg(feature = "crypto-ruco")]
mod ruco;
#[cfg(all(target_arch = "x86_64", feature = "quic", feature = "std"))]
pub(crate) mod x86_aesni;

use crate::crypto::CryptoError;

/// QUIC header protection (RFC 9001 section 5.4) bound to a key.
///
/// The key is expanded once in [`HpKey::new`] and reused by every [`HpKey::mask`].
pub trait HpKey: Sized {
  /// Expands `key`, which has the length of the key of the algorithm: 16 bytes for AES-128, 32 for
  /// AES-256 and 32 for ChaCha20.
  fn new(key: &[u8]) -> crate::Result<Self>;

  /// Computes the 5-byte mask of the 16-byte ciphertext sample.
  fn mask(&self, sample: &[u8; 16]) -> crate::Result<[u8; 5]>;

  // ***** PROVIDED *****

  /// Computes the mask of each element of `samples` into the element of `out` at the same index.
  ///
  /// Fails without computing anything if the lengths differ.
  #[inline]
  fn masks(&self, samples: &[[u8; 16]], out: &mut [[u8; 5]]) -> crate::Result<()> {
    if samples.len() != out.len() {
      core::hint::cold_path();
      return Err(CryptoError::InvalidHeaderProtection.into());
    }
    for (sample, elem) in samples.iter().zip(out) {
      *elem = self.mask(sample)?;
    }
    Ok(())
  }
}

/// Dummy [`HpKey`] implementation used when the selected backend, or the lack of one, has no
/// header protection, as is the case of Graviola.
///
/// Neither the constructor nor [`HpKey::mask`] panic: they fail with
/// [`CryptoError::UnsupportedHeaderProtection`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HpKeyDummy(());

impl HpKey for HpKeyDummy {
  #[inline]
  fn new(_: &[u8]) -> crate::Result<Self> {
    core::hint::cold_path();
    Err(CryptoError::UnsupportedHeaderProtection.into())
  }

  #[inline]
  fn mask(&self, _: &[u8; 16]) -> crate::Result<[u8; 5]> {
    core::hint::cold_path();
    Err(CryptoError::UnsupportedHeaderProtection.into())
  }
}

#[cfg(test)]
mod tests {
  use super::HpKeyDummy;
  use crate::crypto::{CryptoError, HpKey};
  use core::{mem::MaybeUninit, ptr, slice};

  // RFC 9001 appendix A.2: client Initial
  const AES_128_KEY: [u8; 16] = hexd!(b"9f50449e04a0e810283a1e9933adedd2");
  const AES_128_SAMPLE: [u8; 16] = hexd!(b"d1b1c98dd7689fb8ec11d242b123dc9b");
  const AES_128_MASK: [u8; 5] = hexd!(b"437b9aec36");
  // FIPS 197 appendix C.1 and C.3: the mask is the start of the encrypted block
  const FIPS_BLOCK: [u8; 16] = hexd!(b"00112233445566778899aabbccddeeff");
  const FIPS_128_KEY: [u8; 16] = hexd!(b"000102030405060708090a0b0c0d0e0f");
  const FIPS_128_MASK: [u8; 5] = hexd!(b"69c4e0d86a");
  const FIPS_256_KEY: [u8; 32] =
    hexd!(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  const FIPS_256_MASK: [u8; 5] = hexd!(b"8ea2b7ca51");
  // RFC 9001 appendix A.5: short header packet
  const CHACHA_KEY: [u8; 32] =
    hexd!(b"25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
  const CHACHA_SAMPLE: [u8; 16] = hexd!(b"5e5cd55c41f69080575d7999c25a5bfb");
  const CHACHA_MASK: [u8; 5] = hexd!(b"aefefe7d03");
  // RFC 8439 section 2.3.2: the first block with counter 1 starts with 10f1e7e4d13b5915
  const CHACHA_RFC8439_KEY: [u8; 32] =
    hexd!(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  const CHACHA_RFC8439_SAMPLE: [u8; 16] = hexd!(b"01000000000000090000004a00000000");
  const CHACHA_RFC8439_MASK: [u8; 5] = hexd!(b"10f1e7e4d1");
  // Counters at the ends of the 32-bit range, computed with OpenSSL (pyca/cryptography)
  const CHACHA_COUNTER_MAX_SAMPLE: [u8; 16] = hexd!(b"ffffffff0102030405060708090a0b0c");
  const CHACHA_COUNTER_MAX_MASK: [u8; 5] = hexd!(b"0f24a84f30");
  const CHACHA_COUNTER_MAX_MINUS_ONE_SAMPLE: [u8; 16] = hexd!(b"fffffffe0102030405060708090a0b0c");
  const CHACHA_COUNTER_MAX_MINUS_ONE_MASK: [u8; 5] = hexd!(b"703672abe4");
  const CHACHA_ZERO_SAMPLE: [u8; 16] = [0; 16];
  const CHACHA_ZERO_MASK: [u8; 5] = hexd!(b"8683fb9b2d");

  fn check<K>(key: &[u8], sample: [u8; 16], expected: [u8; 5])
  where
    K: HpKey,
  {
    let key = K::new(key).unwrap();
    assert_eq!(key.mask(&sample).unwrap(), expected);
    // Stateless: a second call is the same
    assert_eq!(key.mask(&sample).unwrap(), expected);
  }

  fn masks_loop_over_mask<K>(key: &[u8])
  where
    K: HpKey,
  {
    let key = K::new(key).unwrap();
    let samples = [[1; 16], [2; 16], [0xff; 16], [0; 16]];
    let mut out = [[0; 5]; 4];
    key.masks(&samples, &mut out).unwrap();
    for (sample, mask) in samples.iter().zip(out) {
      assert_eq!(key.mask(sample).unwrap(), mask);
    }
    assert_ne!(out[0], out[1]);
    key.masks(&[], &mut []).unwrap();
    // The lengths must match
    let mut short = [[7; 5]; 3];
    assert!(key.masks(&samples, &mut short).is_err());
    assert_eq!(short, [[7; 5]; 3]);
    assert!(key.masks(samples.get(..3).unwrap(), &mut out).is_err());
  }

  fn wrong_key_length_is_rejected<K>(len: usize)
  where
    K: HpKey,
  {
    assert!(K::new(&[]).is_err());
    assert!(K::new(&[0; 64][..len - 1]).is_err());
    assert!(K::new(&[0; 64][..len + 1]).is_err());
    assert!(K::new(&[0; 64][..len]).is_ok());
  }

  #[test]
  fn dummy_returns_an_error_instead_of_panicking() {
    assert!(matches!(
      HpKeyDummy::new(&[0; 16]),
      Err(crate::Error::Crypto(CryptoError::UnsupportedHeaderProtection))
    ));
    assert!(matches!(
      HpKeyDummy(()).mask(&[0; 16]),
      Err(crate::Error::Crypto(CryptoError::UnsupportedHeaderProtection))
    ));
    assert!(HpKeyDummy(()).masks(&[[0; 16]], &mut [[0; 5]]).is_err());
  }

  // The key is wiped when dropped, which is checked without reading freed memory: the key lives in
  // a slot that the test owns.
  fn wiped_on_drop<K>(key: &[u8])
  where
    K: HpKey,
  {
    let mut slot = MaybeUninit::<K>::uninit();
    slot.write(K::new(key).unwrap());
    // SAFETY: the slot was initialized above and nothing reads it as a `K` after this
    unsafe { ptr::drop_in_place(slot.as_mut_ptr()) };
    // SAFETY: the drop overwrote every byte of the slot, padding included, so all of them are
    // initialized
    let bytes = unsafe { slice::from_raw_parts(slot.as_ptr().cast::<u8>(), size_of::<K>()) };
    let left = bytes.iter().filter(|el| **el != 0).count();
    assert_eq!(left, 0, "non-zero bytes left in the slot");
  }

  macro_rules! suite {
    ($name:ident, $aes128:ty, $aes256:ty, $chacha:ty) => {
      mod $name {
        use super::*;

        #[test]
        fn aes128_hp_mask_matches_rfc9001_a2() {
          check::<$aes128>(&AES_128_KEY, AES_128_SAMPLE, AES_128_MASK);
        }

        #[test]
        fn aes128_hp_mask_matches_fips197() {
          check::<$aes128>(&FIPS_128_KEY, FIPS_BLOCK, FIPS_128_MASK);
        }

        #[test]
        fn aes256_hp_mask_matches_fips197() {
          check::<$aes256>(&FIPS_256_KEY, FIPS_BLOCK, FIPS_256_MASK);
        }

        #[test]
        fn chacha20_hp_mask_matches_rfc9001_a5() {
          check::<$chacha>(&CHACHA_KEY, CHACHA_SAMPLE, CHACHA_MASK);
        }

        #[test]
        fn chacha20_hp_mask_matches_rfc8439() {
          check::<$chacha>(&CHACHA_RFC8439_KEY, CHACHA_RFC8439_SAMPLE, CHACHA_RFC8439_MASK);
        }

        #[test]
        fn chacha20_hp_mask_at_the_ends_of_the_counter_range() {
          check::<$chacha>(&CHACHA_KEY, CHACHA_COUNTER_MAX_SAMPLE, CHACHA_COUNTER_MAX_MASK);
          check::<$chacha>(
            &CHACHA_KEY,
            CHACHA_COUNTER_MAX_MINUS_ONE_SAMPLE,
            CHACHA_COUNTER_MAX_MINUS_ONE_MASK,
          );
          check::<$chacha>(&CHACHA_KEY, CHACHA_ZERO_SAMPLE, CHACHA_ZERO_MASK);
        }

        #[test]
        fn masks_match_mask() {
          masks_loop_over_mask::<$aes128>(&AES_128_KEY);
          masks_loop_over_mask::<$aes256>(&FIPS_256_KEY);
          masks_loop_over_mask::<$chacha>(&CHACHA_KEY);
        }

        #[test]
        fn key_is_wiped_on_drop() {
          wiped_on_drop::<$aes128>(&AES_128_KEY);
          wiped_on_drop::<$aes256>(&FIPS_256_KEY);
          wiped_on_drop::<$chacha>(&CHACHA_KEY);
        }

        #[test]
        fn wrong_key_lengths() {
          wrong_key_length_is_rejected::<$aes128>(16);
          wrong_key_length_is_rejected::<$aes256>(32);
          wrong_key_length_is_rejected::<$chacha>(32);
        }
      }
    };
  }

  // Under Miri only the Rust Crypto backend runs, the others call C or assembly. Graviola has no
  // header protection: with another backend that has it the globals use that one (final review I1)
  #[cfg(all(
    not(miri),
    any(feature = "crypto-ring", feature = "crypto-alr", feature = "crypto-ruco")
  ))]
  suite!(
    global,
    crate::crypto::Aes128HpGlobal,
    crate::crypto::Aes256HpGlobal,
    crate::crypto::Chacha20HpGlobal
  );
  #[cfg(all(feature = "crypto-alr", not(miri)))]
  suite!(alr, crate::crypto::Aes128HpAlr, crate::crypto::Aes256HpAlr, crate::crypto::Chacha20HpAlr);
  #[cfg(all(feature = "crypto-ring", not(miri)))]
  suite!(
    ring,
    crate::crypto::Aes128HpRing,
    crate::crypto::Aes256HpRing,
    crate::crypto::Chacha20HpRing
  );
  #[cfg(feature = "crypto-ruco")]
  suite!(
    ruco,
    crate::crypto::Aes128HpRuco,
    crate::crypto::Aes256HpRuco,
    crate::crypto::Chacha20HpRuco
  );
}
