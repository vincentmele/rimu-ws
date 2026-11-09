//! AES header protection (RFC 9001 section 5.4.3) on AES-NI, whose batches of masks are pipelined
//! eight blocks at a time (task 18, ruling T18-b).
//!
//! A mask is one AES block encryption of the sample. One at a time, each AES round waits for the
//! previous one; in a batch, the rounds of eight samples are interleaved, so that the latency of a
//! round instruction is spent on the seven others. The key is expanded once, here, with the
//! AES-NI key-generation instruction.
//!
//! A key is made only on a CPU with AES-NI (`is_x86_feature_detected!("aes")`): its constructor
//! fails otherwise and the callers keep the header protection of the backend.

use crate::{
  crypto::{CryptoError, HpKey},
  misc::zero_volatile,
};
use core::arch::x86_64::{
  __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_aeskeygenassist_si128, _mm_loadu_si128,
  _mm_setzero_si128, _mm_shuffle_epi32, _mm_slli_si128, _mm_storeu_si128, _mm_xor_si128,
};

// The samples whose rounds are interleaved
const LANES: usize = 8;

/// AES-128 header protection on AES-NI: 11 round keys.
pub(crate) type Aes128HpAesNi = AesNiHp<11>;
/// AES-256 header protection on AES-NI: 15 round keys.
pub(crate) type Aes256HpAesNi = AesNiHp<15>;

/// The `N` round keys of AES (11 for AES-128, 15 for AES-256), wiped when dropped.
pub(crate) struct AesNiHp<const N: usize> {
  keys: [__m128i; N],
}

impl<const N: usize> AesNiHp<N> {
  const KEY_LEN: usize = {
    assert!(N == 11 || N == 15);
    if N == 11 { 16 } else { 32 }
  };
}

impl<const N: usize> core::fmt::Debug for AesNiHp<N> {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str("AesNiHp")
  }
}

impl<const N: usize> HpKey for AesNiHp<N> {
  #[inline]
  fn new(key: &[u8]) -> crate::Result<Self> {
    if key.len() != Self::KEY_LEN {
      core::hint::cold_path();
      return Err(CryptoError::InvalidHeaderProtection.into());
    }
    if !has_aes_ni() {
      core::hint::cold_path();
      return Err(CryptoError::UnsupportedHeaderProtection.into());
    }
    // SAFETY: the CPU has AES-NI (checked above), and the length is that of the variant
    Ok(Self { keys: unsafe { expand::<N>(key) } })
  }

  #[inline]
  fn mask(&self, sample: &[u8; 16]) -> crate::Result<[u8; 5]> {
    // SAFETY: a key is only made on a CPU with AES-NI (`new`)
    Ok(unsafe { mask_one(&self.keys, sample) })
  }

  #[inline]
  fn masks(&self, samples: &[[u8; 16]], out: &mut [[u8; 5]]) -> crate::Result<()> {
    if samples.len() != out.len() {
      core::hint::cold_path();
      return Err(CryptoError::InvalidHeaderProtection.into());
    }
    for (group, masks) in samples.chunks(LANES).zip(out.chunks_mut(LANES)) {
      // SAFETY: a key is only made on a CPU with AES-NI (`new`)
      unsafe { mask_group(&self.keys, group, masks) };
    }
    Ok(())
  }
}

impl<const N: usize> Drop for AesNiHp<N> {
  #[inline]
  fn drop(&mut self) {
    let len = size_of_val(&self.keys);
    // SAFETY: the pointer and the length are those of the array of round keys, which is owned
    unsafe { zero_volatile(self.keys.as_mut_ptr().cast::<u8>(), len) };
  }
}

// The round keys of `key`, which has 16 bytes if `N` is 11 and 32 if `N` is 15 (FIPS 197 section
// 5.2, with the AES-NI key-generation instruction).
//
// SAFETY: the CPU must have AES-NI; `key` must have the length of `N`.
#[target_feature(enable = "aes")]
unsafe fn expand<const N: usize>(key: &[u8]) -> [__m128i; N] {
  let mut keys = [_mm_setzero_si128(); N];
  // SAFETY: up to the caller, `key` has 16 bytes at least
  let k0 = unsafe { load(key.as_ptr()) };
  if N == 11 {
    macro_rules! next {
      ($prev:expr, $rcon:literal) => {
        expand_step::<0xff>($prev, _mm_aeskeygenassist_si128::<$rcon>($prev))
      };
    }
    let k1 = next!(k0, 0x01);
    let k2 = next!(k1, 0x02);
    let k3 = next!(k2, 0x04);
    let k4 = next!(k3, 0x08);
    let k5 = next!(k4, 0x10);
    let k6 = next!(k5, 0x20);
    let k7 = next!(k6, 0x40);
    let k8 = next!(k7, 0x80);
    let k9 = next!(k8, 0x1b);
    let k10 = next!(k9, 0x36);
    for (to, from) in keys.iter_mut().zip([k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10]) {
      *to = from;
    }
  } else {
    // SAFETY: up to the caller, `key` has 32 bytes
    let k1 = unsafe { load(key.as_ptr().add(16)) };
    // Each step makes a key from the one two before it, with the one before it: the even ones
    // with the round constant and the rotated word, the odd ones with the substituted word only
    macro_rules! even {
      ($two_back:expr, $prev:expr, $rcon:literal) => {
        expand_step::<0xff>($two_back, _mm_aeskeygenassist_si128::<$rcon>($prev))
      };
    }
    macro_rules! odd {
      ($two_back:expr, $prev:expr) => {
        expand_step::<0xaa>($two_back, _mm_aeskeygenassist_si128::<0x00>($prev))
      };
    }
    let k2 = even!(k0, k1, 0x01);
    let k3 = odd!(k1, k2);
    let k4 = even!(k2, k3, 0x02);
    let k5 = odd!(k3, k4);
    let k6 = even!(k4, k5, 0x04);
    let k7 = odd!(k5, k6);
    let k8 = even!(k6, k7, 0x08);
    let k9 = odd!(k7, k8);
    let k10 = even!(k8, k9, 0x10);
    let k11 = odd!(k9, k10);
    let k12 = even!(k10, k11, 0x20);
    let k13 = odd!(k11, k12);
    let k14 = even!(k12, k13, 0x40);
    let all = [k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14];
    for (to, from) in keys.iter_mut().zip(all) {
      *to = from;
    }
  }
  keys
}

// One key of the schedule: `prev` with each of its words xored into the next ones, xored with the
// word of `assist` that `SHUFFLE` broadcasts.
#[target_feature(enable = "aes")]
fn expand_step<const SHUFFLE: i32>(prev: __m128i, assist: __m128i) -> __m128i {
  let assist = _mm_shuffle_epi32::<SHUFFLE>(assist);
  let mut key = _mm_xor_si128(prev, _mm_slli_si128::<4>(prev));
  key = _mm_xor_si128(key, _mm_slli_si128::<4>(key));
  key = _mm_xor_si128(key, _mm_slli_si128::<4>(key));
  _mm_xor_si128(key, assist)
}

// The first five bytes of `block`.
#[target_feature(enable = "aes")]
fn first_five(block: __m128i) -> [u8; 5] {
  let mut bytes = [0u8; 16];
  // SAFETY: `bytes` has the 16 bytes that are written; the store has no alignment requirement
  unsafe { _mm_storeu_si128(bytes.as_mut_ptr().cast::<__m128i>(), block) };
  let [b0, b1, b2, b3, b4, ..] = bytes;
  [b0, b1, b2, b3, b4]
}

// SAFETY: `ptr` must be valid for reads of 16 bytes.
#[target_feature(enable = "aes")]
unsafe fn load(ptr: *const u8) -> __m128i {
  // SAFETY: up to the caller; the load has no alignment requirement
  unsafe { _mm_loadu_si128(ptr.cast::<__m128i>()) }
}

// The masks of up to eight samples, whose rounds are interleaved: lanes past the samples encrypt
// zeros, which costs nothing more since the rounds of the lanes overlap.
//
// SAFETY: the CPU must have AES-NI.
#[target_feature(enable = "aes")]
unsafe fn mask_group<const N: usize>(
  keys: &[__m128i; N],
  samples: &[[u8; 16]],
  out: &mut [[u8; 5]],
) {
  let Some((first, rest)) = keys.split_first() else {
    return;
  };
  let Some((last, middle)) = rest.split_last() else {
    return;
  };
  let mut blocks = [_mm_setzero_si128(); LANES];
  for (block, sample) in blocks.iter_mut().zip(samples) {
    // SAFETY: a sample has 16 bytes
    *block = _mm_xor_si128(unsafe { load(sample.as_ptr()) }, *first);
  }
  for key in middle {
    for block in &mut blocks {
      *block = _mm_aesenc_si128(*block, *key);
    }
  }
  for (mask, block) in out.iter_mut().zip(blocks) {
    *mask = first_five(_mm_aesenclast_si128(block, *last));
  }
}

// The mask of one sample.
//
// SAFETY: the CPU must have AES-NI.
#[target_feature(enable = "aes")]
unsafe fn mask_one<const N: usize>(keys: &[__m128i; N], sample: &[u8; 16]) -> [u8; 5] {
  let Some((first, rest)) = keys.split_first() else {
    return [0; 5];
  };
  let Some((last, middle)) = rest.split_last() else {
    return [0; 5];
  };
  // SAFETY: a sample has 16 bytes
  let mut block = _mm_xor_si128(unsafe { load(sample.as_ptr()) }, *first);
  for key in middle {
    block = _mm_aesenc_si128(block, *key);
  }
  first_five(_mm_aesenclast_si128(block, *last))
}

/// If the CPU has the AES-NI instructions (x86-64 always has SSE2).
#[inline]
pub(crate) fn has_aes_ni() -> bool {
  std::arch::is_x86_feature_detected!("aes")
}

#[cfg(test)]
mod tests {
  use crate::{
    crypto::{
      HpKey,
      hp_key::x86_aesni::{Aes128HpAesNi, Aes256HpAesNi, has_aes_ni},
    },
    rng::Xorshift64,
  };
  #[cfg(all(feature = "crypto-ring", not(miri)))]
  use alloc::vec::Vec;

  // FIPS 197 appendix C.1 and C.3: the mask is the start of the encrypted block
  const FIPS_BLOCK: [u8; 16] = hexd!(b"00112233445566778899aabbccddeeff");
  const FIPS_128_KEY: [u8; 16] = hexd!(b"000102030405060708090a0b0c0d0e0f");
  const FIPS_128_MASK: [u8; 5] = hexd!(b"69c4e0d86a");
  const FIPS_256_KEY: [u8; 32] =
    hexd!(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  const FIPS_256_MASK: [u8; 5] = hexd!(b"8ea2b7ca51");
  // RFC 9001 appendix A.2: client Initial
  const RFC_KEY: [u8; 16] = hexd!(b"9f50449e04a0e810283a1e9933adedd2");
  const RFC_SAMPLE: [u8; 16] = hexd!(b"d1b1c98dd7689fb8ec11d242b123dc9b");
  const RFC_MASK: [u8; 5] = hexd!(b"437b9aec36");

  fn fill(rng: &mut Xorshift64, bytes: &mut [u8]) {
    for chunk in bytes.chunks_mut(8) {
      let value = rng.next_value().to_le_bytes();
      chunk.copy_from_slice(&value[..chunk.len()]);
    }
  }

  // Known answers, one mask and in batches of every length to 17, where the sample sits in each
  // lane of a full and of a partial group of eight. Runs under Miri (with `-C
  // target-feature=+aes`, which is what makes the detection succeed there).
  #[test]
  fn aesni_masks_match_known_answers_in_every_lane() {
    if !has_aes_ni() {
      assert!(Aes128HpAesNi::new(&FIPS_128_KEY).is_err());
      return;
    }
    let cases: [(&[u8], [u8; 16], [u8; 5]); 3] = [
      (&FIPS_128_KEY, FIPS_BLOCK, FIPS_128_MASK),
      (&RFC_KEY, RFC_SAMPLE, RFC_MASK),
      (&FIPS_256_KEY, FIPS_BLOCK, FIPS_256_MASK),
    ];
    for (key, sample, mask) in cases {
      let check = |masks: &mut dyn FnMut(&[[u8; 16]], &mut [[u8; 5]])| {
        for len in 1..=17 {
          for lane in 0..len {
            let mut samples = [[0xa5; 16]; 17];
            samples[lane] = sample;
            let mut out = [[0; 5]; 17];
            masks(&samples[..len], &mut out[..len]);
            assert_eq!(out[lane], mask, "len {len} lane {lane}");
          }
        }
      };
      if key.len() == 16 {
        let hp = Aes128HpAesNi::new(key).unwrap();
        assert_eq!(hp.mask(&sample).unwrap(), mask);
        check(&mut |samples, out| hp.masks(samples, out).unwrap());
      } else {
        let hp = Aes256HpAesNi::new(key).unwrap();
        assert_eq!(hp.mask(&sample).unwrap(), mask);
        check(&mut |samples, out| hp.masks(samples, out).unwrap());
      }
    }
  }

  // Ruling T18-b's correctness gate: 10,000 random samples under random keys of both sizes, in
  // batches of random lengths, give the masks that the backend computes one at a time.
  #[cfg(all(feature = "crypto-ring", not(miri)))]
  #[test]
  fn batched_masks_equal_single_masks() {
    use crate::crypto::{Aes128HpRing, Aes256HpRing};
    if !has_aes_ni() {
      return;
    }
    let mut rng = Xorshift64::new(0x5eed_1e55_c0ff_ee01);
    let mut samples = [[0u8; 16]; 64];
    let mut out = [[0u8; 5]; 64];
    let mut done = 0usize;
    while done < 10_000 {
      let mut key = [0u8; 32];
      fill(&mut rng, &mut key);
      let len = usize::try_from(rng.next_value() % 65).unwrap();
      for sample in &mut samples[..len] {
        fill(&mut rng, sample);
      }
      let (batched, single): (Vec<[u8; 5]>, Vec<[u8; 5]>) = if done.is_multiple_of(2) {
        let ring = Aes128HpRing::new(&key[..16]).unwrap();
        let ni = Aes128HpAesNi::new(&key[..16]).unwrap();
        ni.masks(&samples[..len], &mut out[..len]).unwrap();
        let single = samples[..len].iter().map(|el| ring.mask(el).unwrap()).collect();
        assert!(samples[..len].iter().all(|el| ni.mask(el).unwrap() == ring.mask(el).unwrap()));
        (out[..len].to_vec(), single)
      } else {
        let ring = Aes256HpRing::new(&key).unwrap();
        let ni = Aes256HpAesNi::new(&key).unwrap();
        ni.masks(&samples[..len], &mut out[..len]).unwrap();
        let single = samples[..len].iter().map(|el| ring.mask(el).unwrap()).collect();
        assert!(samples[..len].iter().all(|el| ni.mask(el).unwrap() == ring.mask(el).unwrap()));
        (out[..len].to_vec(), single)
      };
      assert_eq!(batched, single, "after {done} samples, batch of {len}");
      done = done.wrapping_add(len.max(1));
    }
  }

  // The round keys are wiped when the key is dropped, checked without reading freed memory: the
  // key lives in a slot that the test owns.
  #[test]
  fn aesni_key_is_wiped_on_drop() {
    use core::{mem::MaybeUninit, ptr, slice};
    if !has_aes_ni() {
      return;
    }
    let mut slot = MaybeUninit::<Aes256HpAesNi>::uninit();
    slot.write(Aes256HpAesNi::new(&FIPS_256_KEY).unwrap());
    // SAFETY: the slot was initialized above and nothing reads it as a key after this
    unsafe { ptr::drop_in_place(slot.as_mut_ptr()) };
    // SAFETY: the drop overwrote every byte of the slot, so all of them are initialized
    let bytes =
      unsafe { slice::from_raw_parts(slot.as_ptr().cast::<u8>(), size_of::<Aes256HpAesNi>()) };
    assert!(bytes.iter().all(|el| *el == 0), "non-zero bytes left in the slot");
  }

  // The lengths of a batch must match, and a key has the length of its variant.
  #[test]
  fn aesni_lengths_are_checked() {
    assert!(Aes128HpAesNi::new(&[0; 15]).is_err());
    assert!(Aes128HpAesNi::new(&[0; 32]).is_err());
    assert!(Aes256HpAesNi::new(&[0; 16]).is_err());
    if !has_aes_ni() {
      return;
    }
    let hp = Aes128HpAesNi::new(&[0; 16]).unwrap();
    let mut short = [[7; 5]; 2];
    assert!(hp.masks(&[[0; 16]; 3], &mut short).is_err());
    assert_eq!(short, [[7; 5]; 2]);
    hp.masks(&[], &mut []).unwrap();
  }
}
