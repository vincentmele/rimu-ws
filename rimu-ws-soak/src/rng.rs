//! Reproducible randomness: every scenario run draws from a seed derived from the run's seed, its
//! slot and its generation, so a failure can be replayed alone.

/// The generator every scenario draws from.
pub type Rng = rand_chacha::ChaCha8Rng;

/// The seed of generation `generation` of slot `slot`.
pub fn seed_for(global: u64, slot: u32, generation: u32) -> u64 {
  // splitmix64
  let mut z =
    (global ^ (u64::from(slot) << 32 | u64::from(generation))).wrapping_add(0x9E37_79B9_7F4A_7C15);
  z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
  z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
  z ^ (z >> 31)
}

pub fn rng(seed: u64) -> Rng {
  rand::SeedableRng::seed_from_u64(seed)
}
