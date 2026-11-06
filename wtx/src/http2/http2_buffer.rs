use crate::{
  collections::VectorUsize,
  rng::{Rng, Xorshift64, simple_seed},
};

/// Reusable parts of a client connection: the seed of its HPACK encoder and its read buffer.
#[derive(Debug)]
pub struct Http2Buffer {
  pub(crate) rng: Xorshift64,
  pub(crate) rx: VectorUsize<u8>,
}

impl Http2Buffer {
  /// Creates a new instance without pre-allocated resources.
  #[inline]
  pub fn new<RNG>(rng: &mut RNG) -> Self
  where
    RNG: Rng,
  {
    Self { rng: Xorshift64::from(u64::from_le_bytes(rng.u8_8())), rx: VectorUsize::new() }
  }
}

impl Default for Http2Buffer {
  #[inline]
  fn default() -> Self {
    Self::new(&mut Xorshift64::from(simple_seed()))
  }
}
