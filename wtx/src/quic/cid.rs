//! Connection IDs (RFC 9000 section 5.1).

use crate::quic::QuicError;
use core::hint::cold_path;

/// The maximum length of a connection ID in QUIC version 1.
pub const MAX_CID_LEN: usize = 20;

/// A connection ID of up to [`MAX_CID_LEN`] bytes, stored inline.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Cid {
  len: u8,
  // The bytes after `len` are always zero, which keeps `Eq` and `Hash` simple.
  bytes: [u8; MAX_CID_LEN],
}

impl Cid {
  /// Copies `bytes`, which must have at most [`MAX_CID_LEN`] bytes.
  #[inline]
  pub fn new(bytes: &[u8]) -> crate::Result<Self> {
    let mut this = Self::default();
    let (Some(dst), Ok(len)) = (this.bytes.get_mut(..bytes.len()), u8::try_from(bytes.len()))
    else {
      cold_path();
      return Err(QuicError::CidTooLong.into());
    };
    dst.copy_from_slice(bytes);
    this.len = len;
    Ok(this)
  }

  /// The bytes of the ID.
  #[inline]
  pub fn as_slice(&self) -> &[u8] {
    self.bytes.get(..self.len()).unwrap_or_default()
  }

  /// If the ID has no bytes.
  #[inline]
  pub const fn is_empty(&self) -> bool {
    self.len == 0
  }

  /// The number of bytes of the ID.
  #[inline]
  pub const fn len(&self) -> usize {
    self.len as usize
  }
}

#[cfg(test)]
mod tests {
  use crate::{
    Error,
    quic::{Cid, MAX_CID_LEN, QuicError},
  };

  #[test]
  fn cid_round_trips_every_valid_length() {
    let source: [u8; 32] = core::array::from_fn(|idx| u8::try_from(idx).unwrap().wrapping_add(1));
    for len in 0..=MAX_CID_LEN {
      let cid = Cid::new(&source[..len]).unwrap();
      assert_eq!(cid.as_slice(), &source[..len]);
      assert_eq!(cid.len(), len);
      assert_eq!(cid.is_empty(), len == 0);
    }
  }

  #[test]
  fn cid_rejects_more_than_20_bytes() {
    assert!(matches!(Cid::new(&[0; MAX_CID_LEN + 1]), Err(Error::Quic(QuicError::CidTooLong))));
    assert!(matches!(Cid::new(&[0; 255]), Err(Error::Quic(QuicError::CidTooLong))));
  }

  #[test]
  fn cid_equality_ignores_nothing_but_the_bytes() {
    assert_eq!(Cid::new(&[1, 2, 3]).unwrap(), Cid::new(&[1, 2, 3]).unwrap());
    assert_ne!(Cid::new(&[1, 2, 3]).unwrap(), Cid::new(&[1, 2]).unwrap());
    assert_ne!(Cid::new(&[1, 2, 0]).unwrap(), Cid::new(&[1, 2]).unwrap());
    assert_eq!(Cid::new(&[]).unwrap(), Cid::default());
  }
}
