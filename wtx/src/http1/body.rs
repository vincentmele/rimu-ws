//! HTTP/1.1 request body decoder.

use crate::http1::BodyKind;
use alloc::vec::Vec;

/// Progress of a [`BodyDecoder`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyStatus {
  /// More input is required.
  NeedMore,
  /// The body is complete.
  Complete {
    /// Number of bytes of the last `feed` input that belong to this body.
    consumed: usize,
  },
}

/// Incremental decoder of `Content-Length` and chunked bodies.
#[derive(Debug)]
pub struct BodyDecoder {
  _kind: BodyKind,
}

impl BodyDecoder {
  /// New decoder for the given framing.
  #[inline]
  pub const fn new(kind: BodyKind) -> Self {
    Self { _kind: kind }
  }

  /// Decodes `input`, appending the payload to `out`.
  #[inline]
  pub fn feed(&mut self, _input: &[u8], _out: &mut Vec<u8>) -> crate::Result<BodyStatus> {
    todo!()
  }
}
