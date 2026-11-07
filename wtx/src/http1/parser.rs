//! HTTP/1.1 request head parser.

use crate::http1::{Http1Request, MAX_HEADERS};

/// Result of [`parse_request`].
#[derive(Debug)]
pub enum ParseOutcome<'b> {
  /// A full request head was parsed.
  Complete {
    /// Borrowed view of the request.
    request: Http1Request<'b>,
    /// Number of bytes the head occupies in the buffer, including the final blank line.
    head_len: usize,
  },
  /// More bytes are needed.
  Partial,
}

/// Reusable storage for the header spans of a single parse.
#[derive(Debug)]
pub struct ParseScratch {
  _headers: [((usize, usize), (usize, usize)); MAX_HEADERS],
  _len: usize,
}

impl ParseScratch {
  /// Empty scratch.
  #[inline]
  pub const fn new() -> Self {
    Self { _headers: [((0, 0), (0, 0)); MAX_HEADERS], _len: 0 }
  }
}

impl Default for ParseScratch {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

/// Parses the head of a request found in `buf`.
#[inline]
pub fn parse_request<'b>(
  _buf: &'b [u8],
  _scratch: &'b mut ParseScratch,
) -> crate::Result<ParseOutcome<'b>> {
  todo!()
}
