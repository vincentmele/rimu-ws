//! HTTP/1.1 response writer.

use crate::http::StatusCode;
use alloc::vec::Vec;

/// Appends a complete response to `out`.
#[inline]
pub fn write_response(
  _out: &mut Vec<u8>,
  _status: StatusCode,
  _content_type: &str,
  _body: &[u8],
  _keep_alive: bool,
) {
  todo!()
}
