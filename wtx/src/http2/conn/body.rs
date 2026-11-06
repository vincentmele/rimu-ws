//! Response bodies the connection core sends: borrowed bytes it copies, or shared bytes it sends
//! by reference.

pub(crate) use crate::misc::SharedBytes;

/// A body for [`super::Http2Conn::send_data`].
#[derive(Debug)]
pub(crate) enum Body<'any> {
  /// Copied into the connection's buffers.
  Borrowed(&'any [u8]),
  /// Queued by reference.
  Shared(SharedBytes),
}
