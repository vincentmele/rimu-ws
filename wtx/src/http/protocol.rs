use crate::http::HttpError;

create_enum! {
  /// Specifies a tunneling protocol
  #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
  pub enum Protocol<u8> {
    /// WebSocket
    WebSocket = (0, "WEBSOCKET" | "websocket")
  }
}

impl Protocol {
  /// A specialized `TryFrom` for the HTTP/2 wire protocol. RFC 8441 registers `websocket`; the
  /// match ignores case.
  #[inline]
  pub fn from_canonical_bytes(bytes: &[u8]) -> crate::Result<Self> {
    if bytes.eq_ignore_ascii_case(b"websocket") {
      return Ok(Self::WebSocket);
    }
    Err(HttpError::UnexpectedProtocol.into())
  }
}
