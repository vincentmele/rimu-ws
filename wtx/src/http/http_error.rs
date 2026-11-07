use crate::http::{KnownHeaderName, Method, Mime};

/// Http error
#[derive(Clone, Copy, Debug)]
pub enum HttpError {
  /// Generic request error
  BadRequest,
  /// Invalid `form/data` content
  InvalidFormDataContent,
  /// Invalid HTTP/2 or HTTP/3 header
  InvalidHttp2pContent,
  /// Header names can not have more than 64 bytes
  LargeHeaderName,
  /// Missing Header
  MissingHeader(
    /// Expected header name
    KnownHeaderName,
  ),
  /// Received request does not contain a method field
  MissingRequestMethod,
  /// HTTP/1.1 request head over the size limit or with too many headers (answered with 431)
  RequestHeaderFieldsTooLarge,
  /// Received response does not contain a status code field
  MissingResponseStatusCode,
  /// The URI doesn't have any placeholder
  MissingUriPlaceholder,
  /// `TlsConfig` is mandatory for TLS connections
  TlsConnectionRequireTlsConfig,
  /// Content-Type mismatch
  UnexpectedContentType {
    /// Expected method
    expected: Mime,
  },
  /// HTTP version does not match the expected method.
  UnexpectedHttpMethod {
    /// Expected method
    expected: Option<Method>,
  },
  /// Unexpected protocol
  UnexpectedProtocol,
  /// Unknown header name.
  UnknownHeaderNameFromBytes {
    /// Received length
    length: u32,
  },
  /// HTTP/1.1 `Transfer-Encoding` with a coding other than `chunked` (answered with 501)
  UnsupportedTransferCoding,
  /// Unknown `WebAuthn` Algorithm
  UnknownWebAuthnAlg,
  /// URI mismatch
  UriMismatch,
}
