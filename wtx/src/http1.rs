//! Sans-I/O HTTP/1.1 server core: request head parser, body decoder, response writer and a
//! keep-alive connection state machine.

mod body;
mod conn;
mod parser;
mod response;

use crate::http::{Method, Version};

pub use body::{BodyDecoder, BodyStatus};
pub use conn::{Http1Conn, Http1Event};
pub use parser::{ParseOutcome, ParseScratch, error_status, parse_request};
pub use response::write_response;

/// Maximum number of headers of a request.
pub const MAX_HEADERS: usize = 64;

/// How the body of a request is framed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyKind {
  /// No body.
  None,
  /// `Content-Length` bytes.
  ContentLength(usize),
  /// `Transfer-Encoding: chunked`.
  Chunked,
}

/// Borrowed view into the read buffer; no allocation.
#[derive(Clone, Copy, Debug)]
pub struct Http1Request<'b> {
  /// Request method.
  pub method: Method,
  /// [`Version::Http1`] for HTTP/1.0, [`Version::Http1_1`] for HTTP/1.1.
  pub version: Version,
  /// Percent-encoded path, without the query.
  pub path: &'b str,
  /// Everything after `?`, or an empty string.
  pub query: &'b str,
  /// Header name and value pairs. For an absolute-form target (`GET http://authority/path`) the
  /// value of `Host` is the target's authority, not what the header said (RFC 9112 §3.2.3).
  pub headers: &'b [(&'b str, &'b str)],
  /// Framing of the body.
  pub body_kind: BodyKind,
  /// If `false`, respond and then close the connection.
  pub keep_alive: bool,
}

#[cfg(test)]
mod tests {
  use crate::{
    http::HttpRecvParams,
    http1::{BodyDecoder, BodyKind, Http1Conn, ParseScratch},
  };

  #[test]
  fn scaffold_types_exist() {
    let _scratch = ParseScratch::new();
    let _decoder = BodyDecoder::new(BodyKind::None);
    let _conn = Http1Conn::new(&HttpRecvParams::with_default_params());
    assert!(matches!(BodyKind::ContentLength(2), BodyKind::ContentLength(2)));
  }
}
