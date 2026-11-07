//! HTTP/1.1 response writer.

use crate::http::StatusCode;
use alloc::vec::Vec;

/// Appends a complete response to `out`.
///
/// Emits the status line, `Content-Type`, `Content-Length`, `Connection: close` only when
/// `keep_alive` is `false`, the blank line and then `body`. No `Date` or `Server` header is
/// written.
#[inline]
pub fn write_response(
  out: &mut Vec<u8>,
  status: StatusCode,
  content_type: &str,
  body: &[u8],
  keep_alive: bool,
) {
  out.extend_from_slice(b"HTTP/1.1 ");
  let code: u16 = status.into();
  out.push(b'0' + (code / 100) as u8);
  out.push(b'0' + ((code / 10) % 10) as u8);
  out.push(b'0' + (code % 10) as u8);
  out.push(b' ');
  out.extend_from_slice(reason_phrase(status).as_bytes());
  out.extend_from_slice(b"\r\nContent-Type: ");
  out.extend_from_slice(content_type.as_bytes());
  out.extend_from_slice(b"\r\nContent-Length: ");
  push_decimal(out, body.len());
  out.extend_from_slice(b"\r\n");
  if !keep_alive {
    out.extend_from_slice(b"Connection: close\r\n");
  }
  out.extend_from_slice(b"\r\n");
  out.extend_from_slice(body);
}

/// Appends `value` in decimal without going through `core::fmt`.
fn push_decimal(out: &mut Vec<u8>, mut value: usize) {
  let mut digits = [0u8; 20];
  let mut at = digits.len();
  loop {
    at -= 1;
    digits[at] = b'0' + (value % 10) as u8;
    value /= 10;
    if value == 0 {
      break;
    }
  }
  out.extend_from_slice(&digits[at..]);
}

/// Standard reason phrase of `status`, as registered with IANA.
const fn reason_phrase(status: StatusCode) -> &'static str {
  match status {
    StatusCode::Continue => "Continue",
    StatusCode::SwitchingProtocols => "Switching Protocols",
    StatusCode::EarlyHints => "Early Hints",
    StatusCode::Ok => "OK",
    StatusCode::Created => "Created",
    StatusCode::Accepted => "Accepted",
    StatusCode::NonAuthoritativeInformation => "Non-Authoritative Information",
    StatusCode::NoContent => "No Content",
    StatusCode::ResetContent => "Reset Content",
    StatusCode::PartialContent => "Partial Content",
    StatusCode::MultiStatus => "Multi-Status",
    StatusCode::ImUsed => "IM Used",
    StatusCode::MultipleChoice => "Multiple Choices",
    StatusCode::MovedPermanently => "Moved Permanently",
    StatusCode::Found => "Found",
    StatusCode::SeeOther => "See Other",
    StatusCode::NotModified => "Not Modified",
    StatusCode::TemporaryRedirect => "Temporary Redirect",
    StatusCode::PermanentRedirect => "Permanent Redirect",
    StatusCode::BadRequest => "Bad Request",
    StatusCode::Unauthorized => "Unauthorized",
    StatusCode::PaymentRequired => "Payment Required",
    StatusCode::Forbidden => "Forbidden",
    StatusCode::NotFound => "Not Found",
    StatusCode::MethodNotAllowed => "Method Not Allowed",
    StatusCode::NotAcceptable => "Not Acceptable",
    StatusCode::ProxyAuthenticationRequired => "Proxy Authentication Required",
    StatusCode::RequestTimeout => "Request Timeout",
    StatusCode::Conflict => "Conflict",
    StatusCode::Gone => "Gone",
    StatusCode::LengthRequired => "Length Required",
    StatusCode::PreconditionFailed => "Precondition Failed",
    StatusCode::PayloadTooLarge => "Payload Too Large",
    StatusCode::UriTooLong => "URI Too Long",
    StatusCode::UnsupportedMediaType => "Unsupported Media Type",
    StatusCode::RequestedRangeNotSatisfiable => "Range Not Satisfiable",
    StatusCode::ExpectationFailed => "Expectation Failed",
    StatusCode::ImATeapot => "I'm a Teapot",
    StatusCode::MisdirectedRequest => "Misdirected Request",
    StatusCode::UnprocessableEntity => "Unprocessable Entity",
    StatusCode::Locked => "Locked",
    StatusCode::FailedDependency => "Failed Dependency",
    StatusCode::TooEarly => "Too Early",
    StatusCode::UpgradeRequired => "Upgrade Required",
    StatusCode::PreconditionRequired => "Precondition Required",
    StatusCode::TooManyRequests => "Too Many Requests",
    StatusCode::RequestHeaderFieldsTooLarge => "Request Header Fields Too Large",
    StatusCode::UnavailableForLegalReasons => "Unavailable For Legal Reasons",
    StatusCode::InternalServerError => "Internal Server Error",
    StatusCode::NotImplemented => "Not Implemented",
    StatusCode::BadGateway => "Bad Gateway",
    StatusCode::ServiceUnavailable => "Service Unavailable",
    StatusCode::GatewayTimeout => "Gateway Timeout",
    StatusCode::HttpVersionNotSupported => "HTTP Version Not Supported",
    StatusCode::VariantAlsoNegotiates => "Variant Also Negotiates",
    StatusCode::InsufficientStorage => "Insufficient Storage",
    StatusCode::LoopDetected => "Loop Detected",
    StatusCode::NotExtended => "Not Extended",
    StatusCode::NetworkAuthenticationRequired => "Network Authentication Required",
  }
}

#[cfg(test)]
mod tests {
  use crate::{http::StatusCode, http1::response::write_response};
  use alloc::{string::String, vec::Vec};

  #[test]
  fn writes_keep_alive_200() {
    let mut out = Vec::new();
    write_response(&mut out, StatusCode::Ok, "text/plain", b"55", true);
    assert_eq!(out, b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n55");
    let text = core::str::from_utf8(&out).unwrap();
    assert!(!text.contains("Connection:"));
    assert!(!text.contains("Date"));
    assert!(!text.contains("Server"));
  }

  #[test]
  fn writes_connection_close() {
    let mut out = Vec::new();
    write_response(&mut out, StatusCode::Ok, "text/plain", b"55", false);
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("Connection: close\r\n"));
  }
}
