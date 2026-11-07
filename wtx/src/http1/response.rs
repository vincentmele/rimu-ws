//! HTTP/1.1 response writer.

use crate::http::{Method, StatusCode, Version};
use alloc::vec::Vec;

/// Appends a complete response to the request of `method` and `version` to `out`.
///
/// Emits the status line (always `HTTP/1.1`), `Content-Type`, `Content-Length`, the
/// `Connection` header, the blank line and then `body`. No `Date` or `Server` header is
/// written.
///
/// - `Connection: close` when `keep_alive` is `false`; `Connection: keep-alive` when it is
///   `true` and `version` is [`Version::Http1`] (HTTP/1.0, where closing is the default).
/// - 1xx, 204 and 304 responses never have content: `content_type` and `body` are ignored and
///   neither `Content-Type` nor `Content-Length` is written (RFC 9110 §8.6, RFC 9112 §6.3).
/// - A response to [`Method::Head`] has the `Content-Length` of `body` but not `body` itself
///   (RFC 9110 §9.3.2).
#[inline]
pub fn write_response(
  out: &mut Vec<u8>,
  method: Method,
  version: Version,
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
  out.extend_from_slice(b"\r\n");
  let has_content = code >= 200 && code != 204 && code != 304;
  if has_content {
    out.extend_from_slice(b"Content-Type: ");
    out.extend_from_slice(content_type.as_bytes());
    out.extend_from_slice(b"\r\nContent-Length: ");
    push_decimal(out, body.len());
    out.extend_from_slice(b"\r\n");
  }
  if !keep_alive {
    out.extend_from_slice(b"Connection: close\r\n");
  } else if version == Version::Http1 {
    out.extend_from_slice(b"Connection: keep-alive\r\n");
  }
  out.extend_from_slice(b"\r\n");
  if has_content && method != Method::Head {
    out.extend_from_slice(body);
  }
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
  use crate::{
    http::{Method, StatusCode, Version},
    http1::response::write_response,
  };
  use alloc::{string::String, vec::Vec};

  fn write(method: Method, version: Version, status: StatusCode, keep_alive: bool) -> String {
    let mut out = Vec::new();
    write_response(&mut out, method, version, status, "text/plain", b"55", keep_alive);
    String::from_utf8(out).unwrap()
  }

  #[test]
  fn writes_keep_alive_200() {
    let mut out = Vec::new();
    write_response(
      &mut out,
      Method::Get,
      Version::Http1_1,
      StatusCode::Ok,
      "text/plain",
      b"55",
      true,
    );
    assert_eq!(out, b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n55");
    let text = core::str::from_utf8(&out).unwrap();
    assert!(!text.contains("Connection:"));
    assert!(!text.contains("Date"));
    assert!(!text.contains("Server"));
  }

  #[test]
  fn writes_connection_close() {
    let text = write(Method::Get, Version::Http1_1, StatusCode::Ok, false);
    assert!(text.contains("Connection: close\r\n"));
    let text = write(Method::Get, Version::Http1, StatusCode::Ok, false);
    assert!(text.contains("Connection: close\r\n"));
  }

  #[test]
  fn writes_keep_alive_for_http10() {
    assert_eq!(
      write(Method::Get, Version::Http1, StatusCode::Ok, true),
      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n55"
    );
  }

  #[test]
  fn head_and_bodiless_statuses() {
    assert_eq!(
      write(Method::Head, Version::Http1_1, StatusCode::Ok, true),
      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n"
    );
    for (status, line) in [
      (StatusCode::Continue, "HTTP/1.1 100 Continue\r\n"),
      (StatusCode::EarlyHints, "HTTP/1.1 103 Early Hints\r\n"),
      (StatusCode::NoContent, "HTTP/1.1 204 No Content\r\n"),
      (StatusCode::NotModified, "HTTP/1.1 304 Not Modified\r\n"),
    ] {
      for method in [Method::Get, Method::Head] {
        assert_eq!(write(method, Version::Http1_1, status, true), alloc::format!("{line}\r\n"));
      }
    }
    assert_eq!(
      write(Method::Get, Version::Http1_1, StatusCode::NoContent, false),
      "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
    );
  }
}
