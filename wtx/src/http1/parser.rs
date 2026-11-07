//! HTTP/1.1 request head parser.
//!
//! Hand-rolled and allocation free. The head is located with a vectorized (SSE2 on `x86_64`,
//! SWAR elsewhere) scan for `\n`, then every line is split with the same byte scans. All spans
//! are zero-copy views into the input.

use crate::{
  http::{HttpError, Method, StatusCode},
  http1::{BodyKind, Http1Request, MAX_HEADERS},
  misc::from_utf8_basic,
};
use core::mem::MaybeUninit;

/// Maximum number of bytes of a request head, including the final blank line.
const MAX_HEAD_LEN: usize = 16 * 1024;

type Header = (&'static str, &'static str);

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

/// Reusable storage for the headers of a single parse.
///
/// The slots are only ever read within the `parse_request` call that wrote them, so stale
/// contents from a previous call (whose buffer may be gone) are never observed.
#[derive(Debug)]
pub struct ParseScratch {
  headers: [MaybeUninit<Header>; MAX_HEADERS],
}

impl ParseScratch {
  /// Empty scratch.
  #[inline]
  pub const fn new() -> Self {
    Self { headers: [MaybeUninit::uninit(); MAX_HEADERS] }
  }
}

impl Default for ParseScratch {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

/// Parses the head of a request found in `buf`.
///
/// Errors are [`HttpError::BadRequest`], [`HttpError::RequestHeaderFieldsTooLarge`] (head over
/// 16 KiB or more than [`MAX_HEADERS`] headers) or [`HttpError::UnsupportedTransferCoding`];
/// [`error_status`] gives the status code each one is answered with.
///
/// Returns [`ParseOutcome::Partial`], never an error, while the blank line that ends the head
/// has not arrived (unless the head is already larger than the 16 KiB limit). The function is
/// pure over `buf`, so it can simply be called again after more bytes were appended.
///
/// One empty line in front of the request line is skipped (RFC 9112 §2.2); it counts toward
/// `head_len`.
#[inline]
pub fn parse_request<'b>(
  buf: &'b [u8],
  scratch: &'b mut ParseScratch,
) -> crate::Result<ParseOutcome<'b>> {
  let skip = if buf.starts_with(b"\r\n") { 2 } else { 0 };
  let buf = buf.get(skip..).unwrap_or_default();
  let window = buf.get(..MAX_HEAD_LEN).unwrap_or(buf);
  let Some(head_len) = find_head_end(window) else {
    if buf.len() > MAX_HEAD_LEN {
      return Err(HttpError::RequestHeaderFieldsTooLarge.into());
    }
    return Ok(ParseOutcome::Partial);
  };
  let Some(head_bytes) = buf.get(..head_len) else {
    return Err(bad());
  };
  let head = from_utf8_basic(head_bytes).map_err(|_| bad())?;

  // Request line

  let line_end = find_byte(head_bytes, b'\n').ok_or_else(bad)?;
  if line_end == 0 || head_bytes.get(line_end - 1) != Some(&b'\r') {
    return Err(bad());
  }
  let line = head.get(..line_end - 1).ok_or_else(bad)?;
  let line_bytes = line.as_bytes();
  if has_ctl(line_bytes) || find_byte(line_bytes, b'\t').is_some() {
    return Err(bad());
  }
  let sp0 = find_byte(line_bytes, b' ').ok_or_else(bad)?;
  let method = Method::from_canonical_bytes(line_bytes.get(..sp0).ok_or_else(bad)?)?;
  let rest = line.get(sp0 + 1..).ok_or_else(bad)?;
  let sp1 = find_byte(rest.as_bytes(), b' ').ok_or_else(bad)?;
  let target = rest.get(..sp1).ok_or_else(bad)?;
  let http10 = match rest.get(sp1 + 1..).ok_or_else(bad)?.as_bytes() {
    b"HTTP/1.1" => false,
    b"HTTP/1.0" => true,
    _ => return Err(bad()),
  };
  if target.is_empty() {
    return Err(bad());
  }
  let (origin, absolute) = origin_part(target)?;
  let (mut path, query) = match find_byte(origin.as_bytes(), b'?') {
    Some(idx) => (origin.get(..idx).ok_or_else(bad)?, origin.get(idx + 1..).ok_or_else(bad)?),
    None => (origin, ""),
  };
  if absolute && path.is_empty() {
    path = "/";
  }

  // Headers

  let mut len = 0usize;
  let mut pos = line_end + 1;
  let mut content_length: Option<usize> = None;
  let mut chunked = false;
  let mut close = false;
  let mut keep_alive_token = false;
  let mut has_host = false;
  loop {
    let tail = head_bytes.get(pos..).ok_or_else(bad)?;
    let nl = find_byte(tail, b'\n').ok_or_else(bad)?;
    if nl == 0 || tail.get(nl - 1) != Some(&b'\r') {
      return Err(bad());
    }
    let hline = head.get(pos..pos + nl - 1).ok_or_else(bad)?;
    pos += nl + 1;
    if hline.is_empty() {
      if pos != head_len {
        return Err(bad());
      }
      break;
    }
    let hbytes = hline.as_bytes();
    if has_ctl(hbytes) {
      return Err(bad());
    }
    let colon = find_byte(hbytes, b':').ok_or_else(bad)?;
    let name = hline.get(..colon).ok_or_else(bad)?;
    if name.is_empty() || !name.bytes().all(is_tchar) {
      return Err(bad());
    }
    let value = hline.get(colon + 1..).ok_or_else(bad)?.trim_matches([' ', '\t']);
    match name.len() {
      4 if name.eq_ignore_ascii_case("host") => {
        // RFC 9112 §3.2: more than one is a bad request.
        if has_host {
          return Err(bad());
        }
        has_host = true;
      }
      10 if name.eq_ignore_ascii_case("connection") => {
        for token in value.split(',') {
          let token = token.trim_matches([' ', '\t']);
          if token.eq_ignore_ascii_case("close") {
            close = true;
          } else if token.eq_ignore_ascii_case("keep-alive") {
            keep_alive_token = true;
          }
        }
      }
      14 if name.eq_ignore_ascii_case("content-length") => {
        if content_length.is_some() {
          return Err(bad());
        }
        content_length = Some(parse_decimal(value.as_bytes())?);
      }
      17 if name.eq_ignore_ascii_case("transfer-encoding") => {
        // A second header is rejected like a list with `chunked` twice.
        if chunked {
          return Err(bad());
        }
        check_transfer_encoding(value)?;
        chunked = true;
      }
      _ => {}
    }
    let Some(slot) = scratch.headers.get_mut(len) else {
      return Err(HttpError::RequestHeaderFieldsTooLarge.into());
    };
    // SAFETY: the stored references are only read back below, within this call and while `'b`
    // (the lifetime of `buf`) is alive. The `'static` is just a placeholder so that the
    // scratch does not need a lifetime of its own.
    let header = unsafe { core::mem::transmute::<(&'b str, &'b str), Header>((name, value)) };
    let _ = slot.write(header);
    len += 1;
  }

  // RFC 9112 §3.2: an HTTP/1.1 request without `Host` is a bad request.
  if (chunked && content_length.is_some()) || (!http10 && !has_host) {
    return Err(bad());
  }
  let body_kind = if chunked {
    BodyKind::Chunked
  } else if let Some(n) = content_length {
    BodyKind::ContentLength(n)
  } else {
    BodyKind::None
  };
  // RFC 9112 §6.1: chunked framing in HTTP/1.0 is faulty, the connection closes after it.
  let keep_alive = if close || (http10 && chunked) { false } else { !http10 || keep_alive_token };

  let scratch: &'b ParseScratch = scratch;
  // SAFETY: the first `len` slots were initialized above.
  let headers: &'b [(&'b str, &'b str)] =
    unsafe { core::slice::from_raw_parts(scratch.headers.as_ptr().cast::<Header>(), len) };
  Ok(ParseOutcome::Complete {
    request: Http1Request { method, path, query, headers, body_kind, keep_alive },
    head_len: head_len.wrapping_add(skip),
  })
}

/// Status code a [`parse_request`] error is answered with: 431, 501 or else 400.
#[inline]
pub fn error_status(error: &crate::Error) -> StatusCode {
  match error {
    crate::Error::Http(HttpError::RequestHeaderFieldsTooLarge) => {
      StatusCode::RequestHeaderFieldsTooLarge
    }
    crate::Error::Http(HttpError::UnsupportedTransferCoding) => StatusCode::NotImplemented,
    _ => StatusCode::BadRequest,
  }
}

#[inline]
fn bad() -> crate::Error {
  HttpError::BadRequest.into()
}

/// The origin-form part (path and query) of an absolute-form target such as
/// `http://authority/path?query`, which a server must accept (RFC 9112 §3.2.2), and if `target`
/// was in that form. Any other target is returned as it is. The authority is not compared with
/// `Host`.
#[inline]
fn origin_part(target: &str) -> crate::Result<(&str, bool)> {
  let bytes = target.as_bytes();
  let scheme_len = if bytes.get(..7).is_some_and(|el| el.eq_ignore_ascii_case(b"http://")) {
    7
  } else if bytes.get(..8).is_some_and(|el| el.eq_ignore_ascii_case(b"https://")) {
    8
  } else {
    return Ok((target, false));
  };
  let rest = target.get(scheme_len..).ok_or_else(bad)?;
  let authority_len =
    rest.bytes().position(|byte| byte == b'/' || byte == b'?').unwrap_or(rest.len());
  if authority_len == 0 {
    return Err(bad());
  }
  Ok((rest.get(authority_len..).ok_or_else(bad)?, true))
}

/// Accepts a `Transfer-Encoding` value that is exactly `chunked`, the only coding supported.
///
/// A malformed list, or one where `chunked` is not the final coding or appears twice, is a bad
/// request (RFC 9112 §6.1, §6.3). `chunked` after other codings is answered as not
/// implemented (RFC 9112 §6.1).
#[inline]
fn check_transfer_encoding(value: &str) -> crate::Result<()> {
  let mut chunked = 0usize;
  let mut others = false;
  let mut last_is_chunked = false;
  for token in value.split(',') {
    let token = token.trim_matches([' ', '\t']);
    if token.is_empty() || !token.bytes().all(is_tchar) {
      return Err(bad());
    }
    last_is_chunked = token.eq_ignore_ascii_case("chunked");
    if last_is_chunked {
      chunked = chunked.wrapping_add(1);
    } else {
      others = true;
    }
  }
  if !last_is_chunked || chunked > 1 {
    return Err(bad());
  }
  if others {
    return Err(HttpError::UnsupportedTransferCoding.into());
  }
  Ok(())
}

/// Strictly digits, no sign, no overflow.
#[inline]
fn parse_decimal(bytes: &[u8]) -> crate::Result<usize> {
  if bytes.is_empty() {
    return Err(bad());
  }
  let mut n: usize = 0;
  for byte in bytes {
    let digit = byte.wrapping_sub(b'0');
    if digit > 9 {
      return Err(bad());
    }
    n = n.checked_mul(10).and_then(|v| v.checked_add(usize::from(digit))).ok_or_else(bad)?;
  }
  Ok(n)
}

/// RFC 9110 `tchar`.
#[inline]
const fn is_tchar(byte: u8) -> bool {
  const TABLE: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0usize;
    while i < 256 {
      let b = i as u8;
      table[i] = b.is_ascii_alphanumeric()
        || matches!(
          b,
          b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
        );
      i += 1;
    }
    table
  };
  TABLE[byte as usize]
}

/// Position right after the first `\r\n\r\n`, if any.
#[inline]
fn find_head_end(buf: &[u8]) -> Option<usize> {
  let mut start = 0usize;
  while let Some(rel) = find_byte(buf.get(start..)?, b'\n') {
    let idx = start + rel;
    if idx >= 3 && buf.get(idx - 3..idx)? == b"\r\n\r" {
      return Some(idx + 1);
    }
    start = idx + 1;
  }
  None
}

/// Position of the first `needle`.
#[cfg(target_arch = "x86_64")]
#[inline]
fn find_byte(hay: &[u8], needle: u8) -> Option<usize> {
  use core::arch::x86_64::{_mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8, _mm_set1_epi8};
  let mut idx = 0usize;
  // SAFETY: SSE2 is part of the `x86_64` baseline and every load stays inside `hay`.
  unsafe {
    let n = _mm_set1_epi8(needle as i8);
    while idx + 16 <= hay.len() {
      let v = _mm_loadu_si128(hay.as_ptr().add(idx).cast());
      let mask = _mm_movemask_epi8(_mm_cmpeq_epi8(v, n)) as u32;
      if mask != 0 {
        return Some(idx + mask.trailing_zeros() as usize);
      }
      idx += 16;
    }
  }
  hay.get(idx..)?.iter().position(|b| *b == needle).map(|p| idx + p)
}

/// Position of the first `needle`.
#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn find_byte(hay: &[u8], needle: u8) -> Option<usize> {
  find_byte_swar(hay, needle)
}

/// Portable word-at-a-time version of [`find_byte`].
#[cfg_attr(target_arch = "x86_64", cfg_attr(not(test), allow(dead_code)))]
#[inline]
fn find_byte_swar(hay: &[u8], needle: u8) -> Option<usize> {
  const LO: u64 = 0x0101_0101_0101_0101;
  const HI: u64 = 0x8080_8080_8080_8080;
  let broadcast = LO.wrapping_mul(u64::from(needle));
  let mut idx = 0usize;
  while let Some(chunk) = hay.get(idx..idx + 8) {
    let mut word = [0u8; 8];
    word.copy_from_slice(chunk);
    let x = u64::from_le_bytes(word) ^ broadcast;
    let found = x.wrapping_sub(LO) & !x & HI;
    if found != 0 {
      return Some(idx + (found.trailing_zeros() / 8) as usize);
    }
    idx += 8;
  }
  hay.get(idx..)?.iter().position(|b| *b == needle).map(|p| idx + p)
}

/// If `bytes` contains a control character other than `\t` or a DEL.
#[cfg(target_arch = "x86_64")]
#[inline]
fn has_ctl(bytes: &[u8]) -> bool {
  use core::arch::x86_64::{
    _mm_andnot_si128, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_min_epu8, _mm_movemask_epi8,
    _mm_or_si128, _mm_set1_epi8,
  };
  let mut idx = 0usize;
  // SAFETY: SSE2 is part of the `x86_64` baseline and every load stays inside `bytes`.
  unsafe {
    let c1f = _mm_set1_epi8(0x1f);
    let tab = _mm_set1_epi8(b'\t' as i8);
    let del = _mm_set1_epi8(0x7f);
    while idx + 16 <= bytes.len() {
      let v = _mm_loadu_si128(bytes.as_ptr().add(idx).cast());
      let le1f = _mm_cmpeq_epi8(_mm_min_epu8(v, c1f), v);
      let bad =
        _mm_or_si128(_mm_andnot_si128(_mm_cmpeq_epi8(v, tab), le1f), _mm_cmpeq_epi8(v, del));
      if _mm_movemask_epi8(bad) != 0 {
        return true;
      }
      idx += 16;
    }
  }
  bytes.get(idx..).is_some_and(has_ctl_scalar)
}

/// If `bytes` contains a control character other than `\t` or a DEL.
#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn has_ctl(bytes: &[u8]) -> bool {
  has_ctl_scalar(bytes)
}

#[inline]
fn has_ctl_scalar(bytes: &[u8]) -> bool {
  bytes.iter().any(|b| (*b < 0x20 && *b != b'\t') || *b == 0x7f)
}

#[cfg(test)]
mod tests {
  use crate::{
    http::{Method, StatusCode},
    http1::{
      BodyKind, MAX_HEADERS,
      parser::{ParseOutcome, ParseScratch, error_status, parse_request},
    },
  };
  use alloc::{format, string::String, vec::Vec};

  const GET: &[u8] = b"GET /baseline11?a=13&b=42 HTTP/1.1\r\nHost: localhost:8080\r\n\r\n";
  const POST_CL: &[u8] =
    b"POST /baseline11?a=13&b=42 HTTP/1.1\r\nHost: localhost:8080\r\nContent-Length: 2\r\n\r\n20";
  const POST_CHUNKED: &[u8] = b"POST /baseline11?a=13&b=42 HTTP/1.1\r\nHost: localhost:8080\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n20\r\n0\r\n\r\n";

  fn complete(
    buf: &[u8],
  ) -> (Method, String, String, Vec<(String, String)>, BodyKind, bool, usize) {
    let mut scratch = ParseScratch::new();
    match parse_request(buf, &mut scratch).unwrap() {
      ParseOutcome::Complete { request, head_len } => (
        request.method,
        request.path.into(),
        request.query.into(),
        request.headers.iter().map(|(n, v)| ((*n).into(), (*v).into())).collect(),
        request.body_kind,
        request.keep_alive,
        head_len,
      ),
      ParseOutcome::Partial => panic!("partial"),
    }
  }

  fn is_err(buf: &[u8]) -> bool {
    let mut scratch = ParseScratch::new();
    parse_request(buf, &mut scratch).is_err()
  }

  /// Status code the parse error of `buf` is answered with.
  fn err_status(buf: &[u8]) -> StatusCode {
    let mut scratch = ParseScratch::new();
    error_status(&parse_request(buf, &mut scratch).unwrap_err())
  }

  #[test]
  fn parses_get_baseline() {
    let (method, path, query, headers, body_kind, keep_alive, head_len) = complete(GET);
    assert_eq!(method, Method::Get);
    assert_eq!(path, "/baseline11");
    assert_eq!(query, "a=13&b=42");
    assert_eq!(headers, [("Host".into(), "localhost:8080".into())]);
    assert_eq!(body_kind, BodyKind::None);
    assert!(keep_alive);
    assert_eq!(head_len, 60);
  }

  #[test]
  fn parses_post_content_length() {
    let (method, _, _, _, body_kind, _, head_len) = complete(POST_CL);
    assert_eq!(method, Method::Post);
    assert_eq!(body_kind, BodyKind::ContentLength(2));
    assert_eq!(head_len, 80);
  }

  #[test]
  fn parses_post_chunked() {
    let (method, _, _, _, body_kind, _, head_len) = complete(POST_CHUNKED);
    assert_eq!(method, Method::Post);
    assert_eq!(body_kind, BodyKind::Chunked);
    assert_eq!(head_len, 89);
  }

  #[test]
  fn partial_returns_partial_at_every_split() {
    let mut scratch = ParseScratch::new();
    for n in 1..GET.len() {
      assert!(matches!(parse_request(&GET[..n], &mut scratch), Ok(ParseOutcome::Partial)), "{n}");
    }
    assert!(matches!(
      parse_request(GET, &mut scratch),
      Ok(ParseOutcome::Complete { head_len: 60, .. })
    ));
  }

  #[test]
  fn partial_at_every_split_with_body_bytes_trailing() {
    let mut scratch = ParseScratch::new();
    for n in 1..80 {
      assert!(
        matches!(parse_request(&POST_CL[..n], &mut scratch), Ok(ParseOutcome::Partial)),
        "{n}"
      );
    }
    for n in 80..=POST_CL.len() {
      assert!(matches!(
        parse_request(&POST_CL[..n], &mut scratch),
        Ok(ParseOutcome::Complete { head_len: 80, .. })
      ));
    }
  }

  #[test]
  fn lowercase_header_names_match() {
    let (_, _, _, headers, body_kind, _, _) =
      complete(b"POST /x HTTP/1.1\r\nhost: a\r\ncontent-length: 7\r\n\r\n");
    assert_eq!(headers.len(), 2);
    assert_eq!(body_kind, BodyKind::ContentLength(7));
    let (_, _, _, _, body_kind, keep_alive, _) = complete(
      b"POST /x HTTP/1.1\r\nHost: a\r\nTRANSFER-ENCODING: Chunked\r\nCONNECTION: Close\r\n\r\n",
    );
    assert_eq!(body_kind, BodyKind::Chunked);
    assert!(!keep_alive);
  }

  #[test]
  fn rejects_cl_and_te() {
    assert!(is_err(
      b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"
    ));
    assert!(is_err(
      b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n"
    ));
  }

  #[test]
  fn rejects_double_cl() {
    assert!(is_err(
      b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n"
    ));
    assert!(is_err(
      b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"
    ));
  }

  #[test]
  fn rejects_too_many_headers() {
    let build = |n: usize| {
      let mut buf = b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec();
      for i in 1..n {
        buf.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
      }
      buf.extend_from_slice(b"\r\n");
      buf
    };
    assert!(!is_err(&build(MAX_HEADERS)));
    assert_eq!(err_status(&build(MAX_HEADERS + 1)), StatusCode::RequestHeaderFieldsTooLarge);
  }

  #[test]
  fn rejects_oversized_head() {
    let mut buf = b"GET / HTTP/1.1\r\nHost: a\r\nX: ".to_vec();
    buf.resize(20_000, b'a');
    assert_eq!(err_status(&buf), StatusCode::RequestHeaderFieldsTooLarge);
    buf.extend_from_slice(b"\r\n\r\n");
    assert_eq!(err_status(&buf), StatusCode::RequestHeaderFieldsTooLarge);
    assert_eq!(err_status(b"GET  / HTTP/1.1\r\n\r\n"), StatusCode::BadRequest);
  }

  #[test]
  fn rejects_malformed() {
    assert!(is_err(b"GET / HTTP/2.0\r\n\r\n"));
    assert!(is_err(b"GET /\r\n\r\n"));
    assert!(is_err(b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n"));
    assert!(is_err(b"BREW / HTTP/1.1\r\nHost: a\r\n\r\n"));
    assert!(is_err(b"get / HTTP/1.1\r\nHost: a\r\n\r\n"));
    assert!(is_err(b"GET / HTTP/1.1\r\nHost: a\r\nBad Name: v\r\n\r\n"));
    assert!(is_err(b"GET / HTTP/1.1\r\nHost: a\r\nNoColon\r\n\r\n"));
    assert!(is_err(b"GET / HTTP/1.1\r\nHost: a\r\n folded: v\r\n\r\n"));
    assert!(is_err(b"GET / HTTP/1.1\r\nHost: a\r\nA: b\rc\r\n\r\n"));
    assert!(is_err(b"GET / HTTP/1.1\r\nHost: a\r\nA: b\0c\r\n\r\n"));
    assert!(is_err(b"GET / HTTP/1.1\r\nHost: a\r\nA: b\nc: d\r\n\r\n"));
    assert!(is_err(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n"));
    assert!(is_err(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: \r\n\r\n"));
    assert!(is_err(
      b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999999\r\n\r\n"
    ));
    assert!(is_err(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n"));
  }

  #[test]
  fn request_line_needs_crlf() {
    assert!(is_err(b"GET / HTTP/1.11\nHost: a\r\n\r\n"));
    assert!(is_err(b"GET / HTTP/1.1X\nHost: a\r\n\r\n"));
    assert!(is_err(b"GET / HTTP/1.1\0\nHost: a\r\n\r\n"));
    assert!(is_err(b"GET / HTTP/1.1\nHost: a\r\n\r\n"));
  }

  #[test]
  fn one_leading_crlf_is_skipped() {
    let raw: &[u8] = b"\r\nGET /x HTTP/1.1\r\nHost: a\r\n\r\n";
    let (method, path, _, _, _, _, head_len) = complete(raw);
    assert_eq!((method, path.as_str(), head_len), (Method::Get, "/x", raw.len()));
    let mut scratch = ParseScratch::new();
    for n in 1..raw.len() {
      assert!(matches!(parse_request(&raw[..n], &mut scratch), Ok(ParseOutcome::Partial)), "{n}");
    }
    assert!(is_err(b"\r\n\r\nGET /x HTTP/1.1\r\nHost: a\r\n\r\n"));
  }

  #[test]
  fn transfer_encoding_is_exactly_chunked() {
    let te = |value: &str| {
      let raw = format!("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: {value}\r\n\r\n");
      let mut scratch = ParseScratch::new();
      match parse_request(raw.as_bytes(), &mut scratch) {
        Ok(ParseOutcome::Complete { request, .. }) => {
          assert_eq!(request.body_kind, BodyKind::Chunked);
          StatusCode::Ok
        }
        Ok(ParseOutcome::Partial) => panic!("partial"),
        Err(err) => error_status(&err),
      }
    };
    assert_eq!(te("chunked"), StatusCode::Ok);
    assert_eq!(te("CHUNKED"), StatusCode::Ok);
    // Not chunked last: the length can not be known (RFC 9112 §6.3).
    assert_eq!(te("gzip"), StatusCode::BadRequest);
    assert_eq!(te("gzip, chunked"), StatusCode::NotImplemented);
    assert_eq!(te("chunked, chunked"), StatusCode::BadRequest);
    assert_eq!(te("chunked, gzip"), StatusCode::BadRequest);
    assert_eq!(te(""), StatusCode::BadRequest);
    assert_eq!(te(", chunked"), StatusCode::BadRequest);
    assert_eq!(te("chu nked"), StatusCode::BadRequest);
    assert_eq!(
      err_status(
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
      ),
      StatusCode::BadRequest
    );
  }

  #[test]
  fn chunked_http10_does_not_keep_alive() {
    let (_, _, _, _, body_kind, keep_alive, _) =
      complete(b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n");
    assert_eq!(body_kind, BodyKind::Chunked);
    assert!(!keep_alive);
  }

  #[test]
  fn host_is_required_once() {
    assert_eq!(err_status(b"GET / HTTP/1.1\r\n\r\n"), StatusCode::BadRequest);
    assert_eq!(err_status(b"GET / HTTP/1.1\r\nX: y\r\n\r\n"), StatusCode::BadRequest);
    assert_eq!(err_status(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"), StatusCode::BadRequest);
    assert_eq!(err_status(b"GET / HTTP/1.1\r\nhost: a\r\nHOST: a\r\n\r\n"), StatusCode::BadRequest);
    assert_eq!(err_status(b"GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n"), StatusCode::BadRequest);
    // HTTP/1.0 may leave it out; an empty one is allowed.
    assert_eq!(complete(b"GET /x HTTP/1.0\r\n\r\n").1, "/x");
    assert_eq!(complete(b"GET /x HTTP/1.1\r\nHost:\r\n\r\n").1, "/x");
  }

  #[test]
  fn absolute_form_routes_on_path_and_query() {
    let target = |t: &str| {
      let (_, path, query, ..) =
        complete(format!("GET {t} HTTP/1.1\r\nHost: a\r\n\r\n").as_bytes());
      (path, query)
    };
    assert_eq!(target("http://evil/x?q=1"), ("/x".into(), "q=1".into()));
    assert_eq!(target("HTTPS://h:8080/a/b"), ("/a/b".into(), "".into()));
    assert_eq!(target("http://h"), ("/".into(), "".into()));
    assert_eq!(target("http://h?x"), ("/".into(), "x".into()));
    assert_eq!(target("/http://h/x"), ("/http://h/x".into(), "".into()));
    assert_eq!(err_status(b"GET http:///x HTTP/1.1\r\nHost: a\r\n\r\n"), StatusCode::BadRequest);
  }

  #[test]
  fn keep_alive_rules() {
    assert!(complete(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").5);
    assert!(!complete(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").5);
    assert!(!complete(b"GET / HTTP/1.0\r\n\r\n").5);
    assert!(complete(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").5);
    assert!(!complete(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, close\r\n\r\n").5);
  }

  #[test]
  fn value_whitespace_and_empty_value() {
    let (_, path, query, headers, _, _, _) =
      complete(b"GET /p? HTTP/1.1\r\nHost: a\r\nA:\t x y \t\r\nB:\r\n\r\n");
    assert_eq!(path, "/p");
    assert_eq!(query, "");
    assert_eq!(
      headers,
      [("Host".into(), "a".into()), ("A".into(), "x y".into()), ("B".into(), "".into())]
    );
  }

  #[test]
  fn simd_scans_match_scalar() {
    use crate::http1::parser::{find_byte, find_byte_swar, has_ctl};
    let mut hay = [b'a'; 70];
    for i in 0..hay.len() {
      for len in 0..=hay.len() {
        hay[i] = b'\n';
        let slice = &hay[..len];
        let expected = slice.iter().position(|b| *b == b'\n');
        assert_eq!(find_byte(slice, b'\n'), expected);
        assert_eq!(find_byte_swar(slice, b'\n'), expected);
        hay[i] = b'a';
      }
    }
    assert!(!has_ctl(b"hello\tworld \x80\xff~"));
    for bad in [0u8, 1, 8, 10, 13, 31, 127] {
      for pos in 0..40 {
        let mut v = [b'a'; 40];
        v[pos] = bad;
        assert!(has_ctl(&v), "{bad} at {pos}");
      }
    }
  }
}
