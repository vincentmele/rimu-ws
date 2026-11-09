//! A request as the HTTP/3 connection hands it to its handler ([`H3Request`]), and the head that a
//! request stream decodes into ([`RequestHead`]), checked field by field as RFC 9114 sections
//! 4.1.2, 4.2 and 4.3 ask.
//!
//! A request that fails a check is malformed ([`Http3Error::MalformedRequest`]): its stream is
//! reset with `H3_MESSAGE_ERROR`. A field section that decodes to more than the advertised
//! `SETTINGS_MAX_FIELD_SECTION_SIZE` ([`Http3Error::FieldSectionTooLarge`]) is answered with 431.

use crate::{
  collections::VectorUsize,
  http3::{Http3Error, h3_conn_state::Budget},
  quic::StreamId,
};
use core::hint::cold_path;

/// The bytes that RFC 9114 section 4.2.2 counts for each field on top of its name and value.
const FIELD_OVERHEAD: u64 = 32;
/// The index of `:method` among the pseudo-header fields of a request.
const METHOD: usize = 0;
/// The index of `:scheme`.
const SCHEME: usize = 1;
/// The index of `:authority`.
const AUTHORITY: usize = 2;
/// The index of `:path`.
const PATH: usize = 3;

/// A complete request: its head, checked (RFC 9114 section 4.3), and its body, the payloads of its
/// DATA frames. Pseudo-header fields that the request does not have are empty (`:scheme` and
/// `:path` of a CONNECT).
#[derive(Clone, Copy, Debug)]
pub(crate) struct H3Request<'a> {
  /// `:method`.
  pub method: &'a [u8],
  /// `:scheme`.
  pub scheme: &'a [u8],
  /// `:authority`, empty if the request has none.
  pub authority: &'a [u8],
  /// `:path`.
  pub path: &'a [u8],
  /// The fields that are not pseudo-header fields, in their order.
  pub fields: &'a [(&'a [u8], &'a [u8])],
  /// The body.
  pub body: &'a [u8],
  /// The stream of the request.
  pub stream: StreamId,
}

/// The decoded head of a request: the bytes of its names and values, where they are, and what
/// the checks of the fields need to remember.
#[derive(Debug)]
pub(crate) struct RequestHead {
  bytes: VectorUsize<u8>,
  content_length: Option<u64>,
  /// The fields that are not pseudo-header fields: where they start, their name and value lengths.
  fields: VectorUsize<(u32, u32, u32)>,
  host: Option<(u32, u32)>,
  /// `:method`, `:scheme`, `:authority` and `:path`: where they start and their lengths.
  pseudo: [Option<(u32, u32)>; 4],
  regular: bool,
  size: u64,
}

impl RequestHead {
  /// An empty head, which allocates nothing.
  pub(crate) const fn new() -> Self {
    Self {
      bytes: VectorUsize::new(),
      content_length: None,
      fields: VectorUsize::new(),
      host: None,
      pseudo: [None; 4],
      regular: false,
      size: 0,
    }
  }

  /// `:authority`, empty if absent.
  pub(crate) fn authority(&self) -> &[u8] {
    self.pseudo_value(AUTHORITY)
  }

  /// The checks that need every field (RFC 9114 section 4.3.1): the pseudo-header fields that a
  /// request must have, a `:path` that is not empty and an authority for `http` and `https`.
  pub(crate) fn check(&self) -> crate::Result<()> {
    let Some(method) = self.pseudo.get(METHOD).copied().flatten() else {
      return Err(malformed());
    };
    if self.slice(method) == b"CONNECT" {
      // RFC 9114 section 4.4; the extended CONNECT of RFC 9220 is not supported
      if self.has(SCHEME) || self.has(PATH) || self.authority().is_empty() {
        return Err(malformed());
      }
      return Ok(());
    }
    if !self.has(SCHEME) || !self.has(PATH) {
      return Err(malformed());
    }
    let scheme = self.pseudo_value(SCHEME);
    if scheme == b"http" || scheme == b"https" {
      if self.pseudo_value(PATH).is_empty() {
        return Err(malformed());
      }
      let host = self.host.map(|el| self.slice(el));
      let authority = self.has(AUTHORITY).then(|| self.authority());
      match (authority, host) {
        (None, None) => return Err(malformed()),
        (Some(elem), None) | (None, Some(elem)) if elem.is_empty() => return Err(malformed()),
        (Some(lhs), Some(rhs)) if lhs != rhs || lhs.is_empty() => return Err(malformed()),
        _ => {}
      }
    }
    Ok(())
  }

  /// Forgets the head; the storage stays.
  pub(crate) fn clear(&mut self) {
    self.bytes.clear();
    self.content_length = None;
    self.fields.clear();
    self.host = None;
    self.pseudo = [None; 4];
    self.regular = false;
    self.size = 0;
  }

  /// The value of `content-length`, if the request has one.
  pub(crate) const fn content_length(&self) -> Option<u64> {
    self.content_length
  }

  /// The fields that are not pseudo-header fields, in their order.
  pub(crate) fn fields(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
    self.fields.iter().map(|&(start, name_len, value_len)| {
      let name_end = start.wrapping_add(name_len);
      (self.slice((start, name_len)), self.slice((name_end, value_len)))
    })
  }

  /// The number of fields that are not pseudo-header fields.
  pub(crate) fn fields_len(&self) -> usize {
    self.fields.len()
  }

  /// Frees each buffer whose capacity is more than `keep` bytes, out of `budget`.
  pub(crate) fn trim(&mut self, budget: &mut Budget, keep: usize) {
    budget.trim(&mut self.bytes, keep);
    budget.trim(&mut self.fields, keep);
  }

  /// `:method`.
  pub(crate) fn method(&self) -> &[u8] {
    self.pseudo_value(METHOD)
  }

  /// `:path`, empty if absent.
  pub(crate) fn path(&self) -> &[u8] {
    self.pseudo_value(PATH)
  }

  /// Takes the next field of the head, decoded, whose section may decode to `max_size` bytes as
  /// RFC 9114 section 4.2.2 counts them, into buffers that grow within `budget`
  /// ([`Http3Error::BufferedLimit`] if they can not).
  pub(crate) fn push(
    &mut self,
    name: &[u8],
    value: &[u8],
    max_size: u64,
    budget: &mut Budget,
  ) -> crate::Result<()> {
    count_field(&mut self.size, name, value, max_size)?;
    if let Some(pseudo) = name.strip_prefix(b":") {
      // Pseudo-header fields come first, once each, and only those of requests (section 4.3); no
      // userinfo in the authority (section 4.3.1)
      let idx = match pseudo {
        b"method" if is_token(value) => METHOD,
        b"scheme" if is_scheme(value) => SCHEME,
        b"authority" if is_visible(value) && !value.contains(&b'@') => AUTHORITY,
        b"path" if is_visible(value) => PATH,
        _ => return Err(malformed()),
      };
      if self.regular || self.has(idx) {
        return Err(malformed());
      }
      let range = self.store(value, budget)?;
      if let Some(elem) = self.pseudo.get_mut(idx) {
        *elem = Some(range);
      }
      return Ok(());
    }
    self.regular = true;
    check_field(name, value)?;
    let start = u32::try_from(self.bytes.len()).map_err(|_err| malformed())?;
    let (name_len, value_len) = (len_u32(name)?, len_u32(value)?);
    reserve(budget, &mut self.bytes, name.len().wrapping_add(value.len()))?;
    reserve(budget, &mut self.fields, 1)?;
    let _ = self.bytes.extend_from_copyable_slices([name, value])?;
    let value_range = (start.wrapping_add(name_len), value_len);
    match name {
      b"content-length" => {
        let length = parse_content_length(value)?;
        if self.content_length.is_some_and(|el| el != length) {
          return Err(malformed());
        }
        self.content_length = Some(length);
      }
      b"host" => {
        // Once, and without userinfo (RFC 9110 section 7.2)
        if self.host.is_some() || value.contains(&b'@') {
          return Err(malformed());
        }
        self.host = Some(value_range);
      }
      _ => {}
    }
    self.fields.push((start, name_len, value_len))?;
    Ok(())
  }

  /// `:scheme`, empty if absent.
  pub(crate) fn scheme(&self) -> &[u8] {
    self.pseudo_value(SCHEME)
  }

  fn has(&self, idx: usize) -> bool {
    self.pseudo.get(idx).is_some_and(Option::is_some)
  }

  fn pseudo_value(&self, idx: usize) -> &[u8] {
    self.pseudo.get(idx).copied().flatten().map(|el| self.slice(el)).unwrap_or_default()
  }

  fn slice(&self, (start, len): (u32, u32)) -> &[u8] {
    let start = usize::try_from(start).unwrap_or(usize::MAX);
    let len = usize::try_from(len).unwrap_or(0);
    self.bytes.get(start..).and_then(|el| el.get(..len)).unwrap_or_default()
  }

  fn store(&mut self, bytes: &[u8], budget: &mut Budget) -> crate::Result<(u32, u32)> {
    let start = u32::try_from(self.bytes.len()).map_err(|_err| malformed())?;
    reserve(budget, &mut self.bytes, bytes.len())?;
    self.bytes.extend_from_copyable_slice(bytes)?;
    Ok((start, len_u32(bytes)?))
  }
}

/// Checks the next field of the trailers of a request, which is not kept: no pseudo-header field
/// (RFC 9114 section 4.3) and the checks of every field. `size` counts the section.
pub(crate) fn check_trailer(
  size: &mut u64,
  name: &[u8],
  value: &[u8],
  max_size: u64,
) -> crate::Result<()> {
  count_field(size, name, value, max_size)?;
  check_field(name, value)
}

// A field that is not a pseudo-header field: a lowercase token for a name (RFC 9114 section 4.2),
// a value of the `field-content` of RFC 9110 section 5.5 (section 10.3) and no field that is
// specific to a connection (section 4.2).
fn check_field(name: &[u8], value: &[u8]) -> crate::Result<()> {
  if name.is_empty() || !name.iter().all(|el| is_tchar(*el) && !el.is_ascii_uppercase()) {
    return Err(malformed());
  }
  if !is_field_content(value) {
    return Err(malformed());
  }
  match name {
    b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding" | b"upgrade" => {
      Err(malformed())
    }
    b"te" if value != b"trailers" => Err(malformed()),
    _ => Ok(()),
  }
}

// Adds the size of a field to `size` (RFC 9114 section 4.2.2).
fn count_field(size: &mut u64, name: &[u8], value: &[u8], max_size: u64) -> crate::Result<()> {
  let len = u64::try_from(name.len().wrapping_add(value.len())).unwrap_or(u64::MAX);
  *size = size.saturating_add(len).saturating_add(FIELD_OVERHEAD);
  if *size > max_size {
    cold_path();
    return Err(crate::Error::Http3(Http3Error::FieldSectionTooLarge));
  }
  Ok(())
}

// SP and HTAB are allowed inside, not at the ends; other controls and DEL are not
fn is_field_content(value: &[u8]) -> bool {
  let ends = |el: Option<&u8>| !matches!(el, Some(b' ' | b'\t'));
  ends(value.first())
    && ends(value.last())
    && value.iter().all(|el| *el == b'\t' || (*el >= 0x20 && *el != 0x7f))
}

// `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` (RFC 3986 section 3.1)
fn is_scheme(value: &[u8]) -> bool {
  value.first().is_some_and(u8::is_ascii_alphabetic)
    && value.iter().all(|el| el.is_ascii_alphanumeric() || matches!(el, b'+' | b'-' | b'.'))
}

fn is_tchar(byte: u8) -> bool {
  byte.is_ascii_alphanumeric()
    || matches!(
      byte,
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
    )
}

fn is_token(value: &[u8]) -> bool {
  !value.is_empty() && value.iter().all(|el| is_tchar(*el))
}

// No space and no control: `:authority` and `:path` are parts of a URI
fn is_visible(value: &[u8]) -> bool {
  value.iter().all(|el| *el > 0x20 && *el != 0x7f)
}

fn len_u32(bytes: &[u8]) -> crate::Result<u32> {
  u32::try_from(bytes.len()).map_err(|_err| malformed())
}

// Room in `buf` for `add` more elements within `budget`.
fn reserve<T>(budget: &mut Budget, buf: &mut VectorUsize<T>, add: usize) -> crate::Result<()> {
  if budget.grow(buf, add, None)? {
    return Ok(());
  }
  cold_path();
  Err(crate::Error::Http3(Http3Error::BufferedLimit))
}

#[cold]
fn malformed() -> crate::Error {
  crate::Error::Http3(Http3Error::MalformedRequest)
}

// One or more digits (RFC 9110 section 8.6), at most what a `u64` holds.
fn parse_content_length(value: &[u8]) -> crate::Result<u64> {
  if value.is_empty() || value.len() > 19 {
    return Err(malformed());
  }
  let mut length = 0u64;
  for byte in value {
    if !byte.is_ascii_digit() {
      return Err(malformed());
    }
    length = length.wrapping_mul(10).wrapping_add(u64::from(byte.wrapping_sub(b'0')));
  }
  Ok(length)
}
