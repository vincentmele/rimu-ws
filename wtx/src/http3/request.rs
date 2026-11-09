//! A request as the HTTP/3 connection hands it to its handler ([`H3Request`]), and the head that a
//! request stream decodes into ([`RequestHead`]), checked field by field as RFC 9114 sections
//! 4.1.2, 4.2 and 4.3 ask.
//!
//! A request that fails a check is malformed ([`Http3Error::MalformedRequest`]): its stream is
//! reset with `H3_MESSAGE_ERROR`. A field section that decodes to more than the advertised
//! `SETTINGS_MAX_FIELD_SECTION_SIZE` ([`Http3Error::FieldSectionTooLarge`]) is answered with 431.

use crate::{
  collections::VectorUsize,
  http3::{
    Http3Error,
    h3_conn_state::Budget,
    qpack::{STATIC_TABLE, StaticRef},
  },
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
// The classes of a byte, bits of `CLASSES` (ruling T16-a: one load per byte for every check)
/// `tchar` (RFC 9110 section 5.6.2).
const TCHAR: u8 = 1;
/// `tchar` that is not an uppercase letter: what a field name is made of (RFC 9114 section 4.2).
const LOWER_TCHAR: u8 = 2;
/// Neither a space nor a control: what `:authority` and `:path` are made of.
const VISIBLE: u8 = 4;
/// HTAB, SP, visible ASCII and obs-text: what a field value is made of (RFC 9110 section 5.5).
const FIELD: u8 = 8;
/// What a scheme is made of after its first letter (RFC 3986 section 3.1).
const SCHEME_CHAR: u8 = 16;
/// Below 0x80: what a field value that is text without a UTF-8 check is made of.
const ASCII: u8 = 32;
static CLASSES: [u8; 256] = classes();

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
  pub fields: Fields<'a>,
  /// The value of `host`, empty if the request has none.
  pub host: &'a [u8],
  /// The body.
  pub body: &'a [u8],
  /// The stream of the request.
  pub stream: StreamId,
}

/// The fields of a request that are not pseudo-header fields, read where they were decoded.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fields<'a> {
  head: &'a RequestHead,
}

impl<'a> Fields<'a> {
  /// The fields of `head`.
  pub(crate) const fn new(head: &'a RequestHead) -> Self {
    Self { head }
  }

  /// The fields, in their order.
  pub(crate) fn iter(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + use<'a> {
    self.head.fields()
  }

  /// The fields as text, in their order, if every byte of them is ASCII: checked once, when
  /// they were decoded.
  pub(crate) fn ascii(&self) -> Option<impl Iterator<Item = (&'a str, &'a str)> + use<'a>> {
    self.head.ascii_fields()
  }
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
  /// A value of a field that is not a pseudo-header field has a byte above 0x7f (names never do).
  non_ascii: bool,
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
      non_ascii: false,
      pseudo: [None; 4],
      regular: false,
      size: 0,
    }
  }

  /// The fields that are not pseudo-header fields as text, in their order, if all of them are
  /// ASCII (`None` otherwise, and the caller checks them).
  pub(crate) fn ascii_fields(&self) -> Option<impl Iterator<Item = (&str, &str)> + use<'_>> {
    if self.non_ascii {
      return None;
    }
    Some(self.fields().map(|(name, value)| {
      // SAFETY: a name is either a literal that `push` checked against `LOWER_TCHAR` or, by the
      // precondition of `push`'s static reference, a name of the static table; with `non_ascii`
      // false every value is either checked by `push` against `ASCII` or, by that precondition
      // with `with_value`, a value of the static table. Every name and value of the table is ASCII
      // (the test of this module), and ASCII bytes are valid UTF-8
      unsafe { (core::str::from_utf8_unchecked(name), core::str::from_utf8_unchecked(value)) }
    }))
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
    self.non_ascii = false;
    self.pseudo = [None; 4];
    self.regular = false;
    self.size = 0;
  }

  /// The value of `content-length`, if the request has one.
  pub(crate) const fn content_length(&self) -> Option<u64> {
    self.content_length
  }

  /// The fields that are not pseudo-header fields, in their order.
  pub(crate) fn fields(&self) -> impl Iterator<Item = (&[u8], &[u8])> + use<'_> {
    self.fields.iter().map(|&(start, name_len, value_len)| {
      let name_end = start.wrapping_add(name_len);
      (self.slice((start, name_len)), self.slice((name_end, value_len)))
    })
  }

  /// Frees each buffer whose capacity is more than `keep` bytes, out of `budget`.
  pub(crate) fn trim(&mut self, budget: &mut Budget, keep: usize) {
    budget.trim(&mut self.bytes, keep);
    budget.trim(&mut self.fields, keep);
  }

  /// The value of `host`, empty if absent.
  pub(crate) fn host(&self) -> &[u8] {
    self.host.map(|el| self.slice(el)).unwrap_or_default()
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
  /// ([`Http3Error::BufferedLimit`] if they can not). `sref`, the static table entry that gave its
  /// name (or name and value), classifies the field without comparing its name (ruling T16-a):
  /// the outcome is that of the same field given as a literal.
  ///
  /// Precondition of `sref`: `name` is the name of the entry of the static table of QPACK at
  /// `sref.idx`, and with `sref.with_value` `value` is its value too, as the decoder gives them
  /// (checked in debug builds). The checks of a name, and with `with_value` of a value, are not
  /// made again for such a field: they hold for every entry of the table (the test of this
  /// module), and the ASCII text of [`Self::ascii_fields`] relies on it.
  pub(crate) fn push(
    &mut self,
    name: &[u8],
    value: &[u8],
    sref: Option<StaticRef>,
    max_size: u64,
    budget: &mut Budget,
  ) -> crate::Result<()> {
    count_field(&mut self.size, name, value, max_size)?;
    if let Some(elem) = sref
      && let Some(kind) = STATIC_KINDS.get(usize::from(elem.idx)).copied()
    {
      debug_assert_eq!(STATIC_TABLE.get(usize::from(elem.idx)).map(|el| el.0), Some(name));
      debug_assert!(
        !elem.with_value || STATIC_TABLE.get(usize::from(elem.idx)).map(|el| el.1) == Some(value)
      );
      // A value of the table passes the checks of its name (the test of this module)
      return match kind {
        StaticKind::Pseudo(idx) => {
          if !elem.with_value && !pseudo_value_ok(idx, value) {
            return Err(malformed());
          }
          self.push_pseudo(idx, value, budget)
        }
        StaticKind::ResponsePseudo => Err(malformed()),
        StaticKind::ContentLength | StaticKind::Regular => {
          self.regular = true;
          let ascii =
            if elem.with_value { true } else { field_value(value).ok_or_else(malformed)? };
          self.non_ascii |= !ascii;
          self.push_regular(name, value, kind == StaticKind::ContentLength, false, budget)
        }
      };
    }
    if let Some(pseudo) = name.strip_prefix(b":") {
      // Pseudo-header fields come first, once each, and only those of requests (section 4.3); no
      // userinfo in the authority (section 4.3.1)
      let idx = match pseudo {
        b"method" => METHOD,
        b"scheme" => SCHEME,
        b"authority" => AUTHORITY,
        b"path" => PATH,
        _ => return Err(malformed()),
      };
      if !pseudo_value_ok(idx, value) {
        return Err(malformed());
      }
      return self.push_pseudo(idx, value, budget);
    }
    self.regular = true;
    let ascii = check_field(name, value)?;
    self.non_ascii |= !ascii;
    self.push_regular(name, value, name == b"content-length", name == b"host", budget)
  }

  // A pseudo-header field of index `idx`, checked, unless it comes after a regular field or again
  fn push_pseudo(&mut self, idx: usize, value: &[u8], budget: &mut Budget) -> crate::Result<()> {
    if self.regular || self.has(idx) {
      return Err(malformed());
    }
    let range = self.store(value, budget)?;
    if let Some(elem) = self.pseudo.get_mut(idx) {
      *elem = Some(range);
    }
    Ok(())
  }

  // A regular field, checked: `content-length` and `host` say if it is one of them.
  fn push_regular(
    &mut self,
    name: &[u8],
    value: &[u8],
    content_length: bool,
    host: bool,
    budget: &mut Budget,
  ) -> crate::Result<()> {
    let start = u32::try_from(self.bytes.len()).map_err(|_err| malformed())?;
    let (name_len, value_len) = (len_u32(name)?, len_u32(value)?);
    reserve(budget, &mut self.bytes, name.len().wrapping_add(value.len()))?;
    reserve(budget, &mut self.fields, 1)?;
    let _ = self.bytes.extend_from_copyable_slices([name, value])?;
    let value_range = (start.wrapping_add(name_len), value_len);
    if content_length {
      let length = parse_content_length(value)?;
      if self.content_length.is_some_and(|el| el != length) {
        return Err(malformed());
      }
      self.content_length = Some(length);
    } else if host {
      // Once, and without userinfo (RFC 9110 section 7.2)
      if self.host.is_some() || value.contains(&b'@') {
        return Err(malformed());
      }
      self.host = Some(value_range);
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

/// What a name of the static table of QPACK is to a request (RFC 9204 Appendix A).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StaticKind {
  /// `content-length`.
  ContentLength,
  /// A pseudo-header field of requests, with its index among them.
  Pseudo(usize),
  /// A regular field, neither `content-length`, `host`, `te` nor specific to a connection: the
  /// names of the table are lowercase tokens.
  Regular,
  /// `:status`, which no request has.
  ResponsePseudo,
}

/// The kinds of the 99 entries of the static table, by index (checked against the names by the
/// test of this module).
static STATIC_KINDS: [StaticKind; 99] = static_kinds();

const fn static_kinds() -> [StaticKind; 99] {
  let mut rslt = [StaticKind::Regular; 99];
  rslt[0] = StaticKind::Pseudo(AUTHORITY);
  rslt[1] = StaticKind::Pseudo(PATH);
  rslt[4] = StaticKind::ContentLength;
  let mut idx = 15;
  while idx <= 21 {
    rslt[idx] = StaticKind::Pseudo(METHOD);
    idx += 1;
  }
  rslt[22] = StaticKind::Pseudo(SCHEME);
  rslt[23] = StaticKind::Pseudo(SCHEME);
  let mut idx = 24;
  while idx <= 28 {
    rslt[idx] = StaticKind::ResponsePseudo;
    idx += 1;
  }
  let mut idx = 63;
  while idx <= 71 {
    rslt[idx] = StaticKind::ResponsePseudo;
    idx += 1;
  }
  rslt
}

// If `value` can be the value of the pseudo-header field of index `idx` (RFC 9114 section 4.3.1:
// no userinfo in the authority)
fn pseudo_value_ok(idx: usize, value: &[u8]) -> bool {
  match idx {
    METHOD => is_token(value),
    SCHEME => is_scheme(value),
    AUTHORITY => is_visible(value) && !value.contains(&b'@'),
    _ => is_visible(value),
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
  check_field(name, value).map(|_| ())
}

// A field that is not a pseudo-header field: a lowercase token for a name (RFC 9114 section 4.2),
// a value of the `field-content` of RFC 9110 section 5.5 (section 10.3) and no field that is
// specific to a connection (section 4.2). If the value is ASCII.
fn check_field(name: &[u8], value: &[u8]) -> crate::Result<bool> {
  if name.is_empty() || !all_in(name, LOWER_TCHAR) {
    return Err(malformed());
  }
  let Some(ascii) = field_value(value) else {
    return Err(malformed());
  };
  match name {
    b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding" | b"upgrade" => {
      Err(malformed())
    }
    b"te" if value != b"trailers" => Err(malformed()),
    _ => Ok(ascii),
  }
}

// If `value` is a `field-content`, if it is ASCII, in one pass: SP and HTAB are allowed inside,
// not at the ends; other controls and DEL are not.
fn field_value(value: &[u8]) -> Option<bool> {
  let ends = |el: Option<&u8>| !matches!(el, Some(b' ' | b'\t'));
  if !ends(value.first()) || !ends(value.last()) {
    return None;
  }
  let classes = value.iter().fold(u8::MAX, |acc, el| acc & class(*el));
  (classes & FIELD != 0).then_some(classes & ASCII != 0)
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

// If every byte of `bytes` is of the class `bit`.
fn all_in(bytes: &[u8], bit: u8) -> bool {
  bytes.iter().all(|el| class(*el) & bit != 0)
}

// The classes of `byte`.
fn class(byte: u8) -> u8 {
  CLASSES.get(usize::from(byte)).copied().unwrap_or(0)
}

const fn classes() -> [u8; 256] {
  let mut rslt = [0; 256];
  let mut idx = 0;
  while idx < 256 {
    #[expect(clippy::cast_possible_truncation, reason = "below 256")]
    let byte = idx as u8;
    let alnum = byte.is_ascii_alphanumeric();
    let tchar = alnum
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
      );
    let mut bits = 0;
    if tchar {
      bits |= TCHAR;
      if !byte.is_ascii_uppercase() {
        bits |= LOWER_TCHAR;
      }
    }
    if byte > 0x20 && byte != 0x7f {
      bits |= VISIBLE;
    }
    if byte == b'\t' || (byte >= 0x20 && byte != 0x7f) {
      bits |= FIELD;
    }
    if alnum || matches!(byte, b'+' | b'-' | b'.') {
      bits |= SCHEME_CHAR;
    }
    if byte < 0x80 {
      bits |= ASCII;
    }
    rslt[idx] = bits;
    idx += 1;
  }
  rslt
}

// `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` (RFC 3986 section 3.1)
fn is_scheme(value: &[u8]) -> bool {
  value.first().is_some_and(u8::is_ascii_alphabetic) && all_in(value, SCHEME_CHAR)
}

fn is_token(value: &[u8]) -> bool {
  !value.is_empty() && all_in(value, TCHAR)
}

// No space and no control: `:authority` and `:path` are parts of a URI
fn is_visible(value: &[u8]) -> bool {
  all_in(value, VISIBLE)
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

#[cfg(test)]
mod tests {
  use crate::http3::{
    h3_conn_state::Budget,
    qpack::{STATIC_TABLE, StaticRef},
    request::{ASCII, FIELD, LOWER_TCHAR, RequestHead, SCHEME_CHAR, TCHAR, VISIBLE, class},
  };
  use alloc::{format, string::String, vec, vec::Vec};

  // The precondition of the static reference of `push` is checked in debug builds: a name that is
  // not the entry's is a programming error.
  #[cfg(debug_assertions)]
  #[should_panic(expected = "assertion")]
  #[test]
  fn static_reference_with_another_name_is_caught_in_debug_builds() {
    let mut head = RequestHead::new();
    let sref = Some(StaticRef { idx: 31, with_value: false });
    let _rslt = head.push(b"x-not-accept-encoding", b"br", sref, 16_384, &mut Budget::new(1 << 20));
  }

  // What the static reference of `push` relies on: every name and value of the static table is
  // ASCII (the text of `ascii_fields`), every name a lowercase token.
  #[test]
  fn static_table_is_ascii_and_its_names_are_lowercase_tokens() {
    for (name, value) in STATIC_TABLE {
      assert!(name.is_ascii() && value.is_ascii(), "{name:?}");
      let bare = name.strip_prefix(b":").unwrap_or(name);
      assert!(!bare.is_empty() && bare.iter().all(|el| class(*el) & LOWER_TCHAR != 0), "{name:?}");
    }
  }

  // Ruling T16-a (fields validated once): a head whose fields are all ASCII hands them out as text
  // without a second UTF-8 check, in their order; one with a byte of obs-text in a value hands out
  // none as text (the caller checks them). Runs under Miri: the conversion is unchecked.
  #[test]
  fn ascii_fields_come_out_as_text() {
    let mut budget = Budget::new(1 << 20);
    let mut head = RequestHead::new();
    for (name, value) in
      [(&b":method"[..], &b"GET"[..]), (b"user-agent", b"h2load nghttp3"), (b"x-a", b"")]
    {
      head.push(name, value, None, 16_384, &mut budget).unwrap();
    }
    let texts: Vec<(&str, &str)> = head.ascii_fields().unwrap().collect();
    assert_eq!(texts, [("user-agent", "h2load nghttp3"), ("x-a", "")]);
    for value in [&b"caf\xc3\xa9"[..], b"\xff"] {
      let mut head = RequestHead::new();
      head.push(b"x-a", b"1", None, 16_384, &mut budget).unwrap();
      head.push(b"x-b", value, None, 16_384, &mut budget).unwrap();
      assert!(head.ascii_fields().is_none());
      assert_eq!(head.fields().count(), 2);
    }
    // A static value is ASCII
    let mut head = RequestHead::new();
    let sref = Some(StaticRef { idx: 31, with_value: true });
    head.push(b"accept-encoding", b"gzip, deflate, br", sref, 16_384, &mut budget).unwrap();
    assert_eq!(head.ascii_fields().unwrap().count(), 1);
  }

  // The head after `before`, each pushed as a literal, then `name` and `value` pushed with `sref`:
  // the outcome and the head, as text.
  fn after(
    before: &[(&[u8], &[u8])],
    name: &[u8],
    value: &[u8],
    sref: Option<StaticRef>,
  ) -> (String, String) {
    let mut head = RequestHead::new();
    let mut budget = Budget::new(1 << 20);
    for (el_name, el_value) in before {
      let _rslt = head.push(el_name, el_value, None, 16_384, &mut budget);
    }
    let rslt = head.push(name, value, sref, 16_384, &mut budget);
    (format!("{rslt:?}"), format!("{head:?}"))
  }

  // Ruling T16-a: a field whose name, or name and value, came from the static table of QPACK is
  // classified by its index instead of by comparing its name; the outcome and the head are those
  // of the same field given as literals, for every entry of the table, with its own value or
  // another, valid or not, at the start of a head, after a regular field and after itself.
  #[test]
  fn static_references_classify_as_the_names_do() {
    let values: [&[u8]; 16] = [
      b"",
      b"GET",
      b"x y",
      b" lead",
      b"trail ",
      b"a@b",
      b"https",
      b"/p?q",
      b"\x7f",
      b"\tx",
      b"trailers",
      b"0",
      b"123",
      b"12a",
      b"\xc3\xa9",
      b"localhost:8443",
    ];
    for (idx, (name, own)) in STATIC_TABLE.iter().enumerate() {
      let idx = u8::try_from(idx).unwrap();
      let mut cases: Vec<(&[u8], StaticRef)> = vec![(own, StaticRef { idx, with_value: true })];
      cases.extend(values.iter().map(|value| (*value, StaticRef { idx, with_value: false })));
      cases.push((own, StaticRef { idx, with_value: false }));
      for (value, sref) in cases {
        for before in [&[][..], &[(&b"user-agent"[..], &b"x"[..])][..], &[(*name, value)][..]] {
          assert_eq!(
            after(before, name, value, Some(sref)),
            after(before, name, value, None),
            "{} {:?} {sref:?} after {before:?}",
            String::from_utf8_lossy(name),
            value
          );
        }
      }
    }
  }

  // The checks as RFC 9110 and RFC 3986 word them, byte by byte, which the classes must match.
  fn tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
  }

  // Ruling T16-a: the field checks read one table of byte classes; every byte is in the classes
  // that the rules give it, and in no other.
  #[test]
  fn byte_classes_match_the_rules() {
    for byte in 0..=255u8 {
      let expected = [
        (TCHAR, tchar(byte)),
        (LOWER_TCHAR, tchar(byte) && !byte.is_ascii_uppercase()),
        (VISIBLE, byte > 0x20 && byte != 0x7f),
        (FIELD, byte == b'\t' || (byte >= 0x20 && byte != 0x7f)),
        (SCHEME_CHAR, byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')),
        (ASCII, byte.is_ascii()),
      ];
      for (bit, is) in expected {
        assert_eq!(class(byte) & bit != 0, is, "byte {byte:#04x}, class {bit:#04x}");
      }
    }
  }
}
