//! The QPACK static table (RFC 9204 Appendix A), indexed from 0.

/// The 99 entries of RFC 9204 Appendix A: name and value.
pub(crate) static STATIC_TABLE: [(&[u8], &[u8]); 99] = [
  (b":authority", b""),
  (b":path", b"/"),
  (b"age", b"0"),
  (b"content-disposition", b""),
  (b"content-length", b"0"),
  (b"cookie", b""),
  (b"date", b""),
  (b"etag", b""),
  (b"if-modified-since", b""),
  (b"if-none-match", b""),
  (b"last-modified", b""),
  (b"link", b""),
  (b"location", b""),
  (b"referer", b""),
  (b"set-cookie", b""),
  (b":method", b"CONNECT"),
  (b":method", b"DELETE"),
  (b":method", b"GET"),
  (b":method", b"HEAD"),
  (b":method", b"OPTIONS"),
  (b":method", b"POST"),
  (b":method", b"PUT"),
  (b":scheme", b"http"),
  (b":scheme", b"https"),
  (b":status", b"103"),
  (b":status", b"200"),
  (b":status", b"304"),
  (b":status", b"404"),
  (b":status", b"503"),
  (b"accept", b"*/*"),
  (b"accept", b"application/dns-message"),
  (b"accept-encoding", b"gzip, deflate, br"),
  (b"accept-ranges", b"bytes"),
  (b"access-control-allow-headers", b"cache-control"),
  (b"access-control-allow-headers", b"content-type"),
  (b"access-control-allow-origin", b"*"),
  (b"cache-control", b"max-age=0"),
  (b"cache-control", b"max-age=2592000"),
  (b"cache-control", b"max-age=604800"),
  (b"cache-control", b"no-cache"),
  (b"cache-control", b"no-store"),
  (b"cache-control", b"public, max-age=31536000"),
  (b"content-encoding", b"br"),
  (b"content-encoding", b"gzip"),
  (b"content-type", b"application/dns-message"),
  (b"content-type", b"application/javascript"),
  (b"content-type", b"application/json"),
  (b"content-type", b"application/x-www-form-urlencoded"),
  (b"content-type", b"image/gif"),
  (b"content-type", b"image/jpeg"),
  (b"content-type", b"image/png"),
  (b"content-type", b"text/css"),
  (b"content-type", b"text/html; charset=utf-8"),
  (b"content-type", b"text/plain"),
  (b"content-type", b"text/plain;charset=utf-8"),
  (b"range", b"bytes=0-"),
  (b"strict-transport-security", b"max-age=31536000"),
  (b"strict-transport-security", b"max-age=31536000; includesubdomains"),
  (b"strict-transport-security", b"max-age=31536000; includesubdomains; preload"),
  (b"vary", b"accept-encoding"),
  (b"vary", b"origin"),
  (b"x-content-type-options", b"nosniff"),
  (b"x-xss-protection", b"1; mode=block"),
  (b":status", b"100"),
  (b":status", b"204"),
  (b":status", b"206"),
  (b":status", b"302"),
  (b":status", b"400"),
  (b":status", b"403"),
  (b":status", b"421"),
  (b":status", b"425"),
  (b":status", b"500"),
  (b"accept-language", b""),
  (b"access-control-allow-credentials", b"FALSE"),
  (b"access-control-allow-credentials", b"TRUE"),
  (b"access-control-allow-headers", b"*"),
  (b"access-control-allow-methods", b"get"),
  (b"access-control-allow-methods", b"get, post, options"),
  (b"access-control-allow-methods", b"options"),
  (b"access-control-expose-headers", b"content-length"),
  (b"access-control-request-headers", b"content-type"),
  (b"access-control-request-method", b"get"),
  (b"access-control-request-method", b"post"),
  (b"alt-svc", b"clear"),
  (b"authorization", b""),
  (b"content-security-policy", b"script-src 'none'; object-src 'none'; base-uri 'none'"),
  (b"early-data", b"1"),
  (b"expect-ct", b""),
  (b"forwarded", b""),
  (b"if-range", b""),
  (b"origin", b""),
  (b"purpose", b"prefetch"),
  (b"server", b""),
  (b"timing-allow-origin", b"*"),
  (b"upgrade-insecure-requests", b"1"),
  (b"user-agent", b""),
  (b"x-forwarded-for", b""),
  (b"x-frame-options", b"deny"),
  (b"x-frame-options", b"sameorigin"),
];

/// The static table entry that a decoded field came from (ruling T16-a): its name, and its value
/// too for an Indexed Field Line. A field with a literal name, or a name of the dynamic table, has
/// none.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StaticRef {
  /// The index of the entry, below 99.
  pub(crate) idx: u8,
  /// If the value is the entry's too.
  pub(crate) with_value: bool,
}

impl StaticRef {
  // The reference as one byte for the decode memo, `NONE_CODE` for none
  pub(crate) const NONE_CODE: u8 = u8::MAX;

  pub(crate) const fn code(this: Option<Self>) -> u8 {
    match this {
      Some(elem) => elem.idx | if elem.with_value { 0x80 } else { 0 },
      None => Self::NONE_CODE,
    }
  }

  pub(crate) const fn from_code(code: u8) -> Option<Self> {
    if code == Self::NONE_CODE {
      return None;
    }
    Some(Self { idx: code & 0x7f, with_value: code & 0x80 != 0 })
  }
}

/// The index of the entry with `name` and `value`, if there is one.
pub(crate) fn find_exact(name: &[u8], value: &[u8]) -> Option<u8> {
  let idx =
    STATIC_TABLE.iter().position(|(el_name, el_value)| *el_name == name && *el_value == value)?;
  u8::try_from(idx).ok()
}

/// The lowest index of an entry with `name`, if there is one.
pub(crate) fn find_name(name: &[u8]) -> Option<u8> {
  let idx = STATIC_TABLE.iter().position(|(el_name, _)| *el_name == name)?;
  u8::try_from(idx).ok()
}

#[cfg(test)]
mod tests {
  use crate::http3::qpack::static_table::{STATIC_TABLE, find_exact, find_name};

  #[test]
  fn static_table_has_99_entries_and_known_indices() {
    assert_eq!(STATIC_TABLE.len(), 99);
    // The entries that responses use (spec 5.9)
    assert_eq!(find_exact(b":status", b"200"), Some(25));
    assert_eq!(find_exact(b"content-type", b"text/plain;charset=utf-8"), Some(54));
    assert_eq!(find_exact(b"content-encoding", b"br"), Some(42));
    assert_eq!(find_exact(b"content-encoding", b"gzip"), Some(43));
    assert_eq!(find_exact(b"vary", b"accept-encoding"), Some(59));
    // The two ends and the entries that RFC 9204 prints over several lines
    assert_eq!(STATIC_TABLE.first(), Some(&(&b":authority"[..], &b""[..])));
    assert_eq!(STATIC_TABLE.last(), Some(&(&b"x-frame-options"[..], &b"sameorigin"[..])));
    assert_eq!(find_exact(b"content-type", b"text/html; charset=utf-8"), Some(52));
    assert_eq!(find_exact(b"content-type", b"application/x-www-form-urlencoded"), Some(47));
    assert_eq!(find_exact(b"cache-control", b"public, max-age=31536000"), Some(41));
    assert_eq!(
      find_exact(b"strict-transport-security", b"max-age=31536000; includesubdomains; preload"),
      Some(58)
    );
    assert_eq!(
      find_exact(
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'"
      ),
      Some(85)
    );
    // The first entry of a name, and names or values that are not there
    assert_eq!(find_name(b":status"), Some(24));
    assert_eq!(find_name(b"content-type"), Some(44));
    assert_eq!(find_name(b"server"), Some(92));
    assert_eq!(find_name(b":authority"), Some(0));
    assert_eq!(find_name(b"x-unknown"), None);
    assert_eq!(find_exact(b":status", b"201"), None);
    assert_eq!(find_exact(b"server", b"rimu"), None);
    // Every index finds itself
    for (idx, (name, value)) in STATIC_TABLE.iter().enumerate() {
      let idx = u8::try_from(idx).unwrap();
      assert_eq!(find_exact(name, value), Some(idx));
      assert!(find_name(name).unwrap() <= idx);
      assert!(name.iter().all(|el| !el.is_ascii_uppercase()), "{idx}");
    }
  }
}
