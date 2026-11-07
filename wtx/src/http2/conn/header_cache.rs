//! Encoded response header blocks, reused while the HPACK dynamic table stays the same.
//!
//! A server sends the same `:status`, `content-type` and `server` on most responses. Once they are
//! in the dynamic table, their encoding is a few index bytes that only change when the table
//! does. The cache keeps such encodings, keyed by the exact fields, and only those whose encoding
//! did not itself change the table, so replaying them leaves the peer's table as it is.

use crate::{
  collections::VectorUsize,
  http::{Header, Headers, KnownHeaderName, StatusCode},
};

const MAX_ENTRIES: usize = 16;

#[derive(Debug)]
struct Entry {
  block: VectorUsize<u8>,
  generation: u64,
  key: VectorUsize<u8>,
  last_use: u64,
  status: StatusCode,
}

/// Encoded header blocks by (status, fields).
#[derive(Debug)]
pub(crate) struct HeaderCache {
  /// The fields of the last [`Self::get`] may be cached: none is sensitive.
  cacheable: bool,
  entries: VectorUsize<Entry>,
  hits: u64,
  key: VectorUsize<u8>,
  uses: u64,
}

impl HeaderCache {
  pub(crate) const fn new() -> Self {
    Self {
      cacheable: false,
      entries: VectorUsize::new(),
      hits: 0,
      key: VectorUsize::new(),
      uses: 0,
    }
  }

  /// Entries held.
  #[cfg(test)]
  pub(crate) fn len(&self) -> usize {
    self.entries.len()
  }

  /// Cache hits so far.
  #[cfg(test)]
  pub(crate) const fn hits(&self) -> u64 {
    self.hits
  }

  /// The fields a cached block covers: everything but `content-length`, which changes per
  /// response. `date` is covered: it changes once a second, so the block for a new second is
  /// encoded twice (the first time adds the date to the dynamic table) and then replayed.
  pub(crate) fn is_cached_field(header: &Header<&str, &str>) -> bool {
    !header
      .name
      .as_bytes()
      .eq_ignore_ascii_case(<&str>::from(KnownHeaderName::ContentLength).as_bytes())
  }

  /// The block for `status` and the cached fields of `headers`, if it was encoded under the
  /// current `generation`.
  pub(crate) fn get(
    &mut self,
    status: StatusCode,
    headers: &Headers,
    generation: u64,
  ) -> crate::Result<Option<&[u8]>> {
    self.make_key(headers)?;
    self.uses = self.uses.wrapping_add(1);
    if !self.cacheable {
      return Ok(None);
    }
    let Self { entries, hits, key, uses, .. } = self;
    let Some(entry) = entries.iter_mut().find(|el| {
      el.status == status && el.generation == generation && el.key.as_slice() == key.as_slice()
    }) else {
      return Ok(None);
    };
    entry.last_use = *uses;
    *hits = hits.wrapping_add(1);
    Ok(Some(entry.block.as_slice()))
  }

  /// Stores `block` for the key of the last [`Self::get`].
  pub(crate) fn insert(
    &mut self,
    status: StatusCode,
    block: &[u8],
    generation: u64,
  ) -> crate::Result<()> {
    if !self.cacheable || block.len() > MAX_BLOCK_LEN {
      return Ok(());
    }
    // An entry encoded under an older table can never be replayed: reuse the least recently used
    // of those, buffers and all, before adding one.
    let stale = self
      .entries
      .iter()
      .enumerate()
      .filter(|(_, el)| el.generation != generation)
      .min_by_key(|(_, el)| el.last_use)
      .map(|(idx, _)| idx);
    let idx = if let Some(idx) = stale {
      idx
    } else if self.entries.len() < MAX_ENTRIES {
      self.entries.push(Entry {
        block: VectorUsize::new(),
        generation: 0,
        key: VectorUsize::new(),
        last_use: 0,
        status,
      })?;
      self.entries.len().wrapping_sub(1)
    } else {
      let mut oldest = 0;
      for (idx, entry) in self.entries.iter().enumerate() {
        if self.entries.get(oldest).is_some_and(|el| entry.last_use < el.last_use) {
          oldest = idx;
        }
      }
      oldest
    };
    let Self { entries, key, uses, .. } = self;
    let Some(entry) = entries.get_mut(idx) else {
      return Ok(());
    };
    entry.block.clear();
    entry.block.extend_from_copyable_slice(block)?;
    entry.generation = generation;
    entry.key.clear();
    entry.key.extend_from_copyable_slice(key)?;
    entry.last_use = *uses;
    entry.status = status;
    Ok(())
  }

  /// The key of the cached fields of `headers`: each field's name and value, length-prefixed, so
  /// no two field sets share one. Also notes whether the fields may be cached at all.
  fn make_key(&mut self, headers: &Headers) -> crate::Result<()> {
    self.key.clear();
    self.cacheable = true;
    for header in headers.iter().filter(Self::is_cached_field) {
      if header.is_sensitive || is_secret(header.name) {
        self.cacheable = false;
        return Ok(());
      }
      let name_len = u32::try_from(header.name.len()).unwrap_or(u32::MAX).to_le_bytes();
      let value_len = u32::try_from(header.value.len()).unwrap_or(u32::MAX).to_le_bytes();
      self.key.extend_from_copyable_slices([
        &name_len[..],
        header.name.as_bytes(),
        &value_len[..],
        header.value.as_bytes(),
      ])?;
    }
    Ok(())
  }
}

/// Blocks above this are not cached: a response with that many header bytes rarely repeats them,
/// and each entry would hold them.
const MAX_BLOCK_LEN: usize = 512;

/// Fields that carry credentials: a block holding one would keep it in memory, and a response
/// that sets one rarely repeats it.
fn is_secret(name: &str) -> bool {
  let secret = match name.len() {
    6 => KnownHeaderName::Cookie,
    10 => KnownHeaderName::SetCookie,
    13 => KnownHeaderName::Authorization,
    19 => KnownHeaderName::ProxyAuthorization,
    _ => return false,
  };
  name.as_bytes().eq_ignore_ascii_case(<&str>::from(secret).as_bytes())
}

#[cfg(test)]
mod tests {
  use crate::{
    http::{Header, Headers, StatusCode},
    http2::conn::header_cache::HeaderCache,
  };

  fn headers(date: &str) -> Headers {
    let mut headers = Headers::new();
    headers.push_from_iter(Header::from_name_and_value("date", [date])).unwrap();
    headers
  }

  // A block cached under an older table is useless: its entry is reused for the next block, so a
  // connection whose `date` changes every second keeps one entry instead of adding one a second.
  #[test]
  fn header_cache_reuses_a_stale_entry() {
    let mut cache = HeaderCache::new();
    for (generation, date) in [(1, "a"), (2, "b"), (3, "c")] {
      assert!(cache.get(StatusCode::Ok, &headers(date), generation).unwrap().is_none());
      cache.insert(StatusCode::Ok, &[0x88, 0xbe], generation).unwrap();
      assert!(cache.get(StatusCode::Ok, &headers(date), generation).unwrap().is_some());
    }
    assert_eq!(cache.len(), 1);
  }

  // Two header sets never share a key: values are length-prefixed, so a value cannot mimic the
  // start of the next field.
  #[test]
  fn header_cache_key_separates_fields() {
    let mut cache = HeaderCache::new();
    let mut two = Headers::new();
    two.push_from_iter(Header::from_name_and_value("a", ["x"])).unwrap();
    two.push_from_iter(Header::from_name_and_value("b", ["y"])).unwrap();
    let mut one = Headers::new();
    one.push_from_iter(Header::from_name_and_value("a", ["x\0\0\x01\0\0\0by"])).unwrap();
    assert!(cache.get(StatusCode::Ok, &two, 1).unwrap().is_none());
    cache.insert(StatusCode::Ok, &[0x88, 0xbe, 0xbf], 1).unwrap();
    assert!(cache.get(StatusCode::Ok, &one, 1).unwrap().is_none(), "another field set's block");
  }

  // Blocks with sensitive fields (set-cookie and the like) or too big to be repeated are not
  // kept: they would hold secrets, or memory, for blocks that never hit.
  #[test]
  fn header_cache_skips_sensitive_and_large_blocks() {
    let mut cache = HeaderCache::new();
    let mut cookie = Headers::new();
    cookie.push_from_iter(Header::from_name_and_value("set-cookie", ["id=secret"])).unwrap();
    assert!(cache.get(StatusCode::Ok, &cookie, 1).unwrap().is_none());
    cache.insert(StatusCode::Ok, &[0x88, 0xbe], 1).unwrap();
    assert_eq!(cache.len(), 0);
    assert!(cache.get(StatusCode::Ok, &headers("a"), 1).unwrap().is_none());
    cache.insert(StatusCode::Ok, &[0x40; 2000], 1).unwrap();
    assert_eq!(cache.len(), 0);
  }
}
