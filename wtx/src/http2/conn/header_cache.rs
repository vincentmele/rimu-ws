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
  entries: VectorUsize<Entry>,
  hits: u64,
  key: VectorUsize<u8>,
  uses: u64,
}

impl HeaderCache {
  pub(crate) const fn new() -> Self {
    Self { entries: VectorUsize::new(), hits: 0, key: VectorUsize::new(), uses: 0 }
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
    let Self { entries, hits, key, uses } = self;
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
    let idx = if self.entries.len() < MAX_ENTRIES {
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

  fn make_key(&mut self, headers: &Headers) -> crate::Result<()> {
    self.key.clear();
    for header in headers.iter().filter(Self::is_cached_field) {
      let sensitive = [u8::from(header.is_sensitive)];
      let name_len = u32::try_from(header.name.len()).unwrap_or(u32::MAX).to_le_bytes();
      self.key.extend_from_copyable_slices([
        &sensitive[..],
        &name_len[..],
        header.name.as_bytes(),
        header.value.as_bytes(),
        &[0],
      ])?;
    }
    Ok(())
  }
}
