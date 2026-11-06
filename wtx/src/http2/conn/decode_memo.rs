//! Request header blocks seen lately, with what they decoded to.
//!
//! Clients repeat requests: once their fields are in the HPACK dynamic table, the same request
//! is the same few bytes every time. A block whose decoding left the decoder's table unchanged
//! decodes to the same fields again as long as the table stays as it is, so its result can be
//! replayed: a byte compare and two copies instead of a decode (cnetmod keeps one such block per
//! connection; this keeps a few, so requests that rotate over a few paths hit too).

use crate::{
  collections::VectorUsize,
  http::{Headers, Method, MsgBufferString, Protocol},
};
use alloc::string::String;

/// Blocks kept per connection.
const MAX_ENTRIES: usize = 8;
/// Longer blocks are not kept: they are rarely repeated and costly to compare.
pub(crate) const MAX_BLOCK_LEN: usize = 512;

/// What a block decoded to.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Decoded {
  pub(crate) content_length: Option<usize>,
  pub(crate) method: Option<Method>,
  pub(crate) protocol: Option<Protocol>,
}

#[derive(Debug)]
struct Entry {
  block: VectorUsize<u8>,
  decoded: Decoded,
  generation: u64,
  headers: Headers,
  last_use: u64,
  uri: String,
}

/// See the module documentation.
#[derive(Debug)]
pub(crate) struct DecodeMemo {
  entries: VectorUsize<Entry>,
  #[cfg(test)]
  hits: u64,
  uses: u64,
}

impl DecodeMemo {
  pub(crate) const fn new() -> Self {
    Self {
      entries: VectorUsize::new(),
      #[cfg(test)]
      hits: 0,
      uses: 0,
    }
  }

  /// Replays so far.
  #[cfg(test)]
  pub(crate) const fn hits(&self) -> u64 {
    self.hits
  }

  /// Writes into `msg` what `block` decoded to under the decoder table `generation`, if it is
  /// kept.
  pub(crate) fn replay(
    &mut self,
    block: &[u8],
    generation: u64,
    msg: &mut MsgBufferString,
  ) -> crate::Result<Option<Decoded>> {
    if block.len() > MAX_BLOCK_LEN {
      return Ok(None);
    }
    self.uses = self.uses.wrapping_add(1);
    let uses = self.uses;
    let Some(entry) =
      self.entries.iter_mut().find(|el| el.generation == generation && el.block.as_slice() == block)
    else {
      return Ok(None);
    };
    entry.last_use = uses;
    #[cfg(test)]
    {
      self.hits = self.hits.wrapping_add(1);
    }
    msg.headers.copy_from(&entry.headers)?;
    msg.uri.reset().push_str(&entry.uri);
    Ok(Some(entry.decoded))
  }

  /// Keeps `block`, which decoded into `msg` and left the decoder table at `generation`.
  pub(crate) fn insert(
    &mut self,
    block: &[u8],
    generation: u64,
    msg: &MsgBufferString,
    decoded: Decoded,
  ) -> crate::Result<()> {
    if block.len() > MAX_BLOCK_LEN {
      return Ok(());
    }
    let idx = if self.entries.len() < MAX_ENTRIES {
      self.entries.push(Entry {
        block: VectorUsize::new(),
        decoded,
        generation,
        headers: Headers::new(),
        last_use: 0,
        uri: String::new(),
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
    let uses = self.uses;
    let Some(entry) = self.entries.get_mut(idx) else {
      return Ok(());
    };
    entry.block.clear();
    entry.block.extend_from_copyable_slice(block)?;
    entry.decoded = decoded;
    entry.generation = generation;
    entry.headers.copy_from(&msg.headers)?;
    entry.last_use = uses;
    entry.uri.clear();
    entry.uri.push_str(msg.uri.as_str());
    Ok(())
  }
}
