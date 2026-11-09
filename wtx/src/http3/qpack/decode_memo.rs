//! Field sections decoded lately, with what they decoded to (spec 5.9).
//!
//! Clients repeat requests byte for byte. A field section decodes to the same fields as long as the
//! dynamic table entries that it references are there: the key is the absolute Required Insert
//! Count with the bytes of the section, and an entry is replayed only while the lowest absolute
//! index that its section referenced is not evicted. Absolute indices are never reused within one
//! table only: each entry also carries the epoch of the decoder table that it was decoded against
//! (unique per `QpackDecoder::new` and `QpackDecoder::reset`), and replays only for it, so a memo
//! that outlives its decoder, or is given to another, never replays another connection's fields.
//! One memo goes with one decoder. The decoder replays a kept section with the same effects as a
//! decode: the blocked check before and the Section Acknowledgment after.

use crate::collections::VectorUsize;

/// Longer field sections are not kept: they are rarely repeated and costly to compare.
pub(crate) const MAX_SECTION_LEN: usize = 128;
/// Sections that decode to more bytes of names and values are not kept, which bounds the memory
/// of an entry (a section of 128 bytes can reference 4 KiB entries of the dynamic table).
pub(crate) const MAX_DECODED_LEN: usize = 2048;

#[derive(Debug)]
struct Entry {
  /// Names and values, one after the other.
  bytes: VectorUsize<u8>,
  /// The decoder table that the section was decoded against.
  epoch: u64,
  /// Name and value lengths of each field, in order.
  fields: VectorUsize<(u32, u32)>,
  last_use: u64,
  lowest_dynamic: u64,
  ric: u64,
  section: [u8; MAX_SECTION_LEN],
  /// 0 while the entry holds nothing that can be replayed.
  section_len: u8,
}

impl Entry {
  const fn new() -> Self {
    Self {
      bytes: VectorUsize::new(),
      epoch: 0,
      fields: VectorUsize::new(),
      last_use: 0,
      lowest_dynamic: 0,
      ric: 0,
      section: [0; MAX_SECTION_LEN],
      section_len: 0,
    }
  }

  fn holds(&self, epoch: u64, ric: u64, section: &[u8]) -> bool {
    self.section_len != 0
      && self.epoch == epoch
      && self.ric == ric
      && self.section.get(..usize::from(self.section_len)) == Some(section)
  }
}

/// See the module documentation.
#[derive(Debug)]
pub(crate) struct DecodeMemo<const N: usize> {
  entries: [Entry; N],
  #[cfg(test)]
  pub(crate) hits: u64,
  uses: u64,
}

impl<const N: usize> DecodeMemo<N> {
  /// A memo with nothing kept, which allocates nothing.
  pub(crate) fn new() -> Self {
    Self {
      entries: core::array::from_fn(|_| Entry::new()),
      #[cfg(test)]
      hits: 0,
      uses: 0,
    }
  }

  /// The bytes that the kept fields take on the heap.
  pub(crate) fn heap_bytes(&self) -> usize {
    self.entries.iter().fold(0usize, |acc, el| {
      let fields = el.fields.capacity().saturating_mul(size_of::<(u32, u32)>());
      acc.saturating_add(el.bytes.capacity()).saturating_add(fields)
    })
  }

  /// The sections that can be replayed.
  #[cfg(test)]
  pub(crate) fn kept(&self) -> usize {
    self.entries.iter().filter(|el| el.section_len != 0).count()
  }

  /// Forgets every kept section; the storage stays for the next ones.
  pub(crate) fn clear(&mut self) {
    for entry in &mut self.entries {
      entry.last_use = 0;
      entry.section_len = 0;
    }
    self.uses = 0;
  }

  /// The fields that `section` with the absolute Required Insert Count `ric` decoded to against
  /// the table of `epoch`, if it is kept and the lowest dynamic table entry that it referenced is
  /// at or above `oldest_live`.
  pub(crate) fn lookup(
    &mut self,
    epoch: u64,
    ric: u64,
    section: &[u8],
    oldest_live: u64,
  ) -> Option<MemoFields<'_>> {
    if section.len() > MAX_SECTION_LEN {
      return None;
    }
    self.uses = self.uses.wrapping_add(1);
    let uses = self.uses;
    let entry = self.entries.iter_mut().find(|el| el.holds(epoch, ric, section))?;
    if entry.lowest_dynamic < oldest_live {
      return None;
    }
    entry.last_use = uses;
    #[cfg(test)]
    {
      self.hits = self.hits.wrapping_add(1);
    }
    Some(MemoFields { bytes: entry.bytes.as_slice(), fields: entry.fields.iter() })
  }

  /// Starts keeping `section` with the absolute Required Insert Count `ric`, decoded against the
  /// table of `epoch`, in place of the entry that holds the same section or else of the entry used
  /// least recently: the fields are pushed to the recorder as they are decoded, which keeps them
  /// once it is sealed. `None` if the section is too long to be kept.
  pub(crate) fn insert(
    &mut self,
    epoch: u64,
    ric: u64,
    section: &[u8],
  ) -> Option<MemoRecorder<'_>> {
    let section_len =
      u8::try_from(section.len()).ok().filter(|el| usize::from(*el) <= MAX_SECTION_LEN)?;
    if section_len == 0 {
      return None;
    }
    let same = self.entries.iter().position(|el| el.holds(epoch, ric, section));
    let idx = same.or_else(|| {
      self.entries.iter().enumerate().min_by_key(|(_, el)| el.last_use).map(|(idx, _)| idx)
    })?;
    self.uses = self.uses.wrapping_add(1);
    let entry = self.entries.get_mut(idx)?;
    entry.bytes.clear();
    entry.fields.clear();
    entry.epoch = epoch;
    entry.last_use = self.uses;
    entry.ric = ric;
    entry.section.get_mut(..section.len())?.copy_from_slice(section);
    entry.section_len = 0;
    Some(MemoRecorder { entry, section_len, valid: true })
  }
}

/// The fields of a kept section: name and value.
#[derive(Debug)]
pub(crate) struct MemoFields<'memo> {
  bytes: &'memo [u8],
  fields: core::slice::Iter<'memo, (u32, u32)>,
}

impl<'memo> Iterator for MemoFields<'memo> {
  type Item = (&'memo [u8], &'memo [u8]);

  #[inline]
  fn next(&mut self) -> Option<Self::Item> {
    let (name_len, value_len) = self.fields.next()?;
    let (name, rest) = self.bytes.split_at_checked(usize::try_from(*name_len).ok()?)?;
    let (value, rest) = rest.split_at_checked(usize::try_from(*value_len).ok()?)?;
    self.bytes = rest;
    Some((name, value))
  }
}

/// Records the fields of a section that is being decoded, see [`DecodeMemo::insert`]. Dropped
/// without [`Self::seal`], the entry keeps nothing.
#[derive(Debug)]
pub(crate) struct MemoRecorder<'memo> {
  entry: &'memo mut Entry,
  section_len: u8,
  valid: bool,
}

impl MemoRecorder<'_> {
  /// Keeps a decoded field. A section that decodes to more than [`MAX_DECODED_LEN`] bytes, or
  /// whose fields can not be stored, is not kept.
  pub(crate) fn push(&mut self, name: &[u8], value: &[u8]) {
    let fits =
      self.entry.bytes.len().wrapping_add(name.len()).wrapping_add(value.len()) <= MAX_DECODED_LEN;
    let (Ok(name_len), Ok(value_len)) = (u32::try_from(name.len()), u32::try_from(value.len()))
    else {
      self.valid = false;
      return;
    };
    self.valid = self.valid
      && fits
      && self.entry.bytes.extend_from_copyable_slices([name, value]).is_ok()
      && self.entry.fields.push((name_len, value_len)).is_ok();
  }

  /// Keeps the section, which referenced no dynamic table entry below `lowest_dynamic`
  /// (`u64::MAX` for none).
  pub(crate) fn seal(self, lowest_dynamic: u64) {
    if self.valid {
      self.entry.lowest_dynamic = lowest_dynamic;
      self.entry.section_len = self.section_len;
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::{
    Error,
    collections::VectorUsize,
    http3::{
      H3ErrorCode, Http3Error,
      qpack::{DecodeMemo, DecodeOutcome, QpackDecoder},
      qpack_check::wire,
    },
  };
  use alloc::vec::Vec;

  type Fields = Vec<(Vec<u8>, Vec<u8>)>;

  fn decode<const N: usize>(
    decoder: &mut QpackDecoder,
    memo: &mut DecodeMemo<N>,
    stream: u64,
    section: &[u8],
  ) -> crate::Result<(DecodeOutcome, Fields)> {
    let mut scratch = VectorUsize::new();
    let mut fields = Vec::new();
    let outcome =
      decoder.decode_with_memo(memo, stream, section, &mut scratch, &mut |name, value| {
        fields.push((name.to_vec(), value.to_vec()));
        Ok(())
      })?;
    Ok((outcome, fields))
  }

  fn output(decoder: &mut QpackDecoder) -> Vec<u8> {
    let out = decoder.decoder_stream_output().to_vec();
    decoder.consume_decoder_output(out.len());
    out
  }

  fn pairs(list: &[(&str, &str)]) -> Fields {
    list.iter().map(|(name, value)| (name.as_bytes().to_vec(), value.as_bytes().to_vec())).collect()
  }

  #[test]
  fn decode_memo_hits_identical_sections() {
    // RFC 9204 B.2: two entries, and a section on stream 4 that references both
    let mut decoder = QpackDecoder::new(220, 2).unwrap();
    let encoder = hexd!(b"3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468");
    assert_eq!(decoder.on_encoder_stream(&encoder).unwrap(), encoder.len());
    let _ = output(&mut decoder);
    let mut memo = DecodeMemo::<2>::new();
    let dynamic = hexd!(b"03811011");
    let expected = pairs(&[(":authority", "www.example.com"), (":path", "/sample/path")]);

    // Decoded, then replayed; each one is acknowledged on its own stream
    let first = decode(&mut decoder, &mut memo, 4, &dynamic).unwrap();
    assert_eq!(first, (DecodeOutcome::Done { referenced_dynamic: true }, expected.clone()));
    assert_eq!(memo.hits, 0);
    assert_eq!(output(&mut decoder), [0x84]);
    let second = decode(&mut decoder, &mut memo, 8, &dynamic).unwrap();
    assert_eq!(second, first);
    assert_eq!(memo.hits, 1);
    assert_eq!(output(&mut decoder), [0x88]);

    // A static section (RFC 9204 B.1) is replayed too, and acknowledged by neither
    let fixed = hexd!(b"0000510b2f696e6465782e68746d6c");
    let static_expected =
      (DecodeOutcome::Done { referenced_dynamic: false }, pairs(&[(":path", "/index.html")]));
    assert_eq!(decode(&mut decoder, &mut memo, 12, &fixed).unwrap(), static_expected);
    assert_eq!(decode(&mut decoder, &mut memo, 16, &fixed).unwrap(), static_expected);
    assert_eq!(memo.hits, 2);
    assert_eq!(output(&mut decoder), b"");

    // Two entries are kept: a third section replaces the one used least recently (the dynamic one)
    let mut other = Vec::new();
    wire::prefix(&mut other, 0, 0, 6);
    wire::literal(&mut other, false, b"x-a", b"1", true);
    let _ = decode(&mut decoder, &mut memo, 20, &other).unwrap();
    let _ = decode(&mut decoder, &mut memo, 24, &fixed).unwrap();
    assert_eq!(memo.hits, 3);
    let _ = decode(&mut decoder, &mut memo, 28, &dynamic).unwrap();
    assert_eq!(memo.hits, 3);
    let _ = output(&mut decoder);

    // Sections longer than 128 bytes are not kept
    let mut long = Vec::new();
    wire::prefix(&mut long, 0, 0, 6);
    wire::literal(&mut long, false, b"x-long", &[b'v'; 130], false);
    let _ = decode(&mut decoder, &mut memo, 32, &long).unwrap();
    let _ = decode(&mut decoder, &mut memo, 36, &long).unwrap();
    assert_eq!(memo.hits, 3);

    // The entries that a kept section references are evicted: the same bytes are decoded again
    // and fail as a decode does (RFC 9204 section 2.2.3), they are not replayed
    let _ = decode(&mut decoder, &mut memo, 40, &dynamic).unwrap();
    assert_eq!(memo.hits, 4);
    let _ = output(&mut decoder);
    assert_eq!(decoder.on_encoder_stream(&[0x20]).unwrap(), 1);
    assert!(matches!(
      decode(&mut decoder, &mut memo, 44, &dynamic),
      Err(Error::Http3Close(
        H3ErrorCode::QpackDecompressionFailed,
        Http3Error::InvalidDynamicIndex
      ))
    ));
    assert_eq!(memo.hits, 4);
    assert_eq!(output(&mut decoder), b"");
  }

  // A memo replays only for the table that it was filled from: with a new decoder, or the same one
  // reset, the same bytes and Required Insert Count decode against the new table
  #[test]
  fn decode_memo_never_replays_another_table() {
    let ours = hexd!(b"3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468");
    let mut theirs = Vec::new();
    wire::set_capacity(&mut theirs, 220);
    wire::insert_name_ref(&mut theirs, true, 0, b"other.example", false);
    wire::insert_name_ref(&mut theirs, true, 1, b"/other", false);
    let dynamic = hexd!(b"03811011");
    let expected = pairs(&[(":authority", "www.example.com"), (":path", "/sample/path")]);
    let other = pairs(&[(":authority", "other.example"), (":path", "/other")]);
    let mut memo = DecodeMemo::<2>::new();
    let mut first = QpackDecoder::new(220, 2).unwrap();
    assert_eq!(first.on_encoder_stream(&ours).unwrap(), ours.len());
    let _ = decode(&mut first, &mut memo, 4, &dynamic).unwrap();
    assert_eq!(decode(&mut first, &mut memo, 8, &dynamic).unwrap().1, expected);
    assert_eq!(memo.hits, 1);
    // A new decoder whose table has other entries at the same absolute indices
    let mut second = QpackDecoder::new(220, 2).unwrap();
    assert_eq!(second.on_encoder_stream(&theirs).unwrap(), theirs.len());
    assert_eq!(decode(&mut second, &mut memo, 4, &dynamic).unwrap().1, other);
    assert_eq!(memo.hits, 1);
    // The first decoder reset and refilled the same way
    first.reset(220, 2).unwrap();
    assert_eq!(first.on_encoder_stream(&theirs).unwrap(), theirs.len());
    assert_eq!(decode(&mut first, &mut memo, 4, &dynamic).unwrap().1, other);
    assert_eq!(memo.hits, 1);
    // Reset and refilled, then emptied: the RFC error, not a replay
    first.reset(220, 2).unwrap();
    let mut emptied = theirs.clone();
    wire::set_capacity(&mut emptied, 0);
    assert_eq!(first.on_encoder_stream(&emptied).unwrap(), emptied.len());
    assert!(matches!(
      decode(&mut first, &mut memo, 8, &dynamic),
      Err(Error::Http3Close(
        H3ErrorCode::QpackDecompressionFailed,
        Http3Error::InvalidDynamicIndex
      ))
    ));
    // A cleared memo keeps nothing
    let fixed = hexd!(b"0000510b2f696e6465782e68746d6c");
    let _ = decode(&mut second, &mut memo, 12, &fixed).unwrap();
    memo.clear();
    let _ = decode(&mut second, &mut memo, 16, &fixed).unwrap();
    assert_eq!(memo.hits, 1);
  }

  // A kept section is not replayed while its stream would block: a decoder whose table is behind
  // the section blocks the stream as a decode does
  #[test]
  fn decode_memo_respects_blocked_streams() {
    let mut decoder = QpackDecoder::new(220, 1).unwrap();
    let mut memo = DecodeMemo::<2>::new();
    let dynamic = hexd!(b"03811011");
    assert_eq!(
      decode(&mut decoder, &mut memo, 4, &dynamic).unwrap(),
      (DecodeOutcome::Blocked { required_insert_count: 2 }, Vec::new())
    );
    assert!(matches!(
      decode(&mut decoder, &mut memo, 8, &dynamic),
      Err(Error::Http3Close(
        H3ErrorCode::QpackDecompressionFailed,
        Http3Error::TooManyBlockedStreams
      ))
    ));
    assert_eq!(memo.hits, 0);
  }
}
