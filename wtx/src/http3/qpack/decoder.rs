//! The QPACK decoder (RFC 9204): the dynamic table that the encoder stream of the peer fills, the
//! field sections of request streams and the instructions of the decoder stream.
//!
//! The table stores names and values in a byte ring of the advertised capacity and their lengths
//! in a ring of capacity / 32 slots, both allocated once by [`QpackDecoder::new`] with a staging
//! buffer of the capacity, where an insert is put together before it evicts anything: an insert
//! can name or duplicate an entry that it evicts (RFC 9204 section 3.2.2). An entry may wrap
//! around the end of the byte ring; it is then copied into the scratch buffer of the caller when a
//! field section references it.
//!
//! Every length read from the wire is checked against the bytes present before anything is
//! copied or reserved, and Huffman output is bounded by 8/5 of its input. The encoder stream has a
//! budget per receive turn of the connection ([`QpackDecoder::start_turn`]): instructions, and bytes
//! copied out of the table, which a one-byte Duplicate of a large entry would otherwise multiply.
//!
//! One [`DecodeMemo`] goes with one decoder: its entries carry the epoch of the table that they were
//! decoded against, unique per [`QpackDecoder::new`] and [`QpackDecoder::reset`] in the process, so
//! a memo never replays the fields of another table (another connection's) for the same bytes.

use crate::{
  collections::{Clear, ExpansionTy, SingleTypeStorage, TryExtend, VectorUsize},
  http::{
    huffman::huffman_decode,
    prefix_int::{decode_prefix_int, encode_prefix_int},
  },
  http3::{
    H3ErrorCode, Http3Error,
    qpack::{DecodeMemo, static_table::STATIC_TABLE},
  },
  misc::{Lease, Usize},
  sync::AtomicU64,
};
use core::{hint::cold_path, sync::atomic::Ordering};

/// The bytes that an entry adds to the size of the table on top of its name and value (RFC 9204
/// section 3.2.1).
const ENTRY_OVERHEAD: u64 = 32;
/// Decoder-stream bytes that may wait for the connection to write them.
const MAX_PENDING_OUTPUT: usize = 16 * 1024;
/// Encoder-stream instructions allowed per turn on top of two per entry that the table can hold.
const INSTRUCTION_BUDGET_BASE: u64 = 64;
/// Bytes that Duplicates and dynamic name references may copy out of the table per turn, in
/// advertised capacities: an encoder has no reason to copy its whole table more than once in a
/// turn, four times leaves room, and each copied byte is written twice (staging and ring).
const COPY_BUDGET_CAPACITIES: u64 = 4;

/// The source of the decoder epochs, see the module documentation.
static EPOCHS: AtomicU64 = AtomicU64::new(0);

/// What became of a field section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecodeOutcome {
  /// Every field went to the sink; `referenced_dynamic` if the section referenced the dynamic
  /// table, whose Section Acknowledgment is then queued.
  Done {
    /// The Required Insert Count of the section is not zero.
    referenced_dynamic: bool,
  },
  /// The section needs entries that did not arrive yet: nothing went to the sink. Decode it again
  /// once [`QpackDecoder::insert_count`] reaches `required_insert_count`.
  Blocked {
    /// The absolute Required Insert Count of the section.
    required_insert_count: u64,
  },
}

/// Where the name and the value of a dynamic table entry are in the byte ring.
#[derive(Clone, Copy, Debug, Default)]
struct Entry {
  name_len: u32,
  start: u32,
  value_len: u32,
}

impl Entry {
  fn size(self) -> u64 {
    u64::from(self.name_len).wrapping_add(self.value_len.into()).wrapping_add(ENTRY_OVERHEAD)
  }
}

/// The parts of a field section prefix (RFC 9204 section 4.5.1).
#[derive(Clone, Copy, Debug)]
struct Prefix {
  base: u64,
  lines: usize,
  ric: u64,
}

/// A name or a value of a field line: borrowed from the section, the static table or the byte
/// ring, or written into the scratch buffer.
#[derive(Clone, Copy, Debug)]
enum Part<'any> {
  Borrowed(&'any [u8]),
  Scratch(usize, usize),
}

impl<'any> Part<'any> {
  fn get<'rslt>(self, scratch: &'rslt [u8]) -> &'rslt [u8]
  where
    'any: 'rslt,
  {
    match self {
      Self::Borrowed(bytes) => bytes,
      Self::Scratch(start, end) => scratch.get(start..end).unwrap_or_default(),
    }
  }
}

/// See the module documentation.
#[derive(Debug)]
pub(crate) struct QpackDecoder {
  /// Blocked streams and the Required Insert Count that they wait for.
  blocked: VectorUsize<(u64, u64)>,
  /// Encoder-stream instructions left in this turn.
  budget: u64,
  /// The capacity that the encoder set, at most `max_capacity`.
  capacity: u64,
  /// Bytes that may still be copied out of the table in this turn.
  copy_budget: u64,
  entries: VectorUsize<Entry>,
  entries_head: usize,
  entries_len: usize,
  /// Identifies the table that this decoder holds since its last `new` or `reset`.
  epoch: u64,
  insert_count: u64,
  /// Inserts that the encoder knows of from what was queued on the decoder stream, apart from a
  /// trailing Insert Count Increment.
  known_received: u64,
  max_blocked: usize,
  max_capacity: u64,
  max_entries: u64,
  out: VectorUsize<u8>,
  out_start: usize,
  /// The Insert Count Increment at the end of `out`, if it was not written yet: where it starts
  /// and the insert count that it acknowledges. It is rewritten when more is acknowledged.
  pending_increment: Option<(usize, u64)>,
  ring: VectorUsize<u8>,
  ring_head: usize,
  ring_len: usize,
  size: u64,
  /// An insert is put together here before it goes into the ring.
  staging: VectorUsize<u8>,
}

impl QpackDecoder {
  /// A decoder for the advertised `SETTINGS_QPACK_MAX_TABLE_CAPACITY` of `capacity` and
  /// `SETTINGS_QPACK_BLOCKED_STREAMS` of `blocked_streams`. The table storage is allocated here,
  /// once: twice `capacity` bytes and 12 bytes per 32 of `capacity`.
  pub(crate) fn new(capacity: u32, blocked_streams: u16) -> crate::Result<Self> {
    let mut this = Self {
      blocked: VectorUsize::new(),
      budget: 0,
      capacity: 0,
      copy_budget: 0,
      entries: VectorUsize::new(),
      entries_head: 0,
      entries_len: 0,
      epoch: 0,
      insert_count: 0,
      known_received: 0,
      max_blocked: 0,
      max_capacity: 0,
      max_entries: 0,
      out: VectorUsize::new(),
      out_start: 0,
      pending_increment: None,
      ring: VectorUsize::new(),
      ring_head: 0,
      ring_len: 0,
      size: 0,
      staging: VectorUsize::new(),
    };
    this.reset(capacity, blocked_streams)?;
    Ok(this)
  }

  /// Makes this decoder a new one for the advertised `capacity` and `blocked_streams`, as
  /// [`Self::new`] does, in the storage that it has: nothing is allocated when the new limits are
  /// at most those that it had. The table gets a new epoch, so a memo filled from the old one
  /// replays nothing: first, so that a reset that fails part way, which the caller must not use
  /// again, never keeps the old epoch with storage partly cleared.
  pub(crate) fn reset(&mut self, capacity: u32, blocked_streams: u16) -> crate::Result<()> {
    self.epoch = EPOCHS.fetch_add(1, Ordering::Relaxed);
    let ring_len = *Usize::from(capacity);
    let max_entries = capacity / 32;
    self.blocked.clear();
    self.blocked.reserve(blocked_streams.into())?;
    self.entries.clear();
    self.entries.expand(ExpansionTy::Len(*Usize::from(max_entries)), Entry::default())?;
    self.out.clear();
    // Zeroed: no byte of the previous table stays
    self.ring.clear();
    self.ring.expand(ExpansionTy::Len(ring_len), 0)?;
    self.staging.clear();
    self.staging.reserve(ring_len)?;
    self.capacity = 0;
    self.entries_head = 0;
    self.entries_len = 0;
    self.insert_count = 0;
    self.known_received = 0;
    self.max_blocked = blocked_streams.into();
    self.max_capacity = capacity.into();
    self.max_entries = max_entries.into();
    self.out_start = 0;
    self.pending_increment = None;
    self.ring_head = 0;
    self.ring_len = 0;
    self.size = 0;
    self.start_turn();
    Ok(())
  }

  /// Inserts and duplications so far.
  #[inline]
  pub(crate) const fn insert_count(&self) -> u64 {
    self.insert_count
  }

  /// Applies the instructions of the encoder stream at the start of `bytes`.
  ///
  /// Returns the number of bytes consumed: an instruction that `bytes` does not hold whole is left
  /// for the caller to keep and give again with what follows it. An insert whose lengths already
  /// show that it does not fit fails at once, so what the caller keeps is bounded by about four
  /// times the capacity. Per turn ([`Self::start_turn`]) at most `2 * capacity / 32 + 64`
  /// instructions are applied and at most `4 * capacity` bytes copied out of the table by
  /// Duplicates and dynamic name references; more is an `H3_EXCESSIVE_LOAD`.
  pub(crate) fn on_encoder_stream(&mut self, bytes: &[u8]) -> crate::Result<usize> {
    let mut consumed = 0usize;
    while let Some(rest) = bytes.get(consumed..)
      && !rest.is_empty()
    {
      let Some(len) = self.encoder_instruction(rest)? else {
        break;
      };
      consumed = consumed.wrapping_add(len);
    }
    self.refresh_increment()?;
    Ok(consumed)
  }

  /// Decodes the field section `section` of `stream`, giving each field to `sink` in order.
  ///
  /// `scratch` holds the bytes of Huffman strings and of entries that wrap around the end of the
  /// ring, one field at a time; `sink` can stop the decoding with an error, which is returned as
  /// it is. A section that references the dynamic table queues its Section Acknowledgment. Errors
  /// of the section are a `QPACK_DECOMPRESSION_FAILED`.
  pub(crate) fn decode(
    &mut self,
    stream: u64,
    section: &[u8],
    scratch: &mut VectorUsize<u8>,
    sink: &mut dyn FnMut(&[u8], &[u8]) -> crate::Result<()>,
  ) -> crate::Result<DecodeOutcome> {
    let prefix = self.prefix(section)?;
    if prefix.ric > self.insert_count {
      return self.block(stream, prefix.ric);
    }
    self.unblock(stream);
    let _lowest = self.decode_lines(prefix, section, scratch, sink)?;
    self.finish(stream, prefix.ric)
  }

  /// [`Self::decode`] that replays the fields of a section kept in `memo`, or keeps the section
  /// once it is decoded. A replay has the effects of a decode: a stream that would block blocks,
  /// and the Section Acknowledgment is queued. `memo` is this decoder's: it replays only what was
  /// decoded against the table of this decoder since its last `new` or `reset`.
  pub(crate) fn decode_with_memo<const N: usize>(
    &mut self,
    memo: &mut DecodeMemo<N>,
    stream: u64,
    section: &[u8],
    scratch: &mut VectorUsize<u8>,
    sink: &mut dyn FnMut(&[u8], &[u8]) -> crate::Result<()>,
  ) -> crate::Result<DecodeOutcome> {
    let prefix = self.prefix(section)?;
    if prefix.ric > self.insert_count {
      return self.block(stream, prefix.ric);
    }
    self.unblock(stream);
    if let Some(fields) = memo.lookup(self.epoch, prefix.ric, section, self.oldest_live()) {
      for (name, value) in fields {
        sink(name, value)?;
      }
      return self.finish(stream, prefix.ric);
    }
    let mut recorder = memo.insert(self.epoch, prefix.ric, section);
    let lowest = self.decode_lines(prefix, section, scratch, &mut |name, value| {
      if let Some(elem) = &mut recorder {
        elem.push(name, value);
      }
      sink(name, value)
    })?;
    if let Some(elem) = recorder {
      elem.seal(lowest);
    }
    self.finish(stream, prefix.ric)
  }

  /// A stream was reset or its reading abandoned: queues a Stream Cancellation (RFC 9204 section
  /// 4.4.2) and forgets the stream if it is blocked. Without a dynamic table nothing is queued.
  pub(crate) fn on_stream_cancelled(&mut self, stream: u64) -> crate::Result<()> {
    self.unblock(stream);
    if self.max_capacity == 0 {
      return Ok(());
    }
    self.retract_increment();
    self.push_instruction(stream, 6, 0b0100_0000)?;
    self.refresh_increment()
  }

  /// The decoder-stream bytes that wait to be written: Section Acknowledgments, Stream
  /// Cancellations and at most one Insert Count Increment, at the end.
  #[inline]
  pub(crate) fn decoder_stream_output(&self) -> &[u8] {
    self.out.get(self.out_start..).unwrap_or_default()
  }

  /// Starts a receive turn of the connection: a new budget of encoder-stream instructions and of
  /// bytes copied out of the dynamic table. The connection calls it once per turn, before it feeds
  /// the encoder stream.
  pub(crate) fn start_turn(&mut self) {
    self.budget = Self::budget(self.max_entries);
    self.copy_budget = self.max_capacity.saturating_mul(COPY_BUDGET_CAPACITIES);
  }

  /// `n` bytes of [`Self::decoder_stream_output`] were written; it can be called any number of
  /// times.
  pub(crate) fn consume_decoder_output(&mut self, n: usize) {
    let len = self.out.len();
    self.out_start = self.out_start.saturating_add(n).min(len);
    if let Some((start, acknowledged)) = self.pending_increment
      && self.out_start > start
    {
      self.known_received = acknowledged;
      self.pending_increment = None;
    }
    if self.out_start == len {
      self.out.clear();
      self.out_start = 0;
    } else if self.out_start >= len / 2 {
      let start = self.out_start;
      self.out.as_slice_mut().copy_within(start.., 0);
      self.out.truncate(len.wrapping_sub(start));
      if let Some((pending, _)) = &mut self.pending_increment {
        *pending = pending.wrapping_sub(start);
      }
      self.out_start = 0;
    }
  }

  // Blocks `stream` on `ric`; a stream that blocks again keeps its slot.
  fn block(&mut self, stream: u64, ric: u64) -> crate::Result<DecodeOutcome> {
    if let Some(elem) = self.blocked.iter_mut().find(|el| el.0 == stream) {
      elem.1 = ric;
    } else {
      if self.blocked.len() >= self.max_blocked {
        cold_path();
        return Err(decompression_failed(Http3Error::TooManyBlockedStreams));
      }
      self.blocked.push((stream, ric))?;
    }
    Ok(DecodeOutcome::Blocked { required_insert_count: ric })
  }

  const fn budget(max_entries: u64) -> u64 {
    max_entries.saturating_mul(2).saturating_add(INSTRUCTION_BUDGET_BASE)
  }

  // Copies the referenced part of the byte ring into `scratch` if it wraps around the end.
  fn ring_part<'this>(
    &'this self,
    start: usize,
    len: usize,
    scratch: &mut VectorUsize<u8>,
  ) -> crate::Result<Part<'this>> {
    let (first, second) = ring_slices(&self.ring, start, len);
    if second.is_empty() {
      return Ok(Part::Borrowed(first));
    }
    let begin = scratch.len();
    scratch.extend_from_copyable_slices([first, second])?;
    Ok(Part::Scratch(begin, scratch.len()))
  }

  // The entry of absolute index `abs`, if it is in the table.
  fn entry(&self, abs: u64) -> Option<Entry> {
    let offset = abs.checked_sub(self.oldest_live())?;
    if abs >= self.insert_count {
      return None;
    }
    let slot = self.entries_head.wrapping_add(usize::try_from(offset).ok()?);
    self.entries.get(slot.checked_rem(self.entries.len())?).copied()
  }

  // The entry of the absolute index of a reference in a field section, which must be below the
  // Required Insert Count and not evicted.
  fn section_entry(&self, prefix: Prefix, abs: Option<u64>) -> crate::Result<(u64, Entry)> {
    if let Some(abs) = abs
      && abs < prefix.ric
      && let Some(entry) = self.entry(abs)
    {
      return Ok((abs, entry));
    }
    cold_path();
    Err(decompression_failed(Http3Error::InvalidDynamicIndex))
  }

  fn decode_lines<'this>(
    &'this self,
    prefix: Prefix,
    section: &'this [u8],
    scratch: &mut VectorUsize<u8>,
    sink: &mut dyn FnMut(&[u8], &[u8]) -> crate::Result<()>,
  ) -> crate::Result<u64> {
    let mut lowest = u64::MAX;
    let mut highest = None;
    let mut rest = section.get(prefix.lines..).unwrap_or_default();
    while let [first, ..] = rest {
      let first = *first;
      scratch.clear();
      let mut track = |abs: u64| {
        lowest = lowest.min(abs);
        highest = highest.max(Some(abs));
      };
      let (name, value, len) = if first & 0b1000_0000 != 0 {
        // Indexed Field Line (RFC 9204 section 4.5.2)
        let (idx, len) = section_int(rest, 6)?;
        if first & 0b0100_0000 != 0 {
          let (name, value) = static_entry(idx)?;
          (Part::Borrowed(name), Part::Borrowed(value), len)
        } else {
          let (abs, entry) = self.section_entry(prefix, relative(prefix.base, idx))?;
          track(abs);
          let (name, value) = self.entry_parts(entry, scratch)?;
          (name, value, len)
        }
      } else if first & 0b0100_0000 != 0 {
        // Literal Field Line with Name Reference (section 4.5.4)
        let (idx, idx_len) = section_int(rest, 4)?;
        let name = if first & 0b0001_0000 != 0 {
          Part::Borrowed(static_entry(idx)?.0)
        } else {
          let (abs, entry) = self.section_entry(prefix, relative(prefix.base, idx))?;
          track(abs);
          self.ring_part(*Usize::from(entry.start), *Usize::from(entry.name_len), scratch)?
        };
        let (value, value_len) =
          section_string(rest.get(idx_len..).unwrap_or_default(), 8, scratch)?;
        (name, value, idx_len.wrapping_add(value_len))
      } else if first & 0b0010_0000 != 0 {
        // Literal Field Line with Literal Name (section 4.5.6)
        let (name, name_len) = section_string(rest, 4, scratch)?;
        let (value, value_len) =
          section_string(rest.get(name_len..).unwrap_or_default(), 8, scratch)?;
        (name, value, name_len.wrapping_add(value_len))
      } else if first & 0b0001_0000 != 0 {
        // Indexed Field Line with Post-Base Index (section 4.5.3)
        let (idx, len) = section_int(rest, 4)?;
        let (abs, entry) = self.section_entry(prefix, prefix.base.checked_add(idx))?;
        track(abs);
        let (name, value) = self.entry_parts(entry, scratch)?;
        (name, value, len)
      } else {
        // Literal Field Line with Post-Base Name Reference (section 4.5.5)
        let (idx, idx_len) = section_int(rest, 3)?;
        let (abs, entry) = self.section_entry(prefix, prefix.base.checked_add(idx))?;
        track(abs);
        let name =
          self.ring_part(*Usize::from(entry.start), *Usize::from(entry.name_len), scratch)?;
        let (value, value_len) =
          section_string(rest.get(idx_len..).unwrap_or_default(), 8, scratch)?;
        (name, value, idx_len.wrapping_add(value_len))
      };
      let bytes = scratch.as_slice();
      sink(name.get(bytes), value.get(bytes))?;
      rest = rest.get(len..).unwrap_or_default();
    }
    // The Required Insert Count must be the one that the references need (section 2.2.1)
    let needed = highest.map_or(0, |el: u64| el.wrapping_add(1));
    if needed != prefix.ric {
      cold_path();
      return Err(decompression_failed(Http3Error::RequiredInsertCountTooLarge));
    }
    Ok(lowest)
  }

  // Applies the encoder instruction at the start of `bytes`, if it is whole.
  fn encoder_instruction(&mut self, bytes: &[u8]) -> crate::Result<Option<usize>> {
    let Some(first) = bytes.first().copied() else {
      return Ok(None);
    };
    if first & 0b1000_0000 != 0 {
      // Insert with Name Reference (RFC 9204 section 4.3.2)
      let Some((idx, idx_len)) = encoder_int(bytes, 6)? else {
        return Ok(None);
      };
      let name_len = if first & 0b0100_0000 != 0 {
        static_name(idx)?.len()
      } else {
        *Usize::from(self.encoder_entry(idx)?.name_len)
      };
      let value_bytes = bytes.get(idx_len..).unwrap_or_default();
      let Some((value, value_len)) = self.encoder_string(value_bytes, 8, name_len)? else {
        return Ok(None);
      };
      self.spend_budget(if first & 0b0100_0000 != 0 { 0 } else { name_len })?;
      self.staging.clear();
      if first & 0b0100_0000 != 0 {
        self.staging.extend_from_copyable_slice(static_name(idx)?)?;
      } else {
        let entry = self.encoder_entry(idx)?;
        self.stage_ring(*Usize::from(entry.start), *Usize::from(entry.name_len))?;
      }
      self.stage_string(value)?;
      self.insert(name_len)?;
      Ok(Some(idx_len.wrapping_add(value_len)))
    } else if first & 0b0100_0000 != 0 {
      // Insert with Literal Name (section 4.3.3)
      let Some((name, name_len)) = self.encoder_string(bytes, 6, 0)? else {
        return Ok(None);
      };
      let name_min = string_min_len(name);
      let value_bytes = bytes.get(name_len..).unwrap_or_default();
      let Some((value, value_len)) = self.encoder_string(value_bytes, 8, name_min)? else {
        return Ok(None);
      };
      self.spend_budget(0)?;
      self.staging.clear();
      self.stage_string(name)?;
      let staged_name_len = self.staging.len();
      self.stage_string(value)?;
      self.insert(staged_name_len)?;
      Ok(Some(name_len.wrapping_add(value_len)))
    } else if first & 0b0010_0000 != 0 {
      // Set Dynamic Table Capacity (section 4.3.1)
      let Some((capacity, len)) = encoder_int(bytes, 5)? else {
        return Ok(None);
      };
      if capacity > self.max_capacity {
        cold_path();
        return Err(encoder_stream_error(Http3Error::CapacityAboveMaximum));
      }
      self.spend_budget(0)?;
      self.capacity = capacity;
      self.evict_down_to(capacity);
      Ok(Some(len))
    } else {
      // Duplicate (section 4.3.4)
      let Some((idx, len)) = encoder_int(bytes, 5)? else {
        return Ok(None);
      };
      let entry = self.encoder_entry(idx)?;
      let name_len = *Usize::from(entry.name_len);
      let len_copied = name_len.wrapping_add(*Usize::from(entry.value_len));
      self.spend_budget(len_copied)?;
      self.staging.clear();
      self.stage_ring(*Usize::from(entry.start), len_copied)?;
      self.insert(name_len)?;
      Ok(Some(len))
    }
  }

  // The entry of a relative index of the encoder stream, counted back from the last insert.
  fn encoder_entry(&self, idx: u64) -> crate::Result<Entry> {
    if let Some(abs) = relative(self.insert_count, idx)
      && let Some(entry) = self.entry(abs)
    {
      return Ok(entry);
    }
    cold_path();
    Err(encoder_stream_error(Http3Error::InvalidDynamicIndex))
  }

  // Reads the string literal at the start of `bytes`, if it is whole, after checking that an
  // entry whose other parts take at least `taken` bytes can still hold it.
  fn encoder_string<'bytes>(
    &self,
    bytes: &'bytes [u8],
    prefix_bits: u8,
    taken: usize,
  ) -> crate::Result<Option<(StringLiteral<'bytes>, usize)>> {
    let Some(first) = bytes.first().copied() else {
      return Ok(None);
    };
    let Some((len, header_len)) = encoder_int(bytes, prefix_bits.wrapping_sub(1))? else {
      return Ok(None);
    };
    let huffman = first & (1 << prefix_bits.wrapping_sub(1)) != 0;
    let min_len = if huffman { huffman_min_len(len) } else { len };
    let min_size = min_len
      .saturating_add(u64::try_from(taken).unwrap_or(u64::MAX))
      .saturating_add(ENTRY_OVERHEAD);
    if min_size > self.capacity {
      cold_path();
      return Err(encoder_stream_error(Http3Error::EntryTooLarge));
    }
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    let Some(data) = bytes.get(header_len..).and_then(|el| el.get(..len)) else {
      return Ok(None);
    };
    Ok(Some((StringLiteral { data, huffman }, header_len.wrapping_add(len))))
  }

  // Inserts the entry in `staging`, whose first `name_len` bytes are the name, evicting what it
  // needs (RFC 9204 section 3.2.2).
  fn insert(&mut self, name_len: usize) -> crate::Result<()> {
    let bytes_len = self.staging.len();
    let size = u64::try_from(bytes_len).unwrap_or(u64::MAX).saturating_add(ENTRY_OVERHEAD);
    if size > self.capacity {
      cold_path();
      return Err(encoder_stream_error(Http3Error::EntryTooLarge));
    }
    self.evict_down_to(self.capacity.wrapping_sub(size));
    // The ring has room: what the table holds is at most capacity - size - 32 per entry
    let ring_capacity = self.ring.len();
    let tail = self.ring_head.wrapping_add(self.ring_len).checked_rem(ring_capacity).unwrap_or(0);
    let Self { ring, staging, .. } = self;
    let first_len = bytes_len.min(ring_capacity.wrapping_sub(tail));
    let (first, second) = staging.as_slice().split_at_checked(first_len).unwrap_or_default();
    if let Some(dst) = ring.get_mut(tail..tail.wrapping_add(first_len)) {
      dst.copy_from_slice(first);
    }
    if let Some(dst) = ring.get_mut(..second.len()) {
      dst.copy_from_slice(second);
    }
    let slot = self.entries_head.wrapping_add(self.entries_len).checked_rem(self.entries.len());
    let Some(elem) = slot.and_then(|el| self.entries.get_mut(el)) else {
      cold_path();
      return Err(encoder_stream_error(Http3Error::EntryTooLarge));
    };
    *elem = Entry {
      name_len: u32::try_from(name_len).unwrap_or(u32::MAX),
      start: u32::try_from(tail).unwrap_or(u32::MAX),
      value_len: u32::try_from(bytes_len.wrapping_sub(name_len)).unwrap_or(u32::MAX),
    };
    self.entries_len = self.entries_len.wrapping_add(1);
    self.ring_len = self.ring_len.wrapping_add(bytes_len);
    self.size = self.size.wrapping_add(size);
    self.insert_count = self.insert_count.wrapping_add(1);
    Ok(())
  }

  // Evicts the oldest entries until the size of the table is at most `size`.
  fn evict_down_to(&mut self, size: u64) {
    while self.size > size {
      let Some(entry) = self.entries.get(self.entries_head).copied() else {
        break;
      };
      let bytes_len = (*Usize::from(entry.name_len)).wrapping_add(*Usize::from(entry.value_len));
      self.ring_head =
        self.ring_head.wrapping_add(bytes_len).checked_rem(self.ring.len()).unwrap_or(0);
      self.ring_len = self.ring_len.wrapping_sub(bytes_len);
      self.entries_head =
        self.entries_head.wrapping_add(1).checked_rem(self.entries.len()).unwrap_or(0);
      self.entries_len = self.entries_len.wrapping_sub(1);
      self.size = self.size.wrapping_sub(entry.size());
    }
  }

  // The name and the value of `entry`.
  fn entry_parts<'this>(
    &'this self,
    entry: Entry,
    scratch: &mut VectorUsize<u8>,
  ) -> crate::Result<(Part<'this>, Part<'this>)> {
    let name_len = *Usize::from(entry.name_len);
    let start = *Usize::from(entry.start);
    let name = self.ring_part(start, name_len, scratch)?;
    let value_start = start.wrapping_add(name_len).checked_rem(self.ring.len()).unwrap_or(0);
    let value = self.ring_part(value_start, *Usize::from(entry.value_len), scratch)?;
    Ok((name, value))
  }

  fn finish(&mut self, stream: u64, ric: u64) -> crate::Result<DecodeOutcome> {
    if ric > 0 {
      // Section Acknowledgment (RFC 9204 section 4.4.1)
      self.retract_increment();
      self.push_instruction(stream, 7, 0b1000_0000)?;
      self.known_received = self.known_received.max(ric);
      self.refresh_increment()?;
    }
    Ok(DecodeOutcome::Done { referenced_dynamic: ric > 0 })
  }

  fn oldest_live(&self) -> u64 {
    self.insert_count.wrapping_sub(u64::try_from(self.entries_len).unwrap_or(u64::MAX))
  }

  fn prefix(&self, section: &[u8]) -> crate::Result<Prefix> {
    let (encoded, ric_len) = section_int(section, 8)?;
    let Some(ric) = decode_required_insert_count(encoded, self.max_entries, self.insert_count)
    else {
      cold_path();
      return Err(decompression_failed(Http3Error::InvalidRequiredInsertCount));
    };
    let rest = section.get(ric_len..).unwrap_or_default();
    let (delta, delta_len) = section_int(rest, 7)?;
    let base = if rest.first().is_some_and(|el| el & 0b1000_0000 != 0) {
      // A Sign of 1 with Delta Base >= Required Insert Count is a negative Base
      ric.checked_sub(delta).and_then(|el| el.checked_sub(1))
    } else {
      ric.checked_add(delta)
    };
    let Some(base) = base else {
      cold_path();
      return Err(decompression_failed(Http3Error::InvalidBase));
    };
    Ok(Prefix { base, lines: ric_len.wrapping_add(delta_len), ric })
  }

  fn push_instruction(&mut self, value: u64, prefix_bits: u8, flags: u8) -> crate::Result<()> {
    let mut buffer = [0u8; 10];
    let Some(len) = encode_prefix_int(value, prefix_bits, flags, &mut buffer) else {
      cold_path();
      return Err(crate::Error::Http3(Http3Error::IntegerOverflow));
    };
    if self.out.len().wrapping_sub(self.out_start).wrapping_add(len) > MAX_PENDING_OUTPUT {
      cold_path();
      return Err(crate::Error::Http3Close(
        H3ErrorCode::ExcessiveLoad,
        Http3Error::DecoderStreamBacklog,
      ));
    }
    self.out.extend_from_copyable_slice(buffer.get(..len).unwrap_or_default())?;
    Ok(())
  }

  // Queues an Insert Count Increment (RFC 9204 section 4.4.3) for the inserts that nothing queued
  // acknowledges, in place of the one that waits at the end of the output.
  fn refresh_increment(&mut self) -> crate::Result<()> {
    self.retract_increment();
    if self.insert_count > self.known_received {
      let start = self.out.len();
      self.push_instruction(self.insert_count.wrapping_sub(self.known_received), 6, 0)?;
      self.pending_increment = Some((start, self.insert_count));
    }
    Ok(())
  }

  fn retract_increment(&mut self) {
    if let Some((start, _)) = self.pending_increment.take() {
      self.out.truncate(start);
    }
  }

  // One instruction of the turn's budget, which copies `copied` bytes out of the table.
  fn spend_budget(&mut self, copied: usize) -> crate::Result<()> {
    let copied = u64::try_from(copied).unwrap_or(u64::MAX);
    let (Some(budget), Some(copy_budget)) =
      (self.budget.checked_sub(1), self.copy_budget.checked_sub(copied))
    else {
      cold_path();
      return Err(crate::Error::Http3Close(
        H3ErrorCode::ExcessiveLoad,
        Http3Error::EncoderInstructionBudget,
      ));
    };
    self.budget = budget;
    self.copy_budget = copy_budget;
    Ok(())
  }

  // Appends `len` bytes of the ring at `start` to `staging`.
  fn stage_ring(&mut self, start: usize, len: usize) -> crate::Result<()> {
    let Self { ring, staging, .. } = self;
    let (first, second) = ring_slices(ring, start, len);
    let _ = staging.extend_from_copyable_slices([first, second])?;
    Ok(())
  }

  // Appends a string literal of the encoder stream to `staging`, decoded if it is Huffman coded;
  // the entry must still fit in the capacity.
  fn stage_string(&mut self, string: StringLiteral<'_>) -> crate::Result<()> {
    let room = usize::try_from(self.capacity.saturating_sub(ENTRY_OVERHEAD))
      .unwrap_or(usize::MAX)
      .saturating_sub(self.staging.len());
    if !string.huffman {
      if string.data.len() > room {
        cold_path();
        return Err(encoder_stream_error(Http3Error::EntryTooLarge));
      }
      self.staging.extend_from_copyable_slice(string.data)?;
      return Ok(());
    }
    // `staging` has the capacity of the ring, which `room` does not exceed: nothing grows
    let start = self.staging.len();
    let mut appender = Appender { limit: room, overflowed: false, start, vec: &mut self.staging };
    if huffman_decode(string.data, &mut appender).is_err() {
      cold_path();
      let error =
        if appender.overflowed { Http3Error::EntryTooLarge } else { Http3Error::InvalidHuffman };
      return Err(encoder_stream_error(error));
    }
    Ok(())
  }

  fn unblock(&mut self, stream: u64) {
    if let Some(idx) = self.blocked.iter().position(|el| el.0 == stream) {
      let _ = self.blocked.swap_remove(idx);
    }
  }

  /// Panics if the table, the blocked streams or the decoder-stream output are not consistent.
  #[cfg(any(test, feature = "_fuzz"))]
  pub(crate) fn check_invariants(&self) {
    assert!(self.capacity <= self.max_capacity);
    assert!(self.size <= self.capacity);
    assert!(u64::try_from(self.entries_len).unwrap() <= self.max_entries);
    assert!(self.blocked.len() <= self.max_blocked);
    assert!(self.oldest_live() <= self.insert_count);
    assert!(self.known_received <= self.insert_count);
    assert!(self.decoder_stream_output().len() <= MAX_PENDING_OUTPUT);
    if let Some((start, acknowledged)) = self.pending_increment {
      assert!(start >= self.out_start && start < self.out.len());
      assert_eq!(acknowledged, self.insert_count);
    } else {
      assert_eq!(self.known_received, self.insert_count);
    }
    // The entries follow each other in the ring from its head, and account for its bytes and the
    // size of the table
    let (mut size, mut bytes, mut next) = (0u64, 0usize, self.ring_head);
    for abs in self.oldest_live()..self.insert_count {
      let entry = self.entry(abs).unwrap();
      assert_eq!(*Usize::from(entry.start), next);
      let len = (*Usize::from(entry.name_len)).wrapping_add(*Usize::from(entry.value_len));
      next = next.wrapping_add(len).checked_rem(self.ring.len()).unwrap_or(0);
      size = size.wrapping_add(entry.size());
      bytes = bytes.wrapping_add(len);
    }
    assert_eq!(size, self.size);
    assert_eq!(bytes, self.ring_len);
    assert!(self.ring_len <= self.ring.len());
  }
}

/// The absolute Required Insert Count of `encoded` (RFC 9204 section 4.5.1.1), for a table of
/// `max_entries` that had `total_inserts`; `None` for a value that no conformant encoder produces.
pub(crate) fn decode_required_insert_count(
  encoded: u64,
  max_entries: u64,
  total_inserts: u64,
) -> Option<u64> {
  if encoded == 0 {
    return Some(0);
  }
  let full_range = max_entries.checked_mul(2)?;
  if encoded > full_range {
    return None;
  }
  let max_value = total_inserts.checked_add(max_entries)?;
  let max_wrapped = max_value.checked_div(full_range)?.checked_mul(full_range)?;
  let mut ric = max_wrapped.checked_add(encoded)?.checked_sub(1)?;
  if ric > max_value {
    if ric <= full_range {
      return None;
    }
    ric = ric.wrapping_sub(full_range);
  }
  if ric == 0 {
    return None;
  }
  Some(ric)
}

/// Appends Huffman output after the bytes that are already in `vec`, up to `limit` bytes.
struct Appender<'vec> {
  limit: usize,
  overflowed: bool,
  start: usize,
  vec: &'vec mut VectorUsize<u8>,
}

impl Clear for Appender<'_> {
  #[inline]
  fn clear(&mut self) {
    self.vec.truncate(self.start);
  }
}

impl Lease<[u8]> for Appender<'_> {
  #[inline]
  fn lease(&self) -> &[u8] {
    self.vec.get(self.start..).unwrap_or_default()
  }
}

impl SingleTypeStorage for Appender<'_> {
  type Item = u8;
}

impl TryExtend<[u8; 1]> for Appender<'_> {
  #[inline]
  fn try_extend(&mut self, set: [u8; 1]) -> crate::Result<()> {
    if self.vec.len().wrapping_sub(self.start) >= self.limit {
      cold_path();
      self.overflowed = true;
      return Err(crate::Error::Http3(Http3Error::HuffmanOutputTooLong));
    }
    self.vec.extend_from_copyable_slice(&set)?;
    Ok(())
  }
}

/// A string literal of the wire, with its Huffman bit.
#[derive(Clone, Copy, Debug)]
struct StringLiteral<'bytes> {
  data: &'bytes [u8],
  huffman: bool,
}

#[cold]
fn decompression_failed(error: Http3Error) -> crate::Error {
  crate::Error::Http3Close(H3ErrorCode::QpackDecompressionFailed, error)
}

#[cold]
fn encoder_stream_error(error: Http3Error) -> crate::Error {
  crate::Error::Http3Close(H3ErrorCode::QpackEncoderStreamError, error)
}

// A prefixed integer of the encoder stream: `None` if it is not whole.
fn encoder_int(bytes: &[u8], prefix_bits: u8) -> crate::Result<Option<(u64, usize)>> {
  decode_prefix_int(bytes, prefix_bits)
    .map_err(|_err| encoder_stream_error(Http3Error::IntegerOverflow))
}

// The fewest bytes that a Huffman string of `len` bytes decodes to: the longest code has 30 bits
// and the padding at most 7.
fn huffman_min_len(len: u64) -> u64 {
  len.saturating_mul(8).saturating_sub(7) / 30
}

// The `len` bytes at `start` of the byte ring, in one or two slices.
fn ring_slices(ring: &[u8], start: usize, len: usize) -> (&[u8], &[u8]) {
  let first_len = len.min(ring.len().saturating_sub(start));
  let first = ring.get(start..start.wrapping_add(first_len)).unwrap_or_default();
  let second = ring.get(..len.wrapping_sub(first_len)).unwrap_or_default();
  (first, second)
}

// The index `idx` relative to `base`, counted back from it (RFC 9204 section 3.2.5).
fn relative(base: u64, idx: u64) -> Option<u64> {
  base.checked_sub(idx)?.checked_sub(1)
}

// A prefixed integer of a field section, which is whole: one that ends early is an error.
fn section_int(bytes: &[u8], prefix_bits: u8) -> crate::Result<(u64, usize)> {
  match decode_prefix_int(bytes, prefix_bits) {
    Ok(Some(elem)) => Ok(elem),
    Ok(None) => Err(decompression_failed(Http3Error::Truncated)),
    Err(_err) => Err(decompression_failed(Http3Error::IntegerOverflow)),
  }
}

// The string literal at the start of `bytes` (RFC 9204 section 4.1.2): raw, it is borrowed;
// Huffman coded, it is decoded at the end of `scratch`, which grows by at most 8/5 of it.
fn section_string<'bytes>(
  bytes: &'bytes [u8],
  prefix_bits: u8,
  scratch: &mut VectorUsize<u8>,
) -> crate::Result<(Part<'bytes>, usize)> {
  let huffman = bytes.first().is_some_and(|el| el & (1 << prefix_bits.wrapping_sub(1)) != 0);
  let (len, header_len) = section_int(bytes, prefix_bits.wrapping_sub(1))?;
  let Some(data) =
    usize::try_from(len).ok().and_then(|len| bytes.get(header_len..).and_then(|el| el.get(..len)))
  else {
    cold_path();
    return Err(decompression_failed(Http3Error::Truncated));
  };
  let total = header_len.wrapping_add(data.len());
  if !huffman {
    return Ok((Part::Borrowed(data), total));
  }
  // The shortest code has 5 bits
  let limit = data.len().saturating_mul(8) / 5;
  scratch.reserve(limit)?;
  let start = scratch.len();
  if huffman_decode(data, &mut Appender { limit, overflowed: false, start, vec: scratch }).is_err()
  {
    cold_path();
    return Err(decompression_failed(Http3Error::InvalidHuffman));
  }
  Ok((Part::Scratch(start, scratch.len()), total))
}

fn static_entry(idx: u64) -> crate::Result<(&'static [u8], &'static [u8])> {
  if let Some(elem) = usize::try_from(idx).ok().and_then(|el| STATIC_TABLE.get(el)) {
    return Ok(*elem);
  }
  cold_path();
  Err(decompression_failed(Http3Error::InvalidStaticIndex))
}

fn static_name(idx: u64) -> crate::Result<&'static [u8]> {
  if let Some(elem) = usize::try_from(idx).ok().and_then(|el| STATIC_TABLE.get(el)) {
    return Ok(elem.0);
  }
  cold_path();
  Err(encoder_stream_error(Http3Error::InvalidStaticIndex))
}

// A lower bound of the decoded length of a string literal.
fn string_min_len(string: StringLiteral<'_>) -> usize {
  let len = u64::try_from(string.data.len()).unwrap_or(u64::MAX);
  let min = if string.huffman { huffman_min_len(len) } else { len };
  usize::try_from(min).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
  use crate::{
    Error,
    collections::VectorUsize,
    http3::{
      H3ErrorCode, Http3Error,
      qpack::{DecodeMemo, DecodeOutcome, QpackDecoder, decoder::decode_required_insert_count},
      qpack_check::wire,
    },
    sync::AtomicU64,
    tests::_count_allocations_in,
  };
  use alloc::vec::Vec;
  use core::sync::atomic::Ordering;

  type Fields = Vec<(Vec<u8>, Vec<u8>)>;

  // RFC 9204 Appendix B, in order
  const B2_ENCODER: [u8; 34] =
    hexd!(b"3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468");
  const B2_STREAM_4: [u8; 4] = hexd!(b"03811011");
  const B3_ENCODER: [u8; 24] = hexd!(b"4a637573746f6d2d6b65790c637573746f6d2d76616c7565");
  const B4_ENCODER: [u8; 1] = hexd!(b"02");
  const B4_STREAM_8: [u8; 5] = hexd!(b"050080c181");
  const B5_ENCODER: [u8; 15] = hexd!(b"810d637573746f6d2d76616c756532");

  const DONE_DYNAMIC: DecodeOutcome = DecodeOutcome::Done { referenced_dynamic: true };
  const DONE_STATIC: DecodeOutcome = DecodeOutcome::Done { referenced_dynamic: false };

  fn decode(
    decoder: &mut QpackDecoder,
    stream: u64,
    section: &[u8],
  ) -> crate::Result<(DecodeOutcome, Fields)> {
    let mut scratch = VectorUsize::new();
    let mut fields = Vec::new();
    let outcome = decoder.decode(stream, section, &mut scratch, &mut |name, value| {
      fields.push((name.to_vec(), value.to_vec()));
      Ok(())
    })?;
    Ok((outcome, fields))
  }

  fn fails(rslt: crate::Result<impl Sized>, code: H3ErrorCode, error: Http3Error) -> bool {
    matches!(rslt, Err(Error::Http3Close(el, err)) if el == code && err == error)
  }

  fn failed(rslt: crate::Result<(DecodeOutcome, Fields)>, error: Http3Error) -> bool {
    fails(rslt, H3ErrorCode::QpackDecompressionFailed, error)
  }

  fn refused(rslt: crate::Result<usize>, error: Http3Error) -> bool {
    fails(rslt, H3ErrorCode::QpackEncoderStreamError, error)
  }

  fn output(decoder: &mut QpackDecoder) -> Vec<u8> {
    let out = decoder.decoder_stream_output().to_vec();
    decoder.consume_decoder_output(out.len());
    out
  }

  fn pairs(list: &[(&str, &str)]) -> Fields {
    list.iter().map(|(name, value)| (name.as_bytes().to_vec(), value.as_bytes().to_vec())).collect()
  }

  fn after_b2() -> QpackDecoder {
    let mut decoder = QpackDecoder::new(220, 2).unwrap();
    assert_eq!(decoder.on_encoder_stream(&B2_ENCODER).unwrap(), B2_ENCODER.len());
    assert_eq!(decode(&mut decoder, 4, &B2_STREAM_4).unwrap().0, DONE_DYNAMIC);
    assert_eq!(output(&mut decoder), [0x84]);
    decoder
  }

  fn after_b3() -> QpackDecoder {
    let mut decoder = after_b2();
    assert_eq!(decoder.on_encoder_stream(&B3_ENCODER).unwrap(), B3_ENCODER.len());
    assert_eq!(output(&mut decoder), [0x01]);
    decoder
  }

  fn after_b4() -> QpackDecoder {
    let mut decoder = after_b3();
    assert_eq!(decoder.on_encoder_stream(&B4_ENCODER).unwrap(), 1);
    assert_eq!(output(&mut decoder), [0x01]);
    decoder
  }

  #[test]
  fn rfc9204_appendix_b1_literal_with_name_reference() {
    let mut decoder = QpackDecoder::new(220, 0).unwrap();
    let section = hexd!(b"0000510b2f696e6465782e68746d6c");
    assert_eq!(
      decode(&mut decoder, 0, &section).unwrap(),
      (DONE_STATIC, pairs(&[(":path", "/index.html")]))
    );
    // Required Insert Count 0: nothing to acknowledge
    assert_eq!(decoder.decoder_stream_output(), b"");
  }

  #[test]
  fn rfc9204_appendix_b2_dynamic_table_and_section_ack() {
    let mut decoder = QpackDecoder::new(220, 2).unwrap();
    assert_eq!(decoder.on_encoder_stream(&B2_ENCODER).unwrap(), B2_ENCODER.len());
    assert_eq!(decoder.insert_count(), 2);
    assert_eq!(decoder.size, 106);
    assert_eq!(decoder.capacity, 220);
    // Until a section acknowledges them, the inserts wait for an Insert Count Increment
    assert_eq!(decoder.decoder_stream_output(), [0x02]);
    let expected = pairs(&[(":authority", "www.example.com"), (":path", "/sample/path")]);
    assert_eq!(decode(&mut decoder, 4, &B2_STREAM_4).unwrap(), (DONE_DYNAMIC, expected));
    // The Section Acknowledgment covers them: it replaces the increment (RFC 9204 2.1.4, 4.4.3)
    assert_eq!(output(&mut decoder), [0x84]);
    assert_eq!(decoder.known_received, 2);
    assert_eq!(decoder.decoder_stream_output(), b"");
  }

  #[test]
  fn rfc9204_appendix_b3_speculative_insert() {
    let mut decoder = after_b2();
    // An instruction that is not whole is left to the caller
    let (head, _) = B3_ENCODER.split_at(13);
    assert_eq!(decoder.on_encoder_stream(head).unwrap(), 0);
    assert_eq!(decoder.insert_count(), 2);
    assert_eq!(decoder.on_encoder_stream(&B3_ENCODER).unwrap(), B3_ENCODER.len());
    assert_eq!(decoder.insert_count(), 3);
    assert_eq!(decoder.size, 160);
    // Nothing references it: an Insert Count Increment of 1
    assert_eq!(output(&mut decoder), [0x01]);
    assert_eq!(decoder.known_received, 3);
  }

  #[test]
  fn rfc9204_appendix_b4_duplicate_instruction() {
    let mut decoder = after_b3();
    // The section arrives before the duplicate that it references: the stream blocks
    assert_eq!(
      decode(&mut decoder, 8, &B4_STREAM_8).unwrap(),
      (DecodeOutcome::Blocked { required_insert_count: 4 }, Vec::new())
    );
    assert_eq!(decoder.blocked.len(), 1);
    // The stream is cancelled before the duplicate arrives
    decoder.on_stream_cancelled(8).unwrap();
    assert_eq!(output(&mut decoder), [0x48]);
    assert_eq!(decoder.blocked.len(), 0);
    // Duplicate of relative index 2: absolute index 0 again, as absolute index 3
    assert_eq!(decoder.on_encoder_stream(&B4_ENCODER).unwrap(), 1);
    assert_eq!(decoder.insert_count(), 4);
    assert_eq!(decoder.size, 217);
    assert_eq!(output(&mut decoder), [0x01]);
    // The same section, on another stream, now decodes
    let expected =
      pairs(&[(":authority", "www.example.com"), (":path", "/"), ("custom-key", "custom-value")]);
    assert_eq!(decode(&mut decoder, 12, &B4_STREAM_8).unwrap(), (DONE_DYNAMIC, expected));
    assert_eq!(output(&mut decoder), [0x8c]);
  }

  #[test]
  fn rfc9204_appendix_b5_insert_evicts_the_oldest_entry() {
    let mut decoder = after_b4();
    // custom-key=custom-value2 by the name of relative index 1 (absolute 2): 57 bytes evicted
    assert_eq!(decoder.on_encoder_stream(&B5_ENCODER).unwrap(), B5_ENCODER.len());
    assert_eq!(decoder.insert_count(), 5);
    assert_eq!(decoder.size, 215);
    assert_eq!(output(&mut decoder), [0x01]);
    // Absolute index 4 decodes; absolute index 0 is gone
    let mut newest = Vec::new();
    wire::prefix(&mut newest, 5, 5, 6);
    wire::indexed(&mut newest, false, 0);
    wire::indexed(&mut newest, false, 3);
    assert_eq!(
      decode(&mut decoder, 16, &newest).unwrap(),
      (DONE_DYNAMIC, pairs(&[("custom-key", "custom-value2"), (":path", "/sample/path")]))
    );
    assert!(failed(decode(&mut decoder, 20, &hexd!(b"020080")), Http3Error::InvalidDynamicIndex));
  }

  #[test]
  fn required_insert_count_wraps_per_rfc9204_section_4_5_1_1() {
    // The example of the RFC: a table of 100 bytes, 10 inserts, an encoded 4
    assert_eq!(decode_required_insert_count(4, 3, 10), Some(9));
    assert_eq!(decode_required_insert_count(0, 3, 10), Some(0));
    assert_eq!(decode_required_insert_count(0, 0, 0), Some(0));
    // Values that no encoder produces
    assert_eq!(decode_required_insert_count(7, 3, 10), None);
    assert_eq!(decode_required_insert_count(1, 0, 0), None);
    assert_eq!(decode_required_insert_count(1, 3, 0), None);
    assert_eq!(decode_required_insert_count(5, 3, 0), None);
    // Every count that an encoder can send, encoded as an encoder does, comes back
    for max_entries in [1u64, 3, 6, 128] {
      for total in 0..200u64 {
        let low = total.saturating_sub(max_entries - 1).max(1);
        for ric in low..=total + max_entries {
          let encoded = ric % (2 * max_entries) + 1;
          assert_eq!(decode_required_insert_count(encoded, max_entries, total), Some(ric));
        }
      }
    }
  }

  #[test]
  fn blocked_stream_resumes_after_insert() {
    let mut decoder = QpackDecoder::new(4096, 1).unwrap();
    let mut encoder = Vec::new();
    wire::set_capacity(&mut encoder, 4096);
    assert_eq!(decoder.on_encoder_stream(&encoder).unwrap(), encoder.len());
    // A section that references the first insert, before it arrives
    let mut section = Vec::new();
    wire::prefix(&mut section, 1, 1, 128);
    wire::indexed(&mut section, false, 0);
    wire::indexed(&mut section, true, 17);
    assert_eq!(
      decode(&mut decoder, 0, &section).unwrap(),
      (DecodeOutcome::Blocked { required_insert_count: 1 }, Vec::new())
    );
    // Decoding it again before the insert keeps one blocked stream, not two
    assert_eq!(
      decode(&mut decoder, 0, &section).unwrap().0,
      DecodeOutcome::Blocked { required_insert_count: 1 }
    );
    assert_eq!(decoder.blocked.len(), 1);
    assert_eq!(output(&mut decoder), b"");
    encoder.clear();
    wire::insert_literal(&mut encoder, b"x-key", b"x-value", true);
    assert_eq!(decoder.on_encoder_stream(&encoder).unwrap(), encoder.len());
    assert_eq!(decoder.insert_count(), 1);
    assert_eq!(
      decode(&mut decoder, 0, &section).unwrap(),
      (DONE_DYNAMIC, pairs(&[("x-key", "x-value"), (":method", "GET")]))
    );
    assert_eq!(decoder.blocked.len(), 0);
    // The Section Acknowledgment covers the insert
    assert_eq!(output(&mut decoder), [0x80]);
    // The stream slot is free again
    let mut later = Vec::new();
    wire::prefix(&mut later, 2, 2, 128);
    wire::indexed(&mut later, false, 0);
    assert_eq!(
      decode(&mut decoder, 4, &later).unwrap().0,
      DecodeOutcome::Blocked { required_insert_count: 2 }
    );
  }

  #[test]
  fn blocked_streams_over_limit_is_decompression_failed() {
    let mut section = Vec::new();
    wire::prefix(&mut section, 1, 1, 128);
    wire::indexed(&mut section, false, 0);
    // Two promised: the third fails
    let mut decoder = QpackDecoder::new(4096, 2).unwrap();
    assert_eq!(
      decode(&mut decoder, 0, &section).unwrap().0,
      DecodeOutcome::Blocked { required_insert_count: 1 }
    );
    assert_eq!(
      decode(&mut decoder, 4, &section).unwrap().0,
      DecodeOutcome::Blocked { required_insert_count: 1 }
    );
    assert!(failed(decode(&mut decoder, 8, &section), Http3Error::TooManyBlockedStreams));
    // None promised: the first fails
    let mut decoder = QpackDecoder::new(4096, 0).unwrap();
    assert!(failed(decode(&mut decoder, 0, &section), Http3Error::TooManyBlockedStreams));
  }

  #[test]
  fn encoder_stream_errors_per_rfc9204() {
    // A capacity above the advertised one (RFC 9204 4.3.1); the advertised one itself is fine
    let mut decoder = QpackDecoder::new(100, 0).unwrap();
    let mut encoder = Vec::new();
    wire::set_capacity(&mut encoder, 101);
    assert!(refused(decoder.on_encoder_stream(&encoder), Http3Error::CapacityAboveMaximum));
    encoder.clear();
    wire::set_capacity(&mut encoder, 100);
    assert_eq!(decoder.on_encoder_stream(&encoder).unwrap(), encoder.len());
    // An entry larger than the capacity (3.2.2): 40 + 40 + 32 > 100, refused as soon as the
    // lengths are known and before the bytes arrive
    encoder.clear();
    wire::insert_literal(&mut encoder, &[b'a'; 40], &[b'b'; 40], false);
    assert!(refused(decoder.on_encoder_stream(&encoder), Http3Error::EntryTooLarge));
    assert!(refused(
      decoder.on_encoder_stream(encoder.get(..43).unwrap()),
      Http3Error::EntryTooLarge
    ));
    // A Huffman value that decodes past the capacity
    encoder.clear();
    wire::insert_literal(&mut encoder, b"a", &[b'0'; 80], true);
    assert!(refused(decoder.on_encoder_stream(&encoder), Http3Error::EntryTooLarge));
    // An index past the static table, references to entries that do not exist (2.2.3)
    encoder.clear();
    wire::insert_name_ref(&mut encoder, true, 99, b"v", false);
    assert!(refused(decoder.on_encoder_stream(&encoder), Http3Error::InvalidStaticIndex));
    encoder.clear();
    wire::insert_name_ref(&mut encoder, false, 0, b"v", false);
    assert!(refused(decoder.on_encoder_stream(&encoder), Http3Error::InvalidDynamicIndex));
    assert!(refused(decoder.on_encoder_stream(&[0x00]), Http3Error::InvalidDynamicIndex));
    // A bad Huffman string
    encoder.clear();
    encoder.extend_from_slice(&[0xc0 | 5, 0x84, 0xff, 0xff, 0xff, 0xff]);
    assert!(refused(decoder.on_encoder_stream(&encoder), Http3Error::InvalidHuffman));
    // An evicted entry: two entries of 51 bytes do not fit in 100, the second evicts the first
    encoder.clear();
    wire::insert_literal(&mut encoder, b"aaaaaaaa", b"bbbbbbbbbbb", false);
    wire::insert_literal(&mut encoder, b"cccccccc", b"ddddddddddd", false);
    assert_eq!(decoder.on_encoder_stream(&encoder).unwrap(), encoder.len());
    assert_eq!((decoder.insert_count(), decoder.size), (2, 51));
    assert!(refused(decoder.on_encoder_stream(&[0x01]), Http3Error::InvalidDynamicIndex));
    // A duplicate of the live one evicts it and still copies it whole
    assert_eq!(decoder.on_encoder_stream(&[0x00]).unwrap(), 1);
    let mut section = Vec::new();
    wire::prefix(&mut section, 3, 3, 3);
    wire::indexed(&mut section, false, 0);
    assert_eq!(
      decode(&mut decoder, 0, &section).unwrap(),
      (DONE_DYNAMIC, pairs(&[("cccccccc", "ddddddddddd")]))
    );
    // A prefixed integer above 62 bits (4.1.1): 31 in the 5-bit prefix of Set Dynamic Table
    // Capacity, then nine continuation bytes and one more
    let mut overflow = alloc::vec![0x3f];
    overflow.extend_from_slice(&[0xff; 9]);
    overflow.push(0x7f);
    assert!(refused(decoder.on_encoder_stream(&overflow), Http3Error::IntegerOverflow));
    // Without a dynamic table nothing can be inserted
    let mut decoder = QpackDecoder::new(0, 0).unwrap();
    assert_eq!(decoder.on_encoder_stream(&[0x20]).unwrap(), 1);
    assert!(refused(decoder.on_encoder_stream(&[0x21]), Http3Error::CapacityAboveMaximum));
    encoder.clear();
    wire::insert_literal(&mut encoder, b"", b"", false);
    assert!(refused(decoder.on_encoder_stream(&encoder), Http3Error::EntryTooLarge));
  }

  #[test]
  fn instruction_budget_is_excessive_load() {
    let budget_exceeded =
      |rslt| fails(rslt, H3ErrorCode::ExcessiveLoad, Http3Error::EncoderInstructionBudget);
    // 2 * 128 entries + 64 instructions per turn
    let budget = 2 * 128 + 64;
    let mut decoder = QpackDecoder::new(4096, 0).unwrap();
    decoder.start_turn();
    // Draining the decoder stream many times in one turn gives nothing back
    for _ in 0..budget / 4 {
      assert_eq!(decoder.on_encoder_stream(&[0x20; 4]).unwrap(), 4);
      let len = decoder.decoder_stream_output().len();
      decoder.consume_decoder_output(len);
      decoder.consume_decoder_output(0);
    }
    assert!(budget_exceeded(decoder.on_encoder_stream(&[0x20])));
    // A new turn does
    let mut decoder = QpackDecoder::new(4096, 0).unwrap();
    let instructions = alloc::vec![0x20; budget];
    assert_eq!(decoder.on_encoder_stream(&instructions).unwrap(), budget);
    decoder.start_turn();
    assert_eq!(decoder.on_encoder_stream(&instructions).unwrap(), budget);
    assert!(budget_exceeded(decoder.on_encoder_stream(&[0x20])));
  }

  // A one-byte Duplicate of a 4 KiB entry copies 4 KiB twice: the bytes copied out of the table in a
  // turn are bounded by four times the advertised capacity
  #[test]
  fn duplicate_flood_is_excessive_load() {
    let mut decoder = QpackDecoder::new(4096, 0).unwrap();
    let mut encoder = Vec::new();
    wire::set_capacity(&mut encoder, 4096);
    wire::insert_literal(&mut encoder, b"x", &[b'v'; 4031], false);
    assert_eq!(decoder.on_encoder_stream(&encoder).unwrap(), encoder.len());
    assert_eq!(decoder.size, 4064);
    // 4 * 4032 <= 4 * 4096 < 5 * 4032
    assert_eq!(decoder.on_encoder_stream(&[0x00; 4]).unwrap(), 4);
    assert!(fails(
      decoder.on_encoder_stream(&[0x00]),
      H3ErrorCode::ExcessiveLoad,
      Http3Error::EncoderInstructionBudget
    ));
    // The next turn may copy again; dynamic name references count their names
    let mut decoder = QpackDecoder::new(4096, 0).unwrap();
    assert_eq!(decoder.on_encoder_stream(&encoder).unwrap(), encoder.len());
    assert_eq!(decoder.on_encoder_stream(&[0x00; 4]).unwrap(), 4);
    decoder.start_turn();
    assert_eq!(decoder.on_encoder_stream(&[0x00; 4]).unwrap(), 4);
    let mut name_refs = Vec::new();
    let mut name_decoder = QpackDecoder::new(4096, 0).unwrap();
    encoder.clear();
    wire::set_capacity(&mut encoder, 4096);
    wire::insert_literal(&mut encoder, &[b'n'; 2000], b"", false);
    assert_eq!(name_decoder.on_encoder_stream(&encoder).unwrap(), encoder.len());
    for _ in 0..8 {
      wire::insert_name_ref(&mut name_refs, false, 0, b"", false);
    }
    assert_eq!(name_decoder.on_encoder_stream(&name_refs).unwrap(), name_refs.len());
    assert!(fails(
      name_decoder.on_encoder_stream(&name_refs),
      H3ErrorCode::ExcessiveLoad,
      Http3Error::EncoderInstructionBudget
    ));
  }

  // A pooled decoder starts over: no entry, no blocked stream, no pending output, the RFC bytes
  // again, and nothing allocated when the new limits fit in the old storage
  #[test]
  fn reset_reuses_the_allocations_and_starts_over() {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut decoder = after_b4();
    assert_eq!(decoder.on_encoder_stream(&B5_ENCODER).unwrap(), B5_ENCODER.len());
    let mut blocked = Vec::new();
    wire::prefix(&mut blocked, 6, 6, 6);
    wire::indexed(&mut blocked, false, 0);
    assert_eq!(
      decode(&mut decoder, 40, &blocked).unwrap().0,
      DecodeOutcome::Blocked { required_insert_count: 6 }
    );
    assert!(!decoder.decoder_stream_output().is_empty());
    _count_allocations_in(&COUNTER);
    let before = COUNTER.load(Ordering::SeqCst);
    decoder.reset(220, 2).unwrap();
    decoder.reset(100, 1).unwrap();
    decoder.reset(220, 2).unwrap();
    assert_eq!(COUNTER.load(Ordering::SeqCst) - before, 0);
    assert_eq!((decoder.insert_count(), decoder.size, decoder.capacity), (0, 0, 0));
    assert_eq!((decoder.entries_len, decoder.blocked.len()), (0, 0));
    assert_eq!(decoder.decoder_stream_output(), b"");
    decoder.check_invariants();
    // The RFC exchange from the start
    assert_eq!(decoder.on_encoder_stream(&B2_ENCODER).unwrap(), B2_ENCODER.len());
    assert_eq!(decoder.decoder_stream_output(), [0x02]);
    let expected = pairs(&[(":authority", "www.example.com"), (":path", "/sample/path")]);
    assert_eq!(decode(&mut decoder, 4, &B2_STREAM_4).unwrap(), (DONE_DYNAMIC, expected));
    assert_eq!(output(&mut decoder), [0x84]);
    // Larger limits are allowed, with new storage
    decoder.reset(4096, 4).unwrap();
    let mut encoder = Vec::new();
    wire::set_capacity(&mut encoder, 4096);
    wire::insert_literal(&mut encoder, &[b'a'; 1000], &[b'b'; 3000], false);
    assert_eq!(decoder.on_encoder_stream(&encoder).unwrap(), encoder.len());
    decoder.check_invariants();
  }

  #[test]
  fn field_section_errors_per_rfc9204() {
    // A prefix that is not whole
    assert!(failed(decode(&mut after_b2(), 0, &[]), Http3Error::Truncated));
    assert!(failed(decode(&mut after_b2(), 0, &[0x03]), Http3Error::Truncated));
    // An encoded Required Insert Count above 2 * MaxEntries (4.5.1.1)
    assert!(failed(
      decode(&mut after_b2(), 0, &[13, 0x00]),
      Http3Error::InvalidRequiredInsertCount
    ));
    // A negative Base (4.5.1.2)
    assert!(failed(decode(&mut after_b2(), 0, &[0x03, 0x82, 0x10]), Http3Error::InvalidBase));
    // A static index past the table (3.1)
    assert!(failed(
      decode(&mut after_b2(), 0, &[0x00, 0x00, 0xff, 0x24]),
      Http3Error::InvalidStaticIndex
    ));
    assert!(failed(
      decode(&mut after_b2(), 0, &[0x00, 0x00, 0x5f, 0x54, 0x00]),
      Http3Error::InvalidStaticIndex
    ));
    // Dynamic references with a Required Insert Count of 0, or at the Required Insert Count (2.2.3)
    assert!(failed(
      decode(&mut after_b2(), 0, &[0x00, 0x00, 0x80]),
      Http3Error::InvalidDynamicIndex
    ));
    assert!(failed(
      decode(&mut after_b2(), 0, &[0x02, 0x00, 0x10]),
      Http3Error::InvalidDynamicIndex
    ));
    assert!(failed(
      decode(&mut after_b2(), 0, &[0x02, 0x00, 0x81]),
      Http3Error::InvalidDynamicIndex
    ));
    assert!(failed(
      decode(&mut after_b2(), 0, &[0x02, 0x80, 0x01, 0x00]),
      Http3Error::InvalidDynamicIndex
    ));
    // A Required Insert Count larger than the references need (2.2.1)
    assert!(failed(
      decode(&mut after_b2(), 0, &[0x03, 0x00, 0x81]),
      Http3Error::RequiredInsertCountTooLarge
    ));
    assert!(failed(
      decode(&mut after_b2(), 0, &[0x03, 0x00, 0xd1]),
      Http3Error::RequiredInsertCountTooLarge
    ));
    // Literals that end early, or whose Huffman string is bad
    assert!(failed(
      decode(&mut after_b2(), 0, &[0x00, 0x00, 0x51, 0x0b, b'/']),
      Http3Error::Truncated
    ));
    assert!(failed(decode(&mut after_b2(), 0, &[0x00, 0x00, 0x27]), Http3Error::Truncated));
    assert!(failed(
      decode(&mut after_b2(), 0, &[0x00, 0x00, 0x51, 0x84, 0xff, 0xff, 0xff, 0xff]),
      Http3Error::InvalidHuffman
    ));
    // An integer above 62 bits
    let mut huge = alloc::vec![0x00, 0x00, 0xff];
    huge.extend_from_slice(&[0xff; 9]);
    huge.push(0x7f);
    assert!(failed(decode(&mut after_b2(), 0, &huge), Http3Error::IntegerOverflow));
    // A failure in the sink stops the decoding and is returned as it is
    let mut decoder = after_b2();
    let mut calls = 0;
    let rslt = decoder.decode(4, &B2_STREAM_4, &mut VectorUsize::new(), &mut |_, _| {
      calls += 1;
      Err(Error::Http3(Http3Error::BufferTooSmall))
    });
    assert!(matches!(rslt, Err(Error::Http3(Http3Error::BufferTooSmall))));
    assert_eq!(calls, 1);
  }

  #[test]
  fn huffman_literals_and_post_base_references_decode() {
    let mut decoder = after_b2();
    let mut section = Vec::new();
    // Required Insert Count 2 with a Base of 0: every dynamic reference is post-Base
    wire::prefix(&mut section, 2, 0, 6);
    wire::indexed_post_base(&mut section, 1);
    wire::post_base_name_ref(&mut section, true, 0, b"example.org", true);
    // RFC 7541 C.4.1: "www.example.com" as Huffman, by the static name of index 0
    section.extend_from_slice(&hexd!(b"508cf1e3c2e5f23a6ba0ab90f4ff"));
    // RFC 7541 C.4.3: custom-key: custom-value, both Huffman
    section.extend_from_slice(&hexd!(b"2f0125a849e95ba97d7f8925a849e95bb8e8b4bf"));
    wire::name_ref(&mut section, true, true, 4, b"0", false);
    wire::literal(&mut section, true, b"x-empty", b"", false);
    let expected = pairs(&[
      (":path", "/sample/path"),
      (":authority", "example.org"),
      (":authority", "www.example.com"),
      ("custom-key", "custom-value"),
      ("content-length", "0"),
      ("x-empty", ""),
    ]);
    assert_eq!(decode(&mut decoder, 4, &section).unwrap(), (DONE_DYNAMIC, expected));
    assert_eq!(output(&mut decoder), [0x84]);
  }

  // Entries go round a ring of the capacity: those that wrap around its end decode whole, by
  // index, by name and duplicated
  #[test]
  fn entries_that_wrap_the_ring_decode_whole() {
    let mut decoder = QpackDecoder::new(100, 0).unwrap();
    let mut encoder = Vec::new();
    wire::set_capacity(&mut encoder, 100);
    assert_eq!(decoder.on_encoder_stream(&encoder).unwrap(), encoder.len());
    for round in 0..64u64 {
      let name = alloc::format!("n{:0w$}", round, w = usize::try_from(round % 7).unwrap() + 1);
      let value = alloc::format!("v{:0w$}", round, w = usize::try_from(round % 11).unwrap() + 1);
      decoder.start_turn();
      encoder.clear();
      wire::insert_literal(&mut encoder, name.as_bytes(), value.as_bytes(), round % 2 == 0);
      // The same name with another value, then a duplicate of it
      wire::insert_name_ref(&mut encoder, false, 0, b"other", false);
      wire::duplicate(&mut encoder, 0);
      assert_eq!(decoder.on_encoder_stream(&encoder).unwrap(), encoder.len());
      let ric = decoder.insert_count();
      let mut section = Vec::new();
      wire::prefix(&mut section, ric, ric, 3);
      wire::indexed(&mut section, false, 0);
      wire::name_ref(&mut section, false, false, 0, value.as_bytes(), false);
      assert_eq!(
        decode(&mut decoder, 0, &section).unwrap(),
        (DONE_DYNAMIC, pairs(&[(&name, "other"), (&name, &value)]))
      );
      let _ = output(&mut decoder);
      assert!(decoder.size <= 100);
    }
  }

  #[test]
  fn random_tables_match_a_model() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut data = Vec::new();
    for round in 0..2_000 {
      data.clear();
      for _ in 0..64 + round % 1024 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data.push(u8::try_from(state & 0xff).unwrap());
      }
      crate::http3::qpack_check::check_model(&data);
    }
    // More instructions than one instruction budget, flushed as a connection does (found by the
    // fuzzer: the model did not flush)
    crate::http3::qpack_check::check_model(&[0; 4096]);
  }

  #[test]
  fn decoder_output_backlog_is_bounded() {
    let mut decoder = QpackDecoder::new(4096, 0).unwrap();
    let mut stream = 0u64;
    let mut rslt = None;
    for _ in 0..100_000 {
      if let Err(err) = decoder.on_stream_cancelled(stream) {
        rslt = Some(err);
        break;
      }
      assert!(decoder.decoder_stream_output().len() <= 16 * 1024);
      stream += 4;
    }
    assert!(matches!(
      rslt,
      Some(Error::Http3Close(H3ErrorCode::ExcessiveLoad, Http3Error::DecoderStreamBacklog))
    ));
    // Written out, it goes on
    let len = decoder.decoder_stream_output().len();
    decoder.consume_decoder_output(len);
    decoder.on_stream_cancelled(stream).unwrap();
    // Without a dynamic table there is nothing to cancel (RFC 9204 2.2.2.2)
    let mut decoder = QpackDecoder::new(0, 0).unwrap();
    decoder.on_stream_cancelled(4).unwrap();
    assert_eq!(decoder.decoder_stream_output(), b"");
  }

  #[test]
  fn decode_allocates_nothing_after_warmup() {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    const WARM_UP: usize = 128;
    const COUNTED: usize = 256;
    // Everything the peer sends is written before the counting starts
    struct Round {
      encoder: Vec<u8>,
      next_insert: Vec<u8>,
      blocked: Vec<u8>,
      dynamic: Vec<u8>,
    }
    let mut setup = Vec::new();
    wire::set_capacity(&mut setup, 1024);
    let mut statics = Vec::new();
    wire::prefix(&mut statics, 0, 0, 32);
    wire::indexed(&mut statics, true, 17);
    wire::indexed(&mut statics, true, 23);
    wire::name_ref(&mut statics, true, false, 0, b"localhost:8443", true);
    wire::name_ref(&mut statics, true, false, 1, b"/baseline2?a=1&b=2", true);
    wire::literal(&mut statics, false, b"user-agent", b"h2load nghttp2/1.64.0", true);
    let mut rounds = Vec::new();
    let mut inserts = 0u64;
    for idx in 0..WARM_UP + COUNTED {
      let mut encoder = Vec::new();
      let value = alloc::format!("value-{idx:06}-{}", "x".repeat(idx % 23));
      wire::insert_literal(&mut encoder, b"x-round", value.as_bytes(), idx % 2 == 0);
      wire::insert_name_ref(&mut encoder, true, 92, value.as_bytes(), true);
      wire::duplicate(&mut encoder, 1);
      inserts += 3;
      let mut dynamic = Vec::new();
      wire::prefix(&mut dynamic, inserts, inserts, 32);
      wire::indexed(&mut dynamic, false, 0);
      wire::indexed(&mut dynamic, false, 1);
      wire::name_ref(&mut dynamic, false, false, 2, b"a-value", true);
      wire::indexed(&mut dynamic, true, 25);
      // A section that needs the next round's first insert
      let mut blocked = Vec::new();
      wire::prefix(&mut blocked, inserts + 1, inserts, 32);
      wire::indexed_post_base(&mut blocked, 0);
      let mut next_insert = Vec::new();
      wire::insert_literal(&mut next_insert, b"x-next", value.as_bytes(), true);
      inserts += 1;
      rounds.push(Round { encoder, next_insert, blocked, dynamic });
    }
    let mut decoder = QpackDecoder::new(1024, 4).unwrap();
    let mut memo = DecodeMemo::<4>::new();
    let mut scratch = VectorUsize::new();
    let mut checksum = 0usize;
    assert_eq!(decoder.on_encoder_stream(&setup).unwrap(), setup.len());
    let mut run = |decoder: &mut QpackDecoder, round: &Round, stream: u64| {
      let mut sink = |name: &[u8], value: &[u8]| {
        checksum = checksum.wrapping_add(name.len()).wrapping_add(value.len());
        Ok(())
      };
      decoder.start_turn();
      assert_eq!(decoder.on_encoder_stream(&round.encoder).unwrap(), round.encoder.len());
      let done = decoder.decode_with_memo(&mut memo, stream, &statics, &mut scratch, &mut sink);
      assert_eq!(done.unwrap(), DONE_STATIC);
      let done = decoder.decode(stream, &statics, &mut scratch, &mut sink);
      assert_eq!(done.unwrap(), DONE_STATIC);
      let done =
        decoder.decode_with_memo(&mut memo, stream + 4, &round.dynamic, &mut scratch, &mut sink);
      assert_eq!(done.unwrap(), DONE_DYNAMIC);
      let done =
        decoder.decode_with_memo(&mut memo, stream + 8, &round.dynamic, &mut scratch, &mut sink);
      assert_eq!(done.unwrap(), DONE_DYNAMIC);
      let blocked = decoder.decode(stream + 12, &round.blocked, &mut scratch, &mut sink).unwrap();
      assert!(matches!(blocked, DecodeOutcome::Blocked { .. }));
      assert_eq!(decoder.on_encoder_stream(&round.next_insert).unwrap(), round.next_insert.len());
      let done = decoder.decode(stream + 12, &round.blocked, &mut scratch, &mut sink);
      assert_eq!(done.unwrap(), DONE_DYNAMIC);
      decoder.on_stream_cancelled(stream + 16).unwrap();
      let len = decoder.decoder_stream_output().len();
      assert!(len > 0);
      decoder.consume_decoder_output(len);
    };
    let mut stream = 0;
    for round in rounds.get(..WARM_UP).unwrap() {
      run(&mut decoder, round, stream);
      stream += 20;
    }
    _count_allocations_in(&COUNTER);
    let before = COUNTER.load(Ordering::SeqCst);
    for round in rounds.get(WARM_UP..).unwrap() {
      run(&mut decoder, round, stream);
      stream += 20;
    }
    let allocations = COUNTER.load(Ordering::SeqCst) - before;
    assert_eq!(allocations, 0);
    // The table evicted in the counted rounds, the memo replayed and the ring wrapped
    assert!(decoder.insert_count() > u64::try_from(decoder.entries_len).unwrap() + 512);
    assert!(memo.hits >= 2 * COUNTED as u64);
  }
}
