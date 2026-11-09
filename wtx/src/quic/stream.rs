//! Streams (RFC 9000 sections 2 to 4): their identifiers, the table of the streams of a
//! connection, the receiving parts that put data in order for the application, the sending parts
//! that hold data until it is acknowledged, and the packing of STREAM frames.
//!
//! # Memory
//!
//! A stream lives in a slot of [`StreamSlots`], a worker-wide slab with generations that the
//! connection reaches by index: client-initiated bidirectional streams through an inline array of
//! 256 `u32` indexed by the stream index modulo 256, unidirectional streams through small arrays
//! of their own. The limit of streams given to the peer is always the lowest stream that is not
//! closed plus the window, so that two open streams never share an entry (ruling T8-b).
//!
//! A slot holds 256 bytes inline for each direction; what does not fit takes blocks of 4 KiB from
//! the pools of the worker. A body written by reference ([`BodyRef`]) is never copied.
//!
//! # Receiving
//!
//! Data that arrives in order goes to the application straight from the decrypted packet. Data
//! that arrives before the data that precedes it waits in blocks, its ranges kept exactly in a
//! [`RangeSet`], until the gap fills. The application can retain the end of what it was given
//! ([`ConnCtx::retain`]): those bytes wait in the slot, or in one block, and come again before
//! the next ones. Waiting and retained bytes are bounded ([`crate::quic::QuicLimits`]) and give
//! no credit back until they are consumed.
//!
//! # Sending
//!
//! After the credit that is owed, a flush writes a STREAM frame for each stream whose next bytes
//! were written by copy, one stream after the other in turn, many frames to a packet, and then
//! the streams whose next bytes are a body, one at a time to its end, in the order in which they
//! were written. A frame has the FIN of its stream when it carries its last byte, and is empty
//! only for a FIN written after the last byte was sent. Bytes stay with the stream until every
//! frame that carries them is acknowledged; the slot goes back once both parts of the stream are
//! done.

use crate::quic::{
  BodyRef, ConnCtx, ConnParams, Frame, FrameWriter, QuicApp, QuicError, QuicLimits,
  TransportErrorCode, TransportParams,
  flow::{ConnFlow, NOT_BLOCKED, flow_control_error, top_up},
  limits::{RESET_WINDOW_US, RateBudget},
  pools::{FreeList, QuicPools, RX_BLOCK_LEN, RxBlock, TX_BLOCK_LEN, TxBlock},
  sent::{FrameRef, FrameRefRange},
  varint::varint_len,
};
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::hint::cold_path;

/// The window of client-initiated bidirectional streams: the entries of their index array.
pub(crate) const BIDI_WINDOW: usize = 256;
/// The bytes of the reason of a close of the application that are sent.
pub(crate) const CLOSE_REASON_LEN: usize = 64;
/// The bytes of the receive buffer and of the send buffer that a slot has inline.
pub(crate) const INLINE_LEN: usize = 256;
/// The window of the unidirectional streams of the peer.
pub(crate) const UNI_REMOTE_WINDOW: usize = 16;

// A stream that a later one opened (RFC 9000 section 3.2), which takes a slot once it is used
const IMPLICIT: u32 = u32::MAX - 1;
// Slots of a worker at most
const MAX_SLOTS: usize = 1 << 14;
const NO_LINK: u32 = u32::MAX;
const NO_SLOT: u32 = u32::MAX;
const OWED_DATA_BLOCKED: u8 = 1 << 0;
const OWED_MAX_DATA: u8 = 1 << 1;
const OWED_MAX_STREAMS_BIDI: u8 = 1 << 2;
const OWED_MAX_STREAMS_UNI: u8 = 1 << 3;
// Segments of the send queue of a slot reserved when the slot is made: headers, a body, trailers
const RESERVED_SEGMENTS: usize = 4;
const RX_BLOCK: u64 = RX_BLOCK_LEN as u64;
// Separate ranges held at most by a stream: received data that waits, acknowledged data
const RX_RANGES: usize = 32;
const TX_RANGES: usize = 16;
// The window of our unidirectional streams (HTTP/3 opens three)
const UNI_LOCAL_WINDOW: usize = 4;

/// A stream identifier (RFC 9000 section 2.1): the index of the stream among the streams of its
/// type, shifted by two, with a bit that says that a server opened it (0x1) and one that says
/// that it is unidirectional (0x2).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct StreamId(pub u64);

impl StreamId {
  /// If a client opened the stream and it is bidirectional: a request of HTTP/3.
  #[inline]
  pub(crate) const fn is_client_bidi(self) -> bool {
    self.0 & 0b11 == 0
  }

  /// If the stream is unidirectional.
  #[inline]
  pub(crate) const fn is_uni(self) -> bool {
    self.0 & 0b10 != 0
  }

  /// The index of the stream among the streams of its type.
  #[inline]
  pub(crate) const fn index(self) -> u64 {
    self.0 >> 2
  }

  const fn by_client(self) -> bool {
    self.0 & 0b01 == 0
  }

  const fn of(index: u64, by_client: bool, uni: bool) -> Self {
    let server_bit = if by_client { 0 } else { 0b01 };
    let uni_bit = if uni { 0b10 } else { 0 };
    Self((index << 2) | server_bit | uni_bit)
  }
}

/// Ranges of offsets from the lowest, at most `N` separate ones. Ranges that touch or overlap
/// are joined and gaps are never filled: the ranges are exact. A range that does not fit is an
/// error, which leaves the ranges as they were.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RangeSet<const N: usize> {
  len: usize,
  // From the lowest: start included, end excluded
  ranges: [(u64, u64); N],
}

impl<const N: usize> RangeSet<N> {
  /// No ranges.
  #[inline]
  pub(crate) const fn new() -> Self {
    Self { len: 0, ranges: [(0, 0); N] }
  }

  /// The lowest range.
  #[inline]
  pub(crate) fn first(&self) -> Option<(u64, u64)> {
    self.held().first().copied()
  }

  /// Adds the offsets from `start` to `end`, excluded. A new separate range when `N` are held is
  /// a connection error (PROTOCOL_VIOLATION).
  #[inline]
  pub(crate) fn insert(&mut self, start: u64, end: u64) -> crate::Result<()> {
    if start >= end {
      return Ok(());
    }
    let held = self.held();
    // The held ranges from `lo` to `hi`, excluded, touch or overlap the new one
    let lo = held.partition_point(|el| el.1 < start);
    let hi = held.partition_point(|el| el.0 <= end);
    if lo == hi {
      if self.len >= N {
        cold_path();
        return Err(crate::Error::QuicClose(
          TransportErrorCode::ProtocolViolation,
          QuicError::RangeSetFull,
        ));
      }
      if let Some(tail) = self.ranges.get_mut(lo..=self.len) {
        tail.rotate_right(1);
        if let Some(elem) = tail.first_mut() {
          *elem = (start, end);
        }
      }
      self.len = self.len.wrapping_add(1);
      return Ok(());
    }
    let (Some(&(first, _)), Some(&(_, last))) = (held.get(lo), held.get(hi.wrapping_sub(1))) else {
      return Ok(());
    };
    if let Some(elem) = self.ranges.get_mut(lo) {
      *elem = (start.min(first), end.max(last));
    }
    let joined = hi.wrapping_sub(lo).wrapping_sub(1);
    if joined > 0 {
      if let Some(tail) = self.ranges.get_mut(lo.wrapping_add(1)..self.len) {
        tail.rotate_left(joined);
      }
      self.len = self.len.wrapping_sub(joined);
    }
    Ok(())
  }

  /// If no range is held.
  #[inline]
  pub(crate) const fn is_empty(&self) -> bool {
    self.len == 0
  }

  /// The ranges, from the lowest, as (start, end excluded).
  #[inline]
  pub(crate) fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
    self.held().iter().copied()
  }

  /// The number of separate ranges.
  #[inline]
  pub(crate) const fn len(&self) -> usize {
    self.len
  }

  /// Forgets the offsets below `at`.
  #[inline]
  pub(crate) fn remove_below(&mut self, at: u64) {
    let gone = self.held().partition_point(|el| el.1 <= at);
    if gone > 0 {
      if let Some(held) = self.ranges.get_mut(..self.len) {
        held.rotate_left(gone);
      }
      self.len = self.len.wrapping_sub(gone);
    }
    if let Some(first) = self.ranges.get_mut(..self.len).and_then(|el| el.first_mut())
      && first.0 < at
    {
      first.0 = at;
    }
  }

  fn held(&self) -> &[(u64, u64)] {
    self.ranges.get(..self.len).unwrap_or_default()
  }
}

/// The streams of the connections of a worker: a slab of slots with generations, grown on demand
/// up to 16,384 slots, whose slots are used again without allocating. A frame reference names a
/// stream by slot and generation, so that a stream that is gone is not mistaken for the next one
/// in its slot.
#[derive(Debug)]
pub(crate) struct StreamSlots {
  entries: Vec<SlotEntry>,
  // The first free slot, the others linked from it
  free: u32,
  // The generation of a slot that is made, above every generation of the slots that a trim let
  // go: a frame reference of a stream of before never matches the stream of a slot made again
  generation_floor: u32,
  live: usize,
}

impl StreamSlots {
  /// No slots.
  #[inline]
  pub(crate) const fn new() -> Self {
    Self { entries: Vec::new(), free: NO_SLOT, generation_floor: 0, live: 0 }
  }

  /// The number of slots that hold a stream.
  #[inline]
  pub(crate) const fn live(&self) -> usize {
    self.live
  }

  /// Frees all but `keep` slots if none holds a stream.
  #[inline]
  pub(crate) fn trim_idle(&mut self, keep: usize) {
    if self.live != 0 {
      return;
    }
    for entry in self.entries.get(keep..).unwrap_or_default() {
      self.generation_floor = self.generation_floor.max(entry.generation.wrapping_add(1));
    }
    self.entries.truncate(keep);
    self.entries.shrink_to(keep);
    self.free = NO_SLOT;
    for (idx, entry) in self.entries.iter_mut().enumerate().rev() {
      entry.next_free = self.free;
      self.free = u32::try_from(idx).unwrap_or(NO_SLOT);
    }
  }

  fn alloc(&mut self) -> crate::Result<u32> {
    let idx = if self.free == NO_SLOT {
      if self.entries.len() >= MAX_SLOTS {
        return Err(exhausted());
      }
      let idx = u32::try_from(self.entries.len()).map_err(|_err| exhausted())?;
      self.entries.try_reserve(1).map_err(|_err| exhausted())?;
      self.entries.push(SlotEntry {
        generation: self.generation_floor,
        live: false,
        next_free: NO_SLOT,
        stream: Stream::new()?,
      });
      idx
    } else {
      let idx = self.free;
      let Some(entry) = self.entry_mut(idx) else {
        return Err(exhausted());
      };
      let next = entry.next_free;
      self.free = next;
      idx
    };
    if let Some(entry) = self.entry_mut(idx) {
      entry.live = true;
      entry.next_free = NO_SLOT;
    }
    self.live = self.live.wrapping_add(1);
    Ok(idx)
  }

  fn entry_mut(&mut self, idx: u32) -> Option<&mut SlotEntry> {
    self.entries.get_mut(usize::try_from(idx).ok()?)
  }

  fn free(&mut self, idx: u32) {
    let free = self.free;
    let Some(entry) = self.entry_mut(idx).filter(|el| el.live) else {
      return;
    };
    entry.live = false;
    entry.generation = entry.generation.wrapping_add(1);
    entry.next_free = free;
    self.free = idx;
    self.live = self.live.wrapping_sub(1);
  }

  fn generation(&self, idx: u32) -> u32 {
    self.entries.get(usize::try_from(idx).unwrap_or(usize::MAX)).map_or(0, |el| el.generation)
  }

  fn get(&self, idx: u32) -> Option<&Stream> {
    let entry = self.entries.get(usize::try_from(idx).ok()?)?;
    entry.live.then_some(&entry.stream)
  }

  fn get_mut(&mut self, idx: u32) -> Option<&mut Stream> {
    self.entry_mut(idx).filter(|el| el.live).map(|el| &mut el.stream)
  }

  // The stream of a frame reference, if its slot was not freed since
  fn get_live(&mut self, idx: u32, generation: u32) -> Option<&mut Stream> {
    self.entry_mut(idx).filter(|el| el.live && el.generation == generation).map(|el| &mut el.stream)
  }
}

#[derive(Debug)]
struct SlotEntry {
  generation: u32,
  live: bool,
  next_free: u32,
  stream: Stream,
}

/// A stream: its two parts and its places in the lists of its connection.
#[derive(Debug)]
pub(crate) struct Stream {
  ctrl: Links,
  // If it is in the small list with nothing but its FIN to send
  fin_only: bool,
  id: StreamId,
  in_ctrl: bool,
  ready: Links,
  ready_in: Option<Ready>,
  rx: RecvPart,
  tx: SendPart,
}

impl Stream {
  fn new() -> crate::Result<Self> {
    let mut segs = VecDeque::new();
    segs.try_reserve(RESERVED_SEGMENTS).map_err(|_err| exhausted())?;
    Ok(Self {
      ctrl: Links::NONE,
      fin_only: false,
      id: StreamId(0),
      in_ctrl: false,
      ready: Links::NONE,
      ready_in: None,
      rx: RecvPart {
        blocks: 0,
        consumed: 0,
        final_size: None,
        high: 0,
        inline: [0; INLINE_LEN],
        keep: 0,
        keep_block: None,
        max: 0,
        max_owed: false,
        ooo: RangeSet::new(),
        ooo_blocks: Vec::new(),
        read: 0,
        state: RxState::None,
        stop_code: 0,
        stop_owed: false,
      },
      tx: SendPart {
        acked: 0,
        acked_ranges: RangeSet::new(),
        blocked_at: NOT_BLOCKED,
        blocked_owed: false,
        cursor: 0,
        cursor_pos: 0,
        end: 0,
        exists: false,
        fin: false,
        fin_acked: false,
        fin_sent: false,
        inline: [0; INLINE_LEN],
        inline_live: 0,
        inline_used: 0,
        max: 0,
        reset: None,
        reset_acked: false,
        reset_owed: false,
        seg_base: 0,
        segs,
        sent: 0,
        stop_counted: false,
      },
    })
  }

  // Makes the slot stream `id`: what it holds was given back when the previous one closed.
  fn open(&mut self, id: StreamId, rx_max: Option<u64>, tx_max: Option<u64>) {
    self.ctrl = Links::NONE;
    self.fin_only = false;
    self.id = id;
    self.in_ctrl = false;
    self.ready = Links::NONE;
    self.ready_in = None;
    let rx = &mut self.rx;
    rx.blocks = 0;
    rx.consumed = 0;
    rx.final_size = None;
    rx.high = 0;
    rx.keep = 0;
    rx.max = rx_max.unwrap_or(0);
    rx.max_owed = false;
    rx.ooo = RangeSet::new();
    rx.read = 0;
    rx.state = if rx_max.is_some() { RxState::Recv } else { RxState::None };
    rx.stop_code = 0;
    rx.stop_owed = false;
    let tx = &mut self.tx;
    tx.acked = 0;
    tx.acked_ranges = RangeSet::new();
    tx.blocked_at = NOT_BLOCKED;
    tx.blocked_owed = false;
    tx.cursor = 0;
    tx.cursor_pos = 0;
    tx.end = 0;
    tx.exists = tx_max.is_some();
    tx.fin = false;
    tx.fin_acked = false;
    tx.fin_sent = false;
    tx.inline_live = 0;
    tx.inline_used = 0;
    tx.max = tx_max.unwrap_or(0);
    tx.reset = None;
    tx.reset_acked = false;
    tx.reset_owed = false;
    tx.seg_base = 0;
    tx.sent = 0;
    tx.stop_counted = false;
  }
}

#[derive(Clone, Copy, Debug)]
struct Links {
  next: u32,
  prev: u32,
}

impl Links {
  const NONE: Self = Self { next: NO_LINK, prev: NO_LINK };
}

// A list of streams of a connection, linked through their slots
#[derive(Clone, Copy, Debug)]
struct List {
  head: u32,
  tail: u32,
}

impl List {
  const EMPTY: Self = Self { head: NO_LINK, tail: NO_LINK };

  fn links(stream: &mut Stream, ctrl: bool) -> &mut Links {
    if ctrl { &mut stream.ctrl } else { &mut stream.ready }
  }

  fn push_back(&mut self, slots: &mut StreamSlots, slot: u32, ctrl: bool) {
    let tail = self.tail;
    if let Some(stream) = slots.get_mut(slot) {
      *Self::links(stream, ctrl) = Links { next: NO_LINK, prev: tail };
    }
    if let Some(stream) = slots.get_mut(tail) {
      Self::links(stream, ctrl).next = slot;
    } else {
      self.head = slot;
    }
    self.tail = slot;
  }

  fn unlink(&mut self, slots: &mut StreamSlots, slot: u32, ctrl: bool) {
    let Some(stream) = slots.get_mut(slot) else {
      return;
    };
    let Links { next, prev } = core::mem::replace(Self::links(stream, ctrl), Links::NONE);
    if let Some(elem) = slots.get_mut(prev) {
      Self::links(elem, ctrl).next = next;
    } else {
      self.head = next;
    }
    if let Some(elem) = slots.get_mut(next) {
      Self::links(elem, ctrl).prev = prev;
    } else {
      self.tail = prev;
    }
  }
}

// The list of streams with something to send
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ready {
  // Next bytes written by copy, or the FIN alone: one frame each in turn
  Small,
  // Next bytes in a body: one stream at a time to its end
  Large,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RxState {
  // No receiving part: a unidirectional stream of ours
  None,
  // Data goes to the application
  Recv,
  // The application asked the peer to stop (STOP_SENDING): what arrives is counted and dropped
  Discard,
  // The application got the FIN, or the peer reset the stream
  Done,
}

#[derive(Debug)]
struct RecvPart {
  // Receive blocks held, the ones out for a call of the application included
  blocks: u32,
  // What the application consumed when credit was last counted: `read - keep`
  consumed: u64,
  final_size: Option<u64>,
  // The end of the highest data received
  high: u64,
  inline: [u8; INLINE_LEN],
  // Bytes retained by the application, which end at `read`: in `inline`, or in `keep_block` if
  // it is there
  keep: usize,
  keep_block: Option<Box<RxBlock>>,
  // The credit given to the peer
  max: u64,
  max_owed: bool,
  // Data after `read` that waits for earlier data, and the blocks that hold it by number
  ooo: RangeSet<RX_RANGES>,
  ooo_blocks: Vec<OooBlock>,
  // The first byte that the application was not given
  read: u64,
  state: RxState,
  stop_code: u64,
  stop_owed: bool,
}

impl RecvPart {
  // If nothing more is expected
  fn is_done(&self) -> bool {
    match self.state {
      RxState::None | RxState::Done => true,
      RxState::Discard => self.final_size.is_some(),
      RxState::Recv => false,
    }
  }

  // The bytes that can go to the application next, after the retained ones: what the packet has
  // at `read`, or else the waiting data at `read`, up to the end of its block
  fn next_run(&self, direct: &[u8]) -> usize {
    if !direct.is_empty() {
      return direct.len();
    }
    match self.ooo.first() {
      Some((start, end)) if start <= self.read && end > self.read => {
        let block_end = (self.read / RX_BLOCK).wrapping_add(1).wrapping_mul(RX_BLOCK);
        usize::try_from(end.min(block_end).wrapping_sub(self.read)).unwrap_or(0)
      }
      _ => 0,
    }
  }

  // Forgets the waiting data that the application was given, and the blocks that held only that
  fn drop_below_read(&mut self, blocks: &mut FreeList<Box<RxBlock>>, held: &mut Held) {
    self.ooo.remove_below(self.read);
    let gone = self
      .ooo_blocks
      .partition_point(|el| el.no.wrapping_add(1).wrapping_mul(RX_BLOCK) <= self.read);
    for elem in self.ooo_blocks.drain(..gone) {
      if let Some(block) = elem.data {
        held.give(blocks, &mut self.blocks, block);
      }
    }
  }

  // Gives back the blocks that are here, not one that is out for a call of the application
  fn release(&mut self, blocks: &mut FreeList<Box<RxBlock>>, held: &mut Held) {
    if let Some(block) = self.keep_block.take() {
      held.give(blocks, &mut self.blocks, block);
    }
    for elem in self.ooo_blocks.drain(..) {
      if let Some(block) = elem.data {
        held.give(blocks, &mut self.blocks, block);
      }
    }
    self.ooo = RangeSet::new();
    self.keep = 0;
  }

  // `bytes` become the retained bytes, which there were none of
  fn store_keep(
    &mut self,
    bytes: &[u8],
    blocks: &mut FreeList<Box<RxBlock>>,
    held: &mut Held,
    limits: &QuicLimits,
  ) -> crate::Result<()> {
    let len = bytes.len();
    if len > INLINE_LEN {
      let mut block = held.take(blocks, &mut self.blocks, limits)?;
      if let Some(dst) = block.get_mut(..len) {
        dst.copy_from_slice(bytes);
      }
      self.keep_block = Some(block);
    } else if let Some(dst) = self.inline.get_mut(..len) {
      dst.copy_from_slice(bytes);
    }
    self.keep = len;
    Ok(())
  }
}

// The receive blocks held by the streams of a connection
#[derive(Clone, Copy, Debug)]
struct Held {
  blocks: u32,
  // The streams that hold at least one
  streams: u32,
}

impl Held {
  // `block` goes back from a part that holds `own` blocks
  fn give(&mut self, blocks: &mut FreeList<Box<RxBlock>>, own: &mut u32, block: Box<RxBlock>) {
    blocks.give(block);
    self.blocks = self.blocks.saturating_sub(1);
    if *own == 1 {
      self.streams = self.streams.saturating_sub(1);
    }
    *own = own.saturating_sub(1);
  }

  // A block for a part that holds `own` blocks. The cap of the connection is the bytes that its
  // credit allows and, as blocks count whole, three blocks for each stream that holds some: a
  // stream holds data within the bytes of its credit that it did not consume, whose first and
  // last blocks may hold little of it, and the bytes that it retains in a block of their own. A
  // peer within its credit never goes past it (ruling T8-g).
  fn take(
    &mut self,
    blocks: &mut FreeList<Box<RxBlock>>,
    own: &mut u32,
    limits: &QuicLimits,
  ) -> crate::Result<Box<RxBlock>> {
    let streams = u64::from(self.streams).wrapping_add(u64::from(*own == 0));
    let max = u64::from(limits.max_out_of_order_bytes_per_conn)
      .div_ceil(RX_BLOCK)
      .saturating_add(streams.saturating_mul(3));
    if u64::from(self.blocks) >= max {
      return Err(out_of_order_limit());
    }
    if *own == 0 {
      self.streams = self.streams.wrapping_add(1);
    }
    self.blocks = self.blocks.wrapping_add(1);
    *own = own.wrapping_add(1);
    Ok(blocks.take().unwrap_or_else(|| Box::new([0; RX_BLOCK_LEN])))
  }
}

#[derive(Debug)]
struct OooBlock {
  // Out of the vector while its bytes are with the application
  data: Option<Box<RxBlock>>,
  // The offsets of the block are from `no * 4096`
  no: u64,
}

#[derive(Debug)]
struct SendPart {
  // Everything before was acknowledged and given back
  acked: u64,
  // Acknowledged data after `acked`
  acked_ranges: RangeSet<TX_RANGES>,
  // The limit of the last STREAM_DATA_BLOCKED, or `NOT_BLOCKED`
  blocked_at: u64,
  blocked_owed: bool,
  // The segment and the position in it of `sent`
  cursor: usize,
  cursor_pos: usize,
  // The end of what was written
  end: u64,
  exists: bool,
  // The application wrote the FIN, which is at `end`
  fin: bool,
  fin_acked: bool,
  fin_sent: bool,
  inline: [u8; INLINE_LEN],
  // Segments in `inline`, which is used from `inline_used` on
  inline_live: u8,
  inline_used: usize,
  // The credit given by the peer
  max: u64,
  // The code of the RESET_STREAM of this part
  reset: Option<u64>,
  reset_acked: bool,
  reset_owed: bool,
  // The offset of the first segment
  seg_base: u64,
  segs: VecDeque<Seg>,
  // The first byte not sent yet
  sent: u64,
  stop_counted: bool,
}

impl SendPart {
  // `bytes` after the last segment if it is a buffer with room after its bytes, in new segments
  // after that: in `inline` while they fit there, in blocks otherwise
  fn append_bytes(
    &mut self,
    mut bytes: &[u8],
    blocks: &mut FreeList<Box<TxBlock>>,
  ) -> crate::Result<()> {
    let count = self.segs.len();
    if let Some(last) = self.segs.back_mut() {
      let (dst, room) = match &mut last.data {
        SegData::Inline(pos) if pos.wrapping_add(last.len) == self.inline_used => {
          let at = self.inline_used;
          (self.inline.get_mut(at..), INLINE_LEN.wrapping_sub(at))
        }
        SegData::Block(block) => (block.get_mut(last.len..), TX_BLOCK_LEN.wrapping_sub(last.len)),
        SegData::Body(_) | SegData::Inline(_) => (None, 0),
      };
      let take = room.min(bytes.len());
      if take > 0
        && let Some(dst) = dst.and_then(|el| el.get_mut(..take))
        && let Some((head, tail)) = bytes.split_at_checked(take)
      {
        dst.copy_from_slice(head);
        bytes = tail;
        // A segment that was all sent has bytes to send again: the cursor, which left it, comes
        // back to them
        if self.cursor >= count {
          self.cursor = count.wrapping_sub(1);
          self.cursor_pos = last.len;
        }
        last.len = last.len.wrapping_add(take);
        if matches!(last.data, SegData::Inline(_)) {
          self.inline_used = self.inline_used.wrapping_add(take);
        }
      }
    }
    while !bytes.is_empty() {
      if self.inline_live == 0 {
        self.inline_used = 0;
      }
      let at = self.inline_used;
      let seg = if bytes.len() <= INLINE_LEN.wrapping_sub(at) {
        if let Some(dst) = self.inline.get_mut(at..at.wrapping_add(bytes.len())) {
          dst.copy_from_slice(bytes);
        }
        self.inline_used = at.wrapping_add(bytes.len());
        self.inline_live = self.inline_live.wrapping_add(1);
        let seg = Seg { data: SegData::Inline(at), len: bytes.len() };
        bytes = &[];
        seg
      } else {
        let mut block = blocks.take().unwrap_or_else(|| Box::new([0; TX_BLOCK_LEN]));
        let (head, tail) =
          bytes.split_at_checked(bytes.len().min(TX_BLOCK_LEN)).unwrap_or_default();
        if let Some(dst) = block.get_mut(..head.len()) {
          dst.copy_from_slice(head);
        }
        bytes = tail;
        Seg { data: SegData::Block(block), len: head.len() }
      };
      self.push(seg)?;
    }
    Ok(())
  }

  // Writes the next `len` unsent bytes into `fw`, after the header of their frame
  fn copy_unsent(&mut self, mut len: usize, fw: &mut FrameWriter<'_>) {
    while len > 0 {
      let Some(seg) = self.segs.get(self.cursor) else {
        break;
      };
      let piece = seg.bytes(&self.inline).get(self.cursor_pos..).unwrap_or_default();
      let take = piece.len().min(len);
      let _written = fw.write_bytes(piece.get(..take).unwrap_or_default());
      len = len.wrapping_sub(take);
      self.cursor_pos = self.cursor_pos.wrapping_add(take);
      if self.cursor_pos >= seg.len {
        self.cursor = self.cursor.wrapping_add(1);
        self.cursor_pos = 0;
      }
      if take == 0 {
        break;
      }
    }
  }

  // If nothing more is to be sent or acknowledged
  fn is_done(&self) -> bool {
    !self.exists
      || self.reset_acked
      || (self.reset.is_none() && self.fin_acked && self.acked >= self.end)
  }

  // If the next bytes to send are in a body
  fn next_is_body(&self) -> bool {
    self.segs.get(self.cursor).is_some_and(|el| matches!(el.data, SegData::Body(_)))
  }

  // Acknowledged: the bytes from `offset`, `len` of them, and the FIN if `fin`
  fn on_acked(
    &mut self,
    offset: u64,
    len: u64,
    fin: bool,
    blocks: &mut FreeList<Box<TxBlock>>,
  ) -> crate::Result<()> {
    if self.reset.is_some() {
      return Ok(());
    }
    self.fin_acked |= fin;
    self.acked_ranges.insert(offset, offset.saturating_add(len)).map_err(|_err| {
      cold_path();
      crate::Error::QuicClose(TransportErrorCode::InternalError, QuicError::RangeSetFull)
    })?;
    if let Some((start, end)) = self.acked_ranges.first()
      && start <= self.acked
    {
      self.acked = self.acked.max(end);
      self.acked_ranges.remove_below(self.acked);
    }
    while let Some(front) = self.segs.front() {
      let seg_end = self.seg_base.wrapping_add(u64::try_from(front.len).unwrap_or(u64::MAX));
      if seg_end > self.acked {
        break;
      }
      let Some(seg) = self.segs.pop_front() else {
        break;
      };
      self.seg_base = seg_end;
      self.cursor = self.cursor.saturating_sub(1);
      self.release_seg(seg, blocks);
    }
    Ok(())
  }

  fn push(&mut self, seg: Seg) -> crate::Result<()> {
    self.segs.try_reserve(1).map_err(|_err| exhausted())?;
    self.segs.push_back(seg);
    Ok(())
  }

  // Gives back every segment
  fn release(&mut self, blocks: &mut FreeList<Box<TxBlock>>) {
    while let Some(seg) = self.segs.pop_front() {
      self.release_seg(seg, blocks);
    }
    self.cursor = 0;
    self.cursor_pos = 0;
    self.inline_live = 0;
    self.inline_used = 0;
    self.seg_base = self.end;
  }

  fn release_seg(&mut self, seg: Seg, blocks: &mut FreeList<Box<TxBlock>>) {
    match seg.data {
      SegData::Block(block) => blocks.give(block),
      // The reference to the body goes
      SegData::Body(_) => {}
      SegData::Inline(_) => {
        self.inline_live = self.inline_live.saturating_sub(1);
        if self.inline_live == 0 {
          self.inline_used = 0;
        }
      }
    }
  }
}

#[derive(Debug)]
struct Seg {
  data: SegData,
  len: usize,
}

impl Seg {
  fn bytes<'this>(&'this self, inline: &'this [u8; INLINE_LEN]) -> &'this [u8] {
    match &self.data {
      SegData::Block(block) => block.get(..self.len),
      SegData::Body(body) => Some(body.as_slice()),
      SegData::Inline(pos) => inline.get(*pos..pos.wrapping_add(self.len)),
    }
    .unwrap_or_default()
  }
}

#[derive(Debug)]
enum SegData {
  // Written by copy, alone in a block
  Block(Box<TxBlock>),
  // Written by reference
  Body(BodyRef),
  // Written by copy, in the inline buffer of the slot from this position
  Inline(usize),
}

/// What the application writes to a stream.
#[derive(Debug)]
pub(crate) enum Source<'any> {
  /// Bytes that are copied.
  Bytes(&'any [u8]),
  /// A body that is held by reference.
  Body(BodyRef),
}

// What is taken out of the stream for a call of `on_stream_data`
enum Piece {
  // The rest of the packet
  Direct,
  // The retained bytes and what followed them, in the retaining block if it is there
  Keep(Option<Box<RxBlock>>),
  // Waiting data from block `no`, at `pos`
  Block { block: Box<RxBlock>, no: u64, pos: usize },
  // The FIN, after everything was given
  Fin,
}

// The types of streams
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
  // Opened by the client
  Bidi,
  UniLocal,
  UniRemote,
}

// Where a stream is in its table
#[derive(Clone, Copy, Debug)]
enum Entry {
  Closed,
  Implicit,
  NotOpened,
  Open(u32),
}

// The streams of a type of a connection: an index array over the window, from the lowest stream
// that is not closed
#[derive(Debug)]
struct Table<const W: usize> {
  meta: TableMeta,
  slots: [u32; W],
}

impl<const W: usize> Table<W> {
  const fn new(limit: u64, window: u64) -> Self {
    Self { meta: TableMeta { base: 0, limit, next: 0, window }, slots: [NO_SLOT; W] }
  }

  const fn view(&mut self) -> TableMut<'_> {
    TableMut { meta: &mut self.meta, slots: &mut self.slots }
  }

  const fn view_ref(&self) -> TableRef<'_> {
    TableRef { meta: &self.meta, slots: &self.slots }
  }
}

#[derive(Clone, Copy, Debug)]
struct TableMeta {
  // The lowest stream that is not closed
  base: u64,
  // Streams of the peer: the limit that it was given; ours: the limit that it gave
  limit: u64,
  // The lowest stream that is not open
  next: u64,
  window: u64,
}

impl TableMeta {
  // The limit to give the peer, once it used half of what it has: the lowest stream that is not
  // closed plus the window
  fn max_streams_due(&self) -> Option<u64> {
    let target = self.base.saturating_add(self.window);
    (target > self.limit && self.limit.saturating_sub(self.next) <= self.window / 2)
      .then_some(target)
  }
}

struct TableMut<'table> {
  meta: &'table mut TableMeta,
  slots: &'table mut [u32],
}

impl TableMut<'_> {
  // The lowest stream that is not closed moves past the streams that closed
  fn advance_base(&mut self) {
    while self.meta.base < self.meta.next
      && self.slots.get(pos(self.slots.len(), self.meta.base)) == Some(&NO_SLOT)
    {
      self.meta.base = self.meta.base.wrapping_add(1);
    }
  }

  fn set(&mut self, index: u64, value: u32) {
    let at = pos(self.slots.len(), index);
    if let Some(elem) = self.slots.get_mut(at) {
      *elem = value;
    }
  }
}

#[derive(Clone, Copy)]
struct TableRef<'table> {
  meta: &'table TableMeta,
  slots: &'table [u32],
}

impl TableRef<'_> {
  fn entry(&self, index: u64) -> Entry {
    if index < self.meta.base {
      return Entry::Closed;
    }
    if index >= self.meta.next {
      return Entry::NotOpened;
    }
    match self.slots.get(pos(self.slots.len(), index)).copied() {
      None | Some(NO_SLOT) => Entry::Closed,
      Some(IMPLICIT) => Entry::Implicit,
      Some(slot) => Entry::Open(slot),
    }
  }
}

/// The state of the streams of a connection that is seldom used: the unidirectional streams, the
/// credit that the peer gives new streams, the receive blocks held, the reset budget and the close
/// that the application asked for. It comes from the pools of the worker and goes back once the
/// connection is over, which keeps the connection small (spec section 5.4, ruling T8-c).
#[derive(Debug)]
pub(crate) struct StreamsCold {
  /// DATA_BLOCKED and STREAM_DATA_BLOCKED frames sent.
  #[cfg(test)]
  blocked_sent: u32,
  close_reason: [u8; CLOSE_REASON_LEN],
  close_reason_len: u8,
  close_request: Option<u64>,
  held: Held,
  // The credit of a stream that the peer gives: client-initiated bidirectional ones and our
  // unidirectional ones
  peer_bidi_credit: u64,
  peer_uni_credit: u64,
  resets: RateBudget,
  /// If DATA_BLOCKED and STREAM_DATA_BLOCKED are sent, which tests turn off.
  #[cfg(test)]
  send_blocked_frames: bool,
  uni_local: Table<UNI_LOCAL_WINDOW>,
  uni_remote: Table<UNI_REMOTE_WINDOW>,
}

impl StreamsCold {
  // From the pool, or new, for a connection with `params`
  fn take(params: &ConnParams, pools: &mut QuicPools) -> Box<Self> {
    let uni_window = params.max_streams_uni.min(UNI_REMOTE_WINDOW as u64);
    let fresh = Self {
      #[cfg(test)]
      blocked_sent: 0,
      close_reason: [0; CLOSE_REASON_LEN],
      close_reason_len: 0,
      close_request: None,
      held: Held { blocks: 0, streams: 0 },
      peer_bidi_credit: 0,
      peer_uni_credit: 0,
      resets: RateBudget::default(),
      #[cfg(test)]
      send_blocked_frames: true,
      uni_local: Table::new(0, UNI_LOCAL_WINDOW as u64),
      uni_remote: Table::new(uni_window, uni_window),
    };
    match pools.streams_cold.take() {
      Some(mut elem) => {
        *elem = fresh;
        elem
      }
      None => Box::new(fresh),
    }
  }
}

// What a write did
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Wrote {
  Frame,
  // The packet is full
  Full,
  // Nothing can be sent now
  Blocked,
}

/// The streams of a connection: the tables of their slots, the connection credit, the lists of
/// streams with something to send and the budget of abandoned streams. See the
/// [module documentation](self).
#[derive(Debug)]
pub(crate) struct Streams {
  // Opened by the client: by the peer on a server, by us on the client of tests
  bidi: Table<BIDI_WINDOW>,
  // The connection is closing: nothing more can be written
  closed: bool,
  // From the pools until the connection is over
  cold: Option<Box<StreamsCold>>,
  ctrl: List,
  fin_only: u32,
  flow: ConnFlow,
  is_client: bool,
  large: List,
  owed: u8,
  small: List,
  unsent: u64,
}

impl Streams {
  /// The streams of a new connection with `params`, whose seldom used state comes from `pools`.
  #[inline]
  pub(crate) fn new(params: &ConnParams, is_client: bool, pools: &mut QuicPools) -> Self {
    let bidi_window = params.max_streams_bidi.min(BIDI_WINDOW as u64);
    let bidi = if is_client {
      Table::new(0, BIDI_WINDOW as u64)
    } else {
      Table::new(bidi_window, bidi_window)
    };
    Self {
      bidi,
      closed: false,
      cold: Some(StreamsCold::take(params, pools)),
      ctrl: List::EMPTY,
      fin_only: 0,
      flow: ConnFlow::new(params.conn_credit()),
      is_client,
      large: List::EMPTY,
      owed: 0,
      small: List::EMPTY,
      unsent: 0,
    }
  }

  /// The limit of client-initiated bidirectional streams: given to the peer on a server, given by
  /// the peer on a client.
  #[cfg(test)]
  pub(crate) const fn bidi_limit(&self) -> u64 {
    self.bidi.meta.limit
  }

  /// The credit of the connection: (given to the peer, consumed of it, given by the peer).
  #[cfg(test)]
  pub(crate) const fn conn_credit(&self) -> (u64, u64, u64) {
    (self.flow.rx_max, self.flow.rx_consumed, self.flow.tx_max)
  }

  /// The credit given to the peer on stream `id` and what it consumed of it: (limit, consumed).
  #[cfg(test)]
  pub(crate) fn recv_credit(&self, slots: &StreamSlots, id: StreamId) -> Option<(u64, u64)> {
    let stream = slots.get(self.app_slot(id)?)?;
    Some((stream.rx.max, stream.rx.consumed))
  }

  /// The credit that the peer gives on stream `id`.
  #[cfg(test)]
  pub(crate) fn send_credit(&self, slots: &StreamSlots, id: StreamId) -> Option<u64> {
    Some(slots.get(self.app_slot(id)?)?.tx.max)
  }

  /// DATA_BLOCKED and STREAM_DATA_BLOCKED frames sent.
  #[cfg(test)]
  pub(crate) fn blocked_frames_sent(&self) -> u32 {
    self.cold.as_ref().map_or(0, |el| el.blocked_sent)
  }

  /// Stops sending DATA_BLOCKED and STREAM_DATA_BLOCKED, as some peers do.
  #[cfg(test)]
  pub(crate) fn never_send_blocked_frames(&mut self) {
    if let Some(cold) = self.cold.as_deref_mut() {
      cold.send_blocked_frames = false;
    }
  }

  /// Receive blocks held by the streams.
  #[inline]
  pub(crate) fn held_blocks(&self) -> u32 {
    self.cold.as_ref().map_or(0, |el| el.held.blocks)
  }

  /// The connection is closing: writes fail from now on.
  #[inline]
  pub(crate) const fn on_closing(&mut self) {
    self.closed = true;
  }

  /// DATA_BLOCKED: the peer has no connection credit left.
  #[inline]
  pub(crate) fn on_data_blocked(&mut self, params: &ConnParams) {
    if self.flow.rx_consumed.saturating_add(params.conn_credit()) > self.flow.rx_max {
      self.owed |= OWED_MAX_DATA;
    }
  }

  /// An acknowledged frame: data that the stream can let go, a reset that is done.
  #[inline]
  pub(crate) fn on_frame_acked(
    &mut self,
    frame: FrameRef,
    pools: &mut QuicPools,
  ) -> crate::Result<()> {
    let (slot, generation, done) = match frame {
      FrameRef::Stream { slot, generation, offset, len, fin } => {
        let QuicPools { stream_slots, tx_blocks, .. } = &mut *pools;
        let Some(stream) = stream_slots.get_live(slot, generation) else {
          return Ok(());
        };
        stream.tx.on_acked(offset, u64::from(len), fin, tx_blocks)?;
        (slot, generation, stream.tx.is_done())
      }
      FrameRef::ResetStream { slot, generation } => {
        let Some(stream) = pools.stream_slots.get_live(slot, generation) else {
          return Ok(());
        };
        stream.tx.reset_acked = true;
        (slot, generation, true)
      }
      FrameRef::Ack { .. }
      | FrameRef::Crypto { .. }
      | FrameRef::DataBlocked { .. }
      | FrameRef::HandshakeDone
      | FrameRef::MaxData { .. }
      | FrameRef::MaxStreamData { .. }
      | FrameRef::MaxStreams { .. }
      | FrameRef::StopSending { .. }
      | FrameRef::StreamDataBlocked { .. } => return Ok(()),
    };
    if done && pools.stream_slots.generation(slot) == generation {
      self.maybe_close(pools, slot);
    }
    Ok(())
  }

  /// MAX_DATA
  #[inline]
  pub(crate) fn on_max_data(&mut self, max: u64) {
    self.flow.tx_max = self.flow.tx_max.max(max);
  }

  /// MAX_STREAM_DATA
  #[inline]
  pub(crate) fn on_max_stream_data(
    &mut self,
    pools: &mut QuicPools,
    params: &ConnParams,
    id: u64,
    max: u64,
  ) -> crate::Result<()> {
    let Some(slot) = self.frame_slot(pools, params, StreamId(id), false)? else {
      return Ok(());
    };
    if let Some(stream) = pools.stream_slots.get_mut(slot) {
      stream.tx.max = stream.tx.max.max(max);
    }
    self.schedule(pools, slot);
    Ok(())
  }

  /// MAX_STREAMS
  #[inline]
  pub(crate) fn on_max_streams(&mut self, bidi: bool, max: u64) {
    // A server opens no bidirectional streams
    let kind = if bidi { Kind::Bidi } else { Kind::UniLocal };
    if (bidi && !self.is_client) || !self.is_local(kind) {
      return;
    }
    if let Some(table) = self.table_mut(kind) {
      table.meta.limit = table.meta.limit.max(max);
    }
  }

  /// The transport parameters of the peer: the credit that it gives.
  #[inline]
  pub(crate) fn on_peer_params(&mut self, peer: &TransportParams) {
    self.flow.tx_max = peer.initial_max_data;
    if self.is_client {
      self.bidi.meta.limit = peer.initial_max_streams_bidi;
    }
    let Some(cold) = self.cold.as_deref_mut() else {
      return;
    };
    cold.peer_bidi_credit = if self.is_client {
      peer.initial_max_stream_data_bidi_remote
    } else {
      peer.initial_max_stream_data_bidi_local
    };
    cold.peer_uni_credit = peer.initial_max_stream_data_uni;
    cold.uni_local.meta.limit = peer.initial_max_streams_uni;
  }

  /// RESET_STREAM: the peer abandons the sending part of a stream, whose final size counts
  /// towards the connection credit. A reset that does not answer a STOP_SENDING of ours takes a
  /// use of the reset budget.
  #[inline]
  pub(crate) fn on_reset_stream<A>(
    &mut self,
    app: &mut A,
    state: &mut A::ConnState,
    pools: &mut QuicPools,
    params: &ConnParams,
    now_us: u64,
    (id, code, final_size): (u64, u64, u64),
  ) -> crate::Result<()>
  where
    A: QuicApp,
  {
    let id = StreamId(id);
    let Some(slot) = self.frame_slot(pools, params, id, true)? else {
      return Ok(());
    };
    let QuicPools { stream_slots, rx_blocks, .. } = &mut *pools;
    let Some(stream) = stream_slots.get_mut(slot) else {
      return Ok(());
    };
    let rx = &mut stream.rx;
    if rx.final_size.is_some_and(|el| el != final_size) || final_size < rx.high {
      return Err(final_size_error());
    }
    if final_size > rx.max {
      return Err(flow_control_error());
    }
    self.flow.on_received(final_size.wrapping_sub(rx.high))?;
    rx.high = final_size;
    rx.final_size = Some(final_size);
    let counted = match rx.state {
      RxState::Recv => true,
      RxState::Discard => false,
      // A repeat, or a reset after the FIN was given
      RxState::Done | RxState::None => return Ok(()),
    };
    if let Some(cold) = self.cold.as_deref_mut() {
      rx.release(rx_blocks, &mut cold.held);
    }
    self.flow.on_consumed(final_size.saturating_sub(rx.consumed));
    rx.consumed = final_size;
    rx.read = final_size;
    rx.state = RxState::Done;
    rx.max_owed = false;
    rx.stop_owed = false;
    self.owe_max_data_if_due(params);
    if counted && !self.take_reset_budget(params, now_us) {
      return Err(excessive_load());
    }
    app.on_stream_reset(&mut ConnCtx::new(state, self, pools, params, now_us), id, code)?;
    self.maybe_close(pools, slot);
    Ok(())
  }

  /// STOP_SENDING: the peer wants nothing more on a stream, whose sending part is reset with its
  /// code. The first one of a stream takes a use of the reset budget.
  #[inline]
  pub(crate) fn on_stop_sending<A>(
    &mut self,
    app: &mut A,
    state: &mut A::ConnState,
    pools: &mut QuicPools,
    params: &ConnParams,
    now_us: u64,
    id: u64,
    code: u64,
  ) -> crate::Result<()>
  where
    A: QuicApp,
  {
    let id = StreamId(id);
    let Some(slot) = self.frame_slot(pools, params, id, false)? else {
      return Ok(());
    };
    let Some(stream) = pools.stream_slots.get_mut(slot) else {
      return Ok(());
    };
    if stream.tx.stop_counted {
      return Ok(());
    }
    stream.tx.stop_counted = true;
    if !self.take_reset_budget(params, now_us) {
      return Err(excessive_load());
    }
    app.on_stop_sending(&mut ConnCtx::new(state, self, pools, params, now_us), id, code)?;
    // RFC 9000 section 3.5
    self.reset_send(pools, slot, code);
    self.maybe_close(pools, slot);
    Ok(())
  }

  /// STREAM: data, which goes to the application in order.
  #[inline]
  pub(crate) fn on_stream<A>(
    &mut self,
    app: &mut A,
    state: &mut A::ConnState,
    pools: &mut QuicPools,
    params: &ConnParams,
    now_us: u64,
    (id, offset, data, fin): (u64, u64, &[u8], bool),
  ) -> crate::Result<()>
  where
    A: QuicApp,
  {
    let Some(slot) = self.frame_slot(pools, params, StreamId(id), true)? else {
      return Ok(());
    };
    let Some(stream) = pools.stream_slots.get_mut(slot) else {
      return Ok(());
    };
    let rx = &mut stream.rx;
    let end = offset.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
    // RFC 9000 section 4.5
    if let Some(size) = rx.final_size
      && (end > size || (fin && end != size))
    {
      return Err(final_size_error());
    }
    if fin && end < rx.high {
      return Err(final_size_error());
    }
    if end > rx.max {
      return Err(flow_control_error());
    }
    self.flow.on_received(end.saturating_sub(rx.high))?;
    rx.high = rx.high.max(end);
    if fin {
      rx.final_size = Some(end);
    }
    match rx.state {
      RxState::Recv => {}
      RxState::Discard => {
        // Counted, and dropped at once
        self.flow.on_consumed(rx.high.saturating_sub(rx.consumed));
        rx.consumed = rx.high;
        rx.read = rx.high;
        let done = rx.is_done();
        self.owe_max_data_if_due(params);
        if done {
          self.maybe_close(pools, slot);
        }
        return Ok(());
      }
      RxState::Done | RxState::None => return Ok(()),
    }
    if offset > rx.read {
      return self.store_out_of_order(pools, params, slot, offset, data);
    }
    let skip = usize::try_from(rx.read.wrapping_sub(offset)).unwrap_or(usize::MAX);
    let direct = data.get(skip..).unwrap_or_default();
    self.deliver(app, state, pools, params, now_us, slot, direct)
  }

  /// STREAM_DATA_BLOCKED: the peer has no credit left on a stream.
  #[inline]
  pub(crate) fn on_stream_data_blocked(
    &mut self,
    pools: &mut QuicPools,
    params: &ConnParams,
    id: u64,
  ) -> crate::Result<()> {
    let Some(slot) = self.frame_slot(pools, params, StreamId(id), true)? else {
      return Ok(());
    };
    let Some(stream) = pools.stream_slots.get_mut(slot) else {
      return Ok(());
    };
    let rx = &mut stream.rx;
    let more = rx.consumed.saturating_add(params.stream_credit()) > rx.max;
    if rx.state == RxState::Recv && rx.final_size.is_none() && more && !rx.max_owed {
      rx.max_owed = true;
      self.ctrl_add(&mut pools.stream_slots, slot);
    }
    Ok(())
  }

  /// STREAMS_BLOCKED: the peer has no stream credit left.
  #[inline]
  pub(crate) fn on_streams_blocked(&mut self, bidi: bool) {
    let (kind, flag) = if bidi {
      (Kind::Bidi, OWED_MAX_STREAMS_BIDI)
    } else {
      (Kind::UniRemote, OWED_MAX_STREAMS_UNI)
    };
    if self.is_local(kind) {
      return;
    }
    let more = self
      .table(kind)
      .is_some_and(|el| el.meta.base.saturating_add(el.meta.window) > el.meta.limit);
    if more {
      self.owed |= flag;
    }
  }

  /// Opens a bidirectional stream of ours, as only the client of tests does.
  #[cfg(test)]
  pub(crate) fn open_bidi(
    &mut self,
    pools: &mut QuicPools,
    params: &ConnParams,
  ) -> crate::Result<StreamId> {
    if !self.is_client {
      return Err(crate::Error::Quic(QuicError::StreamsBlocked));
    }
    self.open_local(pools, params, Kind::Bidi)
  }

  /// Opens a unidirectional stream of ours.
  #[inline]
  pub(crate) fn open_uni(
    &mut self,
    pools: &mut QuicPools,
    params: &ConnParams,
  ) -> crate::Result<StreamId> {
    self.open_local(pools, params, Kind::UniLocal)
  }

  /// Gives every stream back to the pools: the connection is over.
  #[inline]
  pub(crate) fn release(&mut self, pools: &mut QuicPools) {
    let cold = self.cold.take();
    let QuicPools { rx_blocks, stream_slots, streams_cold, tx_blocks, .. } = pools;
    let uni = cold
      .as_deref()
      .into_iter()
      .flat_map(|el| el.uni_local.slots.iter().chain(el.uni_remote.slots.iter()));
    for slot in self.bidi.slots.iter().chain(uni).copied() {
      if slot == NO_SLOT || slot == IMPLICIT {
        continue;
      }
      if let Some(stream) = stream_slots.get_mut(slot) {
        stream.rx.release(rx_blocks, &mut Held { blocks: 0, streams: 0 });
        stream.tx.release(tx_blocks);
      }
      stream_slots.free(slot);
    }
    if let Some(elem) = cold {
      streams_cold.give(elem);
    }
    self.bidi.slots = [NO_SLOT; BIDI_WINDOW];
    self.closed = true;
    self.ctrl = List::EMPTY;
    self.fin_only = 0;
    self.large = List::EMPTY;
    self.owed = 0;
    self.small = List::EMPTY;
    self.unsent = 0;
  }

  /// The reason of the close that the application asked for, if it did.
  #[inline]
  pub(crate) fn close_reason(&self) -> &[u8] {
    self
      .cold
      .as_deref()
      .and_then(|el| el.close_reason.get(..usize::from(el.close_reason_len)))
      .unwrap_or_default()
  }

  /// The application closes the connection with `code` and `reason`, of which the first 64 bytes
  /// are sent. The first request counts.
  #[inline]
  pub(crate) fn request_close(&mut self, code: u64, reason: &[u8]) {
    let Some(cold) = self.cold.as_deref_mut().filter(|el| el.close_request.is_none()) else {
      return;
    };
    let len = reason.len().min(CLOSE_REASON_LEN);
    if let Some((dst, src)) = cold.close_reason.get_mut(..len).zip(reason.get(..len)) {
      dst.copy_from_slice(src);
    }
    cold.close_reason_len = u8::try_from(len).unwrap_or(0);
    cold.close_request = Some(code);
  }

  /// Resets the sending part of stream `id`, for the application.
  #[inline]
  pub(crate) fn reset(&mut self, pools: &mut QuicPools, id: StreamId, code: u64) {
    if let Some(slot) = self.app_slot(id) {
      self.reset_send(pools, slot, code);
    }
  }

  /// Asks the peer to stop sending on stream `id`, for the application.
  #[inline]
  pub(crate) fn stop_sending(
    &mut self,
    pools: &mut QuicPools,
    params: &ConnParams,
    id: StreamId,
    code: u64,
  ) {
    let Some(slot) = self.app_slot(id) else {
      return;
    };
    let QuicPools { rx_blocks, stream_slots, .. } = &mut *pools;
    let Some(stream) = stream_slots.get_mut(slot) else {
      return;
    };
    let rx = &mut stream.rx;
    if rx.state != RxState::Recv {
      return;
    }
    if let Some(cold) = self.cold.as_deref_mut() {
      rx.release(rx_blocks, &mut cold.held);
    }
    // What arrived is consumed
    self.flow.on_consumed(rx.high.saturating_sub(rx.consumed));
    rx.consumed = rx.high;
    rx.read = rx.high;
    rx.state = RxState::Discard;
    rx.max_owed = false;
    rx.stop_code = code;
    rx.stop_owed = true;
    self.owe_max_data_if_due(params);
    self.ctrl_add(stream_slots, slot);
  }

  /// The close that the application asked for, once.
  #[inline]
  pub(crate) fn take_close_request(&mut self) -> Option<u64> {
    self.cold.as_deref_mut().and_then(|el| el.close_request.take())
  }

  /// The bytes written that were not sent yet.
  #[inline]
  pub(crate) const fn unsent(&self) -> u64 {
    self.unsent
  }

  /// If a frame is owed or data can be sent.
  #[inline]
  pub(crate) const fn wants_send(&self) -> bool {
    let ready = self.small.head != NO_LINK || self.large.head != NO_LINK;
    self.owed != 0
      || self.ctrl.head != NO_LINK
      || (ready && self.flow.tx_room() > 0)
      || self.fin_only > 0
  }

  /// Writes `source` to stream `id`, for the application.
  #[inline]
  pub(crate) fn write(
    &mut self,
    pools: &mut QuicPools,
    id: StreamId,
    source: Source<'_>,
    fin: bool,
  ) -> crate::Result<()> {
    let slot = self.app_slot(id).filter(|_| !self.closed).ok_or_else(closed)?;
    let QuicPools { stream_slots, tx_blocks, .. } = &mut *pools;
    let tx = &mut stream_slots.get_mut(slot).ok_or_else(closed)?.tx;
    if !tx.exists || tx.fin || tx.reset.is_some() {
      return Err(closed());
    }
    let len = match source {
      Source::Bytes(bytes) => {
        tx.append_bytes(bytes, tx_blocks)?;
        bytes.len()
      }
      Source::Body(body) => {
        let len = usize::try_from(body.len()).unwrap_or(usize::MAX);
        if len > 0 {
          tx.push(Seg { data: SegData::Body(body), len })?;
        }
        len
      }
    };
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    tx.end = tx.end.wrapping_add(len);
    tx.fin = fin;
    self.unsent = self.unsent.wrapping_add(len);
    self.schedule(pools, slot);
    Ok(())
  }

  /// Writes, into the 1-RTT packet of `fw`, the credit that is owed, the control frames of the
  /// streams and stream data, as much as fits, and records each frame in `frames`. Returns if it
  /// wrote anything.
  #[inline]
  pub(crate) fn write_frames(
    &mut self,
    fw: &mut FrameWriter<'_>,
    frames: &mut FrameRefRange,
    pools: &mut QuicPools,
    params: &ConnParams,
  ) -> crate::Result<bool> {
    let mut wrote = false;
    if self.write_conn_control(fw, frames, pools, params, &mut wrote)?
      && self.write_stream_control(fw, frames, pools, params, &mut wrote)?
    {
      self.write_stream_data(fw, frames, pools, &mut wrote)?;
    }
    Ok(wrote)
  }

  // The slot of stream `id` for the application, if it is open
  fn app_slot(&self, id: StreamId) -> Option<u32> {
    match self.table(self.kind(id)?)?.entry(id.index()) {
      Entry::Open(slot) => Some(slot),
      Entry::Closed | Entry::Implicit | Entry::NotOpened => None,
    }
  }

  // Checks whether MAX_STREAMS is due for the streams of the peer of `kind`
  fn check_max_streams(&mut self, kind: Kind) {
    let flag = match kind {
      Kind::Bidi if !self.is_client => OWED_MAX_STREAMS_BIDI,
      Kind::UniRemote => OWED_MAX_STREAMS_UNI,
      Kind::Bidi | Kind::UniLocal => return,
    };
    if self.table(kind).and_then(|el| el.meta.max_streams_due()).is_some() {
      self.owed |= flag;
    }
  }

  // Gives the stream in `slot` back: both parts are done
  fn close_stream(&mut self, pools: &mut QuicPools, slot: u32) {
    let QuicPools { rx_blocks, stream_slots, tx_blocks, .. } = &mut *pools;
    self.unlink_ready(stream_slots, slot);
    let in_ctrl = stream_slots.get(slot).is_some_and(|el| el.in_ctrl);
    if in_ctrl {
      self.ctrl.unlink(stream_slots, slot, true);
    }
    let Some(stream) = stream_slots.get_mut(slot) else {
      return;
    };
    let id = stream.id;
    if let Some(cold) = self.cold.as_deref_mut() {
      stream.rx.release(rx_blocks, &mut cold.held);
    }
    self.unsent = self.unsent.saturating_sub(stream.tx.end.saturating_sub(stream.tx.sent));
    stream.tx.release(tx_blocks);
    stream_slots.free(slot);
    if let Some(kind) = self.kind(id) {
      if let Some(mut table) = self.table_mut(kind) {
        table.set(id.index(), NO_SLOT);
        table.advance_base();
      }
      self.check_max_streams(kind);
    }
  }

  // Makes the stream of `index` in `kind`, in a new slot
  fn create(
    &mut self,
    pools: &mut QuicPools,
    params: &ConnParams,
    kind: Kind,
    index: u64,
  ) -> crate::Result<u32> {
    let Some(cold) = self.cold.as_deref() else {
      return Err(closed());
    };
    let (by_client, rx_max, tx_max) = match kind {
      Kind::Bidi => (true, Some(params.stream_credit()), Some(cold.peer_bidi_credit)),
      Kind::UniLocal => (self.is_client, None, Some(cold.peer_uni_credit)),
      Kind::UniRemote => (!self.is_client, Some(params.stream_credit()), None),
    };
    let slot = pools.stream_slots.alloc()?;
    if let Some(stream) = pools.stream_slots.get_mut(slot) {
      stream.open(StreamId::of(index, by_client, kind != Kind::Bidi), rx_max, tx_max);
    }
    if let Some(mut table) = self.table_mut(kind) {
      table.set(index, slot);
    }
    Ok(slot)
  }

  fn ctrl_add(&mut self, slots: &mut StreamSlots, slot: u32) {
    let Some(stream) = slots.get_mut(slot).filter(|el| !el.in_ctrl) else {
      return;
    };
    stream.in_ctrl = true;
    self.ctrl.push_back(slots, slot, true);
  }

  // Gives the application what can be given of the stream in `slot`: `direct`, the data of the
  // packet from the first byte that it was not given, then what waits in blocks, each time after
  // the bytes that it retained.
  fn deliver<A>(
    &mut self,
    app: &mut A,
    state: &mut A::ConnState,
    pools: &mut QuicPools,
    params: &ConnParams,
    now_us: u64,
    slot: u32,
    mut direct: &[u8],
  ) -> crate::Result<()>
  where
    A: QuicApp,
  {
    // Retained bytes of the slot, for a call: set up on that path only
    let mut inline: Option<[u8; INLINE_LEN]> = None;
    loop {
      if self.cold.as_ref().is_none_or(|el| el.close_request.is_some()) {
        break;
      }
      let QuicPools { rx_blocks, stream_slots, .. } = &mut *pools;
      let Some(stream) = stream_slots.get_mut(slot) else {
        break;
      };
      let id = stream.id;
      let rx = &mut stream.rx;
      if rx.state != RxState::Recv {
        break;
      }
      let Some(cold) = self.cold.as_deref_mut() else {
        break;
      };
      let held = &mut cold.held;
      rx.drop_below_read(rx_blocks, held);
      let next = rx.next_run(direct);
      let (piece, len) = if rx.keep > 0 {
        let added = if next > 0 {
          append_to_keep(rx, &mut direct, next, rx_blocks, held, &params.limits)?
        } else {
          0
        };
        let fin = rx.final_size == Some(rx.read) && direct.is_empty();
        if added == 0 && !fin {
          break;
        }
        if rx.keep_block.is_none() {
          let buffer = inline.get_or_insert_with(|| [0; INLINE_LEN]);
          if let Some((dst, src)) = buffer.get_mut(..rx.keep).zip(rx.inline.get(..rx.keep)) {
            dst.copy_from_slice(src);
          }
        }
        (Piece::Keep(rx.keep_block.take()), rx.keep)
      } else if !direct.is_empty() {
        rx.read = rx.read.wrapping_add(u64::try_from(direct.len()).unwrap_or(u64::MAX));
        (Piece::Direct, direct.len())
      } else if next > 0 {
        let no = rx.read / RX_BLOCK;
        let block = rx
          .ooo_blocks
          .binary_search_by_key(&no, |el| el.no)
          .ok()
          .and_then(|idx| rx.ooo_blocks.get_mut(idx))
          .and_then(|el| el.data.take())
          .ok_or(crate::Error::ProgrammingError)?;
        let pos = usize::try_from(rx.read % RX_BLOCK).unwrap_or(0);
        rx.read = rx.read.wrapping_add(u64::try_from(next).unwrap_or(u64::MAX));
        (Piece::Block { block, no, pos }, next)
      } else if rx.final_size == Some(rx.read) {
        (Piece::Fin, 0)
      } else {
        break;
      };
      let fin = rx.final_size == Some(rx.read) && (len > 0 || matches!(piece, Piece::Fin));
      let bytes = match &piece {
        Piece::Direct => direct,
        Piece::Keep(Some(block)) => block.get(..len).unwrap_or_default(),
        Piece::Keep(None) => inline.as_ref().and_then(|el| el.get(..len)).unwrap_or_default(),
        Piece::Block { block, pos, .. } => {
          block.get(*pos..pos.wrapping_add(len)).unwrap_or_default()
        }
        Piece::Fin => &[],
      };
      let mut cx = ConnCtx::new(state, self, pools, params, now_us);
      cx.delivered = len;
      let rslt = app.on_stream_data(&mut cx, id, bytes, fin);
      let retained = cx.retained.min(len);
      let tail = len.wrapping_sub(retained);
      let QuicPools { rx_blocks, stream_slots, .. } = &mut *pools;
      let (Some(stream), Some(cold)) = (stream_slots.get_mut(slot), self.cold.as_deref_mut())
      else {
        rslt?;
        break;
      };
      let rx = &mut stream.rx;
      let held = &mut cold.held;
      // Still receiving: the application did not fail and did not ask the peer to stop. A block
      // that was out for the call goes back in any case, before an error goes up.
      let live = rslt.is_ok() && rx.state == RxState::Recv;
      let mut kept = Ok(());
      match piece {
        Piece::Direct => {
          if live && retained > 0 {
            let bytes = direct.get(tail..).unwrap_or_default();
            kept = rx.store_keep(bytes, rx_blocks, held, &params.limits);
          }
          direct = &[];
        }
        Piece::Keep(Some(mut block)) => {
          if live && retained > 0 {
            if let Some(area) = block.get_mut(..len) {
              area.copy_within(tail.., 0);
            }
            rx.keep_block = Some(block);
          } else {
            held.give(rx_blocks, &mut rx.blocks, block);
          }
          rx.keep = if live { retained } else { 0 };
        }
        Piece::Keep(None) => {
          if live {
            if let Some(area) = rx.inline.get_mut(..len) {
              area.copy_within(tail.., 0);
            }
            rx.keep = retained;
          }
        }
        Piece::Block { block, no, pos } => {
          if live && retained > 0 {
            let bytes =
              block.get(pos.wrapping_add(tail)..pos.wrapping_add(len)).unwrap_or_default();
            kept = rx.store_keep(bytes, rx_blocks, held, &params.limits);
          }
          // Back in its place, unless the stream let go of its blocks meanwhile
          match rx.ooo_blocks.binary_search_by_key(&no, |el| el.no) {
            Ok(idx) if live => {
              if let Some(elem) = rx.ooo_blocks.get_mut(idx) {
                elem.data = Some(block);
              }
            }
            _ => held.give(rx_blocks, &mut rx.blocks, block),
          }
        }
        Piece::Fin => {}
      }
      rslt?;
      kept?;
      if live && fin {
        rx.state = RxState::Done;
        rx.release(rx_blocks, held);
      }
      if live {
        self.on_read(stream_slots, params, slot);
      }
      if !live || fin {
        break;
      }
    }
    self.maybe_close(pools, slot);
    Ok(())
  }

  // The slot of stream `id` for a frame of the peer that needs its receiving part, if `recv`, or
  // its sending part. Streams of the peer are opened, with the streams of their type below them;
  // `None` for a stream that is closed, whose frame is ignored.
  fn frame_slot(
    &mut self,
    pools: &mut QuicPools,
    params: &ConnParams,
    id: StreamId,
    recv: bool,
  ) -> crate::Result<Option<u32>> {
    // Server-initiated bidirectional streams are never opened
    let Some(kind) = self.kind(id) else {
      return Err(stream_state_error());
    };
    if (recv && kind == Kind::UniLocal) || (!recv && kind == Kind::UniRemote) {
      return Err(stream_state_error());
    }
    let index = id.index();
    let Some(table) = self.table(kind) else {
      return Ok(None);
    };
    match table.entry(index) {
      Entry::Closed => Ok(None),
      Entry::Open(slot) => Ok(Some(slot)),
      Entry::Implicit => self.create(pools, params, kind, index).map(Some),
      Entry::NotOpened => {
        if self.is_local(kind) {
          return Err(stream_state_error());
        }
        if index >= table.meta.limit {
          return Err(stream_limit_error());
        }
        if let Some(mut table) = self.table_mut(kind) {
          let mut lower = table.meta.next;
          while lower < index {
            table.set(lower, IMPLICIT);
            lower = lower.wrapping_add(1);
          }
          table.meta.next = index.wrapping_add(1);
        }
        let slot = self.create(pools, params, kind, index)?;
        self.check_max_streams(kind);
        Ok(Some(slot))
      }
    }
  }

  const fn is_local(&self, kind: Kind) -> bool {
    match kind {
      Kind::Bidi => self.is_client,
      Kind::UniLocal => true,
      Kind::UniRemote => false,
    }
  }

  // The type of stream `id`, `None` for one that a server opened in both directions
  const fn kind(&self, id: StreamId) -> Option<Kind> {
    if !id.is_uni() {
      return if id.by_client() { Some(Kind::Bidi) } else { None };
    }
    if id.by_client() == self.is_client { Some(Kind::UniLocal) } else { Some(Kind::UniRemote) }
  }

  // Closes the stream in `slot` if both of its parts are done
  fn maybe_close(&mut self, pools: &mut QuicPools, slot: u32) {
    let done = pools.stream_slots.get(slot).is_some_and(|el| el.rx.is_done() && el.tx.is_done());
    if done {
      self.close_stream(pools, slot);
    }
  }

  // The application consumed data of the stream in `slot`: its credit comes back, and with it the
  // credit of the connection
  fn on_read(&mut self, slots: &mut StreamSlots, params: &ConnParams, slot: u32) {
    let Some(stream) = slots.get_mut(slot) else {
      return;
    };
    let rx = &mut stream.rx;
    let consumed = rx.read.saturating_sub(u64::try_from(rx.keep).unwrap_or(u64::MAX));
    self.flow.on_consumed(consumed.saturating_sub(rx.consumed));
    rx.consumed = rx.consumed.max(consumed);
    let due = rx.state == RxState::Recv
      && rx.final_size.is_none()
      && !rx.max_owed
      && top_up(rx.consumed, rx.max, params.stream_credit()).is_some();
    if due {
      rx.max_owed = true;
      self.ctrl_add(slots, slot);
    }
    self.owe_max_data_if_due(params);
  }

  fn open_local(
    &mut self,
    pools: &mut QuicPools,
    params: &ConnParams,
    kind: Kind,
  ) -> crate::Result<StreamId> {
    if self.closed {
      return Err(closed());
    }
    let Some(table) = self.table_mut(kind) else {
      return Err(closed());
    };
    let meta = &mut *table.meta;
    let index = meta.next;
    if index >= meta.limit || index.wrapping_sub(meta.base) >= meta.window {
      cold_path();
      return Err(crate::Error::Quic(QuicError::StreamsBlocked));
    }
    meta.next = index.wrapping_add(1);
    let slot = self.create(pools, params, kind, index)?;
    pools.stream_slots.get(slot).map(|el| el.id).ok_or(crate::Error::ProgrammingError)
  }

  fn owe_max_data_if_due(&mut self, params: &ConnParams) {
    if self.flow.max_data_due(params.conn_credit()).is_some() {
      self.owed |= OWED_MAX_DATA;
    }
  }

  // Resets the sending part of the stream in `slot` with `code`, if it is not done
  fn reset_send(&mut self, pools: &mut QuicPools, slot: u32, code: u64) {
    let QuicPools { stream_slots, tx_blocks, .. } = &mut *pools;
    let Some(stream) = stream_slots.get_mut(slot) else {
      return;
    };
    let tx = &mut stream.tx;
    if !tx.exists || tx.reset.is_some() || tx.is_done() {
      return;
    }
    // What was not sent is not sent, and the final size is what was
    self.unsent = self.unsent.saturating_sub(tx.end.saturating_sub(tx.sent));
    tx.end = tx.sent;
    tx.reset = Some(code);
    tx.reset_owed = true;
    tx.blocked_owed = false;
    tx.release(tx_blocks);
    self.ctrl_add(stream_slots, slot);
    self.schedule(pools, slot);
  }

  // Puts the stream in `slot` in the list that its next bytes call for, or in none, and owes
  // STREAM_DATA_BLOCKED, once per limit, if its credit holds them back
  fn schedule(&mut self, pools: &mut QuicPools, slot: u32) {
    let slots = &mut pools.stream_slots;
    let Some(stream) = slots.get_mut(slot) else {
      return;
    };
    let tx = &mut stream.tx;
    let has_data = tx.sent < tx.end;
    let wants = tx.exists && tx.reset.is_none() && (has_data || (tx.fin && !tx.fin_sent));
    let blocked = has_data && tx.sent >= tx.max;
    #[cfg(test)]
    let send_blocked = self.cold.as_ref().is_some_and(|el| el.send_blocked_frames);
    #[cfg(not(test))]
    let send_blocked = true;
    let owe_blocked = blocked && send_blocked && tx.blocked_at != tx.max && !tx.blocked_owed;
    tx.blocked_owed |= owe_blocked;
    let target = if !wants || blocked {
      None
    } else if tx.next_is_body() {
      Some(Ready::Large)
    } else {
      Some(Ready::Small)
    };
    let fin_only = target == Some(Ready::Small) && !has_data;
    if stream.ready_in != target {
      self.unlink_ready(slots, slot);
      if let Some(list) = target {
        if let Some(elem) = slots.get_mut(slot) {
          elem.ready_in = Some(list);
        }
        match list {
          Ready::Small => self.small.push_back(slots, slot, false),
          Ready::Large => self.large.push_back(slots, slot, false),
        }
      }
    }
    // After the move, which forgets it
    if let Some(elem) = slots.get_mut(slot)
      && elem.fin_only != fin_only
    {
      elem.fin_only = fin_only;
      self.fin_only =
        if fin_only { self.fin_only.wrapping_add(1) } else { self.fin_only.saturating_sub(1) };
    }
    if owe_blocked {
      self.ctrl_add(slots, slot);
    }
    // Data that the connection credit holds back
    if target.is_some() && has_data && self.flow.tx_room() == 0 {
      self.owe_data_blocked();
    }
  }

  // Received data that waits for the data before it, copied into the blocks of the stream
  fn store_out_of_order(
    &mut self,
    pools: &mut QuicPools,
    params: &ConnParams,
    slot: u32,
    offset: u64,
    data: &[u8],
  ) -> crate::Result<()> {
    if data.is_empty() {
      return Ok(());
    }
    let limits = &params.limits;
    let QuicPools { rx_blocks, stream_slots, .. } = &mut *pools;
    let Some(stream) = stream_slots.get_mut(slot) else {
      return Ok(());
    };
    let rx = &mut stream.rx;
    let end = offset.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
    let reach =
      end.saturating_sub(rx.read).saturating_add(u64::try_from(rx.keep).unwrap_or(u64::MAX));
    if reach > u64::from(limits.max_out_of_order_bytes_per_stream) {
      return Err(out_of_order_limit());
    }
    rx.ooo.insert(offset, end)?;
    if rx.ooo.len() > usize::try_from(limits.max_out_of_order_ranges).unwrap_or(usize::MAX) {
      return Err(out_of_order_limit());
    }
    let (mut at, mut rest) = (offset, data);
    while !rest.is_empty() {
      let no = at / RX_BLOCK;
      let pos = usize::try_from(at % RX_BLOCK).unwrap_or(0);
      let idx = match rx.ooo_blocks.binary_search_by_key(&no, |el| el.no) {
        Ok(idx) => idx,
        Err(idx) => {
          let held = self.cold.as_deref_mut().map(|el| &mut el.held).ok_or_else(closed)?;
          let block = held.take(rx_blocks, &mut rx.blocks, limits)?;
          rx.ooo_blocks.try_reserve(1).map_err(|_err| exhausted())?;
          rx.ooo_blocks.insert(idx, OooBlock { data: Some(block), no });
          idx
        }
      };
      let block = rx
        .ooo_blocks
        .get_mut(idx)
        .and_then(|el| el.data.as_deref_mut())
        .ok_or(crate::Error::ProgrammingError)?;
      let take = rest.len().min(RX_BLOCK_LEN.wrapping_sub(pos));
      let (head, tail) = rest.split_at_checked(take).unwrap_or_default();
      if let Some(dst) = block.get_mut(pos..pos.wrapping_add(head.len())) {
        dst.copy_from_slice(head);
      }
      at = at.wrapping_add(u64::try_from(head.len()).unwrap_or(u64::MAX));
      rest = tail;
    }
    Ok(())
  }

  fn take_reset_budget(&mut self, params: &ConnParams, now_us: u64) -> bool {
    let budget = params.limits.reset_budget;
    self
      .cold
      .as_deref_mut()
      .is_some_and(|el| el.resets.take_within(budget, RESET_WINDOW_US, now_us))
  }

  // The table of `kind`, unless the streams were released
  fn table(&self, kind: Kind) -> Option<TableRef<'_>> {
    match kind {
      Kind::Bidi => Some(self.bidi.view_ref()),
      Kind::UniLocal => self.cold.as_deref().map(|el| el.uni_local.view_ref()),
      Kind::UniRemote => self.cold.as_deref().map(|el| el.uni_remote.view_ref()),
    }
  }

  fn table_mut(&mut self, kind: Kind) -> Option<TableMut<'_>> {
    match kind {
      Kind::Bidi => Some(self.bidi.view()),
      Kind::UniLocal => self.cold.as_deref_mut().map(|el| el.uni_local.view()),
      Kind::UniRemote => self.cold.as_deref_mut().map(|el| el.uni_remote.view()),
    }
  }

  fn unlink_ready(&mut self, slots: &mut StreamSlots, slot: u32) {
    let Some(stream) = slots.get_mut(slot) else {
      return;
    };
    let Some(list) = stream.ready_in.take() else {
      return;
    };
    if core::mem::take(&mut stream.fin_only) {
      self.fin_only = self.fin_only.saturating_sub(1);
    }
    match list {
      Ready::Small => self.small.unlink(slots, slot, false),
      Ready::Large => self.large.unlink(slots, slot, false),
    }
  }

  fn write_conn_control(
    &mut self,
    fw: &mut FrameWriter<'_>,
    frames: &mut FrameRefRange,
    pools: &mut QuicPools,
    params: &ConnParams,
    wrote: &mut bool,
  ) -> crate::Result<bool> {
    if self.owed & OWED_MAX_DATA != 0 {
      let max = self.flow.rx_consumed.saturating_add(params.conn_credit());
      if max > self.flow.rx_max {
        if !fw.write_max_data(max) {
          return Ok(false);
        }
        pools.frame_refs.push(frames, FrameRef::MaxData { max })?;
        self.flow.rx_max = max;
        *wrote = true;
      }
      self.owed &= !OWED_MAX_DATA;
    }
    for (flag, bidi) in [(OWED_MAX_STREAMS_BIDI, true), (OWED_MAX_STREAMS_UNI, false)] {
      if self.owed & flag == 0 {
        continue;
      }
      let kind = if bidi { Kind::Bidi } else { Kind::UniRemote };
      if let Some(table) = self.table_mut(kind) {
        let meta = table.meta;
        let max = meta.base.saturating_add(meta.window);
        if max > meta.limit {
          if !fw.write_max_streams(bidi, max) {
            return Ok(false);
          }
          pools.frame_refs.push(frames, FrameRef::MaxStreams { bidi, max })?;
          meta.limit = max;
          *wrote = true;
        }
      }
      self.owed &= !flag;
    }
    if self.owed & OWED_DATA_BLOCKED != 0 {
      let max = self.flow.tx_max;
      if self.flow.tx_room() == 0 && self.flow.tx_blocked_at != max {
        if !fw.write_frame(&Frame::DataBlocked(max)) {
          return Ok(false);
        }
        pools.frame_refs.push(frames, FrameRef::DataBlocked { max })?;
        self.flow.tx_blocked_at = max;
        *wrote = true;
        #[cfg(test)]
        if let Some(cold) = self.cold.as_deref_mut() {
          cold.blocked_sent = cold.blocked_sent.wrapping_add(1);
        }
      }
      self.owed &= !OWED_DATA_BLOCKED;
    }
    Ok(true)
  }

  // A STREAM frame of the stream in `slot` with as much as the packet, the credit and the data
  // allow
  fn write_stream_frame(
    &mut self,
    fw: &mut FrameWriter<'_>,
    frames: &mut FrameRefRange,
    pools: &mut QuicPools,
    slot: u32,
  ) -> crate::Result<Wrote> {
    let QuicPools { frame_refs, stream_slots, .. } = &mut *pools;
    let generation = stream_slots.generation(slot);
    let Some(stream) = stream_slots.get_mut(slot) else {
      return Ok(Wrote::Blocked);
    };
    let id = stream.id.0;
    let tx = &mut stream.tx;
    let unsent = tx.end.saturating_sub(tx.sent);
    let fin_pending = tx.fin && !tx.fin_sent;
    let credit = tx.max.saturating_sub(tx.sent).min(self.flow.tx_room());
    let allowed = unsent.min(credit);
    if allowed == 0 && !(fin_pending && unsent == 0) {
      if unsent > 0 && self.flow.tx_room() == 0 {
        self.owe_data_blocked();
      }
      return Ok(Wrote::Blocked);
    }
    let offset = tx.sent;
    let room = fw.remaining();
    let longest = usize::try_from(allowed).unwrap_or(usize::MAX).min(room);
    let offset_len = if offset == 0 { 0 } else { varint_len(offset) };
    let header = 1usize
      .wrapping_add(varint_len(id))
      .wrapping_add(offset_len)
      .wrapping_add(varint_len(u64::try_from(longest).unwrap_or(u64::MAX)));
    let Some(data_len) = room.checked_sub(header).map(|el| el.min(longest)) else {
      return Ok(Wrote::Full);
    };
    if data_len == 0 && allowed > 0 {
      return Ok(Wrote::Full);
    }
    let len = u64::try_from(data_len).unwrap_or(u64::MAX);
    let fin = fin_pending && len == unsent;
    if !fw.write_stream_header(id, offset, data_len, fin) {
      return Ok(Wrote::Full);
    }
    tx.copy_unsent(data_len, fw);
    tx.sent = tx.sent.wrapping_add(len);
    tx.fin_sent |= fin;
    let more = tx.sent < tx.end;
    self.flow.tx_sent = self.flow.tx_sent.wrapping_add(len);
    self.unsent = self.unsent.saturating_sub(len);
    let len = u16::try_from(data_len).unwrap_or(u16::MAX);
    frame_refs.push(frames, FrameRef::Stream { slot, generation, offset, len, fin })?;
    if more && self.flow.tx_room() == 0 {
      self.owe_data_blocked();
    }
    Ok(Wrote::Frame)
  }

  fn owe_data_blocked(&mut self) {
    #[cfg(test)]
    if self.cold.as_ref().is_some_and(|el| !el.send_blocked_frames) {
      return;
    }
    if self.flow.tx_blocked_at != self.flow.tx_max {
      self.owed |= OWED_DATA_BLOCKED;
    }
  }

  fn write_stream_control(
    &mut self,
    fw: &mut FrameWriter<'_>,
    frames: &mut FrameRefRange,
    pools: &mut QuicPools,
    params: &ConnParams,
    wrote: &mut bool,
  ) -> crate::Result<bool> {
    loop {
      let slot = self.ctrl.head;
      let QuicPools { frame_refs, stream_slots, .. } = &mut *pools;
      let generation = stream_slots.generation(slot);
      let Some(stream) = stream_slots.get_mut(slot) else {
        return Ok(true);
      };
      let id = stream.id.0;
      let (rx, tx) = (&mut stream.rx, &mut stream.tx);
      if tx.reset_owed {
        let code = tx.reset.unwrap_or(0);
        if !fw.write_frame(&Frame::ResetStream { id, code, final_size: tx.end }) {
          return Ok(false);
        }
        frame_refs.push(frames, FrameRef::ResetStream { slot, generation })?;
        tx.reset_owed = false;
        *wrote = true;
      }
      if rx.stop_owed {
        if !fw.write_frame(&Frame::StopSending { id, code: rx.stop_code }) {
          return Ok(false);
        }
        frame_refs.push(frames, FrameRef::StopSending { slot, generation })?;
        rx.stop_owed = false;
        *wrote = true;
      }
      if rx.max_owed {
        let max = rx.consumed.saturating_add(params.stream_credit());
        if rx.state == RxState::Recv && rx.final_size.is_none() && max > rx.max {
          if !fw.write_max_stream_data(id, max) {
            return Ok(false);
          }
          frame_refs.push(frames, FrameRef::MaxStreamData { slot, generation })?;
          rx.max = max;
          *wrote = true;
        }
        rx.max_owed = false;
      }
      if tx.blocked_owed {
        let max = tx.max;
        if tx.sent >= max && tx.sent < tx.end && tx.blocked_at != max {
          if !fw.write_frame(&Frame::StreamDataBlocked { id, max }) {
            return Ok(false);
          }
          frame_refs.push(frames, FrameRef::StreamDataBlocked { slot, generation })?;
          tx.blocked_at = max;
          *wrote = true;
          #[cfg(test)]
          if let Some(cold) = self.cold.as_deref_mut() {
            cold.blocked_sent = cold.blocked_sent.wrapping_add(1);
          }
        }
        tx.blocked_owed = false;
      }
      stream.in_ctrl = false;
      self.ctrl.unlink(stream_slots, slot, true);
      // A part that this ended, such as a STOP_SENDING once the final size is known
      self.maybe_close(pools, slot);
    }
  }

  fn write_stream_data(
    &mut self,
    fw: &mut FrameWriter<'_>,
    frames: &mut FrameRefRange,
    pools: &mut QuicPools,
    wrote: &mut bool,
  ) -> crate::Result<()> {
    // Bytes written by copy: a frame for each stream in turn, those that are sent from go to the
    // end of the list
    let last = self.small.tail;
    let mut slot = self.small.head;
    while slot != NO_LINK {
      let next = pools.stream_slots.get(slot).map_or(NO_LINK, |el| el.ready.next);
      match self.write_stream_frame(fw, frames, pools, slot)? {
        Wrote::Full => return Ok(()),
        // Waits for connection credit
        Wrote::Blocked => {}
        Wrote::Frame => {
          *wrote = true;
          self.unlink_ready(&mut pools.stream_slots, slot);
          self.schedule(pools, slot);
        }
      }
      if slot == last {
        break;
      }
      slot = next;
    }
    // Bodies: one stream at a time, to its end
    loop {
      let slot = self.large.head;
      if slot == NO_LINK {
        return Ok(());
      }
      match self.write_stream_frame(fw, frames, pools, slot)? {
        Wrote::Full | Wrote::Blocked => return Ok(()),
        Wrote::Frame => {
          *wrote = true;
          self.schedule(pools, slot);
        }
      }
    }
  }
}

// Adds to the retained bytes, which take a block once they do not fit inline, the next `next`
// bytes: from `direct` if it has any, from the waiting data otherwise. Returns how many.
fn append_to_keep(
  rx: &mut RecvPart,
  direct: &mut &[u8],
  next: usize,
  blocks: &mut FreeList<Box<RxBlock>>,
  held: &mut Held,
  limits: &QuicLimits,
) -> crate::Result<usize> {
  let RecvPart { blocks: own, inline, keep, keep_block, ooo_blocks, read, .. } = rx;
  if keep_block.is_none() && keep.wrapping_add(next) > INLINE_LEN {
    let mut block = held.take(blocks, own, limits)?;
    if let Some((dst, src)) = block.get_mut(..*keep).zip(inline.get(..*keep)) {
      dst.copy_from_slice(src);
    }
    *keep_block = Some(block);
  }
  let area: &mut [u8] = match keep_block {
    Some(block) => block.as_mut_slice(),
    None => inline.as_mut_slice(),
  };
  let room = area.len().wrapping_sub(*keep);
  if room == 0 {
    cold_path();
    return Err(crate::Error::QuicClose(
      TransportErrorCode::InternalError,
      QuicError::RetainTooLong,
    ));
  }
  let added = room.min(next);
  let Some(dst) = area.get_mut(*keep..keep.wrapping_add(added)) else {
    return Err(crate::Error::ProgrammingError);
  };
  if direct.is_empty() {
    let no = *read / RX_BLOCK;
    let pos = usize::try_from(*read % RX_BLOCK).unwrap_or(0);
    let src = ooo_blocks
      .binary_search_by_key(&no, |el| el.no)
      .ok()
      .and_then(|idx| ooo_blocks.get(idx))
      .and_then(|el| el.data.as_deref())
      .and_then(|el| el.get(pos..pos.wrapping_add(added)))
      .ok_or(crate::Error::ProgrammingError)?;
    dst.copy_from_slice(src);
  } else {
    let Some((head, tail)) = direct.split_at_checked(added) else {
      return Err(crate::Error::ProgrammingError);
    };
    dst.copy_from_slice(head);
    *direct = tail;
  }
  *read = read.wrapping_add(u64::try_from(added).unwrap_or(u64::MAX));
  *keep = keep.wrapping_add(added);
  Ok(added)
}

// The entry of stream `index` in an index array of `len` entries
fn pos(len: usize, index: u64) -> usize {
  usize::try_from(index % u64::try_from(len).unwrap_or(u64::MAX).max(1)).unwrap_or(0)
}

#[inline(always)]
fn closed() -> crate::Error {
  cold_path();
  crate::Error::Quic(QuicError::StreamClosed)
}

#[inline(always)]
fn excessive_load() -> crate::Error {
  cold_path();
  crate::Error::QuicClose(TransportErrorCode::ApplicationError, QuicError::ExcessiveLoad)
}

#[inline(always)]
fn exhausted() -> crate::Error {
  cold_path();
  crate::Error::QuicClose(TransportErrorCode::InternalError, QuicError::PoolExhausted)
}

#[inline(always)]
fn final_size_error() -> crate::Error {
  cold_path();
  crate::Error::QuicClose(TransportErrorCode::FinalSizeError, QuicError::FinalSizeChanged)
}

#[inline(always)]
fn out_of_order_limit() -> crate::Error {
  cold_path();
  crate::Error::QuicClose(TransportErrorCode::ProtocolViolation, QuicError::OutOfOrderLimit)
}

#[inline(always)]
fn stream_limit_error() -> crate::Error {
  cold_path();
  crate::Error::QuicClose(TransportErrorCode::StreamLimitError, QuicError::StreamLimitExceeded)
}

#[inline(always)]
fn stream_state_error() -> crate::Error {
  cold_path();
  crate::Error::QuicClose(TransportErrorCode::StreamStateError, QuicError::StreamStateInvalid)
}

#[cfg(test)]
mod tests {
  use crate::{
    quic::{
      BodyRef, ConnState, Frame, QuicError, StreamId, TransportErrorCode,
      stream::{RangeSet, StreamSlots},
      testing::{Behavior, Link, LinkOpts, TestApp, encode_frames},
    },
    sync::AtomicU64,
    tests::_count_allocations_in,
  };
  use alloc::{rc::Rc, vec, vec::Vec};
  use core::sync::atomic::Ordering;

  // A response that takes a block of the send queue
  const LARGE: &[u8; 1000] = &[b'l'; 1000];
  const RESPONSE: &[u8; 14] = b"HTTP/3 200 ok!";

  fn settled(opts: &LinkOpts) -> Link {
    let mut link = Link::new(opts);
    link.run();
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    assert_eq!(link.client.conn.state(), ConnState::Confirmed);
    link
  }

  // The client sends `frames`, raw, in one packet, which the server receives.
  fn client_sends(link: &mut Link, frames: &[Frame<'_>]) {
    link.client.conn.queue_test_frames(&encode_frames(frames));
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
  }

  // The class and the code of the CONNECTION_CLOSE that the server owes: (application, code).
  fn server_close(link: &Link) -> Option<(bool, u64)> {
    link.server.conn.close_code()
  }

  fn transport(code: TransportErrorCode) -> Option<(bool, u64)> {
    Some((false, code.code()))
  }

  fn open_bidi(link: &mut Link) -> crate::Result<StreamId> {
    let now_us = link.now_us;
    link.client.with_ctx(now_us, |cx| cx.open_bidi())
  }

  fn write(link: &mut Link, id: StreamId, bytes: &[u8], fin: bool) {
    let now_us = link.now_us;
    link.client.with_ctx(now_us, |cx| cx.write(id, bytes, fin)).unwrap();
  }

  // Requests of the client, `total` of them and at most `concurrent` at once, each `request(nth)`
  // with the FIN; returns the responses in the order of the requests. With `never_blocked` the
  // client must always have the stream credit to open the next one, and each MAX_STREAMS that it
  // receives must come with responses.
  fn run_requests(
    link: &mut Link,
    total: usize,
    concurrent: usize,
    request: impl Fn(usize) -> Vec<u8>,
    never_blocked: bool,
  ) -> Vec<Vec<u8>> {
    let mut pending: Vec<(usize, StreamId)> = Vec::new();
    let mut responses = vec![Vec::new(); total];
    let (mut opened, mut done) = (0, 0);
    for _ in 0..total * 16 + 64 {
      let mut idx = 0;
      while let Some(&(nth, id)) = pending.get(idx) {
        if link.client.app.streams.get(&id.0).is_some_and(|el| el.fin) {
          responses[nth] = link.client.app.streams.remove(&id.0).unwrap().data;
          let _ = pending.swap_remove(idx);
          done += 1;
        } else {
          idx += 1;
        }
      }
      if done == total {
        return responses;
      }
      while pending.len() < concurrent && opened < total {
        let bytes = request(opened);
        let now_us = link.now_us;
        let rslt = link.client.with_ctx(now_us, |cx| {
          let id = cx.open_bidi()?;
          cx.write(id, &bytes, true)?;
          Ok::<_, crate::Error>(id)
        });
        match rslt {
          Ok(id) => {
            pending.push((opened, id));
            opened += 1;
          }
          Err(err) => {
            assert!(!never_blocked, "the client was blocked at request {opened}: {err:?}");
            break;
          }
        }
      }
      let _ = link.client.flush(link.now_us);
      let _ = link.deliver_to_server();
      let _ = link.server.flush(link.now_us);
      let limit = link.client.conn.streams().bidi_limit();
      let fins = link.client.app.fins;
      let _ = link.deliver_to_client();
      if never_blocked && link.client.conn.streams().bidi_limit() > limit {
        assert!(link.client.app.fins > fins, "a MAX_STREAMS came without responses");
      }
    }
    panic!("{done} of {total} requests done");
  }

  // Rule: the ranges are exact, and one more separate range than there is room for is an error
  // that loses nothing of what is held.
  #[test]
  fn range_set_overflow_is_error_not_loss() {
    let ranges = |set: &RangeSet<4>| set.iter().collect::<Vec<_>>();
    let mut set = RangeSet::<4>::new();
    for nth in 0..4u64 {
      set.insert(nth * 10, nth * 10 + 5).unwrap();
    }
    let before = ranges(&set);
    assert!(matches!(
      set.insert(100, 105),
      Err(crate::Error::QuicClose(TransportErrorCode::ProtocolViolation, QuicError::RangeSetFull))
    ));
    assert_eq!(ranges(&set), before);
    // A range that touches or overlaps held ones joins them; no gap is ever filled
    set.insert(5, 10).unwrap();
    assert_eq!(ranges(&set), [(0, 15), (20, 25), (30, 35)]);
    set.insert(100, 105).unwrap();
    set.insert(22, 33).unwrap();
    assert_eq!(ranges(&set), [(0, 15), (20, 35), (100, 105)]);
    // Held bytes and empty ranges change nothing, even when full
    set.insert(200, 201).unwrap();
    set.insert(1, 3).unwrap();
    set.insert(50, 50).unwrap();
    assert_eq!(ranges(&set), [(0, 15), (20, 35), (100, 105), (200, 201)]);
    set.remove_below(12);
    assert_eq!(ranges(&set), [(12, 15), (20, 35), (100, 105), (200, 201)]);
    set.remove_below(101);
    assert_eq!(ranges(&set), [(101, 105), (200, 201)]);
    set.remove_below(300);
    assert!(set.is_empty());
  }

  // A freed slot is used again, with a new generation that frame references of the stream that
  // left it do not match, and an idle trim keeps a few slots once none is in use.
  #[test]
  fn stream_slots_reuse_with_generations_and_trim_at_idle() {
    let mut slots = StreamSlots::new();
    let taken: Vec<u32> = (0..100).map(|_| slots.alloc().unwrap()).collect();
    assert_eq!(slots.live(), 100);
    let generation = slots.generation(taken[7]);
    slots.free(taken[7]);
    assert!(slots.get(taken[7]).is_none());
    assert_eq!(slots.alloc().unwrap(), taken[7]);
    assert!(slots.get_live(taken[7], generation).is_none());
    assert!(slots.get_live(taken[7], generation.wrapping_add(1)).is_some());
    // Not trimmed while in use
    slots.trim_idle(64);
    assert_eq!(slots.entries.len(), 100);
    for slot in taken {
      slots.free(slot);
    }
    assert_eq!(slots.live(), 0);
    slots.trim_idle(64);
    assert_eq!(slots.entries.len(), 64);
    let again: Vec<u32> = (0..64).map(|_| slots.alloc().unwrap()).collect();
    assert_eq!(slots.entries.len(), 64);
    assert!(again.iter().all(|el| *el < 64));
    // A slot made again after a trim does not take a generation that its index had: a frame
    // reference of a stream of before can not match the stream that is there now
    let last = 99;
    for _ in 0..36 {
      let _slot = slots.alloc().unwrap();
    }
    assert!(slots.get(last).is_some());
    for generation in 0..=1 {
      assert!(slots.get_live(last, generation).is_none(), "{generation}");
    }
  }

  // 1,000 requests of 100 bytes, 64 at a time, come back whole on their streams: four times the
  // streams that the first credit allows.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn echo_app_many_streams() {
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Echo);
    let mut link = settled(&opts);
    let request = |nth: usize| (0..100).map(|el| (nth * 7 + el) as u8).collect::<Vec<_>>();
    let responses = run_requests(&mut link, 1000, 64, request, false);
    for (nth, response) in responses.iter().enumerate() {
      assert_eq!(*response, request(nth), "{nth}");
    }
    assert_eq!(link.server.app.fins, 1000);
    link.run();
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
  }

  // STREAM frames out of order, duplicated and overlapping, over several blocks, reach the
  // application once each, in order, with the FIN after the last byte.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn out_of_order_and_duplicate_stream_data_reassembled() {
    let mut link = settled(&LinkOpts::new(None));
    let id = open_bidi(&mut link).unwrap();
    let data: Vec<u8> = (0..20_000u32).map(|el| (el % 251) as u8).collect();
    let piece = |nth: usize| (nth * 1000, 1000);
    let mut order: Vec<(usize, usize)> = (0..20).map(|el| piece(el * 7 % 20)).collect();
    // Duplicates and pieces that overlap others
    order.insert(5, piece(1));
    order.insert(9, (500, 1000));
    order.insert(13, (8_100, 950));
    order.push(piece(0));
    for (offset, len) in order {
      let fin = offset + len == data.len();
      let frame =
        Frame::Stream { id: id.0, offset: offset as u64, data: &data[offset..][..len], fin };
      client_sends(&mut link, &[frame]);
      assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    }
    let log = &link.server.app.streams[&id.0];
    assert!(log.fin);
    assert_eq!(log.data, data);
    // Each byte once
    assert_eq!(log.calls.iter().map(|el| el.0).sum::<usize>(), data.len());
    assert_eq!(log.calls.iter().filter(|el| el.1).count(), 1);
    // Nothing is held anymore
    assert_eq!(link.server.conn.streams().held_blocks(), 0);
    assert!(link.server.parts.pools.rx_blocks.len() > 0);
  }

  // 64 responses of 14 bytes go out in a single packet, a STREAM frame each with its FIN.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn small_responses_pack_many_per_packet() {
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Respond(RESPONSE));
    let mut link = settled(&opts);
    let mut ids = Vec::new();
    for _ in 0..64 {
      let id = open_bidi(&mut link).unwrap();
      write(&mut link, id, b"GET /", true);
      ids.push(id);
    }
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    assert_eq!(link.server.app.fins, 64);
    let before = link.server.conn.stats().packets_out;
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.server.conn.stats().packets_out - before, 1);
    assert_eq!(link.deliver_to_client(), 1);
    for id in ids {
      let log = &link.client.app.streams[&id.0];
      assert_eq!((log.data.as_slice(), log.fin), (RESPONSE.as_slice(), true));
      assert_eq!(log.calls, [(14, true)]);
    }
  }

  // The FIN is on the frame with the last bytes, in both directions: after a small response, a
  // body of several packets, and data whose FIN was written apart from it.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn fin_rides_on_last_data_frame() {
    let body: Rc<[u8]> = (0..10_000u32).map(|el| el as u8).collect();
    let fin_on_the_last = |calls: &[(usize, bool)]| {
      let (last, rest) = calls.split_last().unwrap();
      assert!(last.0 > 0 && last.1, "{calls:?}");
      assert!(rest.iter().all(|el| el.0 > 0 && !el.1), "{calls:?}");
    };
    let body_ref = BodyRef::new(body.clone(), 0..10_000).unwrap();
    let mixed = Behavior::Mixed { small: RESPONSE, body: body_ref, large: LARGE };
    for server_app in [TestApp::default(), TestApp::new(mixed)] {
      let collects = matches!(server_app.behavior, Behavior::Collect);
      let mut opts = LinkOpts::new(None);
      opts.server_app = server_app;
      let mut link = settled(&opts);
      let mut ids = Vec::new();
      for _ in 0..2 {
        let id = open_bidi(&mut link).unwrap();
        write(&mut link, id, b"GET /", false);
        write(&mut link, id, b" HTTP/3", false);
        write(&mut link, id, b"", true);
        ids.push(id);
      }
      link.run();
      if collects {
        for id in &ids {
          let log = &link.server.app.streams[&id.0];
          assert_eq!(log.data, b"GET / HTTP/3");
          fin_on_the_last(&log.calls);
        }
        continue;
      }
      let logs = [&link.client.app.streams[&ids[0].0], &link.client.app.streams[&ids[1].0]];
      assert_eq!(logs[0].data, RESPONSE);
      assert_eq!(logs[1].data, *body);
      assert!(logs[1].calls.len() >= 9, "{:?}", logs[1].calls);
      for log in logs {
        fin_on_the_last(&log.calls);
      }
    }
  }

  // The client, 64 requests at a time, never runs out of stream credit: MAX_STREAMS comes with the
  // responses, past stream 300.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn max_streams_topped_up_in_response_packet() {
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Respond(RESPONSE));
    let mut link = settled(&opts);
    let responses = run_requests(&mut link, 400, 64, |_| b"GET /".to_vec(), true);
    assert!(responses.iter().all(|el| el == RESPONSE));
    assert!(link.client.conn.streams().bidi_limit() > 400);
  }

  // A body sent by reference is held until the packets that carry it are acknowledged, then let
  // go, while its stream stays open; so is one that ends a stream.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn body_ref_released_on_ack() {
    let body: Rc<[u8]> = vec![9; 5000].into();
    let mut link = settled(&LinkOpts::new(None));
    let id = open_bidi(&mut link).unwrap();
    write(&mut link, id, b"GET /", false);
    link.run();
    for fin in [false, true] {
      let now_us = link.now_us;
      let response = BodyRef::new(body.clone(), 100..4100).unwrap();
      link.server.with_ctx(now_us, |cx| cx.write_body(id, response, fin)).unwrap();
      let _ = link.server.flush(link.now_us);
      // Sent, not acknowledged
      assert_eq!(Rc::strong_count(&body), 2);
      assert!(link.deliver_to_client() > 0);
      let _ = link.client.flush(link.now_us);
      assert!(link.deliver_to_server() > 0);
      assert_eq!(Rc::strong_count(&body), 1, "{fin}");
    }
    let log = &link.client.app.streams[&id.0];
    assert_eq!((log.data.len(), log.fin), (8000, true));
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
  }

  // A stream written again once its bytes were sent, before they are acknowledged: the next frame
  // carries the new bytes, inline or after those of a block, the frame of another stream that
  // follows it in the packet keeps its own, and the acknowledgments let go of the block and of the
  // body.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn write_after_send_before_ack_carries_the_new_bytes() {
    for first_len in [5, 300] {
      let mut link = settled(&LinkOpts::new(None));
      let blocks = link.client.parts.pools.tx_blocks.len();
      let body: Rc<[u8]> = vec![7; 50].into();
      let first = vec![b'a'; first_len];
      let id = open_bidi(&mut link).unwrap();
      write(&mut link, id, &first, false);
      // Sent, not acknowledged
      let _ = link.client.flush(link.now_us);
      let other = open_bidi(&mut link).unwrap();
      write(&mut link, id, b" more", true);
      let now_us = link.now_us;
      let response = BodyRef::new(body.clone(), 0..50).unwrap();
      link.client.with_ctx(now_us, |cx| cx.write_body(other, response, true)).unwrap();
      let before = link.client.conn.stats().packets_out;
      let _ = link.client.flush(link.now_us);
      // Both frames in one packet, the body after the bytes
      assert_eq!(link.client.conn.stats().packets_out - before, 1);
      link.run();
      assert_eq!(link.server.conn.state(), ConnState::Confirmed, "{first_len}");
      let mut expected = first.clone();
      expected.extend_from_slice(b" more");
      let log = &link.server.app.streams[&id.0];
      assert_eq!((log.data.as_slice(), log.fin), (expected.as_slice(), true));
      let log = &link.server.app.streams[&other.0];
      assert_eq!((log.data.as_slice(), log.fin), (&*body, true));
      assert_eq!(Rc::strong_count(&body), 1);
      assert_eq!(link.client.parts.pools.tx_blocks.len(), blocks + usize::from(first_len > 256));
    }
  }

  // 100 streams that the client abandons, with RESET_STREAM or STOP_SENDING, are within the
  // budget of ten seconds; one more closes the connection with H3_EXCESSIVE_LOAD.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn reset_churn_budget_closes_connection() {
    let mut link = settled(&LinkOpts::new(None));
    let abandon = |link: &mut Link, nth: usize| {
      let now_us = link.now_us;
      link
        .client
        .with_ctx(now_us, |cx| {
          let id = cx.open_bidi()?;
          cx.write(id, b"GET /", false)?;
          if nth.is_multiple_of(2) {
            cx.reset(id, 0x10c);
          } else {
            cx.stop_sending(id, 0x10c);
          }
          Ok::<_, crate::Error>(())
        })
        .unwrap();
    };
    for nth in 0..100 {
      abandon(&mut link, nth);
      if nth % 10 == 9 {
        link.run();
      }
    }
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    assert_eq!((link.server.app.resets.len(), link.server.app.stops.len()), (50, 50));
    // The server answered each STOP_SENDING with a RESET_STREAM
    assert_eq!(link.client.app.resets.len(), 100);
    abandon(&mut link, 0);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    assert_eq!(server_close(&link), Some((true, 0x0107)));
  }

  // A second round of 4,096 requests on warm pools allocates nothing on the server: small
  // responses, bodies by reference and responses that take a block of the send queue alike.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn steady_streams_allocate_nothing_after_warmup() {
    static OTHERS: AtomicU64 = AtomicU64::new(0);
    static SERVER: AtomicU64 = AtomicU64::new(0);
    let body = BodyRef::new(vec![7; 3000].into(), 0..3000).unwrap();
    let mut opts = LinkOpts::new(None);
    opts.counters = Some((&SERVER, &OTHERS));
    opts.server_app = TestApp::new(Behavior::Mixed { small: RESPONSE, body, large: LARGE });
    _count_allocations_in(&OTHERS);
    let mut link = settled(&opts);
    let _ = run_requests(&mut link, 4096, 64, |_| b"GET /".to_vec(), false);
    // The counter sees the server, which warmed its pools
    let before = SERVER.load(Ordering::Relaxed);
    assert!(before > 0);
    let responses = run_requests(&mut link, 4096, 64, |_| b"GET /".to_vec(), false);
    let allocations = SERVER.load(Ordering::Relaxed) - before;
    assert_eq!(allocations, 0, "{allocations} allocations in 4096 requests");
    // The indices of the streams of the second round start at 4,096, 1 modulo 3
    let kinds = |skip| responses.iter().skip(skip).step_by(3);
    assert!(kinds(0).all(|el| el.len() == 3000));
    assert!(kinds(1).all(|el| el == LARGE));
    assert!(kinds(2).all(|el| el == RESPONSE));
  }

  // A second round of streams whose data comes out of order and whose lines the application
  // retains in part, inline and in a block, allocates nothing on the server once its pools are
  // warm.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn steady_reassembly_and_retain_allocate_nothing_after_warmup() {
    static OTHERS: AtomicU64 = AtomicU64::new(0);
    static SERVER: AtomicU64 = AtomicU64::new(0);
    const STREAMS: usize = 64;
    let mut data = vec![b'a'; 300];
    data.push(b'\n');
    data.extend_from_slice(&[b'b'; 300]);
    data.push(b'\n');
    let mut opts = LinkOpts::new(None);
    opts.counters = Some((&SERVER, &OTHERS));
    opts.server_app = TestApp::new(Behavior::LineCount);
    _count_allocations_in(&OTHERS);
    let mut link = settled(&opts);
    let round = |link: &mut Link| {
      for _ in 0..STREAMS {
        let id = open_bidi(link).unwrap();
        // The end first, which waits in a block; then the start, whose second line is retained
        // inline and then, with the end, in a block
        let end = Frame::Stream { id: id.0, offset: 400, data: &data[400..], fin: true };
        client_sends(link, &[end]);
        client_sends(
          link,
          &[Frame::Stream { id: id.0, offset: 0, data: &data[..400], fin: false }],
        );
        link.run();
        assert_eq!(link.client.app.streams[&id.0].data, b"ok");
      }
    };
    round(&mut link);
    let before = SERVER.load(Ordering::Relaxed);
    assert!(before > 0);
    round(&mut link);
    let allocations = SERVER.load(Ordering::Relaxed) - before;
    assert_eq!(allocations, 0, "{allocations} allocations in {STREAMS} streams");
    assert_eq!(link.server.app.line_count, 4 * STREAMS as u64);
    assert_eq!(link.server.conn.streams().held_blocks(), 0);
  }

  // Rule: a stream above the limit given to the peer is a STREAM_LIMIT_ERROR (RFC 9000 section
  // 4.6), bidirectional or unidirectional.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn stream_above_max_streams_is_stream_limit_error() {
    for id in [256 * 4, 16 * 4 + 2] {
      let mut link = settled(&LinkOpts::new(None));
      client_sends(&mut link, &[Frame::Stream { id, offset: 0, data: b"x", fin: false }]);
      assert_eq!(server_close(&link), transport(TransportErrorCode::StreamLimitError), "{id}");
    }
  }

  // Rule: frames for a stream of ours that is not open, or that it can not take in its direction
  // are STREAM_STATE_ERRORs (RFC 9000 sections 19.4, 19.5, 19.8, 19.10 and 19.13).
  #[cfg_attr(miri, ignore)]
  #[test]
  fn frames_for_streams_in_the_wrong_state_are_stream_state_errors() {
    let cases = [
      // On our unidirectional stream, which only sends
      Frame::Stream { id: 3, offset: 0, data: b"x", fin: false },
      Frame::ResetStream { id: 3, code: 0, final_size: 0 },
      Frame::StreamDataBlocked { id: 3, max: 0 },
      // On streams of ours that are not open
      Frame::Stream { id: 7, offset: 0, data: b"x", fin: false },
      Frame::Stream { id: 1, offset: 0, data: b"x", fin: false },
      Frame::MaxStreamData { id: 5, max: 100 },
      // On a unidirectional stream of the client, which the server only receives
      Frame::MaxStreamData { id: 2, max: 100 },
      Frame::StopSending { id: 2, code: 0 },
    ];
    for frame in cases {
      let mut opts = LinkOpts::new(None);
      opts.server_app.uni_on_established = Some(b"settings");
      let mut link = settled(&opts);
      assert_eq!(link.server.app.uni, Some(StreamId(3)));
      client_sends(&mut link, &[frame]);
      assert_eq!(server_close(&link), transport(TransportErrorCode::StreamStateError), "{frame:?}");
    }
  }

  // Rule: a stream opens the streams of its type below it (RFC 9000 section 3.2), whose frames are
  // then no errors.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn opening_a_stream_opens_the_lower_ones() {
    let mut link = settled(&LinkOpts::new(None));
    let frames: [(u64, &[u8]); 6] =
      [(12, b"three"), (0, b"zero"), (8, b"two"), (10, b"uni two"), (4, b"one"), (2, b"uni zero")];
    for (id, data) in frames {
      client_sends(&mut link, &[Frame::Stream { id, offset: 0, data, fin: true }]);
      assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    }
    for (id, data) in frames {
      let log = &link.server.app.streams[&id];
      assert_eq!((log.data.as_slice(), log.fin), (data, true));
    }
    // Stream 6, opened by 10, takes data too
    client_sends(&mut link, &[Frame::Stream { id: 6, offset: 0, data: b"uni one", fin: false }]);
    assert_eq!(link.server.app.streams[&6].data, b"uni one");
  }

  // Rule: STOP_SENDING is answered with RESET_STREAM with its code, and nothing more is sent on
  // the stream (RFC 9000 section 3.5).
  #[cfg_attr(miri, ignore)]
  #[test]
  fn stop_sending_is_answered_with_reset_stream() {
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Echo);
    let mut link = settled(&opts);
    let id = open_bidi(&mut link).unwrap();
    write(&mut link, id, b"abc", false);
    link.run();
    assert_eq!(link.client.app.streams[&id.0].data, b"abc");
    let now_us = link.now_us;
    link.client.with_ctx(now_us, |cx| cx.stop_sending(id, 0x10c));
    link.run();
    assert_eq!(link.server.app.stops, [(id, 0x10c)]);
    assert_eq!(link.client.app.resets, [(id, 0x10c)]);
    write(&mut link, id, b"def", false);
    link.run();
    assert_eq!(link.server.app.streams.len(), 0);
    assert_eq!(link.client.app.streams[&id.0].data, b"abc");
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
  }

  // A stream that stays open holds back the limit given to the peer: stream 256 would find the
  // slot of stream 0 in the window. Once stream 0 ends, the window moves past it.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn max_streams_never_lets_an_index_collide_with_an_open_stream() {
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Respond(RESPONSE));
    let mut link = settled(&opts);
    let first = open_bidi(&mut link).unwrap();
    write(&mut link, first, b"GET /", false);
    let _ = run_requests(&mut link, 255, 64, |_| b"GET /".to_vec(), false);
    link.run();
    assert_eq!(link.server.conn.streams().bidi_limit(), 256);
    assert_eq!(link.client.conn.streams().bidi_limit(), 256);
    assert!(matches!(open_bidi(&mut link), Err(crate::Error::Quic(QuicError::StreamsBlocked))));
    write(&mut link, first, b"", true);
    link.run();
    assert_eq!(link.client.app.streams[&first.0].data, RESPONSE);
    assert!(link.server.conn.streams().bidi_limit() > 256);
    let _ = run_requests(&mut link, 45, 64, |_| b"GET /".to_vec(), true);
    // A peer that opens a stream above the limit anyway
    let limit = link.server.conn.streams().bidi_limit();
    client_sends(&mut link, &[Frame::Stream { id: limit * 4, offset: 0, data: b"x", fin: true }]);
    assert_eq!(server_close(&link), transport(TransportErrorCode::StreamLimitError));
  }

  // Data that waits for earlier data is bounded by stream (how far ahead) and by connection (bytes
  // held), which bound the credit given to the peer (ruling T8-g), and by ranges: one more is a
  // connection error, FLOW_CONTROL_ERROR for the bytes and PROTOCOL_VIOLATION for the ranges.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn out_of_order_limits_are_connection_errors() {
    let stream = |id: u64, offset: u64| Frame::Stream { id, offset, data: b"x", fin: false };
    let flow = TransportErrorCode::FlowControlError;
    let cases: [(fn(&mut LinkOpts), Vec<Frame<'static>>, TransportErrorCode); 3] = [
      (
        |el| el.server.limits.max_out_of_order_bytes_per_stream = 8192,
        vec![stream(0, 8191), stream(0, 8192)],
        flow,
      ),
      (
        |el| el.server.limits.max_out_of_order_ranges = 4,
        vec![stream(0, 10), stream(0, 20), stream(0, 30), stream(0, 40), stream(0, 50)],
        TransportErrorCode::ProtocolViolation,
      ),
      (
        |el| el.server.limits.max_out_of_order_bytes_per_conn = 8192,
        vec![stream(0, 5000), stream(4, 3000), stream(8, 190)],
        flow,
      ),
    ];
    for (change, frames, code) in cases {
      let mut opts = LinkOpts::new(None);
      change(&mut opts);
      let mut link = settled(&opts);
      let (last, rest) = frames.split_last().unwrap();
      for frame in rest {
        client_sends(&mut link, &[*frame]);
        assert_eq!(link.server.conn.state(), ConnState::Confirmed, "{frame:?}");
      }
      client_sends(&mut link, &[*last]);
      assert_eq!(server_close(&link), transport(code), "{last:?}");
    }
  }

  // The server opens unidirectional streams as long as the client allows, which it then reads.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn server_opens_uni_streams_within_the_peer_limit() {
    let mut opts = LinkOpts::new(None);
    opts.client.max_streams_uni = 3;
    opts.server_app.uni_on_established = Some(b"settings");
    let mut link = settled(&opts);
    let log = &link.client.app.streams[&3];
    assert_eq!((log.data.as_slice(), log.fin), (b"settings".as_slice(), false));
    let now_us = link.now_us;
    let ids = link.server.with_ctx(now_us, |cx| {
      let ids = [cx.open_uni().unwrap(), cx.open_uni().unwrap()];
      for id in ids {
        cx.write(id, b"more", true).unwrap();
      }
      assert!(matches!(cx.open_uni(), Err(crate::Error::Quic(QuicError::StreamsBlocked))));
      ids
    });
    assert_eq!(ids, [StreamId(7), StreamId(11)]);
    link.run();
    assert_eq!(link.client.app.streams[&11].data, b"more");
  }
}
