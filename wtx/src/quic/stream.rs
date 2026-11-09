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
//! the pools of the worker. A body written by reference ([`BodyRef`](crate::quic::BodyRef)) is
//! never copied.
//!
//! # Receiving
//!
//! Data that arrives in order goes to the application straight from the decrypted packet. Data
//! that arrives before the data that precedes it waits in blocks, its ranges kept exactly in a
//! [`RangeSet`], until the gap fills. The application can retain the end of what it was given
//! ([`ConnCtx::retain`](crate::quic::ConnCtx::retain)): those bytes wait in the slot, or in one
//! block, and come again before the next ones. Waiting and retained bytes are bounded
//! ([`crate::quic::QuicLimits`]) and give no credit back until they are consumed.
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
  ConnParams, QuicError, TransportErrorCode, TransportParams,
  flow::{ConnFlow, NOT_BLOCKED},
  limits::{RESET_WINDOW_US, RateBudget},
  pools::{FrameRefQueue, FreeList, QuicPools},
};
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::hint::cold_path;
pub(crate) use recv::OooBlock;
use recv::{Held, RecvPart, RxPools, RxState};
use reject::{MAX_REJECTED, Rejected};
use send::{Ready, SendPart};
pub(crate) use send::{Seg, Source};
pub(crate) use table::StreamSlots;
use table::{IMPLICIT, NO_SLOT, Table};

mod recv;
mod reject;
mod send;
mod table;

/// The window of client-initiated bidirectional streams: the entries of their index array.
pub(crate) const BIDI_WINDOW: usize = 256;
/// The bytes of the reason of a close of the application that are sent.
pub(crate) const CLOSE_REASON_LEN: usize = 64;
/// The bytes of the receive buffer and of the send buffer that a slot has inline.
pub(crate) const INLINE_LEN: usize = 256;
/// The window of the unidirectional streams of the peer.
pub(crate) const UNI_REMOTE_WINDOW: usize = 16;

const NO_LINK: u32 = u32::MAX;
const OWED_DATA_BLOCKED: u8 = 1 << 0;
const OWED_MAX_DATA: u8 = 1 << 1;
const OWED_MAX_STREAMS_BIDI: u8 = 1 << 2;
const OWED_MAX_STREAMS_UNI: u8 = 1 << 3;
// The frame that carried the current limit was lost: it is sent again even if the limit did not
// move
const OWED_MAX_DATA_LOST: u8 = 1 << 4;
const OWED_MAX_STREAMS_BIDI_LOST: u8 = 1 << 5;
const OWED_MAX_STREAMS_UNI_LOST: u8 = 1 << 6;
// RESET_STREAM or STOP_SENDING frames of refused streams
const OWED_REJECTS: u8 = 1 << 7;
// Segments of the send queue of a slot reserved when the slot is made: headers, a body, trailers
pub(super) const RESERVED_SEGMENTS: usize = 4;
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
  #[allow(dead_code, reason = "the application interface, which the HTTP/3 layer of task 13 uses")]
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

/// The separate ranges that a [`RangeSet`] holds at most, once it spilled into a block.
pub(crate) const SPILL_RANGES: usize = 256;

/// What a [`RangeSet`] spills into once its inline array is full: 4 KiB of ranges, from the
/// pools of the worker (ruling T9-d).
pub(crate) type RangeBlock = [(u64, u64); SPILL_RANGES];

/// Ranges of offsets from the lowest. Ranges that touch or overlap are joined and gaps are never
/// filled: the ranges are exact.
///
/// `N` separate ranges fit inline. One more moves them all into a [`RangeBlock`] of the pools,
/// which holds [`SPILL_RANGES`], and the block goes back once at most `N / 2` are left. A range
/// that does not fit there either is an error, which leaves the ranges as they were.
#[derive(Debug)]
pub(crate) struct RangeSet<const N: usize> {
  len: usize,
  // From the lowest: start included, end excluded
  ranges: [(u64, u64); N],
  // Holds every range instead of `ranges` once more than `N` were held
  spill: Option<Box<RangeBlock>>,
}

impl<const N: usize> RangeSet<N> {
  /// No ranges.
  #[inline]
  pub(crate) const fn new() -> Self {
    Self { len: 0, ranges: [(0, 0); N], spill: None }
  }

  /// The lowest range.
  #[inline]
  pub(crate) fn first(&self) -> Option<(u64, u64)> {
    self.held().first().copied()
  }

  /// Adds the offsets from `start` to `end`, excluded, taking a block from `blocks` if a new
  /// separate range does not fit inline. A new separate range when [`SPILL_RANGES`] are held is a
  /// connection error (PROTOCOL_VIOLATION) that changes nothing.
  #[inline]
  pub(crate) fn insert(
    &mut self,
    start: u64,
    end: u64,
    blocks: &mut FreeList<Box<RangeBlock>>,
  ) -> crate::Result<()> {
    if start >= end {
      return Ok(());
    }
    let held = self.held();
    // The held ranges from `lo` to `hi`, excluded, touch or overlap the new one
    let lo = held.partition_point(|el| el.1 < start);
    let hi = held.partition_point(|el| el.0 <= end);
    if lo == hi {
      if self.len >= self.capacity() {
        if self.spill.is_some() || N >= SPILL_RANGES {
          cold_path();
          return Err(crate::Error::QuicClose(
            TransportErrorCode::ProtocolViolation,
            QuicError::RangeSetFull,
          ));
        }
        let mut block = blocks.take().unwrap_or_else(|| Box::new([(0, 0); SPILL_RANGES]));
        if let Some((dst, src)) = block.get_mut(..self.len).zip(self.ranges.get(..self.len)) {
          dst.copy_from_slice(src);
        }
        self.spill = Some(block);
      }
      let len = self.len;
      if let Some(tail) = self.storage_mut().get_mut(lo..=len) {
        tail.rotate_right(1);
        if let Some(elem) = tail.first_mut() {
          *elem = (start, end);
        }
      }
      self.len = len.wrapping_add(1);
      return Ok(());
    }
    let (Some(&(first, _)), Some(&(_, last))) = (held.get(lo), held.get(hi.wrapping_sub(1))) else {
      return Ok(());
    };
    let len = self.len;
    let storage = self.storage_mut();
    if let Some(elem) = storage.get_mut(lo) {
      *elem = (start.min(first), end.max(last));
    }
    let joined = hi.wrapping_sub(lo).wrapping_sub(1);
    if joined > 0 {
      if let Some(tail) = storage.get_mut(lo.wrapping_add(1)..len) {
        tail.rotate_left(joined);
      }
      self.len = len.wrapping_sub(joined);
    }
    Ok(())
  }

  /// If no range is held.
  #[inline]
  #[cfg(test)]
  pub(crate) const fn is_empty(&self) -> bool {
    self.len == 0
  }

  /// If the ranges are in a block of the pools.
  #[inline]
  #[cfg(test)]
  pub(crate) const fn is_spilled(&self) -> bool {
    self.spill.is_some()
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

  /// If a new separate range from `start` to `end`, excluded, would take a block.
  #[inline]
  pub(crate) fn needs_block(&self, start: u64, end: u64) -> bool {
    if start >= end || self.spill.is_some() || self.len < N || N >= SPILL_RANGES {
      return false;
    }
    let held = self.held();
    held.partition_point(|el| el.1 < start) == held.partition_point(|el| el.0 <= end)
  }

  /// Forgets every range and gives the block back to `blocks`. Returns whether there was one.
  #[inline]
  pub(crate) fn release(&mut self, blocks: &mut FreeList<Box<RangeBlock>>) -> bool {
    self.len = 0;
    match self.spill.take() {
      Some(block) => {
        blocks.give(block);
        true
      }
      None => false,
    }
  }

  /// Forgets the offsets below `at`. Returns whether that gave the block back to `blocks`.
  #[inline]
  pub(crate) fn remove_below(&mut self, at: u64, blocks: &mut FreeList<Box<RangeBlock>>) -> bool {
    let gone = self.held().partition_point(|el| el.1 <= at);
    let len = self.len;
    if gone > 0 {
      if let Some(held) = self.storage_mut().get_mut(..len) {
        held.rotate_left(gone);
      }
      self.len = len.wrapping_sub(gone);
    }
    let len = self.len;
    if let Some(first) = self.storage_mut().get_mut(..len).and_then(|el| el.first_mut())
      && first.0 < at
    {
      first.0 = at;
    }
    if self.len > N / 2 {
      return false;
    }
    let Some(block) = self.spill.take() else {
      return false;
    };
    if let Some((dst, src)) = self.ranges.get_mut(..self.len).zip(block.get(..self.len)) {
      dst.copy_from_slice(src);
    }
    blocks.give(block);
    true
  }

  fn capacity(&self) -> usize {
    if self.spill.is_some() { SPILL_RANGES } else { N }
  }

  fn held(&self) -> &[(u64, u64)] {
    match &self.spill {
      Some(block) => block.get(..self.len),
      None => self.ranges.get(..self.len),
    }
    .unwrap_or_default()
  }

  fn storage_mut(&mut self) -> &mut [(u64, u64)] {
    match &mut self.spill {
      Some(block) => block.as_mut_slice(),
      None => self.ranges.as_mut_slice(),
    }
  }
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
        max_lost: false,
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
        spare: VecDeque::new(),
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
    rx.max_lost = false;
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

/// The state of the streams of a connection that is seldom used: the unidirectional streams, the
/// credit that the peer gives new streams, the receive blocks held, the reset budget and the close
/// that the application asked for. It comes from the pools of the worker and goes back once the
/// connection is over, which keeps the connection small (spec section 5.4, ruling T8-c).
#[derive(Debug)]
pub(crate) struct StreamsCold {
  /// DATA_BLOCKED and STREAM_DATA_BLOCKED frames sent.
  #[cfg(test)]
  blocked_sent: u32,
  // Bytes that the application wrote by copy (ruling T19-a)
  bytes_copied: u64,
  // Bytes of stream data written into packets, those sent again included (ruling T19-a)
  bytes_out: u64,
  close_reason: [u8; CLOSE_REASON_LEN],
  close_reason_len: u8,
  close_request: Option<u64>,
  // STREAM frames sent with the FIN of their stream, the first time
  fins_out: u64,
  held: Held,
  // The credit of a stream that the peer gives: client-initiated bidirectional ones and our
  // unidirectional ones
  peer_bidi_credit: u64,
  peer_uni_credit: u64,
  // Streams of the peer refused for want of a slot (ruling T10-c)
  rejects: [Option<Rejected>; MAX_REJECTED],
  // Ranges of stream data sent again although they were acknowledged: none, unless a stream had
  // more separate acknowledged ranges than it can remember
  resent_acked: u64,
  resets: RateBudget,
  // STREAM frames sent again
  retransmitted: u64,
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
      bytes_copied: 0,
      bytes_out: 0,
      close_reason: [0; CLOSE_REASON_LEN],
      close_reason_len: 0,
      close_request: None,
      fins_out: 0,
      held: Held { blocks: 0, streams: 0 },
      peer_bidi_credit: 0,
      peer_uni_credit: 0,
      rejects: [None; MAX_REJECTED],
      resent_acked: 0,
      resets: RateBudget::default(),
      retransmitted: 0,
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
  // The STREAM frames of lost packets, sent again before new data
  lost: FrameRefQueue,
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
      lost: FrameRefQueue::EMPTY,
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

  /// Queues, as lost, a STREAM frame of a stream that is gone, which the next packet drops without
  /// writing anything: what a frame lost after its stream was released or fully acknowledged
  /// leaves behind.
  #[cfg(test)]
  pub(crate) fn queue_stale_lost(&mut self, pools: &mut QuicPools) -> crate::Result<()> {
    let frame = crate::quic::sent::FrameRef::Stream {
      slot: u32::MAX,
      generation: 0,
      offset: 0,
      len: 1,
      fin: false,
    };
    pools.frame_refs.queue_push(&mut self.lost, frame)
  }

  /// Stops sending DATA_BLOCKED and STREAM_DATA_BLOCKED, as some peers do.
  #[cfg(test)]
  pub(crate) fn never_send_blocked_frames(&mut self) {
    if let Some(cold) = self.cold.as_deref_mut() {
      cold.send_blocked_frames = false;
    }
  }

  /// STREAM frames sent with the FIN of their stream, retransmissions not counted: the responses
  /// that a server finished sending.
  #[inline]
  pub(crate) fn fins_out(&self) -> u64 {
    self.cold.as_ref().map_or(0, |el| el.fins_out)
  }

  /// The bytes of stream data written into packets, those sent again included, and the bytes
  /// that the application wrote by copy.
  #[inline]
  pub(crate) fn bytes_out_and_copied(&self) -> (u64, u64) {
    self.cold.as_ref().map_or((0, 0), |el| (el.bytes_out, el.bytes_copied))
  }

  /// STREAM frames sent again.
  #[inline]
  pub(crate) fn frames_resent(&self) -> u64 {
    self.cold.as_ref().map_or(0, |el| el.retransmitted)
  }

  /// STREAM frames sent again, and ranges sent again although they were acknowledged.
  #[inline]
  #[cfg(test)]
  pub(crate) fn retransmissions(&self) -> (u64, u64) {
    self.cold.as_ref().map_or((0, 0), |el| (el.retransmitted, el.resent_acked))
  }

  /// Receive blocks held by the streams.
  #[inline]
  #[cfg(test)]
  pub(crate) fn held_blocks(&self) -> u32 {
    self.cold.as_ref().map_or(0, |el| el.held.blocks)
  }

  /// The connection is closing: writes fail from now on.
  #[inline]
  pub(crate) const fn on_closing(&mut self) {
    self.closed = true;
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

  /// Gives every stream back to the pools: the connection is over.
  #[inline]
  pub(crate) fn release(&mut self, pools: &mut QuicPools) {
    let cold = self.cold.take();
    let QuicPools {
      frame_refs,
      ooo_indexes,
      range_blocks,
      rx_blocks,
      seg_queues,
      stream_slots,
      streams_cold,
      tx_blocks,
      ..
    } = pools;
    frame_refs.queue_clear(&mut self.lost);
    let uni = cold
      .as_deref()
      .into_iter()
      .flat_map(|el| el.uni_local.slots.iter().chain(el.uni_remote.slots.iter()));
    for slot in self.bidi.slots.iter().chain(uni).copied() {
      if slot == NO_SLOT || slot == IMPLICIT || slot == table::REJECTED {
        continue;
      }
      if let Some(stream) = stream_slots.get_mut(slot) {
        let rx_pools = RxPools { blocks: rx_blocks, indexes: ooo_indexes, range_blocks };
        stream.rx.release(rx_pools, &mut Held { blocks: 0, streams: 0 });
        stream.tx.release(tx_blocks, range_blocks, seg_queues);
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

  // Gives the stream in `slot` back: both parts are done
  fn close_stream(&mut self, pools: &mut QuicPools, slot: u32) {
    let QuicPools {
      ooo_indexes, range_blocks, rx_blocks, seg_queues, stream_slots, tx_blocks, ..
    } = &mut *pools;
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
      let rx_pools = RxPools { blocks: rx_blocks, indexes: ooo_indexes, range_blocks };
      stream.rx.release(rx_pools, &mut cold.held);
    }
    self.unsent = self.unsent.saturating_sub(stream.tx.end.saturating_sub(stream.tx.sent));
    stream.tx.release(tx_blocks, range_blocks, seg_queues);
    stream_slots.free(slot);
    if let Some(kind) = self.kind(id) {
      if let Some(mut table) = self.table_mut(kind) {
        table.set(id.index(), NO_SLOT);
        table.advance_base();
      }
      self.check_max_streams(kind);
    }
  }

  fn ctrl_add(&mut self, slots: &mut StreamSlots, slot: u32) {
    let Some(stream) = slots.get_mut(slot).filter(|el| !el.in_ctrl) else {
      return;
    };
    stream.in_ctrl = true;
    self.ctrl.push_back(slots, slot, true);
  }

  // Closes the stream in `slot` if both of its parts are done
  fn maybe_close(&mut self, pools: &mut QuicPools, slot: u32) {
    let done = pools.stream_slots.get(slot).is_some_and(|el| el.rx.is_done() && el.tx.is_done());
    if done {
      self.close_stream(pools, slot);
    }
  }

  fn take_reset_budget(&mut self, params: &ConnParams, now_us: u64) -> bool {
    let budget = params.limits.reset_budget;
    self
      .cold
      .as_deref_mut()
      .is_some_and(|el| el.resets.take_within(budget, RESET_WINDOW_US, now_us))
  }
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
      pools::FreeList,
      sent::FrameRef,
      stream::{RangeSet, SPILL_RANGES, StreamSlots},
      testing::{Behavior, Link, LinkOpts, TestApp, encode_frames},
    },
    sync::AtomicU64,
    tests::_count_allocations_in,
  };
  use alloc::{vec, vec::Vec};
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
  // that loses nothing of what is held. Room is the inline array and then, once it is full, a
  // block of the pools that holds 256 ranges and goes back once at most half the inline ones are
  // left (ruling T9-d).
  #[test]
  fn range_set_overflow_is_error_not_loss() {
    let ranges = |set: &RangeSet<4>| set.iter().collect::<Vec<_>>();
    let mut blocks = FreeList::new();
    let mut set = RangeSet::<4>::new();
    for nth in 0..4u64 {
      set.insert(nth * 10, nth * 10 + 5, &mut blocks).unwrap();
    }
    assert!(!set.is_spilled() && !set.needs_block(0, 3) && set.needs_block(100, 105));
    let before = ranges(&set);
    // One more spills into a block, with every range kept
    set.insert(100, 105, &mut blocks).unwrap();
    assert!(set.is_spilled());
    assert_eq!(ranges(&set), [before.as_slice(), &[(100, 105)]].concat());
    for nth in 5..SPILL_RANGES as u64 {
      set.insert(nth * 100, nth * 100 + 5, &mut blocks).unwrap();
    }
    assert_eq!(set.len(), SPILL_RANGES);
    let before = ranges(&set);
    assert!(matches!(
      set.insert(1_000_000, 1_000_005, &mut blocks),
      Err(crate::Error::QuicClose(TransportErrorCode::ProtocolViolation, QuicError::RangeSetFull))
    ));
    assert_eq!(ranges(&set), before);
    // Back to a few ranges: the block goes back to the pool, the ranges inline
    assert!(!set.remove_below(10_000, &mut blocks));
    assert!(set.remove_below((SPILL_RANGES as u64 - 2) * 100, &mut blocks));
    assert!(!set.is_spilled() && blocks.len() == 1);
    assert_eq!(set.len(), 2);
    assert!(!set.release(&mut blocks) && set.is_empty());
    // A range that touches or overlaps held ones joins them; no gap is ever filled
    let mut set = RangeSet::<4>::new();
    for nth in 0..4u64 {
      set.insert(nth * 10, nth * 10 + 5, &mut blocks).unwrap();
    }
    set.insert(5, 10, &mut blocks).unwrap();
    assert_eq!(ranges(&set), [(0, 15), (20, 25), (30, 35)]);
    set.insert(100, 105, &mut blocks).unwrap();
    set.insert(22, 33, &mut blocks).unwrap();
    assert_eq!(ranges(&set), [(0, 15), (20, 35), (100, 105)]);
    // Held bytes and empty ranges change nothing, even when full
    set.insert(200, 201, &mut blocks).unwrap();
    set.insert(1, 3, &mut blocks).unwrap();
    set.insert(50, 50, &mut blocks).unwrap();
    assert_eq!(ranges(&set), [(0, 15), (20, 35), (100, 105), (200, 201)]);
    assert!(!set.is_spilled());
    let _ = set.remove_below(12, &mut blocks);
    assert_eq!(ranges(&set), [(12, 15), (20, 35), (100, 105), (200, 201)]);
    let _ = set.remove_below(101, &mut blocks);
    assert_eq!(ranges(&set), [(101, 105), (200, 201)]);
    let _ = set.remove_below(300, &mut blocks);
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

  // Ruling T16-c: the 64 responses of one packet count 64 FINs, in one flush that carries the
  // acknowledgment of the requests; BLOCKED frames received are counted by kind.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn fins_acked_flushes_and_blocked_frames_are_counted() {
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Respond(RESPONSE));
    let mut link = settled(&opts);
    let before = *link.server.conn.stats();
    let fins = link.server.conn.stream_tally().0;
    for _ in 0..64 {
      let id = open_bidi(&mut link).unwrap();
      write(&mut link, id, b"GET /", true);
    }
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    let _ = link.server.flush(link.now_us);
    let after = *link.server.conn.stats();
    assert_eq!(link.server.conn.stream_tally().0 - fins, 64);
    assert_eq!(after.fin_flushes - before.fin_flushes, 1);
    assert_eq!(after.fin_flushes_acked - before.fin_flushes_acked, 1);
    assert_eq!(link.deliver_to_client(), 1);
    // A flush with nothing finished is not one
    link.server.conn.queue_test_frames(&[0x01]);
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.server.conn.stats().fin_flushes, after.fin_flushes);
    let _ = link.server.take_datagrams();
    let id = open_bidi(&mut link).unwrap();
    write(&mut link, id, b"GET", false);
    client_sends(
      &mut link,
      &[
        Frame::DataBlocked(10),
        Frame::StreamDataBlocked { id: id.0, max: 3 },
        Frame::StreamsBlocked { bidi: true, max: 300 },
      ],
    );
    let stats = link.server.conn.stats();
    let blocked = (stats.data_blocked_in, stats.stream_data_blocked_in, stats.streams_blocked_in);
    assert_eq!(blocked, (1, 1, 1));
  }

  // Ruling T19-a: the stream bytes written into packets, and of them those that the application
  // wrote by copy (a body by reference is copied once, into the packet), are counted; bytes
  // sent again after a loss count again.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn stream_bytes_out_and_copied_are_counted() {
    const SMALL: &[u8] = &[1; 700];
    const LARGE: &[u8] = &[2; 5000];
    let body = crate::misc::SharedBytes::from_slice(&[3; 9000]);
    let mut opts = LinkOpts::new(None);
    let body = BodyRef::new(body, 0..9000).unwrap();
    opts.server_app = TestApp::new(Behavior::Mixed { small: SMALL, body, large: LARGE });
    let mut link = settled(&opts);
    let (out, copied) = link.server.conn.stream_bytes();
    for _ in 0..3 {
      let id = open_bidi(&mut link).unwrap();
      write(&mut link, id, b"GET /", true);
    }
    link.run();
    let (out2, copied2) = link.server.conn.stream_bytes();
    assert_eq!(copied2 - copied, (SMALL.len() + LARGE.len()) as u64);
    assert_eq!(out2 - out, (SMALL.len() + LARGE.len() + 9000) as u64);
    // A response whose datagrams are all lost is sent again, and counted again
    let id = open_bidi(&mut link).unwrap();
    write(&mut link, id, b"GET /", true);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    let _ = link.server.flush(link.now_us);
    assert!(!link.server.take_datagrams().is_empty());
    let mut rounds = 0;
    while !link.client.app.streams.get(&id.0).is_some_and(|el| el.fin) {
      rounds += 1;
      assert!(rounds < 20, "the response was not sent again");
      assert!(link.advance_to_next_event());
      link.run();
    }
    let (out3, copied3) = link.server.conn.stream_bytes();
    assert_eq!(copied3 - copied2, SMALL.len() as u64);
    assert_eq!(out3 - out2, 2 * SMALL.len() as u64);
  }

  // Ruling T16-b (task 19's measurement): bodies go one at a time to their end, or, with
  // `bodies_round_robin`, take turns a STREAM frame each.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn bodies_go_to_completion_or_round_robin() {
    let body = crate::misc::SharedBytes::from_slice(&[9; 6000]);
    for round_robin in [false, true] {
      let mut opts = LinkOpts::new(None);
      opts.server.bodies_round_robin = round_robin;
      let response = BodyRef::new(body.clone(), 0..6000).unwrap();
      opts.server_app = TestApp::new(Behavior::RespondBody(b"", response));
      let mut link = settled(&opts);
      let ids = [open_bidi(&mut link).unwrap(), open_bidi(&mut link).unwrap()];
      for id in ids {
        write(&mut link, id, b"GET /", true);
      }
      let _ = link.client.flush(link.now_us);
      assert_eq!(link.deliver_to_server(), 1);
      let _ = link.server.flush(link.now_us);
      let mut datagrams = link.server.take_datagrams();
      assert!(datagrams.len() >= 4, "{}", datagrams.len());
      for datagram in datagrams.iter_mut().take(2) {
        link.client.recv(link.now_us, datagram, crate::quic::testing::SERVER_ADDR);
      }
      let got = ids.map(|id| link.client.app.streams.get(&id.0).map_or(0, |el| el.data.len()));
      if round_robin {
        assert!(got[0] > 0 && got[1] > 0, "{got:?}");
      } else {
        assert!(got[0] > 0 && got[1] == 0, "{got:?}");
      }
    }
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
    let body =
      crate::misc::SharedBytes::from_slice(&(0..10_000u32).map(|el| el as u8).collect::<Vec<u8>>());
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
      assert_eq!(logs[1].data, body.as_slice());
      // In datagrams of 1472 bytes once path MTU discovery is done: frames of 1440 bytes
      assert!(logs[1].calls.len() >= 7, "{:?}", logs[1].calls);
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
    let body = crate::misc::SharedBytes::from_slice(&[9; 5000]);
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
      assert_eq!(body.strong_count(), 2);
      assert!(link.deliver_to_client() > 0);
      let _ = link.client.flush(link.now_us);
      assert!(link.deliver_to_server() > 0);
      assert_eq!(body.strong_count(), 1, "{fin}");
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
      let body = crate::misc::SharedBytes::from_slice(&[7; 50]);
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
      assert_eq!((log.data.as_slice(), log.fin), (body.as_slice(), true));
      assert_eq!(body.strong_count(), 1);
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
  // responses, bodies by reference and responses that take a block of the send queue alike, with
  // header protection one packet at a time or in batches (ruling T18-b).
  #[cfg_attr(miri, ignore)]
  #[test]
  fn steady_streams_allocate_nothing_after_warmup() {
    static OTHERS: AtomicU64 = AtomicU64::new(0);
    static SERVER: AtomicU64 = AtomicU64::new(0);
    for batched in [false, true] {
      let body = BodyRef::new(crate::misc::SharedBytes::from_slice(&[7; 3000]), 0..3000).unwrap();
      let mut opts = LinkOpts::new(None);
      opts.counters = Some((&SERVER, &OTHERS));
      opts.server.batched_hp = batched;
      opts.server_app = TestApp::new(Behavior::Mixed { small: RESPONSE, body, large: LARGE });
      _count_allocations_in(&OTHERS);
      let mut link = settled(&opts);
      let _ = run_requests(&mut link, 4096, 64, |_| b"GET /".to_vec(), false);
      // The counter sees the server, which warmed its pools
      let before = SERVER.load(Ordering::Relaxed);
      assert!(before > 0);
      let responses = run_requests(&mut link, 4096, 64, |_| b"GET /".to_vec(), false);
      let allocations = SERVER.load(Ordering::Relaxed) - before;
      assert_eq!(allocations, 0, "{allocations} allocations in 4096 requests, batched {batched}");
      // The indices of the streams of the second round start at 4,096, 1 modulo 3
      let kinds = |skip| responses.iter().skip(skip).step_by(3);
      assert!(kinds(0).all(|el| el.len() == 3000));
      assert!(kinds(1).all(|el| el == LARGE));
      assert!(kinds(2).all(|el| el == RESPONSE));
      if batched && crate::quic::crypto::has_aes_ni() {
        assert!(link.server.parts.pools.hp_batch.masked > 0);
      }
    }
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

  // Ruling T9-d: waiting data with more separate ranges than the 32 inline ones spills them into
  // a block of the pools, which counts like a block of data and goes back once the gaps fill;
  // past the 256 ranges of the block the peer is closed (PROTOCOL_VIOLATION).
  #[cfg_attr(miri, ignore)]
  #[test]
  fn receive_ranges_spill_into_a_block_and_past_it_close() {
    let mut link = settled(&LinkOpts::new(None));
    let id = open_bidi(&mut link).unwrap();
    let data: Vec<u8> = (0..1024u32).map(|el| (el % 251) as u8).collect();
    let piece = |nth: usize| Frame::Stream {
      id: id.0,
      offset: (nth * 4) as u64,
      data: &data[nth * 4..nth * 4 + 4],
      fin: false,
    };
    // Every other piece of 4 bytes after the first: 100 separate ranges, in one block of data
    let odd: Vec<Frame<'_>> = (1..200).step_by(2).map(piece).collect();
    for frames in odd.chunks(40) {
      client_sends(&mut link, frames);
    }
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    let pools = &link.server.parts.pools;
    let slot = link.server.conn.streams().app_slot(id).unwrap();
    assert!(pools.stream_slots.get(slot).unwrap().rx.ooo.is_spilled());
    // The block of data and the one of the ranges
    assert_eq!(link.server.conn.streams().held_blocks(), 2);
    let even: Vec<Frame<'_>> = (0..200).step_by(2).map(piece).collect();
    for frames in even.chunks(40) {
      client_sends(&mut link, frames);
    }
    assert_eq!(link.server.app.streams[&id.0].data, &data[..800]);
    // The block of the ranges went back; the one of data until everything before its end is read
    assert_eq!(link.server.conn.streams().held_blocks(), 1);
    assert_eq!(link.server.parts.pools.range_blocks.len(), 1);
    // 256 separate ranges are held, one more closes
    let id = open_bidi(&mut link).unwrap();
    let byte = |nth: u64| Frame::Stream { id: id.0, offset: 2 * nth + 1, data: b"x", fin: false };
    let ranges: Vec<Frame<'_>> = (0..SPILL_RANGES as u64).map(byte).collect();
    for frames in ranges.chunks(64) {
      client_sends(&mut link, frames);
      assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    }
    client_sends(&mut link, &[byte(SPILL_RANGES as u64)]);
    assert_eq!(server_close(&link), transport(TransportErrorCode::ProtocolViolation));
  }

  // Ruling T9-d: acknowledged ranges of a stream past its 16 inline ones spill into a block, which
  // goes back once the gaps are acknowledged. Past the 256 ranges of the block, a range that is
  // acknowledged apart from the others is forgotten and its bytes go again, counted, rather than
  // failing: within the in-flight bound a stream does not get there (the lossy runs of
  // `quic::recovery` count none).
  #[cfg_attr(miri, ignore)]
  #[test]
  fn acked_ranges_spill_into_a_block_and_past_it_go_again() {
    let body = crate::misc::SharedBytes::from_slice(&[5; 12_000]);
    let mut opts = LinkOpts::new(None);
    let response = BodyRef::new(body, 0..12_000).unwrap();
    opts.server_app = TestApp::new(Behavior::RespondBody(b"", response));
    let mut link = settled(&opts);
    let id = open_bidi(&mut link).unwrap();
    write(&mut link, id, b"GET /", true);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    // The response goes out and is lost on the way: only the acknowledgments below arrive
    let _ = link.server.flush(link.now_us);
    let _ = link.server.take_datagrams();
    let server = &mut link.server;
    let (streams, pools) = (server.conn.streams_mut(), &mut server.parts.pools);
    let slot = streams.app_slot(id).unwrap();
    let generation = pools.stream_slots.generation(slot);
    let ack = |streams: &mut crate::quic::stream::Streams, pools: &mut _, offset: u64, len: u16| {
      let frame = FrameRef::Stream { slot, generation, offset, len, fin: false };
      streams.on_frame_acked(frame, pools).unwrap();
    };
    // Every other byte: 300 separate ranges after the first byte
    for nth in 0..=300u64 {
      ack(streams, pools, 2 * nth, 1);
    }
    let tx = &pools.stream_slots.get(slot).unwrap().tx;
    assert!(tx.acked_ranges.is_spilled());
    assert_eq!((tx.acked, tx.acked_ranges.len()), (1, SPILL_RANGES));
    // The 44 that did not fit go again
    assert_eq!(streams.retransmissions(), (0, 44));
    assert_eq!(streams.lost.len(), 44);
    // All of it acknowledged: the block goes back
    ack(streams, pools, 0, 12_000);
    let tx = &pools.stream_slots.get(slot).unwrap().tx;
    assert!(!tx.acked_ranges.is_spilled() && tx.acked_ranges.is_empty());
    assert_eq!(tx.acked, 12_000);
    assert_eq!(pools.range_blocks.len(), 1);
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

  // Ruling T10-c: a stream of the client that finds no slot left on the worker is refused with
  // RESET_STREAM and STOP_SENDING of H3_REQUEST_REJECTED, not the connection; its data counts
  // towards the connection credit, which comes back, until its end; past eight refused streams at
  // once, the connection closes as before.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn exhausted_slots_reject_the_stream_not_the_connection() {
    let rejected = crate::quic::QuicLimits::default().stream_rejected_app_code;
    let mut link = settled(&LinkOpts::new(None));
    link.server.parts.pools.stream_slots.set_cap(2);
    let now_us = link.now_us;
    let ids: Vec<StreamId> = (0..3)
      .map(|_| {
        link.client.with_ctx(now_us, |cx| {
          let id = cx.open_bidi()?;
          cx.write(id, &[b'x'; 100], false)?;
          Ok::<_, crate::Error>(id)
        })
      })
      .collect::<crate::Result<_>>()
      .unwrap();
    link.run();
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    // The first two are served, the third refused
    assert_eq!(link.server.app.streams.len(), 2);
    assert_eq!(link.client.app.stops, [(ids[2], rejected)]);
    assert_eq!(link.client.app.resets, [(ids[2], rejected)]);
    // The data of the refused stream was counted and its credit given back, and the client's
    // reset, which answers the STOP_SENDING, ended it
    let (_, consumed, _) = link.server.conn.streams().conn_credit();
    assert_eq!(consumed, 300);
    assert_eq!(link.server.conn.streams().rejected(), 0);
    // A stream after it is served once a slot is free: the first two end
    for id in &ids[..2] {
      link.client.with_ctx(now_us, |cx| cx.write(*id, b"", true)).unwrap();
      let id = *id;
      link.server.with_ctx(now_us, |cx| cx.write(id, b"bye", true)).unwrap();
    }
    link.run();
    let next = link
      .client
      .with_ctx(now_us, |cx| {
        let id = cx.open_bidi()?;
        cx.write(id, b"again", true)?;
        Ok::<_, crate::Error>(id)
      })
      .unwrap();
    link.run();
    assert_eq!(link.server.app.streams[&next.0].data, b"again");
    // Past eight refused streams at once: INTERNAL_ERROR (the three free slots go first)
    link.server.parts.pools.stream_slots.set_cap(0);
    for _ in 0..12 {
      let _ = link.client.with_ctx(now_us, |cx| {
        let id = cx.open_bidi()?;
        cx.write(id, b"x", false)
      });
    }
    let _ = link.client.flush(link.now_us);
    let _ = link.deliver_to_server();
    assert_eq!(server_close(&link), Some((false, TransportErrorCode::InternalError.code())));
  }
}
