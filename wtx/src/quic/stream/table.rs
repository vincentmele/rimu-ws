//! The tables of the streams of a connection, indexed by stream index over a window, and the
//! worker-wide slab of stream slots with generations that they index.

use crate::quic::{
  ConnParams, QuicError,
  pools::QuicPools,
  stream::{
    OWED_MAX_STREAMS_BIDI, OWED_MAX_STREAMS_UNI, Stream, StreamId, Streams, closed, exhausted,
    reject, stream_limit_error, stream_state_error,
  },
};
use alloc::vec::Vec;
use core::hint::cold_path;

// A stream that a later one opened (RFC 9000 section 3.2), which takes a slot once it is used
pub(super) const IMPLICIT: u32 = u32::MAX - 1;
// A stream of the peer that was refused for want of a slot (ruling T10-c)
pub(super) const REJECTED: u32 = u32::MAX - 2;

/// The stream slots that an idle HTTP/3 connection holds: our control, QPACK encoder and QPACK
/// decoder streams, and the same three of the client (RFC 9114 section 6.2, RFC 9204 section 4.2).
pub(crate) const SLOTS_PER_CONN: usize = 6;
/// The slots of a worker on top of [`SLOTS_PER_CONN`] for each of its connections, for requests:
/// 64 connections with their whole window of 256 bidirectional streams.
pub(crate) const REQUEST_SLOTS: usize = 1 << 14;

pub(super) const NO_SLOT: u32 = u32::MAX;

/// The slots that the table makes room for at a time (about 0.8 MB), so that one stream past the
/// slots in use grows the table by this much and not by as much again (`Vec` doubles), which at
/// 4,096 slots of 3.2 KB would be 13 MB.
pub(crate) const GROW_SLOTS: usize = 256;

/// The slots of a worker of at most `max_conns` connections (spec section 5.4): [`SLOTS_PER_CONN`]
/// for each, so that idle HTTP/3 connections reach the connection cap before the slots run out,
/// and [`REQUEST_SLOTS`] for requests. They are made on demand, [`GROW_SLOTS`] at a time, so a
/// higher cap costs nothing until used.
#[inline]
pub(crate) const fn max_slots(max_conns: usize) -> usize {
  max_conns.saturating_mul(SLOTS_PER_CONN).saturating_add(REQUEST_SLOTS)
}

/// The streams of the connections of a worker: a slab of slots with generations, grown on demand
/// up to [`max_slots`] of the connection cap, whose slots are used again without allocating. A
/// frame reference names a stream by slot and generation, so that a stream that is gone is not
/// mistaken for the next one in its slot.
#[derive(Debug)]
pub(crate) struct StreamSlots {
  // Slots at most
  cap: usize,
  pub(super) entries: Vec<SlotEntry>,
  // The first free slot, the others linked from it
  free: u32,
  // The generation of a slot that is made, above every generation of the slots that a trim let
  // go: a frame reference of a stream of before never matches the stream of a slot made again
  generation_floor: u32,
  live: usize,
}

impl StreamSlots {
  /// No slots, and room for [`max_slots`] of `max_conns` connections.
  #[inline]
  pub(crate) const fn new(max_conns: usize) -> Self {
    let cap = max_slots(max_conns);
    Self { cap, entries: Vec::new(), free: NO_SLOT, generation_floor: 0, live: 0 }
  }

  /// Lowers the slots of the worker to at most `cap`, for tests that run out of them.
  #[cfg(test)]
  pub(crate) const fn set_cap(&mut self, cap: usize) {
    self.cap = cap;
  }

  /// The number of slots that hold a stream.
  #[inline]
  #[cfg_attr(not(test), allow(dead_code, reason = "tests that run the slots out"))]
  pub(crate) const fn live(&self) -> usize {
    self.live
  }

  /// The bytes that the slots take at their capacity.
  #[cfg(all(feature = "_h3-loopback-client", feature = "http3-server-framework"))]
  pub(crate) fn bytes(&self) -> usize {
    self.entries.capacity().saturating_mul(size_of::<SlotEntry>())
  }

  /// Frees all but `keep` slots if none holds a stream.
  #[inline]
  #[cfg_attr(
    not(feature = "http3-server-framework"),
    allow(dead_code, reason = "only the HTTP/3 server framework trims idle workers")
  )]
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

  pub(super) fn alloc(&mut self) -> crate::Result<u32> {
    let idx = if self.free == NO_SLOT {
      if self.entries.len() >= self.cap {
        return Err(exhausted());
      }
      let idx = u32::try_from(self.entries.len()).map_err(|_err| exhausted())?;
      if self.entries.len() == self.entries.capacity() {
        let room = GROW_SLOTS.min(self.cap.saturating_sub(self.entries.len())).max(1);
        self.entries.try_reserve_exact(room).map_err(|_err| exhausted())?;
      }
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

  pub(super) fn entry_mut(&mut self, idx: u32) -> Option<&mut SlotEntry> {
    self.entries.get_mut(usize::try_from(idx).ok()?)
  }

  pub(super) fn free(&mut self, idx: u32) {
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

  pub(super) fn generation(&self, idx: u32) -> u32 {
    self.entries.get(usize::try_from(idx).unwrap_or(usize::MAX)).map_or(0, |el| el.generation)
  }

  pub(super) fn get(&self, idx: u32) -> Option<&Stream> {
    let entry = self.entries.get(usize::try_from(idx).ok()?)?;
    entry.live.then_some(&entry.stream)
  }

  pub(super) fn get_mut(&mut self, idx: u32) -> Option<&mut Stream> {
    self.entry_mut(idx).filter(|el| el.live).map(|el| &mut el.stream)
  }

  // The stream of a frame reference, if its slot was not freed since
  pub(super) fn get_live(&mut self, idx: u32, generation: u32) -> Option<&mut Stream> {
    self.entry_mut(idx).filter(|el| el.live && el.generation == generation).map(|el| &mut el.stream)
  }
}

#[derive(Debug)]
pub(super) struct SlotEntry {
  pub(super) generation: u32,
  pub(super) live: bool,
  pub(super) next_free: u32,
  pub(super) stream: Stream,
}

// The types of streams
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
  // Opened by the client
  Bidi,
  UniLocal,
  UniRemote,
}

// Where a stream is in its table
#[derive(Clone, Copy, Debug)]
pub(super) enum Entry {
  Closed,
  Implicit,
  NotOpened,
  Open(u32),
  Rejected,
}

// The streams of a type of a connection: an index array over the window, from the lowest stream
// that is not closed
#[derive(Debug)]
pub(super) struct Table<const W: usize> {
  pub(super) meta: TableMeta,
  pub(super) slots: [u32; W],
}

impl<const W: usize> Table<W> {
  pub(super) const fn new(limit: u64, window: u64) -> Self {
    Self { meta: TableMeta { base: 0, limit, next: 0, window }, slots: [NO_SLOT; W] }
  }

  pub(super) const fn view(&mut self) -> TableMut<'_> {
    TableMut { meta: &mut self.meta, slots: &mut self.slots }
  }

  pub(super) const fn view_ref(&self) -> TableRef<'_> {
    TableRef { meta: &self.meta, slots: &self.slots }
  }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct TableMeta {
  // The lowest stream that is not closed
  pub(super) base: u64,
  // Streams of the peer: the limit that it was given; ours: the limit that it gave
  pub(super) limit: u64,
  // The lowest stream that is not open
  pub(super) next: u64,
  pub(super) window: u64,
}

impl TableMeta {
  // The limit to give the peer, once it used half of what it has: the lowest stream that is not
  // closed plus the window
  pub(super) fn max_streams_due(&self) -> Option<u64> {
    let target = self.base.saturating_add(self.window);
    (target > self.limit && self.limit.saturating_sub(self.next) <= self.window / 2)
      .then_some(target)
  }
}

pub(super) struct TableMut<'table> {
  pub(super) meta: &'table mut TableMeta,
  pub(super) slots: &'table mut [u32],
}

impl TableMut<'_> {
  // The lowest stream that is not closed moves past the streams that closed
  pub(super) fn advance_base(&mut self) {
    while self.meta.base < self.meta.next
      && self.slots.get(pos(self.slots.len(), self.meta.base)) == Some(&NO_SLOT)
    {
      self.meta.base = self.meta.base.wrapping_add(1);
    }
  }

  pub(super) fn set(&mut self, index: u64, value: u32) {
    let at = pos(self.slots.len(), index);
    if let Some(elem) = self.slots.get_mut(at) {
      *elem = value;
    }
  }
}

#[derive(Clone, Copy)]
pub(super) struct TableRef<'table> {
  pub(super) meta: &'table TableMeta,
  pub(super) slots: &'table [u32],
}

impl TableRef<'_> {
  pub(super) fn entry(&self, index: u64) -> Entry {
    if index < self.meta.base {
      return Entry::Closed;
    }
    if index >= self.meta.next {
      return Entry::NotOpened;
    }
    match self.slots.get(pos(self.slots.len(), index)).copied() {
      None | Some(NO_SLOT) => Entry::Closed,
      Some(IMPLICIT) => Entry::Implicit,
      Some(REJECTED) => Entry::Rejected,
      Some(slot) => Entry::Open(slot),
    }
  }
}

// The entry of stream `index` in an index array of `len` entries
pub(super) fn pos(len: usize, index: u64) -> usize {
  usize::try_from(index % u64::try_from(len).unwrap_or(u64::MAX).max(1)).unwrap_or(0)
}

impl Streams {
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
  #[cfg(any(test, feature = "_h3-loopback-client"))]
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

  // The slot of stream `id` for the application, if it is open
  pub(super) fn app_slot(&self, id: StreamId) -> Option<u32> {
    match self.table(self.kind(id)?)?.entry(id.index()) {
      Entry::Open(slot) => Some(slot),
      Entry::Closed | Entry::Implicit | Entry::NotOpened | Entry::Rejected => None,
    }
  }

  // Checks whether MAX_STREAMS is due for the streams of the peer of `kind`
  pub(super) fn check_max_streams(&mut self, kind: Kind) {
    let flag = match kind {
      Kind::Bidi if !self.is_client => OWED_MAX_STREAMS_BIDI,
      Kind::UniRemote => OWED_MAX_STREAMS_UNI,
      Kind::Bidi | Kind::UniLocal => return,
    };
    if self.table(kind).and_then(|el| el.meta.max_streams_due()).is_some() {
      self.owed |= flag;
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

  // The slot of stream `id` for a frame of the peer that needs its receiving part, if `recv`, or
  // its sending part. Streams of the peer are opened, with the streams of their type below them;
  // `None` for a stream that is closed, whose frame is ignored.
  pub(super) fn frame_slot(
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
      // The data of a refused stream is counted by the caller
      Entry::Closed | Entry::Rejected => Ok(None),
      Entry::Open(slot) => Ok(Some(slot)),
      Entry::Implicit => self.create_or_reject(pools, params, kind, index),
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
        let slot = self.create_or_reject(pools, params, kind, index)?;
        self.check_max_streams(kind);
        Ok(slot)
      }
    }
  }

  // Makes the stream of the peer of `index` in `kind`, or refuses it if the slots of the worker
  // ran out (ruling T10-c)
  fn create_or_reject(
    &mut self,
    pools: &mut QuicPools,
    params: &ConnParams,
    kind: Kind,
    index: u64,
  ) -> crate::Result<Option<u32>> {
    match self.create(pools, params, kind, index) {
      Ok(slot) => Ok(Some(slot)),
      Err(err) if reject::refuses(&err) => self.reject(kind, index, err).map(|()| None),
      Err(err) => Err(err),
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
  pub(super) const fn kind(&self, id: StreamId) -> Option<Kind> {
    if !id.is_uni() {
      return if id.by_client() { Some(Kind::Bidi) } else { None };
    }
    if id.by_client() == self.is_client { Some(Kind::UniLocal) } else { Some(Kind::UniRemote) }
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

  // The table of `kind`, unless the streams were released
  pub(super) fn table(&self, kind: Kind) -> Option<TableRef<'_>> {
    match kind {
      Kind::Bidi => Some(self.bidi.view_ref()),
      Kind::UniLocal => self.cold.as_deref().map(|el| el.uni_local.view_ref()),
      Kind::UniRemote => self.cold.as_deref().map(|el| el.uni_remote.view_ref()),
    }
  }

  pub(super) fn table_mut(&mut self, kind: Kind) -> Option<TableMut<'_>> {
    match kind {
      Kind::Bidi => Some(self.bidi.view()),
      Kind::UniLocal => self.cold.as_deref_mut().map(|el| el.uni_local.view()),
      Kind::UniRemote => self.cold.as_deref_mut().map(|el| el.uni_remote.view()),
    }
  }
}
