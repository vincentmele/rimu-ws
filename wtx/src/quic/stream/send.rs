//! The sending part of a stream: the send queue in segments, its release on acknowledgment, and
//! the packing of STREAM frames and of the control frames of the streams.

use crate::quic::{
  BodyRef, ConnCtx, ConnParams, Frame, FrameWriter, QuicApp, QuicError, TransportErrorCode,
  pools::{FreeList, QuicPools, TX_BLOCK_LEN, TxBlock},
  sent::{FrameRef, FrameRefRange},
  stream::{
    INLINE_LEN, NO_LINK, OWED_DATA_BLOCKED, OWED_MAX_DATA, OWED_MAX_STREAMS_BIDI,
    OWED_MAX_STREAMS_UNI, RangeSet, StreamId, Streams, closed, excessive_load, exhausted,
    recv::RxState,
    table::{Kind, StreamSlots},
  },
  varint::varint_len,
};
use alloc::{boxed::Box, collections::VecDeque};
use core::hint::cold_path;

pub(super) const TX_RANGES: usize = 16;

// The list of streams with something to send
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Ready {
  // Next bytes written by copy, or the FIN alone: one frame each in turn
  Small,
  // Next bytes in a body: one stream at a time to its end
  Large,
}

#[derive(Debug)]
pub(super) struct SendPart {
  // Everything before was acknowledged and given back
  pub(super) acked: u64,
  // Acknowledged data after `acked`
  pub(super) acked_ranges: RangeSet<TX_RANGES>,
  // The limit of the last STREAM_DATA_BLOCKED, or `NOT_BLOCKED`
  pub(super) blocked_at: u64,
  pub(super) blocked_owed: bool,
  // The segment and the position in it of `sent`
  pub(super) cursor: usize,
  pub(super) cursor_pos: usize,
  // The end of what was written
  pub(super) end: u64,
  pub(super) exists: bool,
  // The application wrote the FIN, which is at `end`
  pub(super) fin: bool,
  pub(super) fin_acked: bool,
  pub(super) fin_sent: bool,
  pub(super) inline: [u8; INLINE_LEN],
  // Segments in `inline`, which is used from `inline_used` on
  pub(super) inline_live: u8,
  pub(super) inline_used: usize,
  // The credit given by the peer
  pub(super) max: u64,
  // The code of the RESET_STREAM of this part
  pub(super) reset: Option<u64>,
  pub(super) reset_acked: bool,
  pub(super) reset_owed: bool,
  // The offset of the first segment
  pub(super) seg_base: u64,
  pub(super) segs: VecDeque<Seg>,
  // The first byte not sent yet
  pub(super) sent: u64,
  pub(super) stop_counted: bool,
}

impl SendPart {
  // `bytes` after the last segment if it is a buffer with room after its bytes, in new segments
  // after that: in `inline` while they fit there, in blocks otherwise
  pub(super) fn append_bytes(
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
  pub(super) fn copy_unsent(&mut self, mut len: usize, fw: &mut FrameWriter<'_>) {
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
  pub(super) fn is_done(&self) -> bool {
    !self.exists
      || self.reset_acked
      || (self.reset.is_none() && self.fin_acked && self.acked >= self.end)
  }

  // If the next bytes to send are in a body
  pub(super) fn next_is_body(&self) -> bool {
    self.segs.get(self.cursor).is_some_and(|el| matches!(el.data, SegData::Body(_)))
  }

  // Acknowledged: the bytes from `offset`, `len` of them, and the FIN if `fin`
  pub(super) fn on_acked(
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

  pub(super) fn push(&mut self, seg: Seg) -> crate::Result<()> {
    self.segs.try_reserve(1).map_err(|_err| exhausted())?;
    self.segs.push_back(seg);
    Ok(())
  }

  // Gives back every segment
  pub(super) fn release(&mut self, blocks: &mut FreeList<Box<TxBlock>>) {
    while let Some(seg) = self.segs.pop_front() {
      self.release_seg(seg, blocks);
    }
    self.cursor = 0;
    self.cursor_pos = 0;
    self.inline_live = 0;
    self.inline_used = 0;
    self.seg_base = self.end;
  }

  pub(super) fn release_seg(&mut self, seg: Seg, blocks: &mut FreeList<Box<TxBlock>>) {
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
pub(super) struct Seg {
  pub(super) data: SegData,
  pub(super) len: usize,
}

impl Seg {
  pub(super) fn bytes<'this>(&'this self, inline: &'this [u8; INLINE_LEN]) -> &'this [u8] {
    match &self.data {
      SegData::Block(block) => block.get(..self.len),
      SegData::Body(body) => Some(body.as_slice()),
      SegData::Inline(pos) => inline.get(*pos..pos.wrapping_add(self.len)),
    }
    .unwrap_or_default()
  }
}

#[derive(Debug)]
pub(super) enum SegData {
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

// What a write did
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Wrote {
  Frame,
  // The packet is full
  Full,
  // Nothing can be sent now
  Blocked,
}

impl Streams {
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

  /// Resets the sending part of stream `id`, for the application.
  #[inline]
  pub(crate) fn reset(&mut self, pools: &mut QuicPools, id: StreamId, code: u64) {
    if let Some(slot) = self.app_slot(id) {
      self.reset_send(pools, slot, code);
    }
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

  pub(super) fn unlink_ready(&mut self, slots: &mut StreamSlots, slot: u32) {
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
