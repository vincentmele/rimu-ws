//! The receiving part of a stream: data put in order, waiting data in blocks, retained bytes,
//! and the delivery to the application.

use crate::quic::{
  ConnCtx, ConnParams, QuicApp, QuicError, QuicLimits, TransportErrorCode,
  flow::{flow_control_error, top_up},
  pools::{FreeList, QuicPools, RX_BLOCK_LEN, RxBlock},
  stream::{
    INLINE_LEN, OWED_MAX_DATA, RangeBlock, RangeSet, StreamId, Streams, closed, excessive_load,
    exhausted, final_size_error, out_of_order_limit, table::StreamSlots,
  },
};
use alloc::{boxed::Box, vec::Vec};
use core::hint::cold_path;

pub(super) const RX_BLOCK: u64 = RX_BLOCK_LEN as u64;

// Separate ranges held at most by a stream: received data that waits, acknowledged data
pub(super) const RX_RANGES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RxState {
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
pub(super) struct RecvPart {
  // Receive blocks held, the ones out for a call of the application included
  pub(super) blocks: u32,
  // What the application consumed when credit was last counted: `read - keep`
  pub(super) consumed: u64,
  pub(super) final_size: Option<u64>,
  // The end of the highest data received
  pub(super) high: u64,
  pub(super) inline: [u8; INLINE_LEN],
  // Bytes retained by the application, which end at `read`: in `inline`, or in `keep_block` if
  // it is there
  pub(super) keep: usize,
  pub(super) keep_block: Option<Box<RxBlock>>,
  // The credit given to the peer
  pub(super) max: u64,
  // The MAX_STREAM_DATA that carried `max` was lost: it is sent again even if `max` did not move
  pub(super) max_lost: bool,
  pub(super) max_owed: bool,
  // Data after `read` that waits for earlier data, and the blocks that hold it by number: an
  // index from the pools while there are some, with room for every block that a stream can hold
  pub(super) ooo: RangeSet<RX_RANGES>,
  pub(super) ooo_blocks: Vec<OooBlock>,
  // The first byte that the application was not given
  pub(super) read: u64,
  pub(super) state: RxState,
  pub(super) stop_code: u64,
  pub(super) stop_owed: bool,
}

impl RecvPart {
  // If nothing more is expected
  pub(super) fn is_done(&self) -> bool {
    match self.state {
      RxState::None | RxState::Done => true,
      RxState::Discard => self.final_size.is_some(),
      RxState::Recv => false,
    }
  }

  // The bytes that can go to the application next, after the retained ones: what the packet has
  // at `read`, or else the waiting data at `read`, up to the end of its block
  pub(super) fn next_run(&self, direct: &[u8]) -> usize {
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
  pub(super) fn drop_below_read(&mut self, pools: RxPools<'_>, held: &mut Held) {
    let RxPools { blocks, indexes, range_blocks } = pools;
    if self.ooo.remove_below(self.read, range_blocks) {
      held.refund(&mut self.blocks);
    }
    let gone = self
      .ooo_blocks
      .partition_point(|el| el.no.wrapping_add(1).wrapping_mul(RX_BLOCK) <= self.read);
    for elem in self.ooo_blocks.drain(..gone) {
      if let Some(block) = elem.data {
        held.give(blocks, &mut self.blocks, block);
      }
    }
    self.give_index(indexes);
  }

  // The index of the blocks goes back to the pools once it is empty
  fn give_index(&mut self, indexes: &mut FreeList<Vec<OooBlock>>) {
    if self.ooo_blocks.is_empty() && self.ooo_blocks.capacity() > 0 {
      indexes.give(core::mem::take(&mut self.ooo_blocks));
    }
  }

  // Gives back the blocks that are here, not one that is out for a call of the application
  pub(super) fn release(&mut self, pools: RxPools<'_>, held: &mut Held) {
    let RxPools { blocks, indexes, range_blocks } = pools;
    if let Some(block) = self.keep_block.take() {
      held.give(blocks, &mut self.blocks, block);
    }
    for elem in self.ooo_blocks.drain(..) {
      if let Some(block) = elem.data {
        held.give(blocks, &mut self.blocks, block);
      }
    }
    self.give_index(indexes);
    if self.ooo.release(range_blocks) {
      held.refund(&mut self.blocks);
    }
    self.keep = 0;
  }

  // `bytes` become the retained bytes, which there were none of
  pub(super) fn store_keep(
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
pub(super) struct Held {
  pub(super) blocks: u32,
  // The streams that hold at least one
  pub(super) streams: u32,
}

impl Held {
  // Counts a block of 4 KiB more for a part that holds `own` blocks. The cap of the connection is
  // the bytes that its credit allows and, as blocks count whole, four blocks for each stream that
  // holds some: a stream holds data within the bytes of its credit that it did not consume, whose
  // first and last blocks may hold little of it, the bytes that it retains in a block of their
  // own and the block that the ranges of its waiting data spill into (ruling T9-d). A peer within
  // its credit never goes past it (ruling T8-g).
  pub(super) fn charge(&mut self, own: &mut u32, limits: &QuicLimits) -> crate::Result<()> {
    let streams = u64::from(self.streams).wrapping_add(u64::from(*own == 0));
    let max = u64::from(limits.max_out_of_order_bytes_per_conn)
      .div_ceil(RX_BLOCK)
      .saturating_add(streams.saturating_mul(4));
    if u64::from(self.blocks) >= max {
      return Err(out_of_order_limit());
    }
    if *own == 0 {
      self.streams = self.streams.wrapping_add(1);
    }
    self.blocks = self.blocks.wrapping_add(1);
    *own = own.wrapping_add(1);
    Ok(())
  }

  // `block` goes back from a part that holds `own` blocks
  pub(super) fn give(
    &mut self,
    blocks: &mut FreeList<Box<RxBlock>>,
    own: &mut u32,
    block: Box<RxBlock>,
  ) {
    blocks.give(block);
    self.refund(own);
  }

  // A block of a part that holds `own` blocks went back
  pub(super) fn refund(&mut self, own: &mut u32) {
    self.blocks = self.blocks.saturating_sub(1);
    if *own == 1 {
      self.streams = self.streams.saturating_sub(1);
    }
    *own = own.saturating_sub(1);
  }

  // A block for a part that holds `own` blocks (see [`Self::charge`])
  pub(super) fn take(
    &mut self,
    blocks: &mut FreeList<Box<RxBlock>>,
    own: &mut u32,
    limits: &QuicLimits,
  ) -> crate::Result<Box<RxBlock>> {
    self.charge(own, limits)?;
    Ok(blocks.take().unwrap_or_else(|| Box::new([0; RX_BLOCK_LEN])))
  }
}

/// The pools that the receiving part of a stream gives back to.
pub(super) struct RxPools<'pools> {
  pub(super) blocks: &'pools mut FreeList<Box<RxBlock>>,
  pub(super) indexes: &'pools mut FreeList<Vec<OooBlock>>,
  pub(super) range_blocks: &'pools mut FreeList<Box<RangeBlock>>,
}

/// A receive block of waiting data of a stream, by number.
#[derive(Debug)]
pub(crate) struct OooBlock {
  // Out of the vector while its bytes are with the application
  pub(super) data: Option<Box<RxBlock>>,
  // The offsets of the block are from `no * 4096`
  pub(super) no: u64,
}

// What is taken out of the stream for a call of `on_stream_data`
pub(super) enum Piece {
  // The rest of the packet
  Direct,
  // The retained bytes and what followed them, in the retaining block if it is there
  Keep(Option<Box<RxBlock>>),
  // Waiting data from block `no`, at `pos`
  Block { block: Box<RxBlock>, no: u64, pos: usize },
  // The FIN, after everything was given
  Fin,
}

// Adds to the retained bytes, which take a block once they do not fit inline, the next `next`
// bytes: from `direct` if it has any, from the waiting data otherwise. Returns how many.
pub(super) fn append_to_keep(
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

impl Streams {
  /// DATA_BLOCKED: the peer has no connection credit left.
  #[inline]
  pub(crate) fn on_data_blocked(&mut self, params: &ConnParams) {
    if self.flow.rx_consumed.saturating_add(params.conn_credit()) > self.flow.rx_max {
      self.owed |= OWED_MAX_DATA;
    }
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
    let QuicPools { ooo_indexes, range_blocks, stream_slots, rx_blocks, .. } = &mut *pools;
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
      let pools = RxPools { blocks: rx_blocks, indexes: ooo_indexes, range_blocks };
      rx.release(pools, &mut cold.held);
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
    let QuicPools { ooo_indexes, range_blocks, rx_blocks, stream_slots, .. } = &mut *pools;
    let Some(stream) = stream_slots.get_mut(slot) else {
      return;
    };
    let rx = &mut stream.rx;
    if rx.state != RxState::Recv {
      return;
    }
    if let Some(cold) = self.cold.as_deref_mut() {
      let pools = RxPools { blocks: rx_blocks, indexes: ooo_indexes, range_blocks };
      rx.release(pools, &mut cold.held);
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
      let QuicPools { ooo_indexes, range_blocks, rx_blocks, stream_slots, .. } = &mut *pools;
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
      rx.drop_below_read(RxPools { blocks: rx_blocks, indexes: ooo_indexes, range_blocks }, held);
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
          if inline.is_none() {
            inline = Some([0; INLINE_LEN]);
          }
          if let Some((dst, src)) =
            inline.as_mut().and_then(|el| el.get_mut(..rx.keep)).zip(rx.inline.get(..rx.keep))
          {
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
      let QuicPools { ooo_indexes, range_blocks, rx_blocks, stream_slots, .. } = &mut *pools;
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
        rx.release(RxPools { blocks: rx_blocks, indexes: ooo_indexes, range_blocks }, held);
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

  fn owe_max_data_if_due(&mut self, params: &ConnParams) {
    if self.flow.max_data_due(params.conn_credit()).is_some() {
      self.owed |= OWED_MAX_DATA;
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
    let QuicPools { ooo_indexes, range_blocks, rx_blocks, stream_slots, .. } = &mut *pools;
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
    if rx.ooo.needs_block(offset, end) {
      // The block of the ranges counts like a block of data
      let held = self.cold.as_deref_mut().map(|el| &mut el.held).ok_or_else(closed)?;
      held.charge(&mut rx.blocks, limits)?;
    }
    rx.ooo.insert(offset, end, range_blocks)?;
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
          if rx.ooo_blocks.capacity() == 0 {
            // Room for every block that the data of a stream spans, so that the index never grows
            let len = u64::from(limits.max_out_of_order_bytes_per_stream).div_ceil(RX_BLOCK);
            let len = usize::try_from(len).unwrap_or(usize::MAX).saturating_add(2);
            rx.ooo_blocks = ooo_indexes.take().unwrap_or_else(|| Vec::with_capacity(len));
          }
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
}
