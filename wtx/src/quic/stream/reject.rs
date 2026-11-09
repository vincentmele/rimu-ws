//! The streams of the peer that were refused because the worker had no stream slot left (ruling
//! T10-c): the stream is reset with RESET_STREAM and STOP_SENDING of
//! [`QuicLimits::stream_rejected_app_code`](crate::quic::QuicLimits::stream_rejected_app_code)
//! instead of closing the connection. A refused stream has no slot: its entry in the table of
//! the streams says so, and a record of the connection counts the data that still arrives
//! towards the connection credit, which it gives back at once, until the final size is known and
//! our RESET_STREAM is acknowledged. A connection holds at most [`MAX_REJECTED`] of them; one
//! more closes it as before, with INTERNAL_ERROR.

use crate::quic::{
  ConnParams, Frame, FrameWriter, QuicError,
  flow::flow_control_error,
  pools::QuicPools,
  sent::{FrameRef, FrameRefRange},
  stream::{
    OWED_REJECTS, StreamId, Streams, final_size_error,
    table::{Kind, NO_SLOT, REJECTED},
  },
};
use core::hint::cold_path;

/// The refused streams that a connection keeps at once.
pub(crate) const MAX_REJECTED: usize = 8;

// A refused stream: what arrived of it and the frames that refuse it
#[derive(Clone, Copy, Debug)]
pub(super) struct Rejected {
  final_size: Option<u64>,
  // The end of the highest data received, counted towards the connection credit
  high: u64,
  id: StreamId,
  // A bidirectional stream: its sending part is reset
  reset_acked: bool,
  reset_owed: bool,
  stop_owed: bool,
}

impl Rejected {
  // Nothing more can arrive and our RESET_STREAM arrived
  const fn is_done(&self) -> bool {
    self.final_size.is_some() && self.reset_acked
  }
}

impl Streams {
  /// The refused streams that wait for their end, for tests.
  #[cfg(test)]
  pub(crate) fn rejected(&self) -> usize {
    self.cold.as_deref().map_or(0, |el| el.rejects.iter().flatten().count())
  }

  // If stream `id` was refused and its RESET_STREAM is not acknowledged yet.
  pub(super) fn reset_unacked(&self, id: StreamId) -> bool {
    self
      .cold
      .as_deref()
      .and_then(|el| el.rejects.iter().flatten().find(|el| el.id == id))
      .is_some_and(|el| !el.reset_acked)
  }

  // Refuses stream `index` of `kind`, of the peer, for which no slot was left. Past
  // `MAX_REJECTED` refused streams, the connection closes as before.
  pub(super) fn reject(&mut self, kind: Kind, index: u64, err: crate::Error) -> crate::Result<()> {
    let bidi = kind == Kind::Bidi;
    let id = StreamId::of(index, !self.is_client, !bidi);
    let Some(cold) = self.cold.as_deref_mut() else {
      return Err(err);
    };
    let Some(free) = cold.rejects.iter_mut().find(|el| el.is_none()) else {
      cold_path();
      return Err(err);
    };
    *free = Some(Rejected {
      final_size: None,
      high: 0,
      id,
      reset_acked: !bidi,
      reset_owed: bidi,
      stop_owed: true,
    });
    if let Some(mut table) = self.table_mut(kind) {
      table.set(index, REJECTED);
    }
    self.owed |= OWED_REJECTS;
    Ok(())
  }

  // Data of the refused stream `id`, to `end`: counted towards the connection credit, which is
  // given back, and dropped. Not refused: ignored.
  pub(super) fn on_rejected_data(
    &mut self,
    params: &ConnParams,
    id: StreamId,
    end: u64,
    fin: bool,
    reset: bool,
  ) -> crate::Result<()> {
    let Some(rec) = self
      .cold
      .as_deref_mut()
      .and_then(|el| el.rejects.iter_mut().flatten().find(|el| el.id == id))
    else {
      return Ok(());
    };
    // RFC 9000 section 4.5
    if let Some(size) = rec.final_size
      && (end > size || ((fin || reset) && end != size))
    {
      return Err(final_size_error());
    }
    if (fin || reset) && end < rec.high {
      return Err(final_size_error());
    }
    if end > params.stream_credit() {
      return Err(flow_control_error());
    }
    let fresh = end.saturating_sub(rec.high);
    self.flow.on_received(fresh)?;
    self.flow.on_consumed(fresh);
    rec.high = rec.high.max(end);
    if fin || reset {
      rec.final_size = Some(end);
      // Not needed anymore (RFC 9000 section 3.5)
      rec.stop_owed = false;
    }
    self.owe_max_data_if_due(params);
    self.finish_rejected(id);
    Ok(())
  }

  // A frame that refuses a stream was acknowledged (`acked`) or lost.
  pub(super) fn on_rejected_frame(&mut self, id: u64, stop: bool, acked: bool) {
    let Some(rec) = self
      .cold
      .as_deref_mut()
      .and_then(|el| el.rejects.iter_mut().flatten().find(|el| el.id.0 == id))
    else {
      return;
    };
    match (stop, acked) {
      (false, true) => rec.reset_acked = true,
      (false, false) => rec.reset_owed = !rec.reset_acked,
      (true, true) => {}
      (true, false) => rec.stop_owed = rec.final_size.is_none(),
    }
    if rec.reset_owed || rec.stop_owed {
      self.owed |= OWED_REJECTS;
    }
    self.finish_rejected(StreamId(id));
  }

  // Writes the RESET_STREAM and STOP_SENDING frames of the refused streams that are owed. Returns
  // `false` if the packet is full.
  pub(super) fn write_rejects(
    &mut self,
    fw: &mut FrameWriter<'_>,
    frames: &mut FrameRefRange,
    pools: &mut QuicPools,
    params: &ConnParams,
    wrote: &mut bool,
  ) -> crate::Result<bool> {
    if self.owed & OWED_REJECTS == 0 {
      return Ok(true);
    }
    let code = params.limits.stream_rejected_app_code;
    let Some(cold) = self.cold.as_deref_mut() else {
      return Ok(true);
    };
    for rec in cold.rejects.iter_mut().flatten() {
      let id = rec.id.0;
      if rec.reset_owed {
        // Nothing was sent: the final size is zero
        if !fw.write_frame(&Frame::ResetStream { id, code, final_size: 0 }) {
          return Ok(false);
        }
        pools.frame_refs.push(frames, FrameRef::RejectedStream { id, stop: false })?;
        rec.reset_owed = false;
        *wrote = true;
      }
      if rec.stop_owed {
        if !fw.write_frame(&Frame::StopSending { id, code }) {
          return Ok(false);
        }
        pools.frame_refs.push(frames, FrameRef::RejectedStream { id, stop: true })?;
        rec.stop_owed = false;
        *wrote = true;
      }
    }
    self.owed &= !OWED_REJECTS;
    Ok(true)
  }

  // The refused stream `id` is over once it is done: its entry closes, which lets the limit of
  // streams of the peer move on.
  fn finish_rejected(&mut self, id: StreamId) {
    let Some(cold) = self.cold.as_deref_mut() else {
      return;
    };
    let Some(slot) = cold.rejects.iter_mut().find(|el| el.is_some_and(|el| el.id == id)) else {
      return;
    };
    if !slot.is_some_and(|el| el.is_done()) {
      return;
    }
    *slot = None;
    let Some(kind) = self.kind(id) else {
      return;
    };
    if let Some(mut table) = self.table_mut(kind) {
      table.set(id.index(), NO_SLOT);
      table.advance_base();
    }
    self.check_max_streams(kind);
  }
}

// If `err` says that the slots of the worker ran out, which refuses a stream.
pub(super) const fn refuses(err: &crate::Error) -> bool {
  matches!(err, crate::Error::QuicClose(_, QuicError::PoolExhausted))
}
