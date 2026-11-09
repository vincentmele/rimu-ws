//! Flow control (RFC 9000 section 4): the credit of the connection in both directions and the
//! rule that gives credit back.
//!
//! The windows are large (spec section 5.8) and credit is given back unasked, once half of a
//! window was used, in the flush that carries the responses: a client that never sends
//! DATA_BLOCKED or STREAM_DATA_BLOCKED is never left waiting. Credit comes back for bytes that
//! the application consumed or that were discarded, not for bytes that wait for earlier data or
//! that it retains. The credit of each stream lives with the stream ([`crate::quic::stream`]),
//! which uses the same rule.

use crate::quic::{QuicError, TransportErrorCode};
use core::hint::cold_path;

/// The limit of a DATA_BLOCKED or STREAM_DATA_BLOCKED that was not sent.
pub(crate) const NOT_BLOCKED: u64 = u64::MAX;

/// The credit of a connection, in both directions.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnFlow {
  /// The credit given to the peer, the last MAX_DATA (or `initial_max_data`).
  pub(crate) rx_max: u64,
  /// What the peer used of it: the sum of the highest offsets of its streams, the final sizes of
  /// reset streams included (RFC 9000 section 4.5).
  pub(crate) rx_high: u64,
  /// The bytes of that that the application consumed or that were discarded.
  pub(crate) rx_consumed: u64,
  /// The credit that the peer gave.
  pub(crate) tx_max: u64,
  /// The bytes of stream data sent for the first time.
  pub(crate) tx_sent: u64,
  /// The limit that the last DATA_BLOCKED reported, [`NOT_BLOCKED`] if none.
  pub(crate) tx_blocked_at: u64,
}

impl ConnFlow {
  /// The credit of a new connection, which gives `window` bytes and has none until the transport
  /// parameters of the peer arrive.
  #[inline]
  pub(crate) const fn new(window: u64) -> Self {
    Self {
      rx_max: window,
      rx_high: 0,
      rx_consumed: 0,
      tx_max: 0,
      tx_sent: 0,
      tx_blocked_at: NOT_BLOCKED,
    }
  }

  /// The new limit to give the peer if it is due ([`top_up`]).
  #[inline]
  pub(crate) fn max_data_due(&self, window: u64) -> Option<u64> {
    top_up(self.rx_consumed, self.rx_max, window)
  }

  /// `len` bytes that the peer had not used before arrived. A FLOW_CONTROL_ERROR if they go past
  /// its credit.
  #[inline]
  pub(crate) fn on_received(&mut self, len: u64) -> crate::Result<()> {
    let high = self.rx_high.saturating_add(len);
    if high > self.rx_max {
      return Err(flow_control_error());
    }
    self.rx_high = high;
    Ok(())
  }

  /// `len` received bytes were consumed or discarded.
  #[inline]
  pub(crate) const fn on_consumed(&mut self, len: u64) {
    self.rx_consumed = self.rx_consumed.saturating_add(len);
  }

  /// The bytes that can still be sent for the first time.
  #[inline]
  pub(crate) const fn tx_room(&self) -> u64 {
    self.tx_max.saturating_sub(self.tx_sent)
  }
}

/// The limit to give a peer that used `consumed` bytes of a window of `window` bytes, of which
/// it was last given `advertised`: `consumed + window` once that is at least half a window more,
/// `None` before.
#[inline]
pub(crate) fn top_up(consumed: u64, advertised: u64, window: u64) -> Option<u64> {
  let target = consumed.saturating_add(window);
  let gain = target.checked_sub(advertised).filter(|elem| *elem > 0)?;
  (gain >= window / 2).then_some(target)
}

#[inline(always)]
pub(crate) fn flow_control_error() -> crate::Error {
  cold_path();
  crate::Error::QuicClose(TransportErrorCode::FlowControlError, QuicError::FlowControlExceeded)
}

#[cfg(test)]
mod tests {
  use crate::quic::{
    BodyRef, ConnState, Frame, TransportErrorCode,
    flow::top_up,
    testing::{Behavior, Link, LinkOpts, TestApp, encode_frames},
  };
  use alloc::{rc::Rc, vec::Vec};

  fn settled(opts: &LinkOpts) -> Link {
    let mut link = Link::new(opts);
    link.run();
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    link
  }

  fn client_sends(link: &mut Link, frames: &[Frame<'_>]) {
    link.client.conn.queue_test_frames(&encode_frames(frames));
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
  }

  fn transport(code: TransportErrorCode) -> Option<(bool, u64)> {
    Some((false, code.code()))
  }

  // Credit is given again once half of the window was used, up to a window past what was used.
  #[test]
  fn top_up_is_due_at_half_window() {
    assert_eq!(top_up(0, 1000, 1000), None);
    assert_eq!(top_up(499, 1000, 1000), None);
    assert_eq!(top_up(500, 1000, 1000), Some(1500));
    assert_eq!(top_up(1700, 1500, 1000), Some(2700));
    // A limit that was raised further is never lowered
    assert_eq!(top_up(500, 5000, 1000), None);
  }

  // A client that never sends DATA_BLOCKED or STREAM_DATA_BLOCKED uploads 4 MiB, 16 stream windows
  // and 4 connection windows: the server gives credit before it is asked.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn large_upload_without_blocked_frames_completes() {
    let mut opts = LinkOpts::new(None);
    opts.server.stream_window = 256 << 10;
    opts.server.conn_window = 1 << 20;
    let mut link = settled(&opts);
    link.client.conn.streams_mut().never_send_blocked_frames();
    let len = 4u32 << 20;
    let body: Rc<[u8]> = (0..len).map(|el| (el % 249) as u8).collect();
    let now_us = link.now_us;
    let id = link.client.with_ctx(now_us, |cx| {
      let id = cx.open_bidi()?;
      cx.write_body(id, BodyRef::new(body.clone(), 0..len)?, true)?;
      Ok::<_, crate::Error>(id)
    });
    let id = id.unwrap();
    link.run_for(4096);
    let log = &link.server.app.streams[&id.0];
    assert!(log.fin);
    assert!(log.data == *body);
    assert_eq!(link.client.conn.streams().blocked_frames_sent(), 0);
    let now_us = link.now_us;
    assert_eq!(link.client.with_ctx(now_us, |cx| cx.unsent_bytes()), 0);
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
  }

  fn open_bidi(link: &mut Link) -> crate::quic::StreamId {
    let now_us = link.now_us;
    link.client.with_ctx(now_us, |cx| cx.open_bidi()).unwrap()
  }

  // Ruling T8-g: a peer that sends a whole stream window after a gap at its start, as one whose
  // first packet was lost does, trips no limit, and the stream reaches the application once the
  // gap is filled.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn full_window_after_a_gap_is_delivered() {
    const PIECE: usize = 1000;
    let mut link = settled(&LinkOpts::new(None));
    let window = usize::try_from(crate::quic::ConnParams::default().stream_window).unwrap();
    let id = open_bidi(&mut link);
    let data: Vec<u8> = (0..window).map(|el| (el % 253) as u8).collect();
    for (nth, offset) in (PIECE..window).step_by(PIECE).enumerate() {
      let end = (offset + PIECE).min(window);
      let piece = &data[offset..end];
      let frame =
        Frame::Stream { id: id.0, offset: offset as u64, data: piece, fin: end == window };
      client_sends(&mut link, &[frame]);
      assert_eq!(link.server.conn.state(), ConnState::Confirmed, "{offset}");
      // The acknowledgments make room for more packets of the client
      if nth % 64 == 63 {
        link.run();
      }
    }
    assert!(!link.server.app.streams.contains_key(&id.0));
    let frame = Frame::Stream { id: id.0, offset: 0, data: &data[..PIECE], fin: false };
    client_sends(&mut link, &[frame]);
    let log = &link.server.app.streams[&id.0];
    assert!(log.fin && log.data == data);
    assert_eq!(link.server.conn.streams().held_blocks(), 0);
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
  }

  // Ruling T8-g: early data is held in blocks that count whole. A peer within its credit that
  // sends small pieces across the edges of blocks, on several streams, trips no limit, even with
  // caps as small as the windows.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn pieces_across_block_edges_within_credit_trip_no_limit() {
    let mut opts = LinkOpts::new(None);
    opts.server.stream_window = 64 << 10;
    opts.server.conn_window = 64 << 10;
    opts.server.limits.max_out_of_order_bytes_per_stream = 64 << 10;
    opts.server.limits.max_out_of_order_bytes_per_conn = 64 << 10;
    let mut link = settled(&opts);
    // On each stream two bytes across the edge of its first two blocks, 4,097 bytes of credit
    for _ in 0..15 {
      let id = open_bidi(&mut link);
      let frame = Frame::Stream { id: id.0, offset: 4095, data: b"xy", fin: false };
      client_sends(&mut link, &[frame]);
      assert_eq!(link.server.conn.state(), ConnState::Confirmed, "{id:?}");
    }
    // 30 blocks for less than 16 of credit
    assert_eq!(link.server.conn.streams().held_blocks(), 30);
  }

  // Ruling T8-g: caps below the windows bound the credit that is given, at first and with every
  // MAX_STREAM_DATA and MAX_DATA, and an upload goes through within them.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn credit_never_exceeds_a_smaller_cap() {
    const STREAM_CAP: u64 = 64 << 10;
    const CONN_CAP: u64 = 256 << 10;
    let mut opts = LinkOpts::new(None);
    opts.server.limits.max_out_of_order_bytes_per_stream = STREAM_CAP as u32;
    opts.server.limits.max_out_of_order_bytes_per_conn = CONN_CAP as u32;
    let mut link = settled(&opts);
    assert_eq!(link.client.conn.streams().conn_credit().2, CONN_CAP);
    let len = 1u32 << 20;
    let body: Rc<[u8]> = (0..len).map(|el| (el % 247) as u8).collect();
    let now_us = link.now_us;
    let id = link
      .client
      .with_ctx(now_us, |cx| {
        let id = cx.open_bidi()?;
        cx.write_body(id, BodyRef::new(body.clone(), 0..len)?, true)?;
        Ok::<_, crate::Error>(id)
      })
      .unwrap();
    let client_slots = &link.client.parts.pools.stream_slots;
    assert_eq!(link.client.conn.streams().send_credit(client_slots, id), Some(STREAM_CAP));
    for _ in 0..4096 {
      let server = link.server.conn.streams();
      if let Some((max, consumed)) = server.recv_credit(&link.server.parts.pools.stream_slots, id) {
        assert!(max - consumed <= STREAM_CAP, "{max} {consumed}");
      }
      let (max, consumed, _) = server.conn_credit();
      assert!(max - consumed <= CONN_CAP, "{max} {consumed}");
      if !link.step() {
        break;
      }
    }
    let log = &link.server.app.streams[&id.0];
    assert!(log.fin && log.data == *body);
  }

  // Rule: data past the credit of a stream or of the connection is a FLOW_CONTROL_ERROR (RFC 9000
  // section 4.1); RESET_STREAM counts its final size.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn data_beyond_credit_is_flow_control_error() {
    let data = [0; 1001];
    let cases: [[Frame<'_>; 2]; 4] = [
      [
        Frame::Stream { id: 0, offset: 0, data: &data[..1000], fin: false },
        Frame::Stream { id: 0, offset: 1000, data: &data[..1], fin: false },
      ],
      [
        Frame::Stream { id: 0, offset: 0, data: &data[..1000], fin: false },
        Frame::Stream { id: 4, offset: 0, data: &data[..501], fin: false },
      ],
      // The final size of a reset counts towards the credit of the connection
      [
        Frame::ResetStream { id: 0, code: 0, final_size: 1000 },
        Frame::Stream { id: 4, offset: 0, data: &data[..501], fin: false },
      ],
      [
        Frame::Stream { id: 0, offset: 0, data: &data[..10], fin: false },
        Frame::ResetStream { id: 0, code: 0, final_size: 1001 },
      ],
    ];
    for [first, second] in cases {
      let mut opts = LinkOpts::new(None);
      opts.server.stream_window = 1000;
      opts.server.conn_window = 1500;
      let mut link = settled(&opts);
      client_sends(&mut link, &[first]);
      assert_eq!(link.server.conn.state(), ConnState::Confirmed, "{first:?}");
      client_sends(&mut link, &[second]);
      let code = link.server.conn.close_code();
      assert_eq!(code, transport(TransportErrorCode::FlowControlError), "{second:?}");
    }
  }

  // Rule: a final size that changes, data past it and a final size below the data that arrived
  // are FINAL_SIZE_ERRORs (RFC 9000 section 4.5).
  #[cfg_attr(miri, ignore)]
  #[test]
  fn final_size_changes_are_final_size_errors() {
    let data = [0; 20];
    let stream =
      |len: usize, offset: u64, fin: bool| Frame::Stream { id: 0, offset, data: &data[..len], fin };
    let reset = |final_size: u64| Frame::ResetStream { id: 0, code: 0, final_size };
    let cases = [
      [stream(10, 0, true), stream(12, 0, true)],
      [stream(10, 0, true), stream(1, 10, false)],
      [stream(20, 0, false), stream(10, 0, true)],
      [stream(10, 0, false), reset(5)],
      [stream(10, 0, true), reset(11)],
      [reset(10), stream(1, 10, false)],
    ];
    for [first, second] in cases {
      let mut link = settled(&LinkOpts::new(None));
      client_sends(&mut link, &[first]);
      assert_eq!(link.server.conn.state(), ConnState::Confirmed, "{first:?}");
      client_sends(&mut link, &[second]);
      let code = link.server.conn.close_code();
      assert_eq!(code, transport(TransportErrorCode::FinalSizeError), "{first:?} {second:?}");
    }
  }

  // STREAM_DATA_BLOCKED and DATA_BLOCKED go out once for each limit that holds data back, never
  // again for the same limit. Retained bytes give no credit back.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn blocked_frames_go_out_once_per_limit() {
    let mut opts = LinkOpts::new(None);
    opts.server.stream_window = 1000;
    opts.server.conn_window = 1500;
    // Without a line break the whole stream is retained
    opts.server_app = TestApp::new(Behavior::Lines);
    let mut link = settled(&opts);
    let now_us = link.now_us;
    link
      .client
      .with_ctx(now_us, |cx| {
        let first = cx.open_bidi()?;
        cx.write(first, &[b'a'; 3000], false)?;
        let second = cx.open_bidi()?;
        cx.write(second, &[b'b'; 1000], false)
      })
      .unwrap();
    link.run();
    // 1,000 bytes of the first stream, 500 of the second
    assert_eq!(link.client.with_ctx(now_us, |cx| cx.unsent_bytes()), 2500);
    assert_eq!(link.client.conn.streams().blocked_frames_sent(), 2);
    for _ in 0..3 {
      link.client.conn.queue_test_frames(&[0x01]);
      link.run();
    }
    assert_eq!(link.client.conn.streams().blocked_frames_sent(), 2);
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
  }
}
