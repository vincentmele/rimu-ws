//! What a QUIC connection and the application on top of it (HTTP/3) tell each other: the
//! callbacks of [`QuicApp`], the [`ConnCtx`] that the application acts through, and
//! [`BodyRef`], a body that is sent by reference.

use crate::{
  misc::SharedBytes,
  quic::{
    ConnParams, QuicError,
    pools::{QuicPools, RX_BLOCK_LEN},
    stream::{Source, StreamId, Streams},
  },
};
use core::{hint::cold_path, net::IpAddr, ops::Range};

/// What a connection tells the application.
///
/// Every callback gets the [`ConnCtx`] of the connection, through which it writes, opens, resets
/// and closes, and reaches its [`Self::ConnState`].
///
/// # Errors
///
/// An error returned by a callback closes the connection: [`crate::Error::QuicClose`] with a
/// transport CONNECTION_CLOSE of its [`crate::quic::TransportErrorCode`], any other error with a
/// transport CONNECTION_CLOSE of INTERNAL_ERROR. An application that closes with a code of its own
/// calls [`ConnCtx::close`] and returns `Ok`.
pub(crate) trait QuicApp {
  /// The state that the application keeps for each connection.
  type ConnState: Default;

  /// The handshake is complete: the connection can carry application data.
  fn on_established(&mut self, cx: &mut ConnCtx<'_, Self::ConnState>) -> crate::Result<()>;

  /// The next bytes of stream `id`, in order: the bytes that the application retained from the
  /// previous call ([`ConnCtx::retain`]) and then the ones that follow them. `fin` says that the
  /// last byte of the stream is the last one of `data`, which can then be empty. Bytes that
  /// arrive in order come straight from the packet.
  fn on_stream_data(
    &mut self,
    cx: &mut ConnCtx<'_, Self::ConnState>,
    id: StreamId,
    data: &[u8],
    fin: bool,
  ) -> crate::Result<()>;

  /// The peer abandoned the sending part of stream `id` (RESET_STREAM) with the application
  /// error `code`: nothing more arrives on it.
  ///
  /// The sending part of a bidirectional stream stays open: the stream keeps its slot, and holds
  /// back the stream credit of the peer (MAX_STREAMS), until the application finishes it (a write
  /// with the FIN, then its acknowledgment) or resets it with [`ConnCtx::reset`]. An application
  /// that drops the request should reset it.
  fn on_stream_reset(
    &mut self,
    cx: &mut ConnCtx<'_, Self::ConnState>,
    id: StreamId,
    code: u64,
  ) -> crate::Result<()>;

  /// The peer wants nothing more on stream `id` (STOP_SENDING) with the application error
  /// `code`. Once this returns the connection resets the sending part of the stream with `code`,
  /// unless the application reset it already, and writes to it fail.
  fn on_stop_sending(
    &mut self,
    cx: &mut ConnCtx<'_, Self::ConnState>,
    id: StreamId,
    code: u64,
  ) -> crate::Result<()>;

  /// The connection is over, whatever the reason: its state is not used anymore.
  fn on_closed(&mut self, state: &mut Self::ConnState);

  /// The connection is about to build its packets: what the application writes now leaves with
  /// them. Called at each flush of an established connection that is not closing, once per turn
  /// unless the arena was full (ruling T13-c). A close that it asks for is applied before the
  /// packets are built.
  #[inline]
  fn on_flush(&mut self, cx: &mut ConnCtx<'_, Self::ConnState>) {
    let _cx = cx;
  }

  /// The endpoint shuts down (ruling T13-d). Returns `true` if the application closes the
  /// established connection itself once it is done with it (with [`ConnCtx::close`], from a later
  /// callback), within [`crate::quic::QuicLimits::shutdown_grace_ms`], after which the endpoint
  /// closes it; `false`, the default, to have it closed at once with
  /// [`crate::quic::QuicLimits::shutdown_app_code`].
  #[inline]
  fn on_shutdown(&mut self, cx: &mut ConnCtx<'_, Self::ConnState>) -> bool {
    let _cx = cx;
    false
  }
}

/// What the application acts through: the streams of the connection and its state.
///
/// Writes go into the send queue of the stream and leave with the next flush of the connection,
/// with the credit (MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS) that is due.
#[derive(Debug)]
pub(crate) struct ConnCtx<'c, S> {
  /// The state of the application for this connection.
  pub state: &'c mut S,
  // Bytes given by the `on_stream_data` that is running, which `retain` can keep
  pub(crate) delivered: usize,
  pub(crate) now_us: u64,
  pub(crate) params: &'c ConnParams,
  pub(crate) pools: &'c mut QuicPools,
  pub(crate) retained: usize,
  pub(crate) streams: &'c mut Streams,
}

impl<'c, S> ConnCtx<'c, S> {
  /// The context of a connection at `now_us`.
  #[inline]
  pub(crate) const fn new(
    state: &'c mut S,
    streams: &'c mut Streams,
    pools: &'c mut QuicPools,
    params: &'c ConnParams,
    now_us: u64,
  ) -> Self {
    Self { state, delivered: 0, now_us, params, pools, retained: 0, streams }
  }

  /// Closes the connection with the application error `app_code` (CONNECTION_CLOSE of type
  /// 0x1d) and `reason`, of which the first 64 bytes are sent, once the callback returns. The
  /// first close counts.
  #[inline]
  pub(crate) fn close(&mut self, app_code: u64, reason: &[u8]) {
    self.streams.request_close(app_code, reason);
  }

  /// The handle of the connection on the endpoint of its worker, which names it from outside of
  /// the callbacks ([`crate::quic::Endpoint::with_conn`]): for a handler that answers later.
  #[inline]
  pub(crate) const fn handle(&self) -> ConnHandle {
    self.params.handle
  }

  /// The time of the call that runs.
  #[inline]
  pub(crate) const fn now_us(&self) -> u64 {
    self.now_us
  }

  /// The address of the peer, as the connection was opened from it.
  #[inline]
  pub(crate) const fn peer(&self) -> IpAddr {
    self.params.peer
  }

  /// Opens a unidirectional stream. Fails with [`QuicError::StreamsBlocked`] if the peer allows
  /// no more for now.
  #[inline]
  pub(crate) fn open_uni(&mut self) -> crate::Result<StreamId> {
    self.streams.open_uni(self.pools, self.params)
  }

  /// Resets the sending part of stream `id` with the application error `code` (RESET_STREAM):
  /// what was not sent is dropped and nothing more is sent. Does nothing if it is finished.
  #[inline]
  pub(crate) fn reset(&mut self, id: StreamId, code: u64) {
    self.streams.reset(self.pools, id, code);
  }

  /// Keeps the last `n` bytes of the data that the running [`QuicApp::on_stream_data`] gave: they
  /// come again, followed by the next bytes, in the next call for the stream. Until then their
  /// credit is not given back to the peer.
  ///
  /// At most 4 KiB can be retained, and only from a call of `on_stream_data`: more is an error
  /// ([`QuicError::RetainTooLong`]) and retains nothing.
  #[inline]
  pub(crate) fn retain(&mut self, n: usize) -> crate::Result<()> {
    if n > self.delivered || n > RX_BLOCK_LEN {
      cold_path();
      return Err(crate::Error::Quic(QuicError::RetainTooLong));
    }
    self.retained = n;
    Ok(())
  }

  /// Asks the peer to stop sending on stream `id` with the application error `code`
  /// (STOP_SENDING). What arrives on it from now on is dropped.
  #[inline]
  pub(crate) fn stop_sending(&mut self, id: StreamId, code: u64) {
    self.streams.stop_sending(self.pools, self.params, id, code);
  }

  /// The bytes written to the streams of the connection that were not sent yet, bodies included.
  #[inline]
  pub(crate) fn unsent_bytes(&self) -> usize {
    usize::try_from(self.streams.unsent()).unwrap_or(usize::MAX)
  }

  /// For a server that shuts down: the first client-initiated bidirectional stream from `from` on
  /// and below `below` whose sending part is not done (what was written to it, its FIN or its
  /// reset, is not all acknowledged), with `true` if it still takes writes: the application never
  /// answered it, as for a stream that a later one opened or whose data did not arrive in order
  /// yet.
  #[inline]
  pub(crate) fn first_unanswered(
    &self,
    from: StreamId,
    below: StreamId,
  ) -> Option<(StreamId, bool)> {
    self.streams.first_unanswered(self.pools, from, below)
  }

  /// The lowest client-initiated bidirectional stream that is not open: those below it were
  /// opened, with data or by a later one (RFC 9000 section 3.2).
  #[inline]
  pub(crate) fn next_peer_bidi(&self) -> StreamId {
    self.streams.next_peer_bidi()
  }

  /// Refuses client stream `id`, which the application never answered: RESET_STREAM and
  /// STOP_SENDING with `code`. A stream that a later one opened takes a slot for it.
  #[inline]
  pub(crate) fn refuse(&mut self, id: StreamId, code: u64) -> crate::Result<()> {
    self.streams.refuse(self.pools, self.params, id, code)
  }

  /// The bytes written to stream `id` that were not sent yet.
  #[inline]
  pub(crate) fn unsent_on(&self, id: StreamId) -> usize {
    usize::try_from(self.streams.unsent_on(self.pools, id)).unwrap_or(usize::MAX)
  }

  /// If stream `id` takes no more writes: its FIN was written, it was reset or it is not open for
  /// sending.
  #[inline]
  pub(crate) fn write_closed(&self, id: StreamId) -> bool {
    self.streams.write_closed(self.pools, id)
  }

  /// Writes `bytes` to stream `id`, copied into its send queue, and with them its end if `fin`.
  /// Fails with [`QuicError::StreamClosed`] if the stream is not open for sending.
  #[inline]
  pub(crate) fn write(&mut self, id: StreamId, bytes: &[u8], fin: bool) -> crate::Result<()> {
    self.streams.write(self.pools, id, Source::Bytes(bytes), fin)
  }

  /// [`Self::write`] of the bytes of `pieces` joined, each copied once, straight into the stream.
  #[inline]
  pub(crate) fn write_gather(
    &mut self,
    id: StreamId,
    pieces: &[&[u8]],
    fin: bool,
  ) -> crate::Result<()> {
    self.streams.write(self.pools, id, Source::Gather(pieces), fin)
  }

  /// [`Self::write`] of `body`, which is not copied: the stream holds it until every frame that
  /// carries it is acknowledged, or the stream is reset.
  #[inline]
  pub(crate) fn write_body(&mut self, id: StreamId, body: BodyRef, fin: bool) -> crate::Result<()> {
    self.streams.write(self.pools, id, Source::Body(body), fin)
  }

  /// Opens a bidirectional stream, as the client of tests does.
  #[cfg(test)]
  pub(crate) fn open_bidi(&mut self) -> crate::Result<StreamId> {
    self.streams.open_bidi(self.pools, self.params)
  }
}

/// A connection of the endpoint of a worker: its slot and the generation of the slot, so that a
/// handle of a connection that is gone names no connection, not the next one of its slot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ConnHandle {
  /// The generation of the slot when the connection was put there.
  pub(crate) generation: u32,
  /// The slot.
  pub(crate) slot: u32,
}

/// Bytes that a stream sends by reference: a range of bytes shared with the rest of the process,
/// such as a cached file ([`SharedBytes`], ruling T14-a), held until the stream does not need them
/// anymore.
#[derive(Clone, Debug)]
pub(crate) struct BodyRef {
  bytes: SharedBytes,
}

impl BodyRef {
  /// The bytes of `range` in `bytes`. Fails with [`QuicError::BodyOutOfBounds`] if they are not
  /// all there.
  #[inline]
  pub(crate) fn new(bytes: SharedBytes, range: Range<u32>) -> crate::Result<Self> {
    let in_bounds = usize::try_from(range.end).is_ok_and(|end| end <= bytes.len());
    if range.start > range.end || !in_bounds {
      cold_path();
      return Err(crate::Error::Quic(QuicError::BodyOutOfBounds));
    }
    let start = usize::try_from(range.start).unwrap_or(usize::MAX);
    let end = usize::try_from(range.end).unwrap_or(usize::MAX);
    Ok(Self { bytes: bytes.slice(start, end) })
  }

  /// The bytes.
  #[inline]
  pub(crate) fn as_slice(&self) -> &[u8] {
    self.bytes.as_slice()
  }

  /// If it has no bytes.
  #[inline]
  pub(crate) fn is_empty(&self) -> bool {
    self.bytes.is_empty()
  }

  /// The number of bytes.
  #[inline]
  pub(crate) fn len(&self) -> u32 {
    u32::try_from(self.bytes.len()).unwrap_or(u32::MAX)
  }
}

impl TryFrom<SharedBytes> for BodyRef {
  type Error = crate::Error;

  /// All of `bytes`. Fails with [`QuicError::BodyOutOfBounds`] past 4 GiB.
  #[inline]
  fn try_from(bytes: SharedBytes) -> crate::Result<Self> {
    if u32::try_from(bytes.len()).is_err() {
      cold_path();
      return Err(crate::Error::Quic(QuicError::BodyOutOfBounds));
    }
    Ok(Self { bytes })
  }
}

#[cfg(test)]
mod tests {
  use crate::{
    misc::SharedBytes,
    quic::{
      BodyRef, ConnState, Frame, QuicError, TransportErrorCode,
      testing::{Behavior, Fail, Link, LinkOpts, TestApp, encode_frames},
    },
    sync::Arc,
  };
  use alloc::{vec, vec::Vec};

  fn settled(opts: &LinkOpts) -> Link {
    let mut link = Link::new(opts);
    link.run();
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
    link
  }

  fn request(link: &mut Link, bytes: &[u8], fin: bool) -> crate::quic::StreamId {
    let now_us = link.now_us;
    link
      .client
      .with_ctx(now_us, |cx| {
        let id = cx.open_bidi()?;
        cx.write(id, bytes, fin)?;
        Ok::<_, crate::Error>(id)
      })
      .unwrap()
  }

  #[test]
  fn body_ref_range_is_checked() {
    let bytes: Arc<[u8]> = Arc::from(vec![1, 2, 3, 4, 5, 6, 7, 8].into_boxed_slice());
    let shared = || SharedBytes::new(bytes.clone());
    let body = BodyRef::new(shared(), 2..5).unwrap();
    assert_eq!(body.as_slice(), [3, 4, 5]);
    assert_eq!(body.len(), 3);
    assert!(BodyRef::new(shared(), 0..0).unwrap().is_empty());
    // Past the end, and a start after the end
    for range in [4..9, core::ops::Range { start: 6, end: 5 }] {
      assert!(matches!(
        BodyRef::new(shared(), range),
        Err(crate::Error::Quic(QuicError::BodyOutOfBounds))
      ));
    }
    // All of a shared range, which keeps its own range
    let whole = BodyRef::try_from(shared().slice(1, 4)).unwrap();
    assert_eq!(whole.as_slice(), [2, 3, 4]);
    assert_eq!(BodyRef::new(shared().slice(1, 4), 1..3).unwrap().as_slice(), [3, 4]);
    drop((body, whole));
    assert_eq!(Arc::strong_count(&bytes), 1);
  }

  // Ruling T8-d: an error of a callback closes the connection with a transport CONNECTION_CLOSE,
  // of its code if it is a QUIC close and INTERNAL_ERROR otherwise.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn callback_error_closes_with_its_transport_code() {
    for (fail, code) in [
      (Fail::Transport(TransportErrorCode::FlowControlError), 0x03),
      (Fail::Other, TransportErrorCode::InternalError.code()),
    ] {
      let mut opts = LinkOpts::new(None);
      opts.server_app.fail = Some(fail);
      let mut link = settled(&opts);
      let _ = request(&mut link, b"GET /", true);
      let _ = link.client.flush(link.now_us);
      assert_eq!(link.deliver_to_server(), 1);
      assert_eq!(link.server.conn.close_code(), Some((false, code)), "{fail:?}");
      let _ = link.server.flush(link.now_us);
      assert_eq!(link.deliver_to_client(), 1);
      assert_eq!(link.client.conn.state(), ConnState::Draining);
    }
  }

  // A callback that fails while it was given bytes from a block, data that waited or retained
  // bytes, gives the block back to the pool all the same.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn blocks_go_back_when_a_callback_fails() {
    for retains in [false, true] {
      let mut opts = LinkOpts::new(None);
      opts.server_app = TestApp::new(if retains { Behavior::Lines } else { Behavior::Collect });
      opts.server_app.fail = Some(Fail::Other);
      // Retained: 300 bytes kept in a block, which the next call fails with. Waiting: [0, 10) and
      // [10, 20) succeed, [20, 30) from its block fails.
      opts.server_app.fail_after = if retains { 1 } else { 2 };
      let mut link = settled(&opts);
      let blocks = link.server.parts.pools.rx_blocks.len();
      let id = request(&mut link, b"", false);
      let long = [b'x'; 300];
      let frames: Vec<(u64, &[u8])> = if retains {
        vec![(0, &long), (300, b"y")]
      } else {
        vec![(0, &long[..10]), (20, &long[..10]), (10, &long[..10])]
      };
      for (offset, data) in frames {
        let frame = Frame::Stream { id: id.0, offset, data, fin: false };
        link.client.conn.queue_test_frames(&encode_frames(&[frame]));
        let _ = link.client.flush(link.now_us);
        assert_eq!(link.deliver_to_server(), 1);
      }
      assert_eq!(link.server.conn.close_code(), Some((false, 0x01)), "{retains}");
      link.server.abort();
      assert_eq!(link.server.parts.pools.rx_blocks.len(), blocks + 1, "{retains}");
    }
  }

  // An application that closes with its own code does so through the context: the connection
  // sends an application CONNECTION_CLOSE.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn app_close_sends_an_application_close() {
    let mut opts = LinkOpts::new(None);
    opts.server_app.fail = Some(Fail::AppClose(0x101));
    let mut link = settled(&opts);
    let _ = request(&mut link, b"GET /", true);
    let _ = link.client.flush(link.now_us);
    assert_eq!(link.deliver_to_server(), 1);
    assert_eq!(link.server.conn.close_code(), Some((true, 0x101)));
    assert_eq!(link.server.conn.streams().close_reason(), b"bye");
    let _ = link.server.flush(link.now_us);
    assert_eq!(link.deliver_to_client(), 1);
    assert_eq!(link.client.conn.state(), ConnState::Draining);
  }

  // Ruling T8-a: bytes that the application retains come again at the start of the next call,
  // followed by what arrived since, whether they fit in the slot or take a block.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn retained_bytes_are_delivered_again_with_the_next() {
    let mut opts = LinkOpts::new(None);
    opts.server_app = TestApp::new(Behavior::Lines);
    let mut link = settled(&opts);
    let long = vec![b'x'; 1000];
    let pieces: [(&[u8], bool); 5] =
      [(b"ab\ncd", false), (b"e\nf", false), (&long, false), (b"g\n", false), (b"h", true)];
    let id = request(&mut link, b"", false);
    for (piece, fin) in pieces {
      let now_us = link.now_us;
      link.client.with_ctx(now_us, |cx| cx.write(id, piece, fin)).unwrap();
      link.run();
    }
    let mut long_line = vec![b'f'];
    long_line.extend_from_slice(&long);
    long_line.push(b'g');
    let expected: Vec<Vec<u8>> = vec![b"ab".to_vec(), b"cde".to_vec(), long_line, b"h".to_vec()];
    assert_eq!(link.server.app.lines, expected);
    assert_eq!(link.server.conn.streams().held_blocks(), 0);
    assert_eq!(link.server.conn.state(), ConnState::Confirmed);
  }
}
