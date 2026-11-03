use crate::{
  collections::VectorUsize,
  misc::LeaseMut,
  net::{BufStreamReader, ConnectionState, Stream},
  rng::Xorshift64,
  tls::{TlsCtx, TlsStream},
  web_socket::{
    Frame, FrameMut, WebSocketError, WebSocketPayloadOrigin,
    is_in_continuation_frame::IsInContinuationFrame,
    read_frame::{BufferedFrame, buffered_data_frame, read_frame, take_buffered_data_frame},
    web_socket_compression::NegotiatedWsCompression,
    write_frame::{
      QueuedStream, flush_write_queue, try_queue_frame, write_frame, write_frame_buffered,
    },
  },
};
use core::marker::PhantomData;

/// Auxiliary common structure used by [`WebSocketReaderMut`] and [`WebSocketWriterMut`]
#[derive(Debug)]
pub struct WebSocketCommonMut<'instance, NC, S, TCX, const IS_CLIENT: bool> {
  pub(crate) nc: &'instance mut NC,
  pub(crate) nc_rsv1: u8,
  pub(crate) rng: &'instance mut Xorshift64,
  pub(crate) stream: &'instance mut TlsStream<S, TCX, IS_CLIENT>,
  pub(crate) write_queue: &'instance mut VectorUsize<u8>,
}

/// Auxiliary structure that can be used when it is necessary to write a received frame that belongs
/// to the same instance.
#[derive(Debug)]
pub struct WebSocketReaderMut<'instance, NC, S, TCX, const IS_CLIENT: bool> {
  pub(crate) is_in_continuation_frame: &'instance mut Option<IsInContinuationFrame>,
  pub(crate) max_payload_len: usize,
  pub(crate) network_buffer: &'instance mut BufStreamReader,
  pub(crate) no_masking: bool,
  pub(crate) phantom: PhantomData<(NC, S, TCX)>,
  pub(crate) reader_buffer: &'instance mut VectorUsize<u8>,
}

impl<'instance, NC, S, TCX, const IS_CLIENT: bool>
  WebSocketReaderMut<'instance, NC, S, TCX, IS_CLIENT>
where
  NC: NegotiatedWsCompression,
  S: Stream,
  TCX: TlsCtx,
{
  /// Returns the next frame without touching the stream, if it is a final, uncompressed text or
  /// binary frame whose bytes have already been read. `None` otherwise, with nothing consumed:
  /// [`Self::read_frame`] then handles whatever comes next (control frames, fragments, compressed
  /// frames, or bytes that are still to arrive).
  ///
  /// Draining frames that arrived together with this method avoids an `await` per frame:
  ///
  /// ```ignore,rust
  /// while let Some(mut frame) = reader.read_buffered_frame(&mut buffer, &common, origin)? {
  ///   writer.write_frame_buffered(&mut common, &mut frame).await?;
  /// }
  /// let mut frame = reader.read_frame(&mut buffer, &mut common, origin).await?;
  /// ```
  #[inline]
  pub fn read_buffered_frame<'buffer, 'frame, 'this>(
    &'this mut self,
    buffer: &'buffer mut VectorUsize<u8>,
    common: &WebSocketCommonMut<'instance, NC, S, TCX, IS_CLIENT>,
    payload_origin: WebSocketPayloadOrigin,
  ) -> crate::Result<Option<FrameMut<'frame>>>
  where
    'buffer: 'frame,
    'this: 'frame,
  {
    if self.is_in_continuation_frame.is_some() {
      return Ok(None);
    }
    let BufferedFrame::Data(rslt) = buffered_data_frame::<NC, IS_CLIENT>(
      self.max_payload_len,
      common.nc_rsv1,
      self.network_buffer.following(),
      self.no_masking,
    ) else {
      return Ok(None);
    };
    let (rfi, header_len) = rslt?;
    buffer.clear();
    take_buffered_data_frame::<IS_CLIENT>(
      header_len,
      self.network_buffer,
      common.nc_rsv1,
      self.no_masking,
      payload_origin,
      &rfi,
      buffer,
    )
    .map(Some)
  }

  /// Reads a frame from the stream.
  ///
  /// If a frame is made up of other sub-frames or continuations, then everything is collected
  /// until all fragments are received.
  #[inline]
  pub async fn read_frame<'buffer, 'frame, 'this>(
    &'this mut self,
    buffer: &'buffer mut VectorUsize<u8>,
    common: &mut WebSocketCommonMut<'instance, NC, S, TCX, IS_CLIENT>,
    payload_origin: WebSocketPayloadOrigin,
  ) -> crate::Result<FrameMut<'frame>>
  where
    'buffer: 'frame,
    'this: 'frame,
  {
    if self.is_in_continuation_frame.is_none() {
      buffer.clear();
      loop {
        match buffered_data_frame::<NC, IS_CLIENT>(
          self.max_payload_len,
          common.nc_rsv1,
          self.network_buffer.following(),
          self.no_masking,
        ) {
          BufferedFrame::Data(rslt) => {
            let (rfi, header_len) = rslt?;
            return take_buffered_data_frame::<IS_CLIENT>(
              header_len,
              self.network_buffer,
              common.nc_rsv1,
              self.no_masking,
              payload_origin,
              &rfi,
              buffer,
            );
          }
          BufferedFrame::Incomplete(frame_len) => {
            let stream = &mut QueuedStream {
              stream: &mut *common.stream,
              write_queue: &mut *common.write_queue,
            };
            if !self.network_buffer.read_following(frame_len, stream).await? {
              return Err(WebSocketError::ClosedConnection.into());
            }
          }
          BufferedFrame::Other => break,
        }
      }
    }
    read_frame::<_, _, _, _, _, true, IS_CLIENT>(
      self.is_in_continuation_frame,
      self.max_payload_len,
      common.nc,
      common.nc_rsv1,
      self.network_buffer.lease_mut(),
      self.no_masking,
      payload_origin,
      self.reader_buffer.lease_mut(),
      common.rng,
      &mut QueuedStream { stream: common.stream, write_queue: common.write_queue },
      None,
      buffer,
      |el| el.stream.connection_state = ConnectionState::ClosedGracefully,
      |local_stream| local_stream,
      |local_stream| local_stream,
    )
    .await
  }
}

/// Auxiliary structure that can be used when it is necessary to write a received frame that belongs
/// to the same instance.
#[derive(Debug)]
pub struct WebSocketWriterMut<'instance, NC, S, TCX, const IS_CLIENT: bool> {
  pub(crate) no_masking: bool,
  pub(crate) phantom: PhantomData<(NC, S, TCX)>,
  pub(crate) writer_buffer: &'instance mut VectorUsize<u8>,
}

impl<'instance, NC, S, TCX, const IS_CLIENT: bool>
  WebSocketWriterMut<'instance, NC, S, TCX, IS_CLIENT>
where
  NC: NegotiatedWsCompression,
  S: Stream,
  TCX: TlsCtx,
{
  /// Sends the frames queued by [`Self::write_frame_buffered`], if any.
  #[inline]
  pub async fn flush(
    &mut self,
    common: &mut WebSocketCommonMut<'instance, NC, S, TCX, IS_CLIENT>,
  ) -> crate::Result<()> {
    flush_write_queue(common.stream, common.write_queue).await
  }

  /// Writes a frame to the stream, after any frames queued by [`Self::write_frame_buffered`].
  #[inline]
  pub async fn write_frame<P>(
    &mut self,
    common: &mut WebSocketCommonMut<'instance, NC, S, TCX, IS_CLIENT>,
    frame: &mut Frame<P>,
  ) -> crate::Result<()>
  where
    P: LeaseMut<[u8]>,
  {
    write_frame::<_, _, _, _, IS_CLIENT>(
      frame,
      self.no_masking,
      common.nc,
      common.nc_rsv1,
      common.rng,
      &mut QueuedStream { stream: common.stream, write_queue: common.write_queue },
      self.writer_buffer,
      |el| el.stream.connection_state = ConnectionState::WriteClosed,
    )
    .await
  }

  /// [`Self::write_frame_buffered`] for a frame that can be queued without any I/O: a small,
  /// uncompressed frame other than a close frame, while the queue has room. Returns `false`, with
  /// the frame untouched, when it cannot, and [`Self::write_frame_buffered`] should be awaited.
  #[inline]
  pub fn try_write_frame_buffered<P>(
    &mut self,
    common: &mut WebSocketCommonMut<'instance, NC, S, TCX, IS_CLIENT>,
    frame: &mut Frame<P>,
  ) -> crate::Result<bool>
  where
    P: LeaseMut<[u8]>,
  {
    try_queue_frame::<NC, _, _, IS_CLIENT>(
      frame,
      self.no_masking,
      common.nc_rsv1,
      common.rng,
      common.write_queue,
    )
  }

  /// Queues a frame instead of writing it, so that several frames can go out in one syscall.
  ///
  /// Queued frames are sent before [`WebSocketReaderMut::read_frame`] would wait for the peer,
  /// by [`Self::write_frame`] and [`Self::flush`], or once the queue holds 16 KiB. A close frame
  /// is sent at once, with everything queued in front of it. Large payloads are not copied.
  ///
  /// Call [`Self::flush`] when no further read follows.
  #[inline]
  pub async fn write_frame_buffered<P>(
    &mut self,
    common: &mut WebSocketCommonMut<'instance, NC, S, TCX, IS_CLIENT>,
    frame: &mut Frame<P>,
  ) -> crate::Result<()>
  where
    P: LeaseMut<[u8]>,
  {
    if try_queue_frame::<NC, _, _, IS_CLIENT>(
      frame,
      self.no_masking,
      common.nc_rsv1,
      common.rng,
      common.write_queue,
    )? {
      return Ok(());
    }
    write_frame_buffered::<_, _, _, _, IS_CLIENT>(
      frame,
      self.no_masking,
      common.nc,
      common.nc_rsv1,
      common.rng,
      common.stream,
      self.writer_buffer,
      common.write_queue,
      |el| el.connection_state = ConnectionState::WriteClosed,
    )
    .await
  }
}
