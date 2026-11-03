use crate::{
  collections::VectorUsize,
  misc::LeaseMut,
  net::{BufStreamReader, ConnectionState, Stream, StreamWriter},
  rng::Xorshift64,
  tls::{TlsCtx, TlsStream},
  web_socket::{
    Frame, FrameMut, WebSocketError, WebSocketPayloadOrigin,
    is_in_continuation_frame::IsInContinuationFrame,
    read_frame::{
      BufferedFrame, buffered_data_frame, check_buffered_data_frame, read_frame,
      take_buffered_data_frame, take_checked_data_frame,
    },
    web_socket_compression::NegotiatedWsCompression,
    write_frame::{
      QueuedStream, WRITE_QUEUE_FLUSH_LEN, flush_write_queue, try_queue_frame, write_frame,
      write_frame_buffered,
    },
  },
};
use core::{hint::cold_path, marker::PhantomData};

/// Auxiliary common structure used by [`WebSocketReaderMut`] and [`WebSocketWriterMut`]
#[derive(Debug)]
pub struct WebSocketCommonMut<'instance, NC, S, TCX, const IS_CLIENT: bool> {
  pub(crate) nc: &'instance mut NC,
  pub(crate) nc_rsv1: u8,
  pub(crate) rng: &'instance mut Xorshift64,
  pub(crate) stream: &'instance mut TlsStream<S, TCX, IS_CLIENT>,
  pub(crate) write_queue: &'instance mut VectorUsize<u8>,
}

/// What [`WebSocketReaderMut::fill`] did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fill {
  /// More bytes were read: [`WebSocketReaderMut::read_buffered_frame`] may now return frames.
  Buffered,
  /// The peer closed the connection.
  Closed,
  /// The next frame needs [`WebSocketReaderMut::read_frame`]: a control, fragmented or compressed
  /// frame, or a frame that is invalid and whose error that method reports.
  ReadFrame,
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
  /// Waits for more of the next frame without parsing it, sending the queued frames first, so that
  /// a loop can parse with [`Self::read_buffered_frame`] instead of awaiting [`Self::read_frame`]
  /// for each frame:
  ///
  /// ```ignore,rust
  /// loop {
  ///   while let Some(mut frame) = reader.read_buffered_frame(&mut buffer, &common, origin)? {
  ///     writer.queue_frame(&mut common, &mut frame)?;
  ///   }
  ///   match reader.fill(&mut common).await? {
  ///     Fill::Buffered => {}
  ///     Fill::Closed => break,
  ///     Fill::ReadFrame => { let frame = reader.read_frame(&mut buffer, &mut common, origin).await?; }
  ///   }
  /// }
  /// ```
  ///
  /// Call it once [`Self::read_buffered_frame`] returns `None`: a complete frame still buffered is
  /// then one that method declined, so this returns [`Fill::ReadFrame`] for it without reading.
  #[inline]
  pub async fn fill(
    &mut self,
    common: &mut WebSocketCommonMut<'instance, NC, S, TCX, IS_CLIENT>,
  ) -> crate::Result<Fill> {
    if self.is_in_continuation_frame.is_some() {
      return Ok(Fill::ReadFrame);
    }
    let frame_len = match buffered_data_frame::<NC, IS_CLIENT>(
      self.max_payload_len,
      common.nc_rsv1,
      self.network_buffer.following(),
      self.no_masking,
    ) {
      BufferedFrame::Incomplete(elem) => elem,
      BufferedFrame::Data(_) | BufferedFrame::Other => return Ok(Fill::ReadFrame),
    };
    // With nothing queued (`WebSocketWriterMut::try_flush` sent it), read the stream directly.
    let rslt = if common.write_queue.is_empty() {
      self.network_buffer.read_following(frame_len, &mut *common.stream).await
    } else {
      let stream =
        &mut QueuedStream { stream: &mut *common.stream, write_queue: &mut *common.write_queue };
      self.network_buffer.read_following(frame_len, stream).await
    };
    match rslt {
      Ok(true) => Ok(Fill::Buffered),
      Ok(false) => Ok(Fill::Closed),
      Err(err) => {
        cold_path();
        // Like `read_frame`: what was queued before the error still goes out.
        let _rslt = flush_write_queue(common.stream, common.write_queue).await;
        Err(err)
      }
    }
  }

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
    let BufferedFrame::Data(Ok((rfi, header_len))) = buffered_data_frame::<NC, IS_CLIENT>(
      self.max_payload_len,
      common.nc_rsv1,
      self.network_buffer.following(),
      self.no_masking,
    ) else {
      return Ok(None);
    };
    // A frame that breaks the protocol stays in the buffer for `read_frame`, which reports the
    // error after sending the frames queued in front of it.
    if !check_buffered_data_frame::<IS_CLIENT>(
      header_len,
      self.network_buffer,
      self.no_masking,
      &rfi,
    ) {
      return Ok(None);
    }
    buffer.clear();
    take_checked_data_frame(
      header_len,
      self.network_buffer,
      common.nc_rsv1,
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
    let rslt: crate::Result<FrameMut<'frame>> = 'read: {
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
              let (rfi, header_len) = match rslt {
                Ok(elem) => elem,
                Err(err) => break 'read Err(err),
              };
              break 'read take_buffered_data_frame::<IS_CLIENT>(
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
              match self.network_buffer.read_following(frame_len, stream).await {
                Ok(true) => {}
                Ok(false) => break 'read Err(WebSocketError::ClosedConnection.into()),
                Err(err) => break 'read Err(err),
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
        &mut QueuedStream { stream: &mut *common.stream, write_queue: &mut *common.write_queue },
        None,
        buffer,
        |el| el.stream.connection_state = ConnectionState::ClosedGracefully,
        |local_stream| local_stream,
        |local_stream| local_stream,
      )
      .await
    };
    if rslt.is_err() {
      // Frames queued before the error still go out, in front of whatever the caller sends next.
      cold_path();
      let _rslt = flush_write_queue(common.stream, common.write_queue).await;
    }
    rslt
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

  /// [`Self::flush`] without awaiting, for a stream that can take the queued frames at once.
  /// Returns `false`, sending nothing, when they would have to wait; they then go out before the
  /// next read waits, or with [`Self::flush`].
  ///
  /// After a synchronous loop over the buffered frames, this hands what it queued to the stream
  /// without going through an awaited write.
  #[inline]
  pub fn try_flush(
    &mut self,
    common: &mut WebSocketCommonMut<'instance, NC, S, TCX, IS_CLIENT>,
  ) -> crate::Result<bool> {
    if common.write_queue.is_empty() {
      return Ok(true);
    }
    if common.stream.try_write_all_vectored(&[common.write_queue.as_slice()])? {
      common.write_queue.clear();
      return Ok(true);
    }
    Ok(false)
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
      WRITE_QUEUE_FLUSH_LEN,
      self.no_masking,
      common.nc_rsv1,
      common.rng,
      common.write_queue,
    )
  }

  /// [`Self::try_write_frame_buffered`] without the queue limit: queues an uncompressed frame other
  /// than a close frame by copying it, without any I/O, however much is already queued. Returns
  /// `false`, with the frame untouched, only for a close frame or when the frame would have to be
  /// compressed.
  ///
  /// Meant for echoing frames returned by [`WebSocketReaderMut::read_buffered_frame`], which are
  /// never close or compressed frames: on a connection without compression this never returns
  /// `false` for them, so a loop over the buffered frames can run without awaiting. What it queues
  /// is bounded by what was buffered, and it is sent before the next read would wait.
  #[inline]
  pub fn queue_frame<P>(
    &mut self,
    common: &mut WebSocketCommonMut<'instance, NC, S, TCX, IS_CLIENT>,
    frame: &mut Frame<P>,
  ) -> crate::Result<bool>
  where
    P: LeaseMut<[u8]>,
  {
    try_queue_frame::<NC, _, _, IS_CLIENT>(
      frame,
      usize::MAX,
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
      WRITE_QUEUE_FLUSH_LEN,
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
