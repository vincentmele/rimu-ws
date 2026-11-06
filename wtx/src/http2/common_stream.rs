use crate::{
  collections::{ArrayVectorU16, VectorUsize},
  futures::TryJoinArrayVector,
  http::{Headers, U31},
  http2::{
    Http2Error, Http2RecvStatus, Http2SendStatus,
    client_conn::{ClientShared, ClientState},
    conn::body::Body,
    misc::protocol_err,
  },
  net::StreamWriter,
  tls::TlsCtx,
};
use core::{future::poll_fn, mem, task::Poll};

/// Bytes of a body handed to the connection at a time: the next part waits until the windows
/// let this one go.
const SEND_CHUNK_LEN: usize = 64 * 1024;

/// Groups common client operations as well as low level methods that deal with individual
/// frames.
#[derive(Debug)]
pub struct CommonStream<'instance, SW, TCX, const IS_CLIENT: bool> {
  pub(crate) shared: &'instance ClientShared<SW, TCX>,
  pub(crate) stream_id: U31,
}

impl<'instance, SW, TCX, const IS_CLIENT: bool> CommonStream<'instance, SW, TCX, IS_CLIENT> {
  pub(crate) const fn new(shared: &'instance ClientShared<SW, TCX>, stream_id: U31) -> Self {
    Self { shared, stream_id }
  }

  /// `None` if `stream_id` can still send, otherwise why not.
  pub(crate) fn send_status(state: &ClientState, stream_id: U31) -> Option<Http2SendStatus> {
    if state.is_ended() {
      return Some(Http2SendStatus::ClosedConnection);
    }
    match state.streams.get(&stream_id.u32()) {
      Some(slot) if slot.reset.is_none() => None,
      _ => Some(Http2SendStatus::ClosedStream),
    }
  }
}

impl<SW, TCX, const IS_CLIENT: bool> CommonStream<'_, SW, TCX, IS_CLIENT>
where
  SW: StreamWriter,
  TCX: TlsCtx,
{
  /// Frees the stream: one that has not ended is reset with `CANCEL`. Dropping the
  /// [`crate::http2::ClientStream`] does the same.
  #[inline]
  pub async fn clear(&self) -> crate::Result<()> {
    {
      let mut state = self.shared.state.lock();
      if !state.streams.contains_key(&self.stream_id.u32()) {
        return Ok(());
      }
      state.finish(self.stream_id);
    }
    self.shared.flush().await
  }

  /// Receive Data.
  ///
  /// `cb` receives the body bytes buffered so far, each time more arrive, until the stream ends;
  /// the bytes that arrived with or after the last call are returned in [`Http2RecvStatus::Eos`].
  ///
  /// Shouldn't interact with higher operations that receive data.
  #[inline]
  pub async fn recv_data<ONG>(
    &mut self,
    mut cb: impl FnMut(&mut [u8]) -> crate::Result<ONG>,
  ) -> crate::Result<Http2RecvStatus<VectorUsize<u8>, ONG>> {
    let id = self.stream_id;
    poll_fn(|cx| {
      let mut guard = self.shared.state.lock();
      let state = &mut *guard;
      let ended = state.is_ended();
      let Some(slot) = state.streams.get_mut(&id.u32()) else {
        return Poll::Ready(Ok(Http2RecvStatus::ClosedStream(VectorUsize::new())));
      };
      if slot.reset.is_some() {
        return Poll::Ready(Ok(Http2RecvStatus::ClosedStream(VectorUsize::new())));
      }
      let recv_closed = state.conn.recv_closed(id) == Some(true);
      if let Some(msg) = state.conn.msg_mut(id) {
        if recv_closed {
          slot.released = 0;
          return Poll::Ready(Ok(Http2RecvStatus::Eos(mem::take(&mut msg.body))));
        }
        if !msg.body.is_empty() {
          let ongoing = cb(msg.body.as_slice_mut())?;
          msg.body.clear();
          slot.released = 0;
          return Poll::Ready(Ok(Http2RecvStatus::Ongoing(ongoing)));
        }
      }
      if ended {
        return Poll::Ready(Ok(Http2RecvStatus::ClosedConnection));
      }
      slot.wait(cx.waker())?;
      Poll::Pending
    })
    .await
  }

  /// Receive Trailers
  ///
  /// Waits for the end of the stream and returns the received headers, trailers included.
  /// Shouldn't interact with higher operations that receive data.
  #[inline]
  pub async fn recv_trailers(&mut self) -> crate::Result<Http2RecvStatus<Headers, ()>> {
    let id = self.stream_id;
    poll_fn(|cx| {
      let mut guard = self.shared.state.lock();
      let state = &mut *guard;
      let ended = state.is_ended();
      let Some(slot) = state.streams.get_mut(&id.u32()) else {
        return Poll::Ready(Ok(Http2RecvStatus::ClosedStream(Headers::new())));
      };
      if slot.reset.is_some() {
        return Poll::Ready(Ok(Http2RecvStatus::ClosedStream(Headers::new())));
      }
      if state.conn.recv_closed(id) == Some(true) {
        let headers = state.conn.msg_mut(id).map(|el| mem::take(&mut el.headers));
        return Poll::Ready(Ok(Http2RecvStatus::Eos(headers.unwrap_or_default())));
      }
      if ended {
        return Poll::Ready(Ok(Http2RecvStatus::ClosedConnection));
      }
      slot.wait(cx.waker())?;
      Poll::Pending
    })
    .await
  }

  /// The connection hands the window back as body bytes are buffered (up to
  /// `HttpRecvParams::max_body_len`), so there is nothing left to release. Kept for source
  /// compatibility.
  #[inline]
  pub async fn release_capacity(&mut self, value: u32) -> crate::Result<()> {
    let _ = value;
    Ok(())
  }

  /// Low level operation that sends the content of `data` as one or more DATA frames. If `eos` is
  /// true, then the last frame is set with the end-of-stream flag. Shouldn't interact with
  /// higher operations that send data.
  ///
  /// Waits until the windows let the whole of `data` go to the connection.
  #[inline]
  pub async fn send_data(&self, data: &[u8], is_eos: bool) -> crate::Result<Http2SendStatus> {
    let id = self.stream_id;
    let mut idx: usize = 0;
    loop {
      let status = poll_fn(|cx| {
        let mut guard = self.shared.state.lock();
        let state = &mut *guard;
        if let Some(status) = Self::send_status(state, id) {
          return Poll::Ready(crate::Result::Ok(Some(status)));
        }
        if state.conn.stream_send_pending(id) == 0 {
          return Poll::Ready(Ok(None));
        }
        if let Some(slot) = state.streams.get_mut(&id.u32()) {
          slot.wait(cx.waker())?;
        }
        Poll::Pending
      })
      .await?;
      if let Some(elem) = status {
        return Ok(elem);
      }
      let end = idx.saturating_add(SEND_CHUNK_LEN).min(data.len());
      let is_last = end == data.len();
      if idx == end && !(is_last && is_eos) {
        return Ok(Http2SendStatus::Ok);
      }
      let chunk = data.get(idx..end).unwrap_or_default();
      {
        let mut state = self.shared.state.lock();
        if let Some(status) = Self::send_status(&state, id) {
          return Ok(status);
        }
        state.conn.send_data(id, Body::Borrowed(chunk), is_eos && is_last)?;
      }
      self.shared.flush().await?;
      idx = end;
      if is_last {
        return Ok(Http2SendStatus::Ok);
      }
    }
  }

  /// Calls [`Self::send_data`] concurrently on each data element terminating the stream in the
  /// final iteration.
  ///
  /// Returns [`None`] if `data` is empty. This method will abort early if any sending result is
  /// not [`Http2SendStatus::Ok`].
  ///
  /// `N` is the number of concurrent requests performed in batches until `data` in depleted.
  #[inline]
  pub async fn send_data_concurrent<'bytes, I, const N: usize>(
    &self,
    data: I,
  ) -> crate::Result<Option<Http2SendStatus>>
  where
    I: IntoIterator<Item = &'bytes [u8]>,
    I::IntoIter: ExactSizeIterator,
  {
    const {
      assert!(N > 0);
    }
    let mut iter = data.into_iter();
    let mut remaining = iter.len();
    let mut status = None;
    while remaining > 0 {
      let mut futures = ArrayVectorU16::<_, N>::new();
      let batch_size = remaining.min(N);
      for _ in 0..batch_size {
        let Some(elem) = iter.next() else {
          continue;
        };
        remaining = remaining.wrapping_sub(1);
        futures.push(self.send_data(elem, remaining == 0))?;
      }
      status = TryJoinArrayVector::new(futures, |hss| {
        if !matches!(hss, Http2SendStatus::Ok) {
          return Err(protocol_err(Http2Error::ClosedConnectionWhenSendingConcurrentData));
        }
        Ok(hss)
      })
      .await?
      .last()
      .copied();
    }
    Ok(status)
  }

  /// Calls [`Self::send_data`] sequentially on each data element terminating the stream in the
  /// final iteration.
  ///
  /// Returns [`None`] if `data` is empty. This method will abort early if any sending result is
  /// not [`Http2SendStatus::Ok`].
  #[inline]
  pub async fn send_data_sequential<'bytes, I>(
    &self,
    data: I,
  ) -> crate::Result<Option<Http2SendStatus>>
  where
    I: IntoIterator<Item = &'bytes [u8]>,
    I::IntoIter: ExactSizeIterator,
  {
    let mut iter = data.into_iter();
    let take = iter.len().saturating_sub(1);
    for elem in iter.by_ref().take(take) {
      let hss = self.send_data(elem, false).await?;
      if !matches!(hss, Http2SendStatus::Ok) {
        return Ok(Some(hss));
      }
    }
    if let Some(elem) = iter.next() {
      return Ok(Some(self.send_data(elem, true).await?));
    }
    Ok(None)
  }

  send_go_away_method!();

  /// Sends a reset frame to the peer, which cancels this stream.
  #[inline]
  pub async fn send_reset(&self, error_code: crate::http2::Http2ErrorCode) {
    {
      let mut guard = self.shared.state.lock();
      let state = &mut *guard;
      let Some(slot) = state.streams.get_mut(&self.stream_id.u32()) else {
        return;
      };
      if slot.reset.is_some() {
        return;
      }
      slot.reset = Some(error_code);
      state.conn.send_reset(self.stream_id, error_code);
    }
    let _rslt = self.shared.flush().await;
  }

  /// Low level operation that sends headers after the DATA frames sent so far and then closes
  /// the stream. Shouldn't interact with higher operations that send data. `enc_buffer` is no
  /// longer used.
  #[inline]
  pub async fn send_trailers(
    &mut self,
    enc_buffer: &mut VectorUsize<u8>,
    trailers: &Headers,
  ) -> crate::Result<Http2SendStatus> {
    let _ = enc_buffer;
    {
      let mut state = self.shared.state.lock();
      if let Some(status) = Self::send_status(&state, self.stream_id) {
        return Ok(status);
      }
      state.conn.send_trailers(self.stream_id, trailers)?;
    }
    self.shared.flush().await?;
    Ok(Http2SendStatus::Ok)
  }

  /// Stream ID
  #[inline]
  pub const fn stream_id(&self) -> u32 {
    self.stream_id.u32()
  }
}
