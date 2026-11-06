use crate::{
  collections::VectorUsize,
  http::{MsgBufferString, MsgData, Request, StatusCode, U31},
  http2::{CommonStream, Http2RecvStatus, Http2SendStatus, client_conn::ClientShared},
  misc::Lease,
  net::StreamWriter,
  sync::Arc,
  tls::TlsCtx,
};
use core::{future::poll_fn, mem, task::Poll};

/// Groups the methods used by clients that connect to servers.
///
/// Dropping it frees the stream; one that has not ended is reset with `CANCEL`.
#[derive(Debug)]
pub struct ClientStream<SW, TCX> {
  /// The handle holds room under the server's limit and has no stream id yet.
  reserved: bool,
  pub(crate) shared: Arc<ClientShared<SW, TCX>>,
  pub(crate) stream_id: U31,
}

impl<SW, TCX> ClientStream<SW, TCX> {
  /// A handle that gets its stream id when it sends its request.
  pub(crate) const fn new(shared: Arc<ClientShared<SW, TCX>>) -> Self {
    Self { reserved: true, shared, stream_id: U31::ZERO }
  }

  /// See [`CommonStream`].
  #[inline]
  pub fn common(&mut self) -> CommonStream<'_, SW, TCX, true> {
    CommonStream::new(&self.shared, self.stream_id)
  }
}

impl<SW, TCX> ClientStream<SW, TCX>
where
  SW: StreamWriter,
  TCX: TlsCtx,
{
  /// Receive response
  ///
  /// High-level operation that awaits for the data necessary to build a response and then closes the
  /// stream.
  ///
  /// Returns [`Http2RecvStatus::ClosedStream`] if the server reset the stream and
  /// [`Http2RecvStatus::ClosedConnection`] if the connection closed first.
  ///
  /// Should be called after [`Self::send_req`] or any other low level methods that send data
  /// are successfully executed.
  #[inline]
  pub async fn recv_res(
    &mut self,
  ) -> crate::Result<(Http2RecvStatus<StatusCode, ()>, MsgBufferString)> {
    let Self { shared, stream_id, .. } = self;
    let id = *stream_id;
    poll_fn(|cx| {
      let mut guard = shared.state.lock();
      let state = &mut *guard;
      let Some(slot) = state.streams.get(&id.u32()) else {
        return Poll::Ready(Ok((
          Http2RecvStatus::ClosedStream(StatusCode::InternalServerError),
          MsgBufferString::default(),
        )));
      };
      if slot.reset.is_some() {
        let status = slot.status.unwrap_or(StatusCode::InternalServerError);
        return Poll::Ready(Ok((
          Http2RecvStatus::ClosedStream(status),
          MsgBufferString::default(),
        )));
      }
      if state.conn.recv_closed(id) == Some(true) {
        let status = state.conn.status(id).unwrap_or(StatusCode::InternalServerError);
        let msg = state.conn.msg_mut(id).map(mem::take).unwrap_or_default();
        state.finish(id);
        return Poll::Ready(Ok((Http2RecvStatus::Eos(status), msg)));
      }
      if state.is_ended() {
        return Poll::Ready(Ok((Http2RecvStatus::ClosedConnection, MsgBufferString::default())));
      }
      if let Some(slot) = state.streams.get_mut(&id.u32()) {
        slot.wait(cx.waker())?;
      }
      Poll::Pending
    })
    .await
  }

  /// Send Request
  ///
  /// Sends all data related to a request. `enc_buffer` is no longer used: the connection encodes
  /// into its own buffer.
  ///
  /// Shouldn't be called more than once.
  #[inline]
  pub async fn send_req<MD>(
    &mut self,
    enc_buffer: &mut VectorUsize<u8>,
    req: Request<MD>,
  ) -> crate::Result<Http2SendStatus>
  where
    MD: MsgData,
    MD::Body: Lease<[u8]>,
  {
    let _ = enc_buffer;
    let body = req.msg_data.body().lease();
    {
      let mut state = self.shared.state.lock();
      if self.reserved {
        if state.is_ended() {
          return Ok(Http2SendStatus::ClosedConnection);
        }
        self.reserved = false;
        // The id is taken under the lock that queues the HEADERS: ids leave in order.
        self.stream_id = state.open_reserved()?;
      }
      if let Some(status) = CommonStream::<SW, TCX, true>::send_status(&state, self.stream_id) {
        return Ok(status);
      }
      let uri = req.msg_data.uri();
      state.conn.send_request_head(
        self.stream_id,
        req.method,
        &uri,
        req.msg_data.headers(),
        body.is_empty(),
      )?;
    }
    self.shared.flush().await?;
    if body.is_empty() {
      return Ok(Http2SendStatus::Ok);
    }
    self.common().send_data(body, true).await
  }
}

impl<SW, TCX> Drop for ClientStream<SW, TCX> {
  #[inline]
  fn drop(&mut self) {
    let mut state = self.shared.state.lock();
    if self.reserved {
      state.release_reserved();
    } else if state.streams.contains_key(&self.stream_id.u32()) {
      state.finish(self.stream_id);
    }
  }
}
