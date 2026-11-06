//! A stream of an HTTP/2 server connection, for handlers that drive it themselves (manual mode,
//! WebSocket over HTTP/2).

use crate::{
  collections::VectorUsize,
  http::{Headers, Method, Protocol, StatusCode, U31},
  http2::{
    Http2ErrorCode, Http2RecvStatus, Http2SendStatus,
    conn::{Http2Conn, body::Body},
  },
};
use alloc::rc::Rc;
use core::{cell::RefCell, future::poll_fn, task::Poll, task::Waker};
use hashbrown::HashMap;

/// Above this many bytes queued on a stream, [`ServerStream::send_data`] waits for the peer to
/// open its window.
const SEND_HIGH_WATER: u32 = 256 * 1024;

/// The connection core shared by the connection task and its manual streams. Every access is a
/// short, synchronous borrow on the connection's thread.
#[derive(Debug)]
pub(crate) struct ConnShared {
  pub(crate) conn: Http2Conn<false>,
  /// The connection task, woken when a stream queued output.
  pub(crate) conn_waker: Option<Waker>,
  /// A stream queued output since the connection task last wrote.
  pub(crate) dirty: bool,
  /// Streams waiting for data, window or a reset.
  pub(crate) wakers: HashMap<u32, Waker>,
}

impl ConnShared {
  pub(crate) fn new(conn: Http2Conn<false>) -> Rc<RefCell<Self>> {
    Rc::new(RefCell::new(Self { conn, conn_waker: None, dirty: false, wakers: HashMap::new() }))
  }

  /// Wakes the stream `id` waits on, if any.
  pub(crate) fn wake_stream(&mut self, id: u32) {
    if let Some(waker) = self.wakers.remove(&id) {
      waker.wake();
    }
  }

  fn queued(&mut self) {
    self.dirty = true;
    if let Some(waker) = &self.conn_waker {
      waker.wake_by_ref();
    }
  }
}

/// A stream of a server connection, handed to manual-mode handlers.
///
/// It lives on the connection's thread. Dropping it before the stream ended resets the stream
/// with `CANCEL`.
#[derive(Debug)]
pub struct ServerStream {
  finished: bool,
  method: Method,
  protocol: Option<Protocol>,
  shared: Rc<RefCell<ConnShared>>,
  stream_id: U31,
}

impl ServerStream {
  pub(crate) const fn new(
    shared: Rc<RefCell<ConnShared>>,
    method: Method,
    protocol: Option<Protocol>,
    stream_id: U31,
  ) -> Self {
    Self { finished: false, method, protocol, shared, stream_id }
  }

  /// Request method.
  #[inline]
  pub const fn method(&self) -> Method {
    self.method
  }

  /// The `:protocol` of an extended CONNECT.
  #[inline]
  pub const fn protocol(&self) -> Option<Protocol> {
    self.protocol
  }

  /// Stream identifier.
  #[inline]
  pub const fn stream_id(&self) -> U31 {
    self.stream_id
  }

  /// Appends the next received body bytes to `buffer`. `Eos` once the request ended,
  /// `ClosedStream` if the stream was reset.
  #[inline]
  pub async fn recv_data(
    &mut self,
    buffer: &mut VectorUsize<u8>,
  ) -> crate::Result<Http2RecvStatus<(), ()>> {
    let id = self.stream_id;
    poll_fn(|cx| {
      let mut guard = self.shared.borrow_mut();
      let shared = &mut *guard;
      let Some(msg) = shared.conn.msg_mut(id) else {
        return Poll::Ready(Ok(Http2RecvStatus::ClosedStream(())));
      };
      if !msg.body.is_empty() {
        let n = msg.body.len();
        if let Err(err) = buffer.extend_from_copyable_slice(&msg.body) {
          return Poll::Ready(Err(err));
        }
        msg.body.clear();
        if let Err(err) = shared.conn.release_capacity(id, u32::try_from(n).unwrap_or(u32::MAX)) {
          return Poll::Ready(Err(err));
        }
        shared.queued();
        return Poll::Ready(Ok(Http2RecvStatus::Ongoing(())));
      }
      if shared.conn.recv_closed(id).unwrap_or(true) {
        return Poll::Ready(Ok(Http2RecvStatus::Eos(())));
      }
      let _ = shared.wakers.insert(id.u32(), cx.waker().clone());
      Poll::Pending
    })
    .await
  }

  /// Sends the response HEADERS.
  #[inline]
  pub async fn send_headers(
    &mut self,
    headers: &Headers,
    end_stream: bool,
    status: StatusCode,
  ) -> crate::Result<Http2SendStatus> {
    let mut shared = self.shared.borrow_mut();
    if shared.conn.msg_mut(self.stream_id).is_none() {
      return Ok(Http2SendStatus::ClosedStream);
    }
    shared.conn.send_headers(self.stream_id, Some(status), headers, end_stream)?;
    shared.queued();
    self.finished |= end_stream;
    Ok(Http2SendStatus::Ok)
  }

  /// Queues `data`, waiting while more than 256 KiB of this stream wait for the peer's window.
  #[inline]
  pub async fn send_data(&mut self, data: &[u8], end_stream: bool) -> crate::Result<Http2SendStatus> {
    {
      let mut shared = self.shared.borrow_mut();
      if shared.conn.msg_mut(self.stream_id).is_none() {
        return Ok(Http2SendStatus::ClosedStream);
      }
      shared.conn.send_data(self.stream_id, Body::Borrowed(data), end_stream)?;
      shared.queued();
    }
    self.finished |= end_stream;
    let id = self.stream_id;
    poll_fn(|cx| {
      let mut shared = self.shared.borrow_mut();
      if shared.conn.msg_mut(id).is_none() || shared.conn.stream_send_pending(id) <= SEND_HIGH_WATER {
        return Poll::Ready(Ok(Http2SendStatus::Ok));
      }
      let _ = shared.wakers.insert(id.u32(), cx.waker().clone());
      Poll::Pending
    })
    .await
  }

  /// Sends trailers, which end the stream.
  #[inline]
  pub async fn send_trailers(&mut self, trailers: &Headers) -> crate::Result<Http2SendStatus> {
    let mut shared = self.shared.borrow_mut();
    if shared.conn.msg_mut(self.stream_id).is_none() {
      return Ok(Http2SendStatus::ClosedStream);
    }
    shared.conn.send_trailers(self.stream_id, trailers)?;
    shared.queued();
    self.finished = true;
    Ok(Http2SendStatus::Ok)
  }

  /// Resets the stream.
  #[inline]
  pub async fn send_reset(&mut self, code: Http2ErrorCode) {
    let mut shared = self.shared.borrow_mut();
    shared.conn.send_reset(self.stream_id, code);
    shared.queued();
    self.finished = true;
  }

  /// Starts a graceful shutdown of the whole connection (GOAWAY).
  #[inline]
  pub async fn send_go_away(&mut self, code: Http2ErrorCode) {
    let mut shared = self.shared.borrow_mut();
    shared.conn.go_away(code);
    shared.queued();
  }
}

impl Drop for ServerStream {
  #[inline]
  fn drop(&mut self) {
    if self.finished {
      return;
    }
    if let Ok(mut shared) = self.shared.try_borrow_mut()
      && shared.conn.msg_mut(self.stream_id).is_some()
    {
      shared.conn.send_reset(self.stream_id, Http2ErrorCode::Cancel);
      shared.queued();
    }
  }
}

impl crate::misc::Lease<ServerStream> for ServerStream {
  #[inline]
  fn lease(&self) -> &ServerStream {
    self
  }
}

impl crate::misc::LeaseMut<ServerStream> for ServerStream {
  #[inline]
  fn lease_mut(&mut self) -> &mut ServerStream {
    self
  }
}
