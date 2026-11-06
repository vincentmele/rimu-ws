//! One HTTP/2 server connection driven in batches: everything readable is fed to the protocol
//! core at once, the handlers of the requests it completes run in place, and everything they
//! produce leaves in one write.

#[cfg(all(test, feature = "io-uring"))]
mod tests;

use crate::{
  collections::{ArrayVectorCopy, VectorUsize},
  http::{
    Header, KnownHeaderName, MsgBufferString, MsgDataMut as _, Request, StatusCode, U31,
    date_header::DateHeader,
    http2_server_framework::handler_slots::{HandlerSlots, SlotPoll},
  },
  http2::conn::{ConnEvent, Http2Conn},
  net::{StreamReader, StreamWriter, TryRead},
};
use core::{
  future::poll_fn,
  mem,
  net::IpAddr,
  pin::pin,
  task::Poll,
  time::Duration,
};
use hashbrown::HashMap;

/// The read buffer grows in steps of this many bytes.
const READ_CHUNK: usize = 16 * 1024;

/// Turns requests into handler futures.
pub(crate) trait StreamDispatcher {
  /// Answers a request. It owns the request and gives it back with the response written into
  /// its buffers (headers and body) and the response status.
  type AutoFut: Future<Output = (Request<MsgBufferString>, crate::Result<StatusCode>)>;

  /// The handler future of `req`.
  fn auto(&self, req: Request<MsgBufferString>) -> Self::AutoFut;
}

/// Serves one connection until it closes. `conn` has queued its opening SETTINGS; `peer` is the
/// address `accept` returned.
pub(crate) async fn drive_conn<S, D>(
  stream: &mut S,
  mut conn: Http2Conn<false>,
  dispatcher: &D,
  peer: IpAddr,
) -> crate::Result<()>
where
  S: StreamReader + StreamWriter,
  D: StreamDispatcher,
{
  let _ = peer;
  let mut state = Driver {
    collecting: HashMap::new(),
    date: DateHeader::new(),
    pool: VectorUsize::new(),
    rx: VectorUsize::new(),
    slots: HandlerSlots::new(),
    woken: VectorUsize::new(),
  };
  let rslt = state.run(stream, &mut conn, dispatcher).await;
  // Whatever the core queued last (a GOAWAY after an error) still goes out.
  let _flush = write_output(stream, &mut conn).await;
  rslt
}

struct Driver<F> {
  /// Auto-mode streams whose body is still arriving, with the bytes already released.
  collecting: HashMap<u32, usize>,
  date: DateHeader,
  /// Cleared request buffers, swapped into the core so a new stream reuses their capacity.
  pool: VectorUsize<MsgBufferString>,
  rx: VectorUsize<u8>,
  slots: HandlerSlots<F>,
  woken: VectorUsize<usize>,
}

impl<F> Driver<F>
where
  F: Future<Output = (Request<MsgBufferString>, crate::Result<StatusCode>)>,
{
  async fn run<S, D>(
    &mut self,
    stream: &mut S,
    conn: &mut Http2Conn<false>,
    dispatcher: &D,
  ) -> crate::Result<()>
  where
    S: StreamReader + StreamWriter,
    D: StreamDispatcher<AutoFut = F>,
  {
    loop {
      let closed = self.read_available(stream).await?;
      if !self.rx.is_empty() {
        let now = now();
        let consumed = conn.feed_at(&self.rx, now)?;
        self.consume(consumed);
      }
      self.date.refresh();
      self.handle_events(conn, dispatcher)?;
      self.poll_woken(conn)?;
      write_output(stream, conn).await?;
      if closed || conn.is_closed() {
        return Ok(());
      }
      self.wait(stream).await?;
    }
  }

  /// Reads until the stream would block. Returns whether the peer closed it.
  async fn read_available<S>(&mut self, stream: &mut S) -> crate::Result<bool>
  where
    S: StreamReader,
  {
    loop {
      if self.rx.remaining_capacity() < READ_CHUNK {
        self.rx.reserve(READ_CHUNK)?;
      }
      let (init, uninit) = self.rx.split_at_spare_mut();
      let init_len = init.len();
      match stream.try_read(uninit.into())? {
        TryRead::Read(len) => {
          // SAFETY: `try_read` initialized `len` bytes of the spare capacity
          unsafe {
            self.rx.set_len(init_len.wrapping_add(len.get()));
          }
        }
        TryRead::Closed => return Ok(true),
        TryRead::Pending => return Ok(false),
        TryRead::Unsupported => {
          let (init, uninit) = self.rx.split_at_spare_mut();
          let init_len = init.len();
          return match stream.read(uninit.into()).await? {
            Some(len) => {
              // SAFETY: `read` initialized `len` bytes of the spare capacity
              unsafe {
                self.rx.set_len(init_len.wrapping_add(len.get()));
              }
              Ok(false)
            }
            None => Ok(true),
          };
        }
      }
    }
  }

  fn consume(&mut self, consumed: usize) {
    let len = self.rx.len();
    if consumed >= len {
      self.rx.clear();
      return;
    }
    self.rx.as_slice_mut().copy_within(consumed..len, 0);
    self.rx.truncate(len.wrapping_sub(consumed));
  }

  fn handle_events<D>(&mut self, conn: &mut Http2Conn<false>, dispatcher: &D) -> crate::Result<()>
  where
    D: StreamDispatcher<AutoFut = F>,
  {
    while let Some(event) = conn.poll_event() {
      match event {
        ConnEvent::Headers { end_stream: true, stream_id }
        | ConnEvent::Data { end_stream: true, stream_id }
        | ConnEvent::Trailers { stream_id } => {
          let _ = self.collecting.remove(&stream_id.u32());
          self.start(conn, dispatcher, stream_id)?;
        }
        ConnEvent::Headers { end_stream: false, stream_id } => {
          let _ = self.collecting.insert(stream_id.u32(), 0);
        }
        ConnEvent::Data { end_stream: false, stream_id } => {
          let id = stream_id.u32();
          let len = conn.msg_mut(stream_id).map_or(0, |el| el.body.len());
          if let Some(released) = self.collecting.get_mut(&id) {
            let n = len.saturating_sub(*released);
            *released = len;
            conn.release_capacity(stream_id, u32::try_from(n).unwrap_or(u32::MAX))?;
          }
        }
        ConnEvent::Reset { stream_id, .. } => {
          let _ = self.collecting.remove(&stream_id.u32());
          let _ = self.slots.remove_stream(stream_id.u32());
        }
        ConnEvent::GoAway { .. } | ConnEvent::SendCapacity { .. } => {}
      }
    }
    Ok(())
  }

  /// Takes the request of `stream_id` out of the core and runs its handler once, in place.
  fn start<D>(
    &mut self,
    conn: &mut Http2Conn<false>,
    dispatcher: &D,
    stream_id: U31,
  ) -> crate::Result<()>
  where
    D: StreamDispatcher<AutoFut = F>,
  {
    let Some(method) = conn.method(stream_id) else {
      return Ok(());
    };
    let Some(slot_msg) = conn.msg_mut(stream_id) else {
      return Ok(());
    };
    let mut msg = self.pool.pop().unwrap_or_default();
    mem::swap(slot_msg, &mut msg);
    let idx = self.slots.insert(stream_id.u32(), dispatcher.auto(Request::new(method, msg)))?;
    self.poll_slot(conn, idx)
  }

  fn poll_woken(&mut self, conn: &mut Http2Conn<false>) -> crate::Result<()> {
    if !self.slots.has_woken() {
      return Ok(());
    }
    let mut woken = mem::take(&mut self.woken);
    self.slots.take_woken(&mut woken)?;
    for idx in woken.iter().copied() {
      self.poll_slot(conn, idx)?;
    }
    woken.clear();
    self.woken = woken;
    Ok(())
  }

  fn poll_slot(&mut self, conn: &mut Http2Conn<false>, idx: usize) -> crate::Result<()> {
    let Some(id) = self.slots.stream_id(idx) else {
      return Ok(());
    };
    let stream_id = U31::from_u32(id);
    match self.slots.poll(idx) {
      SlotPoll::Pending => Ok(()),
      SlotPoll::Done((req, rslt)) => {
        let mut msg = req.msg_data;
        let status = match rslt {
          Ok(elem) => elem,
          Err(_) => {
            msg.clear();
            StatusCode::InternalServerError
          }
        };
        self.respond(conn, stream_id, status, msg)
      }
      SlotPoll::Panicked => {
        self.respond(conn, stream_id, StatusCode::InternalServerError, MsgBufferString::default())
      }
    }
  }

  fn respond(
    &mut self,
    conn: &mut Http2Conn<false>,
    stream_id: U31,
    status: StatusCode,
    mut msg: MsgBufferString,
  ) -> crate::Result<()> {
    if status == StatusCode::InternalServerError {
      msg.headers.clear();
      msg.body.clear();
    }
    let date: &str = KnownHeaderName::Date.into();
    msg.headers.push_from_iter(Header::from_name_and_value(date, [self.date.as_str()]))?;
    let rslt = conn.send_response(stream_id, status, &mut msg);
    msg.clear();
    let _ = self.pool.push(msg);
    match rslt {
      Ok(()) => Ok(()),
      Err(crate::Error::Http2ErrorGoAway(_, crate::http2::Http2Error::SendQueueFull)) => rslt,
      // The stream went away meanwhile (reset by the peer): nothing to answer.
      Err(_) => Ok(()),
    }
  }

  /// Waits for bytes to read or a handler to wake.
  async fn wait<S>(&mut self, stream: &mut S) -> crate::Result<()>
  where
    S: StreamReader,
  {
    let slots = &self.slots;
    let mut readable = pin!(stream.readable());
    poll_fn(|cx| {
      slots.register_conn(cx.waker());
      if slots.has_woken() {
        return Poll::Ready(Ok(()));
      }
      readable.as_mut().poll(cx)
    })
    .await
  }
}

/// Writes everything the core queued, in groups of at most 8 slices.
async fn write_output<S>(stream: &mut S, conn: &mut Http2Conn<false>) -> crate::Result<()>
where
  S: StreamWriter,
{
  while conn.has_output() {
    let mut slices = ArrayVectorCopy::<&[u8], 16>::new();
    conn.output(&mut slices);
    let group = slices.get(..usize::from(slices.len()).min(8)).unwrap_or_default();
    let len: usize = group.iter().map(|el| el.len()).sum();
    if !stream.try_write_all_vectored(group)? {
      stream.write_all_vectored(group).await?;
    }
    conn.advance_output(len);
  }
  Ok(())
}

/// A forward-moving clock for the core's rate windows.
fn now() -> Duration {
  std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default()
}
