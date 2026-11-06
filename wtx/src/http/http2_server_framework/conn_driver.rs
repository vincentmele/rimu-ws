//! One HTTP/2 server connection driven in batches: everything readable is fed to the protocol
//! core at once, the handlers of the requests it completes run in place, and everything they
//! produce leaves in one write.

#[cfg(all(test, feature = "io-uring"))]
pub(crate) mod tests;

use crate::{
  collections::{ArrayVectorCopy, VectorUsize},
  http::{
    Header, KnownHeaderName, MsgBufferString, MsgDataMut as _, Protocol, Request, StatusCode, U31,
    date_header::DateHeader,
    http2_server_framework::handler_slots::{HandlerSlots, SlotPoll},
  },
  http2::{
    ServerStream,
    conn::{ConnEvent, Http2Conn},
    server_stream::ConnShared,
  },
  net::{StreamReader, StreamWriter, TryRead},
};
use alloc::{rc::Rc, vec::Vec};
use core::{
  cell::RefCell,
  future::poll_fn,
  mem,
  net::IpAddr,
  pin::pin,
  task::Poll,
  time::Duration,
};
use hashbrown::{HashMap, HashSet};

/// The read buffer grows in steps of this many bytes.
const READ_CHUNK: usize = 16 * 1024;

/// Turns requests into handler futures.
pub(crate) trait StreamDispatcher {
  /// Answers a request. It owns the request and gives it back with the response written into
  /// its buffers (headers and body) and the response status.
  type AutoFut: Future<Output = (Request<MsgBufferString>, crate::Result<StatusCode>)>;
  /// What a route lookup found, handed back to `auto` or `manual` so a path is looked up once.
  type Matches: Copy;

  /// The handler future of `req`, which arrived on a stream with this `:protocol`; `matches` is
  /// what [`Self::route`] found for its path, `None` for no route.
  fn auto(
    &self,
    req: Request<MsgBufferString>,
    protocol: Option<Protocol>,
    matches: Option<Self::Matches>,
  ) -> Self::AutoFut;

  /// Starts the manual-mode handler of `req` on its own task.
  fn manual(&self, stream: ServerStream, req: Request<MsgBufferString>, matches: Self::Matches);

  /// Looks `path` up, once per request, as soon as its headers arrive.
  fn route(&self, path: &str) -> Route<Self::Matches>;
}

/// What [`StreamDispatcher::route`] found.
pub(crate) enum Route<MT> {
  /// An auto-mode endpoint.
  Auto(MT),
  /// A manual-mode endpoint.
  Manual(MT),
  /// No route: auto mode answers 404.
  NotFound,
}

/// Serves one connection until it closes. `conn` has queued its opening SETTINGS; `peer` is the
/// address `accept` returned.
pub(crate) async fn drive_conn<S, D>(
  stream: &mut S,
  conn: Http2Conn<false>,
  dispatcher: &D,
  peer: IpAddr,
) -> crate::Result<()>
where
  S: StreamReader + StreamWriter,
  D: StreamDispatcher,
{
  let _ = peer;
  let shared = ConnShared::new(conn);
  let mut state = Driver {
    collecting: HashMap::new(),
    manual: HashSet::new(),
    shared: shared.clone(),
    date: DateHeader::new(),
    pool: VectorUsize::new(),
    rx: VectorUsize::new(),
    slots: HandlerSlots::new(),
    woken: VectorUsize::new(),
  };
  let rslt = state.run(stream, dispatcher).await;
  // Whatever the core queued last (a GOAWAY after an error) still goes out.
  let _flush = write_output(stream, &shared).await;
  rslt
}

struct Driver<F, MT> {
  /// Auto-mode streams whose body is still arriving, with the bytes already released and their
  /// route.
  collecting: HashMap<u32, (usize, Option<MT>)>,
  date: DateHeader,
  /// Streams served by manual-mode handlers.
  manual: HashSet<u32>,
  shared: Rc<RefCell<ConnShared>>,
  /// Cleared request buffers, swapped into the core so a new stream reuses their capacity.
  pool: VectorUsize<MsgBufferString>,
  rx: VectorUsize<u8>,
  slots: HandlerSlots<F>,
  woken: VectorUsize<usize>,
}

impl<F, MT> Driver<F, MT>
where
  F: Future<Output = (Request<MsgBufferString>, crate::Result<StatusCode>)>,
  MT: Copy,
{
  async fn run<S, D>(&mut self, stream: &mut S, dispatcher: &D) -> crate::Result<()>
  where
    S: StreamReader + StreamWriter,
    D: StreamDispatcher<AutoFut = F, Matches = MT>,
  {
    let shared = self.shared.clone();
    loop {
      let closed = self.read_available(stream).await?;
      {
        let mut guard = shared.borrow_mut();
        let state = &mut *guard;
        state.dirty = false;
        if !self.rx.is_empty() {
          let consumed = state.conn.feed_at(&self.rx, now())?;
          self.consume(consumed);
        }
        self.date.refresh();
        self.handle_events(state, dispatcher)?;
        self.poll_woken(&mut state.conn)?;
      }
      write_output(stream, &shared).await?;
      if closed || shared.borrow().conn.is_closed() {
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

  fn handle_events<D>(&mut self, state: &mut ConnShared, dispatcher: &D) -> crate::Result<()>
  where
    D: StreamDispatcher<AutoFut = F, Matches = MT>,
  {
    while let Some(event) = state.conn.poll_event() {
      if let ConnEvent::Data { stream_id, .. }
      | ConnEvent::Trailers { stream_id }
      | ConnEvent::SendCapacity { stream_id }
      | ConnEvent::Reset { stream_id, .. } = event
        && self.manual.contains(&stream_id.u32())
      {
        if matches!(event, ConnEvent::Reset { .. }) {
          let _ = self.manual.remove(&stream_id.u32());
        }
        state.wake_stream(stream_id.u32());
        continue;
      }
      let conn = &mut state.conn;
      match event {
        ConnEvent::Headers { end_stream, stream_id } => {
          let route = conn
            .msg_mut(stream_id)
            .map_or(Route::NotFound, |el| dispatcher.route(el.uri.path()));
          let matches = match route {
            Route::Manual(elem) => {
              self.start_manual(state, dispatcher, stream_id, elem)?;
              continue;
            }
            Route::Auto(elem) => Some(elem),
            Route::NotFound => None,
          };
          if end_stream {
            self.start(&mut state.conn, dispatcher, stream_id, matches)?;
          } else {
            let _ = self.collecting.insert(stream_id.u32(), (0, matches));
          }
        }
        ConnEvent::Data { end_stream: true, stream_id } | ConnEvent::Trailers { stream_id } => {
          let matches = self.collecting.remove(&stream_id.u32()).and_then(|el| el.1);
          self.start(conn, dispatcher, stream_id, matches)?;
        }
        ConnEvent::Data { end_stream: false, stream_id } => {
          let id = stream_id.u32();
          let len = conn.msg_mut(stream_id).map_or(0, |el| el.body.len());
          if let Some((released, _)) = self.collecting.get_mut(&id) {
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
    matches: Option<MT>,
  ) -> crate::Result<()>
  where
    D: StreamDispatcher<AutoFut = F, Matches = MT>,
  {
    let Some(method) = conn.method(stream_id) else {
      return Ok(());
    };
    let protocol = conn.protocol(stream_id);
    let Some(slot_msg) = conn.msg_mut(stream_id) else {
      return Ok(());
    };
    let mut msg = self.pool.pop().unwrap_or_default();
    mem::swap(slot_msg, &mut msg);
    if msg.body.is_empty() {
      // The response is written into the body buffer the last response on this thread released:
      // still in cache, unlike this stream's own.
      let own = mem::replace(&mut msg.body, body_pool_take());
      body_pool_give(own);
    }
    let fut = dispatcher.auto(Request::new(method, msg), protocol, matches);
    let idx = self.slots.insert(stream_id.u32(), fut)?;
    self.poll_slot(conn, idx)
  }

  /// Hands the stream to its manual-mode handler. The request goes with its headers; its body
  /// stays in the core for [`ServerStream::recv_data`].
  fn start_manual<D>(
    &mut self,
    state: &mut ConnShared,
    dispatcher: &D,
    stream_id: U31,
    matches: MT,
  ) -> crate::Result<()>
  where
    D: StreamDispatcher<AutoFut = F, Matches = MT>,
  {
    let conn = &mut state.conn;
    let Some(method) = conn.method(stream_id) else {
      return Ok(());
    };
    let protocol = conn.protocol(stream_id);
    let Some(slot_msg) = conn.msg_mut(stream_id) else {
      return Ok(());
    };
    let mut msg = self.pool.pop().unwrap_or_default();
    mem::swap(slot_msg, &mut msg);
    // Body bytes that arrived with the headers stay in the core, where `recv_data` finds them.
    mem::swap(&mut slot_msg.body, &mut msg.body);
    let _ = self.manual.insert(stream_id.u32());
    let stream = ServerStream::new(self.shared.clone(), method, protocol, stream_id);
    dispatcher.manual(stream, Request::new(method, msg), matches);
    Ok(())
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
    body_pool_give(mem::take(&mut msg.body));
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
    let shared = &self.shared;
    let mut readable = pin!(stream.readable());
    poll_fn(|cx| {
      slots.register_conn(cx.waker());
      {
        let mut state = shared.borrow_mut();
        if state.dirty || state.conn.has_output() {
          return Poll::Ready(Ok(()));
        }
        state.conn_waker = Some(cx.waker().clone());
      }
      if slots.has_woken() {
        return Poll::Ready(Ok(()));
      }
      readable.as_mut().poll(cx)
    })
    .await
  }
}

/// Response body buffers released on this thread, most recent last, so the next handler writes
/// into one that is still in cache. Buffers above `BODY_POOL_BUFFER_MAX` are freed.
const BODY_POOL_MAX: usize = 64;
const BODY_POOL_BUFFER_MAX: usize = 1 << 20;

std::thread_local! {
  static BODY_POOL: RefCell<Vec<VectorUsize<u8>>> = const { RefCell::new(Vec::new()) };
}

fn body_pool_take() -> VectorUsize<u8> {
  BODY_POOL.with(|pool| pool.borrow_mut().pop()).unwrap_or_default()
}

fn body_pool_give(mut body: VectorUsize<u8>) {
  let capacity = body.capacity();
  if capacity == 0 || capacity > BODY_POOL_BUFFER_MAX {
    return;
  }
  body.clear();
  BODY_POOL.with(|pool| {
    let mut pool = pool.borrow_mut();
    if pool.len() < BODY_POOL_MAX {
      pool.push(body);
    }
  });
}

/// Writes everything the core queued, in groups of at most 8 slices.
async fn write_output<S>(stream: &mut S, shared: &RefCell<ConnShared>) -> crate::Result<()>
where
  S: StreamWriter,
{
  loop {
    // The slices borrow the core; a write that must wait copies them out first, so no borrow is
    // held across the await.
    let written = {
      let mut guard = shared.borrow_mut();
      if !guard.conn.has_output() {
        return Ok(());
      }
      // The usual case: the output is one run of bytes, handed to the stream without a copy;
      // the stream gives back a recycled buffer for the next output.
      if let Ok(mut bytes) = guard.conn.take_output(Vec::new()) {
        if stream.try_send_owned(&mut bytes)? {
          guard.conn.give_output_buffer(bytes);
          continue;
        }
        let _spare = guard.conn.untake_output(bytes);
      }
      let mut slices = ArrayVectorCopy::<&[u8], 16>::new();
      guard.conn.output(&mut slices);
      let group = slices.get(..usize::from(slices.len()).min(8)).unwrap_or_default();
      let len: usize = group.iter().map(|el| el.len()).sum();
      if stream.try_write_all_vectored(group)? {
        guard.conn.advance_output(len);
        None
      } else {
        let mut copy = VectorUsize::with_capacity(len)?;
        let _ = copy.extend_from_copyable_slices(group.iter().copied())?;
        Some((copy, len))
      }
    };
    if let Some((copy, len)) = written {
      stream.write_all(&copy).await?;
      shared.borrow_mut().conn.advance_output(len);
    }
  }
}

/// A forward-moving clock for the core's rate windows.
fn now() -> Duration {
  std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default()
}
