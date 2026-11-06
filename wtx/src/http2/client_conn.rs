//! The client's connection task and the state its handles share.
//!
//! The connection task owns the reading half: it reads, feeds [`Http2Conn`] and wakes the
//! streams the events name. Handles ([`crate::http2::Http2`], [`crate::http2::ClientStream`])
//! reach the core through one short lock, never held across an `.await`. Whoever queues output
//! writes it, through the writer's async lock: a handle right after its call, the task after
//! each read. A blocking stream (std) therefore never stops writes behind a pending read.

use crate::{
  calendar::Instant,
  collections::{ArrayVectorCopy, MaybeUninitSlice, VectorUsize},
  http::{StatusCode, U31},
  http2::{
    Http2ErrorCode,
    conn::{ConnEvent, Http2Conn},
  },
  net::{ConnectionState, StreamReader, StreamWriter},
  sync::{Arc, AsyncMutex, SyncMutex},
  tls::{TlsCtx, TlsStreamBridge, TlsStreamBridgeData, TlsStreamReader, TlsStreamWriter},
};
use core::{
  future::poll_fn,
  pin::pin,
  task::{Poll, Waker},
};
use hashbrown::HashMap;

/// Bytes asked of the socket per read.
const READ_LEN: usize = 32 * 1024;

/// What a client connection's handles and its task share.
#[derive(Debug)]
pub(crate) struct ClientShared<SW, TCX> {
  pub(crate) state: SyncMutex<ClientState>,
  writer: AsyncMutex<ClientWriter<SW, TCX>>,
}

impl<SW, TCX> ClientShared<SW, TCX> {
  pub(crate) fn new(conn: Http2Conn<true>, stream: TlsStreamWriter<SW, TCX, true>) -> Self {
    Self {
      state: SyncMutex::new(ClientState {
        abort: false,
        closed: None,
        conn,
        flush_wanted: false,
        open_wakers: VectorUsize::new(),
        read_done: false,
        read_error: false,
        reserved: 0,
        streams: HashMap::new(),
        task_waker: None,
      }),
      writer: AsyncMutex::new(ClientWriter { buf: VectorUsize::new(), stream }),
    }
  }
}

impl<SW, TCX> ClientShared<SW, TCX>
where
  SW: StreamWriter,
  TCX: TlsCtx,
{
  /// Writes everything the core has queued. A write error ends the connection.
  pub(crate) async fn flush(&self) -> crate::Result<()> {
    let mut guard = self.writer.lock().await;
    let ClientWriter { buf, stream } = &mut *guard;
    loop {
      {
        let mut state = self.state.lock();
        state.flush_wanted = false;
        if state.abort || !state.conn.has_output() {
          return Ok(());
        }
        buf.clear();
        let mut slices = ArrayVectorCopy::new();
        state.conn.output(&mut slices);
        for slice in slices.iter() {
          buf.extend_from_copyable_slice(slice)?;
        }
        state.conn.advance_output(buf.len());
      }
      if let Err(err) = stream.write_all(buf.as_slice()).await {
        let mut state = self.state.lock();
        state.read_error = true;
        state.read_done = true;
        state.wake_all();
        state.wake_task();
        return Err(err);
      }
    }
  }
}

/// The writing half and its scratch buffer.
#[derive(Debug)]
struct ClientWriter<SW, TCX> {
  buf: VectorUsize<u8>,
  stream: TlsStreamWriter<SW, TCX, true>,
}

/// The connection core plus who waits on it.
#[derive(Debug)]
pub(crate) struct ClientState {
  /// Set by `close_abruptly`: the task stops at once.
  abort: bool,
  /// How the connection ended, once the task has stopped.
  closed: Option<ConnectionState>,
  pub(crate) conn: Http2Conn<true>,
  /// Output was queued where it could not be written at once (a dropped handle): the task
  /// writes it.
  flush_wanted: bool,
  /// Callers of `Http2::stream` waiting for the server's limit to leave room.
  open_wakers: VectorUsize<Waker>,
  /// The reading half saw EOF, an error, or a connection error of the core.
  read_done: bool,
  read_error: bool,
  /// Handles from `Http2::stream` that have not sent their request yet: they hold room under
  /// the server's limit, and get their stream id only when they send, so ids reach the server in
  /// increasing order (RFC 9113 §5.1.1).
  pub(crate) reserved: u32,
  /// The streams whose handles are alive.
  pub(crate) streams: HashMap<u32, StreamSlot>,
  /// The connection task, woken when output is queued.
  task_waker: Option<Waker>,
}

impl ClientState {
  /// Aborts the connection: the task stops without writing more and every waiter wakes.
  #[cfg(feature = "http2-client-pool")]
  pub(crate) fn close_abruptly(&mut self) {
    self.abort = true;
    if self.closed.is_none() {
      self.closed = Some(ConnectionState::ClosedAbruptly);
    }
    self.wake_all();
    self.wake_task();
  }

  /// See [`ConnectionState`].
  pub(crate) fn connection_state(&self) -> ConnectionState {
    if let Some(elem) = self.closed {
      elem
    } else if self.read_done || !self.conn.accepts_streams() {
      ConnectionState::Draining
    } else {
      ConnectionState::Open
    }
  }

  /// The handle of `stream_id` is done: the core frees the stream (resetting it if it has not
  /// ended) and a caller waiting for room may open one. A reset is written by the task.
  pub(crate) fn finish(&mut self, stream_id: U31) {
    self.conn.finish_stream(stream_id, true);
    let _ = self.streams.remove(&stream_id.u32());
    self.wake_openers();
    self.flush_later();
  }

  /// Asks the task to write what is queued.
  pub(crate) fn flush_later(&mut self) {
    self.flush_wanted = true;
    self.wake_task();
  }

  /// Opens the stream of a reserved handle, at the moment its HEADERS are queued.
  pub(crate) fn open_reserved(&mut self) -> crate::Result<U31> {
    self.reserved = self.reserved.saturating_sub(1);
    let stream_id = self.conn.open_stream()?;
    let _ = self.streams.insert(stream_id.u32(), StreamSlot::default());
    Ok(stream_id)
  }

  /// A reserved handle went away without sending.
  pub(crate) fn release_reserved(&mut self) {
    self.reserved = self.reserved.saturating_sub(1);
    self.wake_openers();
  }

  /// Nothing more can be sent or received on this connection.
  pub(crate) fn is_ended(&self) -> bool {
    self.closed.is_some() || self.read_done
  }

  /// Registers `waker` to be woken when a stream can be opened.
  pub(crate) fn wait_open(&mut self, waker: &Waker) -> crate::Result<()> {
    if !self.open_wakers.iter().any(|el| el.will_wake(waker)) {
      self.open_wakers.push(waker.clone())?;
    }
    Ok(())
  }

  /// Wakes the connection task: output is queued, or the client wants it to stop.
  fn wake_task(&mut self) {
    if let Some(waker) = self.task_waker.take() {
      waker.wake();
    }
  }

  /// Routes the core's events to the streams they name.
  fn dispatch(&mut self) -> crate::Result<()> {
    let Self { conn, streams, .. } = self;
    while let Some(event) = conn.poll_event() {
      match event {
        ConnEvent::Data { stream_id, .. } => {
          let Some(slot) = streams.get_mut(&stream_id.u32()) else {
            continue;
          };
          // The body is buffered up to `max_body_len`: hand its window back as it arrives.
          let len = conn.msg_mut(stream_id).map_or(0, |el| el.body.len());
          if len > slot.released {
            let n = u32::try_from(len.wrapping_sub(slot.released)).unwrap_or(u32::MAX);
            conn.release_capacity(stream_id, n)?;
            slot.released = len;
          }
          slot.wake();
        }
        ConnEvent::Headers { stream_id, .. } => {
          if let Some(slot) = streams.get_mut(&stream_id.u32()) {
            slot.status = conn.status(stream_id);
            slot.wake();
          }
        }
        ConnEvent::Trailers { stream_id } | ConnEvent::SendCapacity { stream_id } => {
          if let Some(slot) = streams.get_mut(&stream_id.u32()) {
            slot.wake();
          }
        }
        ConnEvent::Reset { code, stream_id } => {
          if let Some(slot) = streams.get_mut(&stream_id.u32()) {
            slot.reset = Some(code);
            slot.wake();
          }
        }
        ConnEvent::GoAway { last_stream_id, .. } => {
          // Streams above `last_stream_id` were not processed and never will be.
          for (id, slot) in streams.iter_mut() {
            if *id > last_stream_id.u32() && slot.reset.is_none() {
              conn.finish_stream(U31::from_u32(*id), false);
              slot.reset = Some(Http2ErrorCode::RefusedStream);
              slot.wake();
            }
          }
        }
      }
    }
    // Streams may have ended and SETTINGS may have changed the limit.
    self.wake_openers();
    Ok(())
  }

  fn wake_all(&mut self) {
    for slot in self.streams.values_mut() {
      slot.wake();
    }
    self.wake_openers();
  }

  fn wake_openers(&mut self) {
    while let Some(waker) = self.open_wakers.pop() {
      waker.wake();
    }
  }
}

/// What the client side knows of one stream beyond the core.
#[derive(Debug, Default)]
pub(crate) struct StreamSlot {
  /// Body bytes whose window was handed back to the server.
  pub(crate) released: usize,
  /// The stream was reset by the server, or refused by its GOAWAY.
  pub(crate) reset: Option<Http2ErrorCode>,
  /// The response status, once its HEADERS arrived; kept for a reset stream, whose core state
  /// is gone.
  pub(crate) status: Option<StatusCode>,
  wakers: VectorUsize<Waker>,
}

impl StreamSlot {
  /// Registers `waker` to be woken by the next event of this stream.
  pub(crate) fn wait(&mut self, waker: &Waker) -> crate::Result<()> {
    if !self.wakers.iter().any(|el| el.will_wake(waker)) {
      self.wakers.push(waker.clone())?;
    }
    Ok(())
  }

  fn wake(&mut self) {
    while let Some(waker) = self.wakers.pop() {
      waker.wake();
    }
  }
}

/// The connection task: writes the preface, then reads until the connection ends and wakes
/// every waiter.
pub(crate) async fn conn_task<SR, SW, TCX>(
  shared: Arc<ClientShared<SW, TCX>>,
  mut rx: VectorUsize<u8>,
  bridge: TlsStreamBridge<true>,
  mut reader: TlsStreamReader<SR, TCX, true>,
) where
  SR: StreamReader,
  SW: StreamWriter,
  TCX: TlsCtx,
{
  enum Next {
    Bridge(TlsStreamBridgeData),
    Flush,
    Stop,
  }
  if shared.flush().await.is_ok() {
    let mut read = pin!(read_loop(&shared, &mut rx, &mut reader));
    let mut bridge_fut = pin!(bridge.listen());
    loop {
      let next = poll_fn(|cx| {
        {
          let mut state = shared.state.lock();
          if state.abort {
            return Poll::Ready(Next::Stop);
          }
          state.task_waker = Some(cx.waker().clone());
        }
        if !TCX::TY.is_plain_text()
          && let Poll::Ready(data) = bridge_fut.as_mut().poll(cx)
        {
          return Poll::Ready(Next::Bridge(data));
        }
        if read.as_mut().poll(cx).is_ready() {
          return Poll::Ready(Next::Stop);
        }
        if shared.state.lock().flush_wanted {
          return Poll::Ready(Next::Flush);
        }
        Poll::Pending
      })
      .await;
      match next {
        Next::Bridge(data) => {
          let _rslt = shared.writer.lock().await.stream.manage_bridge_data(data).await;
          bridge_fut.set(bridge.listen());
        }
        Next::Flush => {
          let _rslt = shared.flush().await;
        }
        Next::Stop => break,
      }
    }
    // A connection error of the core queued GOAWAY.
    let _rslt = shared.flush().await;
  }
  let mut state = shared.state.lock();
  if state.closed.is_none() {
    let graceful = !state.read_error && !state.abort;
    state.closed = Some(if graceful {
      ConnectionState::ClosedGracefully
    } else {
      ConnectionState::ClosedAbruptly
    });
  }
  state.read_done = true;
  state.wake_all();
}

async fn read_loop<SR, SW, TCX>(
  shared: &ClientShared<SW, TCX>,
  rx: &mut VectorUsize<u8>,
  reader: &mut TlsStreamReader<SR, TCX, true>,
) where
  SR: StreamReader,
  TCX: TlsCtx,
{
  let Ok(mut buf) = VectorUsize::from_cloneable_elem(READ_LEN, 0u8) else {
    shared.state.lock().read_error = true;
    return;
  };
  loop {
    let rslt = reader.read(MaybeUninitSlice::from(buf.as_slice_mut())).await;
    let mut state = shared.state.lock();
    let n = match rslt {
      Ok(Some(elem)) => elem.get(),
      Ok(None) => {
        state.read_done = true;
        return;
      }
      Err(_) => {
        state.read_error = true;
        state.read_done = true;
        return;
      }
    };
    let fed = rx
      .extend_from_copyable_slice(buf.as_slice().get(..n).unwrap_or_default())
      .and_then(|()| {
        state.conn.feed_at(rx.as_slice(), Instant::now_timestamp().unwrap_or_default())
      })
      .and_then(|consumed| {
        let len = rx.len();
        if consumed >= len {
          rx.clear();
        } else {
          rx.as_slice_mut().copy_within(consumed..len, 0);
          rx.truncate(len.wrapping_sub(consumed));
        }
        state.dispatch()
      });
    // SETTINGS and PING acknowledgements, window updates.
    state.flush_wanted = true;
    if fed.is_err() {
      // The core queued GOAWAY; the task writes it and ends.
      state.read_error = true;
      state.read_done = true;
      return;
    }
  }
}
