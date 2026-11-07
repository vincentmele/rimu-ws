//! One HTTP/1.1 server connection driven in batches: everything readable is fed to the protocol
//! core at once, the handlers of the requests it completes run in place, and everything they
//! produce leaves in one write.
//!
//! The rules that keep the core sound, and that this loop follows:
//!
//! 1. Output is flushed before the connection waits for input. `poll_event` reports `NeedMore`
//!    both for "more input needed" and while a closing connection still has unflushed output, so
//!    a driver that blocked on a read with output pending would leave a peer waiting forever for
//!    the (closing) response. A connection that wants to close is closed right after the flush.
//! 2. After a `feed`, events are polled before the request is looked at again: the request view
//!    is only valid right after `RequestReady`.
//! 3. `feed` may take fewer bytes than offered when its buffer is full. The rest is fed again
//!    after the requests it made room for were answered.
//! 4. While a response is delayed a plaintext socket is still watched: what arrives is kept for
//!    after the response, and a peer that goes away ends the connection at once.
//! 5. A connection with a first-head deadline (TLS) races it in every wait until its first
//!    request is ready.

use crate::{
  collections::VectorUsize,
  futures::Sleep,
  http::{HttpRecvParams, http1_server_framework::Http1Res},
  http1::{Http1Conn, Http1Event, Http1Request},
  net::{NetError, StreamReader, StreamWriter, TryRead},
  tls::TlsError,
};
use alloc::{collections::BTreeMap, vec::Vec};
use core::{
  cell::{Cell, RefCell},
  future::poll_fn,
  mem,
  pin::{Pin, pin},
  task::{Poll, Waker},
  time::Duration,
};

/// The read buffer grows in steps of this many bytes.
const READ_CHUNK: usize = 16 * 1024;
/// Reading stops once this much is received and not yet fed, so that the peer is slowed down by
/// TCP instead of by memory.
const RX_MAX: usize = 256 * 1024;
/// Responses are flushed once this much has been queued, so that a long pipeline of large
/// responses can't pile up in memory.
const OUT_HIGH_WATER: usize = 256 * 1024;

/// What every connection of a server is driven with.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DriveParams {
  /// Time the connection has for the head of its first request to arrive. Past that it fails
  /// with [`crate::Error::ExpiredFuture`].
  pub(crate) first_head: Option<Duration>,
  pub(crate) hrc: HttpRecvParams,
  /// Longest delay a response may ask for; longer ones are cut to it.
  pub(crate) max_delay: Duration,
}

/// Answers the requests of a connection.
pub(crate) trait Http1Service {
  /// Fills `res` with the answer to the request.
  fn call(&mut self, head: Http1Request<'_>, body: &[u8], res: &mut Http1Res);
}

/// The connections one server drives on one thread, for that server's shutdown to reach: other
/// servers on the thread keep serving.
#[derive(Debug, Default)]
pub(crate) struct ConnGroup {
  going_away: Cell<bool>,
  next_id: Cell<u64>,
  /// Connections waiting for a request, to be woken when the group goes away.
  waiting: RefCell<BTreeMap<u64, Waker>>,
}

impl ConnGroup {
  /// The server is shutting down: connections between requests close, and those in the middle of
  /// one close after answering it.
  pub(crate) fn go_away(&self) {
    self.going_away.set(true);
    let waiting = mem::take(&mut *self.waiting.borrow_mut());
    for waker in waiting.into_values() {
      waker.wake();
    }
  }
}

/// A connection's entry in its group, removed when the connection ends.
struct Member<'group> {
  group: &'group ConnGroup,
  id: u64,
}

impl<'group> Member<'group> {
  fn new(group: &'group ConnGroup) -> Self {
    let id = group.next_id.get();
    group.next_id.set(id.wrapping_add(1));
    Self { group, id }
  }
}

impl Drop for Member<'_> {
  fn drop(&mut self) {
    let _waker = self.group.waiting.borrow_mut().remove(&self.id);
  }
}

/// Serves one connection until it closes. `Ok` when it ended normally: its peer closed it, a
/// response closed it, or its server is shutting down. An error for which [`peer_gone`] holds is
/// a normal close too, which the caller doesn't report.
pub(crate) async fn drive_conn<S, V>(
  stream: &mut S,
  service: &mut V,
  params: &DriveParams,
  group: Option<&ConnGroup>,
) -> crate::Result<()>
where
  S: StreamReader + StreamWriter,
  V: Http1Service,
{
  let _open = OpenConn::new();
  let mut driver = Driver {
    answered: 0,
    conn: Http1Conn::new(&params.hrc),
    deadline: params.first_head.map(Sleep::new).transpose()?,
    max_delay: params.max_delay,
    midreq: false,
    offset: 0,
    peer_eof: false,
    queued: 0,
    reads_async: false,
    res: Http1Res::new(bytes_pool_take()),
    rx: VectorUsize::new(),
    spare: bytes_pool_take(),
    wire: Vec::new(),
  };
  let member = group.map(Member::new);
  let rslt = driver.run(stream, service, member.as_ref()).await;
  rx_pool_give(mem::take(&mut driver.rx));
  bytes_pool_give(mem::take(&mut driver.spare));
  bytes_pool_give(driver.res.take_body());
  rslt
}

struct Driver {
  /// Requests answered in the current round.
  answered: usize,
  conn: Http1Conn,
  /// Until the first request is ready: when the connection's time for it is over.
  deadline: Option<Sleep>,
  max_delay: Duration,
  /// Bytes arrived and no response went out since: probably the middle of a request.
  midreq: bool,
  /// How much of `rx` was fed.
  offset: usize,
  /// The peer is done sending (or its server is going away): what was received is answered and
  /// then the connection closes.
  peer_eof: bool,
  /// Bytes of response queued in the core since the last flush.
  queued: usize,
  /// The stream's reads are awaited (it can't read without waiting).
  reads_async: bool,
  res: Http1Res,
  rx: VectorUsize<u8>,
  /// Buffer swapped into the core when its output is taken.
  spare: Vec<u8>,
  /// Output taken out of the core to splice headers into responses, ahead of what the core still
  /// holds.
  wire: Vec<u8>,
}

impl Driver {
  async fn run<S, V>(
    &mut self,
    stream: &mut S,
    service: &mut V,
    member: Option<&Member<'_>>,
  ) -> crate::Result<()>
  where
    S: StreamReader + StreamWriter,
    V: Http1Service,
  {
    loop {
      if !self.reads_async
        && self.rx.capacity() == 0
        && let Some(buffer) = rx_pool_take()
      {
        self.rx = buffer;
      }
      if self.read_available(stream, member).await? {
        self.peer_eof = true;
      }
      let got = !self.rx.is_empty();
      self.answered = 0;
      loop {
        let done = self.process(stream, service).await?;
        // Whatever the requests produced leaves before anything waits for more input.
        self.flush(stream).await?;
        if self.conn.wants_close() {
          return Ok(());
        }
        if done {
          break;
        }
      }
      if got {
        self.midreq = self.answered == 0;
      }
      // Also when the end of the input was seen while a response was delayed.
      if self.peer_eof {
        return Ok(());
      }
      if self.rx.is_empty() && !self.reads_async {
        rx_pool_give(mem::take(&mut self.rx));
      }
      if self.wait(stream, member).await? {
        return Ok(());
      }
    }
  }

  /// Reads until the stream would block. Returns whether the connection should end: the peer
  /// closed it, or, for a stream that reads only by awaiting, its server is shutting down while
  /// it waits between requests.
  async fn read_available<S>(
    &mut self,
    stream: &mut S,
    member: Option<&Member<'_>>,
  ) -> crate::Result<bool>
  where
    S: StreamReader,
  {
    loop {
      if self.rx.len() >= RX_MAX {
        return Ok(false);
      }
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
          self.reads_async = true;
          if !self.rx.is_empty() {
            return Ok(false);
          }
          // The read would wait for as long as the connection is idle: it waits for input here
          // instead, which the server's shutdown can cut short.
          if self.ready(stream, member).await? {
            return Ok(true);
          }
          // Nothing is waiting to be sent: every round ends with a flush.
          let (init, uninit) = self.rx.split_at_spare_mut();
          let init_len = init.len();
          let read = stream.read(uninit.into());
          let rslt = match &mut self.deadline {
            None => read.await,
            Some(deadline) => before(read, deadline).await,
          };
          let Some(len) = rslt? else {
            return Ok(true);
          };
          // SAFETY: `read` initialized `len` bytes of the spare capacity
          unsafe {
            self.rx.set_len(init_len.wrapping_add(len.get()));
          }
          return Ok(false);
        }
      }
    }
  }

  /// Feeds what was received to the core and answers every request it completes. Returns `false`
  /// when it stopped early to let the queued responses out.
  async fn process<S, V>(&mut self, stream: &mut S, service: &mut V) -> crate::Result<bool>
  where
    S: StreamReader + StreamWriter,
    V: Http1Service,
  {
    loop {
      let rest = self.rx.get(self.offset..).unwrap_or_default();
      let consumed = self.conn.feed(rest)?;
      self.offset = self.offset.wrapping_add(consumed);
      let before = self.answered;
      loop {
        match self.conn.poll_event() {
          Http1Event::RequestReady => {
            self.answer(stream, service).await?;
            if self.queued >= OUT_HIGH_WATER {
              return Ok(false);
            }
          }
          Http1Event::NeedMore | Http1Event::Closed => break,
        }
      }
      if self.offset >= self.rx.len() {
        self.rx.clear();
        self.offset = 0;
        return Ok(true);
      }
      // Input is left, the core took none of it and nothing it holds can be answered.
      if consumed == 0 && self.answered == before {
        return Err(crate::Error::ClosedHttpConnection);
      }
    }
  }

  /// Runs the handler of the request that is ready and queues its response in the core.
  ///
  /// A response with a delay waits for it here, before it is queued: what was answered earlier
  /// leaves first and nothing of this response is sent before the delay is over. Only this
  /// connection's future waits, the thread keeps running the others, and its socket is watched
  /// meanwhile (see [`Self::sleep_watching`]).
  async fn answer<S, V>(&mut self, stream: &mut S, service: &mut V) -> crate::Result<()>
  where
    S: StreamReader + StreamWriter,
    V: Http1Service,
  {
    self.answered = self.answered.wrapping_add(1);
    // The first request is here: its deadline is over, and its timer cancelled.
    self.deadline = None;
    self.res.reset();
    match self.conn.request() {
      Some(head) => service.call(head, self.conn.body(), &mut self.res),
      None => self.res.set_status(crate::http::StatusCode::InternalServerError),
    }
    if let Some(delay) = self.res.delay()
      && !delay.is_zero()
    {
      self.flush(stream).await?;
      self.sleep_watching(stream, delay.min(self.max_delay)).await?;
    }
    if self.res.extra_headers().is_empty() {
      self.conn.respond(self.res.status(), self.res.content_type(), self.res.body());
      self.queued = self.queued.wrapping_add(self.res.body().len()).wrapping_add(128);
      return Ok(());
    }
    // The core writes no header but its own: this response is taken out as soon as it is queued
    // and the headers are put after its status line.
    self.pull_core();
    // What `wire` already holds was counted when it was queued.
    let before = self.wire.len();
    self.conn.respond(self.res.status(), self.res.content_type(), self.res.body());
    if let Ok(taken) = self.conn.take_output(mem::take(&mut self.spare)) {
      let line_end =
        taken.windows(2).position(|el| el == b"\r\n").map_or(0, |at| at.wrapping_add(2));
      self.wire.extend_from_slice(taken.get(..line_end).unwrap_or_default());
      self.wire.extend_from_slice(self.res.extra_headers());
      self.wire.extend_from_slice(taken.get(line_end..).unwrap_or_default());
      self.conn.advance_output(taken.len());
      self.spare = taken;
    }
    self.queued = self.queued.wrapping_add(self.wire.len().wrapping_sub(before));
    Ok(())
  }

  /// Waits for `delay` while watching the socket. What arrives is appended to `rx`, to be fed
  /// after the delayed response, in order. A peer that resets the connection (any read error)
  /// ends it at once: the timer is cancelled with the connection's future, and the connection's
  /// slot, buffers and count are released instead of being held for the rest of the delay. A peer
  /// that only half-closes it is done sending, not reading: the socket is no longer watched, the
  /// delay runs out, and the delayed response and those of the complete requests received before
  /// leave before the connection closes.
  ///
  /// A stream that reads only by awaiting (TLS) is not watched: its reads can't be stopped in the
  /// middle of a record, so one that arrives in pieces (or a KeyUpdate, after which the read waits
  /// for data) would hold the response back for as long as the peer likes. Its delayed response
  /// leaves on time, and a peer that went away meanwhile is noticed after it; the server's
  /// maximum delay bounds how long such a connection is held.
  async fn sleep_watching<S>(&mut self, stream: &mut S, delay: Duration) -> crate::Result<()>
  where
    S: StreamReader,
  {
    let mut sleep = Sleep::new(delay)?;
    loop {
      // Not watched (see above), nothing more to come, or enough is waiting to be fed: the peer
      // is slowed down by TCP until the response is out.
      if self.reads_async || self.peer_eof || self.rx.len() >= RX_MAX {
        return (&mut sleep).await;
      }
      let readable = {
        let mut readable = pin!(stream.readable());
        poll_fn(|cx| {
          if let Poll::Ready(rslt) = Pin::new(&mut sleep).poll(cx) {
            return Poll::Ready(rslt.map(|()| false));
          }
          readable.as_mut().poll(cx).map(|rslt| rslt.map(|()| true))
        })
        .await?
      };
      if !readable {
        return Ok(());
      }
      if self.read_available(stream, None).await? {
        self.peer_eof = true;
      }
    }
  }

  /// Moves what the core holds to the end of `wire`.
  fn pull_core(&mut self) {
    if let Ok(taken) = self.conn.take_output(mem::take(&mut self.spare)) {
      self.wire.extend_from_slice(&taken);
      self.conn.advance_output(taken.len());
      self.spare = taken;
    }
  }

  /// Writes everything the core queued.
  async fn flush<S>(&mut self, stream: &mut S) -> crate::Result<()>
  where
    S: StreamWriter,
  {
    self.queued = 0;
    if !self.wire.is_empty() {
      self.pull_core();
      return send(stream, &mut self.wire).await;
    }
    match self.conn.take_output(mem::take(&mut self.spare)) {
      Ok(mut bytes) => {
        let len = bytes.len();
        send(stream, &mut bytes).await?;
        self.conn.advance_output(len);
        self.spare = bytes;
      }
      Err(spare) => self.spare = spare,
    }
    Ok(())
  }

  /// Waits for bytes to read. Returns whether the connection should end instead: its server is
  /// shutting down and it is between requests.
  ///
  /// A stream that reads only by awaiting waits in [`Self::read_available`], which calls
  /// [`Self::ready`] before its read.
  async fn wait<S>(&mut self, stream: &mut S, member: Option<&Member<'_>>) -> crate::Result<bool>
  where
    S: StreamReader,
  {
    let idle = !self.midreq;
    if idle && member.is_some_and(|el| el.group.going_away.get()) {
      return Ok(true);
    }
    if self.reads_async {
      return Ok(false);
    }
    self.ready(stream, member).await
  }

  /// Waits until the stream has something to report: bytes, the end of the stream or an error.
  /// Returns `true` instead when the connection should end: its server is shutting down and it
  /// is between requests. Fails once the first-head deadline is over.
  async fn ready<S>(&mut self, stream: &mut S, member: Option<&Member<'_>>) -> crate::Result<bool>
  where
    S: StreamReader,
  {
    let idle = !self.midreq;
    let going_away = || member.is_some_and(|el| el.group.going_away.get());
    let deadline = &mut self.deadline;
    let mut readable = pin!(stream.readable());
    poll_fn(|cx| {
      if let Some(member) = member
        && idle
      {
        let mut waiting = member.group.waiting.borrow_mut();
        let replace = waiting.get(&member.id).is_none_or(|el| !el.will_wake(cx.waker()));
        if replace {
          let _prev = waiting.insert(member.id, cx.waker().clone());
        }
      }
      if idle && going_away() {
        return Poll::Ready(Ok(true));
      }
      if let Some(elem) = deadline
        && let Poll::Ready(rslt) = Pin::new(elem).poll(cx)
      {
        return Poll::Ready(rslt.and(Err(crate::Error::ExpiredFuture)));
      }
      readable.as_mut().poll(cx).map(|rslt| rslt.map(|()| false))
    })
    .await
  }
}

/// Hands `bytes` to the stream, which may keep them and give back an empty buffer.
async fn send<S>(stream: &mut S, bytes: &mut Vec<u8>) -> crate::Result<()>
where
  S: StreamWriter,
{
  if !stream.try_send_owned(bytes)? {
    stream.write_all(bytes).await?;
    bytes.clear();
  }
  Ok(())
}

/// `fut`'s output, or [`crate::Error::ExpiredFuture`] once `deadline` is over.
async fn before<T>(
  fut: impl Future<Output = crate::Result<T>>,
  deadline: &mut Sleep,
) -> crate::Result<T> {
  let mut fut = pin!(fut);
  poll_fn(|cx| {
    if let Poll::Ready(elem) = fut.as_mut().poll(cx) {
      return Poll::Ready(elem);
    }
    Pin::new(&mut *deadline).poll(cx).map(|elem| elem.and(Err(crate::Error::ExpiredFuture)))
  })
  .await
}

/// If the error only says the peer is gone, or that the runtime or the server gave up on a quiet
/// or slow connection: a normal close, not reported.
pub(crate) fn peer_gone(err: &crate::Error) -> bool {
  use std::io::ErrorKind;
  match err {
    crate::Error::Io(elem) => matches!(
      elem.kind(),
      ErrorKind::BrokenPipe
        | ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::NotConnected
        | ErrorKind::TimedOut
        | ErrorKind::UnexpectedEof
    ),
    // Closed in the middle of a TLS record or handshake, or a handshake the peer ended with an
    // alert (a client that doesn't trust the certificate, say).
    crate::Error::Net(NetError::AbruptDisconnect)
    | crate::Error::Tls(TlsError::AbruptDisconnect | TlsError::AbortedHandshake(_)) => true,
    // The handshake timeout, the server's own version of the runtime's `TimedOut`.
    crate::Error::ExpiredFuture => true,
    _ => false,
  }
}

/// Buffers released on this thread, most recent last, so the next connection uses ones that are
/// still in cache. Buffers above `POOL_BUFFER_MAX` are freed.
const POOL_MAX: usize = 64;
const POOL_BUFFER_MAX: usize = 1 << 20;

std::thread_local! {
  static BYTES_POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
  /// Connections the driver serves on this thread.
  static OPEN_CONNS: Cell<usize> = const { Cell::new(0) };
  static RX_POOL: RefCell<Vec<VectorUsize<u8>>> = const { RefCell::new(Vec::new()) };
}

/// Counts a connection as open on this thread; the last one to end empties the thread's pools,
/// which after a burst would only hold its largest buffers.
struct OpenConn;

impl OpenConn {
  fn new() -> Self {
    OPEN_CONNS.set(OPEN_CONNS.get().wrapping_add(1));
    Self
  }
}

impl Drop for OpenConn {
  fn drop(&mut self) {
    let open = OPEN_CONNS.get().saturating_sub(1);
    OPEN_CONNS.set(open);
    if open == 0 {
      BYTES_POOL.with(|pool| pool.borrow_mut().clear());
      RX_POOL.with(|pool| pool.borrow_mut().clear());
    }
  }
}

fn bytes_pool_take() -> Vec<u8> {
  BYTES_POOL.with(|pool| pool.borrow_mut().pop()).unwrap_or_default()
}

fn bytes_pool_give(mut buffer: Vec<u8>) {
  let capacity = buffer.capacity();
  if capacity == 0 || capacity > POOL_BUFFER_MAX {
    return;
  }
  buffer.clear();
  BYTES_POOL.with(|pool| {
    let mut pool = pool.borrow_mut();
    if pool.len() < POOL_MAX {
      pool.push(buffer);
    }
  });
}

fn rx_pool_take() -> Option<VectorUsize<u8>> {
  RX_POOL.with(|pool| pool.borrow_mut().pop())
}

fn rx_pool_give(mut buffer: VectorUsize<u8>) {
  let capacity = buffer.capacity();
  if capacity == 0 || capacity > POOL_BUFFER_MAX {
    return;
  }
  buffer.clear();
  RX_POOL.with(|pool| {
    let mut pool = pool.borrow_mut();
    if pool.len() < POOL_MAX {
      pool.push(buffer);
    }
  });
}

#[cfg(test)]
mod tests {
  use crate::{
    collections::MaybeUninitSlice,
    executor::StdRuntime,
    http::{
      HttpRecvParams,
      http1_server_framework::{
        Http1Res,
        conn_driver::{DriveParams, Http1Service, drive_conn},
      },
    },
    http1::Http1Request,
    net::{StreamCommon, StreamReader, StreamWriter, TryRead},
  };
  use alloc::vec::Vec;
  use core::{num::NonZeroUsize, time::Duration};

  /// Gives its input at once, then reports the end of the stream; counts the writes.
  struct Scripted {
    input: Vec<u8>,
    output: Vec<u8>,
    writes: usize,
  }

  impl StreamCommon for Scripted {}

  impl StreamReader for Scripted {
    async fn read(&mut self, _: MaybeUninitSlice<'_, u8>) -> crate::Result<Option<NonZeroUsize>> {
      Ok(None)
    }

    fn try_read(&mut self, mut bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<TryRead> {
      let dst = bytes.initialize_all_bytes();
      let len = dst.len().min(self.input.len());
      let Some(len) = NonZeroUsize::new(len) else {
        return Ok(TryRead::Closed);
      };
      dst[..len.get()].copy_from_slice(&self.input[..len.get()]);
      let _ = self.input.drain(..len.get());
      Ok(TryRead::Read(len))
    }
  }

  impl StreamWriter for Scripted {
    async fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
      self.writes += 1;
      self.output.extend_from_slice(bytes);
      Ok(())
    }

    async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<()> {
      self.writes += 1;
      for elem in bytes {
        self.output.extend_from_slice(elem);
      }
      Ok(())
    }
  }

  /// Answers `pong` with one extra header.
  struct WithHeader;

  impl Http1Service for WithHeader {
    fn call(&mut self, _: Http1Request<'_>, _: &[u8], res: &mut Http1Res) {
      res.push_header("server", "rimu-ws").unwrap();
      res.body_mut().extend_from_slice(b"pong");
    }
  }

  // A batch of small pipelined responses with an extra header is far below the high-water mark
  // and leaves in one write: each response counts its own bytes, not everything spliced so far.
  #[test]
  fn extra_headers_count_their_own_bytes() {
    let count = 300;
    let mut input = Vec::new();
    for _ in 0..count {
      input.extend_from_slice(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n");
    }
    let mut stream = Scripted { input, output: Vec::new(), writes: 0 };
    let params = DriveParams {
      first_head: None,
      hrc: HttpRecvParams::with_default_params(),
      max_delay: Duration::from_secs(10),
    };
    StdRuntime::new().block_on(drive_conn(&mut stream, &mut WithHeader, &params, None)).unwrap();
    let answered = stream.output.windows(4).filter(|el| el == b"pong").count();
    assert_eq!(answered, count);
    assert!(stream.output.len() < 64 * 1024, "{}", stream.output.len());
    assert_eq!(stream.writes, 1, "{} bytes in {} writes", stream.output.len(), stream.writes);
  }
}
