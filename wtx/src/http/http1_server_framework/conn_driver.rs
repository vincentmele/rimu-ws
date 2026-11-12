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
//! 4. While a response is delayed the socket is still watched: a peer that goes away ends the
//!    connection at once. A plaintext one is read meanwhile, and what arrives is kept for after the
//!    response; a TLS one is not read, only watched for the end of its input.
//! 5. A connection with a first-head deadline (TLS) races it in every wait until the head of its
//!    first request is parsed.

use crate::{
  collections::VectorUsize,
  futures::Sleep,
  http::{HttpRecvParams, http1_server_framework::Http1Res},
  http1::{Http1Conn, Http1ConnParts, Http1Event, Http1Request},
  net::{NetError, StreamReader, StreamWriter, TryRead},
  tls::TlsError,
};
use alloc::vec::Vec;
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
///
/// Its members have slots, which the next members reuse: once it has held as many connections
/// at once, joining and leaving it allocate nothing.
#[derive(Debug, Default)]
pub(crate) struct ConnGroup {
  /// Slots of `waiting` no member has.
  free: RefCell<Vec<usize>>,
  going_away: Cell<bool>,
  /// By slot, the connections waiting for a request, to be woken when the group goes away.
  waiting: RefCell<Vec<Option<Waker>>>,
}

impl ConnGroup {
  /// The server is shutting down: connections between requests close, and those in the middle of
  /// one close after answering it.
  pub(crate) fn go_away(&self) {
    self.going_away.set(true);
    let mut slot = 0;
    loop {
      // Not borrowed while it wakes: a waker may reach the group.
      let waker = {
        let mut waiting = self.waiting.borrow_mut();
        let Some(elem) = waiting.get_mut(slot) else {
          break;
        };
        elem.take()
      };
      if let Some(elem) = waker {
        elem.wake();
      }
      slot = slot.wrapping_add(1);
    }
  }
}

/// A connection's slot in its group, freed when the connection ends.
struct Member<'group> {
  group: &'group ConnGroup,
  slot: usize,
}

impl<'group> Member<'group> {
  fn new(group: &'group ConnGroup) -> Self {
    let slot = group.free.borrow_mut().pop().unwrap_or_else(|| {
      let mut waiting = group.waiting.borrow_mut();
      waiting.push(None);
      waiting.len().wrapping_sub(1)
    });
    Self { group, slot }
  }

  /// Has `waker` woken when the group goes away.
  fn register(&self, waker: &Waker) {
    let mut waiting = self.group.waiting.borrow_mut();
    if let Some(elem) = waiting.get_mut(self.slot)
      && elem.as_ref().is_none_or(|el| !el.will_wake(waker))
    {
      *elem = Some(waker.clone());
    }
  }
}

impl Drop for Member<'_> {
  fn drop(&mut self) {
    let _waker = self.group.waiting.borrow_mut().get_mut(self.slot).and_then(Option::take);
    self.group.free.borrow_mut().push(self.slot);
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
  // Declared first, dropped last: the driver's buffers are in the pools by then.
  let _open = OpenConn::new();
  let deadline = params.first_head.map(Sleep::new).transpose()?;
  let buffers = conn_pool_take();
  let mut driver = Driver {
    answered: 0,
    conn: Http1Conn::from_parts(&params.hrc, buffers.core),
    deadline,
    max_delay: params.max_delay,
    midreq: false,
    offset: 0,
    peer_closed: false,
    peer_eof: false,
    queued: 0,
    reads_async: false,
    res: Http1Res::new(buffers.res_body, buffers.res_headers),
    rx: VectorUsize::new(),
    spare: buffers.spare,
    wire: buffers.wire,
  };
  let member = group.map(Member::new);
  driver.run(stream, service, member.as_ref()).await
}

struct Driver {
  /// Requests answered in the current round.
  answered: usize,
  conn: Http1Conn,
  /// Until the head of the first request is parsed: when the connection's time for it is over.
  deadline: Option<Sleep>,
  max_delay: Duration,
  /// Bytes arrived and no response went out since: probably the middle of a request.
  midreq: bool,
  /// How much of `rx` was fed.
  offset: usize,
  /// The peer ended its input (not the server going away): a request body it left incomplete
  /// is answered with a 400 before the connection closes.
  peer_closed: bool,
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

/// The buffers go back to the thread's pools, also when the connection's future is dropped
/// before its end.
impl Drop for Driver {
  fn drop(&mut self) {
    rx_pool_give(mem::take(&mut self.rx));
    let conn = mem::replace(&mut self.conn, Http1Conn::new(&HttpRecvParams::with_default_params()));
    let (res_body, res_headers) = self.res.take_parts();
    conn_pool_give(ConnBuffers {
      core: conn.into_parts(),
      res_body,
      res_headers,
      spare: mem::take(&mut self.spare),
      wire: mem::take(&mut self.wire),
    });
  }
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
        // A body cut short by the end of the input is answered, as Envoy does, instead of being
        // dropped without a word.
        if self.peer_closed && self.conn.end_of_input() {
          self.flush(stream).await?;
        }
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
        TryRead::Closed => {
          self.peer_closed = true;
          return Ok(true);
        }
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
            self.peer_closed = true;
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
      // A head is in, its body perhaps not: the first-head deadline is over.
      if self.deadline.is_some() && !self.conn.awaits_head() {
        self.deadline = None;
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
    // The first request is here: the first-head deadline is over, and its timer cancelled.
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
    match self.conn.take_output(mem::take(&mut self.spare)) {
      Ok(taken) => {
        let line_end =
          taken.windows(2).position(|el| el == b"\r\n").map_or(0, |at| at.wrapping_add(2));
        self.wire.extend_from_slice(taken.get(..line_end).unwrap_or_default());
        self.wire.extend_from_slice(self.res.extra_headers());
        self.wire.extend_from_slice(taken.get(line_end..).unwrap_or_default());
        self.conn.advance_output(taken.len());
        self.spare = taken;
      }
      Err(spare) => self.spare = spare,
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
  /// A stream that reads only by awaiting (TLS) is not read: its reads can't be stopped in the
  /// middle of a record, so one that arrives in pieces (or a KeyUpdate, after which the read waits
  /// for data) would hold the response back for as long as the peer likes. It is watched for the
  /// end of its input instead ([`StreamReader::peer_ended`]), which reads nothing: a reset ends the
  /// connection at once, as above, and a half-close is let be, the delayed response leaving on
  /// time and what was sent before being read after it.
  async fn sleep_watching<S>(&mut self, stream: &mut S, delay: Duration) -> crate::Result<()>
  where
    S: StreamReader,
  {
    let mut sleep = Sleep::new(delay)?;
    if self.reads_async && !self.peer_eof {
      let ended = {
        let mut ended = pin!(stream.peer_ended());
        poll_fn(|cx| {
          if let Poll::Ready(rslt) = Pin::new(&mut sleep).poll(cx) {
            return Poll::Ready(rslt.map(|()| false));
          }
          ended.as_mut().poll(cx).map(|rslt| rslt.map(|()| true))
        })
        .await?
      };
      if !ended {
        return Ok(());
      }
    }
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

  /// Moves what the core holds to the end of `wire`. The spare buffer comes back either way:
  /// dropped, the core's next output would grow a new one from nothing.
  fn pull_core(&mut self) {
    match self.conn.take_output(mem::take(&mut self.spare)) {
      Ok(taken) => {
        self.wire.extend_from_slice(&taken);
        self.conn.advance_output(taken.len());
        self.spare = taken;
      }
      Err(spare) => self.spare = spare,
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
        member.register(cx.waker());
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
    // Closed in the middle of a TLS record or handshake. A client that rejects the certificate
    // is not among these: its alert fails the handshake as a `TlsErrorReply`, which is reported.
    crate::Error::Net(NetError::AbruptDisconnect)
    | crate::Error::Tls(TlsError::AbruptDisconnect) => true,
    // The handshake timeout, the server's own version of the runtime's `TimedOut`.
    crate::Error::ExpiredFuture => true,
    _ => false,
  }
}

/// Buffers released on this thread, most recent last, so the next connection uses ones that are
/// still in cache. A pool holds at most `POOL_MAX` entries, and buffers above `POOL_BUFFER_MAX`
/// are freed, not kept.
const POOL_MAX: usize = 64;
const POOL_BUFFER_MAX: usize = 1 << 20;
/// Bytes the connection pool of a thread holds at most, and its read buffer pool: a set of buffers
/// (or a buffer) that would go past it is freed.
const CONN_POOL_BYTES_MAX: usize = 16 << 20;
const RX_POOL_BYTES_MAX: usize = 16 << 20;
/// Entries a pool keeps once its thread has no connection open: the most recent, enough for
/// connections that come one after the other, and of at most `POOL_IDLE_BYTES` in all. The others,
/// which after a burst would only hold its largest buffers, are freed.
const POOL_IDLE_KEEP: usize = 4;
const POOL_IDLE_BYTES: usize = 2 << 20;

std::thread_local! {
  static CONN_POOL: RefCell<ConnPool> =
    const { RefCell::new(ConnPool { bytes: 0, sets: Vec::new() }) };
  /// Connections the driver serves on this thread.
  static OPEN_CONNS: Cell<usize> = const { Cell::new(0) };
  static RX_POOL: RefCell<RxPool> = const { RefCell::new(RxPool { bytes: 0, buffers: Vec::new() }) };
}

/// The buffers of a connection but its read buffer (which goes back to [`RX_POOL`] whenever it is
/// empty): taken from [`CONN_POOL`] when the connection opens, given back when it ends.
#[derive(Debug, Default)]
struct ConnBuffers {
  core: Http1ConnParts,
  res_body: Vec<u8>,
  res_headers: Vec<u8>,
  spare: Vec<u8>,
  wire: Vec<u8>,
}

impl ConnBuffers {
  fn capacity(&self) -> usize {
    [&self.res_body, &self.res_headers, &self.spare, &self.wire]
      .iter()
      .fold(self.core.capacity(), |acc, el| acc.saturating_add(el.capacity()))
  }
}

/// The sets of buffers of the thread's ended connections.
#[derive(Debug)]
struct ConnPool {
  /// Their capacity.
  bytes: usize,
  sets: Vec<ConnBuffers>,
}

/// The read buffers of the thread's ended connections.
#[derive(Debug)]
struct RxPool {
  /// Their capacity.
  bytes: usize,
  buffers: Vec<VectorUsize<u8>>,
}

/// How many of the newest of `sizes` (oldest first) to keep: at most `POOL_IDLE_KEEP`, of at
/// most `POOL_IDLE_BYTES` in all.
fn idle_keep(sizes: impl DoubleEndedIterator<Item = usize>) -> usize {
  let mut total = 0usize;
  let mut kept = 0usize;
  for size in sizes.rev() {
    total = total.saturating_add(size);
    if kept == POOL_IDLE_KEEP || total > POOL_IDLE_BYTES {
      break;
    }
    kept = kept.wrapping_add(1);
  }
  kept
}

/// Counts a connection as open on this thread; the last one to end trims the thread's pools to
/// their most recent entries (see [`POOL_IDLE_KEEP`]).
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
      let _rslt = CONN_POOL.try_with(|pool| {
        let mut pool = pool.borrow_mut();
        let keep = idle_keep(pool.sets.iter().map(ConnBuffers::capacity));
        let excess = pool.sets.len().wrapping_sub(keep);
        let freed =
          pool.sets.drain(..excess).fold(0usize, |acc, el| acc.wrapping_add(el.capacity()));
        pool.bytes = pool.bytes.saturating_sub(freed);
      });
      let _rslt = RX_POOL.try_with(|pool| {
        let mut pool = pool.borrow_mut();
        let keep = idle_keep(pool.buffers.iter().map(VectorUsize::capacity));
        let excess = pool.buffers.len().wrapping_sub(keep);
        let freed =
          pool.buffers.drain(..excess).fold(0usize, |acc, el| acc.wrapping_add(el.capacity()));
        pool.bytes = pool.bytes.saturating_sub(freed);
      });
    }
  }
}

/// The buffers of an ended connection, or new empty ones.
fn conn_pool_take() -> ConnBuffers {
  CONN_POOL
    .try_with(|pool| {
      let mut pool = pool.borrow_mut();
      let set = pool.sets.pop()?;
      pool.bytes = pool.bytes.saturating_sub(set.capacity());
      Some(set)
    })
    .ok()
    .flatten()
    .unwrap_or_default()
}

/// Keeps the buffers of an ended connection for the next one, emptied, those above
/// `POOL_BUFFER_MAX` freed.
fn conn_pool_give(mut set: ConnBuffers) {
  set.core.free_larger_than(POOL_BUFFER_MAX);
  set.core.clear();
  for buffer in [&mut set.res_body, &mut set.res_headers, &mut set.spare, &mut set.wire] {
    if buffer.capacity() > POOL_BUFFER_MAX {
      *buffer = Vec::new();
    }
    buffer.clear();
  }
  let capacity = set.capacity();
  if capacity == 0 {
    return;
  }
  // During the thread's teardown, without the pool, the set is freed.
  let _rslt = CONN_POOL.try_with(|pool| {
    let mut pool = pool.borrow_mut();
    if pool.sets.len() < POOL_MAX && pool.bytes.saturating_add(capacity) <= CONN_POOL_BYTES_MAX {
      pool.bytes = pool.bytes.wrapping_add(capacity);
      pool.sets.push(set);
    }
  });
}

fn rx_pool_take() -> Option<VectorUsize<u8>> {
  RX_POOL
    .try_with(|pool| {
      let mut pool = pool.borrow_mut();
      let buffer = pool.buffers.pop()?;
      pool.bytes = pool.bytes.saturating_sub(buffer.capacity());
      Some(buffer)
    })
    .ok()
    .flatten()
}

fn rx_pool_give(mut buffer: VectorUsize<u8>) {
  let capacity = buffer.capacity();
  if capacity == 0 || capacity > POOL_BUFFER_MAX {
    return;
  }
  buffer.clear();
  let _rslt = RX_POOL.try_with(|pool| {
    let mut pool = pool.borrow_mut();
    if pool.buffers.len() < POOL_MAX && pool.bytes.saturating_add(capacity) <= RX_POOL_BYTES_MAX {
      pool.bytes = pool.bytes.wrapping_add(capacity);
      pool.buffers.push(buffer);
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

  /// Answers with the request's body, or `pong`, with one extra header.
  struct EchoWithHeader;

  impl Http1Service for EchoWithHeader {
    fn call(&mut self, head: Http1Request<'_>, body: &[u8], res: &mut Http1Res) {
      res.push_header("server", "rimu-ws").unwrap();
      if head.path == "/echo" {
        res.body_mut().extend_from_slice(body);
      } else {
        res.body_mut().extend_from_slice(b"pong");
      }
    }
  }

  /// A connection's input: a GET, a 4 KiB POST, a chunked one and a pipelined pair.
  fn churn_input() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n");
    out.extend_from_slice(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 4096\r\n\r\n");
    out.extend(core::iter::repeat_n(b'e', 4096));
    out.extend_from_slice(
      b"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    );
    out.extend_from_slice(
      b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\nGET /ping HTTP/1.1\r\nHost: x\r\n\r\n",
    );
    out
  }

  // After a warm-up, a connection that opens, sends its requests and closes allocates nothing in
  // the driver, the core or the response: their buffers come from the thread's pool and go back
  // to it. The streams (and their output) are made before counting.
  #[test]
  fn connection_churn_allocates_nothing() {
    use crate::{sync::AtomicU64, tests::_count_allocations_in};
    use core::sync::atomic::Ordering;
    static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
    let (warm, counted) = (10, 50);
    let input = churn_input();
    let mut streams: Vec<Scripted> = (0..warm + counted)
      .map(|_| Scripted { input: input.clone(), output: Vec::with_capacity(64 * 1024), writes: 0 })
      .collect();
    let params = DriveParams {
      first_head: None,
      hrc: HttpRecvParams::with_default_params(),
      max_delay: Duration::from_secs(10),
    };
    let (warm_streams, counted_streams) = streams.split_at_mut(warm);
    let allocations = StdRuntime::new().block_on(async {
      for stream in warm_streams.iter_mut() {
        drive_conn(stream, &mut EchoWithHeader, &params, None).await.unwrap();
      }
      _count_allocations_in(&ALLOCATIONS);
      let before = ALLOCATIONS.load(Ordering::SeqCst);
      for stream in counted_streams.iter_mut() {
        drive_conn(stream, &mut EchoWithHeader, &params, None).await.unwrap();
      }
      ALLOCATIONS.load(Ordering::SeqCst) - before
    });
    assert_eq!(allocations, 0, "allocations of {counted} connections");
    for stream in &streams {
      let answered = stream.output.windows(14).filter(|el| el == b"server: rimu-w").count();
      assert_eq!(answered, 5);
    }
  }

  // Connections that join a group, wait in it and leave it allocate nothing once the group has
  // held as many at once.
  #[test]
  fn group_membership_allocates_nothing() {
    use crate::{
      http::http1_server_framework::conn_driver::{ConnGroup, Member},
      sync::AtomicU64,
      tests::_count_allocations_in,
    };
    use core::{sync::atomic::Ordering, task::Waker};
    static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
    let group = ConnGroup::default();
    let round = |count: usize| {
      let members: [Option<Member<'_>>; 16] =
        core::array::from_fn(|idx| (idx < count).then(|| Member::new(&group)));
      for member in members.iter().flatten() {
        member.register(Waker::noop());
      }
    };
    for count in 1..=16 {
      round(count);
    }
    _count_allocations_in(&ALLOCATIONS);
    let before = ALLOCATIONS.load(Ordering::SeqCst);
    for count in (1..=16).chain((1..=16).rev()) {
      round(count);
    }
    let after = ALLOCATIONS.load(Ordering::SeqCst);
    assert_eq!(after - before, 0, "allocations of 32 rounds of members");
    group.go_away();
    assert!(group.going_away.get());
  }

  /// Gives its input once, then never anything again; never takes a write.
  struct Stuck {
    input: Vec<u8>,
  }

  impl StreamCommon for Stuck {}

  impl StreamReader for Stuck {
    async fn read(&mut self, _: MaybeUninitSlice<'_, u8>) -> crate::Result<Option<NonZeroUsize>> {
      core::future::pending().await
    }

    fn try_read(&mut self, mut bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<TryRead> {
      let dst = bytes.initialize_all_bytes();
      let len = dst.len().min(self.input.len());
      let Some(len) = NonZeroUsize::new(len) else {
        return Ok(TryRead::Pending);
      };
      dst[..len.get()].copy_from_slice(&self.input[..len.get()]);
      let _ = self.input.drain(..len.get());
      Ok(TryRead::Read(len))
    }

    fn readable(&mut self) -> impl Future<Output = crate::Result<()>> {
      core::future::pending()
    }
  }

  impl StreamWriter for Stuck {
    async fn write_all(&mut self, _: &[u8]) -> crate::Result<()> {
      core::future::pending().await
    }

    async fn write_all_vectored(&mut self, _: &[&[u8]]) -> crate::Result<()> {
      core::future::pending().await
    }
  }

  /// Delays `/slow` by 10 s, answers the rest with `pong`.
  struct Slow;

  impl Http1Service for Slow {
    fn call(&mut self, head: Http1Request<'_>, _: &[u8], res: &mut Http1Res) {
      if head.path == "/slow" {
        res.set_delay(Duration::from_secs(10));
      }
      res.body_mut().extend_from_slice(b"pong");
    }
  }

  // A connection whose future is dropped while it answers a request (its request view live)
  // gives its buffers back to the pool, and the next connection, served on them, sees nothing of
  // that request. Run under Miri too, for the view into the recycled input buffer.
  #[test]
  fn connection_dropped_mid_request_gives_its_buffers_back() {
    use super::CONN_POOL;
    use core::{
      pin::pin,
      task::{Context, Poll, Waker},
    };
    let params = DriveParams {
      first_head: None,
      hrc: HttpRecvParams::with_default_params(),
      max_delay: Duration::from_secs(10),
    };
    let mut cx = Context::from_waker(Waker::noop());
    let mut service = Slow;
    let pooled =
      || CONN_POOL.with(|el| el.borrow().sets.iter().map(|el| el.core.capacity()).sum::<usize>());
    let before = pooled();
    {
      let mut stream = Stuck { input: b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n".to_vec() };
      let fut = pin!(drive_conn(&mut stream, &mut service, &params, None));
      assert!(fut.poll(&mut cx).is_pending());
    }
    let after = pooled();
    assert!(after > before, "{before} {after}");
    let mut stream = Scripted {
      input: b"GET /ping HTTP/1.1\r\nHost: y\r\n\r\n".to_vec(),
      output: Vec::new(),
      writes: 0,
    };
    {
      let fut = pin!(drive_conn(&mut stream, &mut service, &params, None));
      assert!(matches!(fut.poll(&mut cx), Poll::Ready(Ok(()))));
    }
    assert!(stream.output.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(stream.output.ends_with(b"pong"));
    assert_eq!(stream.output.windows(4).filter(|el| el == b"pong").count(), 1);
  }

  // A member in a slot an earlier member freed is woken when the group goes away, and the
  // member that left is not: the slot holds the waker of whoever has it now.
  #[allow(clippy::disallowed_types, reason = "std's `Wake` takes std's `Arc`")]
  #[test]
  fn a_member_in_a_reused_slot_is_woken_by_go_away() {
    use crate::http::http1_server_framework::conn_driver::{ConnGroup, Member};
    use core::{sync::atomic::Ordering, task::Waker};
    use std::{sync::Arc, task::Wake};
    struct Count(crate::sync::AtomicUsize);
    impl Wake for Count {
      fn wake(self: Arc<Self>) {
        let _prev = self.0.fetch_add(1, Ordering::SeqCst);
      }
    }
    let count = || Arc::new(Count(crate::sync::AtomicUsize::new(0)));
    let (left, other, reused) = (count(), count(), count());
    let group = ConnGroup::default();
    let first = Member::new(&group);
    first.register(&Waker::from(left.clone()));
    let second = Member::new(&group);
    second.register(&Waker::from(other.clone()));
    let freed = first.slot;
    drop(first);
    let third = Member::new(&group);
    assert_eq!(third.slot, freed, "the freed slot was not reused");
    third.register(&Waker::from(reused.clone()));
    group.go_away();
    let woken = |el: &Arc<Count>| el.0.load(Ordering::SeqCst);
    assert_eq!((woken(&left), woken(&other), woken(&reused)), (0, 1, 1));
    drop((second, third));
  }

  // At idle the pools keep a few of their most recent entries and at most 2 MiB each: after a
  // burst of large transfers a quiet thread holds little. The read buffer pool is bounded in bytes
  // while busy too.
  #[test]
  fn idle_pools_keep_few_bytes() {
    use super::{
      ConnBuffers, OpenConn, POOL_IDLE_BYTES as IDLE_BYTES, RX_POOL, RX_POOL_BYTES_MAX as RX_BYTES,
      conn_pool_give, rx_pool_give,
    };
    use crate::collections::VectorUsize;
    let conn_pool = || super::CONN_POOL.with(|el| (el.borrow().sets.len(), el.borrow().bytes));
    let rx_pool = || {
      RX_POOL.with(|el| {
        let pool = el.borrow();
        let bytes = pool.buffers.iter().map(VectorUsize::capacity).sum::<usize>();
        assert_eq!(bytes, pool.bytes);
        (pool.buffers.len(), bytes)
      })
    };
    let open = OpenConn::new();
    for _ in 0..64 {
      conn_pool_give(ConnBuffers { wire: Vec::with_capacity(900 << 10), ..ConnBuffers::default() });
      rx_pool_give(VectorUsize::with_capacity(900 << 10).unwrap());
    }
    let (_, busy_rx) = rx_pool();
    assert!(busy_rx <= RX_BYTES, "{busy_rx} bytes in the read buffer pool");
    drop(open);
    let ((sets, set_bytes), (rxs, rx_bytes)) = (conn_pool(), rx_pool());
    assert!(sets > 0 && rxs > 0, "nothing kept for the next connection");
    assert!(set_bytes <= IDLE_BYTES, "{sets} sets of {set_bytes} bytes kept at idle");
    assert!(rx_bytes <= IDLE_BYTES, "{rxs} read buffers of {rx_bytes} bytes kept at idle");
  }
}
