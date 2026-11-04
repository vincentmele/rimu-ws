//! A thread-per-core executor on io_uring (Linux).
//!
//! Each [`UringRuntime`] owns one ring and runs the tasks spawned on it. A turn of its loop polls
//! every task that was woken, then makes a single `io_uring_enter` that submits all the sends the
//! tasks queued and collects all the completions that arrived since the previous turn. Sockets
//! are read with multishot receives into a ring of provided buffers and accepted with multishot
//! accepts, so a busy server spends one syscall per turn instead of a readiness wait, a read and a
//! write per connection.
//!
//! Writes copy into a per-connection buffer and return at once; the bytes are sent at the end of
//! the turn, in order, and kept alive until the kernel is done with them, even if the stream is
//! dropped first. A dropped stream is closed once everything written to it has been sent.
//!
//! Wakers must be woken on the thread that runs the runtime.

use crate::{
  collections::MaybeUninitSlice,
  executor::{Executor, ExecutorError, ExecutorTy, Runtime, resolve_addrs, tcp_listener_std},
  net::{
    Stream, StreamCommon, StreamReader, StreamWriter, TcpListener, TcpParams, TcpStream,
    ToSocketAddrs, TryRead,
  },
};
use alloc::{boxed::Box, collections::VecDeque, rc::Rc, vec::Vec};
use core::{
  alloc::Layout,
  cell::{Cell, RefCell},
  future::poll_fn,
  net::SocketAddr,
  num::NonZeroUsize,
  pin::{Pin, pin},
  task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
  time::Duration,
};
use io_uring::{IoUring, cqueue, opcode, opcode::AcceptMulti, squeue, types};
use std::os::fd::{IntoRawFd, RawFd};

const BUF_GROUP: u16 = 0;

const KIND_RECV: u64 = 1;
const KIND_SEND: u64 = 2;
const KIND_ACCEPT: u64 = 3;
const KIND_CANCEL: u64 = 4;
const KIND_TIMER: u64 = 5;
const KIND_ACCEPT_RETRY: u64 = 6;
const MAIN_TASK: usize = usize::MAX;
// One-shot accepts kept armed per listener with direct descriptors close to running out
const ACCEPT_DEPTH: u32 = 16;
// The `generation` of a one-shot accept's `user_data`; a multishot accept's is 0.
const ONE_SHOT: u32 = 1;

// `Conn::activity` bits: something was received, something was sent.
const ACTIVE_RX: u8 = 1;
const ACTIVE_TX: u8 = 2;

std::thread_local! {
  static CURRENT: Cell<*const Reactor> = const { Cell::new(core::ptr::null()) };
}

/// See the [module documentation](self).
#[derive(Clone, Debug, Default)]
pub struct UringExecutor {}

impl Executor for UringExecutor {
  const TY: ExecutorTy = ExecutorTy::Uring;

  type LocalRuntime = UringRuntime;
  type SpawnFuture<T> = UringJoinHandle<T>;
  type SpawnLocalFuture<T> = UringJoinHandle<T>;
  type TcpListener = UringTcpListener;
  type TcpStream = UringTcpStream;

  /// Spawns on the runtime of the current thread: tasks never move between threads.
  #[inline]
  fn spawn<F>(&self, future: F) -> Self::SpawnFuture<F::Output>
  where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
  {
    spawn_on_current(future)
  }

  #[inline]
  fn spawn_local<F>(&self, future: F, _: &Self::LocalRuntime) -> Self::SpawnLocalFuture<F::Output>
  where
    F: Future + 'static,
    F::Output: 'static,
  {
    spawn_on_current(future)
  }
}

/// One ring and the tasks that run on it. See the [module documentation](self).
#[derive(Debug)]
pub struct UringRuntime {
  reactor: Box<Reactor>,
}

impl UringRuntime {
  #[cfg(test)]
  fn open_conns(&self) -> usize {
    self.reactor.conns.borrow().iter().filter(|conn| conn.in_use).count()
  }

  /// A runtime with the given settings.
  #[inline]
  pub fn with_params(params: UringParams) -> crate::Result<Self> {
    Ok(Self { reactor: Box::new(Reactor::new(params)?) })
  }
}

/// Settings of a [`UringRuntime`].
#[derive(Clone, Copy, Debug)]
pub struct UringParams {
  close_timeout: Option<Duration>,
  cq_entries: u32,
  direct_files: u32,
  handshake_timeout: Option<Duration>,
  idle_timeout: Option<Duration>,
  peer_addrs: bool,
  recv_buffer_len: u32,
  recv_buffers: u16,
  rx_high_water: usize,
  spin: Duration,
  sq_entries: u32,
  tx_high_water: usize,
}

impl UringParams {
  /// Peer addresses resolved, no spinning.
  #[inline]
  pub const fn new() -> Self {
    Self {
      close_timeout: Some(Duration::from_secs(10)),
      cq_entries: 4096,
      direct_files: 0,
      handshake_timeout: None,
      idle_timeout: None,
      peer_addrs: true,
      recv_buffer_len: 4096,
      recv_buffers: 512,
      rx_high_water: 64 * 1024,
      spin: Duration::ZERO,
      sq_entries: 1024,
      tx_high_water: 4 * 1024 * 1024,
    }
  }

  /// How long a connection whose last handle was dropped may go without sending anything while
  /// it still has written bytes to send. Past that its sends are cancelled and it is closed, so
  /// a peer that stops reading cannot hold the connection, or the end of
  /// [`Runtime::block_on`], forever. `None` waits for as long as it takes. Defaults to 10 s.
  #[inline]
  #[must_use]
  pub const fn set_close_timeout(mut self, value: Option<Duration>) -> Self {
    self.close_timeout = value;
    self
  }

  /// How long an accepted connection may go before anything is sent on it. Past that, its reads
  /// and writes fail with `ETIMEDOUT`. A server writes once it has a whole request or handshake,
  /// so this bounds how long a client may take to send one, even one byte at a time. Defaults to
  /// `None`.
  #[inline]
  #[must_use]
  pub const fn set_handshake_timeout(mut self, value: Option<Duration>) -> Self {
    self.handshake_timeout = value;
    self
  }

  /// How long a connection may go without receiving or sending anything. Past that, its reads
  /// and writes fail with `ETIMEDOUT`. A peer that only listens should be pinged: the pongs keep
  /// it alive. Connections are checked a few times per timeout, from one timer per runtime.
  /// Defaults to `None`.
  #[inline]
  #[must_use]
  pub const fn set_idle_timeout(mut self, value: Option<Duration>) -> Self {
    self.idle_timeout = value;
    self
  }

  /// How many received bytes a connection can hold that nobody has read before it stops
  /// receiving, which leaves the rest in the socket and lets TCP slow the peer down. It receives
  /// again once reads take it under half of that. Defaults to 64 KiB.
  #[inline]
  #[must_use]
  pub const fn set_rx_high_water(mut self, value: usize) -> Self {
    self.rx_high_water = value;
    self
  }

  /// The ring of buffers that receives are made into: `count` buffers (rounded up to a power of
  /// two) of `len` bytes each, shared by the connections of a runtime. Received bytes are copied
  /// out as soon as they complete, so the ring only has to cover one turn. Defaults to 512 of
  /// 4096 bytes.
  #[inline]
  #[must_use]
  pub const fn set_recv_buffers(mut self, count: u16, len: u32) -> Self {
    self.recv_buffers = count;
    self.recv_buffer_len = len;
    self
  }

  /// The submission and completion ring sizes, each rounded up to a power of two (the completion
  /// ring is also raised to at least the submission ring). Larger rings submit fewer times and
  /// tolerate more completions per turn, which helps a server with many pipelined connections, at
  /// the cost of more locked memory per runtime. Defaults to 1024 submission and 4096 completion
  /// entries.
  #[inline]
  #[must_use]
  pub const fn set_ring_entries(mut self, submission: u32, completion: u32) -> Self {
    self.sq_entries = submission;
    self.cq_entries = completion;
    self
  }

  /// How many written bytes a connection can have waiting to be sent before a write waits for
  /// them. Defaults to 4 MiB.
  #[inline]
  #[must_use]
  pub const fn set_tx_high_water(mut self, value: usize) -> Self {
    self.tx_high_water = value;
    self
  }

  /// Accepts connections as direct descriptors in a table of `value` slots registered with the
  /// ring, `0` to use ordinary file descriptors.
  ///
  /// Direct descriptors live in the ring rather than the process, so sends skip the file lookup
  /// and closing a connection is a queued operation instead of a syscall. They cannot be passed to
  /// other syscalls: accepted connections keep the listener's `TCP_NODELAY` and report the
  /// unspecified peer address, and at most `value` of them can be open at once.
  #[inline]
  #[must_use]
  pub const fn set_direct_files(mut self, value: u32) -> Self {
    self.direct_files = value;
    self
  }

  /// Whether accepting a connection looks up its peer's address, which costs a `getpeername` per
  /// connection. When `false`, accepted connections report the unspecified address `0.0.0.0:0`.
  #[inline]
  #[must_use]
  pub const fn set_peer_addrs(mut self, value: bool) -> Self {
    self.peer_addrs = value;
    self
  }

  /// Busy-polls for up to `value` before sleeping while waiting for completions.
  ///
  /// Sleeping and being woken again costs several microseconds, which dominates when every turn
  /// has little work, as with one message in flight per connection. Spinning keeps the thread on
  /// its CPU; it only enters the kernel when the ring flags pending completions. Worth it when the
  /// runtime has its CPU to itself.
  #[inline]
  #[must_use]
  pub const fn set_spin(mut self, value: Duration) -> Self {
    self.spin = value;
    self
  }
}

impl Default for UringParams {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

impl Runtime for UringRuntime {
  #[inline]
  fn new() -> crate::Result<Self> {
    Ok(Self { reactor: Box::new(Reactor::new(UringParams::new())?) })
  }

  #[inline]
  fn block_on<F>(&self, future: F) -> F::Output
  where
    F: Future,
  {
    let reactor = &*self.reactor;
    let prev = CURRENT.with(|el| el.replace(reactor));
    let _guard = RestoreCurrent(prev);
    let mut future = pin!(future);
    let main_waker = waker(MAIN_TASK);
    reactor.main_woken.set(true);
    loop {
      if reactor.main_woken.replace(false)
        && let Poll::Ready(elem) = future.as_mut().poll(&mut Context::from_waker(&main_waker))
      {
        reactor.finish_closing();
        return elem;
      }
      reactor.run_ready();
      let idle = !reactor.main_woken.get() && reactor.ready.borrow().is_empty();
      reactor.enter(idle);
      reactor.reap();
    }
  }
}

struct RestoreCurrent(*const Reactor);

impl Drop for RestoreCurrent {
  #[inline]
  fn drop(&mut self) {
    CURRENT.with(|el| el.set(self.0));
  }
}

/// Resolves to the output of a spawned task. Dropping it leaves the task running.
pub struct UringJoinHandle<T> {
  // `None` if there was no runtime to spawn on.
  task: Option<Rc<dyn JoinTask<T>>>,
}

impl<T> core::fmt::Debug for UringJoinHandle<T> {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("UringJoinHandle").finish()
  }
}

impl<T> Future for UringJoinHandle<T> {
  type Output = crate::Result<T>;

  #[inline]
  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let Some(task) = &self.task else {
      return Poll::Ready(Err(ExecutorError::MissingRuntime.into()));
    };
    task.poll_join(cx).map(Ok)
  }
}

// A spawned future and its output share one allocation, seen by the runtime as a `RunTask` and by
// the join handle as a `JoinTask`.
struct TaskCell<F>
where
  F: Future,
{
  inner: RefCell<(TaskState<F>, Option<Waker>)>,
}

enum TaskState<F>
where
  F: Future,
{
  Done(Option<F::Output>),
  Running(F),
}

trait RunTask {
  fn poll_task(&self, cx: &mut Context<'_>) -> Poll<()>;
}

trait JoinTask<T> {
  fn poll_join(&self, cx: &mut Context<'_>) -> Poll<T>;
}

impl<F> RunTask for TaskCell<F>
where
  F: Future,
{
  #[inline]
  fn poll_task(&self, cx: &mut Context<'_>) -> Poll<()> {
    let mut inner = self.inner.borrow_mut();
    let TaskState::Running(future) = &mut inner.0 else {
      return Poll::Ready(());
    };
    // SAFETY: the future lives in the `Rc` allocation and is only dropped in place, never moved
    let future = unsafe { Pin::new_unchecked(future) };
    let Poll::Ready(value) = future.poll(cx) else {
      return Poll::Pending;
    };
    inner.0 = TaskState::Done(Some(value));
    let waker = inner.1.take();
    drop(inner);
    if let Some(elem) = waker {
      elem.wake();
    }
    Poll::Ready(())
  }
}

impl<F> JoinTask<F::Output> for TaskCell<F>
where
  F: Future,
{
  #[inline]
  fn poll_join(&self, cx: &mut Context<'_>) -> Poll<F::Output> {
    let mut inner = self.inner.borrow_mut();
    if let TaskState::Done(value) = &mut inner.0
      && let Some(elem) = value.take()
    {
      return Poll::Ready(elem);
    }
    inner.1 = Some(cx.waker().clone());
    Poll::Pending
  }
}

/// A listening socket whose connections are taken with a multishot accept.
#[derive(Debug)]
pub struct UringTcpListener {
  idx: usize,
  // Accepted sockets inherit it from the listening one.
  nodelay: bool,
}

impl Drop for UringTcpListener {
  #[inline]
  fn drop(&mut self) {
    let reactor = CURRENT.with(Cell::get);
    if reactor.is_null() {
      return;
    }
    // SAFETY: set by `block_on`, which outlives everything it polls
    unsafe { &*reactor }.drop_listener(self.idx);
  }
}

impl TcpListener for UringTcpListener {
  type TcpStream = UringTcpStream;

  #[inline]
  async fn bind<A>(addr: A, tcp_params: TcpParams) -> crate::Result<Self>
  where
    A: ToSocketAddrs,
  {
    let listener = tcp_listener_std(addr, &UringExecutor::default(), tcp_params).await?;
    let fd = listener.into_raw_fd();
    let idx = with_reactor(|reactor| reactor.add_listener(fd))?;
    Ok(Self { idx, nodelay: tcp_params.tcp_nodelay() })
  }

  #[inline]
  async fn accept(&self, tcp_params: TcpParams) -> crate::Result<(Self::TcpStream, SocketAddr)> {
    let fd = poll_fn(|cx| poll_reactor(|reactor| reactor.poll_accept(self.idx, cx))).await?;
    let params = with_reactor(|reactor| Ok(reactor.params))?;
    let direct = params.direct_files > 0;
    if !direct && tcp_params.tcp_nodelay() != self.nodelay {
      set_nodelay(fd, tcp_params.tcp_nodelay())?;
    }
    let peer_addr = if params.peer_addrs && !direct {
      peer_addr(fd)?
    } else {
      SocketAddr::V4(core::net::SocketAddrV4::new(core::net::Ipv4Addr::UNSPECIFIED, 0))
    };
    let (idx, generation) = with_reactor(|reactor| reactor.add_conn(fd, 1, direct, true))?;
    Ok((UringTcpStream { generation, idx }, peer_addr))
  }
}

/// A connected socket. See the [module documentation](self).
#[derive(Debug)]
pub struct UringTcpStream {
  generation: u32,
  idx: u32,
}

impl Drop for UringTcpStream {
  #[inline]
  fn drop(&mut self) {
    drop_conn_ref(self.idx, self.generation);
  }
}

impl Stream for UringTcpStream {
  type BridgeOwned = ();
  type ReadHalfOwned = UringReadHalf;
  type WriteHalfOwned = UringWriteHalf;

  #[inline]
  fn into_split(
    self,
  ) -> crate::Result<(Self::BridgeOwned, Self::ReadHalfOwned, Self::WriteHalfOwned)> {
    let (generation, idx) = (self.generation, self.idx);
    core::mem::forget(self);
    with_reactor(|reactor| reactor.add_conn_ref(idx, generation))?;
    Ok(((), UringReadHalf { generation, idx }, UringWriteHalf { generation, idx }))
  }
}

impl StreamCommon for UringTcpStream {}

impl StreamReader for UringTcpStream {
  #[inline]
  async fn read(&mut self, bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<Option<NonZeroUsize>> {
    read(self.idx, self.generation, bytes).await
  }

  #[inline]
  fn try_read(&mut self, mut bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<TryRead> {
    with_reactor(|reactor| reactor.try_read(self.idx, self.generation, &mut bytes))
  }

  #[inline]
  fn readable(&mut self) -> impl Future<Output = crate::Result<()>> {
    readable(self.idx, self.generation)
  }
}

impl StreamWriter for UringTcpStream {
  #[inline]
  async fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
    write_all_vectored(self.idx, self.generation, &[bytes]).await
  }

  #[inline]
  async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<()> {
    write_all_vectored(self.idx, self.generation, bytes).await
  }

  #[inline]
  fn try_write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<bool> {
    try_write_all_vectored(self.idx, self.generation, bytes)
  }
}

impl TcpStream for UringTcpStream {
  type Executor = UringExecutor;

  /// Connects with a blocking `connect`, then hands the socket to the ring.
  #[inline]
  async fn connect<A>(addr: A, tcp_params: TcpParams) -> crate::Result<Self>
  where
    A: ToSocketAddrs,
  {
    let stream = resolve_addrs(addr, &UringExecutor::default(), async |socket_addr| {
      Ok(std::net::TcpStream::connect(socket_addr)?)
    })
    .await?;
    stream.set_nodelay(tcp_params.tcp_nodelay())?;
    let fd = stream.into_raw_fd();
    let (idx, generation) = with_reactor(|reactor| reactor.add_conn(fd, 1, false, false))?;
    Ok(Self { generation, idx })
  }

  #[inline]
  fn peer_addr(&self) -> crate::Result<SocketAddr> {
    let (fd, direct) = with_reactor(|reactor| reactor.conn_fd(self.idx, self.generation))?;
    if direct {
      return Err(io_err(libc::EOPNOTSUPP));
    }
    peer_addr(fd)
  }
}

/// Reading part of a split [`UringTcpStream`].
#[derive(Debug)]
pub struct UringReadHalf {
  generation: u32,
  idx: u32,
}

impl Drop for UringReadHalf {
  #[inline]
  fn drop(&mut self) {
    drop_conn_ref(self.idx, self.generation);
  }
}

impl StreamCommon for UringReadHalf {}

impl StreamReader for UringReadHalf {
  #[inline]
  async fn read(&mut self, bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<Option<NonZeroUsize>> {
    read(self.idx, self.generation, bytes).await
  }

  #[inline]
  fn try_read(&mut self, mut bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<TryRead> {
    with_reactor(|reactor| reactor.try_read(self.idx, self.generation, &mut bytes))
  }

  #[inline]
  fn readable(&mut self) -> impl Future<Output = crate::Result<()>> {
    readable(self.idx, self.generation)
  }
}

/// Writing part of a split [`UringTcpStream`].
#[derive(Debug)]
pub struct UringWriteHalf {
  generation: u32,
  idx: u32,
}

impl Drop for UringWriteHalf {
  #[inline]
  fn drop(&mut self) {
    drop_conn_ref(self.idx, self.generation);
  }
}

impl StreamCommon for UringWriteHalf {}

impl StreamWriter for UringWriteHalf {
  #[inline]
  async fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
    write_all_vectored(self.idx, self.generation, &[bytes]).await
  }

  #[inline]
  async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<()> {
    write_all_vectored(self.idx, self.generation, bytes).await
  }

  #[inline]
  fn try_write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<bool> {
    try_write_all_vectored(self.idx, self.generation, bytes)
  }
}

async fn read(
  idx: u32,
  generation: u32,
  mut bytes: MaybeUninitSlice<'_, u8>,
) -> crate::Result<Option<NonZeroUsize>> {
  poll_fn(|cx| poll_reactor(|reactor| reactor.poll_read(idx, generation, &mut bytes, cx))).await
}

// A plain `fn`: the future holds the two ids and nothing else.
fn readable(idx: u32, generation: u32) -> impl Future<Output = crate::Result<()>> {
  poll_fn(move |cx| poll_reactor(|reactor| reactor.poll_readable(idx, generation, cx)))
}

async fn write_all_vectored(idx: u32, generation: u32, bytes: &[&[u8]]) -> crate::Result<()> {
  with_reactor(|reactor| reactor.queue_send(idx, generation, bytes))?;
  poll_fn(|cx| poll_reactor(|reactor| reactor.poll_send_room(idx, generation, cx))).await
}

fn try_write_all_vectored(idx: u32, generation: u32, bytes: &[&[u8]]) -> crate::Result<bool> {
  with_reactor(|reactor| reactor.try_queue_send(idx, generation, bytes))
}

fn drop_conn_ref(idx: u32, generation: u32) {
  let reactor = CURRENT.with(Cell::get);
  if reactor.is_null() {
    return;
  }
  // SAFETY: set by `block_on`, which outlives everything it polls
  unsafe { &*reactor }.drop_conn_ref(idx, generation);
}

fn spawn_on_current<F>(future: F) -> UringJoinHandle<F::Output>
where
  F: Future + 'static,
  F::Output: 'static,
{
  let reactor = CURRENT.with(Cell::get);
  if reactor.is_null() {
    return UringJoinHandle { task: None };
  }
  let cell = Rc::new(TaskCell { inner: RefCell::new((TaskState::Running(future), None)) });
  // SAFETY: set by `block_on`, which outlives everything it polls
  unsafe { &*reactor }.spawn(cell.clone());
  UringJoinHandle { task: Some(cell) }
}

fn with_reactor<T>(cb: impl FnOnce(&Reactor) -> crate::Result<T>) -> crate::Result<T> {
  let reactor = CURRENT.with(Cell::get);
  if reactor.is_null() {
    return Err(ExecutorError::MissingRuntime.into());
  }
  // SAFETY: set by `block_on`, which outlives everything it polls
  cb(unsafe { &*reactor })
}

fn poll_reactor<T>(cb: impl FnOnce(&Reactor) -> Poll<crate::Result<T>>) -> Poll<crate::Result<T>> {
  let reactor = CURRENT.with(Cell::get);
  if reactor.is_null() {
    return Poll::Ready(Err(ExecutorError::MissingRuntime.into()));
  }
  // SAFETY: set by `block_on`, which outlives everything it polls
  cb(unsafe { &*reactor })
}

fn io_err(errno: i32) -> crate::Error {
  std::io::Error::from_raw_os_error(errno).into()
}

fn peer_addr(fd: RawFd) -> crate::Result<SocketAddr> {
  // SAFETY: borrows `fd` for the call; `ManuallyDrop` keeps it open
  let stream = core::mem::ManuallyDrop::new(unsafe {
    <std::net::TcpStream as std::os::fd::FromRawFd>::from_raw_fd(fd)
  });
  Ok(stream.peer_addr()?)
}

fn set_nodelay(fd: RawFd, value: bool) -> crate::Result<()> {
  let flag = libc::c_int::from(value);
  // SAFETY: `flag` outlives the call and its size is passed
  let rslt = unsafe {
    libc::setsockopt(
      fd,
      libc::IPPROTO_TCP,
      libc::TCP_NODELAY,
      (&raw const flag).cast(),
      size_of::<libc::c_int>() as libc::socklen_t,
    )
  };
  if rslt != 0 {
    return Err(std::io::Error::last_os_error().into());
  }
  Ok(())
}

const fn user_data(kind: u64, generation: u32, idx: u32) -> u64 {
  (kind << 60) | ((generation as u64 & 0x0FFF_FFFF) << 32) | idx as u64
}

const fn split_user_data(user_data: u64) -> (u64, u32, u32) {
  ((user_data >> 60), ((user_data >> 32) & 0x0FFF_FFFF) as u32, user_data as u32)
}

// ---- wakers: the data is a task index and generation, or `MAIN_TASK`

static VTABLE: RawWakerVTable =
  RawWakerVTable::new(waker_clone, waker_wake, waker_wake, waker_drop);

fn waker(data: usize) -> Waker {
  // SAFETY: the vtable functions don't dereference `data`
  unsafe { Waker::from_raw(RawWaker::new(data as *const (), &VTABLE)) }
}

fn waker_clone(data: *const ()) -> RawWaker {
  RawWaker::new(data, &VTABLE)
}

fn waker_wake(data: *const ()) {
  let reactor = CURRENT.with(Cell::get);
  if reactor.is_null() {
    return;
  }
  // SAFETY: set by `block_on`, which outlives everything it polls
  unsafe { &*reactor }.schedule(data as usize);
}

fn waker_drop(_: *const ()) {}

// ---- the reactor

// 32 bytes, so that no slot straddles two cache lines: a wake reads one.
#[repr(align(32))]
struct TaskSlot {
  future: Option<Rc<dyn RunTask>>,
  generation: u32,
  scheduled: bool,
}

// Every frame reads or writes a connection's slot in several passes (the receive completion,
// the read, the send, the send completion), with the kernel's network work in between evicting
// it. So the fields those passes touch fill the first two cache lines exactly, and the slot is
// line-aligned: one frame costs two lines here instead of the three a 144-byte slot spanned.
// Fields only setup and teardown touch come after.
#[derive(Default)]
#[repr(C, align(64))]
struct Conn {
  generation: u32,
  fd: RawFd,
  rx: Vec<u8>,
  rx_off: u32,
  rx_err: u8,
  tx_err: u8,
  // The receive was cancelled because `rx` holds more than `rx_high_water` unread bytes
  rx_paused: bool,
  // `ACTIVE_RX` and `ACTIVE_TX`, set by completions and cleared by the timer
  activity: u8,
  reader: Option<Waker>,
  tx_inflight: Vec<u8>,
  tx_pending: Vec<u8>,
  tx_done: u32,
  closing: bool,
  // `fd` is an index into the ring's table of direct descriptors
  direct: bool,
  rx_eof: bool,
  sending: bool,
  writer: Option<Waker>,
  // Setup, teardown and the timer only
  cancel_sent: bool,
  in_use: bool,
  // In `Timers::lingering`
  lingering: bool,
  recv_armed: bool,
  refs: u8,
  // The tick `activity` was last seen set
  last_active: u32,
}

const _: () = {
  assert!(size_of::<Conn>() == 192);
  assert!(core::mem::offset_of!(Conn, activity) < 64);
  assert!(core::mem::offset_of!(Conn, writer) + size_of::<Option<Waker>>() == 128);
};

/// An errno from a negative completion result. Linux errnos fit a `u8` (the largest is 133).
fn errno(res: i32) -> u8 {
  u8::try_from(res.unsigned_abs()).unwrap_or(u8::MAX)
}

// The queue views are read through `ManuallyDrop`: dropping one stores its index back to the
// rings' first cache line, which other CPUs write the task-work flag to, and a spinning reactor
// would keep pulling that line away from them.

/// Deferred task work to run or overflowed completions to flush.
fn needs_kernel(ring: &mut IoUring) -> bool {
  let sq = core::mem::ManuallyDrop::new(ring.submission());
  sq.taskrun() || sq.cq_overflow()
}

/// Whether an `io_uring_enter` has anything to do.
fn needs_enter(ring: &mut IoUring) -> bool {
  !core::mem::ManuallyDrop::new(ring.submission()).is_empty() || needs_kernel(ring)
}

fn cq_is_empty(ring: &mut IoUring) -> bool {
  core::mem::ManuallyDrop::new(ring.completion()).is_empty()
}

fn set_waker(slot: &mut Option<Waker>, cx: &Context<'_>) {
  if !slot.as_ref().is_some_and(|el| el.will_wake(cx.waker())) {
    *slot = Some(cx.waker().clone());
  }
}

/// Moves received bytes into `bytes`. Never [`TryRead::Unsupported`].
fn take_rx(conn: &mut Conn, bytes: &mut MaybeUninitSlice<'_, u8>) -> crate::Result<TryRead> {
  let available = conn.rx.get(conn.rx_off as usize..).unwrap_or_default();
  if !available.is_empty() {
    // The whole slice, as other streams read: an initialized one has no uninitialized part.
    // SAFETY: only initialized bytes are written into it
    let dst = unsafe { bytes.all_mut() };
    // Reading nothing would report the end of the stream, with bytes still to read.
    if dst.is_empty() {
      return Err(io_err(libc::EINVAL));
    }
    let len = available.len().min(dst.len());
    // SAFETY: `dst` has room for `len` bytes, and the regions don't overlap
    unsafe {
      core::ptr::copy_nonoverlapping(available.as_ptr(), dst.as_mut_ptr().cast(), len);
    }
    // `len` is at most what `rx` holds past `rx_off`, which `rx_off` already indexes
    conn.rx_off += len as u32;
    if conn.rx_off as usize == conn.rx.len() {
      conn.rx.clear();
      conn.rx_off = 0;
    }
    return Ok(NonZeroUsize::new(len).map_or(TryRead::Pending, TryRead::Read));
  }
  if conn.rx_err != 0 {
    return Err(io_err(conn.rx_err.into()));
  }
  if conn.rx_eof {
    return Ok(TryRead::Closed);
  }
  if bytes.all().is_empty() {
    return Err(io_err(libc::EINVAL));
  }
  Ok(TryRead::Pending)
}

fn cancel_sqe(target: u64) -> squeue::Entry {
  opcode::AsyncCancel::new(target).build().flags(squeue::Flags::SKIP_SUCCESS).user_data(user_data(
    KIND_CANCEL,
    0,
    0,
  ))
}

fn ticks(value: Duration, period: Duration) -> u32 {
  u32::try_from(value.as_nanos().div_ceil(period.as_nanos().max(1))).unwrap_or(u32::MAX).max(1)
}

/// Deadlines, counted in ticks of one timer per runtime that runs while something needs it.
struct Timers {
  armed: bool,
  close_ticks: u32,
  // Accepted connections nothing was sent on yet: index, generation, deadline
  handshakes: Vec<(u32, u32, u32)>,
  handshake_ticks: u32,
  // How often the idle sweep runs, in ticks
  idle_every: u32,
  idle_ticks: u32,
  // Dropped connections still sending: index, generation, the tick they last sent by
  lingering: Vec<(u32, u32, u32)>,
  tick: u32,
}

struct ListenerState {
  // A multishot accept is armed
  armed: bool,
  // Waiting out a resource error before accepting again
  backoff: bool,
  closed: bool,
  fd: RawFd,
  // Fewer than `ACCEPT_DEPTH` accepts are armed for lack of direct descriptor slots
  gated: bool,
  // One-shot accepts armed
  pending: u32,
  queue: VecDeque<RawFd>,
  waker: Option<Waker>,
}

struct BufRing {
  count: u16,
  entries: *mut u8,
  layout: Layout,
  len: usize,
  mem: Vec<u8>,
  tail: u16,
}

impl BufRing {
  fn push(&mut self, bid: u16) {
    let idx = usize::from(self.tail & (self.count - 1));
    let addr = self.mem.as_ptr() as u64 + u64::from(bid) * self.len as u64;
    // SAFETY: `entries` holds `count` entries of 16 bytes: addr u64, len u32, bid u16, resv u16
    unsafe {
      let entry = self.entries.add(idx * 16);
      entry.cast::<u64>().write(addr);
      entry.add(8).cast::<u32>().write(self.len as u32);
      entry.add(12).cast::<u16>().write(bid);
    }
    self.tail = self.tail.wrapping_add(1);
  }

  fn publish(&self) {
    // SAFETY: the ring's tail aliases the `resv` field of the first entry, at offset 14
    let tail = unsafe { &*self.entries.add(14).cast::<core::sync::atomic::AtomicU16>() };
    tail.store(self.tail, core::sync::atomic::Ordering::Release);
  }
}

impl Drop for BufRing {
  fn drop(&mut self) {
    // SAFETY: allocated in `Reactor::new` with this layout
    unsafe { alloc::alloc::dealloc(self.entries, self.layout) };
  }
}

struct Reactor {
  // First, so that it is dropped first: the kernel may still use the buffers below until the ring
  // is closed.
  ring: RefCell<IoUring>,
  #[cfg(test)]
  accept_arms: Cell<usize>,
  // Read by the kernel when it takes a timeout entry off the queue
  backoff_ts: types::Timespec,
  tick_ts: types::Timespec,
  bufs: RefCell<BufRing>,
  cqes: RefCell<Vec<(u64, i32, u32)>>,
  conns: RefCell<Vec<Conn>>,
  // Slots of the direct descriptor table that connections, accept queues and armed accepts hold.
  // Accepting into a full table drops the connection, so accepts stop at `direct_files` and the
  // connections wait in the backlog instead.
  direct_open: Cell<u32>,
  free_conns: RefCell<Vec<u32>>,
  free_tasks: RefCell<Vec<u32>>,
  listeners: RefCell<Vec<ListenerState>>,
  main_woken: Cell<bool>,
  params: UringParams,
  // The task `run_ready` is polling, or `usize::MAX`
  polling: Cell<usize>,
  ready: RefCell<VecDeque<usize>>,
  tasks: RefCell<Vec<TaskSlot>>,
  timers: RefCell<Timers>,
}

impl Drop for Reactor {
  fn drop(&mut self) {
    // Handles that outlive the runtime can no longer reach it to close themselves. Direct
    // descriptors go with the ring.
    for conn in self.conns.get_mut().iter().filter(|el| el.in_use && !el.direct) {
      // SAFETY: closed once, here; the ring that could still use it is dropped right after
      let _rslt = unsafe { libc::close(conn.fd) };
    }
    let direct = self.params.direct_files > 0;
    for listener in self.listeners.get_mut().iter_mut().filter(|el| !el.closed) {
      listener.closed = true;
      let accepted = listener.queue.drain(..).filter(|_| !direct);
      for fd in accepted.chain(core::iter::once(listener.fd)) {
        // SAFETY: closed once, here; the ring that could still use them is dropped right after
        let _rslt = unsafe { libc::close(fd) };
      }
    }
  }
}

impl core::fmt::Debug for Reactor {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Reactor").finish()
  }
}

impl Reactor {
  fn new(params: UringParams) -> crate::Result<Self> {
    let sq_entries = params.sq_entries.max(1).next_power_of_two();
    let cq_entries = params.cq_entries.max(sq_entries).next_power_of_two();
    let ring = IoUring::builder()
      .setup_single_issuer()
      .setup_defer_taskrun()
      .setup_taskrun_flag()
      .setup_submit_all()
      .setup_cqsize(cq_entries)
      .build(sq_entries)?;
    let count = params.recv_buffers.max(1).next_power_of_two();
    let len = params.recv_buffer_len.max(1) as usize;
    let layout = Layout::from_size_align(usize::from(count) * 16, 4096)
      .map_err(|_err| io_err(libc::EINVAL))?;
    // SAFETY: `layout` has a non-zero size
    let entries = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if entries.is_null() {
      return Err(io_err(libc::ENOMEM));
    }
    let mut bufs = BufRing {
      count,
      entries,
      layout,
      len,
      mem: alloc::vec![0; usize::from(count) * len],
      tail: 0,
    };
    // SAFETY: `entries` stays allocated, and registered, for as long as the ring
    unsafe {
      ring.submitter().register_buf_ring_with_flags(entries as u64, count, BUF_GROUP, 0)?;
    }
    for bid in 0..count {
      bufs.push(bid);
    }
    bufs.publish();
    if params.direct_files > 0 {
      ring.submitter().register_files_sparse(params.direct_files)?;
    }
    // A few ticks per timeout keep each within a quarter of its length.
    let timeouts = [params.close_timeout, params.handshake_timeout, params.idle_timeout];
    let period = timeouts
      .iter()
      .flatten()
      .min()
      .map_or(Duration::from_secs(1), |el| *el / 4)
      .clamp(Duration::from_millis(1), Duration::from_secs(1));
    let ticks_of = |value: Option<Duration>| value.map_or(0, |el| ticks(el, period));
    let idle_ticks = ticks_of(params.idle_timeout);
    let timers = Timers {
      armed: false,
      close_ticks: ticks_of(params.close_timeout),
      handshakes: Vec::new(),
      handshake_ticks: ticks_of(params.handshake_timeout),
      idle_every: (idle_ticks / 4).max(1),
      idle_ticks,
      lingering: Vec::new(),
      tick: 0,
    };
    Ok(Self {
      ring: RefCell::new(ring),
      #[cfg(test)]
      accept_arms: Cell::new(0),
      backoff_ts: types::Timespec::new().nsec(100_000_000),
      tick_ts: types::Timespec::from(period),
      bufs: RefCell::new(bufs),
      cqes: RefCell::new(Vec::with_capacity(cq_entries as usize)),
      conns: RefCell::new(Vec::new()),
      direct_open: Cell::new(0),
      free_conns: RefCell::new(Vec::new()),
      free_tasks: RefCell::new(Vec::new()),
      listeners: RefCell::new(Vec::new()),
      main_woken: Cell::new(false),
      params,
      polling: Cell::new(usize::MAX),
      ready: RefCell::new(VecDeque::new()),
      tasks: RefCell::new(Vec::new()),
      timers: RefCell::new(timers),
    })
  }

  // ---- tasks

  fn spawn(&self, future: Rc<dyn RunTask>) {
    let mut tasks = self.tasks.borrow_mut();
    let idx = if let Some(idx) = self.free_tasks.borrow_mut().pop() {
      let slot = &mut tasks[idx as usize];
      slot.future = Some(future);
      slot.scheduled = true;
      idx
    } else {
      tasks.push(TaskSlot { future: Some(future), generation: 0, scheduled: true });
      (tasks.len() - 1) as u32
    };
    self.ready.borrow_mut().push_back(idx as usize);
  }

  fn schedule(&self, data: usize) {
    if data == MAIN_TASK {
      self.main_woken.set(true);
      return;
    }
    let (idx, generation) = (data as u32, (data >> 32) as u32);
    let mut tasks = self.tasks.borrow_mut();
    // A task being polled has its future taken out of the slot, and can still wake itself.
    if let Some(slot) = tasks.get_mut(idx as usize)
      && slot.generation == generation
      && (slot.future.is_some() || self.polling.get() == idx as usize)
      && !slot.scheduled
    {
      slot.scheduled = true;
      self.ready.borrow_mut().push_back(idx as usize);
    }
  }

  fn run_ready(&self) {
    let count = self.ready.borrow().len();
    for _ in 0..count {
      let Some(idx) = self.ready.borrow_mut().pop_front() else {
        break;
      };
      let (future, generation) = {
        let mut tasks = self.tasks.borrow_mut();
        let slot = &mut tasks[idx];
        slot.scheduled = false;
        (slot.future.take(), slot.generation)
      };
      let Some(future) = future else {
        continue;
      };
      let waker = waker(((generation as usize) << 32) | idx);
      self.polling.set(idx);
      let poll = future.poll_task(&mut Context::from_waker(&waker));
      self.polling.set(usize::MAX);
      if poll.is_ready() {
        drop(future);
        let mut tasks = self.tasks.borrow_mut();
        let slot = &mut tasks[idx];
        slot.generation = slot.generation.wrapping_add(1);
        slot.scheduled = false;
        self.free_tasks.borrow_mut().push(idx as u32);
      } else {
        self.tasks.borrow_mut()[idx].future = Some(future);
      }
    }
  }

  /// Keeps turning until every connection whose last handle was dropped has sent what was
  /// written to it and is closed, so that returning from `block_on` loses nothing.
  fn finish_closing(&self) {
    while self.conns.borrow().iter().any(|conn| conn.in_use && conn.closing) {
      self.run_ready();
      self.enter(self.ready.borrow().is_empty());
      self.reap();
    }
    // Closing a direct descriptor is itself a queued operation.
    self.enter(false);
  }

  // ---- ring

  // Inlined, so the entry can be stored straight into its slot; a full queue, which needs a
  // submit and a retry, is handled out of line.
  #[inline(always)]
  fn push_sqe(&self, sqe: &squeue::Entry) {
    let mut ring = self.ring.borrow_mut();
    // SAFETY: every buffer an entry points to lives in a `Conn` or `BufRing` until its completion
    if unsafe { ring.submission().push(sqe) }.is_err() {
      drop(ring);
      self.push_sqe_full(sqe);
    }
  }

  #[cold]
  #[inline(never)]
  fn push_sqe_full(&self, sqe: &squeue::Entry) {
    let mut ring = self.ring.borrow_mut();
    // SAFETY: as in `push_sqe`
    while unsafe { ring.submission().push(sqe) }.is_err() {
      let _rslt = ring.submit();
    }
  }

  fn enter(&self, wait: bool) {
    let mut ring = self.ring.borrow_mut();
    if !wait {
      if needs_enter(&mut ring) {
        let _rslt = ring.submit();
      }
      return;
    }
    if !self.params.spin.is_zero() {
      // Sends usually complete inside this submit and post their completions at once; `reap`
      // takes those without another syscall.
      if needs_enter(&mut ring) {
        let _rslt = ring.submit();
      }
      if !cq_is_empty(&mut ring) {
        return;
      }
      let begin = std::time::Instant::now();
      let mut iter: u32 = 0;
      loop {
        // With `DEFER_TASKRUN` the kernel only flags task work while this thread is out of the
        // kernel, and `submit` runs it.
        if needs_kernel(&mut ring) {
          let _rslt = ring.submit();
          return;
        }
        if !cq_is_empty(&mut ring) {
          return;
        }
        iter = iter.wrapping_add(1);
        if iter % 64 == 0 && begin.elapsed() >= self.params.spin {
          break;
        }
        core::hint::spin_loop();
      }
    }
    let _rslt = ring.submit_and_wait(1);
  }

  fn reap(&self) {
    let mut cqes = self.cqes.borrow_mut();
    cqes.clear();
    {
      let mut ring = self.ring.borrow_mut();
      cqes.extend(ring.completion().map(|cqe| (cqe.user_data(), cqe.result(), cqe.flags())));
    }
    let mut recycled = false;
    for &(user_data, res, flags) in cqes.iter() {
      let (kind, generation, idx) = split_user_data(user_data);
      match kind {
        KIND_RECV => recycled |= self.on_recv(idx, generation, res, flags),
        KIND_SEND => self.on_send(idx, generation, res),
        KIND_ACCEPT => self.on_accept(idx as usize, generation == ONE_SHOT, res, flags),
        KIND_ACCEPT_RETRY => self.on_accept_retry(idx as usize),
        KIND_TIMER => self.on_tick(),
        _ => {}
      }
    }
    if recycled {
      self.bufs.borrow().publish();
    }
  }

  // ---- listeners

  fn add_listener(&self, fd: RawFd) -> crate::Result<usize> {
    let mut listeners = self.listeners.borrow_mut();
    listeners.push(ListenerState {
      armed: false,
      backoff: false,
      closed: false,
      fd,
      gated: false,
      pending: 0,
      queue: VecDeque::new(),
      waker: None,
    });
    let idx = listeners.len() - 1;
    drop(listeners);
    self.arm_accept(idx);
    Ok(idx)
  }

  /// Arms a multishot accept, or with direct descriptors close to running out, tops the listener
  /// up to `ACCEPT_DEPTH` one-shot accepts that each hold a slot of the table. A multishot accept
  /// takes whatever the backlog holds, and the connections it takes into a full table are dropped;
  /// one-shot accepts cost a submission per connection, so they are kept for the last
  /// `accept_margin` slots.
  fn arm_accept(&self, idx: usize) {
    let direct = self.params.direct_files > 0;
    let (fd, count) = {
      let mut listeners = self.listeners.borrow_mut();
      let listener = &mut listeners[idx];
      if listener.closed || listener.backoff || listener.armed {
        return;
      }
      let free = self.params.direct_files.saturating_sub(self.direct_open.get());
      if direct && free <= self.accept_margin() {
        let count = ACCEPT_DEPTH.saturating_sub(listener.pending).min(free);
        listener.gated = listener.pending + count < ACCEPT_DEPTH;
        if count == 0 {
          return;
        }
        listener.pending += count;
        self.direct_open.set(self.direct_open.get() + count);
        (listener.fd, count)
      } else {
        listener.armed = true;
        (listener.fd, 0)
      }
    };
    #[cfg(test)]
    self.accept_arms.set(self.accept_arms.get() + 1);
    if count > 0 {
      let sqe = opcode::Accept::new(types::Fd(fd), core::ptr::null_mut(), core::ptr::null_mut())
        .file_index(Some(types::DestinationSlot::auto_target()))
        .build()
        .user_data(user_data(KIND_ACCEPT, ONE_SHOT, idx as u32));
      for _ in 0..count {
        self.push_sqe(&sqe);
      }
    } else {
      let sqe = AcceptMulti::new(types::Fd(fd))
        .allocate_file_index(direct)
        .build()
        .user_data(user_data(KIND_ACCEPT, 0, idx as u32));
      self.push_sqe(&sqe);
    }
  }

  fn accept_margin(&self) -> u32 {
    (self.params.direct_files / 8).max(2 * ACCEPT_DEPTH)
  }

  fn on_accept(&self, idx: usize, one_shot: bool, res: i32, flags: u32) {
    let direct = self.params.direct_files > 0;
    let mut listeners = self.listeners.borrow_mut();
    let Some(listener) = listeners.get_mut(idx) else {
      return;
    };
    let more = !one_shot && cqueue::more(flags);
    if one_shot {
      listener.pending = listener.pending.saturating_sub(1);
    } else {
      if !more {
        listener.armed = false;
      }
      if direct && res >= 0 {
        self.direct_open.set(self.direct_open.get() + 1);
      }
    }
    if listener.closed {
      drop(listeners);
      if res >= 0 {
        self.close_accepted(res);
      } else if one_shot {
        self.release_direct();
      }
      return;
    }
    if res >= 0 {
      listener.queue.push_back(res);
      if let Some(elem) = listener.waker.take() {
        elem.wake();
      }
    }
    // Out of descriptors or memory: retrying at once would fail again.
    let backoff = res < 0
      && matches!(-res, libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
      && !listener.backoff;
    if backoff {
      listener.backoff = true;
    }
    drop(listeners);
    if res < 0 && one_shot {
      // The slot the accept held
      self.release_direct();
    }
    let free = self.params.direct_files.saturating_sub(self.direct_open.get());
    if backoff {
      let sqe = opcode::Timeout::new(&raw const self.backoff_ts).build().user_data(user_data(
        KIND_ACCEPT_RETRY,
        0,
        idx as u32,
      ));
      self.push_sqe(&sqe);
    } else if more && direct && free <= self.accept_margin() {
      // Close to running out: its last completion re-arms the listener with one-shot accepts.
      self.push_sqe(&cancel_sqe(user_data(KIND_ACCEPT, 0, idx as u32)));
    } else if !more {
      self.arm_accept(idx);
    }
  }

  fn on_accept_retry(&self, idx: usize) {
    if let Some(listener) = self.listeners.borrow_mut().get_mut(idx) {
      listener.backoff = false;
    }
    self.arm_accept(idx);
  }

  /// A slot of the direct descriptor table was freed: accepts that waited for one start again.
  fn release_direct(&self) {
    self.direct_open.set(self.direct_open.get().saturating_sub(1));
    let gated = self.listeners.borrow().iter().position(|el| el.gated && !el.closed);
    if let Some(first) = gated {
      let count = self.listeners.borrow().len();
      for idx in first..count {
        if self.listeners.borrow()[idx].gated {
          self.arm_accept(idx);
        }
      }
    }
  }

  /// Stops listening: the armed accepts are cancelled, and the connections they took that nobody
  /// claimed are closed, along with any they still complete.
  fn drop_listener(&self, idx: usize) {
    let (armed, fd, queue) = {
      let mut listeners = self.listeners.borrow_mut();
      let Some(listener) = listeners.get_mut(idx).filter(|el| !el.closed) else {
        return;
      };
      listener.closed = true;
      listener.waker = None;
      (listener.armed || listener.pending > 0, listener.fd, core::mem::take(&mut listener.queue))
    };
    for accepted in queue {
      self.close_accepted(accepted);
    }
    if armed {
      self.push_sqe(&cancel_sqe(user_data(KIND_ACCEPT, 0, idx as u32)));
      let target =
        types::CancelBuilder::user_data(user_data(KIND_ACCEPT, ONE_SHOT, idx as u32)).all();
      let sqe = opcode::AsyncCancel2::new(target)
        .build()
        .flags(squeue::Flags::SKIP_SUCCESS)
        .user_data(user_data(KIND_CANCEL, 0, 0));
      self.push_sqe(&sqe);
    }
    // SAFETY: closed once, here; the accepts still armed keep their own reference until cancelled
    let _rslt = unsafe { libc::close(fd) };
  }

  fn close_accepted(&self, fd: RawFd) {
    if self.params.direct_files > 0 {
      let sqe = opcode::Close::new(types::Fixed(fd as u32))
        .build()
        .flags(squeue::Flags::SKIP_SUCCESS)
        .user_data(user_data(KIND_CANCEL, 0, 0));
      self.push_sqe(&sqe);
      self.release_direct();
    } else {
      // SAFETY: an accepted socket that no handle owns
      let _rslt = unsafe { libc::close(fd) };
    }
  }

  fn poll_accept(&self, idx: usize, cx: &mut Context<'_>) -> Poll<crate::Result<RawFd>> {
    let mut listeners = self.listeners.borrow_mut();
    let Some(listener) = listeners.get_mut(idx) else {
      return Poll::Ready(Err(io_err(libc::EBADF)));
    };
    if let Some(fd) = listener.queue.pop_front() {
      return Poll::Ready(Ok(fd));
    }
    listener.waker = Some(cx.waker().clone());
    Poll::Pending
  }

  // ---- connections

  fn add_conn(
    &self,
    fd: RawFd,
    refs: u8,
    direct: bool,
    accepted: bool,
  ) -> crate::Result<(u32, u32)> {
    let tick = self.timers.borrow().tick;
    let (idx, generation) = {
      let mut conns = self.conns.borrow_mut();
      let idx = if let Some(idx) = self.free_conns.borrow_mut().pop() {
        idx
      } else {
        conns.push(Conn::default());
        (conns.len() - 1) as u32
      };
      let conn = &mut conns[idx as usize];
      conn.activity = 0;
      conn.cancel_sent = false;
      conn.closing = false;
      conn.direct = direct;
      conn.fd = fd;
      conn.in_use = true;
      conn.last_active = tick;
      conn.lingering = false;
      conn.reader = None;
      conn.refs = refs;
      conn.rx.clear();
      conn.rx_eof = false;
      conn.rx_err = 0;
      conn.rx_off = 0;
      conn.rx_paused = false;
      conn.sending = false;
      conn.tx_done = 0;
      conn.tx_err = 0;
      conn.tx_inflight.clear();
      conn.tx_pending.clear();
      conn.writer = None;
      (idx, conn.generation)
    };
    self.arm_recv(idx, generation, fd);
    let watch = {
      let mut timers = self.timers.borrow_mut();
      if accepted && timers.handshake_ticks > 0 {
        let deadline = tick.wrapping_add(timers.handshake_ticks).wrapping_add(1);
        timers.handshakes.push((idx, generation, deadline));
      }
      !timers.handshakes.is_empty() || timers.idle_ticks > 0
    };
    if watch {
      self.arm_timer();
    }
    Ok((idx, generation))
  }

  fn add_conn_ref(&self, idx: u32, generation: u32) -> crate::Result<()> {
    let mut conns = self.conns.borrow_mut();
    if let Some(conn) = conns.get_mut(idx as usize)
      && conn.generation == generation
    {
      conn.refs = conn.refs.wrapping_add(1);
    }
    Ok(())
  }

  fn conn_fd(&self, idx: u32, generation: u32) -> crate::Result<(RawFd, bool)> {
    let conns = self.conns.borrow();
    match conns.get(idx as usize) {
      Some(conn) if conn.generation == generation && conn.in_use => Ok((conn.fd, conn.direct)),
      _ => Err(io_err(libc::EBADF)),
    }
  }

  fn arm_recv(&self, idx: u32, generation: u32, fd: RawFd) {
    let mut direct = false;
    if let Some(conn) = self.conns.borrow_mut().get_mut(idx as usize) {
      conn.recv_armed = true;
      direct = conn.direct;
    }
    let sqe = if direct {
      opcode::RecvMulti::new(types::Fixed(fd as u32), BUF_GROUP).build()
    } else {
      opcode::RecvMulti::new(types::Fd(fd), BUF_GROUP).build()
    };
    self.push_sqe(&sqe.user_data(user_data(KIND_RECV, generation, idx)));
  }

  /// Returns `true` if a provided buffer was given back to the ring.
  fn on_recv(&self, idx: u32, generation: u32, res: i32, flags: u32) -> bool {
    let mut recycled = false;
    let mut conns = self.conns.borrow_mut();
    let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      if let Some(bid) = cqueue::buffer_select(flags) {
        self.bufs.borrow_mut().push(bid);
        recycled = true;
      }
      return recycled;
    };
    if res > 0 {
      conn.activity |= ACTIVE_RX;
      if let Some(bid) = cqueue::buffer_select(flags) {
        let bufs_len = self.bufs.borrow().len;
        let begin = usize::from(bid) * bufs_len;
        let len = res as usize;
        if conn.rx_off as usize == conn.rx.len() {
          conn.rx.clear();
          conn.rx_off = 0;
        }
        let bufs = self.bufs.borrow();
        conn.rx.extend_from_slice(bufs.mem.get(begin..begin + len).unwrap_or_default());
        drop(bufs);
        self.bufs.borrow_mut().push(bid);
        recycled = true;
        if conn.rx.len() - conn.rx_off as usize > self.params.rx_high_water && !conn.rx_paused {
          self.pause_recv(conn, idx, generation);
        }
      }
    } else if res == 0 {
      conn.rx_eof = true;
    } else if res == -libc::ENOBUFS {
      #[cfg(test)]
      let _ = tests::ENOBUFS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    } else if res != -libc::ECANCELED {
      conn.rx_err = errno(res);
    }
    if let Some(elem) = conn.reader.take() {
      elem.wake();
    }
    if !cqueue::more(flags) {
      conn.recv_armed = false;
      if conn.closing {
        let fd = conn.fd;
        drop(conns);
        self.maybe_close(idx, fd);
        return recycled;
      }
      if !conn.rx_eof && conn.rx_err == 0 && !conn.rx_paused {
        let fd = conn.fd;
        drop(conns);
        self.arm_recv(idx, generation, fd);
      }
    }
    recycled
  }

  /// Stops receiving into a connection that holds `rx_high_water` unread bytes: the rest waits in
  /// the socket. Completions already in flight still land in `rx`.
  #[cold]
  #[inline(never)]
  fn pause_recv(&self, conn: &mut Conn, idx: u32, generation: u32) {
    conn.rx_paused = true;
    if conn.recv_armed {
      self.push_sqe(&cancel_sqe(user_data(KIND_RECV, generation, idx)));
    }
  }

  /// Receives again into a paused connection once reads have taken it under half of
  /// `rx_high_water`.
  #[cold]
  #[inline(never)]
  fn maybe_resume_recv(&self, mut conns: core::cell::RefMut<'_, Vec<Conn>>, idx: u32) {
    let conn = &mut conns[idx as usize];
    if conn.rx.len() - conn.rx_off as usize > self.params.rx_high_water / 2 {
      return;
    }
    conn.rx_paused = false;
    // An armed receive is the one the pause is cancelling: its last completion re-arms it.
    if conn.recv_armed || conn.rx_eof || conn.rx_err != 0 || conn.closing {
      return;
    }
    let (fd, generation) = (conn.fd, conn.generation);
    drop(conns);
    self.arm_recv(idx, generation, fd);
  }

  fn poll_read(
    &self,
    idx: u32,
    generation: u32,
    bytes: &mut MaybeUninitSlice<'_, u8>,
    cx: &mut Context<'_>,
  ) -> Poll<crate::Result<Option<NonZeroUsize>>> {
    let mut conns = self.conns.borrow_mut();
    let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return Poll::Ready(Err(io_err(libc::EBADF)));
    };
    let rslt = take_rx(conn, bytes);
    if let Ok(TryRead::Pending | TryRead::Unsupported) = rslt {
      set_waker(&mut conn.reader, cx);
    }
    if conn.rx_paused {
      self.maybe_resume_recv(conns, idx);
    }
    match rslt {
      Ok(TryRead::Read(len)) => Poll::Ready(Ok(Some(len))),
      Ok(TryRead::Closed) => Poll::Ready(Ok(None)),
      Ok(TryRead::Pending | TryRead::Unsupported) => Poll::Pending,
      Err(err) => Poll::Ready(Err(err)),
    }
  }

  fn poll_readable(
    &self,
    idx: u32,
    generation: u32,
    cx: &mut Context<'_>,
  ) -> Poll<crate::Result<()>> {
    let mut conns = self.conns.borrow_mut();
    let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return Poll::Ready(Err(io_err(libc::EBADF)));
    };
    if conn.rx_off as usize != conn.rx.len() || conn.rx_err != 0 || conn.rx_eof {
      return Poll::Ready(Ok(()));
    }
    set_waker(&mut conn.reader, cx);
    Poll::Pending
  }

  fn try_read(
    &self,
    idx: u32,
    generation: u32,
    bytes: &mut MaybeUninitSlice<'_, u8>,
  ) -> crate::Result<TryRead> {
    let mut conns = self.conns.borrow_mut();
    let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return Err(io_err(libc::EBADF));
    };
    let rslt = take_rx(conn, bytes);
    if conn.rx_paused {
      self.maybe_resume_recv(conns, idx);
    }
    rslt
  }

  fn queue_send(&self, idx: u32, generation: u32, bytes: &[&[u8]]) -> crate::Result<()> {
    let mut conns = self.conns.borrow_mut();
    let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return Err(io_err(libc::EBADF));
    };
    if conn.tx_err != 0 {
      return Err(io_err(conn.tx_err.into()));
    }
    for elem in bytes {
      conn.tx_pending.extend_from_slice(elem);
    }
    if !conn.sending && !conn.tx_pending.is_empty() {
      drop(conns);
      self.start_send(idx, generation);
    }
    Ok(())
  }

  /// [`Self::queue_send`] only while the connection is under its high-water mark, so that a
  /// write that needn't wait for room skips the future: `false` queues nothing.
  fn try_queue_send(&self, idx: u32, generation: u32, bytes: &[&[u8]]) -> crate::Result<bool> {
    {
      let conns = self.conns.borrow();
      let Some(conn) = conns.get(idx as usize).filter(|el| el.generation == generation) else {
        return Err(io_err(libc::EBADF));
      };
      if conn.tx_err != 0 {
        return Err(io_err(conn.tx_err.into()));
      }
      if conn.tx_pending.len() >= self.params.tx_high_water {
        return Ok(false);
      }
    }
    self.queue_send(idx, generation, bytes)?;
    Ok(true)
  }

  fn start_send(&self, idx: u32, generation: u32) {
    let sqe = {
      let mut conns = self.conns.borrow_mut();
      let conn = &mut conns[idx as usize];
      core::mem::swap(&mut conn.tx_inflight, &mut conn.tx_pending);
      conn.tx_pending.clear();
      conn.tx_done = 0;
      conn.sending = true;
      send_sqe(conn, &conn.tx_inflight).user_data(user_data(KIND_SEND, generation, idx))
    };
    self.push_sqe(&sqe);
  }

  fn on_send(&self, idx: u32, generation: u32, res: i32) {
    let mut conns = self.conns.borrow_mut();
    let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return;
    };
    if res < 0 {
      // A timeout cancels the send: keep its `ETIMEDOUT`.
      if conn.tx_err == 0 {
        conn.tx_err = errno(res);
      }
      conn.sending = false;
      conn.tx_pending.clear();
    } else {
      conn.activity |= ACTIVE_TX;
      conn.tx_done += res as u32;
      // A timed-out connection sends nothing more, even if the cancel found the send half done.
      if (conn.tx_done as usize) < conn.tx_inflight.len() && conn.tx_err == 0 {
        let rest = conn.tx_inflight.get(conn.tx_done as usize..).unwrap_or_default();
        let sqe = send_sqe(conn, rest).user_data(user_data(KIND_SEND, generation, idx));
        drop(conns);
        self.push_sqe(&sqe);
        return;
      }
      conn.sending = false;
      conn.tx_inflight.clear();
    }
    if let Some(elem) = conn.writer.take() {
      elem.wake();
    }
    if !conn.tx_pending.is_empty() && conn.tx_err == 0 {
      drop(conns);
      self.start_send(idx, generation);
      return;
    }
    if conn.closing {
      let fd = conn.fd;
      drop(conns);
      self.maybe_close(idx, fd);
    }
  }

  fn poll_send_room(
    &self,
    idx: u32,
    generation: u32,
    cx: &mut Context<'_>,
  ) -> Poll<crate::Result<()>> {
    let mut conns = self.conns.borrow_mut();
    let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return Poll::Ready(Err(io_err(libc::EBADF)));
    };
    if conn.tx_err != 0 {
      return Poll::Ready(Err(io_err(conn.tx_err.into())));
    }
    if conn.tx_pending.len() < self.params.tx_high_water {
      return Poll::Ready(Ok(()));
    }
    conn.writer = Some(cx.waker().clone());
    Poll::Pending
  }

  fn drop_conn_ref(&self, idx: u32, generation: u32) {
    let fd = {
      let mut conns = self.conns.borrow_mut();
      let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
        return;
      };
      conn.refs = conn.refs.saturating_sub(1);
      if conn.refs > 0 {
        return;
      }
      conn.closing = true;
      conn.reader = None;
      conn.writer = None;
      conn.fd
    };
    self.maybe_close(idx, fd);
  }

  /// Closes a connection whose last handle was dropped once its sends are done and its receive
  /// is cancelled; the completions that are still due call this again.
  fn maybe_close(&self, idx: u32, fd: RawFd) {
    let mut conns = self.conns.borrow_mut();
    let conn = &mut conns[idx as usize];
    if conn.sending || !conn.tx_pending.is_empty() {
      if !conn.lingering {
        conn.lingering = true;
        let generation = conn.generation;
        drop(conns);
        self.linger(idx, generation);
      }
      return;
    }
    if conn.recv_armed {
      if conn.cancel_sent {
        return;
      }
      conn.cancel_sent = true;
      let target = user_data(KIND_RECV, conn.generation, idx);
      drop(conns);
      self.push_sqe(&cancel_sqe(target));
      return;
    }
    let direct = conn.direct;
    conn.in_use = false;
    conn.generation = conn.generation.wrapping_add(1) & 0x0FFF_FFFF;
    drop(conns);
    if direct {
      let sqe = opcode::Close::new(types::Fixed(fd as u32))
        .build()
        .flags(squeue::Flags::SKIP_SUCCESS)
        .user_data(user_data(KIND_CANCEL, 0, 0));
      self.push_sqe(&sqe);
    } else {
      // SAFETY: no operation on `fd` is in flight any more
      let _rslt = unsafe { libc::close(fd) };
    }
    self.free_conns.borrow_mut().push(idx);
    if direct {
      self.release_direct();
    }
  }

  // ---- timeouts

  /// Watches a dropped connection that still has bytes to send, for the close timeout.
  #[cold]
  #[inline(never)]
  fn linger(&self, idx: u32, generation: u32) {
    {
      let mut timers = self.timers.borrow_mut();
      if timers.close_ticks == 0 {
        return;
      }
      let tick = timers.tick;
      timers.lingering.push((idx, generation, tick));
    }
    self.arm_timer();
  }

  fn arm_timer(&self) {
    {
      let mut timers = self.timers.borrow_mut();
      if timers.armed {
        return;
      }
      timers.armed = true;
    }
    let sqe =
      opcode::Timeout::new(&raw const self.tick_ts).build().user_data(user_data(KIND_TIMER, 0, 0));
    self.push_sqe(&sqe);
  }

  /// One tick: times out the connections past a deadline, then re-arms the timer if anything is
  /// still watched. The handshake and close checks read the activity bits before the idle sweep
  /// clears them.
  fn on_tick(&self) {
    let mut timers = self.timers.borrow_mut();
    timers.armed = false;
    timers.tick = timers.tick.wrapping_add(1);
    let Timers { close_ticks, handshakes, idle_every, idle_ticks, lingering, tick, .. } =
      &mut *timers;
    let tick = *tick;
    let past = |deadline: u32| tick.wrapping_sub(deadline) as i32 >= 0;
    let mut conns = self.conns.borrow_mut();
    let live = |conns: &[Conn], idx: u32, generation: u32| {
      conns.get(idx as usize).is_some_and(|el| el.in_use && el.generation == generation)
    };
    handshakes.retain(|&(idx, generation, deadline)| {
      if !live(&conns, idx, generation) {
        return false;
      }
      let conn = &mut conns[idx as usize];
      if conn.activity & ACTIVE_TX != 0 || conn.closing {
        return false;
      }
      if past(deadline) {
        self.time_out(conn, idx);
        return false;
      }
      true
    });
    lingering.retain_mut(|(idx, generation, since)| {
      if !live(&conns, *idx, *generation) {
        return false;
      }
      let conn = &mut conns[*idx as usize];
      if conn.activity & ACTIVE_TX != 0 {
        conn.activity &= !ACTIVE_TX;
        *since = tick;
        return true;
      }
      if tick.wrapping_sub(*since) >= *close_ticks {
        self.time_out(conn, *idx);
        return false;
      }
      true
    });
    let mut open = false;
    if *idle_ticks > 0 && tick % *idle_every == 0 {
      for (idx, conn) in conns.iter_mut().enumerate() {
        if !conn.in_use {
          continue;
        }
        open = true;
        if conn.activity != 0 {
          conn.activity = 0;
          conn.last_active = tick;
        } else if tick.wrapping_sub(conn.last_active) >= *idle_ticks {
          self.time_out(conn, idx as u32);
        }
      }
    } else if *idle_ticks > 0 {
      open = conns.len() > self.free_conns.borrow().len();
    }
    drop(conns);
    let watch = open || !handshakes.is_empty() || !lingering.is_empty();
    drop(timers);
    if watch {
      self.arm_timer();
    }
  }

  /// Fails a connection's reads and writes with `ETIMEDOUT` and cancels what it has in flight,
  /// which also lets a dropped connection close.
  #[cold]
  #[inline(never)]
  fn time_out(&self, conn: &mut Conn, idx: u32) {
    let timed_out = libc::ETIMEDOUT as u8;
    if conn.rx_err == 0 {
      conn.rx_err = timed_out;
    }
    if conn.tx_err == 0 {
      conn.tx_err = timed_out;
    }
    conn.tx_pending.clear();
    if conn.recv_armed && !conn.cancel_sent {
      conn.cancel_sent = true;
      self.push_sqe(&cancel_sqe(user_data(KIND_RECV, conn.generation, idx)));
    }
    if conn.sending {
      self.push_sqe(&cancel_sqe(user_data(KIND_SEND, conn.generation, idx)));
    }
    if let Some(elem) = conn.reader.take() {
      elem.wake();
    }
    if let Some(elem) = conn.writer.take() {
      elem.wake();
    }
  }
}

fn send_sqe(conn: &Conn, bytes: &[u8]) -> squeue::Entry {
  let (ptr, len) = (bytes.as_ptr(), bytes.len() as u32);
  if conn.direct {
    opcode::Send::new(types::Fixed(conn.fd as u32), ptr, len).flags(libc::MSG_NOSIGNAL).build()
  } else {
    opcode::Send::new(types::Fd(conn.fd), ptr, len).flags(libc::MSG_NOSIGNAL).build()
  }
}

#[cfg(all(test, feature = "web-socket", feature = "crypto-ring"))]
mod tests {
  use crate::{
    collections::VectorUsize,
    executor::{Runtime, UringExecutor, UringRuntime, UringTcpListener},
    net::{TcpListener, TcpParams},
    rng::{ChaCha20, CryptoSeedableRng},
    tests::_uri,
    tls::{TlsAcceptor, TlsConfig},
    web_socket::{Fill, OpCode, WebSocketAcceptor, WebSocketPayloadOrigin},
  };
  use alloc::vec::Vec;
  use core::{future::poll_fn, task::Poll};
  use std::io::{Read, Write};

  // Sixteen texts with a ping in the middle sent in one write, then a close: the server echoes
  // through the write queue and the drain API, and the client must see every reply in order.
  #[test]
  fn pipelined_echo_ping_and_close() {
    pipelined_echo_ping_and_close_on(UringRuntime::new().unwrap());
  }

  #[test]
  fn pipelined_echo_ping_and_close_with_direct_files() {
    pipelined_echo_ping_and_close_on(
      UringRuntime::with_params(crate::executor::UringParams::new().set_direct_files(64)).unwrap(),
    );
  }

  fn pipelined_echo_ping_and_close_on(runtime: UringRuntime) {
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    let addr = alloc::format!("{host}:{port}");
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut stream = loop {
        if let Ok(elem) = std::net::TcpStream::connect(&client_addr) {
          break elem;
        }
        std::thread::sleep(core::time::Duration::from_millis(10));
      };
      stream
        .write_all(
          b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .unwrap();
      let mut res = Vec::new();
      while !res.windows(4).any(|el| el == b"\r\n\r\n") {
        let mut byte = [0; 1];
        stream.read_exact(&mut byte).unwrap();
        res.push(byte[0]);
      }
      assert!(res.starts_with(b"HTTP/1.1 101"));
      let frame = |op: u8, payload: &[u8]| {
        let mask = [1, 2, 3, 4];
        let mut elem = alloc::vec![0x80 | op, 0x80 | payload.len() as u8];
        elem.extend_from_slice(&mask);
        elem.extend(payload.iter().enumerate().map(|(idx, el)| el ^ mask[idx % 4]));
        elem
      };
      let mut burst = Vec::new();
      for idx in 0u8..16 {
        if idx == 8 {
          burst.extend(frame(0x9, b"p"));
        }
        burst.extend(frame(0x1, &[b'a' + idx]));
      }
      burst.extend(frame(0x8, &[3, 232]));
      stream.write_all(&burst).unwrap();
      let mut expected = Vec::new();
      for idx in 0u8..16 {
        if idx == 8 {
          expected.extend_from_slice(&[0x8A, 1, b'p']);
        }
        expected.extend_from_slice(&[0x81, 1, b'a' + idx]);
      }
      expected.extend_from_slice(&[0x88, 2, 3, 232]);
      let mut got = alloc::vec![0; expected.len()];
      stream.read_exact(&mut got).unwrap();
      assert_eq!(got, expected);
      // The server closed after its close reply.
      let mut rest = Vec::new();
      let _len = stream.read_to_end(&mut rest).unwrap();
      assert!(rest.is_empty());
    });
    runtime.block_on(async {
      let listener = UringTcpListener::bind(addr.as_str(), TcpParams::default()).await.unwrap();
      let (stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      let handler = async move {
        let mut ws = WebSocketAcceptor::default()
          .accept(TlsAcceptor::new(
            &TlsConfig::plaintext(),
            &mut ChaCha20::from_std_random().unwrap(),
            stream,
          ))
          .await
          .unwrap();
        let mut buffer = VectorUsize::new();
        let (mut common, mut reader, mut writer) = ws.split_mut();
        let origin = WebSocketPayloadOrigin::Adaptive;
        loop {
          while let Some(mut frame) =
            reader.read_buffered_frame(&mut buffer, &common, origin).unwrap()
          {
            if !writer.try_write_frame_buffered(&mut common, &mut frame).unwrap() {
              writer.write_frame_buffered(&mut common, &mut frame).await.unwrap();
            }
          }
          let mut frame = reader.read_frame(&mut buffer, &mut common, origin).await.unwrap();
          match frame.op_code() {
            OpCode::Text | OpCode::Binary => {
              writer.write_frame_buffered(&mut common, &mut frame).await.unwrap();
            }
            OpCode::Close => return,
            _ => {}
          }
        }
      };
      let handle = crate::executor::Executor::spawn_local(
        &UringExecutor::default(),
        handler,
        &UringRuntime::new().unwrap(),
      );
      handle.await.unwrap();
    });
    client.join().unwrap();
  }

  // ---- stress

  struct Gen(u64);

  impl Gen {
    fn next(&mut self) -> u64 {
      self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
      let mut z = self.0;
      z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
      z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
      z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
      if n == 0 { 0 } else { self.next() % n }
    }
  }

  fn client_frame(out: &mut Vec<u8>, fin: bool, op: u8, payload: &[u8], key: [u8; 4]) {
    out.push(if fin { 0x80 } else { 0 } | op);
    let len = payload.len();
    if len < 126 {
      out.push(0x80 | len as u8);
    } else if len <= 0xFFFF {
      out.push(0x80 | 126);
      out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
      out.push(0x80 | 127);
      out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&key);
    out.extend(payload.iter().enumerate().map(|(idx, el)| el ^ key[idx % 4]));
  }

  fn server_frame(out: &mut Vec<u8>, op: u8, payload: &[u8]) {
    out.push(0x80 | op);
    let len = payload.len();
    if len < 126 {
      out.push(len as u8);
    } else if len <= 0xFFFF {
      out.push(126);
      out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
      out.push(127);
      out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
  }

  // A spawned task that wakes itself while it is being polled, as a yield does, is polled
  // again: its future is out of its slot during the poll, and the wake used to be dropped.
  #[test]
  fn spawned_task_woken_during_its_own_poll() {
    let out = UringRuntime::new().unwrap().block_on(async {
      let task = async {
        yield_once().await;
        yield_once().await;
        7u8
      };
      let handle = crate::executor::Executor::spawn_local(
        &UringExecutor::default(),
        task,
        &UringRuntime::new().unwrap(),
      );
      handle.await.unwrap()
    });
    assert_eq!(out, 7);
  }

  async fn yield_once() {
    let mut yielded = false;
    poll_fn(|cx| {
      if yielded {
        return Poll::Ready(());
      }
      yielded = true;
      cx.waker().wake_by_ref();
      Poll::Pending
    })
    .await;
  }

  // A dropped listener stops listening: a connection it accepted but nobody took is closed, and
  // new connections are refused.
  fn dropped_listener_closes_on(runtime: UringRuntime) {
    use core::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Arc;
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    let addr = alloc::format!("{host}:{port}");
    let client_addr = addr.clone();
    let stage = Arc::new(AtomicU8::new(0));
    let client_stage = stage.clone();
    let client = std::thread::spawn(move || {
      let _first = loop {
        if let Ok(elem) = std::net::TcpStream::connect(&client_addr) {
          break elem;
        }
        std::thread::sleep(core::time::Duration::from_millis(5));
      };
      while client_stage.load(Ordering::Acquire) < 1 {
        std::thread::sleep(core::time::Duration::from_millis(1));
      }
      let mut second = std::net::TcpStream::connect(&client_addr).unwrap();
      client_stage.store(2, Ordering::Release);
      second.set_read_timeout(Some(core::time::Duration::from_secs(5))).unwrap();
      let mut byte = [0; 1];
      match second.read(&mut byte) {
        Ok(0) => {}
        Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("the unclaimed connection is still open: {other:?}"),
      }
      for _ in 0..200 {
        if std::net::TcpStream::connect(&client_addr).is_err() {
          return;
        }
        std::thread::sleep(core::time::Duration::from_millis(10));
      }
      panic!("the dropped listener still accepts connections");
    });
    runtime.block_on(async {
      let tcp_params = TcpParams::default().set_reuse_port(Some(false));
      let listener = UringTcpListener::bind(addr.as_str(), tcp_params).await.unwrap();
      let (first, _) = listener.accept(TcpParams::default()).await.unwrap();
      stage.store(1, Ordering::Release);
      while stage.load(Ordering::Acquire) < 2 {
        yield_once().await;
      }
      // Turns enough for the multishot accept to take the second connection off the backlog.
      for _ in 0..64 {
        yield_once().await;
      }
      drop(listener);
      while !client.is_finished() {
        yield_once().await;
      }
      drop(first);
    });
    client.join().unwrap();
  }

  #[test]
  fn dropped_listener_closes() {
    dropped_listener_closes_on(UringRuntime::new().unwrap());
  }

  #[test]
  fn dropped_listener_closes_with_direct_files() {
    dropped_listener_closes_on(
      UringRuntime::with_params(crate::executor::UringParams::new().set_direct_files(64)).unwrap(),
    );
  }

  enum Scenario {
    Normal,
    SlowReader,
    Reset,
    Flood,
  }

  // The bytes a client sends after the upgrade, and the bytes it must get back.
  fn script(rng: &mut Gen, scenario: &Scenario) -> (Vec<u8>, Vec<u8>) {
    let (mut send, mut expect) = (Vec::new(), Vec::new());
    let messages = match scenario {
      Scenario::Flood => 400,
      _ => 1 + rng.below(20),
    };
    for _ in 0..messages {
      let key = (rng.next() as u32).to_be_bytes();
      if rng.below(6) == 0 {
        let ping: Vec<u8> = (0..rng.below(126)).map(|_| rng.next() as u8).collect();
        client_frame(&mut send, true, 0x9, &ping, key);
        server_frame(&mut expect, 0xA, &ping);
        continue;
      }
      let len = match scenario {
        Scenario::Flood => rng.below(8) as usize,
        _ => match rng.below(10) {
          0 => 70_000 + rng.below(130_000) as usize,
          1..=3 => rng.below(4000) as usize,
          _ => rng.below(130) as usize,
        },
      };
      let text = rng.below(2) == 0;
      let payload: Vec<u8> = (0..len)
        .map(|_| if text { b'a' + (rng.below(26) as u8) } else { rng.next() as u8 })
        .collect();
      let op = if text { 0x1 } else { 0x2 };
      let parts = if len > 2 && rng.below(4) == 0 { 2 + rng.below(3) as usize } else { 1 };
      let step = len.div_ceil(parts);
      for (idx, chunk) in payload.chunks(step.max(1)).enumerate() {
        let last = (idx + 1) * step >= len;
        client_frame(&mut send, last, if idx == 0 { op } else { 0 }, chunk, key);
        if !last && rng.below(5) == 0 {
          client_frame(&mut send, true, 0x9, b"mid", key);
          server_frame(&mut expect, 0xA, b"mid");
        }
      }
      if len == 0 {
        client_frame(&mut send, true, op, &[], key);
      }
      server_frame(&mut expect, op, &payload);
    }
    let key = (rng.next() as u32).to_be_bytes();
    client_frame(&mut send, true, 0x8, &[3, 232], key);
    server_frame(&mut expect, 0x8, &[3, 232]);
    (send, expect)
  }

  fn run_client(addr: &str, seed: u64) {
    use std::os::fd::AsRawFd;
    let mut rng = Gen(seed);
    let scenario = match rng.below(10) {
      0 => Scenario::Reset,
      1 => Scenario::SlowReader,
      2 => Scenario::Flood,
      _ => Scenario::Normal,
    };
    let (send, expect) = script(&mut rng, &scenario);
    let mut stream = loop {
      if let Ok(elem) = std::net::TcpStream::connect(addr) {
        break elem;
      }
      std::thread::sleep(core::time::Duration::from_millis(5));
    };
    let small: libc::c_int = 4096;
    // SAFETY: valid socket and option buffer
    unsafe {
      libc::setsockopt(
        stream.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        (&raw const small).cast(),
        size_of::<libc::c_int>() as libc::socklen_t,
      );
    }
    stream
      .write_all(
        b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
      )
      .unwrap();
    let mut res = Vec::new();
    while !res.windows(4).any(|el| el == b"\r\n\r\n") {
      let mut byte = [0; 1];
      stream.read_exact(&mut byte).unwrap();
      res.push(byte[0]);
    }
    assert!(res.starts_with(b"HTTP/1.1 101"));
    if let Scenario::Reset = scenario {
      let cut = rng.below(send.len() as u64) as usize;
      stream.write_all(&send[..cut]).unwrap();
      let linger = libc::linger { l_onoff: 1, l_linger: 0 };
      // SAFETY: valid socket and option buffer
      unsafe {
        libc::setsockopt(
          stream.as_raw_fd(),
          libc::SOL_SOCKET,
          libc::SO_LINGER,
          (&raw const linger).cast(),
          size_of::<libc::linger>() as libc::socklen_t,
        );
      }
      return;
    }
    let slow = matches!(scenario, Scenario::SlowReader);
    let mut reader = stream.try_clone().unwrap();
    let reading = std::thread::spawn(move || {
      let mut got = Vec::new();
      let mut buf = [0; 8192];
      loop {
        if slow {
          std::thread::sleep(core::time::Duration::from_micros(200));
        }
        match reader.read(&mut buf) {
          Ok(0) | Err(_) => break,
          Ok(len) => got.extend_from_slice(&buf[..len]),
        }
      }
      got
    });
    let mut written = 0;
    while written < send.len() {
      let step = (1 + rng.below(70_000) as usize).min(send.len() - written);
      stream.write_all(&send[written..written + step]).unwrap();
      written += step;
    }
    let got = reading.join().unwrap();
    assert!(got == expect, "seed {seed}: got {} bytes, expected {}", got.len(), expect.len());
  }

  fn stress(params: crate::executor::UringParams, conns: u64, seed: u64) {
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    let addr = alloc::format!("{host}:{port}");
    let runtime = UringRuntime::with_params(params).unwrap();
    let client_addr = addr.clone();
    let clients = std::thread::spawn(move || {
      let handles: Vec<_> = (0..conns)
        .map(|idx| {
          let local_addr = client_addr.clone();
          std::thread::spawn(move || {
            run_client(&local_addr, seed.wrapping_mul(1000).wrapping_add(idx))
          })
        })
        .collect();
      for handle in handles {
        handle.join().unwrap();
      }
    });
    runtime.block_on(async {
      // Without `SO_REUSEPORT`, another test run on the same ports fails to bind instead of
      // quietly taking some of the connections.
      let tcp_params = TcpParams::default().set_reuse_port(Some(false));
      let listener = UringTcpListener::bind(addr.as_str(), tcp_params).await.unwrap();
      let mut handles = Vec::new();
      for _ in 0..conns {
        let (stream, _) = listener.accept(TcpParams::default()).await.unwrap();
        let handler = async move {
          let Ok(mut ws) = WebSocketAcceptor::default()
            .accept(TlsAcceptor::new(
              &TlsConfig::plaintext(),
              &mut ChaCha20::from_std_random().unwrap(),
              stream,
            ))
            .await
          else {
            return;
          };
          let mut buffer = VectorUsize::new();
          let (mut common, mut reader, mut writer) = ws.split_mut();
          let origin = WebSocketPayloadOrigin::Adaptive;
          loop {
            // `queue_frame` queues without the queue limit and `fill` waits without parsing, so
            // large frames, floods, resets and slow readers here exercise both.
            while let Ok(Some(mut frame)) = reader.read_buffered_frame(&mut buffer, &common, origin)
            {
              if !writer.queue_frame(&mut common, &mut frame).unwrap()
                && writer.write_frame_buffered(&mut common, &mut frame).await.is_err()
              {
                return;
              }
            }
            if writer.try_flush(&mut common).is_err() {
              return;
            }
            match reader.fill(&mut common).await {
              Ok(Fill::Buffered) => continue,
              Ok(Fill::ReadFrame) => {}
              Ok(Fill::Closed) | Err(_) => return,
            }
            let Ok(mut frame) = reader.read_frame(&mut buffer, &mut common, origin).await else {
              return;
            };
            match frame.op_code() {
              OpCode::Text | OpCode::Binary => {
                if writer.write_frame_buffered(&mut common, &mut frame).await.is_err() {
                  return;
                }
              }
              OpCode::Close => return,
              _ => {}
            }
          }
        };
        handles.push(crate::executor::Executor::spawn_local(
          &UringExecutor::default(),
          handler,
          &runtime,
        ));
      }
      for handle in handles {
        handle.await.unwrap();
      }
    });
    clients.join().unwrap();
    assert_eq!(runtime.open_conns(), 0, "connections left open");
  }

  fn stress_conns() -> u64 {
    std::env::var("WTX_STRESS_CONNS").ok().and_then(|el| el.parse().ok()).unwrap_or(48)
  }

  #[test]
  fn stress_default() {
    stress(crate::executor::UringParams::new(), stress_conns(), 1);
  }

  pub(super) static ENOBUFS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

  #[test]
  fn stress_starved_buffers_and_small_queue() {
    let params =
      crate::executor::UringParams::new().set_recv_buffers(8, 512).set_tx_high_water(16 * 1024);
    stress(params, stress_conns(), 2);
    let starved = ENOBUFS.load(core::sync::atomic::Ordering::Relaxed);
    std::eprintln!("receives that found the buffer ring empty: {starved}");
    assert!(starved > 0, "the ring was never exhausted, so the test didn't exercise it");
  }

  #[test]
  fn stress_direct_files() {
    let params = crate::executor::UringParams::new().set_direct_files(1024).set_peer_addrs(false);
    stress(params, stress_conns(), 3);
  }

  // ---- robustness

  fn test_addr() -> alloc::string::String {
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    alloc::format!("{host}:{port}")
  }

  fn connect(addr: &str) -> std::net::TcpStream {
    loop {
      if let Ok(elem) = std::net::TcpStream::connect(addr) {
        break elem;
      }
      std::thread::sleep(core::time::Duration::from_millis(5));
    }
  }

  fn set_sock_int(stream: &std::net::TcpStream, level: i32, name: i32, value: libc::c_int) {
    use std::os::fd::AsRawFd;
    // SAFETY: valid socket and option buffer
    unsafe {
      libc::setsockopt(
        stream.as_raw_fd(),
        level,
        name,
        (&raw const value).cast(),
        size_of::<libc::c_int>() as libc::socklen_t,
      );
    }
  }

  async fn bind(addr: &str) -> UringTcpListener {
    UringTcpListener::bind(addr, TcpParams::default().set_reuse_port(Some(false))).await.unwrap()
  }

  fn os_error(err: &crate::Error) -> Option<i32> {
    match err {
      crate::Error::Io(elem) => elem.raw_os_error(),
      _ => None,
    }
  }

  /// The most unread bytes any connection holds.
  fn max_unread() -> usize {
    super::with_reactor(|reactor| {
      Ok(
        reactor
          .conns
          .borrow()
          .iter()
          .filter(|el| el.in_use)
          .map(|el| el.rx.len() - el.rx_off as usize)
          .max()
          .unwrap_or(0),
      )
    })
    .unwrap()
  }

  // A peer that sends 8 MiB but reads nothing for a while: the echo stalls on writing, and the
  // connection stops receiving at its high-water mark instead of buffering everything. Once the
  // peer reads, every byte comes back in order.
  #[test]
  fn peer_that_stops_reading_is_held_at_the_high_water_mark() {
    use crate::net::{StreamReader, StreamWriter};
    const TOTAL: usize = 8 << 20;
    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut stream = connect(&client_addr);
      let mut writer = stream.try_clone().unwrap();
      let sending = std::thread::spawn(move || {
        let data: Vec<u8> = (0..TOTAL).map(|idx| (idx * 7 % 251) as u8).collect();
        Write::write_all(&mut writer, &data).unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
      });
      std::thread::sleep(core::time::Duration::from_millis(500));
      let mut got = Vec::new();
      let _len = stream.read_to_end(&mut got).unwrap();
      sending.join().unwrap();
      assert_eq!(got.len(), TOTAL);
      assert!(got.iter().enumerate().all(|(idx, el)| *el == (idx * 7 % 251) as u8));
    });
    let params = crate::executor::UringParams::new()
      .set_recv_buffers(64, 4096)
      .set_rx_high_water(16 * 1024)
      .set_tx_high_water(16 * 1024);
    let runtime = UringRuntime::with_params(params).unwrap();
    let peak = runtime.block_on(async {
      let listener = bind(&addr).await;
      let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      let echo = async move {
        let mut buf = alloc::vec![0; 4096];
        while let Some(len) = stream.read(buf.as_mut_slice().into()).await.unwrap() {
          stream.write_all(&buf[..len.get()]).await.unwrap();
        }
      };
      let handle =
        crate::executor::Executor::spawn_local(&UringExecutor::default(), echo, &runtime_ref());
      let mut peak = 0;
      while !client.is_finished() {
        peak = peak.max(max_unread());
        yield_once().await;
      }
      handle.await.unwrap();
      peak
    });
    // The receives that complete in the turn that crosses the mark still land: at most a ring
    // of buffers beyond it.
    assert!(peak <= 16 * 1024 + 64 * 4096, "{peak} unread bytes held");
    assert!(peak >= 16 * 1024, "the mark was never reached ({peak}), so nothing was tested");
    assert_eq!(runtime.open_conns(), 0);
  }

  fn runtime_ref() -> UringRuntime {
    UringRuntime::new().unwrap()
  }

  // A connection that receives and sends nothing fails its read with `ETIMEDOUT`.
  #[test]
  fn idle_connection_times_out() {
    use crate::net::StreamReader;
    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut stream = connect(&client_addr);
      let mut rest = Vec::new();
      let _rslt = stream.read_to_end(&mut rest);
    });
    let params = crate::executor::UringParams::new()
      .set_idle_timeout(Some(core::time::Duration::from_millis(100)));
    let runtime = UringRuntime::with_params(params).unwrap();
    let (errno, elapsed) = runtime.block_on(async {
      let listener = bind(&addr).await;
      let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      let begin = std::time::Instant::now();
      let mut buf = [0; 16];
      let err = stream.read(buf.as_mut_slice().into()).await.unwrap_err();
      (os_error(&err), begin.elapsed())
    });
    client.join().unwrap();
    assert_eq!(errno, Some(libc::ETIMEDOUT));
    assert!(elapsed >= core::time::Duration::from_millis(100), "{elapsed:?}");
    assert!(elapsed < core::time::Duration::from_secs(1), "{elapsed:?}");
    assert_eq!(runtime.open_conns(), 0);
  }

  // A client that trickles its request a byte at a time keeps the connection active, but never
  // gets an answer: the handshake timeout cuts it off. A connection that was answered is left
  // alone however long it then waits.
  #[test]
  fn handshake_timeout_cuts_off_a_trickling_client() {
    use crate::net::{StreamReader, StreamWriter};
    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut trickle = connect(&client_addr);
      let trickling = std::thread::spawn(move || {
        for _ in 0..50 {
          if Write::write_all(&mut trickle, b"x").is_err() {
            break;
          }
          std::thread::sleep(core::time::Duration::from_millis(20));
        }
      });
      let mut answered = connect(&client_addr);
      Write::write_all(&mut answered, b"q").unwrap();
      let mut byte = [0; 1];
      answered.read_exact(&mut byte).unwrap();
      trickling.join().unwrap();
      Write::write_all(&mut answered, b"r").unwrap();
      let mut rest = Vec::new();
      let _rslt = answered.read_to_end(&mut rest);
    });
    let params = crate::executor::UringParams::new()
      .set_handshake_timeout(Some(core::time::Duration::from_millis(200)));
    let runtime = UringRuntime::with_params(params).unwrap();
    let (errno, elapsed) = runtime.block_on(async {
      let listener = bind(&addr).await;
      let mut streams = Vec::new();
      for _ in 0..2 {
        streams.push(listener.accept(TcpParams::default()).await.unwrap().0);
      }
      let begin = std::time::Instant::now();
      let mut buf = [0; 16];
      // Tell the two apart: the answered one sends `q` first and waits.
      let (mut first, second) = (streams.remove(0), streams.remove(0));
      let len = first.read(buf.as_mut_slice().into()).await.unwrap().unwrap();
      let (mut trickle, mut answered) =
        if buf[..len.get()].contains(&b'q') { (second, first) } else { (first, second) };
      answered.write_all(b"a").await.unwrap();
      let err = loop {
        match trickle.read(buf.as_mut_slice().into()).await {
          Ok(Some(_)) => {}
          Ok(None) => panic!("closed before the timeout"),
          Err(err) => break err,
        }
      };
      let elapsed = begin.elapsed();
      // Past the timeout, the answered connection still reads.
      let mut got = Vec::new();
      while !got.contains(&b'r') {
        let len = answered.read(buf.as_mut_slice().into()).await.unwrap().unwrap();
        got.extend_from_slice(&buf[..len.get()]);
      }
      (os_error(&err), elapsed)
    });
    client.join().unwrap();
    assert_eq!(errno, Some(libc::ETIMEDOUT));
    assert!(elapsed >= core::time::Duration::from_millis(150), "{elapsed:?}");
    assert!(elapsed < core::time::Duration::from_secs(1), "{elapsed:?}");
  }

  // A connection dropped with 32 MiB still to send to a peer that never reads is closed once the
  // close timeout passes without progress, and `block_on` returns.
  #[test]
  fn dropped_connection_to_a_peer_that_never_reads_is_closed() {
    use crate::net::StreamWriter;
    let addr = test_addr();
    let client_addr = addr.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let client = std::thread::spawn(move || {
      let stream = connect(&client_addr);
      set_sock_int(&stream, libc::SOL_SOCKET, libc::SO_RCVBUF, 4096);
      let _rslt = done_rx.recv();
      drop(stream);
    });
    let params = crate::executor::UringParams::new()
      .set_close_timeout(Some(core::time::Duration::from_millis(100)));
    let runtime = UringRuntime::with_params(params).unwrap();
    let elapsed = runtime.block_on(async {
      let listener = bind(&addr).await;
      let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      stream.write_all(&alloc::vec![7; 32 << 20]).await.unwrap();
      drop(stream);
      let begin = std::time::Instant::now();
      while super::with_reactor(|reactor| Ok(reactor.conns.borrow().iter().any(|el| el.in_use)))
        .unwrap()
      {
        assert!(begin.elapsed() < core::time::Duration::from_secs(5), "never closed");
        yield_once().await;
      }
      begin.elapsed()
    });
    let _rslt = done_tx.send(());
    client.join().unwrap();
    assert!(elapsed >= core::time::Duration::from_millis(50), "{elapsed:?}");
    assert_eq!(runtime.open_conns(), 0);
  }

  // With two direct descriptors, the third and fourth connections wait in the backlog until one
  // is closed, instead of being accepted into a full table and dropped, and the accept isn't
  // re-armed in a loop meanwhile.
  #[test]
  fn accepts_wait_for_a_free_direct_descriptor() {
    use crate::net::StreamReader;
    let accept_arms = || super::with_reactor(|reactor| Ok(reactor.accept_arms.get())).unwrap();
    let addr = test_addr();
    let client_addr = addr.clone();
    let clients = std::thread::spawn(move || {
      let handles: Vec<_> = (0..4u8)
        .map(|id| {
          let local = client_addr.clone();
          std::thread::spawn(move || {
            let mut stream = connect(&local);
            stream.write_all(&[id]).unwrap();
            stream.set_read_timeout(Some(core::time::Duration::from_secs(10))).unwrap();
            let mut rest = Vec::new();
            // Served, then closed by the server: a clean end of stream, not a reset.
            let _len = stream.read_to_end(&mut rest).unwrap();
          })
        })
        .collect();
      for handle in handles {
        handle.join().unwrap();
      }
    });
    let params = crate::executor::UringParams::new().set_direct_files(2).set_peer_addrs(false);
    let runtime = UringRuntime::with_params(params).unwrap();
    let (ids, arms) = runtime.block_on(async {
      let listener = bind(&addr).await;
      let mut held = Vec::new();
      let mut ids = Vec::new();
      let mut buf = [0; 1];
      for _ in 0..2 {
        let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
        let _len = stream.read(buf.as_mut_slice().into()).await.unwrap();
        ids.push(buf[0]);
        held.push(stream);
      }
      let arms_before = accept_arms();
      let begin = std::time::Instant::now();
      while begin.elapsed() < core::time::Duration::from_millis(300) {
        yield_once().await;
      }
      let arms = accept_arms() - arms_before;
      for _ in 0..2 {
        drop(held.remove(0));
        let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
        let _len = stream.read(buf.as_mut_slice().into()).await.unwrap();
        ids.push(buf[0]);
        held.push(stream);
      }
      drop(held);
      (ids, arms)
    });
    clients.join().unwrap();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, [0, 1, 2, 3]);
    assert_eq!(arms, 0, "accepts were armed while the table was full");
    assert_eq!(runtime.open_conns(), 0);
  }

  // With 40 slots the accept starts multishot; the second wave takes the table within the margin,
  // so the listener switches to one-shot accepts that each hold a slot, and the last four
  // connections wait in the backlog instead of being dropped.
  #[test]
  fn accept_switches_to_reserved_one_shots_near_capacity() {
    use crate::net::StreamReader;
    use std::sync::mpsc;
    let addr = test_addr();
    let client_addr = addr.clone();
    let (wave_tx, wave_rx) = mpsc::channel::<()>();
    let clients = std::thread::spawn(move || {
      let spawn = |ids: core::ops::Range<u8>| -> Vec<_> {
        ids
          .map(|id| {
            let local = client_addr.clone();
            std::thread::spawn(move || {
              let mut stream = connect(&local);
              stream.write_all(&[id]).unwrap();
              stream.set_read_timeout(Some(core::time::Duration::from_secs(10))).unwrap();
              let mut rest = Vec::new();
              let _len = stream.read_to_end(&mut rest).unwrap();
            })
          })
          .collect()
      };
      let mut handles = spawn(0..10);
      wave_rx.recv().unwrap();
      handles.extend(spawn(10..44));
      for handle in handles {
        handle.join().unwrap();
      }
    });
    let params = crate::executor::UringParams::new().set_direct_files(40).set_peer_addrs(false);
    let runtime = UringRuntime::with_params(params).unwrap();
    let ids = runtime.block_on(async {
      let listener = bind(&addr).await;
      let mut held = Vec::new();
      let mut ids = Vec::new();
      let mut buf = [0; 1];
      for idx in 0..40 {
        if idx == 10 {
          wave_tx.send(()).unwrap();
        }
        let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
        let _len = stream.read(buf.as_mut_slice().into()).await.unwrap();
        ids.push(buf[0]);
        held.push(stream);
      }
      let begin = std::time::Instant::now();
      while begin.elapsed() < core::time::Duration::from_millis(300) {
        yield_once().await;
      }
      for _ in 0..4 {
        drop(held.remove(0));
        let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
        let _len = stream.read(buf.as_mut_slice().into()).await.unwrap();
        ids.push(buf[0]);
        held.push(stream);
      }
      drop(held);
      ids
    });
    clients.join().unwrap();
    let mut sorted = ids;
    sorted.sort_unstable();
    assert_eq!(sorted, (0..44).collect::<Vec<u8>>());
    assert_eq!(runtime.open_conns(), 0);
  }

  // Reading into an empty buffer would report the end of the stream: it fails instead, and the
  // bytes stay readable.
  #[test]
  fn reading_into_an_empty_buffer_is_an_error() {
    use crate::net::StreamReader;
    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut stream = connect(&client_addr);
      stream.write_all(b"ab").unwrap();
      let mut rest = Vec::new();
      let _rslt = stream.read_to_end(&mut rest);
    });
    let runtime = UringRuntime::new().unwrap();
    runtime.block_on(async {
      let listener = bind(&addr).await;
      let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      let mut buf = [0; 4];
      let len = stream.read(buf.get_mut(..1).unwrap().into()).await.unwrap().unwrap();
      assert_eq!(len.get(), 1);
      let err = stream.read((&mut buf[..0]).into()).await.unwrap_err();
      assert_eq!(os_error(&err), Some(libc::EINVAL));
      let len = stream.read(buf.as_mut_slice().into()).await.unwrap().unwrap();
      assert_eq!(&buf[..len.get()], b"b");
    });
    client.join().unwrap();
  }

  // A connection whose handle outlives the runtime is closed when the runtime is dropped.
  #[test]
  fn dropping_the_runtime_closes_connections_still_open() {
    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut stream = connect(&client_addr);
      stream.set_read_timeout(Some(core::time::Duration::from_secs(5))).unwrap();
      let mut rest = Vec::new();
      stream.read_to_end(&mut rest).unwrap();
    });
    let runtime = UringRuntime::new().unwrap();
    let stream = runtime.block_on(async {
      let listener = bind(&addr).await;
      listener.accept(TcpParams::default()).await.unwrap().0
    });
    drop(runtime);
    client.join().unwrap();
    drop(stream);
  }
}
