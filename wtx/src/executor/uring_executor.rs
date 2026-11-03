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
    ToSocketAddrs,
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
use io_uring::{IoUring, cqueue, opcode, squeue, types};
use std::os::fd::{IntoRawFd, RawFd};

const BUF_GROUP: u16 = 0;
const BUF_LEN: usize = 4096;
const BUFS: u16 = 512;
const CQ_ENTRIES: u32 = 4096;
const SQ_ENTRIES: u32 = 1024;
// A write waits for the connection's earlier bytes to be sent once this many are queued.
const TX_HIGH_WATER: usize = 4 * 1024 * 1024;

const KIND_RECV: u64 = 1;
const KIND_SEND: u64 = 2;
const KIND_ACCEPT: u64 = 3;
const KIND_CANCEL: u64 = 4;
const MAIN_TASK: usize = usize::MAX;

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
  /// A runtime with the given settings.
  #[inline]
  pub fn with_params(params: UringParams) -> crate::Result<Self> {
    let mut reactor = Reactor::new()?;
    reactor.params = params;
    Ok(Self { reactor: Box::new(reactor) })
  }
}

/// Settings of a [`UringRuntime`].
#[derive(Clone, Copy, Debug)]
pub struct UringParams {
  peer_addrs: bool,
  spin: Duration,
}

impl UringParams {
  /// Peer addresses resolved, no spinning.
  #[inline]
  pub const fn new() -> Self {
    Self { peer_addrs: true, spin: Duration::ZERO }
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
    Ok(Self { reactor: Box::new(Reactor::new()?) })
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
    if tcp_params.tcp_nodelay() != self.nodelay {
      set_nodelay(fd, tcp_params.tcp_nodelay())?;
    }
    let peer_addrs = with_reactor(|reactor| Ok(reactor.params.peer_addrs))?;
    let peer_addr = if peer_addrs {
      peer_addr(fd)?
    } else {
      SocketAddr::V4(core::net::SocketAddrV4::new(core::net::Ipv4Addr::UNSPECIFIED, 0))
    };
    let (idx, generation) = with_reactor(|reactor| reactor.add_conn(fd, 1))?;
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
    let (idx, generation) = with_reactor(|reactor| reactor.add_conn(fd, 1))?;
    Ok(Self { generation, idx })
  }

  #[inline]
  fn peer_addr(&self) -> crate::Result<SocketAddr> {
    let fd = with_reactor(|reactor| reactor.conn_fd(self.idx, self.generation))?;
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
}

async fn read(
  idx: u32,
  generation: u32,
  mut bytes: MaybeUninitSlice<'_, u8>,
) -> crate::Result<Option<NonZeroUsize>> {
  poll_fn(|cx| poll_reactor(|reactor| reactor.poll_read(idx, generation, &mut bytes, cx))).await
}

async fn write_all_vectored(idx: u32, generation: u32, bytes: &[&[u8]]) -> crate::Result<()> {
  with_reactor(|reactor| reactor.queue_send(idx, generation, bytes))?;
  poll_fn(|cx| poll_reactor(|reactor| reactor.poll_send_room(idx, generation, cx))).await
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

struct TaskSlot {
  future: Option<Rc<dyn RunTask>>,
  generation: u32,
  scheduled: bool,
}

#[derive(Default)]
struct Conn {
  cancel_sent: bool,
  closing: bool,
  fd: RawFd,
  generation: u32,
  in_use: bool,
  reader: Option<Waker>,
  recv_armed: bool,
  refs: u8,
  rx: Vec<u8>,
  rx_eof: bool,
  rx_err: i32,
  rx_off: usize,
  sending: bool,
  tx_done: usize,
  tx_err: i32,
  tx_inflight: Vec<u8>,
  tx_pending: Vec<u8>,
  writer: Option<Waker>,
}

struct ListenerState {
  armed: bool,
  fd: RawFd,
  queue: VecDeque<RawFd>,
  waker: Option<Waker>,
}

struct BufRing {
  entries: *mut u8,
  layout: Layout,
  mem: Vec<u8>,
  tail: u16,
}

impl BufRing {
  fn push(&mut self, bid: u16) {
    let idx = usize::from(self.tail & (BUFS - 1));
    let addr = self.mem.as_ptr() as u64 + u64::from(bid) * BUF_LEN as u64;
    // SAFETY: `entries` holds `BUFS` entries of 16 bytes: addr u64, len u32, bid u16, resv u16
    unsafe {
      let entry = self.entries.add(idx * 16);
      entry.cast::<u64>().write(addr);
      entry.add(8).cast::<u32>().write(BUF_LEN as u32);
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
  bufs: RefCell<BufRing>,
  cqes: RefCell<Vec<(u64, i32, u32)>>,
  conns: RefCell<Vec<Conn>>,
  free_conns: RefCell<Vec<u32>>,
  free_tasks: RefCell<Vec<u32>>,
  listeners: RefCell<Vec<ListenerState>>,
  main_woken: Cell<bool>,
  params: UringParams,
  ready: RefCell<VecDeque<usize>>,
  tasks: RefCell<Vec<TaskSlot>>,
}

impl core::fmt::Debug for Reactor {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Reactor").finish()
  }
}

impl Reactor {
  fn new() -> crate::Result<Self> {
    let ring = IoUring::builder()
      .setup_single_issuer()
      .setup_defer_taskrun()
      .setup_taskrun_flag()
      .setup_submit_all()
      .setup_cqsize(CQ_ENTRIES)
      .build(SQ_ENTRIES)?;
    let layout =
      Layout::from_size_align(usize::from(BUFS) * 16, 4096).map_err(|_err| io_err(libc::EINVAL))?;
    // SAFETY: `layout` has a non-zero size
    let entries = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if entries.is_null() {
      return Err(io_err(libc::ENOMEM));
    }
    let mut bufs =
      BufRing { entries, layout, mem: alloc::vec![0; usize::from(BUFS) * BUF_LEN], tail: 0 };
    // SAFETY: `entries` stays allocated, and registered, for as long as the ring
    unsafe {
      ring.submitter().register_buf_ring_with_flags(entries as u64, BUFS, BUF_GROUP, 0)?;
    }
    for bid in 0..BUFS {
      bufs.push(bid);
    }
    bufs.publish();
    Ok(Self {
      ring: RefCell::new(ring),
      bufs: RefCell::new(bufs),
      cqes: RefCell::new(Vec::with_capacity(CQ_ENTRIES as usize)),
      conns: RefCell::new(Vec::new()),
      free_conns: RefCell::new(Vec::new()),
      free_tasks: RefCell::new(Vec::new()),
      listeners: RefCell::new(Vec::new()),
      main_woken: Cell::new(false),
      params: UringParams::new(),
      ready: RefCell::new(VecDeque::new()),
      tasks: RefCell::new(Vec::new()),
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
    if let Some(slot) = tasks.get_mut(idx as usize)
      && slot.generation == generation
      && slot.future.is_some()
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
      if future.poll_task(&mut Context::from_waker(&waker)).is_ready() {
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
  }

  // ---- ring

  fn push_sqe(&self, sqe: &squeue::Entry) {
    let mut ring = self.ring.borrow_mut();
    // SAFETY: every buffer an entry points to lives in a `Conn` or `BufRing` until its completion
    while unsafe { ring.submission().push(sqe) }.is_err() {
      let _rslt = ring.submit();
    }
  }

  fn enter(&self, wait: bool) {
    let mut ring = self.ring.borrow_mut();
    if !wait {
      let _rslt = ring.submit();
      return;
    }
    if !self.params.spin.is_zero() {
      let _rslt = ring.submit();
      let begin = std::time::Instant::now();
      let mut iter: u32 = 0;
      loop {
        let pending = {
          let sq = ring.submission();
          sq.taskrun() || sq.cq_overflow()
        } || !ring.completion().is_empty();
        if pending {
          let _rslt = ring.submit();
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
        KIND_ACCEPT => self.on_accept(idx as usize, res, flags),
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
    listeners.push(ListenerState { armed: false, fd, queue: VecDeque::new(), waker: None });
    let idx = listeners.len() - 1;
    drop(listeners);
    self.arm_accept(idx);
    Ok(idx)
  }

  fn arm_accept(&self, idx: usize) {
    let fd = {
      let mut listeners = self.listeners.borrow_mut();
      let listener = &mut listeners[idx];
      listener.armed = true;
      listener.fd
    };
    let sqe = opcode::AcceptMulti::new(types::Fd(fd)).build().user_data(user_data(
      KIND_ACCEPT,
      0,
      idx as u32,
    ));
    self.push_sqe(&sqe);
  }

  fn on_accept(&self, idx: usize, res: i32, flags: u32) {
    let rearm = {
      let mut listeners = self.listeners.borrow_mut();
      let Some(listener) = listeners.get_mut(idx) else {
        return;
      };
      if res >= 0 {
        listener.queue.push_back(res);
        if let Some(elem) = listener.waker.take() {
          elem.wake();
        }
      }
      if !cqueue::more(flags) {
        listener.armed = false;
      }
      !listener.armed
    };
    if rearm {
      self.arm_accept(idx);
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

  fn add_conn(&self, fd: RawFd, refs: u8) -> crate::Result<(u32, u32)> {
    let (idx, generation) = {
      let mut conns = self.conns.borrow_mut();
      let idx = if let Some(idx) = self.free_conns.borrow_mut().pop() {
        idx
      } else {
        conns.push(Conn::default());
        (conns.len() - 1) as u32
      };
      let conn = &mut conns[idx as usize];
      conn.cancel_sent = false;
      conn.closing = false;
      conn.fd = fd;
      conn.in_use = true;
      conn.reader = None;
      conn.refs = refs;
      conn.rx.clear();
      conn.rx_eof = false;
      conn.rx_err = 0;
      conn.rx_off = 0;
      conn.sending = false;
      conn.tx_done = 0;
      conn.tx_err = 0;
      conn.tx_inflight.clear();
      conn.tx_pending.clear();
      conn.writer = None;
      (idx, conn.generation)
    };
    self.arm_recv(idx, generation, fd);
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

  fn conn_fd(&self, idx: u32, generation: u32) -> crate::Result<RawFd> {
    let conns = self.conns.borrow();
    match conns.get(idx as usize) {
      Some(conn) if conn.generation == generation && conn.in_use => Ok(conn.fd),
      _ => Err(io_err(libc::EBADF)),
    }
  }

  fn arm_recv(&self, idx: u32, generation: u32, fd: RawFd) {
    if let Some(conn) = self.conns.borrow_mut().get_mut(idx as usize) {
      conn.recv_armed = true;
    }
    let sqe = opcode::RecvMulti::new(types::Fd(fd), BUF_GROUP)
      .build()
      .user_data(user_data(KIND_RECV, generation, idx));
    self.push_sqe(&sqe);
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
      if let Some(bid) = cqueue::buffer_select(flags) {
        let begin = usize::from(bid) * BUF_LEN;
        let len = res as usize;
        if conn.rx_off == conn.rx.len() {
          conn.rx.clear();
          conn.rx_off = 0;
        }
        let bufs = self.bufs.borrow();
        conn.rx.extend_from_slice(bufs.mem.get(begin..begin + len).unwrap_or_default());
        drop(bufs);
        self.bufs.borrow_mut().push(bid);
        recycled = true;
      }
    } else if res == 0 {
      conn.rx_eof = true;
    } else if res != -libc::ENOBUFS && res != -libc::ECANCELED {
      conn.rx_err = -res;
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
      if !conn.rx_eof && conn.rx_err == 0 {
        let fd = conn.fd;
        drop(conns);
        self.arm_recv(idx, generation, fd);
      }
    }
    recycled
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
    let available = conn.rx.get(conn.rx_off..).unwrap_or_default();
    if !available.is_empty() {
      let dst = bytes.uninitialized_mut();
      let len = available.len().min(dst.len());
      // SAFETY: `dst` has room for `len` bytes, and the regions don't overlap
      unsafe {
        core::ptr::copy_nonoverlapping(available.as_ptr(), dst.as_mut_ptr().cast(), len);
      }
      conn.rx_off += len;
      if conn.rx_off == conn.rx.len() {
        conn.rx.clear();
        conn.rx_off = 0;
      }
      return Poll::Ready(Ok(NonZeroUsize::new(len)));
    }
    if conn.rx_err != 0 {
      return Poll::Ready(Err(io_err(conn.rx_err)));
    }
    if conn.rx_eof {
      return Poll::Ready(Ok(None));
    }
    if !conn.reader.as_ref().is_some_and(|el| el.will_wake(cx.waker())) {
      conn.reader = Some(cx.waker().clone());
    }
    Poll::Pending
  }

  fn queue_send(&self, idx: u32, generation: u32, bytes: &[&[u8]]) -> crate::Result<()> {
    let mut conns = self.conns.borrow_mut();
    let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return Err(io_err(libc::EBADF));
    };
    if conn.tx_err != 0 {
      return Err(io_err(conn.tx_err));
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

  fn start_send(&self, idx: u32, generation: u32) {
    let sqe = {
      let mut conns = self.conns.borrow_mut();
      let conn = &mut conns[idx as usize];
      core::mem::swap(&mut conn.tx_inflight, &mut conn.tx_pending);
      conn.tx_pending.clear();
      conn.tx_done = 0;
      conn.sending = true;
      opcode::Send::new(
        types::Fd(conn.fd),
        conn.tx_inflight.as_ptr(),
        conn.tx_inflight.len() as u32,
      )
      .flags(libc::MSG_NOSIGNAL)
      .build()
      .user_data(user_data(KIND_SEND, generation, idx))
    };
    self.push_sqe(&sqe);
  }

  fn on_send(&self, idx: u32, generation: u32, res: i32) {
    let mut conns = self.conns.borrow_mut();
    let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return;
    };
    if res < 0 {
      conn.tx_err = -res;
      conn.sending = false;
      conn.tx_pending.clear();
    } else {
      conn.tx_done += res as usize;
      if conn.tx_done < conn.tx_inflight.len() {
        let rest = conn.tx_inflight.get(conn.tx_done..).unwrap_or_default();
        let sqe = opcode::Send::new(types::Fd(conn.fd), rest.as_ptr(), rest.len() as u32)
          .flags(libc::MSG_NOSIGNAL)
          .build()
          .user_data(user_data(KIND_SEND, generation, idx));
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
      return Poll::Ready(Err(io_err(conn.tx_err)));
    }
    if conn.tx_pending.len() < TX_HIGH_WATER {
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
      return;
    }
    if conn.recv_armed {
      if conn.cancel_sent {
        return;
      }
      conn.cancel_sent = true;
      let target = user_data(KIND_RECV, conn.generation, idx);
      drop(conns);
      let sqe = opcode::AsyncCancel::new(target).build().user_data(user_data(KIND_CANCEL, 0, 0));
      self.push_sqe(&sqe);
      return;
    }
    // SAFETY: no operation on `fd` is in flight any more
    let _rslt = unsafe { libc::close(fd) };
    conn.in_use = false;
    conn.generation = conn.generation.wrapping_add(1) & 0x0FFF_FFFF;
    drop(conns);
    self.free_conns.borrow_mut().push(idx);
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
    web_socket::{OpCode, WebSocketAcceptor, WebSocketPayloadOrigin},
  };
  use alloc::vec::Vec;
  use std::io::{Read, Write};

  // Sixteen texts with a ping in the middle sent in one write, then a close: the server echoes
  // through the write queue and the drain API, and the client must see every reply in order.
  #[test]
  fn pipelined_echo_ping_and_close() {
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    let addr = alloc::format!("{host}:{port}");
    let runtime = UringRuntime::new().unwrap();
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
}
