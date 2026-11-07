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
//! Wakers can be woken, and handles dropped, from any thread: what reaches a runtime from another
//! thread goes through its inbox, which wakes the ring. A stream is only read or written on the
//! runtime that made it; elsewhere it fails with `EBADF`.

use crate::{
  collections::MaybeUninitSlice,
  executor::{Executor, ExecutorError, ExecutorTy, Runtime, resolve_addrs, tcp_listener_std},
  net::{
    Stream, StreamCommon, StreamReader, StreamWriter, TcpListener, TcpParams, TcpStream,
    ToSocketAddrs, TryRead,
  },
};
use alloc::{alloc::Global, boxed::Box, collections::VecDeque, rc::Rc, vec::Vec};
use core::{
  alloc::{AllocError, Allocator, AllocatorClone, Layout},
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
const KIND_DOORBELL: u64 = 7;
const KIND_SLEEP: u64 = 8;
const KIND_CONNECT: u64 = 9;
// One-shot accepts kept armed per listener with direct descriptors close to running out
const ACCEPT_DEPTH: u32 = 16;
// The `generation` of a one-shot accept's `user_data`; a multishot accept's is 0.
const ONE_SHOT: u32 = 1;

// `Conn::activity` bits: something was received, something was sent.
const ACTIVE_RX: u8 = 1;
const ACTIVE_TX: u8 = 2;
const ACTIVE_ANY: u8 = ACTIVE_RX | ACTIVE_TX;
// Not activity: a kernel TLS alert waits in `Conn::tls_alert` for the sends before it to finish.
// It sits in the same byte so that the send completion, which reads it, touches no other line.
const TLS_ALERT_PENDING: u8 = 4;
// `tx_inflight` came from `try_send_owned`: its buffer goes to `Reactor::send_pool` once sent
const TX_OWNED: u8 = 8;
// Sent buffers kept for `try_send_owned` to hand out, most recently used first, so the ones a
// thread writes into stay in its caches. Bigger buffers are freed. With many connections more
// sends are in flight than a small pool holds, and the connections that found it empty grew
// fresh buffers by doubling, copying at each step.
//
// The pool also takes the larger buffers of closed connections, and gives them to the receives and
// copied writes that would grow a buffer, so a connection that moves large bodies doesn't grow new
// ones by doubling when an earlier one left them. With no connection open it keeps its most recent
// `SEND_POOL_IDLE_KEEP` buffers within `SEND_POOL_IDLE_BYTES`: enough for connections that come
// one after the other, without the largest outputs of a burst held for good.
const SEND_POOL_MAX: usize = 64;
const SEND_POOL_BUFFER_MAX: usize = 1 << 20;
const SEND_POOL_IDLE_KEEP: usize = 4;
const SEND_POOL_IDLE_BYTES: usize = 1 << 20;
// A free slot keeps a buffer up to this capacity for the next connection, and gives a larger one
// to the pool.
const SLOT_BUFFER_KEEP: usize = 64 * 1024;
// Room the handshake and lingering lists start with, so that connections accepted between two
// ticks don't grow them as they come.
const TIMER_LIST_CAPACITY: usize = 1024;
// Free slots that keep their buffers however few connections are open; more stay warm while more
// are open.
const WARM_FREE_MIN: usize = 64;
// A connection's offsets into its buffers are `u32`s, so that its hot fields fit two cache lines.
// These keep them under 4 GiB: one send covers at most `MAX_SEND` bytes, and the sent ones are
// dropped from the front once they pass it. Unread received bytes stay under the high-water mark
// plus what the completions of a turn or two bring, at most twice the receive ring; the read ones
// are dropped from the front once they outnumber the unread ones and pass `RX_COMPACT`.
const MAX_SEND: usize = 1 << 30;
const MAX_RX_HIGH_WATER: usize = 512 << 20;
const MAX_RECV_RING: usize = 512 << 20;
const RX_COMPACT: usize = 32 * 1024;
// Refused submissions in a row, with the queue full or waiting for completions, after which the
// ring is taken to be broken.
const SUBMIT_TRIES: u32 = 1024;

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
  /// See [`UringStats`].
  #[inline]
  #[must_use]
  pub fn stats(&self) -> UringStats {
    self.reactor.stats()
  }

  #[cfg(test)]
  fn open_conns(&self) -> usize {
    self.reactor.conns.borrow().iter().filter(|conn| conn.in_use).count()
  }

  /// A runtime with the given settings.
  #[inline]
  pub fn with_params(params: UringParams) -> crate::Result<Self> {
    let reactor = Box::new(Reactor::new(params)?);
    // Once boxed: the read points into the reactor
    reactor.arm_doorbell();
    Ok(Self { reactor })
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
  send_submit_bytes: usize,
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
      handshake_timeout: Some(Duration::from_secs(10)),
      idle_timeout: Some(Duration::from_secs(300)),
      peer_addrs: true,
      recv_buffer_len: 4096,
      recv_buffers: 512,
      rx_high_water: 64 * 1024,
      send_submit_bytes: 16 * 1024,
      spin: Duration::ZERO,
      sq_entries: 1024,
      tx_high_water: 16 * 1024,
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
  /// 10 s.
  #[inline]
  #[must_use]
  pub const fn set_handshake_timeout(mut self, value: Option<Duration>) -> Self {
    self.handshake_timeout = value;
    self
  }

  /// How long an accepted connection may go without receiving or sending anything. Past that, its
  /// reads and writes fail with `ETIMEDOUT`. A peer that only listens should be pinged: the pongs
  /// keep it alive. Connections this runtime opened with `connect` are not watched. Connections
  /// are checked many times per timeout, from one timer per runtime. Defaults to 300 s.
  #[inline]
  #[must_use]
  pub const fn set_idle_timeout(mut self, value: Option<Duration>) -> Self {
    self.idle_timeout = value;
    self
  }

  /// How many received bytes a connection can hold that nobody has read before it stops
  /// receiving, which leaves the rest in the socket and lets TCP slow the peer down. It receives
  /// again once reads take it under half of that. Defaults to 64 KiB, at most 512 MiB.
  #[inline]
  #[must_use]
  pub const fn set_rx_high_water(mut self, value: usize) -> Self {
    self.rx_high_water = if value > MAX_RX_HIGH_WATER { MAX_RX_HIGH_WATER } else { value };
    self
  }

  /// The ring of buffers that receives are made into: `count` buffers (rounded up to a power of
  /// two, at most 32768, the kernel's limit) of `len` bytes each, shared by the connections of a
  /// runtime. Received bytes are copied out as soon as they complete, so the ring only has to
  /// cover one turn. `len` is lowered to keep the ring within 512 MiB. Defaults to 512 of 4096
  /// bytes.
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

  /// How many bytes the sends queued during a turn may add up to before they are submitted at
  /// once, rather than with everything else at the end of the turn. A busy turn produces output
  /// for many connections; submitted together, the first buffers are out of the CPU's caches by
  /// the time the kernel copies them, and that copy costs several times more. `0` submits every
  /// send as it is queued and `usize::MAX` only at the end of the turn. Defaults to 16 KiB, the
  /// default send threshold: static-h2 measured 23% faster than at 128 KiB at 1024 connections,
  /// json-h2c 1-2% slower (a few more submits).
  #[inline]
  #[must_use]
  pub const fn set_send_submit_bytes(mut self, value: usize) -> Self {
    self.send_submit_bytes = value;
    self
  }

  /// How many written bytes a connection can have waiting to be sent before a write waits for
  /// them. Defaults to 16 KiB: past that a caller keeps its output until there is room (an HTTP/2
  /// connection keeps response bodies as references), then writes or seals it into buffers still
  /// in the cache. More waiting per connection measured slower: static-h2 at 256 KiB ran 17% below
  /// 16 KiB, as the waiting bytes were copied into buffers out of the cache.
  ///
  /// A peer that stops reading holds about twice this per connection (the bytes being sent and
  /// those queued behind them), plus the largest single write, until a timeout closes it.
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

/// What a [`UringRuntime`] has seen since it started: counts of the events an operator wants to
/// watch. Taken with [`UringRuntime::stats`], or [`uring_stats`] from inside a task.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct UringStats {
  /// Connections accepted.
  pub accepted: u64,
  /// Accepts that failed with something other than a connection that went away.
  pub accept_errors: u64,
  /// Times accepting paused 100 ms after such a failure.
  pub accept_backoffs: u64,
  /// Completions the kernel had to hold back because the completion ring was full. More than a
  /// few means the ring is too small (see [`UringParams::set_ring_entries`]).
  pub cq_overflows: u64,
  /// Messages from other threads: wakes and dropped handles.
  pub remote_messages: u64,
  /// Connections open now.
  pub open_connections: u64,
  /// Receives that found every provided buffer in use (see [`UringParams::set_recv_buffers`]).
  pub recv_buffers_exhausted: u64,
  /// Times a connection stopped receiving because its unread bytes reached the high-water mark.
  pub recv_pauses: u64,
  /// Submissions the kernel refused.
  pub submit_errors: u64,
  /// Tasks that panicked.
  pub task_panics: u64,
  /// Connections cut off by a handshake, idle or close timeout.
  pub timeouts: u64,
  /// Timers ([`crate::futures::Sleep`]) on the ring now: armed, or dropped and waiting for the
  /// kernel to confirm their removal. Back to 0 once nothing waits.
  pub timers_pending: u64,
  /// Slots of the table of timers, which follows the most timers ever pending at once.
  pub timer_slots: u64,
  /// Open connections with a reader waiting on them (a read, `readable` or `peer_ended`): at most
  /// one each, however many times their futures are made again.
  pub waiting_readers: u64,
}

/// Submissions the runtime running on this thread has queued, if any.
#[cfg(test)]
pub(crate) fn sqes_pushed() -> Option<u64> {
  let reactor = CURRENT.with(Cell::get);
  // SAFETY: set by `block_on`, which outlives everything it polls
  unsafe { reactor.as_ref() }.map(|el| el.sqes_pushed.get())
}

/// The [`UringStats`] of the runtime running on this thread, if any.
#[inline]
#[must_use]
pub fn uring_stats() -> Option<UringStats> {
  let reactor = CURRENT.with(Cell::get);
  // SAFETY: set by `block_on`, which outlives everything it polls
  unsafe { reactor.as_ref() }.map(Reactor::stats)
}

#[derive(Default)]
struct Counters {
  accept_backoffs: Cell<u64>,
  accept_errors: Cell<u64>,
  accepted: Cell<u64>,
  recv_buffers_exhausted: Cell<u64>,
  recv_pauses: Cell<u64>,
  remote_messages: Cell<u64>,
  submit_errors: Cell<u64>,
  task_panics: Cell<u64>,
  timeouts: Cell<u64>,
}

fn bump(counter: &Cell<u64>) {
  counter.set(counter.get().wrapping_add(1));
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
    Self::with_params(UringParams::new())
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
    let main_waker = waker(waker_data(reactor.slot(), 0, MAIN_TASK));
    reactor.main_woken.set(true);
    loop {
      if reactor.main_woken.replace(false)
        && let Poll::Ready(elem) = future.as_mut().poll(&mut Context::from_waker(&main_waker))
      {
        reactor.check_ring();
        reactor.finish_closing();
        return elem;
      }
      reactor.run_ready();
      reactor.check_ring();
      let idle = !reactor.main_woken.get() && reactor.ready.borrow().is_empty();
      reactor.enter(idle);
      reactor.reap();
    }
  }
}

/// Clears a flag when dropped, so a panic doesn't leave it set.
struct ClearOnDrop<'flag>(&'flag Cell<bool>);

impl Drop for ClearOnDrop<'_> {
  #[inline]
  fn drop(&mut self) {
    self.0.set(false);
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
  task: Option<TaskRc<dyn JoinTask<T>>>,
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
    task.poll_join(cx)
  }
}

// ---- task allocations

/// A spawned task's allocation, from [`TaskAlloc`].
type TaskRc<T> = Rc<T, TaskAlloc>;

// Ended tasks' blocks a thread keeps for the next tasks, most recent last: at most this many, of
// at most this many bytes in all, and with no connection open (see `Reactor::trim_free_slots`)
// the most recent `TASK_POOL_IDLE_KEEP` within `TASK_POOL_IDLE_BYTES`. A block is one of a size
// class (its size rounded up to `TASK_CLASS`); tasks larger than `TASK_BLOCK_MAX`, or aligned
// beyond `TASK_CLASS`, are not pooled.
const TASK_POOL_MAX: usize = 256;
const TASK_POOL_BYTES: usize = 2 << 20;
const TASK_POOL_IDLE_KEEP: usize = 4;
const TASK_POOL_IDLE_BYTES: usize = 256 << 10;
const TASK_CLASS: usize = 64;
const TASK_BLOCK_MAX: usize = 64 << 10;

/// Allocates the tasks spawned on a runtime from the blocks of the tasks that ended on its thread,
/// so that a server that spawns a task per connection allocates nothing for it once warm (the
/// tasks of one server are of one size). A block is zeroed when it comes back: a task's future may
/// have held a connection's secrets, which the next task must not find.
#[derive(Clone, Copy, Debug, Default)]
struct TaskAlloc;

/// The blocks of ended tasks: pointer and size, each allocated with [`task_class`].
struct TaskPool {
  blocks: Vec<(core::ptr::NonNull<u8>, usize)>,
  bytes: usize,
}

impl TaskPool {
  /// Frees the oldest blocks until at most `keep` are left, of at most `bytes`.
  fn trim(&mut self, keep: usize, bytes: usize) {
    while self.blocks.len() > keep || self.bytes > bytes {
      let (ptr, size) = self.blocks.remove(0);
      self.bytes = self.bytes.wrapping_sub(size);
      // SAFETY: a block of the pool, allocated with this layout and owned by it
      unsafe { Global.deallocate(ptr, Layout::from_size_align_unchecked(size, TASK_CLASS)) };
    }
  }
}

impl Drop for TaskPool {
  fn drop(&mut self) {
    self.trim(0, 0);
  }
}

std::thread_local! {
  static TASK_POOL: RefCell<TaskPool> =
    const { RefCell::new(TaskPool { blocks: Vec::new(), bytes: 0 }) };
}

/// The layout a task's block is allocated with, if it is pooled.
fn task_class(layout: Layout) -> Option<Layout> {
  if layout.align() > TASK_CLASS || layout.size() == 0 || layout.size() > TASK_BLOCK_MAX {
    return None;
  }
  Layout::from_size_align(layout.size().next_multiple_of(TASK_CLASS), TASK_CLASS).ok()
}

/// Trims this thread's task pool: see `TASK_POOL_IDLE_KEEP`.
fn trim_task_pool(keep: usize, bytes: usize) {
  let _rslt = TASK_POOL.try_with(|pool| {
    if let Ok(mut elem) = pool.try_borrow_mut() {
      elem.trim(keep, bytes);
    }
  });
}

// SAFETY: blocks come from `Global` with the layout `task_class` gives (or the caller's, for those
// not pooled) and go back to it with that layout; a pooled block is handed out once, and is the
// pool's alone until then.
unsafe impl Allocator for TaskAlloc {
  #[inline]
  fn allocate(&self, layout: Layout) -> Result<core::ptr::NonNull<[u8]>, AllocError> {
    let Some(class) = task_class(layout) else {
      return Global.allocate(layout);
    };
    let pooled = TASK_POOL
      .try_with(|pool| {
        let mut pool = pool.try_borrow_mut().ok()?;
        let idx = pool.blocks.iter().rposition(|el| el.1 == class.size())?;
        let (ptr, size) = pool.blocks.remove(idx);
        pool.bytes = pool.bytes.wrapping_sub(size);
        Some(ptr)
      })
      .ok()
      .flatten();
    let ptr = match pooled {
      Some(elem) => elem,
      None => Global.allocate(class)?.cast(),
    };
    Ok(core::ptr::NonNull::slice_from_raw_parts(ptr, class.size()))
  }

  #[inline]
  unsafe fn deallocate(&self, ptr: core::ptr::NonNull<u8>, layout: Layout) {
    let Some(class) = task_class(layout) else {
      // SAFETY: allocated by `Global` with this layout, in `allocate`
      unsafe { Global.deallocate(ptr, layout) };
      return;
    };
    // SAFETY: the block has `class.size()` bytes, all of them the caller's to give back
    unsafe { ptr.as_ptr().write_bytes(0, class.size()) };
    // The zeroes are written before the block can be handed out again, whatever is inlined.
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let kept = TASK_POOL
      .try_with(|pool| {
        let Ok(mut pool) = pool.try_borrow_mut() else {
          return false;
        };
        let bytes = pool.bytes.wrapping_add(class.size());
        if pool.blocks.len() >= TASK_POOL_MAX || bytes > TASK_POOL_BYTES {
          return false;
        }
        pool.blocks.push((ptr, class.size()));
        pool.bytes = bytes;
        true
      })
      .unwrap_or(false);
    if !kept {
      // SAFETY: allocated by `Global` with `class`, in `allocate`
      unsafe { Global.deallocate(ptr, class) };
    }
  }
}

// SAFETY: every `TaskAlloc` is the same allocator: a block one allocates, any other frees.
unsafe impl AllocatorClone for TaskAlloc {}

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
  Panicked,
  Running(F),
}

trait RunTask {
  fn poll_task(&self, cx: &mut Context<'_>) -> Poll<()>;

  /// Ends a task whose poll panicked: its future is dropped and its join handle gets
  /// `TaskPanicked`.
  fn end_panicked(&self);
}

trait JoinTask<T> {
  fn poll_join(&self, cx: &mut Context<'_>) -> Poll<crate::Result<T>>;
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

  #[cold]
  fn end_panicked(&self) {
    // The unwind released the poll's borrow.
    let Ok(mut inner) = self.inner.try_borrow_mut() else {
      return;
    };
    inner.0 = TaskState::Panicked;
    let waker = inner.1.take();
    drop(inner);
    if let Some(elem) = waker {
      elem.wake();
    }
  }
}

impl<F> JoinTask<F::Output> for TaskCell<F>
where
  F: Future,
{
  #[inline]
  fn poll_join(&self, cx: &mut Context<'_>) -> Poll<crate::Result<F::Output>> {
    let mut inner = self.inner.borrow_mut();
    match &mut inner.0 {
      TaskState::Done(value) => {
        if let Some(elem) = value.take() {
          return Poll::Ready(Ok(elem));
        }
      }
      TaskState::Panicked => return Poll::Ready(Err(ExecutorError::TaskPanicked.into())),
      TaskState::Running(_) => {}
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
  runtime: u32,
}

impl Drop for UringTcpListener {
  #[inline]
  fn drop(&mut self) {
    match own_reactor(self.runtime) {
      Some(reactor) => reactor.drop_listener(self.idx),
      None => send_to_runtime(self.runtime, Message::DropListener(self.idx)),
    }
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
    let (idx, runtime) = with_reactor(|reactor| Ok((reactor.add_listener(fd)?, reactor.id)))?;
    Ok(Self { idx, nodelay: tcp_params.tcp_nodelay(), runtime })
  }

  /// A connection its peer already reset or closed is closed and skipped, as are the ones whose
  /// setup fails: their sockets are never left open.
  #[inline]
  async fn accept(&self, tcp_params: TcpParams) -> crate::Result<(Self::TcpStream, SocketAddr)> {
    loop {
      let runtime = self.runtime;
      let fd = poll_fn(|cx| poll_own_reactor(runtime, |reactor| reactor.poll_accept(self.idx, cx)))
        .await?;
      let params = with_reactor(|reactor| Ok(reactor.params))?;
      let direct = params.direct_files > 0;
      let setup = (|| {
        if !direct && tcp_params.tcp_nodelay() != self.nodelay {
          set_nodelay(fd, tcp_params.tcp_nodelay())?;
        }
        if params.peer_addrs && !direct {
          peer_addr(fd)
        } else {
          Ok(SocketAddr::V4(core::net::SocketAddrV4::new(core::net::Ipv4Addr::UNSPECIFIED, 0)))
        }
      })();
      match setup {
        Ok(peer_addr) => {
          let conn = with_reactor(|reactor| reactor.add_conn(fd, 1, direct, true))?;
          return Ok((UringTcpStream { conn }, peer_addr));
        }
        Err(err) => {
          with_reactor(|reactor| {
            reactor.close_accepted(fd);
            #[cfg(test)]
            reactor.accept_setup_failures.set(reactor.accept_setup_failures.get() + 1);
            Ok(())
          })?;
          if !peer_gone(&err) {
            return Err(err);
          }
        }
      }
    }
  }
}

/// A connected socket. See the [module documentation](self).
#[derive(Debug)]
pub struct UringTcpStream {
  conn: ConnRef,
}

impl Drop for UringTcpStream {
  #[inline]
  fn drop(&mut self) {
    drop_conn_ref(self.conn);
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
    let conn = self.conn;
    core::mem::forget(self);
    with_own_reactor(conn.runtime, |reactor| reactor.add_conn_ref(conn.idx, conn.generation))?;
    Ok(((), UringReadHalf { conn }, UringWriteHalf { conn }))
  }
}

impl StreamCommon for UringTcpStream {
  #[cfg(feature = "tls")]
  #[inline]
  fn with_kernel_tls(
    &mut self,
    cb: impl FnOnce(RawFd) -> crate::Result<bool>,
  ) -> crate::Result<bool> {
    let conn = self.conn;
    match with_own_reactor(conn.runtime, |reactor| {
      Ok(reactor.kernel_tls_fd(conn.idx, conn.generation))
    })? {
      Some(fd) => cb(fd),
      None => Ok(false),
    }
  }
}

impl StreamReader for UringTcpStream {
  #[inline]
  async fn read(&mut self, bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<Option<NonZeroUsize>> {
    read(self.conn, bytes).await
  }

  #[inline]
  fn try_read(&mut self, bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<TryRead> {
    try_read(self.conn, bytes)
  }

  #[inline]
  fn readable(&mut self) -> impl Future<Output = crate::Result<()>> {
    readable(self.conn)
  }

  #[inline]
  fn peer_ended(&mut self) -> impl Future<Output = crate::Result<()>> {
    peer_ended(self.conn)
  }

  #[cfg(feature = "tls")]
  #[inline]
  fn read_kernel_tls_record(&mut self, buffer: &mut [u8]) -> crate::Result<(u8, usize)> {
    read_kernel_tls_record(self.conn, buffer)
  }
}

impl StreamWriter for UringTcpStream {
  #[inline]
  async fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
    write_all_vectored(self.conn, &[bytes]).await
  }

  #[inline]
  async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<()> {
    write_all_vectored(self.conn, bytes).await
  }

  #[inline]
  fn try_write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<bool> {
    try_write_all_vectored(self.conn, bytes)
  }

  #[inline]
  fn try_send_owned(&mut self, bytes: &mut Vec<u8>) -> crate::Result<bool> {
    try_send_owned(self.conn, bytes)
  }

  #[inline]
  fn try_send_with(
    &mut self,
    len: usize,
    write: &mut dyn FnMut(&mut Vec<u8>) -> crate::Result<()>,
  ) -> crate::Result<bool> {
    let conn = self.conn;
    with_own_reactor(conn.runtime, |reactor| {
      reactor.try_queue_send_with(conn.idx, conn.generation, len, write)
    })
  }

  #[inline]
  async fn send_room(&mut self) -> crate::Result<bool> {
    let conn = self.conn;
    poll_fn(|cx| {
      poll_own_reactor(conn.runtime, |reactor| reactor.poll_send_room(conn.idx, conn.generation, cx))
    })
    .await?;
    Ok(true)
  }

  #[cfg(feature = "tls")]
  #[inline]
  fn send_kernel_tls_alert(&mut self, level: u8, description: u8) -> crate::Result<()> {
    let conn = self.conn;
    with_own_reactor(conn.runtime, |reactor| {
      reactor.send_kernel_tls_alert(conn.idx, conn.generation, level, description)
    })
  }
}

impl TcpStream for UringTcpStream {
  type Executor = UringExecutor;

  /// Connects through the ring, trying each address `addr` resolves to in turn. Names are
  /// resolved on a thread of their own, so neither step holds up the runtime's other tasks.
  #[inline]
  async fn connect<A>(addr: A, tcp_params: TcpParams) -> crate::Result<Self>
  where
    A: ToSocketAddrs,
  {
    let fd = resolve_addrs(addr, &UringExecutor::default(), async |socket_addr| {
      UringConnect::new(socket_addr)?.await
    })
    .await?;
    let nodelay = libc::c_int::from(tcp_params.tcp_nodelay());
    // SAFETY: `nodelay` outlives the call and its size is passed
    let rslt = unsafe {
      libc::setsockopt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_NODELAY,
        (&raw const nodelay).cast(),
        size_of::<libc::c_int>() as libc::socklen_t,
      )
    };
    if rslt != 0 {
      let err = std::io::Error::last_os_error();
      // SAFETY: a connected socket that nothing else owns
      let _rslt = unsafe { libc::close(fd) };
      return Err(err.into());
    }
    let conn = with_reactor(|reactor| reactor.add_conn(fd, 1, false, false))?;
    Ok(Self { conn })
  }

  #[inline]
  fn peer_addr(&self) -> crate::Result<SocketAddr> {
    let conn = self.conn;
    let (fd, direct) =
      with_own_reactor(conn.runtime, |reactor| reactor.conn_fd(conn.idx, conn.generation))?;
    if direct {
      return Err(io_err(libc::EOPNOTSUPP));
    }
    peer_addr(fd)
  }
}

/// Reading part of a split [`UringTcpStream`].
#[derive(Debug)]
pub struct UringReadHalf {
  conn: ConnRef,
}

impl Drop for UringReadHalf {
  #[inline]
  fn drop(&mut self) {
    drop_conn_ref(self.conn);
  }
}

impl StreamCommon for UringReadHalf {}

impl StreamReader for UringReadHalf {
  #[inline]
  async fn read(&mut self, bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<Option<NonZeroUsize>> {
    read(self.conn, bytes).await
  }

  #[inline]
  fn try_read(&mut self, bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<TryRead> {
    try_read(self.conn, bytes)
  }

  #[inline]
  fn readable(&mut self) -> impl Future<Output = crate::Result<()>> {
    readable(self.conn)
  }

  #[inline]
  fn peer_ended(&mut self) -> impl Future<Output = crate::Result<()>> {
    peer_ended(self.conn)
  }

  #[cfg(feature = "tls")]
  #[inline]
  fn read_kernel_tls_record(&mut self, buffer: &mut [u8]) -> crate::Result<(u8, usize)> {
    read_kernel_tls_record(self.conn, buffer)
  }
}

/// Writing part of a split [`UringTcpStream`].
#[derive(Debug)]
pub struct UringWriteHalf {
  conn: ConnRef,
}

impl Drop for UringWriteHalf {
  #[inline]
  fn drop(&mut self) {
    drop_conn_ref(self.conn);
  }
}

impl StreamCommon for UringWriteHalf {}

impl StreamWriter for UringWriteHalf {
  #[inline]
  async fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
    write_all_vectored(self.conn, &[bytes]).await
  }

  #[inline]
  async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<()> {
    write_all_vectored(self.conn, bytes).await
  }

  #[inline]
  fn try_write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<bool> {
    try_write_all_vectored(self.conn, bytes)
  }

  #[inline]
  fn try_send_owned(&mut self, bytes: &mut Vec<u8>) -> crate::Result<bool> {
    try_send_owned(self.conn, bytes)
  }

  #[inline]
  fn try_send_with(
    &mut self,
    len: usize,
    write: &mut dyn FnMut(&mut Vec<u8>) -> crate::Result<()>,
  ) -> crate::Result<bool> {
    let conn = self.conn;
    with_own_reactor(conn.runtime, |reactor| {
      reactor.try_queue_send_with(conn.idx, conn.generation, len, write)
    })
  }

  #[inline]
  async fn send_room(&mut self) -> crate::Result<bool> {
    let conn = self.conn;
    poll_fn(|cx| {
      poll_own_reactor(conn.runtime, |reactor| reactor.poll_send_room(conn.idx, conn.generation, cx))
    })
    .await?;
    Ok(true)
  }

  #[cfg(feature = "tls")]
  #[inline]
  fn send_kernel_tls_alert(&mut self, level: u8, description: u8) -> crate::Result<()> {
    let conn = self.conn;
    with_own_reactor(conn.runtime, |reactor| {
      reactor.send_kernel_tls_alert(conn.idx, conn.generation, level, description)
    })
  }
}

/// A timer of the runtime running on this thread: one timeout on its ring. Created by
/// `futures::Sleep` when that runtime is current.
#[derive(Debug)]
pub(crate) struct UringSleep {
  duration: Duration,
  // Slot, generation and runtime, once the first poll armed it
  armed: Option<(u32, u32, u32)>,
}

impl UringSleep {
  /// `None` if no `UringRuntime` runs on this thread.
  pub(crate) fn new(duration: Duration) -> Option<Self> {
    (!CURRENT.with(Cell::get).is_null()).then_some(Self { duration, armed: None })
  }
}

impl Future for UringSleep {
  type Output = crate::Result<()>;

  #[inline]
  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let Some((idx, generation, runtime)) = self.armed else {
      let duration = self.duration;
      let armed = with_reactor(|reactor| {
        let (idx, generation) = reactor.add_sleep(duration, cx);
        Ok((idx, generation, reactor.id))
      });
      return match armed {
        Ok(elem) => {
          self.armed = Some(elem);
          Poll::Pending
        }
        Err(err) => Poll::Ready(Err(err)),
      };
    };
    // Polled on another runtime, it can't reach its timeout: it reports itself done.
    poll_own_reactor(runtime, |reactor| reactor.poll_sleep(idx, generation, cx))
      .map(|el| el.or(Ok(())))
  }
}

impl Drop for UringSleep {
  #[inline]
  fn drop(&mut self) {
    if let Some((idx, generation, runtime)) = self.armed
      && let Some(reactor) = own_reactor(runtime)
    {
      reactor.drop_sleep(idx, generation);
    }
  }
}

/// A connect submitted to the ring. Resolves to the connected socket, which the caller then owns.
struct UringConnect {
  addr: SocketAddr,
  // Until the first poll hands it to the reactor
  fd: Option<RawFd>,
  // Slot, generation and runtime, from the first poll until the result is taken
  armed: Option<(u32, u32, u32)>,
}

impl UringConnect {
  fn new(addr: SocketAddr) -> crate::Result<Self> {
    let family = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    // SAFETY: no pointers involved
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
      return Err(std::io::Error::last_os_error().into());
    }
    Ok(Self { addr, fd: Some(fd), armed: None })
  }
}

impl Future for UringConnect {
  type Output = crate::Result<RawFd>;

  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    if let Some(fd) = self.fd {
      let addr = self.addr;
      let armed = with_reactor(|reactor| {
        let (idx, generation) = reactor.add_connect(fd, &addr, cx);
        Ok((idx, generation, reactor.id))
      });
      // The slot owns the socket from here, or nobody would close it.
      self.fd = None;
      return match armed {
        Ok(elem) => {
          self.armed = Some(elem);
          Poll::Pending
        }
        Err(err) => {
          // SAFETY: never handed out
          let _rslt = unsafe { libc::close(fd) };
          Poll::Ready(Err(err))
        }
      };
    }
    let Some((idx, generation, runtime)) = self.armed else {
      return Poll::Ready(Err(crate::Error::FuturePolledAfterFinalization));
    };
    let poll = poll_own_reactor(runtime, |reactor| reactor.poll_connect(idx, generation, cx));
    if poll.is_ready() {
      self.armed = None;
    }
    poll
  }
}

impl Drop for UringConnect {
  fn drop(&mut self) {
    if let Some(fd) = self.fd {
      // SAFETY: never handed out
      let _rslt = unsafe { libc::close(fd) };
    }
    if let Some((idx, generation, runtime)) = self.armed
      && let Some(reactor) = own_reactor(runtime)
    {
      reactor.drop_connect(idx, generation);
    }
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectState {
  Armed,
  // Its future was dropped before it completed; the slot waits for the kernel's completion.
  Dropped,
  Done,
  Free,
}

struct ConnectSlot {
  // Boxed, so that it stays put until the kernel is done with it, however `connects` grows
  addr: Box<libc::sockaddr_storage>,
  fd: RawFd,
  generation: u32,
  res: i32,
  state: ConnectState,
  waker: Option<Waker>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SleepState {
  Armed,
  // Its handle was dropped before it fired; the slot waits for the kernel's completion.
  Dropped,
  Fired,
  Free,
}

struct SleepSlot {
  generation: u32,
  state: SleepState,
  // Boxed, so that it stays put until the kernel copies it at submission, however `sleeps` grows
  ts: Box<types::Timespec>,
  waker: Option<Waker>,
}

/// A connection of one runtime: its slot, the slot's generation and the runtime's id. Every use
/// checks the runtime, so a handle moved to another runtime fails instead of reaching that
/// runtime's connection in the same slot.
#[derive(Clone, Copy, Debug)]
struct ConnRef {
  generation: u32,
  idx: u32,
  runtime: u32,
}

async fn read(
  conn: ConnRef,
  mut bytes: MaybeUninitSlice<'_, u8>,
) -> crate::Result<Option<NonZeroUsize>> {
  poll_fn(|cx| {
    poll_own_reactor(conn.runtime, |reactor| {
      reactor.poll_read(conn.idx, conn.generation, &mut bytes, cx)
    })
  })
  .await
}

fn try_read(conn: ConnRef, mut bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<TryRead> {
  with_own_reactor(conn.runtime, |reactor| reactor.try_read(conn.idx, conn.generation, &mut bytes))
}

#[cfg(feature = "tls")]
fn read_kernel_tls_record(conn: ConnRef, buffer: &mut [u8]) -> crate::Result<(u8, usize)> {
  with_own_reactor(conn.runtime, |reactor| {
    reactor.read_kernel_tls_record(conn.idx, conn.generation, buffer)
  })
}

// A plain `fn`: the future holds the ids and nothing else.
fn readable(conn: ConnRef) -> impl Future<Output = crate::Result<()>> {
  poll_fn(move |cx| {
    poll_own_reactor(conn.runtime, |reactor| reactor.poll_readable(conn.idx, conn.generation, cx))
  })
}

fn peer_ended(conn: ConnRef) -> impl Future<Output = crate::Result<()>> {
  poll_fn(move |cx| {
    poll_own_reactor(conn.runtime, |reactor| reactor.poll_peer_ended(conn.idx, conn.generation, cx))
  })
}

async fn write_all_vectored(conn: ConnRef, bytes: &[&[u8]]) -> crate::Result<()> {
  with_own_reactor(conn.runtime, |reactor| reactor.queue_send(conn.idx, conn.generation, bytes))?;
  poll_fn(|cx| {
    poll_own_reactor(conn.runtime, |reactor| reactor.poll_send_room(conn.idx, conn.generation, cx))
  })
  .await
}

fn try_write_all_vectored(conn: ConnRef, bytes: &[&[u8]]) -> crate::Result<bool> {
  with_own_reactor(conn.runtime, |reactor| reactor.try_queue_send(conn.idx, conn.generation, bytes))
}

fn try_send_owned(conn: ConnRef, bytes: &mut Vec<u8>) -> crate::Result<bool> {
  with_own_reactor(conn.runtime, |reactor| {
    reactor.try_queue_send_owned(conn.idx, conn.generation, bytes)
  })
}

/// Drops a handle's reference on its own runtime, or, from anywhere else, asks that runtime to.
fn drop_conn_ref(conn: ConnRef) {
  match own_reactor(conn.runtime) {
    Some(reactor) => reactor.drop_conn_ref(conn.idx, conn.generation),
    None => send_to_runtime(conn.runtime, Message::DropConn(conn.idx, conn.generation)),
  }
}

/// The runtime running on this thread, if it is the one with this id.
fn own_reactor<'any>(runtime: u32) -> Option<&'any Reactor> {
  let reactor = CURRENT.with(Cell::get);
  // SAFETY: set by `block_on`, which outlives everything it polls
  unsafe { reactor.as_ref() }.filter(|el| el.id == runtime)
}

fn with_own_reactor<T>(
  runtime: u32,
  cb: impl FnOnce(&Reactor) -> crate::Result<T>,
) -> crate::Result<T> {
  with_reactor(|reactor| if reactor.id == runtime { cb(reactor) } else { Err(io_err(libc::EBADF)) })
}

fn poll_own_reactor<T>(
  runtime: u32,
  cb: impl FnOnce(&Reactor) -> Poll<crate::Result<T>>,
) -> Poll<crate::Result<T>> {
  poll_reactor(|reactor| {
    if reactor.id == runtime { cb(reactor) } else { Poll::Ready(Err(io_err(libc::EBADF))) }
  })
}

pub(crate) fn spawn_on_current<F>(future: F) -> UringJoinHandle<F::Output>
where
  F: Future + 'static,
  F::Output: 'static,
{
  let reactor = CURRENT.with(Cell::get);
  if reactor.is_null() {
    return UringJoinHandle { task: None };
  }
  let cell =
    Rc::new_in(TaskCell { inner: RefCell::new((TaskState::Running(future), None)) }, TaskAlloc);
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

/// Whether an error setting up an accepted socket only says its peer is already gone.
fn peer_gone(err: &crate::Error) -> bool {
  matches!(
    err,
    crate::Error::Io(elem)
      if matches!(elem.raw_os_error(), Some(libc::ENOTCONN | libc::ECONNRESET | libc::ECONNABORTED))
  )
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

// ---- wakers
//
// A waker's data is plain bits, so cloning and dropping one costs nothing: the runtime's slot in
// `RUNTIMES` (12 bits), the task's generation (24 bits) and its index (28 bits; `MAIN_TASK` for
// the future `block_on` runs). Woken on the thread of its runtime, a waker schedules its task
// directly. Woken anywhere else, it queues the wake in that runtime's inbox and rings the
// runtime's eventfd.

#[cfg(not(target_pointer_width = "64"))]
compile_error!("UringExecutor packs runtime, generation and task index into a 64-bit waker");

const IDX_BITS: u32 = 28;
const GEN_BITS: u32 = 24;
const IDX_MASK: usize = (1 << IDX_BITS) - 1;
const GEN_MASK: u32 = (1 << GEN_BITS) - 1;
const MAIN_TASK: usize = IDX_MASK;
// At most this many runtimes at once, one slot each
const RUNTIME_SLOTS: usize = 4096;

static VTABLE: RawWakerVTable =
  RawWakerVTable::new(waker_clone, waker_wake, waker_wake, waker_drop);

fn waker(data: usize) -> Waker {
  // SAFETY: the vtable functions don't dereference `data`
  unsafe { Waker::from_raw(RawWaker::new(data as *const (), &VTABLE)) }
}

const fn waker_data(slot: usize, generation: u32, idx: usize) -> usize {
  (slot << (IDX_BITS + GEN_BITS)) | (((generation & GEN_MASK) as usize) << IDX_BITS) | idx
}

const fn split_waker_data(data: usize) -> (usize, u32, usize) {
  (data >> (IDX_BITS + GEN_BITS), ((data >> IDX_BITS) as u32) & GEN_MASK, data & IDX_MASK)
}

fn waker_clone(data: *const ()) -> RawWaker {
  RawWaker::new(data, &VTABLE)
}

fn waker_wake(data: *const ()) {
  let data = data as usize;
  let reactor = CURRENT.with(Cell::get);
  // SAFETY: set by `block_on`, which outlives everything it polls
  if let Some(reactor) = unsafe { reactor.as_ref() }
    && reactor.slot() == split_waker_data(data).0
  {
    reactor.schedule(data);
    return;
  }
  wake_remote(data);
}

fn waker_drop(_: *const ()) {}

// ---- runtimes reached from other threads

/// What another thread asks a runtime to do.
enum Message {
  DropConn(u32, u32),
  DropListener(usize),
  Wake(usize),
}

/// A runtime's queue of messages from other threads, and the eventfd that tells it there are
/// some.
struct Inbox {
  eventfd: RawFd,
  messages: std::sync::Mutex<Vec<Message>>,
}

impl Inbox {
  fn push(&self, message: Message) {
    let was_empty = {
      let mut messages = self.messages.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
      let was_empty = messages.is_empty();
      messages.push(message);
      was_empty
    };
    // The runtime drains the whole queue on each ring, so only the first message rings.
    if was_empty {
      let one: u64 = 1;
      // SAFETY: `one` outlives the call and its size is passed; the eventfd lives as long as
      // `self`
      let _rslt = unsafe { libc::write(self.eventfd, (&raw const one).cast(), 8) };
    }
  }

  fn take(&self) -> Vec<Message> {
    core::mem::take(&mut *self.messages.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
  }
}

impl Drop for Inbox {
  fn drop(&mut self) {
    // SAFETY: closed once, here, when the last reference to the inbox goes
    let _rslt = unsafe { libc::close(self.eventfd) };
  }
}

/// A slot of `RUNTIMES`: the inbox of the runtime in it, and how many runtimes it has had, which
/// makes runtime ids unique over time.
#[derive(Default)]
struct RuntimeSlot {
  epoch: u32,
  inbox: Option<crate::sync::Arc<Inbox>>,
}

static RUNTIMES: std::sync::Mutex<Vec<RuntimeSlot>> = std::sync::Mutex::new(Vec::new());

fn runtimes() -> std::sync::MutexGuard<'static, Vec<RuntimeSlot>> {
  RUNTIMES.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A slot for a new runtime: its id (the slot in the low 12 bits, the slot's epoch above) and its
/// inbox.
fn register_runtime() -> crate::Result<(u32, crate::sync::Arc<Inbox>)> {
  // SAFETY: plain syscall
  let eventfd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
  if eventfd < 0 {
    return Err(std::io::Error::last_os_error().into());
  }
  let inbox = crate::sync::Arc::new(Inbox { eventfd, messages: std::sync::Mutex::new(Vec::new()) });
  let mut slots = runtimes();
  let idx = if let Some(idx) = slots.iter().position(|el| el.inbox.is_none()) {
    idx
  } else if slots.len() < RUNTIME_SLOTS {
    slots.push(RuntimeSlot::default());
    slots.len() - 1
  } else {
    return Err(io_err(libc::EMFILE));
  };
  let slot = &mut slots[idx];
  slot.epoch = slot.epoch.wrapping_add(1) & 0x000F_FFFF;
  slot.inbox = Some(inbox.clone());
  Ok(((slot.epoch << 12) | idx as u32, inbox))
}

fn unregister_runtime(id: u32) {
  if let Some(slot) = runtimes().get_mut(id as usize & (RUNTIME_SLOTS - 1)) {
    slot.inbox = None;
  }
}

/// The inbox of the runtime in `slot`, if `epoch` is `None` or still that runtime's.
fn inbox_of(slot: usize, epoch: Option<u32>) -> Option<crate::sync::Arc<Inbox>> {
  let slots = runtimes();
  let elem = slots.get(slot)?;
  if epoch.is_some_and(|el| el != elem.epoch) {
    return None;
  }
  elem.inbox.clone()
}

/// A wake from outside its runtime's thread. A runtime that is gone has nothing left to wake;
/// a wake that reaches a newer runtime in the same slot can only be spurious, which futures
/// allow, as the task index and generation must match.
#[cold]
fn wake_remote(data: usize) {
  if let Some(inbox) = inbox_of(split_waker_data(data).0, None) {
    inbox.push(Message::Wake(data));
  }
}

/// A message for the runtime with this exact id; dropped if that runtime is gone.
#[cold]
fn send_to_runtime(runtime: u32, message: Message) {
  if let Some(inbox) = inbox_of(runtime as usize & (RUNTIME_SLOTS - 1), Some(runtime >> 12)) {
    inbox.push(message);
  }
}

// ---- the reactor

// 32 bytes, so that no slot straddles two cache lines: a wake reads one.
#[repr(align(32))]
struct TaskSlot {
  future: Option<TaskRc<dyn RunTask>>,
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
  // Came from a listener, so the idle timeout applies
  accepted: bool,
  // A kernel TLS alert (level, description) to send once the sends before it are out
  tls_alert: [u8; 2],
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

/// Registers the waker of `cx`, returning the one it replaces, which the caller drops once it
/// has released its borrows (see [`Deferred`]).
#[must_use]
fn set_waker(slot: &mut Option<Waker>, cx: &Context<'_>) -> Option<Waker> {
  if !slot.as_ref().is_some_and(|el| el.will_wake(cx.waker())) {
    return slot.replace(cx.waker().clone());
  }
  None
}

/// Wakers taken out while the reactor's state is borrowed, woken (`wake`) or just dropped
/// (`stale`) once the borrow is over. A waker from another executor may run anything when it is
/// woken or dropped, the drop of one of this runtime's streams included, and that borrows the
/// state again. Declared before the borrow, so that it drops after it.
#[derive(Default)]
struct Deferred {
  wake: Option<Waker>,
  stale: [Option<Waker>; 2],
}

impl Drop for Deferred {
  fn drop(&mut self) {
    if let Some(elem) = self.wake.take() {
      elem.wake();
    }
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
  // The last accept error, for `accept` to report once
  error: Option<i32>,
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
  // Unique among the runtimes alive or ever made: see `register_runtime`
  id: u32,
  inbox: crate::sync::Arc<Inbox>,
  // Where the doorbell read puts the eventfd's count
  doorbell: core::cell::UnsafeCell<u64>,
  #[cfg(test)]
  accept_arms: Cell<usize>,
  // Submissions queued, for tests that pin a path as submitting nothing
  #[cfg(test)]
  sqes_pushed: Cell<u64>,
  // Accepted sockets closed because setting them up failed
  #[cfg(test)]
  accept_setup_failures: Cell<usize>,
  // Read by the kernel when it takes a timeout entry off the queue
  backoff_ts: types::Timespec,
  tick_ts: types::Timespec,
  bufs: RefCell<BufRing>,
  cqes: RefCell<Vec<(u64, i32, u32)>>,
  // How many slots at the bottom of `free_conns` hold no buffers
  cold_free: Cell<usize>,
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
  // The task `run_ready` is polling
  current: Cell<Option<TaskRc<dyn RunTask>>>,
  // `UringSleep`s, by slot, and the free slots
  sleeps: RefCell<Vec<SleepSlot>>,
  connects: RefCell<Vec<ConnectSlot>>,
  free_connects: RefCell<Vec<u32>>,
  free_sleeps: RefCell<Vec<u32>>,
  counters: Counters,
  // Waits for completions that failed in a row
  enter_failures: Cell<u32>,
  // The errno the ring kept refusing submissions with, if it did: `block_on` panics with it
  ring_failed: Cell<i32>,
  ready: RefCell<VecDeque<usize>>,
  // See `SEND_POOL_MAX`
  send_pool: RefCell<Vec<Vec<u8>>>,
  // Bytes of the sends queued since the last submit (see `UringParams::set_send_submit_bytes`)
  send_queued: Cell<usize>,
  // Set while `reap` runs: a send it starts doesn't reap again from inside it
  reaping: Cell<bool>,
  tasks: RefCell<Vec<TaskSlot>>,
  timers: RefCell<Timers>,
}

impl Drop for Reactor {
  fn drop(&mut self) {
    // Wakes and drops from other threads now find nothing to reach. The eventfd closes with the
    // last reference to the inbox.
    unregister_runtime(self.id);
    // Handles that outlive the runtime can no longer reach it to close themselves. Direct
    // descriptors go with the ring.
    for conn in self.conns.get_mut().iter().filter(|el| el.in_use && !el.direct) {
      // SAFETY: closed once, here; the ring that could still use it is dropped right after
      let _rslt = unsafe { libc::close(conn.fd) };
    }
    for slot in self.connects.get_mut().iter().filter(|el| el.state != ConnectState::Free) {
      // SAFETY: closed once, here; the ring that could still use it is dropped right after
      let _rslt = unsafe { libc::close(slot.fd) };
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
    // The kernel takes at most 32768 buffers in a ring, and the next power of two above that
    // overflows a `u16`.
    let count = params.recv_buffers.clamp(1, 32768).next_power_of_two();
    let len = (params.recv_buffer_len.max(1) as usize).min(MAX_RECV_RING / usize::from(count));
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
    // Eight ticks per timeout keep each within a quarter of its length: a deadline can fire up to
    // two ticks late, and an idle connection up to two sweeps late.
    let timeouts = [params.close_timeout, params.handshake_timeout, params.idle_timeout];
    let period = timeouts
      .iter()
      .flatten()
      .min()
      .map_or(Duration::from_secs(1), |el| *el / 8)
      .clamp(Duration::from_millis(1), Duration::from_secs(1));
    let ticks_of = |value: Option<Duration>| value.map_or(0, |el| ticks(el, period));
    let idle_ticks = ticks_of(params.idle_timeout);
    let timers = Timers {
      armed: false,
      close_ticks: ticks_of(params.close_timeout),
      handshakes: Vec::with_capacity(TIMER_LIST_CAPACITY),
      handshake_ticks: ticks_of(params.handshake_timeout),
      idle_every: (idle_ticks / 16).max(1),
      idle_ticks,
      lingering: Vec::with_capacity(TIMER_LIST_CAPACITY),
      tick: 0,
    };
    let (id, inbox) = register_runtime()?;
    Ok(Self {
      ring: RefCell::new(ring),
      id,
      inbox,
      doorbell: core::cell::UnsafeCell::new(0),
      #[cfg(test)]
      accept_arms: Cell::new(0),
      #[cfg(test)]
      sqes_pushed: Cell::new(0),
      #[cfg(test)]
      accept_setup_failures: Cell::new(0),
      backoff_ts: types::Timespec::new().nsec(100_000_000),
      tick_ts: types::Timespec::from(period),
      bufs: RefCell::new(bufs),
      cqes: RefCell::new(Vec::with_capacity(cq_entries as usize)),
      cold_free: Cell::new(0),
      conns: RefCell::new(Vec::new()),
      direct_open: Cell::new(0),
      free_conns: RefCell::new(Vec::new()),
      free_tasks: RefCell::new(Vec::new()),
      listeners: RefCell::new(Vec::new()),
      main_woken: Cell::new(false),
      params,
      polling: Cell::new(usize::MAX),
      current: Cell::new(None),
      sleeps: RefCell::new(Vec::new()),
      connects: RefCell::new(Vec::new()),
      free_connects: RefCell::new(Vec::new()),
      free_sleeps: RefCell::new(Vec::new()),
      counters: Counters::default(),
      enter_failures: Cell::new(0),
      ring_failed: Cell::new(0),
      send_pool: RefCell::new(Vec::with_capacity(SEND_POOL_MAX)),
      send_queued: Cell::new(0),
      reaping: Cell::new(false),
      ready: RefCell::new(VecDeque::new()),
      tasks: RefCell::new(Vec::new()),
      timers: RefCell::new(timers),
    })
  }

  fn stats(&self) -> UringStats {
    let counters = &self.counters;
    let open = self.conns.borrow().len().saturating_sub(self.free_conns.borrow().len());
    let cq_overflows = core::mem::ManuallyDrop::new(self.ring.borrow_mut().completion()).overflow();
    let sleeps = self.sleeps.borrow();
    let pending = |el: &&SleepSlot| matches!(el.state, SleepState::Armed | SleepState::Dropped);
    let waiting = |el: &&Conn| el.in_use && el.reader.is_some();
    UringStats {
      accepted: counters.accepted.get(),
      accept_errors: counters.accept_errors.get(),
      accept_backoffs: counters.accept_backoffs.get(),
      cq_overflows: cq_overflows.into(),
      remote_messages: counters.remote_messages.get(),
      open_connections: open as u64,
      recv_buffers_exhausted: counters.recv_buffers_exhausted.get(),
      recv_pauses: counters.recv_pauses.get(),
      submit_errors: counters.submit_errors.get(),
      task_panics: counters.task_panics.get(),
      timeouts: counters.timeouts.get(),
      timers_pending: sleeps.iter().filter(pending).count() as u64,
      timer_slots: sleeps.len() as u64,
      waiting_readers: self.conns.borrow().iter().filter(waiting).count() as u64,
    }
  }

  /// This runtime's slot in `RUNTIMES`.
  fn slot(&self) -> usize {
    self.id as usize & (RUNTIME_SLOTS - 1)
  }

  // ---- sleeps

  fn add_sleep(&self, duration: Duration, cx: &Context<'_>) -> (u32, u32) {
    let mut deferred = Deferred::default();
    let mut sleeps = self.sleeps.borrow_mut();
    // A free list, not a scan: every closing TLS stream (plaintext too) starts an after-close
    // timer, so with many connections closing the table is large.
    let idx = match self.free_sleeps.borrow_mut().pop() {
      Some(idx) => idx as usize,
      None => {
        sleeps.push(SleepSlot {
          generation: 0,
          state: SleepState::Free,
          ts: Box::new(types::Timespec::new()),
          waker: None,
        });
        sleeps.len() - 1
      }
    };
    let slot = &mut sleeps[idx];
    slot.generation = slot.generation.wrapping_add(1) & 0x0FFF_FFFF;
    slot.state = SleepState::Armed;
    *slot.ts = types::Timespec::from(duration);
    deferred.stale[0] = slot.waker.replace(cx.waker().clone());
    let generation = slot.generation;
    let sqe = opcode::Timeout::new(&raw const *slot.ts)
      .build()
      .user_data(user_data(KIND_SLEEP, generation, idx as u32));
    drop(sleeps);
    self.push_sqe(&sqe);
    (idx as u32, generation)
  }

  fn poll_sleep(&self, idx: u32, generation: u32, cx: &Context<'_>) -> Poll<crate::Result<()>> {
    let mut deferred = Deferred::default();
    let mut sleeps = self.sleeps.borrow_mut();
    let Some(slot) = sleeps.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return Poll::Ready(Ok(()));
    };
    if slot.state == SleepState::Armed {
      deferred.stale[0] = set_waker(&mut slot.waker, cx);
      return Poll::Pending;
    }
    Poll::Ready(Ok(()))
  }

  fn drop_sleep(&self, idx: u32, generation: u32) {
    let mut deferred = Deferred::default();
    let mut sleeps = self.sleeps.borrow_mut();
    let Some(slot) = sleeps.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return;
    };
    deferred.stale[0] = slot.waker.take();
    match slot.state {
      SleepState::Armed => {
        slot.state = SleepState::Dropped;
        drop(sleeps);
        let sqe = opcode::TimeoutRemove::new(user_data(KIND_SLEEP, generation, idx))
          .build()
          .flags(squeue::Flags::SKIP_SUCCESS)
          .user_data(user_data(KIND_CANCEL, 0, 0));
        self.push_sqe(&sqe);
      }
      SleepState::Fired => {
        slot.state = SleepState::Free;
        self.free_sleeps.borrow_mut().push(idx);
      }
      SleepState::Dropped | SleepState::Free => {}
    }
  }

  /// A timeout completed, by firing or by being removed.
  fn on_sleep(&self, idx: u32, generation: u32) {
    let mut sleeps = self.sleeps.borrow_mut();
    let Some(slot) = sleeps.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return;
    };
    match slot.state {
      SleepState::Armed => {
        slot.state = SleepState::Fired;
        let waker = slot.waker.take();
        drop(sleeps);
        if let Some(elem) = waker {
          elem.wake();
        }
      }
      SleepState::Dropped => {
        slot.state = SleepState::Free;
        self.free_sleeps.borrow_mut().push(idx);
      }
      SleepState::Fired | SleepState::Free => {}
    }
  }

  // ---- connects

  fn add_connect(&self, fd: RawFd, addr: &SocketAddr, cx: &Context<'_>) -> (u32, u32) {
    let mut deferred = Deferred::default();
    let mut connects = self.connects.borrow_mut();
    let idx = match self.free_connects.borrow_mut().pop() {
      Some(idx) => idx as usize,
      None => {
        connects.push(ConnectSlot {
          // SAFETY: all zeroes is a valid `sockaddr_storage`
          addr: Box::new(unsafe { core::mem::zeroed() }),
          fd: -1,
          generation: 0,
          res: 0,
          state: ConnectState::Free,
          waker: None,
        });
        connects.len() - 1
      }
    };
    let slot = &mut connects[idx];
    slot.generation = slot.generation.wrapping_add(1) & 0x0FFF_FFFF;
    slot.fd = fd;
    slot.res = 0;
    slot.state = ConnectState::Armed;
    deferred.stale[0] = slot.waker.replace(cx.waker().clone());
    let len = write_sockaddr(addr, &mut slot.addr);
    let generation = slot.generation;
    let sqe = opcode::Connect::new(types::Fd(fd), (&raw const *slot.addr).cast(), len)
      .build()
      .user_data(user_data(KIND_CONNECT, generation, idx as u32));
    drop(connects);
    self.push_sqe(&sqe);
    (idx as u32, generation)
  }

  /// The connected socket, or the connect's error with the socket closed.
  fn poll_connect(
    &self,
    idx: u32,
    generation: u32,
    cx: &Context<'_>,
  ) -> Poll<crate::Result<RawFd>> {
    let mut deferred = Deferred::default();
    let mut connects = self.connects.borrow_mut();
    let Some(slot) = connects.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return Poll::Ready(Err(io_err(libc::EBADF)));
    };
    if slot.state == ConnectState::Armed {
      deferred.stale[0] = set_waker(&mut slot.waker, cx);
      return Poll::Pending;
    }
    let (fd, res) = (slot.fd, slot.res);
    slot.state = ConnectState::Free;
    slot.fd = -1;
    drop(connects);
    self.free_connects.borrow_mut().push(idx);
    if res < 0 {
      // SAFETY: the slot's socket, which nobody else has
      let _rslt = unsafe { libc::close(fd) };
      return Poll::Ready(Err(io_err(-res)));
    }
    Poll::Ready(Ok(fd))
  }

  fn drop_connect(&self, idx: u32, generation: u32) {
    let mut deferred = Deferred::default();
    let mut connects = self.connects.borrow_mut();
    let Some(slot) = connects.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return;
    };
    deferred.stale[0] = slot.waker.take();
    match slot.state {
      ConnectState::Armed => {
        slot.state = ConnectState::Dropped;
        drop(connects);
        self.push_sqe(&cancel_sqe(user_data(KIND_CONNECT, generation, idx)));
      }
      ConnectState::Done => {
        let fd = slot.fd;
        slot.state = ConnectState::Free;
        slot.fd = -1;
        drop(connects);
        self.free_connects.borrow_mut().push(idx);
        // SAFETY: the slot's socket, which nobody else has
        let _rslt = unsafe { libc::close(fd) };
      }
      ConnectState::Dropped | ConnectState::Free => {}
    }
  }

  fn on_connect(&self, idx: u32, generation: u32, res: i32) {
    let mut connects = self.connects.borrow_mut();
    let Some(slot) = connects.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return;
    };
    match slot.state {
      ConnectState::Armed => {
        slot.state = ConnectState::Done;
        slot.res = res;
        let waker = slot.waker.take();
        drop(connects);
        if let Some(elem) = waker {
          elem.wake();
        }
      }
      ConnectState::Dropped => {
        let fd = slot.fd;
        slot.state = ConnectState::Free;
        slot.fd = -1;
        drop(connects);
        self.free_connects.borrow_mut().push(idx);
        // SAFETY: the slot's socket, which nobody else has
        let _rslt = unsafe { libc::close(fd) };
      }
      ConnectState::Done | ConnectState::Free => {}
    }
  }

  // ---- messages from other threads

  fn arm_doorbell(&self) {
    let sqe = opcode::Read::new(types::Fd(self.inbox.eventfd), self.doorbell.get().cast(), 8)
      .build()
      .user_data(user_data(KIND_DOORBELL, 0, 0));
    self.push_sqe(&sqe);
  }

  /// The eventfd rang: runs what other threads asked for, then listens again.
  fn on_doorbell(&self, res: i32) {
    for message in self.inbox.take() {
      bump(&self.counters.remote_messages);
      match message {
        Message::DropConn(idx, generation) => self.drop_conn_ref(idx, generation),
        Message::DropListener(idx) => self.drop_listener(idx),
        Message::Wake(data) => self.schedule(data),
      }
    }
    if res != -libc::ECANCELED {
      self.arm_doorbell();
    }
  }

  // ---- tasks

  fn spawn(&self, future: TaskRc<dyn RunTask>) {
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
    let (_, generation, idx) = split_waker_data(data);
    if idx == MAIN_TASK {
      self.main_woken.set(true);
      return;
    }
    let mut tasks = self.tasks.borrow_mut();
    // A task being polled has its future taken out of the slot, and can still wake itself.
    if let Some(slot) = tasks.get_mut(idx)
      && slot.generation & GEN_MASK == generation
      && (slot.future.is_some() || self.polling.get() == idx)
      && !slot.scheduled
    {
      slot.scheduled = true;
      self.ready.borrow_mut().push_back(idx);
    }
  }

  /// Polls the tasks woken so far. A task that panics ends alone: the others, and the runtime's
  /// connections, carry on. With `panic = "abort"` the process aborts as usual.
  fn run_ready(&self) {
    let mut count = self.ready.borrow().len();
    // One unwind guard per turn: one per poll would keep each task's poll from being inlined.
    while std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| self.poll_ready(&mut count)))
      .is_err()
    {
      self.end_panicked_task();
    }
  }

  #[cold]
  #[inline(never)]
  fn end_panicked_task(&self) {
    bump(&self.counters.task_panics);
    let idx = self.polling.replace(usize::MAX);
    if let Some(task) = self.current.take() {
      // Dropping its future may panic too; the task is over either way.
      let _rslt = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| task.end_panicked()));
    }
    let mut tasks = self.tasks.borrow_mut();
    if let Some(slot) = tasks.get_mut(idx) {
      slot.future = None;
      slot.generation = slot.generation.wrapping_add(1);
      slot.scheduled = false;
      self.free_tasks.borrow_mut().push(idx as u32);
    }
  }

  fn poll_ready(&self, count: &mut usize) {
    while *count > 0 {
      *count -= 1;
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
      let waker = waker(waker_data(self.slot(), generation, idx));
      self.polling.set(idx);
      // Kept here as well, for `end_panicked_task` to reach the task if its poll unwinds
      self.current.set(Some(future.clone()));
      let poll = future.poll_task(&mut Context::from_waker(&waker));
      self.current.set(None);
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
    #[cfg(test)]
    self.sqes_pushed.set(self.sqes_pushed.get().wrapping_add(1));
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
    if self.ring_failed.get() != 0 {
      return;
    }
    let mut ring = self.ring.borrow_mut();
    let mut tries: u32 = 0;
    // SAFETY: as in `push_sqe`
    while unsafe { ring.submission().push(sqe) }.is_err() {
      #[cfg(test)]
      let rslt = if tests::FAIL_SUBMIT.with(core::cell::Cell::get) {
        Err(std::io::Error::from_raw_os_error(libc::EAGAIN))
      } else {
        ring.submit()
      };
      #[cfg(not(test))]
      let rslt = ring.submit();
      // A submit that succeeds empties the queue, so a second try means refusals.
      let Err(err) = rslt else {
        continue;
      };
      bump(&self.counters.submit_errors);
      tries += 1;
      if tries >= SUBMIT_TRIES {
        // The entry is lost and the runtime can't go on: `block_on` ends with the error.
        self.ring_failed.set(err.raw_os_error().unwrap_or(libc::EIO));
        return;
      }
      // Most likely a transient shortage (`EAGAIN`, `ENOMEM`): give the kernel a moment.
      std::thread::yield_now();
    }
  }

  /// Panics if the ring kept refusing submissions: entries were lost, so tasks would wait for
  /// completions that never come.
  fn check_ring(&self) {
    let errno = self.ring_failed.get();
    if errno != 0 {
      ring_failed(errno);
    }
  }

  fn enter(&self, wait: bool) {
    self.send_queued.set(0);
    let mut ring = self.ring.borrow_mut();
    if !wait {
      if needs_enter(&mut ring) && ring.submit().is_err() {
        bump(&self.counters.submit_errors);
      }
      return;
    }
    if !self.params.spin.is_zero() {
      // Sends usually complete inside this submit and post their completions at once; `reap`
      // takes those without another syscall.
      if needs_enter(&mut ring) && ring.submit().is_err() {
        bump(&self.counters.submit_errors);
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
          if ring.submit().is_err() {
            bump(&self.counters.submit_errors);
          }
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
    // EINTR from a signal is not a refusal: the next turn waits again.
    match ring.submit_and_wait(1) {
      Err(err) if err.kind() != std::io::ErrorKind::Interrupted => {
        bump(&self.counters.submit_errors);
        let failures = self.enter_failures.get() + 1;
        self.enter_failures.set(failures);
        // Failing at once every time, the loop would spin instead of waiting.
        if failures >= SUBMIT_TRIES {
          self.ring_failed.set(err.raw_os_error().unwrap_or(libc::EIO));
        }
      }
      _ => self.enter_failures.set(0),
    }
  }

  fn reap(&self) {
    self.reaping.set(true);
    let _reaping = ClearOnDrop(&self.reaping);
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
        KIND_DOORBELL => self.on_doorbell(res),
        KIND_SLEEP => self.on_sleep(idx, generation),
        KIND_CONNECT => self.on_connect(idx, generation, res),
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
      error: None,
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
    let mut deferred = Deferred::default();
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
      bump(&self.counters.accepted);
      deferred.wake = listener.waker.take();
    }
    // Anything but a connection that went away before it was taken, or a cancel of our own,
    // would fail again at once: wait before retrying, and tell `accept`.
    let failed = res < 0
      && !matches!(
        -res,
        libc::ECONNABORTED | libc::EINTR | libc::EAGAIN | libc::EPERM | libc::ECANCELED
      );
    let backoff = failed && !listener.backoff;
    if backoff {
      listener.backoff = true;
      bump(&self.counters.accept_backoffs);
    }
    if failed {
      bump(&self.counters.accept_errors);
      listener.error = Some(-res);
      if deferred.wake.is_none() {
        deferred.wake = listener.waker.take();
      }
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
    let mut deferred = Deferred::default();
    let (armed, fd, queue) = {
      let mut listeners = self.listeners.borrow_mut();
      let Some(listener) = listeners.get_mut(idx).filter(|el| !el.closed) else {
        return;
      };
      listener.closed = true;
      deferred.stale[0] = listener.waker.take();
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
    let mut deferred = Deferred::default();
    let mut listeners = self.listeners.borrow_mut();
    let Some(listener) = listeners.get_mut(idx) else {
      return Poll::Ready(Err(io_err(libc::EBADF)));
    };
    if let Some(fd) = listener.queue.pop_front() {
      return Poll::Ready(Ok(fd));
    }
    if let Some(errno) = listener.error.take() {
      return Poll::Ready(Err(io_err(errno)));
    }
    deferred.stale[0] = listener.waker.replace(cx.waker().clone());
    Poll::Pending
  }

  // ---- connections

  fn add_conn(&self, fd: RawFd, refs: u8, direct: bool, accepted: bool) -> crate::Result<ConnRef> {
    let tick = self.timers.borrow().tick;
    let mut deferred = Deferred::default();
    let (idx, generation) = {
      let mut conns = self.conns.borrow_mut();
      let mut free = self.free_conns.borrow_mut();
      let idx = if let Some(idx) = free.pop() {
        self.cold_free.set(self.cold_free.get().min(free.len()));
        idx
      } else {
        conns.push(Conn::default());
        (conns.len() - 1) as u32
      };
      drop(free);
      let conn = &mut conns[idx as usize];
      conn.accepted = accepted;
      conn.activity = 0;
      conn.cancel_sent = false;
      conn.closing = false;
      conn.direct = direct;
      conn.fd = fd;
      conn.in_use = true;
      conn.last_active = tick;
      conn.lingering = false;
      deferred.stale[0] = conn.reader.take();
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
      deferred.stale[1] = conn.writer.take();
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
    Ok(ConnRef { generation, idx, runtime: self.id })
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
    let mut deferred = Deferred::default();
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
        let off = conn.rx_off as usize;
        if off == conn.rx.len() {
          conn.rx.clear();
          conn.rx_off = 0;
        } else if off >= RX_COMPACT && off >= conn.rx.len() - off {
          compact_rx(conn);
        }
        if conn.rx.capacity() - conn.rx.len() < len {
          self.grow_rx(conn, len);
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
      bump(&self.counters.recv_buffers_exhausted);
      #[cfg(test)]
      let _ = tests::ENOBUFS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    } else if res != -libc::ECANCELED {
      conn.rx_err = errno(res);
    }
    deferred.wake = conn.reader.take();
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

  /// Moves the unread bytes of `conn.rx` into a pooled buffer with room for `additional` more, if
  /// the pool has one, instead of growing it by doubling; the buffer it leaves goes to the pool.
  #[cold]
  #[inline(never)]
  fn grow_rx(&self, conn: &mut Conn, additional: usize) {
    let unread = conn.rx.get(conn.rx_off as usize..).unwrap_or_default();
    let Some(mut buffer) =
      self.take_send_buffer(unread.len().saturating_add(additional), usize::MAX)
    else {
      return;
    };
    buffer.extend_from_slice(unread);
    conn.rx_off = 0;
    let old = core::mem::replace(&mut conn.rx, buffer);
    self.recycle_send_buffer(old);
  }

  /// Stops receiving into a connection that holds `rx_high_water` unread bytes: the rest waits in
  /// the socket. Completions already in flight still land in `rx`.
  #[cold]
  #[inline(never)]
  fn pause_recv(&self, conn: &mut Conn, idx: u32, generation: u32) {
    bump(&self.counters.recv_pauses);
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
    let mut deferred = Deferred::default();
    let mut conns = self.conns.borrow_mut();
    let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return Poll::Ready(Err(io_err(libc::EBADF)));
    };
    let rslt = take_rx(conn, bytes);
    if let Ok(TryRead::Pending | TryRead::Unsupported) = rslt {
      deferred.stale[0] = set_waker(&mut conn.reader, cx);
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
    let mut deferred = Deferred::default();
    let mut conns = self.conns.borrow_mut();
    let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return Poll::Ready(Err(io_err(libc::EBADF)));
    };
    if conn.rx_off as usize != conn.rx.len() || conn.rx_err != 0 || conn.rx_eof {
      return Poll::Ready(Ok(()));
    }
    deferred.stale[0] = set_waker(&mut conn.reader, cx);
    Poll::Pending
  }

  /// Ready once the peer ended its side (`Ok`) or the connection failed (its error), whatever is
  /// left to read. A connection whose receive is paused (see `pause_recv`) notices neither until
  /// its reads take it under the mark again.
  fn poll_peer_ended(
    &self,
    idx: u32,
    generation: u32,
    cx: &mut Context<'_>,
  ) -> Poll<crate::Result<()>> {
    let mut deferred = Deferred::default();
    let mut conns = self.conns.borrow_mut();
    let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return Poll::Ready(Err(io_err(libc::EBADF)));
    };
    if conn.rx_err != 0 {
      return Poll::Ready(Err(io_err(conn.rx_err.into())));
    }
    if conn.rx_eof {
      return Poll::Ready(Ok(()));
    }
    deferred.stale[0] = set_waker(&mut conn.reader, cx);
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
    let len = bytes.iter().map(|el| el.len()).sum();
    // No floor: copied writes are mostly small (WebSocket echoes, HTTP/2 control frames), and small
    // buffers let thousands of connections share pages. A 32 KiB floor here cost WebSocket echo
    // about 10% more user cycles per frame.
    self.reserve_send(&mut conn.tx_pending, len, 0);
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

  /// [`Self::try_queue_send_owned`] for bytes `write` makes in place, written once, into the
  /// buffer they are sent from: a recycled one from `send_pool` (still in the cache), which
  /// becomes the send, or behind a send in flight `tx_pending`. An empty `tx_pending` too small
  /// for them is replaced by one with room for everything a connection may have waiting, rather
  /// than grown by a copy as the writes come. `false` calls nothing.
  fn try_queue_send_with(
    &self,
    idx: u32,
    generation: u32,
    len: usize,
    write: &mut dyn FnMut(&mut Vec<u8>) -> crate::Result<()>,
  ) -> crate::Result<bool> {
    let (sqe, sent) = {
      let mut conns = self.conns.borrow_mut();
      let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
        return Err(io_err(libc::EBADF));
      };
      if conn.tx_err != 0 {
        return Err(io_err(conn.tx_err.into()));
      }
      if conn.sending || !conn.tx_pending.is_empty() {
        if conn.tx_pending.len() >= self.params.tx_high_water {
          return Ok(false);
        }
        self.reserve_send(&mut conn.tx_pending, len, self.params.tx_high_water.saturating_mul(2));
        let before = conn.tx_pending.len();
        if let Err(err) = write(&mut conn.tx_pending) {
          conn.tx_pending.truncate(before);
          return Err(err);
        }
        return Ok(true);
      }
      // A buffer too small would be grown by a copy of its whole capacity: start a new one.
      let mut buffer = self
        .take_send_buffer(len, usize::MAX)
        .or_else(|| self.send_pool.borrow_mut().pop())
        .unwrap_or_default();
      self.reserve_send(&mut buffer, len, self.params.tx_high_water.saturating_mul(2));
      if let Err(err) = write(&mut buffer) {
        self.recycle_send_buffer(buffer);
        return Err(err);
      }
      if buffer.is_empty() {
        self.recycle_send_buffer(buffer);
        return Ok(true);
      }
      let idle = core::mem::replace(&mut conn.tx_inflight, buffer);
      self.recycle_send_buffer(idle);
      conn.activity |= TX_OWNED;
      conn.tx_done = 0;
      conn.sending = true;
      let sqe = send_sqe(conn, &conn.tx_inflight).user_data(user_data(KIND_SEND, generation, idx));
      (sqe, conn.tx_inflight.len())
    };
    self.push_sqe(&sqe);
    self.count_queued_send(sent);
    Ok(true)
  }

  /// [`Self::try_queue_send`] for one buffer, taken instead of copied when nothing is being sent:
  /// `bytes` becomes the send and is replaced by a recycled buffer from `send_pool` (or an empty
  /// one). Behind a send in flight it is copied after it, as `try_queue_send` would. `false`
  /// takes nothing.
  fn try_queue_send_owned(
    &self,
    idx: u32,
    generation: u32,
    bytes: &mut Vec<u8>,
  ) -> crate::Result<bool> {
    let (sqe, len) = {
      let mut conns = self.conns.borrow_mut();
      let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
        return Err(io_err(libc::EBADF));
      };
      if conn.tx_err != 0 {
        return Err(io_err(conn.tx_err.into()));
      }
      if conn.sending || !conn.tx_pending.is_empty() {
        if conn.tx_pending.len() >= self.params.tx_high_water {
          return Ok(false);
        }
        let floor = self.params.tx_high_water.saturating_mul(2);
        self.reserve_send(&mut conn.tx_pending, bytes.len(), floor);
        conn.tx_pending.extend_from_slice(bytes);
        bytes.clear();
        return Ok(true);
      }
      if bytes.is_empty() {
        return Ok(true);
      }
      // The next output is likely as big as this one: a buffer with room for it, else room for it
      // up front instead of growth by doubling.
      let spare = self
        .take_send_buffer(bytes.len(), usize::MAX)
        .or_else(|| self.send_pool.borrow_mut().pop())
        .unwrap_or_else(|| Vec::with_capacity(bytes.len().min(SEND_POOL_BUFFER_MAX)));
      let idle = core::mem::replace(&mut conn.tx_inflight, core::mem::replace(bytes, spare));
      self.recycle_send_buffer(idle);
      conn.activity |= TX_OWNED;
      conn.tx_done = 0;
      conn.sending = true;
      let sqe = send_sqe(conn, &conn.tx_inflight).user_data(user_data(KIND_SEND, generation, idx));
      (sqe, conn.tx_inflight.len())
    };
    self.push_sqe(&sqe);
    self.count_queued_send(len);
    Ok(true)
  }

  /// The most recently pooled buffer with a capacity of `min` to `max` bytes, if any.
  #[inline]
  fn take_send_buffer(&self, min: usize, max: usize) -> Option<Vec<u8>> {
    let mut pool = self.send_pool.borrow_mut();
    let idx = pool.iter().rposition(|el| (min..=max).contains(&el.capacity()))?;
    Some(pool.remove(idx))
  }

  /// Room in `buf` for `additional` more bytes, in a size class (a power of two, at least `floor`),
  /// so that buffers settle at sizes later outputs fit rather than grow by a few bytes now and then.
  /// An empty buffer is replaced, not grown: growing copies its whole capacity. The replacement is
  /// a pooled buffer of up to four times the class if there is one, a new one of the class if not.
  #[inline]
  fn reserve_send(&self, buf: &mut Vec<u8>, additional: usize, floor: usize) {
    let want = buf.len().saturating_add(additional);
    if buf.capacity() >= want {
      return;
    }
    self.grow_send(buf, want, floor);
  }

  #[cold]
  #[inline(never)]
  fn grow_send(&self, buf: &mut Vec<u8>, want: usize, floor: usize) {
    let class = want.max(floor).checked_next_power_of_two().unwrap_or(want);
    if !buf.is_empty() {
      buf.reserve_exact(class.saturating_sub(buf.len()));
      return;
    }
    if let Some(elem) = self.take_send_buffer(want, class.saturating_mul(4)) {
      let old = core::mem::replace(buf, elem);
      self.recycle_send_buffer(old);
      return;
    }
    *buf = Vec::with_capacity(class);
  }

  /// Keeps an emptied send buffer for `try_queue_send_owned`, or frees it.
  fn recycle_send_buffer(&self, mut buffer: Vec<u8>) {
    let capacity = buffer.capacity();
    if capacity == 0 || capacity > SEND_POOL_BUFFER_MAX {
      return;
    }
    let mut pool = self.send_pool.borrow_mut();
    if pool.len() < SEND_POOL_MAX {
      buffer.clear();
      pool.push(buffer);
    }
  }

  fn start_send(&self, idx: u32, generation: u32) {
    let (sqe, len) = {
      let mut conns = self.conns.borrow_mut();
      let conn = &mut conns[idx as usize];
      core::mem::swap(&mut conn.tx_inflight, &mut conn.tx_pending);
      conn.tx_pending.clear();
      conn.tx_done = 0;
      conn.sending = true;
      let sqe = send_sqe(conn, &conn.tx_inflight).user_data(user_data(KIND_SEND, generation, idx));
      (sqe, conn.tx_inflight.len())
    };
    self.push_sqe(&sqe);
    self.count_queued_send(len);
  }

  /// Counts `len` more bytes queued for sending and, once those queued since the last submit
  /// reach `send_submit_bytes`, submits them now: the kernel copies them while they are still in
  /// the cache. A failed submit leaves them queued for the end of the turn.
  ///
  /// Sends that complete inside the submit have posted their completions already. Taking them at
  /// once returns their buffers to `send_pool` while those are still in the cache, so the next
  /// outputs of the turn are written into them, as into one reused buffer, rather than into
  /// buffers recycled at the end of an earlier turn.
  #[inline]
  fn count_queued_send(&self, len: usize) {
    let queued = self.send_queued.get().saturating_add(len);
    if queued < self.params.send_submit_bytes {
      self.send_queued.set(queued);
      return;
    }
    self.send_queued.set(0);
    if self.ring.borrow_mut().submit().is_err() {
      bump(&self.counters.submit_errors);
    }
    if !self.reaping.get() {
      self.reap();
    }
  }

  fn on_send(&self, idx: u32, generation: u32, res: i32) {
    let mut deferred = Deferred::default();
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
      if conn.tx_done as usize >= MAX_SEND {
        drop_sent(conn);
      }
      // A timed-out connection sends nothing more, even if the cancel found the send half done.
      if (conn.tx_done as usize) < conn.tx_inflight.len() && conn.tx_err == 0 {
        let rest = conn.tx_inflight.get(conn.tx_done as usize..).unwrap_or_default();
        let sqe = send_sqe(conn, rest).user_data(user_data(KIND_SEND, generation, idx));
        drop(conns);
        self.push_sqe(&sqe);
        return;
      }
      conn.sending = false;
      if conn.activity & TX_OWNED == 0 {
        conn.tx_inflight.clear();
      } else {
        conn.activity &= !TX_OWNED;
        self.recycle_send_buffer(core::mem::take(&mut conn.tx_inflight));
      }
    }
    deferred.wake = conn.writer.take();
    if !conn.tx_pending.is_empty() && conn.tx_err == 0 {
      drop(conns);
      self.start_send(idx, generation);
      return;
    }
    if conn.activity & TLS_ALERT_PENDING != 0 {
      send_pending_tls_alert(conn);
    }
    if conn.closing {
      let fd = conn.fd;
      drop(conns);
      self.maybe_close(idx, fd);
    }
  }

  // ---- kernel TLS

  /// The socket of a connection the kernel can take for TLS: an ordinary descriptor with nothing
  /// received and unread, and nothing waiting to be sent (those bytes were encrypted in user space,
  /// and the kernel would encrypt them again). With `DEFER_TASKRUN` a receive completes only inside
  /// `io_uring_enter` on this thread, so while no completion waits to be reaped, nothing can land
  /// in `rx` between this check and the kernel taking the socket; later receives read through it.
  #[cfg(feature = "tls")]
  fn kernel_tls_fd(&self, idx: u32, generation: u32) -> Option<RawFd> {
    let conns = self.conns.borrow();
    let conn = conns.get(idx as usize).filter(|el| el.generation == generation)?;
    if conn.direct
      || conn.rx_off as usize != conn.rx.len()
      || conn.rx_err != 0
      || conn.rx_eof
      || conn.sending
      || !conn.tx_pending.is_empty()
    {
      return None;
    }
    cq_is_empty(&mut self.ring.borrow_mut()).then_some(conn.fd)
  }

  #[cfg(feature = "tls")]
  fn read_kernel_tls_record(
    &self,
    idx: u32,
    generation: u32,
    buffer: &mut [u8],
  ) -> crate::Result<(u8, usize)> {
    let (fd, direct) = self.conn_fd(idx, generation)?;
    if direct {
      return Err(io_err(libc::EOPNOTSUPP));
    }
    crate::tls::kernel_tls::read_record(fd, buffer)
  }

  /// Sends an alert now if nothing is waiting to be sent, else once the sends before it are out.
  #[cfg(feature = "tls")]
  fn send_kernel_tls_alert(
    &self,
    idx: u32,
    generation: u32,
    level: u8,
    description: u8,
  ) -> crate::Result<()> {
    let mut conns = self.conns.borrow_mut();
    let Some(conn) = conns.get_mut(idx as usize).filter(|el| el.generation == generation) else {
      return Err(io_err(libc::EBADF));
    };
    if conn.tx_err != 0 {
      return Err(io_err(conn.tx_err.into()));
    }
    if conn.direct {
      return Err(io_err(libc::EOPNOTSUPP));
    }
    conn.tls_alert = [level, description];
    conn.activity |= TLS_ALERT_PENDING;
    if !conn.sending && conn.tx_pending.is_empty() {
      send_pending_tls_alert(conn);
    }
    Ok(())
  }

  fn poll_send_room(
    &self,
    idx: u32,
    generation: u32,
    cx: &mut Context<'_>,
  ) -> Poll<crate::Result<()>> {
    let mut deferred = Deferred::default();
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
    deferred.stale[0] = conn.writer.replace(cx.waker().clone());
    Poll::Pending
  }

  fn drop_conn_ref(&self, idx: u32, generation: u32) {
    let mut deferred = Deferred::default();
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
      deferred.stale = [conn.reader.take(), conn.writer.take()];
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
    // Slots are reused, so a buffer that grew for one connection would stay allocated for as
    // long as the runtime runs: memory a burst of large or unread transfers never gives back. It
    // goes to the pool instead, which is bounded.
    for buffer in [&mut conn.rx, &mut conn.tx_inflight, &mut conn.tx_pending] {
      if buffer.capacity() > SLOT_BUFFER_KEEP {
        self.recycle_send_buffer(core::mem::take(buffer));
      }
    }
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
    self.trim_free_slots();
    if direct {
      self.release_direct();
    }
  }

  /// Strips the buffers of the free slots the next connections are unlikely to reuse soon: all but
  /// as many as are open, and at least `WARM_FREE_MIN`; with no connection open, the pools are
  /// trimmed to a few entries too (the send pool, ended tasks' blocks and TLS state). After a
  /// burst closes, memory then follows the connections open rather than the most ever open. The
  /// free list is a stack, so the stripped slots are a prefix at its bottom, which `cold_free`
  /// counts: each slot is stripped at most once per time it is freed.
  fn trim_free_slots(&self) {
    let free = self.free_conns.borrow();
    let mut conns = self.conns.borrow_mut();
    // With no connection left, the buffers kept for reuse would only hold the largest outputs of
    // the last burst, but for the few the next connection needs.
    if free.len() == conns.len() {
      trim_newest(&mut self.send_pool.borrow_mut(), SEND_POOL_IDLE_KEEP, SEND_POOL_IDLE_BYTES);
      trim_task_pool(TASK_POOL_IDLE_KEEP, TASK_POOL_IDLE_BYTES);
      #[cfg(feature = "tls")]
      crate::tls::trim_idle_pools();
    }
    let keep = conns.len().wrapping_sub(free.len()).max(WARM_FREE_MIN);
    let mut cold = self.cold_free.get().min(free.len());
    while free.len().wrapping_sub(cold) > keep {
      if let Some(conn) = free.get(cold).and_then(|&idx| conns.get_mut(idx as usize)) {
        conn.rx = Vec::new();
        conn.tx_inflight = Vec::new();
        conn.tx_pending = Vec::new();
      }
      cold = cold.wrapping_add(1);
    }
    self.cold_free.set(cold);
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
    // Woken once the borrows below are over (see `Deferred`)
    let mut woken = Vec::new();
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
        self.time_out(conn, idx, &mut woken);
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
        self.time_out(conn, *idx, &mut woken);
        return false;
      }
      true
    });
    let mut open = false;
    if *idle_ticks > 0 && tick % *idle_every == 0 {
      for (idx, conn) in conns.iter_mut().enumerate() {
        if !conn.in_use || !conn.accepted {
          continue;
        }
        open = true;
        if conn.activity & ACTIVE_ANY != 0 {
          conn.activity &= !ACTIVE_ANY;
          conn.last_active = tick;
        } else if tick.wrapping_sub(conn.last_active) >= *idle_ticks {
          self.time_out(conn, idx as u32, &mut woken);
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
    for elem in woken {
      elem.wake();
    }
  }

  /// Fails a connection's reads and writes with `ETIMEDOUT` and cancels what it has in flight,
  /// which also lets a dropped connection close.
  #[cold]
  #[inline(never)]
  fn time_out(&self, conn: &mut Conn, idx: u32, woken: &mut Vec<Waker>) {
    bump(&self.counters.timeouts);
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
    woken.extend(conn.reader.take());
    woken.extend(conn.writer.take());
  }
}

/// Sends the alert `Conn::tls_alert` holds. It is a small record on a socket whose sends just
/// finished, so it goes out at once; if the socket can't take it now, it is dropped, as a TLS stack
/// would drop an alert it could not send while closing.
#[cold]
#[inline(never)]
fn send_pending_tls_alert(conn: &mut Conn) {
  conn.activity &= !TLS_ALERT_PENDING;
  #[cfg(feature = "tls")]
  {
    let _rslt = crate::tls::kernel_tls::send_record(
      conn.fd,
      crate::tls::kernel_tls::RECORD_ALERT,
      &conn.tls_alert,
    );
  }
}

#[cold]
#[inline(never)]
fn ring_failed(errno: i32) -> ! {
  panic!(
    "io_uring refused submissions {SUBMIT_TRIES} times in a row: {}",
    std::io::Error::from_raw_os_error(errno)
  );
}

/// Writes `addr` the way the kernel takes it, returning its length.
fn write_sockaddr(addr: &SocketAddr, dst: &mut libc::sockaddr_storage) -> libc::socklen_t {
  let dst: *mut libc::sockaddr_storage = dst;
  match addr {
    SocketAddr::V4(elem) => {
      // SAFETY: all zeroes is a valid `sockaddr_in`
      let mut sin: libc::sockaddr_in = unsafe { core::mem::zeroed() };
      sin.sin_family = libc::AF_INET as libc::sa_family_t;
      sin.sin_port = elem.port().to_be();
      sin.sin_addr.s_addr = u32::from_ne_bytes(elem.ip().octets());
      // SAFETY: `sockaddr_storage` is larger than, and aligned for, `sockaddr_in`
      unsafe { dst.cast::<libc::sockaddr_in>().write(sin) };
      size_of::<libc::sockaddr_in>() as libc::socklen_t
    }
    SocketAddr::V6(elem) => {
      // SAFETY: all zeroes is a valid `sockaddr_in6`
      let mut sin6: libc::sockaddr_in6 = unsafe { core::mem::zeroed() };
      sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
      sin6.sin6_port = elem.port().to_be();
      sin6.sin6_flowinfo = elem.flowinfo();
      sin6.sin6_addr.s6_addr = elem.ip().octets();
      sin6.sin6_scope_id = elem.scope_id();
      // SAFETY: `sockaddr_storage` is larger than, and aligned for, `sockaddr_in6`
      unsafe { dst.cast::<libc::sockaddr_in6>().write(sin6) };
      size_of::<libc::sockaddr_in6>() as libc::socklen_t
    }
  }
}

/// Drops the read bytes from the front of a connection's received ones, which a reader that never
/// takes everything there is would otherwise keep for as long as the connection lives.
#[cold]
#[inline(never)]
fn compact_rx(conn: &mut Conn) {
  let _drained = conn.rx.drain(..conn.rx_off as usize);
  conn.rx_off = 0;
}

/// Drops the sent bytes from the front of a write larger than [`MAX_SEND`].
#[cold]
#[inline(never)]
fn drop_sent(conn: &mut Conn) {
  let _drained = conn.tx_inflight.drain(..conn.tx_done as usize);
  conn.tx_done = 0;
}

/// Frees the oldest of `pool`'s buffers until at most `keep` are left, of at most `bytes` in all.
fn trim_newest(pool: &mut Vec<Vec<u8>>, keep: usize, bytes: usize) {
  let mut kept = 0usize;
  let mut total = 0usize;
  let mut first = pool.len();
  for (idx, elem) in pool.iter().enumerate().rev() {
    total = total.saturating_add(elem.capacity());
    if kept == keep || total > bytes {
      break;
    }
    kept = kept.wrapping_add(1);
    first = idx;
  }
  let _ = pool.drain(..first);
}

fn send_sqe(conn: &Conn, bytes: &[u8]) -> squeue::Entry {
  // At most `MAX_SEND`, which fits the `u32` length; the completion sends the rest.
  let (ptr, len) = (bytes.as_ptr(), bytes.len().min(MAX_SEND) as u32);
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
  use core::{cell::Cell, future::poll_fn, task::Poll};
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

  // A task that ended gives its allocation back to the runtime's thread, and the next task of
  // its size takes it: a server that spawns a task per connection allocates nothing for it once
  // warm.
  #[test]
  fn spawned_tasks_reuse_the_allocations_of_ended_ones() {
    use crate::{sync::AtomicU64, tests::_count_allocations_in};
    use core::sync::atomic::Ordering;
    static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
    let task = |seed: u8| async move {
      let state = [seed; 4096];
      yield_once().await;
      core::hint::black_box(&state)[4095]
    };
    let allocations = UringRuntime::new().unwrap().block_on(async move {
      for seed in 0..4 {
        assert_eq!(super::spawn_on_current(task(seed)).await.unwrap(), seed);
      }
      _count_allocations_in(&ALLOCATIONS);
      let before = ALLOCATIONS.load(Ordering::SeqCst);
      for seed in 0..100 {
        assert_eq!(super::spawn_on_current(task(seed)).await.unwrap(), seed);
      }
      ALLOCATIONS.load(Ordering::SeqCst) - before
    });
    assert_eq!(allocations, 0, "allocations of 100 spawned tasks");
  }

  // The task allocator, without a runtime (so under Miri too): a block comes back zeroed, the
  // next task of its class takes it, others don't, and the pool keeps its bounds.
  #[test]
  fn task_blocks_come_back_zeroed_and_are_reused() {
    use super::{TASK_POOL, TASK_POOL_MAX, TaskAlloc, TaskRc, trim_task_pool};
    use alloc::rc::Rc;
    trim_task_pool(0, 0);
    let first = Rc::new_in([0xA5u8; 1000], TaskAlloc);
    let addr = Rc::as_ptr(&first).addr();
    drop(first);
    TASK_POOL.with(|pool| {
      let pool = pool.borrow();
      let &(ptr, size) = pool.blocks.last().unwrap();
      assert!(size >= 1000 && size % super::TASK_CLASS == 0);
      // SAFETY: a block of the pool, every byte of which was written with a zero
      let bytes = unsafe { core::slice::from_raw_parts(ptr.as_ptr(), size) };
      assert!(bytes.iter().all(|el| *el == 0), "a pooled task block kept its bytes");
    });
    // Another class doesn't take it, the same one does.
    let other: TaskRc<[u8; 4000]> = Rc::new_in([1; 4000], TaskAlloc);
    assert_ne!(Rc::as_ptr(&other).cast::<u8>().addr(), addr);
    let again = Rc::new_in([2u8; 1000], TaskAlloc);
    assert_eq!(Rc::as_ptr(&again).addr(), addr);
    assert_eq!(again[999], 2);
    drop((other, again));
    let many: Vec<_> = (0..TASK_POOL_MAX + 8).map(|_| Rc::new_in([3u8; 100], TaskAlloc)).collect();
    drop(many);
    let (len, bytes) = TASK_POOL.with(|pool| (pool.borrow().blocks.len(), pool.borrow().bytes));
    assert!(len <= TASK_POOL_MAX && bytes <= super::TASK_POOL_BYTES, "{len} {bytes}");
    trim_task_pool(super::TASK_POOL_IDLE_KEEP, super::TASK_POOL_IDLE_BYTES);
    let len = TASK_POOL.with(|pool| pool.borrow().blocks.len());
    assert_eq!(len, super::TASK_POOL_IDLE_KEEP);
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

  std::thread_local! {
    // Every submission on this thread fails with `EAGAIN`
    pub(super) static FAIL_SUBMIT: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
  }

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

  // The owned reader has no writer of its own: a frame that breaks the protocol (here, an
  // unmasked one) is answered by handing a 1002 close frame to the bridge, which the writer
  // sends.
  #[test]
  fn split_reader_answers_a_protocol_error_with_a_close_frame() {
    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut stream = connect(&client_addr);
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
      stream.write_all(&[0x81, 1, b'a']).unwrap();
      let mut rest = Vec::new();
      let _len = stream.read_to_end(&mut rest).unwrap();
      assert_eq!(rest, [0x88, 2, 3, 234]);
    });
    let runtime = UringRuntime::new().unwrap();
    runtime.block_on(async {
      let listener = bind(&addr).await;
      let (stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      let ws = WebSocketAcceptor::default()
        .accept(TlsAcceptor::new(
          &TlsConfig::plaintext(),
          &mut ChaCha20::from_std_random().unwrap(),
          stream,
        ))
        .await
        .unwrap();
      let (bridge, mut reader, mut writer) = ws.into_split().unwrap();
      let mut buffer = VectorUsize::new();
      let _err =
        reader.read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive).await.unwrap_err();
      let mut listen = core::pin::pin!(bridge.listen());
      let data = poll_fn(|cx| Poll::Ready(listen.as_mut().poll(cx))).await;
      let Poll::Ready(data) = data else {
        panic!("no close frame was handed to the bridge");
      };
      assert!(writer.manage_bridge_data(data).await.unwrap());
    });
    client.join().unwrap();
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

  fn set_sock_opt<T>(stream: &std::net::TcpStream, level: i32, name: i32, value: &T) {
    use std::os::fd::AsRawFd;
    // SAFETY: valid socket, and the option buffer is a live `T` of the size passed
    unsafe {
      libc::setsockopt(
        stream.as_raw_fd(),
        level,
        name,
        core::ptr::from_ref(value).cast(),
        size_of::<T>() as libc::socklen_t,
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

  // Small copied writes (a WebSocket echo) keep small send buffers: thousands of connections
  // then share pages and cache lines instead of each holding a buffer of its own pages.
  #[test]
  fn small_copied_writes_keep_small_send_buffers() {
    use crate::net::{StreamReader, StreamWriter};
    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut stream = connect(&client_addr);
      let mut got = [0; 100];
      for _ in 0..10 {
        Write::write_all(&mut stream, &[7; 100]).unwrap();
        stream.read_exact(&mut got).unwrap();
      }
    });
    let runtime = UringRuntime::new().unwrap();
    let largest = runtime.block_on(async {
      let listener = bind(&addr).await;
      let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      let mut buf = alloc::vec![0; 4096];
      let mut largest = 0;
      while let Some(len) = stream.read(buf.as_mut_slice().into()).await.unwrap() {
        stream.write_all_vectored(&[&buf[..1], &buf[1..len.get()]]).await.unwrap();
        largest = largest.max(super::with_reactor(|reactor| {
          Ok(reactor.conns.borrow().iter().map(|el| el.tx_pending.capacity().max(el.tx_inflight.capacity())).max().unwrap_or(0))
        }).unwrap());
      }
      largest
    });
    client.join().unwrap();
    assert!(largest > 0 && largest <= 1024, "send buffers of {largest} bytes for 100-byte writes");
  }

  /// The receive and send state of every open connection, for a test that stalls.
  fn conn_states() -> alloc::string::String {
    super::with_reactor(|reactor| {
      let mut out = alloc::string::String::new();
      for (idx, el) in reactor.conns.borrow().iter().enumerate().filter(|(_, el)| el.in_use) {
        out.push_str(&alloc::format!(
          "conn {idx}: unread {} paused {} armed {} eof {} rx_err {} reader {} | pending {} \
           inflight {} done {} sending {} tx_err {} writer {} closing {}\n",
          el.rx.len() - el.rx_off as usize,
          el.rx_paused,
          el.recv_armed,
          el.rx_eof,
          el.rx_err,
          el.reader.is_some(),
          el.tx_pending.len(),
          el.tx_inflight.len(),
          el.tx_done,
          el.sending,
          el.tx_err,
          el.writer.is_some(),
          el.closing,
        ));
      }
      Ok(out)
    })
    .unwrap()
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
      // A stall fails with the connection's state instead of hanging the suite.
      let deadline = std::time::Instant::now() + core::time::Duration::from_secs(60);
      while !client.is_finished() {
        peak = peak.max(max_unread());
        assert!(
          std::time::Instant::now() < deadline,
          "stalled after 60 s (peak {peak}):\n{}",
          conn_states()
        );
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

  // A connection nothing is sent on is cut off within an eighth past the handshake timeout.
  #[test]
  fn handshake_timeout_fires_within_an_eighth_of_its_length() {
    use crate::net::StreamReader;
    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut stream = connect(&client_addr);
      let mut rest = Vec::new();
      let _rslt = stream.read_to_end(&mut rest);
    });
    let limit = core::time::Duration::from_secs(1);
    let params = crate::executor::UringParams::new().set_handshake_timeout(Some(limit));
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
    assert!(elapsed >= limit * 15 / 16, "{elapsed:?}");
    assert!(elapsed < limit * 19 / 16, "{elapsed:?}");
  }

  // Idle connections whose last activity falls anywhere between two sweeps are all cut off within
  // an eighth past the idle timeout, with a handshake timeout set too (which sets the tick).
  #[test]
  fn idle_timeout_fires_within_an_eighth_of_its_length() {
    use crate::net::{StreamReader, StreamWriter};
    const CONNS: usize = 8;
    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut streams = Vec::new();
      for _ in 0..CONNS {
        streams.push(connect(&client_addr));
        std::thread::sleep(core::time::Duration::from_millis(25));
      }
      for mut stream in streams {
        let mut rest = Vec::new();
        let _rslt = stream.read_to_end(&mut rest);
      }
    });
    let idle = core::time::Duration::from_millis(800);
    let params = crate::executor::UringParams::new()
      .set_handshake_timeout(Some(idle * 2 / 5))
      .set_idle_timeout(Some(idle));
    let runtime = UringRuntime::with_params(params).unwrap();
    let results = runtime.block_on(async {
      let listener = bind(&addr).await;
      let mut handles = Vec::new();
      for _ in 0..CONNS {
        let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
        let wait = async move {
          stream.write_all(b"a").await.unwrap();
          let begin = std::time::Instant::now();
          let mut buf = [0; 16];
          let err = stream.read(buf.as_mut_slice().into()).await.unwrap_err();
          (os_error(&err), begin.elapsed())
        };
        handles.push(crate::executor::Executor::spawn_local(
          &UringExecutor::default(),
          wait,
          &runtime_ref(),
        ));
      }
      let mut results = Vec::new();
      for handle in handles {
        results.push(handle.await.unwrap());
      }
      results
    });
    client.join().unwrap();
    for (errno, elapsed) in results {
      assert_eq!(errno, Some(libc::ETIMEDOUT));
      assert!(elapsed >= idle * 15 / 16, "{elapsed:?}");
      assert!(elapsed < idle * 9 / 8, "{elapsed:?}");
    }
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

  // With the default limits, a peer that never reads pins a bounded amount of send buffer:
  // writes wait once it is reached. Thousands of such peers must not take gigabytes.
  #[test]
  fn peer_that_never_reads_pins_little_send_buffer_by_default() {
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
      .set_close_timeout(Some(core::time::Duration::from_millis(50)));
    let runtime = UringRuntime::with_params(params).unwrap();
    let largest = runtime.block_on(async {
      let listener = bind(&addr).await;
      let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      let chunk = alloc::vec![7; 4096];
      let mut largest = 0;
      let begin = std::time::Instant::now();
      {
        let mut writing = alloc::boxed::Box::pin(async {
          loop {
            stream.write_all(&chunk).await.unwrap();
          }
        });
        while begin.elapsed() < core::time::Duration::from_millis(500) {
          let _pending: Poll<()> = poll_fn(|cx| Poll::Ready(writing.as_mut().poll(cx))).await;
          largest = largest.max(
            super::with_reactor(|reactor| {
              Ok(
                reactor
                  .conns
                  .borrow()
                  .iter()
                  .map(|el| el.tx_pending.capacity() + el.tx_inflight.capacity())
                  .sum::<usize>(),
              )
            })
            .unwrap(),
          );
          yield_once().await;
        }
      }
      drop(stream);
      largest
    });
    let _rslt = done_tx.send(());
    client.join().unwrap();
    // Blocked once both buffers hold the send threshold (16 KiB by default).
    assert!(largest >= 32 * 1024, "the peer never stopped taking bytes ({largest})");
    assert!(largest <= 1 << 20, "{largest} bytes of send buffer for one peer");
  }

  /// Writes `bytes` with `try_send_owned` and reports whether the peer can read them before the
  /// writing task yields, then waits until the peer has read them all.
  async fn arrives_within_the_turn(
    stream: &mut super::UringTcpStream,
    peer: &mut std::net::TcpStream,
    bytes: alloc::vec::Vec<u8>,
  ) -> bool {
    use crate::net::StreamWriter;
    use std::io::Read;
    let len = bytes.len();
    let mut owned = bytes;
    assert!(stream.try_send_owned(&mut owned).unwrap());
    let mut probe = [0; 1];
    let arrived = peer.peek(&mut probe).is_ok();
    let mut buf = alloc::vec![0; 64 * 1024];
    let mut read = 0;
    let begin = std::time::Instant::now();
    while read < len {
      assert!(begin.elapsed() < core::time::Duration::from_secs(5), "{read} of {len} bytes");
      match peer.read(&mut buf) {
        Ok(n) => read += n,
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => yield_once().await,
        Err(err) => panic!("{err}"),
      }
    }
    arrived
  }

  // Sends reach the kernel once those queued in a turn add up to the submit threshold, not only
  // when the turn ends, so the kernel copies them while they are still in the cache. Below the
  // threshold they wait for the turn's single submit.
  #[test]
  fn large_sends_reach_the_peer_within_the_turn() {
    let addr = test_addr();
    let client_addr = addr.clone();
    let (peer_tx, peer_rx) = std::sync::mpsc::channel::<std::net::TcpStream>();
    let client = std::thread::spawn(move || {
      let stream = connect(&client_addr);
      stream.set_nonblocking(true).unwrap();
      peer_tx.send(stream).unwrap();
    });
    let runtime = UringRuntime::with_params(crate::executor::UringParams::new()).unwrap();
    let (small, large) = runtime.block_on(async {
      let listener = bind(&addr).await;
      let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      let mut peer = peer_rx.recv().unwrap();
      let small = arrives_within_the_turn(&mut stream, &mut peer, alloc::vec![1; 1000]).await;
      let large = arrives_within_the_turn(&mut stream, &mut peer, alloc::vec![2; 1 << 20]).await;
      (small, large)
    });
    client.join().unwrap();
    assert!(!small, "a 1000-byte send was submitted before the turn ended");
    assert!(large, "a 1 MiB send waited for the end of the turn");
  }

  #[test]
  fn send_submit_bytes_sets_the_threshold() {
    for (threshold, len, expected) in [(0, 1000, true), (usize::MAX, 1 << 20, false)] {
      let addr = test_addr();
      let client_addr = addr.clone();
      let (peer_tx, peer_rx) = std::sync::mpsc::channel::<std::net::TcpStream>();
      let client = std::thread::spawn(move || {
        let stream = connect(&client_addr);
        stream.set_nonblocking(true).unwrap();
        peer_tx.send(stream).unwrap();
      });
      let params = crate::executor::UringParams::new().set_send_submit_bytes(threshold);
      let runtime = UringRuntime::with_params(params).unwrap();
      let arrived = runtime.block_on(async {
        let listener = bind(&addr).await;
        let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
        let mut peer = peer_rx.recv().unwrap();
        arrives_within_the_turn(&mut stream, &mut peer, alloc::vec![3; len]).await
      });
      client.join().unwrap();
      assert_eq!(arrived, expected, "threshold {threshold}, {len} bytes");
    }
  }

  // A send that completes inside an early submit gives its buffer back at once, so the next
  // output of the same turn is written into that buffer, still in the cache, instead of one
  // recycled at the end of an earlier turn.
  #[test]
  fn a_buffer_sent_early_is_reused_within_the_turn() {
    use crate::net::StreamWriter;
    let addr = test_addr();
    let client_addr = addr.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let client = std::thread::spawn(move || {
      let _stream = connect(&client_addr);
      let _rslt = done_rx.recv();
    });
    let params = crate::executor::UringParams::new().set_send_submit_bytes(1000);
    let runtime = UringRuntime::with_params(params).unwrap();
    let (first, reused) = runtime.block_on(async {
      let listener = bind(&addr).await;
      let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      let mut bytes = alloc::vec![1; 2000];
      let first = bytes.as_ptr();
      assert!(stream.try_send_owned(&mut bytes).unwrap());
      let mut next = alloc::vec![2; 10];
      assert!(stream.try_send_owned(&mut next).unwrap());
      (first, next.as_ptr())
    });
    let _rslt = done_tx.send(());
    client.join().unwrap();
    assert_eq!(first, reused, "the second send's spare is not the first send's buffer");
  }

  // A connection that moved megabytes each way gives its buffers back when it is closed: its
  // slot is reused, and one that kept them would hold the most any connection ever needed.
  #[test]
  fn closed_connection_keeps_no_large_buffers() {
    use crate::net::{StreamReader, StreamWriter};
    const TOTAL: usize = 2 << 20;
    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut stream = connect(&client_addr);
      Write::write_all(&mut stream, &alloc::vec![3; TOTAL]).unwrap();
      let mut got = Vec::new();
      let _len = stream.read_to_end(&mut got).unwrap();
      assert_eq!(got.len(), TOTAL);
    });
    let runtime = UringRuntime::new().unwrap();
    let largest = runtime.block_on(async {
      let listener = bind(&addr).await;
      let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      // Let the client's bytes pile up in the receive buffer before reading them.
      std::thread::sleep(core::time::Duration::from_millis(100));
      let mut buf = alloc::vec![0; 64 * 1024];
      let mut read = 0;
      while read < TOTAL {
        read += stream.read(buf.as_mut_slice().into()).await.unwrap().unwrap().get();
      }
      stream.write_all(&alloc::vec![5; TOTAL]).await.unwrap();
      drop(stream);
      while super::with_reactor(|reactor| Ok(reactor.conns.borrow().iter().any(|el| el.in_use)))
        .unwrap()
      {
        yield_once().await;
      }
      super::with_reactor(|reactor| {
        let largest = reactor.conns.borrow().iter().fold(0, |acc, el| {
          acc.max(el.rx.capacity()).max(el.tx_inflight.capacity()).max(el.tx_pending.capacity())
        });
        Ok((largest, reactor.send_pool.borrow().iter().map(Vec::capacity).sum::<usize>()))
      })
      .unwrap()
    });
    client.join().unwrap();
    let (largest, pooled) = largest;
    assert!(largest <= 64 * 1024, "a free slot holds a {largest}-byte buffer");
    // The large ones went to the pool, which keeps little once no connection is left.
    assert!(pooled <= super::SEND_POOL_IDLE_BYTES, "{pooled} bytes pooled");
  }

  // The send threshold defaults to 16 KiB: with less output waiting per connection, the rest
  // waits as references in the caller (HTTP/2 bodies, for one) and is written, or sealed, into
  // buffers still in the cache. static-h2 256: 326k req/s at 256 KiB, 393k at 16 KiB.
  #[test]
  fn tx_high_water_defaults_to_16_kib() {
    assert_eq!(crate::executor::UringParams::new().tx_high_water, 16 * 1024);
  }

  // Sends are submitted once a turn has queued 16 KiB of them: the kernel copies them while they
  // are still in the cache. static-h2 at 1024 connections: 332k req/s at 128 KiB, 408k at 16 KiB.
  #[test]
  fn send_submit_bytes_defaults_to_16_kib() {
    assert_eq!(crate::executor::UringParams::new().send_submit_bytes, 16 * 1024);
  }

  // A write declined because the queue is full can wait for room instead of being copied into
  // the queue: `send_room` resolves once the bytes queued fall back under the high-water mark.
  #[test]
  fn send_room_resolves_when_the_queue_drains() {
    use crate::net::StreamWriter;
    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut stream = connect(&client_addr);
      // Let the server fill its queue before reading.
      std::thread::sleep(core::time::Duration::from_millis(100));
      let mut got = Vec::new();
      let _len = stream.read_to_end(&mut got).unwrap();
      got.len()
    });
    let params = crate::executor::UringParams::new().set_tx_high_water(64 * 1024);
    let runtime = UringRuntime::with_params(params).unwrap();
    let sent = runtime.block_on(async {
      let listener = bind(&addr).await;
      let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      let mut sent = 0;
      let mut declined = 0;
      while sent < 8 << 20 {
        let mut write = |buf: &mut Vec<u8>| {
          buf.extend_from_slice(&[4; 32 * 1024]);
          Ok(())
        };
        if stream.try_send_with(32 * 1024, &mut write).unwrap() {
          sent += 32 * 1024;
        } else {
          declined += 1;
          assert!(stream.send_room().await.unwrap(), "the stream can't tell when it has room");
        }
      }
      assert!(declined > 0, "the queue never filled");
      sent
    });
    assert_eq!(client.join().unwrap(), sent);
  }

  // A runtime left with no connection keeps few send buffers, of little memory: the pool that let
  // a busy turn reuse them would otherwise hold the largest outputs of a burst for good. The most
  // recent are kept, for a connection that comes after the last one.
  #[test]
  fn no_connection_left_keeps_few_send_buffers() {
    use crate::net::StreamWriter;
    const LEN: usize = 512 * 1024;
    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut stream = connect(&client_addr);
      let mut got = Vec::new();
      let _len = stream.read_to_end(&mut got).unwrap();
      assert_eq!(got.len(), 4 * LEN);
    });
    let runtime = UringRuntime::new().unwrap();
    let (pooled_open, pooled_closed) = runtime.block_on(async {
      let listener = bind(&addr).await;
      let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      for _ in 0..4 {
        let mut owned = alloc::vec![9; LEN];
        if !stream.try_send_owned(&mut owned).unwrap() {
          stream.write_all(&alloc::vec![9; LEN]).await.unwrap();
        }
        for _ in 0..20 {
          yield_once().await;
        }
      }
      let pool_len = || {
        super::with_reactor(|reactor| {
          let pool = reactor.send_pool.borrow();
          Ok((pool.len(), pool.iter().map(Vec::capacity).sum::<usize>()))
        })
        .unwrap()
      };
      for _ in 0..100 {
        yield_once().await;
      }
      let pooled_open = pool_len();
      drop(stream);
      while super::with_reactor(|reactor| Ok(reactor.conns.borrow().iter().any(|el| el.in_use)))
        .unwrap()
      {
        yield_once().await;
      }
      (pooled_open, pool_len())
    });
    client.join().unwrap();
    assert!(pooled_open.0 > 0, "the test never filled the pool");
    let (len, bytes) = pooled_closed;
    assert!(len > 0, "no send buffer kept for the next connection");
    assert!(len <= super::SEND_POOL_IDLE_KEEP, "{len} send buffers kept with no connection left");
    assert!(bytes <= super::SEND_POOL_IDLE_BYTES, "{bytes} bytes kept with no connection left");
  }

  // After a burst of connections closes, at most `WARM_FREE_MIN` free slots keep buffers: the rest
  // give them back, so memory follows the connections open, not the most ever open.
  #[test]
  fn a_closed_burst_leaves_few_slots_with_buffers() {
    use crate::net::{StreamReader, StreamWriter};
    const CONNS: usize = 200;
    const LEN: usize = 8 * 1024;
    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut streams: Vec<_> = (0..CONNS).map(|_| connect(&client_addr)).collect();
      for stream in &mut streams {
        Write::write_all(stream, &alloc::vec![7; LEN]).unwrap();
      }
      for stream in &mut streams {
        let mut got = alloc::vec![0; LEN];
        stream.read_exact(&mut got).unwrap();
      }
    });
    let runtime = UringRuntime::new().unwrap();
    let (warm, slots) = runtime.block_on(async {
      let listener = bind(&addr).await;
      let mut handles = Vec::new();
      for _ in 0..CONNS {
        let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
        let echo = async move {
          let mut buf = alloc::vec![0; LEN];
          let mut read = 0;
          while read < LEN {
            read += stream.read(buf[read..].as_mut().into()).await.unwrap().unwrap().get();
          }
          stream.write_all(&buf).await.unwrap();
        };
        handles.push(crate::executor::Executor::spawn_local(
          &UringExecutor::default(),
          echo,
          &runtime_ref(),
        ));
      }
      for handle in handles {
        handle.await.unwrap();
      }
      while super::with_reactor(|reactor| Ok(reactor.conns.borrow().iter().any(|el| el.in_use)))
        .unwrap()
      {
        yield_once().await;
      }
      super::with_reactor(|reactor| {
        let conns = reactor.conns.borrow();
        let warm = conns
          .iter()
          .filter(|el| el.rx.capacity() + el.tx_inflight.capacity() + el.tx_pending.capacity() > 0)
          .count();
        Ok((warm, conns.len()))
      })
      .unwrap()
    });
    client.join().unwrap();
    assert_eq!(slots, CONNS);
    assert!(warm <= super::WARM_FREE_MIN, "{warm} of {slots} free slots hold buffers");
    assert!(warm > 0, "no free slot kept its buffers for the next connection");
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

  // ---- hardening

  // A connection reset before `accept` looks up its peer fails that lookup (ENOTCONN). The
  // accepted socket is closed, not leaked, and `accept` goes on to the next connection.
  #[test]
  fn a_connection_reset_before_accept_is_closed_and_skipped() {
    use crate::net::StreamReader;
    use std::sync::mpsc;
    let addr = test_addr();
    let client_addr = addr.clone();
    let (reset_tx, reset_rx) = mpsc::channel::<()>();
    let client = std::thread::spawn(move || {
      for _ in 0..8 {
        let stream = connect(&client_addr);
        let linger = libc::linger { l_onoff: 1, l_linger: 0 };
        set_sock_opt(&stream, libc::SOL_SOCKET, libc::SO_LINGER, &linger);
        drop(stream);
      }
      reset_tx.send(()).unwrap();
      let mut good = connect(&client_addr);
      good.write_all(b"g").unwrap();
      let mut rest = Vec::new();
      let _rslt = good.read_to_end(&mut rest);
    });
    let runtime = UringRuntime::new().unwrap();
    let (byte, failures) = runtime.block_on(async {
      let listener = bind(&addr).await;
      // Let the resets land before `accept` looks at the connections.
      while reset_rx.try_recv().is_err() {
        yield_once().await;
      }
      let begin = std::time::Instant::now();
      while begin.elapsed() < core::time::Duration::from_millis(100) {
        yield_once().await;
      }
      let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      let mut buf = [0; 1];
      let _len = stream.read(buf.as_mut_slice().into()).await.unwrap();
      let failures =
        super::with_reactor(|reactor| Ok(reactor.accept_setup_failures.get())).unwrap();
      (buf[0], failures)
    });
    client.join().unwrap();
    assert_eq!(byte, b'g');
    assert_eq!(failures, 8, "every reset connection is closed when its setup fails");
    assert_eq!(runtime.open_conns(), 0);
  }

  // The kernel takes at most 32768 provided buffers; more must not overflow the ring size.
  #[test]
  fn recv_buffers_beyond_the_kernel_limit_are_clamped() {
    let params = crate::executor::UringParams::new().set_recv_buffers(40_000, 64);
    let runtime = UringRuntime::with_params(params).unwrap();
    assert_eq!(runtime.block_on(async { 1 }), 1);
  }

  // A receive ring asked for past 512 MiB gets shorter buffers instead of the allocation: the
  // most a connection holds unread is bounded by it, and has to stay under 4 GiB.
  #[test]
  fn a_receive_ring_past_512_mib_is_lowered() {
    let params = crate::executor::UringParams::new().set_recv_buffers(32768, u32::MAX);
    let runtime = UringRuntime::with_params(params).unwrap();
    let bufs = runtime.reactor.bufs.borrow();
    assert_eq!(usize::from(bufs.count) * bufs.len, super::MAX_RECV_RING);
    drop(bufs);
    assert_eq!(runtime.block_on(async { 1 }), 1);
  }

  // A task that panics ends with an error at its join handle; the runtime and its other tasks
  // carry on, and the task's slot is freed.
  #[test]
  fn a_panicking_task_does_not_take_down_the_runtime() {
    let out = UringRuntime::new().unwrap().block_on(async {
      let exec = UringExecutor::default();
      let runtime = UringRuntime::new().unwrap();
      let bad = crate::executor::Executor::spawn_local(
        &exec,
        async {
          yield_once().await;
          panic!("a task panicked on purpose");
        },
        &runtime,
      );
      let good = crate::executor::Executor::spawn_local(
        &exec,
        async {
          yield_once().await;
          yield_once().await;
          5u8
        },
        &runtime,
      );
      let bad = bad.await;
      let good = good.await.unwrap();
      let free = super::with_reactor(|reactor| Ok(reactor.free_tasks.borrow().len())).unwrap();
      (bad.is_err(), good, free)
    });
    assert_eq!(out, (true, 5, 2));
  }

  // The idle timeout is for accepted connections: an outbound one waiting on a quiet server is
  // left alone.
  #[test]
  fn idle_timeout_leaves_outbound_connections_alone() {
    use crate::net::{StreamReader, TcpStream};
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = std_listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
      let (mut stream, _) = std_listener.accept().unwrap();
      std::thread::sleep(core::time::Duration::from_millis(400));
      stream.write_all(b"late").unwrap();
    });
    let params = crate::executor::UringParams::new()
      .set_idle_timeout(Some(core::time::Duration::from_millis(100)));
    let runtime = UringRuntime::with_params(params).unwrap();
    let got = runtime.block_on(async {
      let mut stream = super::UringTcpStream::connect(addr, TcpParams::default()).await.unwrap();
      let mut buf = [0; 8];
      let len = stream.read(buf.as_mut_slice().into()).await.unwrap().unwrap();
      buf[..len.get()].to_vec()
    });
    server.join().unwrap();
    assert_eq!(got, b"late");
  }

  // Safe for a public server out of the box: a handshake and an idle deadline.
  #[test]
  fn defaults_bound_handshakes_and_idle_connections() {
    let params = crate::executor::UringParams::new();
    assert_eq!(params.handshake_timeout, Some(core::time::Duration::from_secs(10)));
    assert_eq!(params.idle_timeout, Some(core::time::Duration::from_secs(300)));
  }

  /// Pending until `flag` is set, with its waker handed to `slot` for another thread to wake.
  async fn woken_by_another_thread(
    flag: std::sync::Arc<core::sync::atomic::AtomicBool>,
    slot: std::sync::Arc<std::sync::Mutex<Option<core::task::Waker>>>,
  ) {
    poll_fn(|cx| {
      if flag.load(core::sync::atomic::Ordering::Acquire) {
        return Poll::Ready(());
      }
      *slot.lock().unwrap() = Some(cx.waker().clone());
      Poll::Pending
    })
    .await;
  }

  /// Sets `flag` and wakes the waker in `slot` from a new thread, once one is there.
  fn wake_from_another_thread(
    flag: std::sync::Arc<core::sync::atomic::AtomicBool>,
    slot: std::sync::Arc<std::sync::Mutex<Option<core::task::Waker>>>,
  ) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
      let waker = loop {
        if let Some(elem) = slot.lock().unwrap().take() {
          break elem;
        }
        std::thread::sleep(core::time::Duration::from_millis(5));
      };
      std::thread::sleep(core::time::Duration::from_millis(20));
      flag.store(true, core::sync::atomic::Ordering::Release);
      waker.wake();
    })
  }

  /// Runs `cb` on a new thread and fails if it hasn't finished within 5 s.
  fn within_5s<T: Send + 'static>(cb: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    let _thread = std::thread::spawn(move || {
      let _rslt = tx.send(cb());
    });
    rx.recv_timeout(core::time::Duration::from_secs(5)).expect("did not finish within 5 s")
  }

  // A waker is `Send`: a task woken from another thread is polled again. The wake used to be
  // dropped, as no runtime runs on the waking thread.
  #[test]
  fn a_task_woken_from_another_thread_is_polled() {
    let out = within_5s(|| {
      let flag = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
      let slot = std::sync::Arc::new(std::sync::Mutex::new(None));
      let waking = wake_from_another_thread(flag.clone(), slot.clone());
      let out = UringRuntime::new().unwrap().block_on(async {
        let task = async move {
          woken_by_another_thread(flag, slot).await;
          9u8
        };
        crate::executor::Executor::spawn_local(
          &UringExecutor::default(),
          task,
          &UringRuntime::new().unwrap(),
        )
        .await
        .unwrap()
      });
      waking.join().unwrap();
      out
    });
    assert_eq!(out, 9);
  }

  // The same for the future `block_on` runs.
  #[test]
  fn a_main_future_woken_from_another_thread_completes() {
    within_5s(|| {
      let flag = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
      let slot = std::sync::Arc::new(std::sync::Mutex::new(None));
      let waking = wake_from_another_thread(flag.clone(), slot.clone());
      UringRuntime::new().unwrap().block_on(woken_by_another_thread(flag, slot));
      waking.join().unwrap();
    });
  }

  // A stream belongs to the runtime that made it. Used on another runtime it fails with EBADF:
  // its slot index and generation used to be looked up in that runtime's table, so it read
  // another client's bytes. Dropped there, it doesn't touch that runtime's connections, and its
  // own runtime closes it when it next runs.
  #[test]
  fn a_stream_used_on_another_runtime_is_refused() {
    use crate::net::StreamReader;
    let (addr_a, addr_b) = (test_addr(), test_addr());
    let clients = {
      let (addr_a, addr_b) = (addr_a.clone(), addr_b.clone());
      std::thread::spawn(move || {
        let mut a = connect(&addr_a);
        a.write_all(b"A").unwrap();
        let mut b = connect(&addr_b);
        b.write_all(b"B").unwrap();
        let mut rest = Vec::new();
        let _rslt = a.read_to_end(&mut rest);
        let _rslt = b.read_to_end(&mut rest);
      })
    };
    let runtime_a = UringRuntime::new().unwrap();
    let (listener_a, mut stream_a) = runtime_a.block_on(async {
      let listener = bind(&addr_a).await;
      let stream = listener.accept(TcpParams::default()).await.unwrap().0;
      (listener, stream)
    });
    let runtime_b = UringRuntime::new().unwrap();
    let (wrong, right) = runtime_b.block_on(async {
      let listener = bind(&addr_b).await;
      let (mut stream_b, _) = listener.accept(TcpParams::default()).await.unwrap();
      let mut buf = [0; 4];
      let wrong = stream_a
        .read(buf.as_mut_slice().into())
        .await
        .map(|el| el.map(|len| buf[..len.get()].to_vec()));
      drop(stream_a);
      let len = stream_b.read(buf.as_mut_slice().into()).await.unwrap().unwrap();
      (wrong.map_err(|err| os_error(&err)), buf[..len.get()].to_vec())
    });
    assert_eq!(wrong, Err(Some(libc::EBADF)));
    assert_eq!(right, b"B");
    let open = runtime_a.block_on(async {
      for _ in 0..16 {
        yield_once().await;
      }
      drop(listener_a);
      super::with_reactor(|reactor| {
        Ok(reactor.conns.borrow().iter().filter(|el| el.in_use).count())
      })
      .unwrap()
    });
    assert_eq!(open, 0, "the stream dropped on the other runtime was not closed by its own");
    drop(runtime_b);
    drop(runtime_a);
    clients.join().unwrap();
  }

  // A stream dropped on a thread with no runtime is closed by its own runtime when that next
  // runs, instead of holding its slot and socket forever.
  #[test]
  fn a_stream_dropped_on_another_thread_is_closed() {
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
    std::thread::spawn(move || drop(stream)).join().unwrap();
    runtime.block_on(async {
      let begin = std::time::Instant::now();
      while super::with_reactor(|reactor| Ok(reactor.conns.borrow().iter().any(|el| el.in_use)))
        .unwrap()
      {
        assert!(begin.elapsed() < core::time::Duration::from_secs(2), "never closed");
        yield_once().await;
      }
    });
    client.join().unwrap();
  }

  /// CPU time this thread has used.
  fn thread_cpu() -> core::time::Duration {
    // SAFETY: `usage` is a plain C struct the call fills
    let usage = unsafe {
      let mut usage = core::mem::zeroed::<libc::rusage>();
      let _rslt = libc::getrusage(libc::RUSAGE_THREAD, &mut usage);
      usage
    };
    let tv =
      |el: libc::timeval| core::time::Duration::new(el.tv_sec as u64, (el.tv_usec * 1000) as u32);
    tv(usage.ru_utime) + tv(usage.ru_stime)
  }

  // `Sleep` on a uring runtime is one of its timeouts: it waits its time without the busy poll
  // the default `Sleep` falls back to (or tokio's, which panics outside a tokio runtime).
  #[test]
  fn sleep_waits_on_the_ring_without_spinning() {
    let (elapsed, cpu) = UringRuntime::new().unwrap().block_on(async {
      let (begin, cpu) = (std::time::Instant::now(), thread_cpu());
      crate::futures::Sleep::new(core::time::Duration::from_millis(100)).unwrap().await.unwrap();
      (begin.elapsed(), thread_cpu() - cpu)
    });
    assert!(elapsed >= core::time::Duration::from_millis(100), "{elapsed:?}");
    assert!(elapsed < core::time::Duration::from_millis(400), "{elapsed:?}");
    assert!(cpu < core::time::Duration::from_millis(20), "spent {cpu:?} of CPU sleeping");
  }

  // A sleep dropped before it fires is cancelled: nothing wakes for it later, and its slot is
  // free once the kernel confirms.
  #[test]
  fn a_dropped_sleep_is_cancelled() {
    let free = UringRuntime::new().unwrap().block_on(async {
      let mut sleep = alloc::boxed::Box::pin(
        crate::futures::Sleep::new(core::time::Duration::from_secs(30)).unwrap(),
      );
      assert!(crate::futures::PollOnce::new(sleep.as_mut()).await.is_none());
      drop(sleep);
      for _ in 0..8 {
        yield_once().await;
      }
      super::with_reactor(|reactor| {
        Ok(reactor.sleeps.borrow().iter().all(|el| el.state == super::SleepState::Free))
      })
      .unwrap()
    });
    assert!(free, "the dropped sleep's slot was not freed");
  }

  // A listener whose accepts keep failing (here a socket shut down underneath it, which fails
  // every accept with EINVAL) backs off instead of re-arming in a loop, and `accept` reports the
  // error instead of waiting forever.
  #[test]
  fn a_failing_listener_backs_off_and_reports_its_error() {
    let addr = test_addr();
    let (arms, err) = UringRuntime::new().unwrap().block_on(async {
      let listener = bind(&addr).await;
      let fd =
        super::with_reactor(|reactor| Ok(reactor.listeners.borrow()[listener.idx].fd)).unwrap();
      // SAFETY: the listener's own socket, still open
      let _rslt = unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
      let before = super::with_reactor(|reactor| Ok(reactor.accept_arms.get())).unwrap();
      let begin = std::time::Instant::now();
      while begin.elapsed() < core::time::Duration::from_millis(300) {
        yield_once().await;
      }
      let arms = super::with_reactor(|reactor| Ok(reactor.accept_arms.get())).unwrap() - before;
      let err = within_accept(&listener).await;
      (arms, err)
    });
    assert!(arms <= 8, "the failing accept was re-armed {arms} times in 300 ms");
    assert_eq!(err, Some(libc::EINVAL));
  }

  /// The error `accept` returns, waiting at most 2 s for one.
  async fn within_accept(listener: &UringTcpListener) -> Option<i32> {
    let accept = core::pin::pin!(listener.accept(TcpParams::default()));
    let mut accept = accept;
    let begin = std::time::Instant::now();
    loop {
      if let Some(rslt) = crate::futures::PollOnce::new(accept.as_mut()).await {
        return rslt.err().and_then(|err| os_error(&err));
      }
      if begin.elapsed() > core::time::Duration::from_secs(2) {
        return None;
      }
      yield_once().await;
    }
  }

  // The counters an operator watches follow what the runtime did: two accepts, one idle timeout,
  // one panicked task, one wake from another thread.
  #[test]
  fn stats_count_what_happened() {
    use crate::net::StreamReader;
    let addr = test_addr();
    let client_addr = addr.clone();
    let clients = std::thread::spawn(move || {
      let mut first = connect(&client_addr);
      let mut second = connect(&client_addr);
      let mut rest = Vec::new();
      let _rslt = first.read_to_end(&mut rest);
      let _rslt = second.read_to_end(&mut rest);
    });
    let params = crate::executor::UringParams::new()
      .set_idle_timeout(Some(core::time::Duration::from_millis(100)));
    let runtime = UringRuntime::with_params(params).unwrap();
    let inside = runtime.block_on(async {
      let listener = bind(&addr).await;
      let (mut first, _) = listener.accept(TcpParams::default()).await.unwrap();
      let (second, _) = listener.accept(TcpParams::default()).await.unwrap();
      let mut buf = [0; 4];
      let _err = first.read(buf.as_mut_slice().into()).await.unwrap_err();
      let exec = UringExecutor::default();
      let bad = crate::executor::Executor::spawn_local(
        &exec,
        async { panic!("a task panicked on purpose") },
        &UringRuntime::new().unwrap(),
      );
      let _rslt = bad.await;
      let flag = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
      let slot = std::sync::Arc::new(std::sync::Mutex::new(None));
      let waking = wake_from_another_thread(flag.clone(), slot.clone());
      woken_by_another_thread(flag, slot).await;
      waking.join().unwrap();
      let inside = super::uring_stats().unwrap();
      drop((first, second));
      inside
    });
    clients.join().unwrap();
    assert_eq!(inside.accepted, 2);
    assert_eq!(inside.open_connections, 2);
    assert!(inside.timeouts >= 1, "{inside:?}");
    assert_eq!(inside.task_panics, 1);
    assert_eq!(inside.remote_messages, 1);
    assert_eq!(inside.accept_errors, 0);
    assert_eq!(runtime.stats().open_connections, 0);
  }

  // A TLS server on io_uring hands the connection to the kernel after the handshake: the bytes go
  // both ways through it, and the client's close_notify ends the stream cleanly. All three TLS 1.3
  // ciphers (their keys and IVs are laid out differently for the kernel), a stream split into
  // halves, and direct descriptors, which the kernel can't take: those stay in user space.
  #[test]
  fn kernel_tls_on_uring() {
    use crate::tls::CipherSuite;
    let ulp = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_ulp").unwrap_or_default();
    let offered = ulp.split_whitespace().any(|el| el == "tls");
    let params = crate::executor::UringParams::new;
    for cipher in CipherSuite::PRIORITY {
      for split in [false, true] {
        assert_eq!(kernel_tls_round_trip(cipher, params(), split), offered, "{cipher:?} {split}");
      }
    }
    assert!(!kernel_tls_round_trip(
      CipherSuite::Aes128GcmSha256,
      params().set_direct_files(8),
      false
    ));
  }

  /// A TLS ping, pong and close between a std client and a server on uring; whether the server
  /// used kernel TLS.
  fn kernel_tls_round_trip(
    cipher: crate::tls::CipherSuite,
    params: crate::executor::UringParams,
    split: bool,
  ) -> bool {
    use crate::{
      executor::StdRuntime,
      net::{Stream, StreamReader, StreamWriter},
      tests::{_PUBLIC_KEY, _ROOT_CA, _SECRET_KEY},
      tls::TlsConnectorBuilder,
    };
    let uri = _uri();
    let (host, port) = uri.hostname_with_implied_port();
    let addr = alloc::format!("{host}:{port}");
    let client = std::thread::spawn(move || {
      <StdRuntime as Runtime>::new().unwrap().block_on(async move {
        let mut rng = ChaCha20::from_std_random().unwrap();
        let config = || {
          let mut elem = TlsConfig::from_trust_anchors_pem([_ROOT_CA]).unwrap();
          elem.cipher_suites_mut().clear();
          elem.cipher_suites_mut().push(cipher).unwrap();
          elem
        };
        let mut tls_stream = loop {
          let connector = TlsConnectorBuilder::std(uri.clone()).build(config(), &mut rng).await;
          if let Ok(elem) = connector {
            break elem.connect().await.unwrap().tls_stream;
          }
          std::thread::sleep(core::time::Duration::from_millis(5));
        };
        // The first ping arrives with the handshake's last records and is read in user space;
        // the connection switches at a later read.
        let mut buf = [0; 16];
        for _ in 0..4 {
          tls_stream.write_all(b"ping").await.unwrap();
          let len = tls_stream.read(buf.as_mut_slice().into()).await.unwrap().unwrap();
          assert_eq!(&buf[..len.get()], b"pong");
        }
        tls_stream.send_close_notify().await.unwrap();
      });
    });
    let runtime = UringRuntime::with_params(params).unwrap();
    let (kernel, got) = runtime.block_on(async {
      let listener = bind(&addr).await;
      let (stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      let mut rng = ChaCha20::from_std_random().unwrap();
      let config = TlsConfig::from_keys_pem(_PUBLIC_KEY, _SECRET_KEY).unwrap();
      let mut tls_stream =
        TlsAcceptor::new(config, &mut rng, stream).accept().await.unwrap().tls_stream;
      let mut buf = [0; 16];
      let mut got = Vec::new();
      // Two rounds whole, so that it can switch, then split for the rest.
      for _ in 0..2 {
        let len = tls_stream.read(buf.as_mut_slice().into()).await.unwrap().unwrap();
        got.extend_from_slice(&buf[..len.get()]);
        tls_stream.write_all(b"pong").await.unwrap();
      }
      if split {
        let kernel = tls_stream.is_kernel_tls();
        let (_bridge, mut reader, mut writer) = tls_stream.into_split().unwrap();
        while let Some(len) = reader.read(buf.as_mut_slice().into()).await.unwrap() {
          got.extend_from_slice(&buf[..len.get()]);
          writer.write_all(b"pong").await.unwrap();
        }
        return (kernel, got);
      }
      while let Some(len) = tls_stream.read(buf.as_mut_slice().into()).await.unwrap() {
        got.extend_from_slice(&buf[..len.get()]);
        tls_stream.write_all(b"pong").await.unwrap();
      }
      (tls_stream.is_kernel_tls(), got)
    });
    client.join().unwrap();
    assert_eq!(got, b"pingpingpingping");
    assert_eq!(runtime.open_conns(), 0);
    kernel
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

  // A reader that always leaves a byte unread never empties a connection's received bytes, so
  // they were never cleared: the ones it had read stayed in front of the rest, and the buffer
  // grew with everything the connection ever received (its offset wrapping past 4 GiB).
  #[test]
  fn a_reader_that_never_catches_up_does_not_keep_what_it_read() {
    use crate::net::StreamReader;
    const TOTAL: usize = 8 << 20;
    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut stream = connect(&client_addr);
      let data: Vec<u8> = (0..TOTAL).map(|idx| (idx % 251) as u8).collect();
      Write::write_all(&mut stream, &data).unwrap();
      let mut rest = Vec::new();
      let _len = stream.read_to_end(&mut rest);
    });
    let params =
      crate::executor::UringParams::new().set_recv_buffers(8, 4096).set_rx_high_water(16 * 1024);
    let runtime = UringRuntime::with_params(params).unwrap();
    let largest = runtime.block_on(async {
      let listener = bind(&addr).await;
      let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      let idx = stream.conn.idx as usize;
      let mut buf = alloc::vec![0; 64 * 1024];
      let (mut read, mut largest) = (0, 0);
      while read < TOTAL {
        let (len, unread) = super::with_reactor(|reactor| {
          let conns = reactor.conns.borrow();
          Ok((conns[idx].rx.len(), conns[idx].rx.len() - conns[idx].rx_off as usize))
        })
        .unwrap();
        largest = largest.max(len);
        let want = if read + unread == TOTAL { unread } else { unread.saturating_sub(1) };
        if want == 0 {
          crate::futures::Sleep::new(core::time::Duration::from_micros(100))
            .unwrap()
            .await
            .unwrap();
          continue;
        }
        let want = want.min(buf.len());
        let got = stream.read(buf[..want].as_mut().into()).await.unwrap().unwrap().get();
        for (offset, byte) in buf[..got].iter().enumerate() {
          assert_eq!(*byte, ((read + offset) % 251) as u8, "byte {}", read + offset);
        }
        read += got;
      }
      drop(stream);
      largest
    });
    client.join().unwrap();
    assert!(largest <= 256 * 1024, "{largest} bytes held to receive {TOTAL}");
  }

  // One write of more than 4 GiB arrives whole and in order. Its length and progress were kept
  // as `u32`: the send was cut to the length modulo 4 GiB, and then sent nothing, forever.
  // Ignored by default: it needs about 9 GiB of memory.
  #[ignore = "needs about 9 GiB of memory"]
  #[test]
  fn a_write_past_4_gib_arrives_whole() {
    use crate::net::StreamWriter;
    const LEN: usize = (4 << 30) + 3;
    let addr = test_addr();
    let client_addr = addr.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let _client = std::thread::spawn(move || {
      let mut stream = connect(&client_addr);
      let mut buf = alloc::vec![0; 1 << 20];
      let mut read = 0;
      let mut bad = None;
      loop {
        let len = match stream.read(&mut buf) {
          Ok(0) | Err(_) => break,
          Ok(elem) => elem,
        };
        if bad.is_none() {
          bad = buf[..len]
            .iter()
            .enumerate()
            .find(|(offset, byte)| **byte != ((read + offset) % 251) as u8)
            .map(|(offset, _)| read + offset);
        }
        read += len;
      }
      let _rslt = done_tx.send((read, bad));
    });
    let _server = std::thread::spawn(move || {
      UringRuntime::new().unwrap().block_on(async {
        let listener = bind(&addr).await;
        let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
        let data: Vec<u8> = (0..LEN).map(|idx| (idx % 251) as u8).collect();
        stream.write_all(&data).await.unwrap();
        drop(data);
        drop(stream);
      });
    });
    let rslt = done_rx.recv_timeout(core::time::Duration::from_secs(120));
    assert_eq!(rslt, Ok((LEN, None)));
  }

  // A ring that refuses every submission once its queue is full ends `block_on` with a panic
  // that names the error, instead of spinning on the full queue forever.
  #[test]
  fn a_ring_that_refuses_submissions_ends_the_runtime() {
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let _thread = std::thread::spawn(move || {
      let rslt = std::panic::catch_unwind(|| {
        let params = crate::executor::UringParams::new().set_ring_entries(4, 8);
        UringRuntime::with_params(params).unwrap().block_on(async {
          super::tests::FAIL_SUBMIT.with(|el| el.set(true));
          let mut sleeps: Vec<_> = (0..8)
            .map(|_| crate::futures::Sleep::new(core::time::Duration::from_secs(60)).unwrap())
            .collect();
          poll_fn(|cx| {
            for sleep in &mut sleeps {
              let _poll = core::pin::Pin::new(sleep).poll(cx);
            }
            Poll::Ready(())
          })
          .await;
          crate::futures::Sleep::new(core::time::Duration::from_secs(60)).unwrap().await.unwrap();
        });
      });
      let msg = rslt.err().and_then(|el| {
        el.downcast_ref::<alloc::string::String>()
          .cloned()
          .or_else(|| el.downcast_ref::<&str>().map(|msg| alloc::string::String::from(*msg)))
      });
      let _rslt = done_tx.send(msg);
    });
    let msg = done_rx.recv_timeout(core::time::Duration::from_secs(5));
    let msg = msg.expect("the runtime spun on a full submission queue").unwrap_or_default();
    assert!(msg.contains("submission"), "{msg}");
  }

  // A listener on loopback whose accept queue is full: the kernel drops further SYNs, so a
  // connect to it waits for a retransmission, a second or more.
  fn full_listener() -> (std::os::fd::OwnedFd, std::net::SocketAddr, Vec<std::net::TcpStream>) {
    use std::os::fd::FromRawFd;
    // SAFETY: plain socket calls on a socket this function owns
    unsafe {
      let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
      assert!(fd >= 0);
      let owned = std::os::fd::OwnedFd::from_raw_fd(fd);
      let mut addr: libc::sockaddr_in = core::mem::zeroed();
      addr.sin_family = libc::AF_INET as libc::sa_family_t;
      addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
      let len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
      assert_eq!(libc::bind(fd, (&raw const addr).cast(), len), 0);
      assert_eq!(libc::listen(fd, 0), 0);
      let mut bound: libc::sockaddr_in = core::mem::zeroed();
      let mut bound_len = len;
      assert_eq!(libc::getsockname(fd, (&raw mut bound).cast(), &raw mut bound_len), 0);
      let port = u16::from_be(bound.sin_port);
      let socket_addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
      let mut held = Vec::new();
      loop {
        let timeout = core::time::Duration::from_millis(100);
        match std::net::TcpStream::connect_timeout(&socket_addr, timeout) {
          Ok(elem) => held.push(elem),
          Err(_) => break,
        }
        assert!(held.len() < 16, "the accept queue never filled");
      }
      (owned, socket_addr, held)
    }
  }

  // A connect that takes a while leaves the runtime running its other tasks, and dropping it
  // cancels it. A blocking `connect` held the whole runtime until the kernel gave up or got
  // through.
  #[test]
  fn connect_does_not_block_the_runtime() {
    use crate::net::TcpStream as _;
    let (_listener, socket_addr, _held) = full_listener();
    let runtime = UringRuntime::new().unwrap();
    let (ticks, elapsed) = runtime.block_on(async {
      let ticks = std::rc::Rc::new(Cell::new(0u32));
      let ticker_ticks = ticks.clone();
      let _ticker = crate::executor::Executor::spawn_local(
        &UringExecutor::default(),
        async move {
          loop {
            crate::futures::Sleep::new(core::time::Duration::from_millis(10))
              .unwrap()
              .await
              .unwrap();
            ticker_ticks.set(ticker_ticks.get() + 1);
          }
        },
        &UringRuntime::new().unwrap(),
      );
      let begin = std::time::Instant::now();
      let mut connect =
        alloc::boxed::Box::pin(super::UringTcpStream::connect(socket_addr, TcpParams::default()));
      let mut sleep = crate::futures::Sleep::new(core::time::Duration::from_millis(200)).unwrap();
      poll_fn(|cx| {
        if let Poll::Ready(rslt) = connect.as_mut().poll(cx) {
          let _rslt = rslt;
          return Poll::Ready(());
        }
        core::pin::Pin::new(&mut sleep).poll(cx).map(|_| ())
      })
      .await;
      let elapsed = begin.elapsed();
      // The cancelled connect gives its slot back, its socket closed.
      drop(connect);
      let free = || {
        super::with_reactor(|reactor| {
          Ok(reactor.connects.borrow().iter().all(|el| el.state == super::ConnectState::Free))
        })
        .unwrap()
      };
      for _ in 0..100 {
        if free() {
          break;
        }
        crate::futures::Sleep::new(core::time::Duration::from_millis(1)).unwrap().await.unwrap();
      }
      assert!(free(), "the cancelled connect kept its slot");
      (ticks.get(), elapsed)
    });
    assert!(
      elapsed < core::time::Duration::from_millis(900),
      "connect held the runtime {elapsed:?}"
    );
    assert!(ticks >= 5, "{ticks} ticks in {elapsed:?}");
  }

  // Connects reach IPv4 and IPv6 addresses and names, and a refused one fails with its error.
  #[test]
  fn connect_reaches_both_families_and_names() {
    use crate::net::{StreamReader, StreamWriter, TcpStream as _};
    let v4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let v6 = std::net::TcpListener::bind("[::1]:0").unwrap();
    let (v4_addr, v6_addr) = (v4.local_addr().unwrap(), v6.local_addr().unwrap());
    let echo = |listener: std::net::TcpListener, count: usize| {
      std::thread::spawn(move || {
        for _ in 0..count {
          let (mut stream, _) = listener.accept().unwrap();
          let mut byte = [0; 1];
          Read::read_exact(&mut stream, &mut byte).unwrap();
          Write::write_all(&mut stream, &byte).unwrap();
        }
      })
    };
    let (v4_server, v6_server) = (echo(v4, 2), echo(v6, 1));
    // A port nothing listens on: bound, then closed.
    let refused = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    UringRuntime::new().unwrap().block_on(async {
      let name = alloc::format!("localhost:{}", v4_addr.port());
      for (addr, byte) in [(v4_addr, 1u8), (v6_addr, 2)] {
        let mut stream = super::UringTcpStream::connect(addr, TcpParams::default()).await.unwrap();
        stream.write_all(&[byte]).await.unwrap();
        let mut buf = [0; 1];
        let _len = stream.read(buf.as_mut_slice().into()).await.unwrap();
        assert_eq!(buf, [byte]);
      }
      let mut stream =
        super::UringTcpStream::connect(name.as_str(), TcpParams::default()).await.unwrap();
      stream.write_all(&[3]).await.unwrap();
      let mut buf = [0; 1];
      let _len = stream.read(buf.as_mut_slice().into()).await.unwrap();
      assert_eq!(buf, [3]);
      let err = super::UringTcpStream::connect(refused, TcpParams::default()).await.unwrap_err();
      assert!(
        matches!(&err, crate::Error::Io(elem) if elem.raw_os_error() == Some(libc::ECONNREFUSED)),
        "{err:?}"
      );
    });
    v4_server.join().unwrap();
    v6_server.join().unwrap();
  }

  // A waker from another executor that, woken or dropped, drops a stream of this runtime: the
  // last reference to a nested executor's task, say, whose future holds the stream. Waking it,
  // or replacing it, with the connections borrowed made the stream's drop borrow them again, a
  // panic outside any task.
  #[test]
  fn a_waker_that_drops_a_stream_when_woken_or_replaced() {
    use crate::net::StreamReader;
    use core::task::{Context, RawWaker, RawWakerVTable, Waker};
    use std::rc::Rc;

    type Holder = core::cell::RefCell<Option<super::UringTcpStream>>;

    fn raw(holder: Rc<Holder>) -> RawWaker {
      RawWaker::new(Rc::into_raw(holder).cast(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(
      |data| {
        // SAFETY: `data` came from `Rc::into_raw` and is still counted
        unsafe { Rc::increment_strong_count(data.cast::<Holder>()) };
        raw_from(data)
      },
      |data| {
        // SAFETY: as above; the waker's count is taken back
        let holder = unsafe { Rc::from_raw(data.cast::<Holder>()) };
        drop(holder.borrow_mut().take());
      },
      |data| {
        // SAFETY: as above, borrowed
        let holder = unsafe { &*data.cast::<Holder>() };
        drop(holder.borrow_mut().take());
      },
      // SAFETY: as above; the waker's count is taken back
      |data| drop(unsafe { Rc::from_raw(data.cast::<Holder>()) }),
    );
    fn raw_from(data: *const ()) -> RawWaker {
      RawWaker::new(data, &VTABLE)
    }

    let addr = test_addr();
    let client_addr = addr.clone();
    let client = std::thread::spawn(move || {
      let mut first = connect(&client_addr);
      let mut second = connect(&client_addr);
      let mut third = connect(&client_addr);
      std::thread::sleep(core::time::Duration::from_millis(100));
      Write::write_all(&mut first, b"x").unwrap();
      // The other two streams were dropped by the wakers, so the server closed them.
      for stream in [&mut second, &mut third] {
        let mut rest = Vec::new();
        let _len = stream.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
      }
    });
    let runtime = UringRuntime::new().unwrap();
    runtime.block_on(async {
      let listener = bind(&addr).await;
      let (mut first, _) = listener.accept(TcpParams::default()).await.unwrap();
      let (second, _) = listener.accept(TcpParams::default()).await.unwrap();
      let (third, _) = listener.accept(TcpParams::default()).await.unwrap();
      let mut buf = [0u8; 1];
      // Registered, then replaced by the next one: dropped with the connections borrowed.
      for stream in [third, second] {
        let holder = Rc::new(core::cell::RefCell::new(Some(stream)));
        // SAFETY: the vtable keeps the `Rc` counts; the waker stays on this thread
        let waker = unsafe { Waker::from_raw(raw(holder)) };
        let mut read = core::pin::pin!(first.read(buf.as_mut_slice().into()));
        assert!(read.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
      }
      // The client's byte completes the receive, which wakes the waker above.
      crate::futures::Sleep::new(core::time::Duration::from_millis(300)).unwrap().await.unwrap();
      let len = first.read(buf.as_mut_slice().into()).await.unwrap();
      assert_eq!((len.map(core::num::NonZeroUsize::get), buf), (Some(1), *b"x"));
    });
    client.join().unwrap();
  }
}
