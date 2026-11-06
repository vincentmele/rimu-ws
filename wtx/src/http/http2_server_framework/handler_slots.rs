//! Handler futures of one connection, each pinned into a reusable heap slot before it is first
//! polled.
//!
//! A future that finishes in its first poll costs no allocation once the connection has warmed
//! up: the slot is emptied and kept. A future that waits stays where it is (it is pinned and never
//! moves) and is polled again when its waker fires.

// `std::task::Wake` is implemented for `alloc::sync::Arc` only.
#![allow(clippy::disallowed_types, reason = "`Waker::from` needs the standard `Arc`")]

use crate::{
  collections::VectorUsize,
  sync::{Arc, AtomicWaker, SyncMutex},
};
use alloc::boxed::Box;
use core::{
  panic::AssertUnwindSafe,
  pin::Pin,
  sync::atomic::{AtomicBool, Ordering},
  task::{Context, Poll, Waker},
};

/// What wakes a connection: the slots whose futures want another poll.
#[derive(Debug)]
pub(crate) struct WakeShared {
  conn: AtomicWaker,
  woken: SyncMutex<VectorUsize<usize>>,
}

impl WakeShared {
  fn new() -> Self {
    Self { conn: AtomicWaker::new(), woken: SyncMutex::new(VectorUsize::new()) }
  }
}

#[derive(Debug)]
struct SlotWaker {
  idx: usize,
  queued: AtomicBool,
  shared: Arc<WakeShared>,
}

impl std::task::Wake for SlotWaker {
  fn wake(self: alloc::sync::Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &alloc::sync::Arc<Self>) {
    if !self.queued.swap(true, Ordering::AcqRel) {
      let _rslt = self.shared.woken.lock().push(self.idx);
    }
    self.shared.conn.wake();
  }
}

struct Slot<F> {
  fut: Pin<Box<Option<F>>>,
  stream_id: u32,
  wake: alloc::sync::Arc<SlotWaker>,
  waker: Waker,
}

/// How a slot's poll ended.
pub(crate) enum SlotPoll<T> {
  /// The future finished.
  Done(T),
  /// The future panicked; its slot is free again.
  Panicked,
  /// The future waits.
  Pending,
}

/// The handler futures of a connection.
pub(crate) struct HandlerSlots<F> {
  free: VectorUsize<usize>,
  len: usize,
  shared: Arc<WakeShared>,
  slots: VectorUsize<Slot<F>>,
}

impl<F> HandlerSlots<F>
where
  F: Future,
{
  pub(crate) fn new() -> Self {
    Self {
      free: VectorUsize::new(),
      len: 0,
      shared: Arc::new(WakeShared::new()),
      slots: VectorUsize::new(),
    }
  }

  /// Futures not finished yet.
  pub(crate) const fn len(&self) -> usize {
    self.len
  }

  /// Pins `fut`, for stream `stream_id`, into a free slot and returns the slot.
  pub(crate) fn insert(&mut self, stream_id: u32, fut: F) -> crate::Result<usize> {
    let idx = if let Some(idx) = self.free.pop() {
      idx
    } else {
      let idx = self.slots.len();
      let wake = alloc::sync::Arc::new(SlotWaker {
        idx,
        queued: AtomicBool::new(false),
        shared: self.shared.clone(),
      });
      let waker = Waker::from(wake.clone());
      self.slots.push(Slot { fut: Box::pin(None), stream_id: 0, wake, waker })?;
      idx
    };
    let slot = self.slots.get_mut(idx).ok_or(crate::Error::ProgrammingError)?;
    slot.fut.as_mut().set(Some(fut));
    slot.stream_id = stream_id;
    slot.wake.queued.store(false, Ordering::Release);
    self.len = self.len.wrapping_add(1);
    Ok(idx)
  }

  /// The stream of slot `idx`, if it holds a future.
  pub(crate) fn stream_id(&self, idx: usize) -> Option<u32> {
    let slot = self.slots.get(idx)?;
    slot.fut.is_some().then_some(slot.stream_id)
  }

  /// Polls the future in slot `idx`, with a panic caught and confined to it.
  pub(crate) fn poll(&mut self, idx: usize) -> SlotPoll<F::Output> {
    let Some(slot) = self.slots.get_mut(idx) else {
      return SlotPoll::Pending;
    };
    slot.wake.queued.store(false, Ordering::Release);
    let mut cx = Context::from_waker(&slot.waker);
    let fut = &mut slot.fut;
    let rslt = std::panic::catch_unwind(AssertUnwindSafe(|| {
      fut.as_mut().as_pin_mut().map(|el| el.poll(&mut cx))
    }));
    match rslt {
      Ok(None | Some(Poll::Pending)) => SlotPoll::Pending,
      Ok(Some(Poll::Ready(output))) => {
        self.release(idx);
        SlotPoll::Done(output)
      }
      Err(_) => {
        self.release(idx);
        SlotPoll::Panicked
      }
    }
  }

  /// Drops the future of `stream_id`, if one waits.
  pub(crate) fn remove_stream(&mut self, stream_id: u32) -> bool {
    let found = self
      .slots
      .iter()
      .position(|el| el.fut.is_some() && el.stream_id == stream_id);
    if let Some(idx) = found {
      self.release(idx);
      return true;
    }
    false
  }

  /// Moves the slots woken since the last call into `out`.
  pub(crate) fn take_woken(&self, out: &mut VectorUsize<usize>) -> crate::Result<()> {
    let mut woken = self.shared.woken.lock();
    out.extend_from_copyable_slice(woken.as_slice())?;
    woken.clear();
    Ok(())
  }

  /// Whether a slot was woken since the last [`Self::take_woken`].
  pub(crate) fn has_woken(&self) -> bool {
    !self.shared.woken.lock().as_slice().is_empty()
  }

  /// The waker of the connection task, which a slot's wake also wakes.
  pub(crate) fn register_conn(&self, waker: &Waker) {
    self.shared.conn.register(waker);
  }

  fn release(&mut self, idx: usize) {
    if let Some(slot) = self.slots.get_mut(idx) {
      // Dropping the future may run arbitrary code: it must not unwind into the connection.
      let fut = &mut slot.fut;
      let _rslt = std::panic::catch_unwind(AssertUnwindSafe(|| fut.as_mut().set(None)));
      slot.stream_id = 0;
      self.len = self.len.saturating_sub(1);
      let _rslt = self.free.push(idx);
    }
  }
}
