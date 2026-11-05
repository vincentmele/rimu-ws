use crate::sync::{Arc, AtomicBool, SyncMutex};
use alloc::vec::Vec;
use core::{
  future::poll_fn,
  sync::atomic::Ordering,
  task::{Context, Poll, Waker},
};

/// Tells servers to stop: they stop accepting, give their connections a while to finish, and
/// return. Clones share one signal, so a handler can keep one and wait on [`Self::triggered`] to
/// close its connection itself (for example with close code 1001, going away).
#[derive(Clone)]
pub struct ShutdownSignal(Arc<Inner>);

struct Inner {
  triggered: AtomicBool,
  wakers: SyncMutex<Vec<Waker>>,
}

impl ShutdownSignal {
  /// A signal not yet triggered.
  #[inline]
  #[must_use]
  pub fn new() -> Self {
    Self(Arc::new(Inner { triggered: AtomicBool::new(false), wakers: SyncMutex::new(Vec::new()) }))
  }

  /// Whether [`Self::trigger`] was called.
  #[inline]
  #[must_use]
  pub fn is_triggered(&self) -> bool {
    self.0.triggered.load(Ordering::Acquire)
  }

  /// Triggers the signal and wakes everything waiting on it, from any thread.
  #[inline]
  pub fn trigger(&self) {
    self.0.triggered.store(true, Ordering::Release);
    let wakers = core::mem::take(&mut *self.0.wakers.lock());
    for waker in wakers {
      waker.wake();
    }
  }

  /// Resolves once the signal is triggered.
  #[inline]
  pub async fn triggered(&self) {
    poll_fn(|cx| self.poll_triggered(cx)).await;
  }

  pub(crate) fn poll_triggered(&self, cx: &Context<'_>) -> Poll<()> {
    if self.is_triggered() {
      return Poll::Ready(());
    }
    {
      let mut wakers = self.0.wakers.lock();
      if !wakers.iter().any(|el| el.will_wake(cx.waker())) {
        wakers.push(cx.waker().clone());
      }
    }
    // Triggered while the waker was being stored
    if self.is_triggered() {
      return Poll::Ready(());
    }
    Poll::Pending
  }
}

impl Default for ShutdownSignal {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

impl core::fmt::Debug for ShutdownSignal {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("ShutdownSignal").field("triggered", &self.is_triggered()).finish()
  }
}
