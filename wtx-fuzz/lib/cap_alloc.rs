//! A global allocator that tells how much heap one input of a fuzz target held at its peak, so
//! that the target can fail an input that needs more than `CAP` bytes.

use std::{
  alloc::{GlobalAlloc, Layout, System},
  sync::atomic::{AtomicUsize, Ordering::Relaxed},
};

/// The most heap, beyond what was live when the input started, that an input may hold.
pub const CAP: usize = 128 << 20;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Counts the bytes that are live and their peak.
pub struct CapAlloc;

impl CapAlloc {
  fn grew(by: usize) {
    let live = LIVE.fetch_add(by, Relaxed).wrapping_add(by);
    let _prev = PEAK.fetch_max(live, Relaxed);
  }
}

// SAFETY: every call is forwarded to the system allocator unchanged, only counted.
unsafe impl GlobalAlloc for CapAlloc {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    // SAFETY: forwarded as is
    let ptr = unsafe { System.alloc(layout) };
    if !ptr.is_null() {
      Self::grew(layout.size());
    }
    ptr
  }

  unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
    // SAFETY: forwarded as is
    let ptr = unsafe { System.alloc_zeroed(layout) };
    if !ptr.is_null() {
      Self::grew(layout.size());
    }
    ptr
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
    let _prev = LIVE.fetch_sub(layout.size(), Relaxed);
    // SAFETY: forwarded as is
    unsafe { System.dealloc(ptr, layout) }
  }

  unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    // SAFETY: forwarded as is
    let new = unsafe { System.realloc(ptr, layout, new_size) };
    if !new.is_null() {
      if new_size >= layout.size() {
        Self::grew(new_size - layout.size());
      } else {
        let _prev = LIVE.fetch_sub(layout.size() - new_size, Relaxed);
      }
    }
    new
  }
}

/// Starts the measure of an input: the live heap now.
pub fn start() -> usize {
  let live = LIVE.load(Relaxed);
  PEAK.store(live, Relaxed);
  live
}

/// Fails if the input held more than `CAP` bytes beyond `base`, the value of [`start`].
pub fn check(base: usize) {
  let peak = PEAK.load(Relaxed);
  assert!(peak.saturating_sub(base) <= CAP, "the input needed {} bytes of heap", peak.saturating_sub(base));
}
