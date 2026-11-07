use crate::net::UriString;
use alloc::string::String;
use std::sync::OnceLock;
use rimu_ws::misc::EnvVars;

pub(crate) static _PUBLIC_KEY: &[u8] = include_bytes!("../../.certs/cert.pem");
pub(crate) static _SECRET_KEY: &[u8] = include_bytes!("../../.certs/key.pem");
pub(crate) static _ROOT_CA: &[u8] = include_bytes!("../../.certs/root-ca.crt");

#[allow(unused, reason = "depends on feature")]
#[derive(Debug, rimu_ws::FromVars)]
pub(crate) struct Vars {
  pub(crate) wtx_database_uri_postgres: String,
}

pub(crate) fn _uri() -> UriString {
  // A port the kernel reports free: fixed ranges collide with other services on the machine and
  // with the previous run's connections in TIME_WAIT.
  let port = std::net::TcpListener::bind("127.0.0.1:0")
    .and_then(|el| el.local_addr())
    .map(|el| el.port())
    .unwrap_or(0);
  UriString::new(alloc::format!("http://127.0.0.1:{port}"))
}

pub(crate) fn _vars() -> &'static Vars {
  static VARS: OnceLock<Vars> = OnceLock::new();
  VARS.get_or_init(|| EnvVars::from_available([]).unwrap().finish())
}

/// Allocations made by threads that called [`_count_allocations`], for tests that pin a path as
/// allocation-free.
pub(crate) static _ALLOCATIONS: crate::sync::AtomicU64 = crate::sync::AtomicU64::new(0);

std::thread_local! {
  static COUNTING: core::cell::Cell<Option<&'static crate::sync::AtomicU64>> =
    const { core::cell::Cell::new(None) };
}

/// Counts this thread's allocations in [`_ALLOCATIONS`] from now on.
pub(crate) fn _count_allocations() {
  _count_allocations_in(&_ALLOCATIONS);
}

/// Counts this thread's allocations in `counter` from now on: a test of its own counter is not
/// disturbed by the threads of the tests that run alongside.
pub(crate) fn _count_allocations_in(counter: &'static crate::sync::AtomicU64) {
  COUNTING.with(|el| el.set(Some(counter)));
}

struct CountingAlloc;

impl CountingAlloc {
  fn count() {
    if let Some(counter) = COUNTING.try_with(core::cell::Cell::get).ok().flatten() {
      let _ = counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
  }
}

// SAFETY: every call is forwarded to the system allocator unchanged.
unsafe impl core::alloc::GlobalAlloc for CountingAlloc {
  unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
    Self::count();
    // SAFETY: forwarded as is
    unsafe { core::alloc::GlobalAlloc::alloc(&std::alloc::System, layout) }
  }

  unsafe fn alloc_zeroed(&self, layout: core::alloc::Layout) -> *mut u8 {
    Self::count();
    // SAFETY: forwarded as is
    unsafe { core::alloc::GlobalAlloc::alloc_zeroed(&std::alloc::System, layout) }
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
    // SAFETY: forwarded as is
    unsafe { core::alloc::GlobalAlloc::dealloc(&std::alloc::System, ptr, layout) }
  }

  unsafe fn realloc(&self, ptr: *mut u8, layout: core::alloc::Layout, new_size: usize) -> *mut u8 {
    Self::count();
    // SAFETY: forwarded as is
    unsafe { core::alloc::GlobalAlloc::realloc(&std::alloc::System, ptr, layout, new_size) }
  }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;
