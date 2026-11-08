use core::ptr;

/// Sets the first `len` elements pointed by `dst` according to the specified `src`.
///
/// Volatile operations are intended to act on I/O memory, and are guaranteed to not be elided or
/// reordered by the compiler across other volatile operations.
///
/// # Safety
///
/// `dst` must be a valid continuous block of allocated memory with at least `len` elements.
#[inline(never)]
pub unsafe fn memset_volatile<T>(dst: *mut T, src: T, len: usize)
where
  T: Copy + Sized,
{
  for idx in 0..len {
    // Safety: up to the caller
    let ptr = unsafe { dst.add(idx) };
    // Safety: up to the caller
    unsafe {
      ptr::write_volatile(ptr, src);
    }
  }
}

/// Fills `slice` with elements through the copying of `src`.
///
/// Volatile operations are intended to act on I/O memory, and are guaranteed to not be elided or
/// reordered by the compiler across other volatile operations.
#[inline]
pub fn memset_slice_volatile<T>(slice: &mut [T], src: T)
where
  T: Copy + Sized,
{
  let len = slice.len();
  let dst = slice.as_mut_ptr().cast();
  // SAFETY: parameters are originated from an existing slice
  unsafe {
    memset_volatile(dst, src, len);
  }
}

/// Writes `len` zero bytes at `ptr` with volatile stores (a word at a time where aligned), which
/// the compiler may not remove or merge into a later write or free: memory that held a secret is
/// cleared before it is handed back to an allocator or to a pool, even when it is freed right
/// after. A plain `write_bytes` before a free is a dead store the optimizer may delete.
///
/// # Safety
///
/// `ptr` must be valid for writes of `len` bytes.
#[inline(never)]
pub(crate) unsafe fn zero_volatile(ptr: *mut u8, len: usize) {
  let word = size_of::<usize>();
  let head = ptr.align_offset(word).min(len);
  let words = len.wrapping_sub(head) / word;
  for idx in 0..head {
    // SAFETY: within the `len` bytes the caller vouches for
    unsafe { ptr::write_volatile(ptr.add(idx), 0) };
  }
  // SAFETY: `head` bytes in, the pointer is aligned for `usize`
  let words_ptr = unsafe { ptr.add(head) }.cast::<usize>();
  for idx in 0..words {
    // SAFETY: aligned, and within the `len` bytes the caller vouches for
    unsafe { ptr::write_volatile(words_ptr.add(idx), 0) };
  }
  for idx in head.wrapping_add(words.wrapping_mul(word))..len {
    // SAFETY: within the `len` bytes the caller vouches for
    unsafe { ptr::write_volatile(ptr.add(idx), 0) };
  }
  core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
  #[cfg(all(test, feature = "std"))]
  ZEROED.with(|el| el.set(el.get().wrapping_add(len)));
}

#[cfg(all(test, feature = "std"))]
std::thread_local! {
  /// Bytes [`zero_volatile`] cleared on this thread, for tests that pin a path as clearing.
  pub(crate) static ZEROED: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Locks a chunk of data into RAM, preventing it from being paged to the swap area.
///
/// # Safety
///
/// * `addr` must point to `len` bytes of valid memory
#[cfg(feature = "libc")]
#[inline]
pub unsafe fn mlock(_addr: *mut u8, _len: usize) -> crate::Result<()> {
  // SAFETY: up to the caller
  let mlock = unsafe { libc::mlock(_addr.cast(), _len) };
  if mlock != 0 {
    return Err(crate::Error::MlockError);
  }
  Ok(())
}

/// Safer [`mlock`] version.
#[cfg(feature = "libc")]
#[inline]
pub fn mlock_slice(_slice: &mut [u8]) -> crate::Result<()> {
  // SAFETY: parameters come from a valid slice
  #[cfg(not(miri))]
  unsafe {
    let len = _slice.len();
    mlock(_slice.as_mut_ptr(), len)?;
  }
  Ok(())
}

/// Unlocks memory flagged with [`mlock`].
///
/// # Safety
///
/// * `addr` must point to `len` bytes of valid memory
#[cfg(feature = "libc")]
#[inline]
pub unsafe fn munlock(_addr: *mut u8, _len: usize) -> crate::Result<()> {
  // SAFETY: up to the caller
  let munlock = unsafe { libc::munlock(_addr.cast(), _len) };
  if munlock != 0 {
    return Err(crate::Error::MunlockError);
  }
  Ok(())
}

/// Safer [`munlock`] version.
#[cfg(feature = "libc")]
#[inline]
pub fn munlock_slice(_slice: &mut [u8]) -> crate::Result<()> {
  // SAFETY: parameters come from a valid slice
  #[cfg(not(miri))]
  unsafe {
    let len = _slice.len();
    munlock(_slice.as_mut_ptr(), len)?;
  }
  Ok(())
}

#[cfg(all(feature = "libc", test))]
mod tests {
  use crate::{
    collections::VectorUsize,
    misc::{mlock, mlock_slice, munlock, munlock_slice},
  };

  #[cfg_attr(miri, ignore)]
  #[test]
  fn mlock_and_munlock() {
    let mut data = VectorUsize::with_capacity(1024).unwrap();
    unsafe {
      mlock(data.as_mut_ptr(), data.capacity()).unwrap();
    }
    unsafe {
      munlock(data.as_mut_ptr(), data.capacity()).unwrap();
    }
  }

  #[cfg_attr(miri, ignore)]
  #[test]
  fn mlock_and_munlock_slice() {
    let mut data = [1, 2, 3, 4];
    mlock_slice(&mut data).unwrap();
    munlock_slice(&mut data).unwrap();
  }
}
