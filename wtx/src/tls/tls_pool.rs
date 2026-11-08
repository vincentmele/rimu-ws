//! Per-thread pools of TLS connection state, so that a warm thread allocates none of it per
//! connection: the boxes of key schedules ([`KsBox`]) and the buffers of streams ([`TlsBuffer`]).
//!
//! Whatever comes back is zeroed first, all of it: a key schedule holds a connection's secrets, a
//! buffer its handshake and decrypted data, and the next connection must find none of them. This
//! covers key material and TLS record buffers only: the decrypted requests and responses the
//! HTTP/1.1 driver keeps in its own pools (`CONN_POOL`, `RX_POOL`) are reused without being zeroed,
//! and are only ever read through the lengths of what the next connection wrote (unreachable from
//! safe code). The
//! pools are bounded in count and bytes, and trimmed to a few entries once their thread has no
//! connection open (see [`trim_idle_pools`]).

use crate::{
  collections::VectorUsize,
  misc::zero_volatile,
  tls::{KeySchedule, TlsBuffer},
};
use alloc::boxed::Box;
use core::{
  mem::{ManuallyDrop, MaybeUninit},
  ops::{Deref, DerefMut},
};

/// Key schedule boxes a thread keeps, and with no connection open.
const KS_POOL_MAX: usize = 64;
#[cfg(all(feature = "io-uring", target_os = "linux"))]
const KS_POOL_IDLE_KEEP: usize = 4;
/// Buffer pairs a thread keeps, of at most `BUF_POOL_BYTES` in all; buffers larger than
/// `BUF_MAX` are freed. With no connection open: the most recent `BUF_POOL_IDLE_KEEP` within
/// `BUF_POOL_IDLE_BYTES`.
const BUF_POOL_MAX: usize = 64;
const BUF_POOL_BYTES: usize = 8 << 20;
const BUF_MAX: usize = 1 << 20;
#[cfg(all(feature = "io-uring", target_os = "linux"))]
const BUF_POOL_IDLE_KEEP: usize = 4;
#[cfg(all(feature = "io-uring", target_os = "linux"))]
const BUF_POOL_IDLE_BYTES: usize = 2 << 20;

#[cfg(feature = "std")]
std::thread_local! {
  #[allow(clippy::vec_box, reason = "the boxes are what is pooled")]
  static KS_POOL: core::cell::RefCell<alloc::vec::Vec<Box<MaybeUninit<KeySchedule>>>> =
    const { core::cell::RefCell::new(alloc::vec::Vec::new()) };
  static BUF_POOL: core::cell::RefCell<BufPool> =
    const { core::cell::RefCell::new(BufPool { bytes: 0, pairs: alloc::vec::Vec::new() }) };
}

/// Reader and writer buffers of ended streams, zeroed and emptied, most recent last.
#[derive(Debug)]
struct BufPool {
  bytes: usize,
  pairs: alloc::vec::Vec<(VectorUsize<u8>, VectorUsize<u8>)>,
}

/// Frees the oldest entries of this thread's pools until a few are left: called once the thread
/// has no connection open.
#[cfg(all(feature = "io-uring", target_os = "linux"))]
#[inline]
pub(crate) fn trim_idle_pools() {
  #[cfg(feature = "std")]
  {
    let _rslt = KS_POOL.try_with(|pool| {
      if let Ok(mut elem) = pool.try_borrow_mut() {
        let excess = elem.len().saturating_sub(KS_POOL_IDLE_KEEP);
        let _ = elem.drain(..excess);
      }
    });
    let _rslt = BUF_POOL.try_with(|pool| {
      if let Ok(mut elem) = pool.try_borrow_mut() {
        let mut kept = 0usize;
        let mut total = 0usize;
        let mut first = elem.pairs.len();
        for (idx, pair) in elem.pairs.iter().enumerate().rev() {
          let bytes = pair.0.capacity().saturating_add(pair.1.capacity());
          if kept == BUF_POOL_IDLE_KEEP || total.saturating_add(bytes) > BUF_POOL_IDLE_BYTES {
            break;
          }
          total = total.saturating_add(bytes);
          kept = kept.wrapping_add(1);
          first = idx;
        }
        let _ = elem.pairs.drain(..first);
        elem.bytes = total;
      }
    });
  }
}

/// Zeroes all of `buffer`'s capacity, with stores the compiler may not drop (whether the buffer is
/// then pooled or freed), then empties it.
fn zero_buffer(buffer: &mut VectorUsize<u8>) {
  let capacity = buffer.capacity();
  // SAFETY: the allocation has `capacity` bytes, written here as plain bytes
  unsafe { zero_volatile(buffer.as_ptr_mut(), capacity) };
  buffer.clear();
}

/// A boxed [`KeySchedule`] whose box comes from, and goes back to, this thread's pool, zeroed.
pub(crate) struct KsBox(ManuallyDrop<Box<KeySchedule>>);

impl KsBox {
  /// `key_schedule` in a pooled box, or a new one.
  #[inline]
  pub(crate) fn new(key_schedule: KeySchedule) -> Self {
    #[cfg(feature = "std")]
    if let Some(elem) = KS_POOL.try_with(|pool| pool.try_borrow_mut().ok()?.pop()).ok().flatten() {
      return Self(ManuallyDrop::new(Box::write(elem, key_schedule)));
    }
    Self(ManuallyDrop::new(Box::new(key_schedule)))
  }

  /// The key schedule, moved out of its box, which goes back zeroed.
  #[inline]
  pub(crate) fn into_inner(self) -> KeySchedule {
    let mut this = ManuallyDrop::new(self);
    // SAFETY: `this` is never used or dropped again
    let raw = Box::into_raw(unsafe { ManuallyDrop::take(&mut this.0) });
    // SAFETY: `raw` is a valid, owned key schedule, read once and never dropped in place
    let value = unsafe { raw.read() };
    // SAFETY: what `raw` held was moved out
    unsafe { give_back(raw.cast()) };
    value
  }
}

/// Zeroes the box of a key schedule that was dropped or moved out, and keeps it, or frees it if
/// the pool is full.
///
/// # Safety
///
/// `raw` comes from `Box::into_raw` of a `Box<KeySchedule>` whose value is no longer used.
unsafe fn give_back(raw: *mut MaybeUninit<KeySchedule>) {
  // SAFETY: the allocation has room for a key schedule, written here as plain bytes, with stores
  // the compiler may not drop: the box is pooled or freed right after
  unsafe { zero_volatile(raw.cast::<u8>(), size_of::<KeySchedule>()) };
  // SAFETY: `MaybeUninit<KeySchedule>` has the layout of `KeySchedule`, which `raw` was boxed with
  let elem = unsafe { Box::from_raw(raw) };
  #[cfg(feature = "std")]
  {
    let mut elem = Some(elem);
    let _rslt = KS_POOL.try_with(|pool| {
      if let Ok(mut pool) = pool.try_borrow_mut()
        && pool.len() < KS_POOL_MAX
        && let Some(value) = elem.take()
      {
        pool.push(value);
      }
    });
    drop(elem);
  }
  #[cfg(not(feature = "std"))]
  drop(elem);
}

impl Deref for KsBox {
  type Target = KeySchedule;

  #[inline]
  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl DerefMut for KsBox {
  #[inline]
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.0
  }
}

impl core::fmt::Debug for KsBox {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    (**self.0).fmt(f)
  }
}

impl Drop for KsBox {
  #[inline]
  fn drop(&mut self) {
    // SAFETY: `self.0` is never used again
    let raw = Box::into_raw(unsafe { ManuallyDrop::take(&mut self.0) });
    // SAFETY: a valid key schedule, dropped once, here
    unsafe { core::ptr::drop_in_place(raw) };
    // SAFETY: its value was dropped
    unsafe { give_back(raw.cast()) };
  }
}

impl TlsBuffer {
  /// Buffers an ended stream of this thread left, or empty ones.
  #[inline]
  pub(crate) fn pooled() -> Self {
    #[cfg(feature = "std")]
    if let Some((reader, writer)) = BUF_POOL
      .try_with(|pool| {
        let mut pool = pool.try_borrow_mut().ok()?;
        let pair = pool.pairs.pop()?;
        pool.bytes = pool.bytes.saturating_sub(pair.0.capacity().saturating_add(pair.1.capacity()));
        Some(pair)
      })
      .ok()
      .flatten()
    {
      let reader_buffer = crate::net::BufStreamReader::with_buffer(reader);
      return Self { reader_buffer, writer_buffer: writer };
    }
    Self::new()
  }
}

impl Drop for TlsBuffer {
  #[inline]
  fn drop(&mut self) {
    let mut reader = self.reader_buffer.take_buffer();
    let mut writer = core::mem::take(&mut self.writer_buffer);
    let mut bytes = 0usize;
    for buffer in [&mut reader, &mut writer] {
      zero_buffer(buffer);
      if buffer.capacity() > BUF_MAX {
        *buffer = VectorUsize::new();
      }
      bytes = bytes.saturating_add(buffer.capacity());
    }
    if bytes == 0 {
      return;
    }
    #[cfg(feature = "std")]
    {
      let mut pair = Some((reader, writer));
      let _rslt = BUF_POOL.try_with(|pool| {
        if let Ok(mut pool) = pool.try_borrow_mut()
          && pool.pairs.len() < BUF_POOL_MAX
          && pool.bytes.saturating_add(bytes) <= BUF_POOL_BYTES
          && let Some(value) = pair.take()
        {
          pool.bytes = pool.bytes.wrapping_add(bytes);
          pool.pairs.push(value);
        }
      });
      drop(pair);
    }
  }
}

/// Empties this thread's pools, so that what a test returns to them is the last entry.
#[cfg(all(test, feature = "std"))]
pub(crate) fn clear_thread_pools() {
  KS_POOL.with(|el| el.borrow_mut().clear());
  BUF_POOL.with(|el| {
    let mut pool = el.borrow_mut();
    pool.pairs.clear();
    pool.bytes = 0;
  });
}

/// Where the last key schedule box and the last buffer pair this thread pooled are, each with
/// whether all of its bytes (the whole capacity, for buffers) are zero.
#[cfg(all(test, feature = "std"))]
pub(crate) fn last_pooled() -> (Option<(usize, bool)>, Option<[(usize, bool); 2]>) {
  let zeroed = |ptr: *const u8, len| {
    // SAFETY: the `len` bytes from `ptr` belong to one allocation (a pooled box or the capacity
    // of a pooled buffer), every byte of which was written with a zero when it was pooled
    unsafe { core::slice::from_raw_parts(ptr, len) }.iter().all(|el| *el == 0)
  };
  let ks = KS_POOL.with(|pool| {
    let ptr = (&raw const **pool.borrow().last()?).cast::<u8>();
    Some((ptr.addr(), zeroed(ptr, size_of::<KeySchedule>())))
  });
  let buffers = BUF_POOL.with(|pool| {
    let pool = pool.borrow();
    let (reader, writer) = pool.pairs.last()?;
    Some([reader, writer].map(|el| (el.as_ptr().addr(), zeroed(el.as_ptr(), el.capacity()))))
  });
  (ks, buffers)
}

#[cfg(all(test, feature = "std"))]
mod tests {
  use crate::tls::{
    KeySchedule, TlsBuffer,
    tls_pool::{BUF_POOL, KS_POOL, KsBox},
  };

  // A key schedule's box comes back zeroed, and is the next one's.
  #[test]
  fn key_schedule_box_comes_back_zeroed() {
    KS_POOL.with(|el| el.borrow_mut().clear());
    // `unset`: the crypto backend is not needed, so Miri runs this too
    let ks = KsBox::new(KeySchedule::unset());
    let addr = (&raw const *ks).addr();
    drop(ks);
    KS_POOL.with(|pool| {
      let pool = pool.borrow();
      let elem = pool.last().unwrap();
      let ptr = (&raw const **elem).cast::<u8>();
      assert_eq!(ptr.addr(), addr);
      // SAFETY: the pool's box, every byte of which was written with a zero
      let bytes = unsafe { core::slice::from_raw_parts(ptr, size_of::<KeySchedule>()) };
      assert!(bytes.iter().all(|el| *el == 0), "a pooled key schedule kept its bytes");
    });
    let again = KsBox::new(KeySchedule::unset());
    assert_eq!((&raw const *again).addr(), addr);
    let _moved = again.into_inner();
    assert!(KS_POOL.with(|el| el.borrow().len()) == 1);
  }

  // What leaves for the allocator is cleared too, with stores the compiler may not drop: a key
  // schedule box when the pool is full, a buffer too large to pool.
  #[test]
  fn secrets_are_zeroed_on_every_free_path() {
    use crate::{misc::ZEROED, tls::tls_pool::KS_POOL_MAX};
    let zeroed = || ZEROED.with(core::cell::Cell::get);
    KS_POOL.with(|el| el.borrow_mut().clear());
    let boxes: alloc::vec::Vec<_> =
      (0..=KS_POOL_MAX).map(|_| KsBox::new(KeySchedule::unset())).collect();
    let before = zeroed();
    drop(boxes);
    let cleared = zeroed() - before;
    assert_eq!(KS_POOL.with(|el| el.borrow().len()), KS_POOL_MAX);
    assert_eq!(
      cleared,
      (KS_POOL_MAX + 1) * size_of::<KeySchedule>(),
      "a key schedule box left uncleared"
    );
    BUF_POOL.with(|el| el.borrow_mut().pairs.clear());
    let mut buffer = TlsBuffer::pooled();
    buffer.writer_buffer.reserve(2 << 20).unwrap();
    let capacity = buffer.writer_buffer.capacity();
    let before = zeroed();
    drop(buffer);
    assert!(zeroed() - before >= capacity, "a buffer too large to pool was freed uncleared");
    assert!(BUF_POOL.with(|el| el.borrow().pairs.is_empty()));
  }

  // What the helper for the tests of other modules reports: the last entries, zeroed.
  #[test]
  fn last_pooled_reports_the_last_entries() {
    use crate::tls::tls_pool::{clear_thread_pools, last_pooled};
    clear_thread_pools();
    assert_eq!(last_pooled(), (None, None));
    let ks = KsBox::new(KeySchedule::unset());
    let ks_addr = (&raw const *ks).addr();
    let mut buffer = TlsBuffer::pooled();
    buffer.writer_buffer.extend_from_copyable_slice(&[7; 100]).unwrap();
    buffer.reader_buffer.buffer_mut().extend_from_copyable_slice(&[9; 10]).unwrap();
    let addrs =
      [buffer.reader_buffer.buffer_mut().as_ptr().addr(), buffer.writer_buffer.as_ptr().addr()];
    drop((ks, buffer));
    assert_eq!(last_pooled(), (Some((ks_addr, true)), Some(addrs.map(|el| (el, true)))));
  }

  // A stream's buffers come back zeroed in all of their capacity, and are the next one's.
  #[test]
  fn tls_buffers_come_back_zeroed() {
    BUF_POOL.with(|el| el.borrow_mut().pairs.clear());
    let mut buffer = TlsBuffer::pooled();
    buffer.writer_buffer.extend_from_copyable_slice(&[7; 1000]).unwrap();
    buffer.writer_buffer.truncate(10);
    let addr = buffer.writer_buffer.as_ptr().addr();
    drop(buffer);
    BUF_POOL.with(|pool| {
      let pool = pool.borrow();
      let (_, writer) = pool.pairs.last().unwrap();
      assert_eq!((writer.as_ptr().addr(), writer.len()), (addr, 0));
      // SAFETY: the pool's buffer, every byte of whose capacity was written with a zero
      let bytes = unsafe { core::slice::from_raw_parts(writer.as_ptr(), writer.capacity()) };
      assert!(bytes.len() >= 1000 && bytes.iter().all(|el| *el == 0));
    });
    let again = TlsBuffer::pooled();
    assert_eq!(again.writer_buffer.as_ptr().addr(), addr);
  }
}
