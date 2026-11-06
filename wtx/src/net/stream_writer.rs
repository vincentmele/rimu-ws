use crate::net::StreamCommon;

/// A stream of values written asynchronously.
pub trait StreamWriter: StreamCommon {
  /// Attempts to write ***all*** `bytes`.
  fn write_all(&mut self, bytes: &[u8]) -> impl Future<Output = crate::Result<()>>;

  /// Attempts to write ***all*** `bytes` of all slices in a single syscall.
  ///
  /// # Panics
  ///
  /// If the length of the outermost slice is greater than 8.
  fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> impl Future<Output = crate::Result<()>>;

  /// [`Self::write_all_vectored`] without awaiting, for streams that can take the bytes at once.
  /// Returns `false`, having written nothing, when the bytes would have to wait, and then
  /// [`Self::write_all_vectored`] should be awaited. The default never writes.
  #[inline]
  fn try_write_all_vectored(&mut self, _bytes: &[&[u8]]) -> crate::Result<bool> {
    Ok(false)
  }

  /// [`Self::try_write_all_vectored`] for one buffer that the stream may take instead of copy:
  /// `true` when it took or queued all of `bytes`, which then holds an empty buffer (perhaps a
  /// recycled one, with capacity) for the caller to write its next bytes into. `false` leaves
  /// `bytes` as it was. The default never takes.
  #[inline]
  fn try_send_owned(&mut self, _bytes: &mut alloc::vec::Vec<u8>) -> crate::Result<bool> {
    Ok(false)
  }

  /// For kernel TLS: sends an alert record after what was written before it, which may be once
  /// those bytes are out. The default, for streams without kernel TLS, fails with `Unsupported`.
  #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
  #[inline]
  fn send_kernel_tls_alert(&mut self, level: u8, description: u8) -> crate::Result<()> {
    let _ = (level, description);
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported).into())
  }
}

impl<T> StreamWriter for &mut T
where
  T: StreamWriter,
{
  #[inline]
  async fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
    (**self).write_all(bytes).await
  }

  #[inline]
  async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<()> {
    (**self).write_all_vectored(bytes).await
  }

  #[inline]
  fn try_write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<bool> {
    (**self).try_write_all_vectored(bytes)
  }

  #[inline]
  fn try_send_owned(&mut self, bytes: &mut alloc::vec::Vec<u8>) -> crate::Result<bool> {
    (**self).try_send_owned(bytes)
  }

  #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
  #[inline]
  fn send_kernel_tls_alert(&mut self, level: u8, description: u8) -> crate::Result<()> {
    (**self).send_kernel_tls_alert(level, description)
  }
}

impl StreamWriter for () {
  #[inline]
  async fn write_all(&mut self, _: &[u8]) -> crate::Result<()> {
    Ok(())
  }

  #[inline]
  async fn write_all_vectored(&mut self, _: &[&[u8]]) -> crate::Result<()> {
    Ok(())
  }
}
