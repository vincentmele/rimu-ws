/// Common stream properties for both readers and writers
pub trait StreamCommon {
  /// For kernel TLS: calls `cb` with the stream's socket if nothing the stream took from it is
  /// still unread, and returns its result. Unread bytes mean the kernel would start mid-stream, so
  /// then `cb` isn't called and the result is `false`. The default, for streams without a socket
  /// the kernel can take, is `false` too.
  #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
  #[inline]
  fn with_kernel_tls(
    &mut self,
    cb: impl FnOnce(std::os::fd::RawFd) -> crate::Result<bool>,
  ) -> crate::Result<bool> {
    drop(cb);
    Ok(false)
  }
}

impl<T> StreamCommon for &mut T
where
  T: StreamCommon,
{
  #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
  #[inline]
  fn with_kernel_tls(
    &mut self,
    cb: impl FnOnce(std::os::fd::RawFd) -> crate::Result<bool>,
  ) -> crate::Result<bool> {
    (**self).with_kernel_tls(cb)
  }
}

impl StreamCommon for () {}
