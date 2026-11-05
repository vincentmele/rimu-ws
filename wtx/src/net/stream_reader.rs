use crate::{collections::MaybeUninitSlice, net::StreamCommon};
use core::num::NonZeroUsize;

/// What [`StreamReader::try_read`] found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TryRead {
  /// The peer closed the stream.
  Closed,
  /// Nothing has arrived yet.
  Pending,
  /// This many bytes were read.
  Read(NonZeroUsize),
  /// The stream can't read without awaiting: use [`StreamReader::read`].
  Unsupported,
}

/// A stream of values sent asynchronously.
pub trait StreamReader: StreamCommon {
  /// Pulls some bytes from this source into the specified buffer, returning how many bytes
  /// were read.
  fn read(
    &mut self,
    bytes: MaybeUninitSlice<'_, u8>,
  ) -> impl Future<Output = crate::Result<Option<NonZeroUsize>>>;

  /// [`Self::read`] without awaiting, for streams that know whether bytes already arrived.
  /// [`TryRead::Pending`] means nothing has arrived yet: await [`Self::readable`] and try again.
  /// The default returns [`TryRead::Unsupported`], and then [`Self::read`] should be awaited.
  #[inline]
  fn try_read(&mut self, _bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<TryRead> {
    Ok(TryRead::Unsupported)
  }

  /// Waits until [`Self::try_read`] has something to report: bytes, the end of the stream or an
  /// error. The default is ready at once.
  #[inline]
  fn readable(&mut self) -> impl Future<Output = crate::Result<()>> {
    async { Ok(()) }
  }

  /// For kernel TLS: reads the record a read refused with `EIO`, returning its content type and
  /// its length in `buffer`.
  #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
  #[inline]
  fn read_kernel_tls_record(&mut self, buffer: &mut [u8]) -> crate::Result<(u8, usize)> {
    let _ = buffer;
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported).into())
  }

  /// Reads and at the same time discards exactly `len` bytes.
  #[inline]
  fn read_skip(&mut self, len: usize) -> impl Future<Output = crate::Result<()>> {
    async move {
      let mut buffer = [0; 32];
      let mut counter = len;
      for _ in 0..len {
        if counter == 0 {
          break;
        }
        let slice = if let Some(el) = buffer.get_mut(..counter) { el } else { &mut buffer[..] };
        let Some(read) = self.read(slice.into()).await? else {
          return Err(crate::net::NetError::UnexpectedStreamReadEOF.into());
        };
        counter = counter.wrapping_sub(read.get());
      }
      Ok(())
    }
  }
}

impl<T> StreamReader for &mut T
where
  T: StreamReader,
{
  #[inline]
  async fn read(&mut self, bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<Option<NonZeroUsize>> {
    (**self).read(bytes).await
  }

  #[inline]
  fn try_read(&mut self, bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<TryRead> {
    (**self).try_read(bytes)
  }

  #[inline]
  fn readable(&mut self) -> impl Future<Output = crate::Result<()>> {
    (**self).readable()
  }

  #[cfg(all(feature = "libc", feature = "std", target_os = "linux"))]
  #[inline]
  fn read_kernel_tls_record(&mut self, buffer: &mut [u8]) -> crate::Result<(u8, usize)> {
    (**self).read_kernel_tls_record(buffer)
  }
}

impl StreamReader for () {
  #[inline]
  async fn read(&mut self, _: MaybeUninitSlice<'_, u8>) -> crate::Result<Option<NonZeroUsize>> {
    Ok(None)
  }
}
