use crate::{
  collections::MaybeUninitSlice,
  net::{Stream, StreamCommon, StreamReader, StreamWriter, UdpStream},
};
use core::{net::SocketAddr, num::NonZeroUsize};
use std::{
  io::{Read, Write},
  net::{TcpStream, UdpSocket},
};

impl Stream for TcpStream {
  type BridgeOwned = ();
  type ReadHalfOwned = TcpStream;
  type WriteHalfOwned = TcpStream;

  #[inline]
  fn into_split(
    self,
  ) -> crate::Result<(Self::BridgeOwned, Self::ReadHalfOwned, Self::WriteHalfOwned)> {
    Ok(((), self.try_clone()?, self))
  }
}

impl StreamCommon for TcpStream {
  // Reads and writes are synchronous: nothing is read ahead of the caller or left to send.
  #[cfg(all(feature = "libc", feature = "tls", target_os = "linux"))]
  #[inline]
  fn with_kernel_tls(
    &mut self,
    cb: impl FnOnce(std::os::fd::RawFd) -> crate::Result<bool>,
  ) -> crate::Result<bool> {
    cb(std::os::fd::AsRawFd::as_raw_fd(self))
  }
}

#[cfg(unix)]
impl StreamCommon for std::os::unix::net::UnixStream {}

impl StreamReader for TcpStream {
  #[inline]
  async fn read(
    &mut self,
    mut bytes: MaybeUninitSlice<'_, u8>,
  ) -> crate::Result<Option<NonZeroUsize>> {
    Ok(NonZeroUsize::new(<Self as Read>::read(self, bytes.initialize_all_bytes())?))
  }

  #[cfg(all(feature = "libc", feature = "tls", target_os = "linux"))]
  #[inline]
  fn read_kernel_tls_record(&mut self, buffer: &mut [u8]) -> crate::Result<(u8, usize)> {
    crate::tls::kernel_tls::read_record(std::os::fd::AsRawFd::as_raw_fd(self), buffer)
  }
}

#[cfg(unix)]
impl StreamReader for std::os::unix::net::UnixStream {
  #[inline]
  async fn read(
    &mut self,
    mut bytes: MaybeUninitSlice<'_, u8>,
  ) -> crate::Result<Option<NonZeroUsize>> {
    Ok(NonZeroUsize::new(<Self as Read>::read(self, bytes.initialize_all_bytes())?))
  }
}

impl StreamWriter for TcpStream {
  #[inline]
  async fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
    <Self as Write>::write_all(self, bytes)?;
    Ok(())
  }

  #[cfg(all(feature = "libc", feature = "tls", target_os = "linux"))]
  #[inline]
  fn send_kernel_tls_alert(&mut self, level: u8, description: u8) -> crate::Result<()> {
    crate::tls::kernel_tls::send_record(
      std::os::fd::AsRawFd::as_raw_fd(self),
      crate::tls::kernel_tls::RECORD_ALERT,
      &[level, description],
    )
  }

  #[inline]
  async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<()> {
    _local_write_all_vectored!(bytes, self, |io_slices| self.write_vectored(io_slices));
    Ok(())
  }
}

#[cfg(unix)]
impl StreamWriter for std::os::unix::net::UnixStream {
  #[inline]
  async fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
    <Self as Write>::write_all(self, bytes)?;
    Ok(())
  }

  #[inline]
  async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<()> {
    _local_write_all_vectored!(bytes, self, |io_slices| self.write_vectored(io_slices));
    Ok(())
  }
}

impl UdpStream for UdpSocket {
  #[inline]
  async fn recv_from(&mut self, buffer: &mut [u8]) -> crate::Result<(usize, SocketAddr)> {
    Ok((*self).recv_from(buffer)?)
  }

  #[inline]
  async fn send_to(&mut self, bytes: &mut [u8], addr: SocketAddr) -> crate::Result<usize> {
    Ok((*self).send_to(bytes, addr)?)
  }
}
