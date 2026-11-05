//! Kernel TLS (kTLS): after a TLS 1.3 handshake in user space, the kernel encrypts what is
//! written to the socket and decrypts what is read from it.
//!
//! <https://docs.kernel.org/networking/tls.html>
//!
//! The socket then carries plaintext as far as the process is concerned. A record that isn't
//! application data (an alert such as `close_notify`, a `KeyUpdate`) fails a plain read with
//! `EIO` and is read with [`read_record`]; records other than data are sent with
//! [`send_record`].

use crate::{
  sync::AtomicU8,
  tls::{CipherSuite, key_schedule::KeyScheduleState, ktls_bindings as kb},
};
use core::{mem::size_of, sync::atomic::Ordering};
use std::os::fd::RawFd;

/// Reads and writes at which a server connection may try to switch to kernel TLS before it stays
/// in user space.
pub(crate) const KERNEL_TLS_TRIES: u8 = 32;
pub(crate) const RECORD_ALERT: u8 = 21;
pub(crate) const RECORD_HANDSHAKE: u8 = 22;

// Whether this kernel offers TLS: unknown until the first try, then remembered so that a kernel
// without it costs one failed `setsockopt` per process instead of one per connection.
const UNKNOWN: u8 = 0;
const AVAILABLE: u8 = 1;
const UNAVAILABLE: u8 = 2;
static SUPPORT: AtomicU8 = AtomicU8::new(UNKNOWN);

/// The kernel's description of one direction's keys.
enum CryptoInfo {
  Aes128(kb::tls12_crypto_info_aes_gcm_128),
  Aes256(kb::tls12_crypto_info_aes_gcm_256),
  Chacha20(kb::tls12_crypto_info_chacha20_poly1305),
}

impl CryptoInfo {
  /// TLS 1.3 with the static IV split the kernel's way: for AES-GCM a 4-byte salt and an 8-byte
  /// IV, for ChaCha20 the whole 12 bytes as the IV. The record sequence is the next record's.
  fn new(state: &KeyScheduleState) -> Option<Self> {
    let info = |cipher: u32| kb::tls_crypto_info {
      version: ((kb::TLS_1_3_VERSION_MAJOR << 8) | kb::TLS_1_3_VERSION_MINOR) as u16,
      cipher_type: cipher as u16,
    };
    let key = state.cipher_key().as_slice();
    let iv = state.iv();
    let rec_seq = state.counter().to_be_bytes();
    Some(match state.cipher_suite() {
      CipherSuite::Aes128GcmSha256 => Self::Aes128(kb::tls12_crypto_info_aes_gcm_128 {
        info: info(kb::TLS_CIPHER_AES_GCM_128),
        iv: iv.get(4..)?.try_into().ok()?,
        key: key.try_into().ok()?,
        salt: iv.get(..4)?.try_into().ok()?,
        rec_seq,
      }),
      CipherSuite::Aes256GcmSha384 => Self::Aes256(kb::tls12_crypto_info_aes_gcm_256 {
        info: info(kb::TLS_CIPHER_AES_GCM_256),
        iv: iv.get(4..)?.try_into().ok()?,
        key: key.try_into().ok()?,
        salt: iv.get(..4)?.try_into().ok()?,
        rec_seq,
      }),
      CipherSuite::Chacha20Poly1305Sha256 => {
        Self::Chacha20(kb::tls12_crypto_info_chacha20_poly1305 {
          info: info(kb::TLS_CIPHER_CHACHA20_POLY1305),
          iv,
          key: key.try_into().ok()?,
          salt: kb::__IncompleteArrayField::new(),
          rec_seq,
        })
      }
    })
  }

  fn set(&self, fd: RawFd, direction: u32) -> std::io::Result<()> {
    let (ptr, len): (*const libc::c_void, usize) = match self {
      Self::Aes128(elem) => {
        ((&raw const *elem).cast(), size_of::<kb::tls12_crypto_info_aes_gcm_128>())
      }
      Self::Aes256(elem) => {
        ((&raw const *elem).cast(), size_of::<kb::tls12_crypto_info_aes_gcm_256>())
      }
      Self::Chacha20(elem) => {
        ((&raw const *elem).cast(), size_of::<kb::tls12_crypto_info_chacha20_poly1305>())
      }
    };
    // SAFETY: `ptr` points to a live crypto info of `len` bytes
    let rslt = unsafe {
      libc::setsockopt(fd, libc::SOL_TLS, direction as libc::c_int, ptr, len as libc::socklen_t)
    };
    if rslt != 0 {
      return Err(std::io::Error::last_os_error());
    }
    Ok(())
  }
}

impl Drop for CryptoInfo {
  fn drop(&mut self) {
    // The keys don't outlive their use in plain memory.
    let bytes: &mut [u8] = match self {
      Self::Aes128(elem) => &mut elem.key,
      Self::Aes256(elem) => &mut elem.key,
      Self::Chacha20(elem) => &mut elem.key,
    };
    for byte in bytes {
      // SAFETY: a valid `u8` place; volatile so the clear isn't optimized away
      unsafe { core::ptr::write_volatile(byte, 0) };
    }
  }
}

/// Hands the socket's records to the kernel: the `tls` upper layer protocol, then the keys of
/// both directions. The keys' counters must be those of the next record each way, and nothing
/// the peer sent after the handshake may have been read from the socket yet.
///
/// `Ok(false)` when the kernel doesn't offer TLS or this cipher, which leaves the socket as it was:
/// the connection then carries on in user space. An error means the kernel took one direction but
/// refused the other, and the connection can't continue.
pub(crate) fn enable(
  fd: RawFd,
  read: &KeyScheduleState,
  write: &KeyScheduleState,
) -> crate::Result<bool> {
  if SUPPORT.load(Ordering::Relaxed) == UNAVAILABLE {
    return Ok(false);
  }
  let (Some(tx), Some(rx)) = (CryptoInfo::new(write), CryptoInfo::new(read)) else {
    return Ok(false);
  };
  let ulp = b"tls";
  // SAFETY: `ulp` outlives the call and its length is passed
  let rslt = unsafe {
    libc::setsockopt(
      fd,
      libc::SOL_TCP,
      libc::TCP_ULP,
      ulp.as_ptr().cast(),
      ulp.len() as libc::socklen_t,
    )
  };
  if rslt != 0 {
    let err = std::io::Error::last_os_error();
    // No `tls` module that the kernel could load: don't try again in this process.
    if matches!(err.raw_os_error(), Some(libc::ENOENT | libc::ENOPROTOOPT | libc::EOPNOTSUPP)) {
      SUPPORT.store(UNAVAILABLE, Ordering::Relaxed);
    }
    return Ok(false);
  }
  SUPPORT.store(AVAILABLE, Ordering::Relaxed);
  // With the upper layer set but no keys, the socket still passes bytes through unchanged.
  if tx.set(fd, kb::TLS_TX).is_err() {
    return Ok(false);
  }
  rx.set(fd, kb::TLS_RX)?;
  Ok(true)
}

/// Reads the record a plain read refused with `EIO`: its content type and its payload, which
/// must fit `buffer`.
pub(crate) fn read_record(fd: RawFd, buffer: &mut [u8]) -> crate::Result<(u8, usize)> {
  let mut control = [0u64; 4];
  let mut iov = libc::iovec { iov_base: buffer.as_mut_ptr().cast(), iov_len: buffer.len() };
  // SAFETY: plain C struct, filled below
  let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
  msg.msg_iov = &raw mut iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control.as_mut_ptr().cast();
  msg.msg_controllen = size_of::<[u64; 4]>();
  // SAFETY: `msg` points to `iov` and `control`, which outlive the call
  let len = unsafe { libc::recvmsg(fd, &raw mut msg, libc::MSG_DONTWAIT) };
  if len < 0 {
    return Err(std::io::Error::last_os_error().into());
  }
  // SAFETY: `msg` was filled by `recvmsg`; the cmsg macros stay within `msg_controllen`
  let ty = unsafe {
    let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
    if cmsg.is_null()
      || (*cmsg).cmsg_level != libc::SOL_TLS
      || (*cmsg).cmsg_type != kb::TLS_GET_RECORD_TYPE as libc::c_int
    {
      return Err(std::io::Error::from_raw_os_error(libc::EPROTO).into());
    }
    *libc::CMSG_DATA(cmsg)
  };
  Ok((ty, len as usize))
}

/// Sends one record of content type `ty`: the kernel encrypts it as that type rather than as
/// application data.
pub(crate) fn send_record(fd: RawFd, ty: u8, payload: &[u8]) -> crate::Result<()> {
  let mut control = [0u64; 4];
  let mut iov =
    libc::iovec { iov_base: payload.as_ptr().cast_mut().cast(), iov_len: payload.len() };
  // SAFETY: plain C struct, filled below
  let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
  msg.msg_iov = &raw mut iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control.as_mut_ptr().cast();
  // SAFETY: computing the size needs no memory
  msg.msg_controllen = unsafe { libc::CMSG_SPACE(1) } as usize;
  // SAFETY: `control` holds one cmsg with a byte of data (`CMSG_SPACE(1)` fits in 32 bytes)
  unsafe {
    let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
    (*cmsg).cmsg_level = libc::SOL_TLS;
    (*cmsg).cmsg_type = kb::TLS_SET_RECORD_TYPE as libc::c_int;
    (*cmsg).cmsg_len = libc::CMSG_LEN(1) as usize;
    *libc::CMSG_DATA(cmsg) = ty;
  }
  // SAFETY: `msg` points to `iov` and `control`, which outlive the call
  let len = unsafe { libc::sendmsg(fd, &raw const msg, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
  if len < 0 {
    return Err(std::io::Error::last_os_error().into());
  }
  Ok(())
}

/// Whether an error is the `EIO` a kernel TLS socket gives a read that met a record other than
/// application data.
pub(crate) fn is_record_error(err: &crate::Error) -> bool {
  matches!(err, crate::Error::Io(elem) if elem.raw_os_error() == Some(libc::EIO))
}
