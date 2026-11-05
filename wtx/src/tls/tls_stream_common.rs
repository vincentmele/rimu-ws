use crate::sync::{AtomicBool, AtomicU8, AtomicWaker};

#[derive(Debug)]
pub(crate) struct TlsStreamCommon {
  pub(crate) can_reply_key_update: AtomicBool,
  pub(crate) connection_state: AtomicU8,
  // The kernel encrypts and decrypts the records (see `TlsStream::kernel_tls`)
  pub(crate) kernel_tls: bool,
  pub(crate) reader_waker: AtomicWaker,
}
