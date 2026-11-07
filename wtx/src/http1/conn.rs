//! Sans-I/O keep-alive HTTP/1.1 connection core.

use crate::{
  http::{HttpRecvParams, StatusCode},
  http1::Http1Request,
};
use alloc::vec::Vec;

/// What a connection needs next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http1Event {
  /// A request is ready to be inspected through [`Http1Conn::request`].
  RequestReady,
  /// More input is required.
  NeedMore,
  /// The connection must be closed.
  Closed,
}

/// Keep-alive connection state.
#[derive(Debug)]
pub struct Http1Conn {
  _private: (),
}

impl Http1Conn {
  /// New connection.
  #[inline]
  pub fn new(_params: &HttpRecvParams) -> Self {
    Self { _private: () }
  }

  /// Buffers `input`, returning how many bytes were consumed.
  #[inline]
  pub fn feed(&mut self, _input: &[u8]) -> crate::Result<usize> {
    todo!()
  }

  /// Advances the state machine.
  #[inline]
  pub fn poll_event(&mut self) -> Http1Event {
    todo!()
  }

  /// Current request. Valid only right after [`Http1Event::RequestReady`].
  #[inline]
  pub fn request(&self) -> Option<Http1Request<'_>> {
    todo!()
  }

  /// Queues the response of the current request.
  #[inline]
  pub fn respond(&mut self, _status: StatusCode, _content_type: &str, _body: &[u8]) {
    todo!()
  }

  /// Takes the pending output, swapping in `spare`. Returns `spare` back in `Err` if there is
  /// nothing to send.
  #[inline]
  pub fn take_output(&mut self, _spare: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
    todo!()
  }

  /// Marks `n` bytes of the taken output as sent.
  #[inline]
  pub fn advance_output(&mut self, _n: usize) {
    todo!()
  }

  /// If the connection should be closed once the output is flushed.
  #[inline]
  pub fn wants_close(&self) -> bool {
    todo!()
  }
}
