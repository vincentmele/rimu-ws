//! The server side of the upgrade over scripted bytes, for tests and the fuzzer: whatever a
//! client sends, the server upgrades it, refuses it with a 400 or 431, or closes, and reads only
//! a bounded amount of it.

use crate::{
  collections::MaybeUninitSlice,
  net::{Stream, StreamCommon, StreamReader, StreamWriter},
  rng::{ChaCha20, CryptoSeedableRng as _},
  tls::{TlsAcceptor, TlsConfig},
  web_socket::{WebSocketAcceptor, handshake::MAX_REQUEST_LEN},
};
use alloc::{rc::Rc, vec::Vec};
use core::{
  cell::{Cell, RefCell},
  num::NonZeroUsize,
  pin::pin,
  task::{Context, Poll, Waker},
};

/// How the server answered.
#[derive(Debug)]
pub struct Served {
  /// What it wrote.
  pub answer: Vec<u8>,
  /// How many bytes it read.
  pub read: usize,
  /// Whether `accept` returned a WebSocket.
  pub upgraded: bool,
}

/// Feeds `input` to the server `chunk` bytes per read, then reports the end of the stream.
struct Scripted {
  chunk: usize,
  input: Vec<u8>,
  output: Rc<RefCell<Vec<u8>>>,
  pos: Rc<Cell<usize>>,
}

impl Stream for Scripted {
  type BridgeOwned = ();
  type ReadHalfOwned = ();
  type WriteHalfOwned = ();

  fn into_split(self) -> crate::Result<((), (), ())> {
    Ok(((), (), ()))
  }
}

impl StreamCommon for Scripted {}

impl StreamReader for Scripted {
  async fn read(&mut self, mut bytes: MaybeUninitSlice<'_, u8>) -> crate::Result<Option<NonZeroUsize>> {
    let init = bytes.initialize_all_bytes();
    let pos = self.pos.get();
    let rest = self.input.get(pos..).unwrap_or_default();
    let len = init.len().min(self.chunk).min(rest.len());
    init.get_mut(..len).unwrap_or_default().copy_from_slice(rest.get(..len).unwrap_or_default());
    self.pos.set(pos.wrapping_add(len));
    Ok(NonZeroUsize::new(len))
  }
}

impl StreamWriter for Scripted {
  async fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
    self.output.borrow_mut().extend_from_slice(bytes);
    Ok(())
  }

  async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<()> {
    for elem in bytes {
      self.output.borrow_mut().extend_from_slice(elem);
    }
    Ok(())
  }
}

/// Runs the server's upgrade over `input`, read `chunk` bytes at a time.
pub fn serve(input: &[u8], chunk: usize) -> Served {
  let output = Rc::new(RefCell::new(Vec::new()));
  let pos = Rc::new(Cell::new(0));
  let stream =
    Scripted { chunk: chunk.max(1), input: input.to_vec(), output: output.clone(), pos: pos.clone() };
  let tls_config = TlsConfig::plaintext();
  let Ok(rng) = ChaCha20::from_seed([7; 32]) else { return Served { answer: Vec::new(), read: 0, upgraded: false } };
  let mut fut = pin!(async {
    WebSocketAcceptor::default().accept(TlsAcceptor::new(&tls_config, rng, stream)).await.is_ok()
  });
  // The stream never waits, so neither does the upgrade.
  let mut cx = Context::from_waker(Waker::noop());
  let upgraded = loop {
    if let Poll::Ready(elem) = fut.as_mut().poll(&mut cx) {
      break elem;
    }
  };
  let answer = output.borrow().clone();
  Served { answer, read: pos.get(), upgraded }
}

/// The fuzzer's oracle: the first byte sets the read size, the rest is what the client sends. The
/// server never reads more than the request limit and one read, and answers with a 101 (when it
/// upgraded), a 400 or a 431, or nothing.
pub fn check_bytes(data: &[u8]) {
  let [chunk, input @ ..] = data else { return };
  let chunk = usize::from(*chunk).max(1);
  let served = serve(input, chunk);
  assert!(
    served.read <= MAX_REQUEST_LEN.wrapping_add(chunk),
    "read {} bytes of a request",
    served.read
  );
  let answer = served.answer.as_slice();
  if served.upgraded {
    assert!(answer.starts_with(b"HTTP/1.1 101 "), "upgraded with {answer:?}");
    let accept = b"Sec-WebSocket-Accept: ";
    let at = answer.windows(accept.len()).position(|el| el == accept);
    let key = at.and_then(|el| answer.get(el.wrapping_add(accept.len())..).and_then(|rest| rest.get(..28)));
    assert!(key.is_some_and(|el| el.ends_with(b"=")), "upgraded with {answer:?}");
  } else {
    assert!(
      answer.is_empty() || answer.starts_with(b"HTTP/1.1 400 ") || answer.starts_with(b"HTTP/1.1 431 "),
      "refused with {answer:?}"
    );
  }
}
