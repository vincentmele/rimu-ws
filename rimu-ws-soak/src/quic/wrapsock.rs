//! A `quinn::AsyncUdpSocket` wrapper (ruling T23-j #3) around several inner sockets, so one quinn
//! connection's datagrams can be spread across source addresses per datagram (the migration
//! flapper) and the client's transmit can be black-holed after the request (the never-ACK slow
//! reader). It counts bytes in and out per inner socket, so the flapper can assert the server sends
//! at most 3× to an unvalidated address what that address sent (RFC 9000 anti-amplification).

use quinn::{
  AsyncUdpSocket, UdpPoller,
  udp::{RecvMeta, Transmit},
};
use std::{
  fmt,
  io::{self, IoSliceMut},
  pin::Pin,
  sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
  },
  task::{Context, Poll},
};

/// Wraps N inner UDP sockets. Each `try_send` goes out the next inner in turn (so a single quinn
/// connection's datagrams alternate source address per datagram); `poll_recv` polls them all. Byte
/// counters per inner feed the 3× amplification check. `blackhole` drops all sends when set.
pub struct FlapSocket {
  inners: Vec<Arc<dyn AsyncUdpSocket>>,
  next: AtomicUsize,
  bytes_out: Vec<AtomicU64>,
  bytes_in: Vec<AtomicU64>,
  blackhole: Arc<AtomicBool>,
  flap: Arc<AtomicBool>,
}

impl fmt::Debug for FlapSocket {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("FlapSocket").field("inners", &self.inners.len()).finish()
  }
}

impl FlapSocket {
  /// Wraps the given inner sockets (at least one). The flapper passes two or more; the never-ACK
  /// reader passes one and flips [`Self::blackhole_handle`].
  pub fn new(inners: Vec<Arc<dyn AsyncUdpSocket>>) -> Arc<Self> {
    let n = inners.len().max(1);
    Arc::new(Self {
      inners,
      next: AtomicUsize::new(0),
      bytes_out: (0..n).map(|_| AtomicU64::new(0)).collect(),
      bytes_in: (0..n).map(|_| AtomicU64::new(0)).collect(),
      blackhole: Arc::new(AtomicBool::new(false)),
      flap: Arc::new(AtomicBool::new(false)),
    })
  }

  /// A handle that, when set to `true`, starts alternating the source socket on every send. Kept
  /// `false` through the handshake so it completes on one path, then turned on to flap.
  pub fn flap_handle(&self) -> Arc<AtomicBool> {
    self.flap.clone()
  }

  /// A handle that, when set to `true`, makes every later send a silent no-op (the client stops
  /// ACKing — the never-ACK slow reader).
  pub fn blackhole_handle(&self) -> Arc<AtomicBool> {
    self.blackhole.clone()
  }

  /// Bytes sent from inner socket `i` (what source address `i` sent).
  pub fn bytes_out(&self, i: usize) -> u64 {
    self.bytes_out.get(i).map_or(0, |el| el.load(Ordering::Relaxed))
  }

  /// Bytes received on inner socket `i` (what the server sent to source address `i`).
  pub fn bytes_in(&self, i: usize) -> u64 {
    self.bytes_in.get(i).map_or(0, |el| el.load(Ordering::Relaxed))
  }

  /// Number of inner sockets.
  pub fn len(&self) -> usize {
    self.inners.len()
  }
}

impl AsyncUdpSocket for FlapSocket {
  fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
    // Writability of the first inner stands in for the set: on loopback a UDP socket is almost
    // always writable, and quinn only consults the poller after a WouldBlock.
    self.inners[0].clone().create_io_poller()
  }

  fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
    if self.blackhole.load(Ordering::Relaxed) {
      return Ok(()); // the never-ACK reader: pretend the datagram left.
    }
    let idx = if self.flap.load(Ordering::Relaxed) {
      self.next.fetch_add(1, Ordering::Relaxed) % self.inners.len()
    } else {
      0 // pinned to one path until flapping is turned on (e.g. through the handshake).
    };
    let res = self.inners[idx].try_send(transmit);
    if res.is_ok() {
      self.bytes_out[idx].fetch_add(transmit.contents.len() as u64, Ordering::Relaxed);
    }
    res
  }

  fn poll_recv(
    &self,
    cx: &mut Context,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
  ) -> Poll<io::Result<usize>> {
    // Poll every inner with the same waker, so a wakeup on any re-polls all. Return the first that
    // has datagrams, counting their bytes against that inner.
    for (idx, inner) in self.inners.iter().enumerate() {
      match inner.poll_recv(cx, bufs, meta) {
        Poll::Ready(Ok(n)) => {
          let total: usize = meta.get(..n).unwrap_or(&[]).iter().map(|el| el.len).sum();
          self.bytes_in[idx].fetch_add(total as u64, Ordering::Relaxed);
          return Poll::Ready(Ok(n));
        }
        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        Poll::Pending => {}
      }
    }
    Poll::Pending
  }

  fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
    self.inners[0].local_addr()
  }

  fn max_transmit_segments(&self) -> usize {
    1 // one datagram per send, so each alternates source address.
  }

  fn max_receive_segments(&self) -> usize {
    1
  }
}
