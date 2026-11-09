//! UDP sockets on the ring, for the QUIC endpoint of a worker (spec section 5.2).
//!
//! A socket receives with one multishot `IORING_OP_RECVMSG` into a ring of provided buffers of its
//! own: buffer group `BUF_GROUP_UDP` plus the socket's slot. Each completion leaves a datagram in
//! its buffer, which [`UringUdpSocket::poll_recv`] hands out **in place**, mutable so that it can
//! be decrypted there, with the peer, the local address it was sent to (`IP_PKTINFO` /
//! `IPV6_PKTINFO`) and, with generic receive offload, the size of the datagrams it coalesces. The
//! buffer goes back to the ring once the callback returns. When every buffer is in use the kernel
//! ends the multishot receive with `ENOBUFS`; the datagrams wait in the socket until `poll_recv`
//! has given the buffers back and armed it again.
//!
//! Datagrams are sent from the socket's [`TxArena`]: [`UringUdpSocket::submit`] queues one
//! `IORING_OP_SENDMSG` per pending train, with `UDP_SEGMENT` for a train of more than one
//! datagram and `IP_PKTINFO` / `IPV6_PKTINFO` for the local address it must leave from. The
//! msghdr, iovec, address and control messages of each train stay in a slot of the socket until
//! the train's completion, which gives its space back to the arena whether the send succeeded or
//! failed: a failed train counts as sent, and QUIC's loss recovery takes care of its packets
//! (ruling T11-e). Every datagram has DF set and the kernel's path MTU ignored
//! (`IP_PMTUDISC_PROBE`, `IPV6_PMTUDISC_PROBE`): QUIC finds the path MTU itself (ruling T11-d).
//!
//! With [`UdpParams::zerocopy`] the trains go with `IORING_OP_SENDMSG_ZC` instead (ruling T19-b):
//! the kernel sends from the bytes of the arena, which it pins, instead of copying them into pages
//! of its own (which it zeroes first under `init_on_alloc`). It reads them until the send's
//! notification (`IORING_CQE_F_NOTIF`), which follows the completion of the send itself: a train
//! is given back to the arena, and its slot freed, only once both arrived ([`SendWait`]), so that
//! no byte of a train the kernel may still read is written again. A ring that does not know the
//! operation, a zero-copy send that the kernel refuses (`EOPNOTSUPP`), or a first zero-copy result
//! of `EINVAL` or `ENOMEM` (the pinned pages over `RLIMIT_MEMLOCK`), turns it off for the socket,
//! which then copies; each such fallback is counted ([`UdpStats::zc_fallbacks`]). The kernel may
//! copy anyway (for a loopback peer it copies on delivery), which each notification reports
//! ([`UdpStats::zc_copied`]). A socket closes only once every notification arrived; a runtime that
//! is dropped with notifications outstanding (teardown only) closes the ring first, and the kernel
//! keeps its own references to the pinned pages until it is done with them, whatever becomes of the
//! arena.
//!
//! The datagrams that other workers forward to this one (spec section 5.11) arrive through the
//! socket's [`UdpInbox`], whose pushes wake the socket's ring with an `IORING_OP_MSG_RING` sent
//! from the ring of the worker that forwards.
//!
//! A turn of the runtime reaps every completion before it polls the tasks they woke, so the task
//! of an endpoint is woken once per turn with all the datagrams of that turn already queued, and
//! what it submits goes out with the one `io_uring_enter` that ends the turn. A runtime with no
//! UDP socket runs none of this: its completions never carry the kinds of this module.

use crate::{
  executor::uring_executor::{
    BUF_GROUP_UDP, BufRing, CURRENT, ClearOnDrop, KIND_MSG_RING, KIND_MSG_RING_SENT, KIND_UDP_RECV,
    KIND_UDP_SEND, Message, Reactor, bump, cancel_sqe, io_err, own_reactor, send_to_runtime,
    set_waker, user_data, with_reactor, write_sockaddr,
  },
  quic::{DatagramMeta, STEERING_PROGRAM_LEN, SteeringProgram, TrainId, TxArena},
  sync::{Arc, AtomicBool, AtomicUsize, AtomicWaker, CachePadded},
};
use alloc::{boxed::Box, collections::VecDeque, rc::Rc, vec::Vec};
use core::{
  cell::{Cell, RefCell, RefMut, UnsafeCell},
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
  sync::atomic::Ordering,
  task::{Context, Poll, Waker},
};
use io_uring::{cqueue, opcode, types};
use std::os::fd::{FromRawFd, RawFd};

// A receive buffer starts with what the kernel writes before the payload: its header
// (`io_uring_recvmsg_out`), room for the peer's address (a `sockaddr_in6` has 28 bytes) and room
// for the control messages: `IPV6_PKTINFO` (40 bytes) and `IP_PKTINFO` (32), which an IPv4
// datagram on a dual-stack socket gets both of, and `UDP_GRO` (24), with 32 bytes to spare for
// one the socket did not ask for. Control messages that still don't fit are counted
// (`UdpStats::control_truncated`).
const RECV_OUT_LEN: usize = 16;
const RECV_NAME_LEN: usize = 32;
const RECV_CONTROL_LEN: usize = 128;
const RECV_HEADROOM: usize = RECV_OUT_LEN + RECV_NAME_LEN + RECV_CONTROL_LEN;
// What a buffer holds of a coalesced datagram, which carries at most 65,535 bytes of IP payload
const GRO_RECV_LEN: u32 = 65_536;
// The receive buffers of a socket stay within this: fewer buffers, never shorter ones
const MAX_RECV_RING: usize = 512 << 20;
// The kernel takes at most 32768 buffers in a ring
const MAX_RECV_BUFFERS: u16 = 32_768;
// `UDP_SEGMENT` (24 bytes), then `IPV6_PKTINFO` (40) or `IP_PKTINFO` (32)
const SEND_CONTROL_LEN: usize = 64;
// The `ioprio` flag of a zero-copy send that asks its notification to say whether the kernel
// copied the bytes after all (`IORING_SEND_ZC_REPORT_USAGE`, Linux 6.2), and the bit of the
// notification's result that says so (`IORING_NOTIF_USAGE_ZC_COPIED`): the io-uring crate does
// not export them
const SEND_ZC_REPORT_USAGE: u16 = 1 << 3;
const NOTIF_USAGE_ZC_COPIED: u32 = 1 << 31;
// The user data of a send carries the socket's slot in its low 16 bits and the send's slot in
// the high 16; the buffer group of a socket is `BUF_GROUP_UDP` plus its slot.
const MAX_SOCKETS: usize = 4096;
const MAX_SEND_SLOTS: usize = 1 << 16;
// The generations of the user data have 28 bits
const GENERATION_MASK: u32 = 0x0FFF_FFFF;
// The kernel's `cmsghdr`: a `size_t` length, then the level and the type, two `int`s. With musl
// the length is a `socklen_t` and padding, which a native `usize` writes the same way.
const CMSG_HEADER: usize = size_of::<libc::cmsghdr>();
const _: () = assert!(CMSG_HEADER == size_of::<usize>() + 8);

/// Settings of a [`UringUdpSocket`].
#[derive(Clone, Copy, Debug)]
pub struct UdpParams {
  /// Buffers of the socket's receive ring, rounded up to a power of two, at most 32768. When all
  /// are in use the datagrams wait in the socket until [`UringUdpSocket::poll_recv`] gives
  /// buffers back. Defaults to 256.
  pub recv_buffers: u16,
  /// Bytes of datagram that a receive buffer holds, besides the room the kernel takes for the
  /// addresses and control messages; a longer datagram is dropped. With [`Self::gro`] at least
  /// 65,536, enough for a coalesced datagram. The buffers are made fewer to keep a socket's ring
  /// within 512 MiB. Defaults to 2048.
  pub recv_buffer_len: u32,
  /// Generic receive offload (`UDP_GRO`): the kernel coalesces datagrams of a flow that arrive
  /// together into one and reports their size in [`DatagramMeta::segment_size`]; the receive
  /// buffers are then 64 KiB each (256 of them: 256 x 65,536 B, exactly 16 MiB or 16.8 MB, per
  /// socket). Defaults to `false` (ruling T16-h): on, it measured 2.8 % less server CPU per request
  /// at 0.8 % more requests per second on HttpArena baseline-h3 (task 16, EC2; static-h3 unchanged
  /// within the spread), but its ring equals the 16 MiB pool budget of a worker (spec section 5.4)
  /// by itself, leaving nothing for the other pools (48 workers: 768 MiB). Turn it on where
  /// the memory is there, with fewer [`Self::recv_buffers`] to keep the ring small.
  pub gro: bool,
  /// The `SO_RCVBUF` asked for. The kernel caps it at `net.core.rmem_max`, which is never raised
  /// here; what it granted is in [`UdpStats::rcvbuf`]. Defaults to 4 MiB.
  pub rcvbuf: usize,
  /// The `SO_SNDBUF` asked for, capped at `net.core.wmem_max`; what the kernel granted is in
  /// [`UdpStats::sndbuf`]. Defaults to 4 MiB.
  pub sndbuf: usize,
  /// `SO_REUSEPORT`, so that one socket per worker binds the same address and port: the order in
  /// which they bind is the index that [`UringUdpSocket::attach_reuseport_cbpf`] steers to.
  /// Defaults to `true`.
  ///
  /// With it, a bind to port 0 can get the port of a live `SO_REUSEPORT` socket of the same user
  /// and join its group (the kernel does not take such a port for used), which then shares its
  /// datagrams. Servers bind a fixed port; a socket bound to port 0, a client's or a test's,
  /// should turn this off.
  pub reuseport: bool,
  /// Bytes of the socket's [`TxArena`]. Defaults to [`TxArena::DEFAULT_BYTES`], 512 × 1500.
  pub tx_arena_bytes: usize,
  /// The datagrams of one send at most (one `UDP_SEGMENT` train), from 1 to 64, the kernel's
  /// limit. Defaults to 64 (task 19 measures it).
  pub max_train_segments: u16,
  /// Zero-copy sends (`IORING_OP_SENDMSG_ZC`, Linux 6.0, with the copy report of Linux 6.2): the
  /// kernel sends from the arena instead of copying each train into pages of its own, and the
  /// train's bytes stay the kernel's until its notification (see the
  /// [module documentation](self)). Where the kernel refuses, the socket copies instead
  /// ([`UdpStats::zc_fallbacks`]). Without `CAP_IPC_LOCK` the pinned bytes count against
  /// `RLIMIT_MEMLOCK`. Defaults to `false` (task 19 measures it, ruling T19-b).
  pub zerocopy: bool,
}

impl UdpParams {
  /// The defaults of the fields.
  #[inline]
  pub const fn new() -> Self {
    Self {
      recv_buffers: 256,
      recv_buffer_len: 2048,
      gro: false,
      rcvbuf: 4 << 20,
      sndbuf: 4 << 20,
      reuseport: true,
      tx_arena_bytes: TxArena::DEFAULT_BYTES,
      max_train_segments: 64,
      zerocopy: false,
    }
  }
}

impl Default for UdpParams {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

/// What a [`UringUdpSocket`] has seen since it was bound, and the socket buffers the kernel
/// granted. Taken with [`UringUdpSocket::stats`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdpStats {
  /// Datagrams handed to the callback of [`UringUdpSocket::poll_recv`].
  pub datagrams_in: u64,
  /// Datagrams longer than a receive buffer, dropped (see [`UdpParams::recv_buffer_len`]).
  pub datagrams_truncated: u64,
  /// Datagrams whose source the kernel did not report as an IPv4 or IPv6 address, dropped.
  pub datagrams_without_address: u64,
  /// Datagrams handed out whose control messages did not all fit their room (`MSG_CTRUNC`):
  /// their local address or segment size may be missing.
  pub control_truncated: u64,
  /// Times the multishot receive ended because every receive buffer was in use; the datagrams
  /// waited in the socket meanwhile (see [`UdpParams::recv_buffers`]).
  pub recv_buffers_exhausted: u64,
  /// Receives that failed otherwise.
  pub recv_errors: u64,
  /// Trains handed to the kernel, one send each.
  pub trains_out: u64,
  /// Trains that could not be sent: their space was given back, and their packets count as sent
  /// and lost.
  pub send_errors: u64,
  /// Of [`Self::trains_out`], those sent zero-copy ([`UdpParams::zerocopy`]).
  pub zc_sends: u64,
  /// Notifications of zero-copy sends: the kernel was done with the bytes of that many trains.
  pub zc_notifications: u64,
  /// Of [`Self::zc_notifications`], those that reported that the kernel copied the bytes after
  /// all (on a loopback it copies them on delivery).
  pub zc_copied: u64,
  /// Times zero-copy was turned off for the socket: the ring does not know the operation, or
  /// the kernel refused a zero-copy send (that train counts in [`Self::send_errors`]).
  pub zc_fallbacks: u64,
  /// Datagrams taken from the socket's [`UdpInbox`].
  pub inbox_in: u64,
  /// Times the ring of another runtime woke this one for the inbox.
  pub inbox_wakes: u64,
  /// The receive buffer the kernel granted, as `SO_RCVBUF` reads back: Linux doubles the size
  /// asked for, capped at `net.core.rmem_max`, to leave room for its bookkeeping.
  pub rcvbuf: usize,
  /// The send buffer the kernel granted, as `SO_SNDBUF` reads back (doubled the same way, capped
  /// at `net.core.wmem_max`).
  pub sndbuf: usize,
}

/// A UDP socket of the runtime of the current thread, for a QUIC endpoint. See the
/// [module documentation](self).
///
/// It stays on the runtime that bound it: elsewhere, the methods that reach the ring fail with
/// `EBADF`.
pub struct UringUdpSocket {
  generation: u32,
  idx: u32,
  runtime: u32,
  shared: Rc<UdpShared>,
}

impl UringUdpSocket {
  /// A socket bound to `addr`, on the runtime of the current thread, already receiving.
  ///
  /// An unspecified IPv6 address (`[::]`) makes a dual-stack socket (`IPV6_V6ONLY` off) that
  /// reports its IPv4 peers and local addresses as plain IPv4 ones. The socket reports the local
  /// address of each datagram (`IP_PKTINFO`, and `IPV6_RECVPKTINFO` for IPv6), sets DF on every
  /// datagram without the kernel's path MTU (`IP_MTU_DISCOVER` = `IP_PMTUDISC_PROBE`, and
  /// `IPV6_MTU_DISCOVER` = `IPV6_PMTUDISC_PROBE` for IPv6), and coalesces received datagrams
  /// with [`UdpParams::gro`].
  #[inline]
  pub fn bind(addr: SocketAddr, params: &UdpParams) -> crate::Result<Self> {
    Self::bind_with(addr, params, &|_fd| Ok(()))
  }

  /// [`Self::bind`], with `before_bind` given the socket before it binds.
  fn bind_with(
    addr: SocketAddr,
    params: &UdpParams,
    before_bind: &dyn Fn(RawFd) -> crate::Result<()>,
  ) -> crate::Result<Self> {
    with_reactor(|reactor| reactor.add_udp(addr, params, before_bind))
  }

  /// The address the socket is bound to, with the port the kernel chose if it was 0.
  #[inline]
  pub fn local_addr(&self) -> SocketAddr {
    self.shared.local_addr
  }

  /// Steers the datagrams of the socket's `SO_REUSEPORT` group with `program` (from
  /// [`crate::quic::steering_cbpf`]): the program applies to every socket of the group, which
  /// it indexes in the order they bound.
  ///
  /// `SO_ATTACH_REUSEPORT_CBPF` exists since Linux 4.5, older than the io_uring this runtime
  /// needs, so this fails only on a misconfigured set of sockets. The caller then falls back to
  /// the kernel's hash with every connection accepted by the worker its first datagram reached
  /// (spec section 5.11): a degraded mode with one connection ID per connection and no rotation
  /// of connection IDs, which leaves the privacy SHOULD of RFC 9000 section 9.5 unmet (ruling
  /// T11-a).
  #[inline]
  pub fn attach_reuseport_cbpf(&self, program: &SteeringProgram) -> crate::Result<()> {
    // On its runtime, the descriptor is still the socket's
    let _reactor = self.reactor()?;
    let fprog = libc::sock_fprog {
      len: const { STEERING_PROGRAM_LEN as u16 },
      filter: program.as_ptr().cast_mut(),
    };
    // SAFETY: `fprog` and the program it points to outlive the call, which copies them, and the
    // size of `fprog` is passed
    let rslt = unsafe {
      libc::setsockopt(
        self.shared.fd,
        libc::SOL_SOCKET,
        libc::SO_ATTACH_REUSEPORT_CBPF,
        (&raw const fprog).cast(),
        size_of::<libc::sock_fprog>() as libc::socklen_t,
      )
    };
    if rslt != 0 {
      core::hint::cold_path();
      return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
  }

  /// Hands every datagram received since the previous call to `f`, in its receive buffer, which
  /// goes back to the ring once `f` returns, and resolves to how many there were. Re-arms the
  /// multishot receive if the kernel ended it. The waker of `cx` is woken when more datagrams
  /// arrive, whatever this returns.
  ///
  /// Resolves to an error once for a receive that failed with something other than every buffer
  /// in use (counted in [`UdpStats::recv_errors`]); the socket goes on receiving. Fails with
  /// `EBUSY` if `f` calls it again.
  #[inline]
  pub fn poll_recv(
    &self,
    cx: &mut Context<'_>,
    f: &mut dyn FnMut(&mut [u8], DatagramMeta),
  ) -> Poll<crate::Result<usize>> {
    let reactor = match self.reactor() {
      Ok(elem) => elem,
      Err(err) => return Poll::Ready(Err(err)),
    };
    let shared = &*self.shared;
    if shared.recv_draining.replace(true) {
      return Poll::Ready(Err(io_err(libc::EBUSY)));
    }
    let _draining = ClearOnDrop(&shared.recv_draining);
    let stale = set_waker(&mut shared.recv_waker.borrow_mut(), cx);
    drop(stale);
    let mut count: usize = 0;
    let mut recycled = false;
    loop {
      let Some((bid, len)) = shared.completed.borrow_mut().pop_front() else {
        break;
      };
      let len = len as usize;
      let bufs = shared.bufs.borrow_mut();
      if !bufs.holds(bid, len) {
        // Not a buffer of the ring, which must not get it
        core::hint::cold_path();
        continue;
      }
      let mut lent = LentBuffer { bufs, bid };
      recycled = true;
      let Some(buffer) = lent.bufs.buffer_mut(bid, len) else {
        continue;
      };
      let counters = &shared.counters;
      match parse_recvmsg(buffer) {
        Ok(received) => {
          if received.control_truncated {
            core::hint::cold_path();
            bump(&counters.control_truncated);
          }
          bump(&counters.datagrams_in);
          count = count.wrapping_add(1);
          if let Some(payload) = buffer.get_mut(received.start..) {
            f(payload, received.meta);
          }
        }
        Err(Dropped::Truncated) => {
          core::hint::cold_path();
          bump(&counters.datagrams_truncated);
        }
        Err(Dropped::NoAddress) => {
          core::hint::cold_path();
          bump(&counters.datagrams_without_address);
        }
      }
    }
    if recycled {
      shared.bufs.borrow().publish();
    }
    // Every buffer is back in the ring
    if shared.recv_rearm.get() && !shared.recv_armed.get() {
      reactor.arm_udp_recv(self.idx, self.generation, shared);
    }
    if count > 0 {
      return Poll::Ready(Ok(count));
    }
    let errno = shared.recv_err.replace(0);
    if errno != 0 {
      return Poll::Ready(Err(io_err(errno)));
    }
    Poll::Pending
  }

  /// The arena the datagrams to send are written into; [`Self::submit`] sends its pending trains.
  ///
  /// # Panics
  ///
  /// If the arena is already borrowed.
  #[inline]
  pub fn tx(&self) -> RefMut<'_, TxArena> {
    let mut tx = self.shared.tx.borrow_mut();
    if let Ok(mut sends) = self.shared.sends.try_borrow_mut() {
      for id in sends.late.drain(..) {
        tx.release(id);
      }
    }
    tx
  }

  /// Queues one send for each pending train of the arena, from the oldest, and resolves to how
  /// many it queued. They are submitted with everything else at the end of the turn. A train
  /// that can not be sent from this socket (an IPv6 peer of an IPv4 socket) is given back and
  /// counted in [`UdpStats::send_errors`]. Fails with `EBUSY` while the arena is borrowed.
  #[inline]
  pub fn submit(&self) -> crate::Result<usize> {
    let reactor = self.reactor()?;
    let shared = &*self.shared;
    let mut tx = shared.tx.try_borrow_mut().map_err(|_err| io_err(libc::EBUSY))?;
    let mut sends = shared.sends.borrow_mut();
    let sends = &mut *sends;
    for id in sends.late.drain(..) {
      tx.release(id);
    }
    let mut queued: u32 = 0;
    let mut zc_queued: u64 = 0;
    for train in tx.pending() {
      if sends.round.len() >= sends.round.capacity() {
        break;
      }
      let Some(slot_idx) = sends.free.pop() else {
        break;
      };
      let Some(slot) = sends.slots.get_mut(usize::from(slot_idx)) else {
        sends.free.push(slot_idx);
        break;
      };
      let prepared =
        prepare_send(slot, train.bytes, train.segment_size, train.peer, train.local, shared.v6);
      if prepared.is_err() {
        core::hint::cold_path();
        sends.free.push(slot_idx);
        sends.round.push((train.id, false));
        continue;
      }
      let zc = shared.zerocopy.get();
      slot.start(train.id, zc);
      let packed = (u32::from(slot_idx) << 16) | self.idx;
      let fd = types::Fd(shared.fd);
      // A zero-copy send reads the train in the arena until its notification, which
      // `SendSlots::complete` waits for before the train goes back to it
      let sqe = if zc {
        opcode::SendMsgZc::new(fd, &raw const slot.msg).ioprio(SEND_ZC_REPORT_USAGE).build()
      } else {
        opcode::SendMsg::new(fd, &raw const slot.msg).build()
      };
      reactor.push_sqe(&sqe.user_data(user_data(KIND_UDP_SEND, self.generation, packed)));
      sends.round.push((train.id, true));
      queued = queued.wrapping_add(1);
      zc_queued = zc_queued.wrapping_add(u64::from(zc));
    }
    for (id, submitted) in sends.round.drain(..) {
      if submitted {
        tx.mark_submitted(id);
      } else {
        bump(&shared.counters.send_errors);
        tx.release(id);
      }
    }
    shared.sends_inflight.set(shared.sends_inflight.get().wrapping_add(queued));
    let counters = &shared.counters;
    counters.trains_out.set(counters.trains_out.get().wrapping_add(queued.into()));
    counters.zc_sends.set(counters.zc_sends.get().wrapping_add(zc_queued));
    Ok(queued as usize)
  }

  /// The socket's inbox, for the other workers to forward datagrams to this one.
  #[inline]
  pub fn inbox(&self) -> UdpInbox {
    self.shared.inbox.clone()
  }

  /// Hands every datagram pushed into the socket's [`UdpInbox`] since the previous call to `f`,
  /// in its slot of the inbox, which is free again once `f` returns, and resolves to how many
  /// there were. The waker of `cx` is woken when more are pushed, whatever this returns. Pending
  /// if `f` calls it again.
  #[inline]
  pub fn poll_inbox(
    &self,
    cx: &mut Context<'_>,
    f: &mut dyn FnMut(&mut [u8], DatagramMeta),
  ) -> Poll<usize> {
    let shared = &*self.shared;
    if shared.inbox_draining.replace(true) {
      return Poll::Pending;
    }
    let _draining = ClearOnDrop(&shared.inbox_draining);
    let inbox = &*shared.inbox.inner;
    inbox.waker.register(cx.waker());
    // Before the queue is read: a push that this misses sees the flag clear and signals again
    let _signalled = inbox.signalled.swap(false, Ordering::AcqRel);
    let mut count: usize = 0;
    // SAFETY: the socket that owns an inbox is its only consumer, and `inbox_draining` keeps `f`
    // from taking from it while a datagram is out
    while unsafe { inbox.queue.pop(|bytes, meta| f(bytes, meta)) } {
      count = count.wrapping_add(1);
    }
    let counter = &shared.counters.inbox_in;
    counter.set(counter.get().wrapping_add(count as u64));
    if count > 0 { Poll::Ready(count) } else { Poll::Pending }
  }

  /// See [`UdpStats`].
  #[inline]
  pub fn stats(&self) -> UdpStats {
    let shared = &*self.shared;
    let counters = &shared.counters;
    UdpStats {
      datagrams_in: counters.datagrams_in.get(),
      datagrams_truncated: counters.datagrams_truncated.get(),
      datagrams_without_address: counters.datagrams_without_address.get(),
      control_truncated: counters.control_truncated.get(),
      recv_buffers_exhausted: counters.recv_buffers_exhausted.get(),
      recv_errors: counters.recv_errors.get(),
      trains_out: counters.trains_out.get(),
      send_errors: counters.send_errors.get(),
      zc_sends: counters.zc_sends.get(),
      zc_notifications: counters.zc_notifications.get(),
      zc_copied: counters.zc_copied.get(),
      zc_fallbacks: counters.zc_fallbacks.get(),
      inbox_in: counters.inbox_in.get(),
      inbox_wakes: counters.inbox_wakes.get(),
      rcvbuf: shared.rcvbuf,
      sndbuf: shared.sndbuf,
    }
  }

  fn reactor(&self) -> crate::Result<&Reactor> {
    own_reactor(self.runtime).ok_or_else(|| io_err(libc::EBADF))
  }
}

impl core::fmt::Debug for UringUdpSocket {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("UringUdpSocket").field("local_addr", &self.shared.local_addr).finish()
  }
}

impl Drop for UringUdpSocket {
  #[inline]
  fn drop(&mut self) {
    self.shared.inbox.inner.closed.store(true, Ordering::Release);
    match own_reactor(self.runtime) {
      Some(reactor) => reactor.drop_udp(self.idx, self.generation),
      None => send_to_runtime(self.runtime, Message::DropUdp(self.idx, self.generation)),
    }
  }
}

/// A receive buffer that `poll_recv` hands out: it goes back to the ring when this drops, also
/// when the callback panics, which then publishes it at once (the end of `poll_recv` won't).
struct LentBuffer<'shared> {
  bufs: RefMut<'shared, BufRing>,
  bid: u16,
}

impl Drop for LentBuffer<'_> {
  fn drop(&mut self) {
    self.bufs.push(self.bid);
    if std::thread::panicking() {
      self.bufs.publish();
    }
  }
}

/// The inbox of a [`UringUdpSocket`]: a bounded queue of datagrams that other threads push and the
/// socket takes with [`UringUdpSocket::poll_inbox`]. Each of its [`Self::SLOTS`] slots holds a
/// datagram of up to [`Self::DATAGRAM_LEN`] bytes, allocated with the socket. A handle: its clones
/// push into the same inbox.
#[derive(Clone)]
pub struct UdpInbox {
  inner: Arc<InboxShared>,
}

/// What the handles of an inbox share.
struct InboxShared {
  // The socket is gone: pushes are refused
  closed: AtomicBool,
  queue: InboxQueue,
  // The ring of the socket's runtime, and the completion a push posts to it
  ring_fd: RawFd,
  ring_user_data: u64,
  runtime: u32,
  // Set by the push that signals the owner, cleared by the owner before it takes the datagrams
  signalled: AtomicBool,
  waker: AtomicWaker,
}

impl UdpInbox {
  /// The most bytes of a datagram that an inbox takes.
  pub const DATAGRAM_LEN: usize = 1500;
  /// The datagrams that an inbox holds at once.
  pub const SLOTS: usize = 256;

  /// Queues `datagram`, which came with `meta`, for the socket. `false` if the inbox is full, the
  /// datagram longer than [`Self::DATAGRAM_LEN`] or the socket gone: the datagram is dropped,
  /// and QUIC retransmits it.
  ///
  /// The first push since the socket last took its datagrams wakes it: from another runtime with
  /// an `IORING_OP_MSG_RING` that the ring of the current thread submits at the end of its turn,
  /// from anywhere else through the socket's waker.
  #[inline]
  pub fn push(&self, datagram: &[u8], meta: DatagramMeta) -> bool {
    let inner = &*self.inner;
    if inner.closed.load(Ordering::Acquire) || !inner.queue.push(datagram, meta) {
      return false;
    }
    if !inner.signalled.swap(true, Ordering::AcqRel) {
      self.signal();
    }
    true
  }

  fn new(ring_fd: RawFd, ring_user_data: u64, runtime: u32) -> crate::Result<Self> {
    let inner = InboxShared {
      closed: AtomicBool::new(false),
      queue: InboxQueue::new(Self::SLOTS)?,
      ring_fd,
      ring_user_data,
      runtime,
      signalled: AtomicBool::new(false),
      waker: AtomicWaker::new(),
    };
    Ok(Self { inner: Arc::new(inner) })
  }

  fn signal(&self) {
    let inner = &*self.inner;
    let reactor = CURRENT.with(Cell::get);
    // SAFETY: set by `block_on`, which outlives everything it polls
    match unsafe { reactor.as_ref() } {
      Some(reactor) if reactor.id != inner.runtime => {
        // The ring that sends the message keeps the inbox until the message's own completion,
        // which, if the message failed, clears `signalled` and wakes the owner its other way
        // (`Reactor::on_msg_ring_sent`). Once the owner's runtime is gone its descriptor may be
        // another ring's: that ring finds no socket of that slot and generation, or a spurious
        // wake at worst, and the inbox is marked closed with the runtime anyway.
        let held = reactor.udp.hold_signal(self.inner.clone());
        let msg = opcode::MsgRingData::new(types::Fd(inner.ring_fd), 0, inner.ring_user_data, None);
        reactor.push_sqe(&msg.build().user_data(user_data(KIND_MSG_RING_SENT, 0, held)));
      }
      // On the socket's own runtime the wake schedules its task at once; anywhere else it goes
      // through the runtime's eventfd.
      _ => inner.waker.wake(),
    }
  }
}

impl core::fmt::Debug for UdpInbox {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    let closed = self.inner.closed.load(Ordering::Relaxed);
    f.debug_struct("UdpInbox").field("closed", &closed).finish()
  }
}

/// A bounded queue of datagrams for many producers and one consumer (Dmitry Vyukov's bounded
/// queue): each slot has a sequence number that says whose turn it is. A slot of position `pos`
/// can be written when its number is `pos`, is filled when it is `pos + 1`, and free again for
/// position `pos + capacity` once the consumer is done with it.
struct InboxQueue {
  head: CachePadded<AtomicUsize>,
  tail: CachePadded<AtomicUsize>,
  mask: usize,
  slots: Box<[InboxSlot]>,
}

struct InboxSlot {
  seq: AtomicUsize,
  datagram: UnsafeCell<InboxDatagram>,
}

struct InboxDatagram {
  bytes: [u8; UdpInbox::DATAGRAM_LEN],
  len: u16,
  meta: DatagramMeta,
}

// SAFETY: a slot's datagram is only reached by the producer that claimed the slot's position, or
// by the one consumer once the producer released it, as its sequence number says (see `push` and
// `pop`); everything else is atomic.
unsafe impl Sync for InboxQueue {}

impl InboxQueue {
  /// `capacity`, rounded up to a power of two of at least two, datagrams.
  fn new(capacity: usize) -> crate::Result<Self> {
    let capacity =
      capacity.max(2).checked_next_power_of_two().ok_or_else(|| io_err(libc::EINVAL))?;
    let meta = DatagramMeta {
      peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
      local: None,
      segment_size: None,
    };
    let mut slots = Vec::new();
    slots.try_reserve_exact(capacity).map_err(|_err| io_err(libc::ENOMEM))?;
    for idx in 0..capacity {
      slots.push(InboxSlot {
        seq: AtomicUsize::new(idx),
        datagram: UnsafeCell::new(InboxDatagram {
          bytes: [0; UdpInbox::DATAGRAM_LEN],
          len: 0,
          meta,
        }),
      });
    }
    Ok(Self {
      head: CachePadded(AtomicUsize::new(0)),
      tail: CachePadded(AtomicUsize::new(0)),
      mask: capacity.wrapping_sub(1),
      slots: slots.into_boxed_slice(),
    })
  }

  /// `false` if the queue is full or the datagram too long.
  fn push(&self, datagram: &[u8], meta: DatagramMeta) -> bool {
    let Ok(len) = u16::try_from(datagram.len()) else {
      return false;
    };
    if datagram.len() > UdpInbox::DATAGRAM_LEN {
      return false;
    }
    let mut pos = self.tail.load(Ordering::Relaxed);
    loop {
      let Some(slot) = self.slots.get(pos & self.mask) else {
        return false;
      };
      let seq = slot.seq.load(Ordering::Acquire);
      let diff = seq.wrapping_sub(pos).cast_signed();
      if diff == 0 {
        match self.tail.compare_exchange_weak(
          pos,
          pos.wrapping_add(1),
          Ordering::Relaxed,
          Ordering::Relaxed,
        ) {
          Ok(_) => {
            // SAFETY: winning the exchange for `pos` gives this producer the slot until it stores
            // `pos + 1`: the consumer waits for that, and other producers for `pos + capacity`
            let elem = unsafe { &mut *slot.datagram.get() };
            if let Some(dst) = elem.bytes.get_mut(..datagram.len()) {
              dst.copy_from_slice(datagram);
            }
            elem.len = len;
            elem.meta = meta;
            slot.seq.store(pos.wrapping_add(1), Ordering::Release);
            return true;
          }
          Err(actual) => pos = actual,
        }
      } else if diff < 0 {
        // The consumer has not freed the slot of the position one lap behind
        return false;
      } else {
        pos = self.tail.load(Ordering::Relaxed);
      }
    }
  }

  /// Hands the oldest datagram to `f`, then frees its slot; `false` if there is none.
  ///
  /// # Safety
  ///
  /// Only one thread at a time pops, and `f` does not pop.
  unsafe fn pop(&self, f: impl FnOnce(&mut [u8], DatagramMeta)) -> bool {
    let pos = self.head.load(Ordering::Relaxed);
    let Some(slot) = self.slots.get(pos & self.mask) else {
      return false;
    };
    if slot.seq.load(Ordering::Acquire) != pos.wrapping_add(1) {
      return false;
    }
    let _free = FreeSlot { queue: self, slot, pos };
    // SAFETY: the producer released the slot by storing `pos + 1`, and no producer writes it
    // before `_free` stores `pos + capacity`, after the last use of `elem`; the caller guarantees
    // the only consumer
    let elem = unsafe { &mut *slot.datagram.get() };
    let len = usize::from(elem.len);
    if let Some(bytes) = elem.bytes.get_mut(..len) {
      f(bytes, elem.meta);
    }
    true
  }
}

/// The slot of position `pos` that `InboxQueue::pop` handed out: freed for the producers, and the
/// head moved past it, when this drops, also when the callback panics.
struct FreeSlot<'queue> {
  queue: &'queue InboxQueue,
  slot: &'queue InboxSlot,
  pos: usize,
}

impl Drop for FreeSlot<'_> {
  fn drop(&mut self) {
    self.queue.head.store(self.pos.wrapping_add(1), Ordering::Relaxed);
    self.slot.seq.store(self.pos.wrapping_add(self.queue.slots.len()), Ordering::Release);
  }
}

/// What a socket's handle and its slot in the reactor share. The slot keeps it until the kernel
/// is done with everything of it that it was given: the receive buffers, the msghdr of the
/// receive and the slots and bytes of the sends.
struct UdpShared {
  bgid: u16,
  fd: RawFd,
  local_addr: SocketAddr,
  rcvbuf: usize,
  sndbuf: usize,
  // The socket is an IPv6 one, which reaches IPv4 peers by their v4-mapped addresses
  v6: bool,
  // ---- receiving
  bufs: RefCell<BufRing>,
  // Buffers the kernel filled that `poll_recv` has not handed out: buffer and length. Never more
  // than the buffers, which it has room for.
  completed: RefCell<VecDeque<(u16, u32)>>,
  // Read by the kernel when the receive is submitted: the room for the name and control messages
  recv_msg: libc::msghdr,
  recv_armed: Cell<bool>,
  // The kernel ended the multishot receive for want of buffers or with an error: `poll_recv`
  // arms it again once it has given the buffers back
  recv_rearm: Cell<bool>,
  // The errno of a failed receive, for `poll_recv` to report once
  recv_err: Cell<i32>,
  recv_waker: RefCell<Option<Waker>>,
  // `poll_recv` or `poll_inbox` is running
  recv_draining: Cell<bool>,
  inbox_draining: Cell<bool>,
  // ---- sending
  tx: RefCell<TxArena>,
  sends: RefCell<SendSlots>,
  // Sends whose trains the kernel has not given back yet: their completions, and with zero-copy
  // their notifications, have not all arrived
  sends_inflight: Cell<u32>,
  // Trains go zero-copy: asked for, and not refused so far
  zerocopy: Cell<bool>,
  // A result of a zero-copy send arrived
  zc_results: Cell<bool>,
  // ---- closing
  closing: Cell<bool>,
  cancel_sent: Cell<bool>,
  inbox: UdpInbox,
  counters: UdpCounters,
}

#[derive(Default)]
struct UdpCounters {
  control_truncated: Cell<u64>,
  datagrams_in: Cell<u64>,
  datagrams_truncated: Cell<u64>,
  datagrams_without_address: Cell<u64>,
  inbox_in: Cell<u64>,
  inbox_wakes: Cell<u64>,
  recv_buffers_exhausted: Cell<u64>,
  recv_errors: Cell<u64>,
  send_errors: Cell<u64>,
  trains_out: Cell<u64>,
  zc_copied: Cell<u64>,
  zc_fallbacks: Cell<u64>,
  zc_notifications: Cell<u64>,
  zc_sends: Cell<u64>,
}

/// The sends of a socket, one slot per train in flight, as many as the arena has trains.
struct SendSlots {
  // Never moved nor reallocated: the kernel reads a slot's msghdr, and what it points to, until
  // the send completes
  slots: Box<[SendSlot]>,
  free: Vec<u16>,
  // Trains whose send completed while the arena was borrowed, released at its next borrow
  late: Vec<TrainId>,
  // The trains of the `submit` under way, and whether each was submitted or failed
  round: Vec<(TrainId, bool)>,
}

impl SendSlots {
  fn new(count: usize) -> crate::Result<Self> {
    let count = count.clamp(1, MAX_SEND_SLOTS);
    let mut slots = Vec::new();
    slots.try_reserve_exact(count).map_err(|_err| io_err(libc::ENOMEM))?;
    let mut free = Vec::new();
    free.try_reserve_exact(count).map_err(|_err| io_err(libc::ENOMEM))?;
    for idx in 0..count {
      slots.push(SendSlot::new());
      // The newest slots last, so that the first sends take the lowest
      free.push(u16::try_from(count.wrapping_sub(1).wrapping_sub(idx)).unwrap_or(u16::MAX));
    }
    let mut late = Vec::new();
    late.try_reserve_exact(count).map_err(|_err| io_err(libc::ENOMEM))?;
    let mut round = Vec::new();
    round.try_reserve_exact(count).map_err(|_err| io_err(libc::ENOMEM))?;
    Ok(Self { slots: slots.into_boxed_slice(), free, late, round })
  }

  /// A completion of the send in slot `slot_idx`, with the flags of its CQE: once the send and,
  /// for a zero-copy one, its notification have both arrived, the slot is free again and its
  /// train goes back to the arena; until then neither is.
  fn complete(&mut self, slot_idx: u16, flags: u32) -> SendDone {
    let Some(slot) = self.slots.get_mut(usize::from(slot_idx)) else {
      return SendDone::Stray;
    };
    if slot.train.is_none() {
      return SendDone::Stray;
    }
    if slot.wait.on_completion(flags) == SendStep::Waits {
      return SendDone::Waits { zc: slot.zc };
    }
    let (Some(id), zc) = (slot.train.take(), slot.zc) else {
      return SendDone::Stray;
    };
    self.free.push(slot_idx);
    SendDone::Released { id, zc }
  }
}

/// What a completion did to the send of a slot ([`SendSlots::complete`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SendDone {
  /// The slot holds no send: a stray or repeated completion, which changes nothing.
  Stray,
  /// The send waits for its other completion. `zc`: it is a zero-copy send.
  Waits { zc: bool },
  /// The send is over: its slot is free and train `id` can be given back to the arena. `zc`: it
  /// was a zero-copy send.
  Released { id: TrainId, zc: bool },
}

/// What the send of a train waits for before the kernel is done with its bytes (ruling T19-b): a
/// copying send completes once; a zero-copy send completes with its result, flagged
/// `IORING_CQE_F_MORE` when a notification follows, and with that notification
/// (`IORING_CQE_F_NOTIF`) once the kernel no longer reads the bytes. Either may arrive first.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SendWait {
  notification_owed: bool,
  notification_seen: bool,
  result_seen: bool,
}

/// See [`SendWait::on_completion`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SendStep {
  /// The kernel may still read the bytes.
  Waits,
  /// The kernel is done with the bytes.
  Done,
}

impl SendWait {
  /// A completion of the send, with the flags of its CQE.
  fn on_completion(&mut self, flags: u32) -> SendStep {
    if cqueue::notif(flags) {
      self.notification_seen = true;
    } else {
      self.result_seen = true;
      self.notification_owed = cqueue::more(flags);
    }
    if self.result_seen && (self.notification_seen || !self.notification_owed) {
      SendStep::Done
    } else {
      SendStep::Waits
    }
  }
}

/// Where a send's peer address is written, for the kernel: an IPv4 or an IPv6 one.
#[repr(C)]
union RawSockAddr {
  v4: libc::sockaddr_in,
  v6: libc::sockaddr_in6,
}

/// The control messages of a send, aligned as the kernel's `cmsghdr`s.
#[repr(C, align(8))]
struct SendControl([u8; SEND_CONTROL_LEN]);

/// What the kernel reads of the send of a train, from `msg`, whose pointers point into the slot
/// itself and at the bytes of the train in the arena.
struct SendSlot {
  msg: libc::msghdr,
  iov: libc::iovec,
  name: RawSockAddr,
  control: SendControl,
  train: Option<TrainId>,
  // What the send waits for, and if it is a zero-copy one
  wait: SendWait,
  zc: bool,
}

impl SendSlot {
  fn new() -> Self {
    Self {
      // SAFETY: all zeroes is a valid `msghdr`: null pointers and zero lengths
      msg: unsafe { core::mem::zeroed() },
      iov: libc::iovec { iov_base: core::ptr::null_mut(), iov_len: 0 },
      // SAFETY: all zeroes is a valid `sockaddr_in6`
      name: RawSockAddr { v6: unsafe { core::mem::zeroed() } },
      control: SendControl([0; SEND_CONTROL_LEN]),
      train: None,
      wait: SendWait::default(),
      zc: false,
    }
  }

  /// The slot takes the send of train `id`, zero-copy or not, whose msghdr `prepare_send` wrote.
  fn start(&mut self, id: TrainId, zc: bool) {
    self.train = Some(id);
    self.wait = SendWait::default();
    self.zc = zc;
  }
}

/// The UDP sockets of a reactor, by slot. Each slot's generation tells its sockets apart over
/// time, in the user data of their operations.
#[derive(Default)]
pub(super) struct UdpTable {
  entries: RefCell<Vec<UdpEntry>>,
  free: RefCell<Vec<u32>>,
  // The inboxes of other runtimes that this one sent a message to, until its completion: as many
  // as there are messages in flight at once, then reused
  signals: RefCell<Vec<Option<Arc<InboxShared>>>>,
  free_signals: RefCell<Vec<u32>>,
}

struct UdpEntry {
  generation: u32,
  socket: Option<Rc<UdpShared>>,
}

impl UdpTable {
  /// Closes the sockets still open, when their runtime goes. The ring, dropped right after,
  /// takes what is in flight with it; the table, dropped after the ring, keeps what the kernel
  /// was given of them until then. A zero-copy train whose notification did not arrive is the
  /// only thing that may outlive that: the kernel holds references to its pinned pages until it
  /// is done with them, so freeing the arena then is safe, if the bytes still leaving may change.
  pub(super) fn close_all(&mut self) {
    for shared in self.entries.get_mut().iter().filter_map(|el| el.socket.as_ref()) {
      // Its ring descriptor goes with the runtime
      shared.inbox.inner.closed.store(true, Ordering::Release);
      // SAFETY: closed once, here; the ring that could still use it is dropped right after
      let _rslt = unsafe { libc::close(shared.fd) };
    }
  }

  fn get(&self, idx: u32, generation: u32) -> Option<Rc<UdpShared>> {
    let entries = self.entries.borrow();
    let entry = entries.get(idx as usize).filter(|el| el.generation == generation)?;
    entry.socket.clone()
  }

  /// A free slot and its generation.
  fn reserve(&self) -> crate::Result<(u32, u32)> {
    let mut entries = self.entries.borrow_mut();
    let idx = match self.free.borrow_mut().pop() {
      Some(idx) => idx,
      None => {
        if entries.len() >= MAX_SOCKETS {
          return Err(io_err(libc::EMFILE));
        }
        entries.push(UdpEntry { generation: 0, socket: None });
        u32::try_from(entries.len().wrapping_sub(1)).map_err(|_err| io_err(libc::EMFILE))?
      }
    };
    let generation = entries.get(idx as usize).map_or(0, |el| el.generation);
    Ok((idx, generation))
  }

  fn install(&self, idx: u32, shared: Rc<UdpShared>) {
    if let Some(entry) = self.entries.borrow_mut().get_mut(idx as usize) {
      entry.socket = Some(shared);
    }
  }

  /// Keeps `inbox` until the completion of the message sent to its ring, whose index this is.
  fn hold_signal(&self, inbox: Arc<InboxShared>) -> u32 {
    let mut signals = self.signals.borrow_mut();
    if let Some(idx) = self.free_signals.borrow_mut().pop()
      && let Some(slot) = signals.get_mut(idx as usize)
    {
      *slot = Some(inbox);
      return idx;
    }
    signals.push(Some(inbox));
    u32::try_from(signals.len().wrapping_sub(1)).unwrap_or(u32::MAX)
  }

  /// The inbox that `hold_signal` kept with index `idx`.
  fn take_signal(&self, idx: u32) -> Option<Arc<InboxShared>> {
    let inbox = self.signals.borrow_mut().get_mut(idx as usize)?.take()?;
    self.free_signals.borrow_mut().push(idx);
    Some(inbox)
  }

  /// Frees a slot, which the next socket takes with a new generation.
  fn release(&self, idx: u32) {
    if let Some(entry) = self.entries.borrow_mut().get_mut(idx as usize) {
      entry.socket = None;
      entry.generation = entry.generation.wrapping_add(1) & GENERATION_MASK;
      self.free.borrow_mut().push(idx);
    }
  }
}

impl Reactor {
  fn add_udp(
    &self,
    addr: SocketAddr,
    params: &UdpParams,
    before_bind: &dyn Fn(RawFd) -> crate::Result<()>,
  ) -> crate::Result<UringUdpSocket> {
    let fd = open_socket(addr, params, before_bind)?;
    let (idx, generation) = match self.udp.reserve() {
      Ok(elem) => elem,
      Err(err) => {
        // SAFETY: a socket nothing else has
        let _rslt = unsafe { libc::close(fd) };
        return Err(err);
      }
    };
    let shared = match self.new_udp_shared(fd, addr.is_ipv6(), params, idx, generation) {
      Ok(elem) => Rc::new(elem),
      Err(err) => {
        // SAFETY: a socket nothing else has
        let _rslt = unsafe { libc::close(fd) };
        self.udp.release(idx);
        return Err(err);
      }
    };
    self.udp.install(idx, shared.clone());
    self.arm_udp_recv(idx, generation, &shared);
    Ok(UringUdpSocket { generation, idx, runtime: self.id, shared })
  }

  fn new_udp_shared(
    &self,
    fd: RawFd,
    v6: bool,
    params: &UdpParams,
    idx: u32,
    generation: u32,
  ) -> crate::Result<UdpShared> {
    let local_addr = socket_local_addr(fd)?;
    let rcvbuf = usize::try_from(get_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF)?).unwrap_or(0);
    let sndbuf = usize::try_from(get_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF)?).unwrap_or(0);
    let (count, len) = recv_ring_geometry(params);
    let mut bufs = BufRing::new(count, len)?;
    let mut completed = VecDeque::new();
    completed.try_reserve_exact(usize::from(count)).map_err(|_err| io_err(libc::ENOMEM))?;
    let tx = TxArena::with_train_segments(params.tx_arena_bytes, params.max_train_segments)?;
    let sends = SendSlots::new(tx.max_trains())?;
    // A ring that does not know zero-copy sends copies
    let zerocopy = params.zerocopy && {
      let mut probe = io_uring::Probe::new();
      let known = self.ring.borrow().submitter().register_probe(&mut probe).is_ok()
        && probe.is_supported(opcode::SendMsgZc::CODE);
      if !known {
        core::hint::cold_path();
      }
      known
    };
    let ring_fd = std::os::fd::AsRawFd::as_raw_fd(&*self.ring.borrow());
    let inbox_user_data = user_data(KIND_MSG_RING, generation, idx);
    let inbox = UdpInbox::new(ring_fd, inbox_user_data, self.id)?;
    // SAFETY: all zeroes is a valid `msghdr`: null pointers and zero lengths
    let mut recv_msg: libc::msghdr = unsafe { core::mem::zeroed() };
    recv_msg.msg_namelen = RECV_NAME_LEN as libc::socklen_t;
    recv_msg.msg_controllen = RECV_CONTROL_LEN;
    let bgid = BUF_GROUP_UDP.wrapping_add(u16::try_from(idx).map_err(|_err| io_err(libc::EMFILE))?);
    // Last, as nothing that follows fails: the ring is unregistered when the socket closes.
    // SAFETY: the entries stay allocated, and registered, until `maybe_close_udp` unregisters
    // them or the ring is dropped, both before the `UdpShared` that owns them is
    unsafe {
      self.ring.borrow().submitter().register_buf_ring_with_flags(
        bufs.entries as u64,
        count,
        bgid,
        0,
      )?;
    }
    for bid in 0..count {
      bufs.push(bid);
    }
    bufs.publish();
    Ok(UdpShared {
      bgid,
      fd,
      local_addr,
      rcvbuf,
      sndbuf,
      v6,
      bufs: RefCell::new(bufs),
      completed: RefCell::new(completed),
      recv_msg,
      recv_armed: Cell::new(false),
      recv_rearm: Cell::new(false),
      recv_err: Cell::new(0),
      recv_waker: RefCell::new(None),
      recv_draining: Cell::new(false),
      inbox_draining: Cell::new(false),
      tx: RefCell::new(tx),
      sends: RefCell::new(sends),
      sends_inflight: Cell::new(0),
      zerocopy: Cell::new(zerocopy),
      zc_results: Cell::new(false),
      closing: Cell::new(false),
      cancel_sent: Cell::new(false),
      inbox,
      counters: UdpCounters {
        zc_fallbacks: Cell::new(u64::from(params.zerocopy && !zerocopy)),
        ..UdpCounters::default()
      },
    })
  }

  fn arm_udp_recv(&self, idx: u32, generation: u32, shared: &UdpShared) {
    shared.recv_armed.set(true);
    shared.recv_rearm.set(false);
    let sqe =
      opcode::RecvMsgMulti::new(types::Fd(shared.fd), &raw const shared.recv_msg, shared.bgid)
        .build()
        .user_data(user_data(KIND_UDP_RECV, generation, idx));
    self.push_sqe(&sqe);
  }

  /// A completion of a socket's multishot receive: a filled buffer, or the end of the receive.
  pub(super) fn on_udp_recv(&self, idx: u32, generation: u32, res: i32, flags: u32) {
    let Some(shared) = self.udp.get(idx, generation) else {
      return;
    };
    let mut woken = None;
    if shared.closing.get() {
      // Its buffers are unregistered once the receive ends
    } else if res >= 0 {
      if let Some(bid) = cqueue::buffer_select(flags) {
        shared.completed.borrow_mut().push_back((bid, res.unsigned_abs()));
        woken = shared.recv_waker.borrow_mut().take();
      }
    } else {
      core::hint::cold_path();
      if res == -libc::ENOBUFS {
        bump(&shared.counters.recv_buffers_exhausted);
      } else if res != -libc::ECANCELED {
        bump(&shared.counters.recv_errors);
        shared.recv_err.set(-res);
      }
      woken = shared.recv_waker.borrow_mut().take();
    }
    if !cqueue::more(flags) {
      shared.recv_armed.set(false);
      if shared.closing.get() {
        self.maybe_close_udp(idx, generation, &shared);
      } else if res >= 0 {
        // Ended for a reason of the kernel's own, with buffers to spare
        self.arm_udp_recv(idx, generation, &shared);
      } else if res != -libc::ECANCELED {
        shared.recv_rearm.set(true);
      }
    }
    drop(shared);
    if let Some(elem) = woken {
      elem.wake();
    }
  }

  /// A send completed, or failed, or the notification of a zero-copy send arrived: once the
  /// kernel is done with the train ([`SendSlots::complete`]), it is given back to the arena,
  /// whether it was sent or not.
  pub(super) fn on_udp_send(&self, packed: u32, generation: u32, res: i32, flags: u32) {
    let idx = packed & 0xFFFF;
    let slot_idx = (packed >> 16) as u16;
    let Some(shared) = self.udp.get(idx, generation) else {
      return;
    };
    let counters = &shared.counters;
    let notification = cqueue::notif(flags);
    let done = shared.sends.borrow_mut().complete(slot_idx, flags);
    let (released, zc) = match done {
      // A slot that holds no train is already free: a second entry on the free list would give
      // it to two sends at once
      SendDone::Stray => {
        core::hint::cold_path();
        return;
      }
      SendDone::Waits { zc } => (None, zc),
      SendDone::Released { id, zc } => (Some(id), zc),
    };
    if notification {
      bump(&counters.zc_notifications);
      if res.cast_unsigned() & NOTIF_USAGE_ZC_COPIED != 0 {
        bump(&counters.zc_copied);
      }
    } else {
      if res < 0 {
        core::hint::cold_path();
        bump(&counters.send_errors);
      }
      // The result of a refused zero-copy send turns zero-copy off, whether a notification
      // follows or not
      if zc {
        let first = !shared.zc_results.replace(true);
        if zc_refused(res, first) && shared.zerocopy.replace(false) {
          core::hint::cold_path();
          bump(&counters.zc_fallbacks);
        }
      }
    }
    let Some(id) = released else {
      return;
    };
    shared.sends_inflight.set(shared.sends_inflight.get().saturating_sub(1));
    match shared.tx.try_borrow_mut() {
      Ok(mut tx) => tx.release(id),
      Err(_err) => shared.sends.borrow_mut().late.push(id),
    }
    if shared.closing.get() {
      self.maybe_close_udp(idx, generation, &shared);
    }
  }

  /// Another ring pushed into the inbox of a socket of this one.
  pub(super) fn on_msg_ring(&self, idx: u32, generation: u32) {
    let Some(shared) = self.udp.get(idx, generation) else {
      return;
    };
    bump(&shared.counters.inbox_wakes);
    shared.inbox.inner.waker.wake();
  }

  /// A message this ring sent to the ring of another runtime's inbox completed. If it failed
  /// (that ring is out of memory, overflowing, or gone), the inbox would stay signalled and no
  /// later push would send another: its signal is cleared, so that the next push sends one, and
  /// its owner is woken through its waker instead.
  pub(super) fn on_msg_ring_sent(&self, idx: u32, res: i32) {
    let Some(inbox) = self.udp.take_signal(idx) else {
      return;
    };
    if res < 0 {
      core::hint::cold_path();
      inbox.signalled.store(false, Ordering::Release);
      inbox.waker.wake();
    }
  }

  /// The handle of a socket was dropped: its receive is cancelled, and it closes once nothing of
  /// it is in flight.
  pub(super) fn drop_udp(&self, idx: u32, generation: u32) {
    let Some(shared) = self.udp.get(idx, generation) else {
      return;
    };
    shared.closing.set(true);
    shared.inbox.inner.closed.store(true, Ordering::Release);
    let stale = shared.recv_waker.borrow_mut().take();
    if shared.recv_armed.get() && !shared.cancel_sent.replace(true) {
      self.push_sqe(&cancel_sqe(user_data(KIND_UDP_RECV, generation, idx)));
    }
    self.maybe_close_udp(idx, generation, &shared);
    drop(shared);
    drop(stale);
  }

  fn maybe_close_udp(&self, idx: u32, generation: u32, shared: &UdpShared) {
    if shared.recv_armed.get() || shared.sends_inflight.get() > 0 {
      return;
    }
    if self.udp.get(idx, generation).is_none() {
      return;
    }
    // Nothing in flight uses the buffers any more
    let _rslt = self.ring.borrow().submitter().unregister_buf_ring(shared.bgid);
    // SAFETY: closed once, here: no operation on it is in flight, and the slot forgets it
    let _rslt = unsafe { libc::close(shared.fd) };
    self.udp.release(idx);
  }
}

/// If the result of a zero-copy send says that the kernel does not take zero-copy sends from this
/// socket: the socket unable to (`EOPNOTSUPP`, whenever it comes), or, as the `first` zero-copy
/// result of the socket, the operation or its flags unknown (`EINVAL`) or the pinned pages over the
/// limit (`ENOMEM`). After a zero-copy send went, those two are a packet's failure or a passing
/// shortage, which QUIC's loss recovery covers, and zero-copy stays on.
fn zc_refused(res: i32, first: bool) -> bool {
  match -res {
    libc::EOPNOTSUPP => true,
    libc::EINVAL | libc::ENOMEM => first,
    _ => false,
  }
}

/// The number of receive buffers and the length of each, the room before the payload included,
/// a multiple of a cache line.
fn recv_ring_geometry(params: &UdpParams) -> (u16, usize) {
  let payload =
    if params.gro { params.recv_buffer_len.max(GRO_RECV_LEN) } else { params.recv_buffer_len };
  let len = (payload.max(1) as usize).wrapping_add(RECV_HEADROOM).next_multiple_of(64);
  let mut count = params.recv_buffers.clamp(1, MAX_RECV_BUFFERS).next_power_of_two();
  while count > 1 && usize::from(count).wrapping_mul(len) > MAX_RECV_RING {
    count /= 2;
  }
  (count, len)
}

/// A UDP socket with the options of [`UringUdpSocket::bind`], bound to `addr`.
fn open_socket(
  addr: SocketAddr,
  params: &UdpParams,
  before_bind: &dyn Fn(RawFd) -> crate::Result<()>,
) -> crate::Result<RawFd> {
  let v6 = addr.is_ipv6();
  let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
  // SAFETY: no pointers involved
  let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
  if fd < 0 {
    return Err(std::io::Error::last_os_error().into());
  }
  let setup = || {
    let size = |value: usize| libc::c_int::try_from(value).unwrap_or(libc::c_int::MAX);
    if params.reuseport {
      set_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;
    }
    set_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, size(params.rcvbuf))?;
    set_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, size(params.sndbuf))?;
    if v6 {
      if addr.ip().is_unspecified() {
        set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 0)?;
      }
      set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1)?;
      set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, libc::IPV6_PMTUDISC_PROBE)?;
    }
    // Also on an IPv6 socket, for the IPv4 datagrams of a dual-stack one
    set_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?;
    set_int(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, libc::IP_PMTUDISC_PROBE)?;
    if params.gro {
      set_int(fd, libc::SOL_UDP, libc::UDP_GRO, 1)?;
    }
    before_bind(fd)?;
    // SAFETY: all zeroes is a valid `sockaddr_storage`
    let mut storage: libc::sockaddr_storage = unsafe { core::mem::zeroed() };
    let len = write_sockaddr(&addr, &mut storage);
    // SAFETY: `storage` holds an address of `len` bytes and outlives the call
    if unsafe { libc::bind(fd, (&raw const storage).cast(), len) } != 0 {
      return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
  };
  if let Err(err) = setup() {
    // SAFETY: a socket nothing else has
    let _rslt = unsafe { libc::close(fd) };
    return Err(err);
  }
  Ok(fd)
}

fn set_int(
  fd: RawFd,
  level: libc::c_int,
  name: libc::c_int,
  value: libc::c_int,
) -> crate::Result<()> {
  // SAFETY: `value` outlives the call and its size is passed
  let rslt = unsafe {
    libc::setsockopt(
      fd,
      level,
      name,
      (&raw const value).cast(),
      size_of::<libc::c_int>() as libc::socklen_t,
    )
  };
  if rslt != 0 {
    return Err(std::io::Error::last_os_error().into());
  }
  Ok(())
}

fn get_int(fd: RawFd, level: libc::c_int, name: libc::c_int) -> crate::Result<libc::c_int> {
  let mut value: libc::c_int = 0;
  let mut len = size_of::<libc::c_int>() as libc::socklen_t;
  // SAFETY: `value` and `len` outlive the call, and `len` is the size of `value`
  let rslt = unsafe { libc::getsockopt(fd, level, name, (&raw mut value).cast(), &raw mut len) };
  if rslt != 0 {
    return Err(std::io::Error::last_os_error().into());
  }
  Ok(value)
}

fn socket_local_addr(fd: RawFd) -> crate::Result<SocketAddr> {
  // SAFETY: borrows `fd` for the call; `ManuallyDrop` keeps it open
  let socket = core::mem::ManuallyDrop::new(unsafe { std::net::UdpSocket::from_raw_fd(fd) });
  Ok(socket.local_addr()?)
}

impl BufRing {
  /// Whether buffer `bid` is one of the ring's and holds `len` bytes.
  fn holds(&self, bid: u16, len: usize) -> bool {
    bid < self.count && len <= self.len
  }

  /// The first `len` bytes of buffer `bid`, which the kernel filled, to be read and changed in
  /// place.
  fn buffer_mut(&mut self, bid: u16, len: usize) -> Option<&mut [u8]> {
    if !self.holds(bid, len) {
      return None;
    }
    let begin = usize::from(bid).wrapping_mul(self.len);
    self.mem.get_mut(begin..begin.wrapping_add(len))
  }
}

/// A datagram that a multishot recvmsg left in a buffer.
#[derive(Debug, PartialEq)]
struct Received {
  // Where the payload starts in the buffer
  start: usize,
  meta: DatagramMeta,
  // Some control messages did not fit their room (`MSG_CTRUNC`): `meta` may lack what they said
  control_truncated: bool,
}

/// Why a buffer that a multishot recvmsg filled holds no datagram to hand out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Dropped {
  // The payload did not fit the buffer (`MSG_TRUNC`)
  Truncated,
  // The name is no IPv4 or IPv6 address
  NoAddress,
}

/// The payload of a buffer that a multishot recvmsg filled, and where the datagram came from.
fn parse_recvmsg(buffer: &[u8]) -> Result<Received, Dropped> {
  let header = buffer.get(..RECV_OUT_LEN).ok_or(Dropped::Truncated)?;
  let field = |idx: usize| {
    let bytes = header.get(idx.wrapping_mul(4)..idx.wrapping_mul(4).wrapping_add(4))?;
    Some(u32::from_ne_bytes(bytes.try_into().ok()?) as usize)
  };
  let (Some(namelen), Some(controllen), Some(flags)) = (field(0), field(1), field(3)) else {
    return Err(Dropped::Truncated);
  };
  if flags & (libc::MSG_TRUNC as usize) != 0 {
    core::hint::cold_path();
    return Err(Dropped::Truncated);
  }
  let name_end = RECV_OUT_LEN.wrapping_add(namelen.min(RECV_NAME_LEN));
  let control_start = RECV_OUT_LEN.wrapping_add(RECV_NAME_LEN);
  let control_end = control_start.wrapping_add(controllen.min(RECV_CONTROL_LEN));
  let (Some(name), Some(control)) =
    (buffer.get(RECV_OUT_LEN..name_end), buffer.get(control_start..control_end))
  else {
    return Err(Dropped::Truncated);
  };
  if buffer.len() < RECV_HEADROOM {
    return Err(Dropped::Truncated);
  }
  let peer = parse_sockaddr(name).ok_or(Dropped::NoAddress)?;
  let (local, segment_size) = parse_cmsgs(control);
  let meta = DatagramMeta { peer, local, segment_size };
  let control_truncated = flags & (libc::MSG_CTRUNC as usize) != 0;
  Ok(Received { start: RECV_HEADROOM, meta, control_truncated })
}

/// A `sockaddr_in` or `sockaddr_in6`, a v4-mapped address as a plain IPv4 one.
fn parse_sockaddr(name: &[u8]) -> Option<SocketAddr> {
  let family = u16::from_ne_bytes(name.get(..2)?.try_into().ok()?);
  let port = u16::from_be_bytes(name.get(2..4)?.try_into().ok()?);
  if i32::from(family) == libc::AF_INET {
    let ip = <[u8; 4]>::try_from(name.get(4..8)?).ok()?;
    return Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)));
  }
  if i32::from(family) != libc::AF_INET6 {
    return None;
  }
  let flowinfo = u32::from_ne_bytes(name.get(4..8)?.try_into().ok()?);
  let ip = Ipv6Addr::from(<[u8; 16]>::try_from(name.get(8..24)?).ok()?);
  let scope_id = u32::from_ne_bytes(name.get(24..28)?.try_into().ok()?);
  if let Some(elem) = ip.to_ipv4_mapped() {
    return Some(SocketAddr::V4(SocketAddrV4::new(elem, port)));
  }
  Some(SocketAddr::V6(SocketAddrV6::new(ip, port, flowinfo, scope_id)))
}

/// The local address a datagram was sent to (`IP_PKTINFO`, `IPV6_PKTINFO`) and the size of the
/// datagrams it coalesces (`UDP_GRO`), from its control messages.
fn parse_cmsgs(control: &[u8]) -> (Option<IpAddr>, Option<u16>) {
  let mut local = None;
  let mut segment_size = None;
  let mut off: usize = 0;
  while let Some(header) = control.get(off..off.wrapping_add(CMSG_HEADER)) {
    let read_i32 = |at: usize| {
      header.get(at..at.wrapping_add(4)).and_then(|el| el.try_into().ok()).map(i32::from_ne_bytes)
    };
    let len = header
      .get(..size_of::<usize>())
      .and_then(|el| el.try_into().ok())
      .map_or(0, usize::from_ne_bytes);
    let (Some(level), Some(ty)) = (read_i32(size_of::<usize>()), read_i32(size_of::<usize>() + 4))
    else {
      break;
    };
    if len < CMSG_HEADER {
      break;
    }
    let Some(data) = control.get(off.wrapping_add(CMSG_HEADER)..off.wrapping_add(len)) else {
      break;
    };
    match (level, ty) {
      // `in_pktinfo`: the interface, the local address replies would leave from by the routes,
      // then the destination address of the datagram
      (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
        if let Some(elem) = data.get(8..12).and_then(|el| <[u8; 4]>::try_from(el).ok()) {
          local = Some(IpAddr::V4(Ipv4Addr::from(elem)));
        }
      }
      // `in6_pktinfo`: the destination address of the datagram, then the interface
      (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
        if let Some(elem) = data.get(..16).and_then(|el| <[u8; 16]>::try_from(el).ok()) {
          let ip = Ipv6Addr::from(elem);
          local = Some(ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4));
        }
      }
      (libc::SOL_UDP, libc::UDP_GRO) => {
        let size = data.get(..4).and_then(|el| el.try_into().ok()).map(i32::from_ne_bytes);
        segment_size = size.and_then(|el| u16::try_from(el).ok());
      }
      _ => {}
    }
    off = off.wrapping_add(cmsg_align(len));
  }
  (local, segment_size)
}

const fn cmsg_align(len: usize) -> usize {
  len.next_multiple_of(size_of::<usize>())
}

/// Writes a control message into `dst`, returning the bytes it takes with its padding, or 0 if
/// `dst` has no room for it.
fn put_cmsg(dst: &mut [u8], level: libc::c_int, ty: libc::c_int, data: &[u8]) -> usize {
  let len = CMSG_HEADER.wrapping_add(data.len());
  let space = cmsg_align(len);
  let Some(cmsg) = dst.get_mut(..space) else {
    return 0;
  };
  cmsg.fill(0);
  let word = size_of::<usize>();
  let fields = [
    (0, &len.to_ne_bytes()[..]),
    (word, &level.to_ne_bytes()[..]),
    (word.wrapping_add(4), &ty.to_ne_bytes()[..]),
    (CMSG_HEADER, data),
  ];
  for (at, bytes) in fields {
    if let Some(elem) = cmsg.get_mut(at..at.wrapping_add(bytes.len())) {
      elem.copy_from_slice(bytes);
    }
  }
  space
}

/// Writes `peer` the way a socket of the family `v6_socket` takes it, returning its length: an
/// IPv6 socket reaches IPv4 peers by their v4-mapped addresses. `None` for an IPv6 peer of an
/// IPv4 socket.
fn encode_sockaddr(dst: &mut RawSockAddr, peer: SocketAddr, v6_socket: bool) -> Option<u32> {
  let v4 = match peer {
    SocketAddr::V4(elem) => Some(elem),
    SocketAddr::V6(elem) => elem.ip().to_ipv4_mapped().map(|ip| SocketAddrV4::new(ip, elem.port())),
  };
  if !v6_socket {
    let elem = v4?;
    dst.v4 = libc::sockaddr_in {
      sin_family: libc::AF_INET as libc::sa_family_t,
      sin_port: elem.port().to_be(),
      sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(elem.ip().octets()) },
      sin_zero: [0; 8],
    };
    return Some(size_of::<libc::sockaddr_in>() as u32);
  }
  let v6 = match peer {
    SocketAddr::V4(elem) => SocketAddrV6::new(elem.ip().to_ipv6_mapped(), elem.port(), 0, 0),
    SocketAddr::V6(elem) => elem,
  };
  dst.v6 = libc::sockaddr_in6 {
    sin6_family: libc::AF_INET6 as libc::sa_family_t,
    sin6_port: v6.port().to_be(),
    sin6_flowinfo: v6.flowinfo(),
    sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
    sin6_scope_id: v6.scope_id(),
  };
  Some(size_of::<libc::sockaddr_in6>() as u32)
}

/// The control messages of a send: `UDP_SEGMENT` with the size of the datagrams of a train of
/// more than one, and the local address the datagrams leave from, `IP_PKTINFO` for an IPv4 one
/// (v4-mapped ones included) and `IPV6_PKTINFO` for an IPv6 one. Returns their length.
fn encode_send_cmsgs(
  dst: &mut [u8; SEND_CONTROL_LEN],
  segment_size: Option<u16>,
  local: Option<IpAddr>,
) -> usize {
  let mut off: usize = 0;
  if let Some(elem) = segment_size {
    off = put_cmsg(dst, libc::SOL_UDP, libc::UDP_SEGMENT, &elem.to_ne_bytes());
  }
  let rest = dst.get_mut(off..).unwrap_or_default();
  let local = local.map(|el| match el {
    IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(el, IpAddr::V4),
    IpAddr::V4(_) => el,
  });
  match local {
    Some(IpAddr::V4(ip)) => {
      // `in_pktinfo`: any interface, the source address, and the destination, unused in a send
      let mut info = [0; 12];
      if let Some(elem) = info.get_mut(4..8) {
        elem.copy_from_slice(&ip.octets());
      }
      off.wrapping_add(put_cmsg(rest, libc::IPPROTO_IP, libc::IP_PKTINFO, &info))
    }
    Some(IpAddr::V6(ip)) => {
      // `in6_pktinfo`: the source address, then any interface
      let mut info = [0; 20];
      if let Some(elem) = info.get_mut(..16) {
        elem.copy_from_slice(&ip.octets());
      }
      off.wrapping_add(put_cmsg(rest, libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &info))
    }
    None => off,
  }
}

/// Fills `slot` for the send of a train of `bytes`, datagrams of `segment_size` bytes but the
/// last, to `peer` from `local`, on a socket of the family `v6_socket`: its msghdr points at its
/// own address, iovec and control messages, and its iovec at `bytes`. Fails with
/// `EAFNOSUPPORT` for a peer the socket can not reach.
fn prepare_send(
  slot: &mut SendSlot,
  bytes: &[u8],
  segment_size: u16,
  peer: SocketAddr,
  local: Option<IpAddr>,
  v6_socket: bool,
) -> Result<(), i32> {
  let namelen = encode_sockaddr(&mut slot.name, peer, v6_socket).ok_or(libc::EAFNOSUPPORT)?;
  let segments = (bytes.len() > usize::from(segment_size)).then_some(segment_size);
  let controllen = encode_send_cmsgs(&mut slot.control.0, segments, local);
  slot.iov = libc::iovec { iov_base: bytes.as_ptr().cast_mut().cast(), iov_len: bytes.len() };
  slot.msg.msg_name = (&raw mut slot.name).cast();
  slot.msg.msg_namelen = namelen;
  slot.msg.msg_iov = &raw mut slot.iov;
  slot.msg.msg_iovlen = 1;
  slot.msg.msg_control =
    if controllen > 0 { (&raw mut slot.control).cast() } else { core::ptr::null_mut() };
  slot.msg.msg_controllen = controllen;
  slot.msg.msg_flags = 0;
  Ok(())
}

#[cfg(all(test, not(miri)))]
mod tests {
  use crate::{
    executor::{
      Runtime, UringRuntime,
      uring_executor::udp::{UdpInbox, UdpParams, UringUdpSocket},
    },
    futures::Sleep,
    quic::{DatagramMeta, TxArena, steering_cbpf},
  };
  use alloc::vec::Vec;
  use core::{
    future::poll_fn,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    task::Poll,
    time::Duration,
  };
  use std::os::fd::RawFd;

  const V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
  const TIMEOUT: Duration = Duration::from_secs(5);

  type Received = Vec<(Vec<u8>, DatagramMeta)>;

  // The settings of a test socket: without SO_REUSEPORT, as a port-0 bind with it can return the
  // port of a live socket of another test, which then shares its datagrams (see
  // `UdpParams::reuseport`). Only `cbpf_steers_by_dcid_byte` makes a group, on purpose.
  fn params() -> UdpParams {
    UdpParams { reuseport: false, ..UdpParams::new() }
  }

  // Brief step 3 of task 16 (EC2 variant batch of 9 Nov 2026) and ruling T16-h: generic receive
  // offload stays off by default, although it won on baseline-h3 (-2.8 % server CPU per request at
  // +0.8 % requests per second): its 256 receive buffers of 64 KiB make one socket's ring exactly
  // 16 MiB, which equals the 16 MiB pool budget of a worker (spec section 5.4), leaving nothing for
  // the other pools. The other defaults are the measured ones too.
  #[test]
  fn defaults_are_the_measured_ones() {
    let params = UdpParams::new();
    assert!(!params.gro);
    assert_eq!((params.recv_buffers, params.recv_buffer_len), (256, 2048));
    assert_eq!((params.rcvbuf, params.sndbuf), (4 << 20, 4 << 20));
    assert_eq!((params.tx_arena_bytes, params.max_train_segments), (TxArena::DEFAULT_BYTES, 64));
    assert!(params.reuseport);
    // Ruling T19-b: zero-copy sends stay off until the EC2 batch measures them
    assert!(!params.zerocopy);
  }

  // Ruling T19-b: zero-copy trains reach the peer intact, each given back to the arena only once
  // its notification arrived (one per train), and the arena is whole again after the last. On a
  // loopback the kernel copies on delivery, which the notifications may report; a kernel that
  // does not take zero-copy sends falls back to copying, counted, and the trains arrive anyway.
  #[test]
  fn zero_copy_trains_arrive_and_go_back_after_their_notifications() {
    const TRAINS: u8 = 16;
    let receiver = std_socket("127.0.0.1:0");
    // Room for all of them (capped by `net.core.rmem_max`), which wait until the end
    super::set_int(
      std::os::fd::AsRawFd::as_raw_fd(&receiver),
      libc::SOL_SOCKET,
      libc::SO_RCVBUF,
      4 << 20,
    )
    .unwrap();
    let peer = receiver.local_addr().unwrap();
    let mut stats = None;
    UringRuntime::new().unwrap().block_on(async {
      let sock = UringUdpSocket::bind(V4, &UdpParams { zerocopy: true, ..params() }).unwrap();
      for round in 0..TRAINS {
        for segment in 0..4u8 {
          queue(&sock, peer, None, &[round.wrapping_mul(4).wrapping_add(segment); 1472]);
        }
        assert_eq!(sock.submit().unwrap(), 1);
        // A new train never takes bytes that a train in flight holds: the next one is written
        // while this one may still be the kernel's
      }
      settle(&sock).await;
      assert!(sock.tx().begin(peer, None, 65_507).is_some());
      stats = Some(sock.stats());
    });
    let stats = stats.unwrap();
    let trains = u64::from(TRAINS);
    assert_eq!((stats.trains_out, stats.send_errors), (trains, 0), "{stats:?}");
    if stats.zc_fallbacks == 0 {
      assert_eq!((stats.zc_sends, stats.zc_notifications), (trains, trains), "{stats:?}");
      assert!(stats.zc_copied <= trains, "{stats:?}");
    } else {
      assert_eq!((stats.zc_fallbacks, stats.zc_sends), (1, 0), "{stats:?}");
    }
    for nth in 0..usize::from(TRAINS) * 4 {
      let mut buffer = [0; 2048];
      // The task work of the ring that ended can interrupt the first receive
      let (len, _) = loop {
        match receiver.recv_from(&mut buffer) {
          Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
          rslt => break rslt.unwrap(),
        }
      };
      assert_eq!(len, 1472);
      assert!(buffer[..len].iter().all(|el| usize::from(*el) == nth % 256), "datagram {nth}");
    }
  }

  // Ruling T19-b: once warm, zero-copy sends allocate nothing on the thread of the runtime, their
  // notifications included.
  #[test]
  fn zero_copy_sends_allocate_nothing_after_warmup() {
    use crate::{sync::AtomicU64, tests::_count_allocations_in};
    use core::sync::atomic::Ordering;
    static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
    const TRAINS: usize = 8;
    let receiver = std_socket("127.0.0.1:0");
    super::set_int(
      std::os::fd::AsRawFd::as_raw_fd(&receiver),
      libc::SOL_SOCKET,
      libc::SO_RCVBUF,
      4 << 20,
    )
    .unwrap();
    let peer = receiver.local_addr().unwrap();
    let mut counted = None;
    UringRuntime::new().unwrap().block_on(async {
      let sock = UringUdpSocket::bind(V4, &UdpParams { zerocopy: true, ..params() }).unwrap();
      for round in 0..2 {
        if round == 1 {
          _count_allocations_in(&ALLOCATIONS);
        }
        let before = ALLOCATIONS.load(Ordering::SeqCst);
        for _ in 0..TRAINS {
          for segment in 0..4u8 {
            queue(&sock, peer, None, &[segment; 1200]);
          }
          assert_eq!(sock.submit().unwrap(), 1);
        }
        let begin = std::time::Instant::now();
        while sock.shared.sends_inflight.get() > 0 {
          assert!(begin.elapsed() < TIMEOUT, "sends never completed");
          yield_now().await;
        }
        if round == 1 {
          counted = Some((ALLOCATIONS.load(Ordering::SeqCst) - before, sock.stats()));
        }
      }
    });
    let (allocations, stats) = counted.unwrap();
    assert_eq!(allocations, 0, "{stats:?}");
    assert_eq!(stats.trains_out, 2 * TRAINS as u64, "{stats:?}");
  }

  // Ruling T19-b: a zero-copy send that the kernel refuses (here a completion of EOPNOTSUPP made
  // up for a send that was never submitted) gives its train back, counts as a failed send, and
  // turns zero-copy off for the socket, once; the next trains are copied. A refusal that says a
  // notification follows (`IORING_CQE_F_MORE`) turns it off at once too, and the train goes back
  // with the notification.
  #[test]
  fn a_refused_zero_copy_send_turns_zero_copy_off() {
    for more in [false, true] {
      refused_zero_copy_send(more);
    }
  }

  // The flags of a CQE (`IORING_CQE_F_MORE`, `IORING_CQE_F_NOTIF`)
  const MORE_FLAG: u32 = 1 << 1;
  const NOTIF_FLAG: u32 = 1 << 3;

  // `bytes` to `peer` as one train in flight as a zero-copy send that was never submitted: the
  // completions of a test stand in for the kernel's. Returns the user data of the send.
  fn fake_zero_copy_send(sock: &UringUdpSocket, peer: SocketAddr, bytes: &[u8]) -> u32 {
    let shared = &*sock.shared;
    queue(sock, peer, None, bytes);
    let id = sock.tx().pending().next().unwrap().id;
    let slot_idx = {
      let mut sends = shared.sends.borrow_mut();
      let slot_idx = sends.free.pop().unwrap();
      sends.slots[usize::from(slot_idx)].start(id, true);
      slot_idx
    };
    sock.tx().mark_submitted(id);
    shared.sends_inflight.set(shared.sends_inflight.get() + 1);
    (u32::from(slot_idx) << 16) | sock.idx
  }

  // A completion of the send `packed` of `sock`, as the kernel's would arrive.
  fn complete(sock: &UringUdpSocket, packed: u32, res: i32, flags: u32) {
    crate::executor::uring_executor::with_reactor(|reactor| {
      reactor.on_udp_send(packed, sock.generation, res, flags);
      Ok(())
    })
    .unwrap();
  }

  fn refused_zero_copy_send(more: bool) {
    let receiver = std_socket("127.0.0.1:0");
    let peer = receiver.local_addr().unwrap();
    UringRuntime::new().unwrap().block_on(async {
      let sock = UringUdpSocket::bind(V4, &UdpParams { zerocopy: true, ..params() }).unwrap();
      let shared = &*sock.shared;
      let packed = fake_zero_copy_send(&sock, peer, b"refused");
      complete(&sock, packed, -libc::EOPNOTSUPP, if more { MORE_FLAG } else { 0 });
      assert!(!shared.zerocopy.get(), "more {more}");
      assert_eq!(shared.sends_inflight.get(), u32::from(more));
      if more {
        complete(&sock, packed, 0, NOTIF_FLAG);
      }
      assert_eq!(shared.sends_inflight.get(), 0);
      assert!(sock.tx().begin(peer, None, 65_507).is_some());
      send(&sock, peer, None, b"copied");
      settle(&sock).await;
      let stats = sock.stats();
      assert_eq!((stats.send_errors, stats.zc_fallbacks, stats.zc_sends), (1, 1, 0), "{stats:?}");
    });
    let mut buffer = [0; 16];
    let (len, _) = receiver.recv_from(&mut buffer).unwrap();
    assert_eq!(&buffer[..len], b"copied");
  }

  // Ruling T19-b (review): once zero-copy sends went, a send that fails with EINVAL or ENOMEM (a
  // bad packet, memory short for a moment) counts as failed and leaves zero-copy on; EOPNOTSUPP
  // turns it off whenever it comes. A first result of ENOMEM (the pinned pages over the limit)
  // turns it off too.
  #[test]
  fn zero_copy_goes_off_for_a_refusal_not_for_a_failed_packet() {
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    UringRuntime::new().unwrap().block_on(async {
      let sock = UringUdpSocket::bind(V4, &UdpParams { zerocopy: true, ..params() }).unwrap();
      let shared = &*sock.shared;
      let packed = fake_zero_copy_send(&sock, peer, b"sent");
      complete(&sock, packed, 4, MORE_FLAG);
      complete(&sock, packed, 0, NOTIF_FLAG);
      for errno in [libc::EINVAL, libc::ENOMEM] {
        let packed = fake_zero_copy_send(&sock, peer, b"failed");
        complete(&sock, packed, -errno, 0);
        assert!(shared.zerocopy.get(), "errno {errno}");
      }
      let packed = fake_zero_copy_send(&sock, peer, b"refused");
      complete(&sock, packed, -libc::EOPNOTSUPP, 0);
      assert!(!shared.zerocopy.get());
      let stats = sock.stats();
      assert_eq!((stats.send_errors, stats.zc_fallbacks), (3, 1), "{stats:?}");
      assert_eq!(shared.sends_inflight.get(), 0);
      let first = UringUdpSocket::bind(V4, &UdpParams { zerocopy: true, ..params() }).unwrap();
      let packed = fake_zero_copy_send(&first, peer, b"pinned");
      complete(&first, packed, -libc::ENOMEM, 0);
      assert!(!first.shared.zerocopy.get());
      assert_eq!(first.stats().zc_fallbacks, 1);
    });
  }

  // Ruling T19-b (review), at the level of the completions: with an arena of one train, the
  // completion of a zero-copy send leaves its bytes the kernel's (the arena has no room), and the
  // notification gives them back.
  #[test]
  fn a_zero_copy_train_goes_back_only_with_its_notification() {
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    UringRuntime::new().unwrap().block_on(async {
      let params = UdpParams { zerocopy: true, tx_arena_bytes: 2000, ..params() };
      let sock = UringUdpSocket::bind(V4, &params).unwrap();
      let packed = fake_zero_copy_send(&sock, peer, &[7; 2000]);
      complete(&sock, packed, 2000, MORE_FLAG);
      assert!(sock.tx().begin(peer, None, 1).is_none());
      assert_eq!(sock.shared.sends_inflight.get(), 1);
      complete(&sock, packed, 0, NOTIF_FLAG);
      assert!(sock.tx().begin(peer, None, 2000).is_some());
      assert_eq!(sock.shared.sends_inflight.get(), 0);
      let stats = sock.stats();
      assert_eq!((stats.zc_notifications, stats.send_errors), (1, 0), "{stats:?}");
    });
  }

  // One datagram written into the arena; it joins the newest train if it can.
  fn queue(sock: &UringUdpSocket, peer: SocketAddr, local: Option<IpAddr>, bytes: &[u8]) {
    let mut tx = sock.tx();
    let buffer = tx.begin(peer, local, bytes.len()).unwrap();
    buffer.copy_from_slice(bytes);
    tx.commit(bytes.len());
  }

  fn send(sock: &UringUdpSocket, peer: SocketAddr, local: Option<IpAddr>, bytes: &[u8]) {
    queue(sock, peer, local, bytes);
    assert_eq!(sock.submit().unwrap(), 1);
  }

  // Waits until `n` datagrams in all were received, or fails after five seconds.
  async fn recv(sock: &UringUdpSocket, n: usize) -> Received {
    let mut received = Vec::new();
    let mut timeout = Sleep::new(TIMEOUT).unwrap();
    poll_fn(|cx| {
      let poll = sock.poll_recv(cx, &mut |bytes, meta| received.push((bytes.to_vec(), meta)));
      if let Poll::Ready(Err(err)) = poll {
        panic!("{err:?}");
      }
      if received.len() >= n {
        return Poll::Ready(());
      }
      assert!(Pin::new(&mut timeout).poll(cx).is_pending(), "{} of {n} datagrams", received.len());
      Poll::Pending
    })
    .await;
    received
  }

  // Waits for one call of `poll_recv` that visits at least one datagram; returns how many.
  async fn recv_batch(sock: &UringUdpSocket, f: &mut dyn FnMut(&mut [u8], DatagramMeta)) -> usize {
    let mut timeout = Sleep::new(TIMEOUT).unwrap();
    poll_fn(|cx| {
      if let Poll::Ready(rslt) = sock.poll_recv(cx, f) {
        return Poll::Ready(rslt.unwrap());
      }
      assert!(Pin::new(&mut timeout).poll(cx).is_pending(), "no datagram");
      Poll::Pending
    })
    .await
  }

  // Waits until every send submitted has completed.
  async fn settle(sock: &UringUdpSocket) {
    let begin = std::time::Instant::now();
    while sock.shared.sends_inflight.get() > 0 {
      assert!(begin.elapsed() < TIMEOUT, "sends never completed");
      Sleep::new(Duration::from_millis(1)).unwrap().await.unwrap();
    }
  }

  fn sockopt(fd: RawFd, level: i32, name: i32) -> libc::c_int {
    let mut value: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `value` and `len` outlive the call, and `len` is the size of `value`
    let rslt = unsafe { libc::getsockopt(fd, level, name, (&raw mut value).cast(), &raw mut len) };
    assert_eq!(rslt, 0, "{}", std::io::Error::last_os_error());
    value
  }

  fn std_socket(addr: &str) -> std::net::UdpSocket {
    let socket = std::net::UdpSocket::bind(addr).unwrap();
    socket.set_read_timeout(Some(TIMEOUT)).unwrap();
    socket
  }

  fn meta(peer: SocketAddr, local: IpAddr) -> DatagramMeta {
    DatagramMeta { peer, local: Some(local), segment_size: None }
  }

  // A datagram each way between two sockets of one runtime: the receiver learns the peer and the
  // local address the datagram was sent to, the reply leaves from it, and every datagram has DF.
  #[test]
  fn udp_round_trip_on_loopback() {
    UringRuntime::new().unwrap().block_on(async {
      let server = UringUdpSocket::bind(V4, &params()).unwrap();
      let client = UringUdpSocket::bind(V4, &params()).unwrap();
      let (server_addr, client_addr) = (server.local_addr(), client.local_addr());
      assert_ne!(server_addr.port(), 0);
      let fd = server.shared.fd;
      assert_eq!(sockopt(fd, libc::SOL_IP, libc::IP_MTU_DISCOVER), libc::IP_PMTUDISC_PROBE);
      assert_eq!(sockopt(fd, libc::SOL_IP, libc::IP_PKTINFO), 1);
      send(&client, server_addr, None, b"ping");
      let received = recv(&server, 1).await;
      assert_eq!(received, [(b"ping".to_vec(), meta(client_addr, server_addr.ip()))]);
      let (_, from) = received[0];
      send(&server, from.peer, from.local, b"pong");
      let received = recv(&client, 1).await;
      assert_eq!(received, [(b"pong".to_vec(), meta(server_addr, client_addr.ip()))]);
      settle(&server).await;
      settle(&client).await;
      let stats = server.stats();
      assert_eq!((stats.datagrams_in, stats.trains_out, stats.send_errors), (1, 1, 0));
      assert!(stats.rcvbuf > 0 && stats.sndbuf > 0, "{stats:?}");
    });
  }

  // 10,000 datagrams through the 256 buffers of the ring: a consumer that sleeps between batches
  // but never has more than 200 datagrams outstanding loses none and finds them in batches. Then a
  // burst of 300 while it does not consume: the ring runs out, the multishot receive ends with
  // ENOBUFS, and once the consumer gives the buffers back it receives again and the rest, which
  // waited in the socket, arrive.
  #[test]
  fn multishot_recv_batches_and_recycles_buffers() {
    use crate::sync::{Arc, AtomicBool, AtomicUsize};
    use core::sync::atomic::Ordering;
    const TOTAL: usize = 10_000;
    const WINDOW: usize = 200;
    const BURST: usize = 300;
    let consumed = Arc::new(AtomicUsize::new(0));
    let burst_sent = Arc::new(AtomicBool::new(false));
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let (go_tx, go_rx) = std::sync::mpsc::channel();
    let (client_consumed, client_burst_sent) = (consumed.clone(), burst_sent.clone());
    let client = std::thread::spawn(move || {
      let addr: SocketAddr = addr_rx.recv().unwrap();
      let socket = std_socket("127.0.0.1:0");
      let mut seq = 0u64;
      while seq < TOTAL as u64 {
        for _ in 0..WINDOW {
          let _len = socket.send_to(&seq.to_be_bytes(), addr).unwrap();
          seq += 1;
        }
        let begin = std::time::Instant::now();
        while client_consumed.load(Ordering::SeqCst) < seq as usize {
          assert!(begin.elapsed() < TIMEOUT, "the consumer stalled at {seq}");
          std::thread::sleep(Duration::from_micros(50));
        }
      }
      go_rx.recv().unwrap();
      for _ in 0..BURST {
        let _len = socket.send_to(&seq.to_be_bytes(), addr).unwrap();
        seq += 1;
      }
      client_burst_sent.store(true, Ordering::SeqCst);
    });
    UringRuntime::new().unwrap().block_on(async {
      let sock = UringUdpSocket::bind(V4, &params()).unwrap();
      addr_tx.send(sock.local_addr()).unwrap();
      let mut next = 0u64;
      let mut largest = 0;
      let mut check = |bytes: &mut [u8], _: DatagramMeta| {
        assert_eq!(bytes, next.to_be_bytes(), "datagram {next}");
        next += 1;
      };
      let mut seen = 0;
      while seen < TOTAL {
        let len = recv_batch(&sock, &mut check).await;
        seen += len;
        largest = largest.max(len);
        consumed.store(seen, Ordering::SeqCst);
        Sleep::new(Duration::from_micros(500)).unwrap().await.unwrap();
      }
      assert_eq!(seen, TOTAL);
      assert_eq!(sock.stats().recv_buffers_exhausted, 0);
      assert!(largest > 1, "every datagram came alone");
      // The burst: nothing is consumed until all of it was sent and the ring ran dry
      go_tx.send(()).unwrap();
      let begin = std::time::Instant::now();
      while !burst_sent.load(Ordering::SeqCst) {
        assert!(begin.elapsed() < TIMEOUT, "the burst was never sent");
        Sleep::new(Duration::from_millis(1)).unwrap().await.unwrap();
      }
      // The kernel fills the 256 buffers, then ends the receive at the 257th datagram
      while sock.stats().recv_buffers_exhausted == 0 {
        assert!(begin.elapsed() < TIMEOUT, "the ring never ran dry");
        Sleep::new(Duration::from_millis(1)).unwrap().await.unwrap();
      }
      assert_eq!(sock.stats().recv_buffers_exhausted, 1);
      while seen < TOTAL + BURST {
        seen += recv_batch(&sock, &mut check).await;
      }
      let stats = sock.stats();
      assert_eq!(seen, TOTAL + BURST);
      assert_eq!(stats.datagrams_in, (TOTAL + BURST) as u64);
      assert_eq!((stats.datagrams_truncated, stats.recv_errors), (0, 0));
    });
    client.join().unwrap();
  }

  // One train of four 1472-byte datagrams goes out with one send and reaches a plain socket, one
  // without generic receive offload, as four datagrams.
  #[test]
  fn gso_train_arrives_as_segments() {
    let receiver = std_socket("127.0.0.1:0");
    let peer = receiver.local_addr().unwrap();
    UringRuntime::new().unwrap().block_on(async {
      let sock = UringUdpSocket::bind(V4, &params()).unwrap();
      for idx in 0..4u8 {
        queue(&sock, peer, None, &[idx; 1472]);
      }
      assert_eq!(sock.tx().pending().count(), 1);
      assert_eq!(sock.submit().unwrap(), 1);
      settle(&sock).await;
      for idx in 0..4u8 {
        let mut buffer = [0; 2048];
        let (len, from) = receiver.recv_from(&mut buffer).unwrap();
        assert_eq!((len, from), (1472, sock.local_addr()));
        assert!(buffer[..len].iter().all(|el| *el == idx), "segment {idx}");
      }
      let stats = sock.stats();
      assert_eq!((stats.trains_out, stats.send_errors), (1, 0));
    });
  }

  // With generic receive offload, the train of the previous test arrives as one datagram of
  // 5888 bytes whose segment size is reported; a datagram that was not coalesced reports none.
  #[test]
  fn gro_coalesces_when_enabled() {
    UringRuntime::new().unwrap().block_on(async {
      let receiver = UringUdpSocket::bind(V4, &UdpParams { gro: true, ..params() }).unwrap();
      let sender = UringUdpSocket::bind(V4, &params()).unwrap();
      let fd = receiver.shared.fd;
      assert_eq!(sockopt(fd, libc::SOL_UDP, libc::UDP_GRO), 1);
      for idx in 0..4u8 {
        queue(&sender, receiver.local_addr(), None, &[idx; 1472]);
      }
      assert_eq!(sender.submit().unwrap(), 1);
      let received = recv(&receiver, 1).await;
      let (bytes, meta) = &received[0];
      assert_eq!((bytes.len(), meta.segment_size), (4 * 1472, Some(1472)));
      for (idx, segment) in bytes.chunks(1472).enumerate() {
        assert!(segment.iter().all(|el| usize::from(*el) == idx), "segment {idx}");
      }
      send(&sender, receiver.local_addr(), None, &[9; 100]);
      let received = recv(&receiver, 1).await;
      assert_eq!((received[0].0.len(), received[0].1.segment_size), (100, None));
    });
  }

  // Restricts a socket to the loopback interface before it binds, so that a socket bound to the
  // wildcard address only ever sees loopback traffic (Linux 5.7 allows this without privileges).
  fn bind_to_loopback(fd: RawFd) -> crate::Result<()> {
    let name = b"lo\0";
    // SAFETY: `name` outlives the call and its length is passed
    let rslt = unsafe {
      libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_BINDTODEVICE,
        name.as_ptr().cast(),
        name.len() as libc::socklen_t,
      )
    };
    if rslt != 0 {
      return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
  }

  // A dual-stack socket (`[::]`, `IPV6_V6ONLY` off) answers IPv4 clients, reported with plain
  // IPv4 addresses, and IPv6 clients, each from the exact address the client sent to: 127.0.0.2
  // is a loopback address too, but replies to its client would leave from 127.0.0.1 if the
  // socket chose the source address itself (review focus 3).
  #[test]
  fn dual_stack_replies_from_the_address_used() {
    let clients = [
      (std_socket("127.0.0.1:0"), IpAddr::V4(Ipv4Addr::LOCALHOST)),
      (std_socket("127.0.0.1:0"), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
      (std_socket("[::1]:0"), IpAddr::V6(Ipv6Addr::LOCALHOST)),
    ];
    UringRuntime::new().unwrap().block_on(async {
      let any = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
      let server = UringUdpSocket::bind_with(any, &params(), &bind_to_loopback).unwrap();
      let port = server.local_addr().port();
      let fd = server.shared.fd;
      assert_eq!(sockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY), 0);
      assert_eq!(sockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO), 1);
      let probe = libc::IPV6_PMTUDISC_PROBE;
      assert_eq!(sockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER), probe);
      assert_eq!(sockopt(fd, libc::SOL_IP, libc::IP_MTU_DISCOVER), libc::IP_PMTUDISC_PROBE);
      for (idx, (client, dst)) in clients.iter().enumerate() {
        let _len = client.send_to(&[idx as u8; 32], SocketAddr::new(*dst, port)).unwrap();
        let received = recv(&server, 1).await;
        let (bytes, from) = &received[0];
        assert_eq!(bytes, &[idx as u8; 32]);
        assert_eq!(*from, meta(client.local_addr().unwrap(), *dst), "client {idx}");
        send(&server, from.peer, from.local, &[0xa0 | idx as u8; 16]);
      }
      settle(&server).await;
      assert_eq!(server.stats().send_errors, 0);
    });
    for (idx, (client, dst)) in clients.iter().enumerate() {
      let mut buffer = [0; 64];
      let (len, from) = client.recv_from(&mut buffer).unwrap();
      assert_eq!(&buffer[..len], &[0xa0 | idx as u8; 16]);
      assert_eq!(from.ip(), *dst, "client {idx}");
    }
  }

  // Two sockets of one SO_REUSEPORT group with the steering program attached: the datagrams whose
  // destination connection ID starts with an even byte reach the first socket, the others the
  // second, for short and long headers. A single client's datagrams all have the same 4-tuple, so
  // the kernel's hash alone would send them all to one socket.
  #[test]
  fn cbpf_steers_by_dcid_byte() {
    let client = std_socket("127.0.0.1:0");
    UringRuntime::new().unwrap().block_on(async {
      let first = UringUdpSocket::bind(V4, &UdpParams::new()).unwrap();
      let second = UringUdpSocket::bind(first.local_addr(), &UdpParams::new()).unwrap();
      first.attach_reuseport_cbpf(&steering_cbpf(2)).unwrap();
      for byte in 0..8u8 {
        let short = [0x41, byte, 1, 2, 3, 4, 5, 6, 7];
        let long = [0xc3, 0, 0, 0, 1, 8, byte, 1, 2, 3, 4, 5, 6, 7];
        for datagram in [&short[..], &long[..]] {
          let _len = client.send_to(datagram, first.local_addr()).unwrap();
        }
      }
      let dcid = |el: &(Vec<u8>, DatagramMeta)| if el.0[0] & 0x80 == 0 { el.0[1] } else { el.0[6] };
      for (idx, sock) in [&first, &second].into_iter().enumerate() {
        let received = recv(sock, 8).await;
        let mut bytes: Vec<u8> = received.iter().map(dcid).collect();
        bytes.sort_unstable();
        let expected: Vec<u8> = (0..8u8).filter(|el| usize::from(*el) % 2 == idx).collect();
        let doubled: Vec<u8> = expected.iter().flat_map(|el| [*el, *el]).collect();
        assert_eq!(bytes, doubled, "socket {idx}");
      }
    });
  }

  // A datagram pushed into the inbox of a socket of another runtime, on another thread, reaches
  // it, woken by a message on its ring: it has nothing else to wake it but a five-second timeout.
  #[test]
  fn inbox_forward_wakes_other_runtime() {
    const COUNT: usize = 100;
    let (inbox_tx, inbox_rx) = std::sync::mpsc::channel();
    let owner = std::thread::spawn(move || {
      UringRuntime::new().unwrap().block_on(async {
        let sock = UringUdpSocket::bind(V4, &params()).unwrap();
        inbox_tx.send(sock.inbox()).unwrap();
        let mut received: Received = Vec::new();
        let begin = std::time::Instant::now();
        let mut timeout = Sleep::new(TIMEOUT).unwrap();
        poll_fn(|cx| {
          let _poll = sock.poll_inbox(cx, &mut |bytes, meta| received.push((bytes.to_vec(), meta)));
          if received.len() >= COUNT {
            return Poll::Ready(());
          }
          assert!(Pin::new(&mut timeout).poll(cx).is_pending(), "{} datagrams", received.len());
          Poll::Pending
        })
        .await;
        (received, begin.elapsed(), sock.stats())
      })
    });
    let inbox: UdpInbox = inbox_rx.recv().unwrap();
    UringRuntime::new().unwrap().block_on(async {
      for batch in 0..10u8 {
        for idx in 0..10u8 {
          let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, batch, idx)), 4433);
          let datagram = [batch * 10 + idx; 1200];
          assert!(inbox.push(&datagram, meta(peer, IpAddr::V4(Ipv4Addr::LOCALHOST))));
        }
        Sleep::new(Duration::from_millis(2)).unwrap().await.unwrap();
      }
    });
    let (received, elapsed, stats) = owner.join().unwrap();
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    assert_eq!(received.len(), COUNT);
    for (idx, (bytes, from)) in received.iter().enumerate() {
      assert_eq!(bytes, &[idx as u8; 1200]);
      let peer =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, idx as u8 / 10, idx as u8 % 10)), 4433);
      assert_eq!(*from, meta(peer, IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }
    assert!(stats.inbox_wakes >= 1, "{stats:?}");
    assert_eq!(stats.inbox_in, COUNT as u64);
  }

  // A thread without a runtime pushes too: the owner is woken through its waker.
  #[test]
  fn inbox_push_from_a_thread_without_a_runtime_wakes_the_owner() {
    UringRuntime::new().unwrap().block_on(async {
      let sock = UringUdpSocket::bind(V4, &params()).unwrap();
      let inbox = sock.inbox();
      let pusher = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
        assert!(inbox.push(b"hello", meta(peer, IpAddr::V4(Ipv4Addr::LOCALHOST))));
      });
      let mut received: Received = Vec::new();
      let mut timeout = Sleep::new(TIMEOUT).unwrap();
      poll_fn(|cx| {
        let _poll = sock.poll_inbox(cx, &mut |bytes, meta| received.push((bytes.to_vec(), meta)));
        if !received.is_empty() {
          return Poll::Ready(());
        }
        assert!(Pin::new(&mut timeout).poll(cx).is_pending(), "never woken");
        Poll::Pending
      })
      .await;
      assert_eq!(received[0].0, b"hello");
      pusher.join().unwrap();
    });
  }

  // The inbox takes `SLOTS` datagrams of at most `DATAGRAM_LEN` bytes, refuses more until they
  // are taken, and refuses everything once its socket is gone.
  #[test]
  fn inbox_is_bounded_and_closes_with_its_socket() {
    UringRuntime::new().unwrap().block_on(async {
      let sock = UringUdpSocket::bind(V4, &params()).unwrap();
      let inbox = sock.inbox();
      let from = meta(sock.local_addr(), IpAddr::V4(Ipv4Addr::LOCALHOST));
      assert!(!inbox.push(&[0; UdpInbox::DATAGRAM_LEN + 1], from));
      for idx in 0..UdpInbox::SLOTS {
        assert!(inbox.push(&[idx as u8; UdpInbox::DATAGRAM_LEN], from), "{idx}");
      }
      assert!(!inbox.push(&[0; 1], from));
      let mut count = 0;
      let poll = poll_fn(|cx| {
        let poll = sock.poll_inbox(cx, &mut |bytes, _| {
          assert_eq!(bytes, &[count as u8; UdpInbox::DATAGRAM_LEN][..]);
          count += 1;
        });
        Poll::Ready(poll)
      })
      .await;
      assert_eq!((poll, count), (Poll::Ready(UdpInbox::SLOTS), UdpInbox::SLOTS));
      assert!(inbox.push(&[0; 1], from));
      drop(sock);
      assert!(!inbox.push(&[0; 1], from));
    });
  }

  // A train whose send fails (here: from a local address that is not ours) is released and
  // counted, and the socket goes on sending.
  #[test]
  fn a_failed_send_releases_its_train_and_the_socket_goes_on() {
    let receiver = std_socket("127.0.0.1:0");
    let peer = receiver.local_addr().unwrap();
    UringRuntime::new().unwrap().block_on(async {
      let sock = UringUdpSocket::bind(V4, &params()).unwrap();
      send(&sock, peer, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))), b"lost");
      settle(&sock).await;
      assert_eq!(sock.stats().send_errors, 1);
      // All of the arena is free again
      assert!(sock.tx().begin(peer, None, 65_507).is_some());
      send(&sock, peer, None, b"sent");
      settle(&sock).await;
      let stats = sock.stats();
      assert_eq!((stats.trains_out, stats.send_errors), (2, 1));
    });
    let mut buffer = [0; 16];
    let (len, _) = receiver.recv_from(&mut buffer).unwrap();
    assert_eq!(&buffer[..len], b"sent");
  }

  // A waker that counts its wakes in `WOKEN`.
  static WOKEN: crate::sync::AtomicUsize = crate::sync::AtomicUsize::new(0);

  fn counting_waker() -> core::task::Waker {
    use core::task::{RawWaker, RawWakerVTable};
    fn clone(data: *const ()) -> RawWaker {
      RawWaker::new(data, &VTABLE)
    }
    fn wake(_: *const ()) {
      let _ = WOKEN.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
    fn drop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake, drop);
    // SAFETY: the vtable never reads the data pointer
    unsafe { core::task::Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
  }

  // A message to a ring that fails (here the "ring" of the inbox is a plain socket, as for a ring
  // that is gone or out of memory) comes back on the ring that sent it: the inbox's signal is
  // cleared, so that the next push signals again, and the owner is woken through its waker.
  #[test]
  fn a_failed_msg_ring_clears_the_signal_and_wakes_the_owner() {
    use core::sync::atomic::Ordering;
    let not_a_ring = std_socket("127.0.0.1:0");
    let fd = std::os::fd::AsRawFd::as_raw_fd(&not_a_ring);
    let inbox = UdpInbox::new(fd, 0, u32::MAX).unwrap();
    let from = meta(not_a_ring.local_addr().unwrap(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    UringRuntime::new().unwrap().block_on(async {
      for round in 1..=2 {
        inbox.inner.waker.register(&counting_waker());
        assert!(inbox.push(&[round; 8], from));
        assert!(inbox.inner.signalled.load(Ordering::SeqCst));
        let begin = std::time::Instant::now();
        while inbox.inner.signalled.load(Ordering::SeqCst) {
          assert!(begin.elapsed() < TIMEOUT, "the failed message left the inbox signalled");
          Sleep::new(Duration::from_millis(1)).unwrap().await.unwrap();
        }
        assert_eq!(WOKEN.load(Ordering::SeqCst), usize::from(round));
      }
    });
  }

  // A callback that panics in `poll_recv` still gives its buffer back: with two buffers, two
  // panics would otherwise leave the ring empty for good.
  #[test]
  fn a_panicking_recv_callback_gives_its_buffer_back() {
    let client = std_socket("127.0.0.1:0");
    UringRuntime::new().unwrap().block_on(async {
      let sock = UringUdpSocket::bind(V4, &UdpParams { recv_buffers: 2, ..params() }).unwrap();
      for _ in 0..2 {
        let _len = client.send_to(b"boom", sock.local_addr()).unwrap();
        let begin = std::time::Instant::now();
        while sock.shared.completed.borrow().is_empty() {
          assert!(begin.elapsed() < TIMEOUT, "no datagram");
          Sleep::new(Duration::from_millis(1)).unwrap().await.unwrap();
        }
        poll_fn(|cx| {
          let unwound = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
            sock.poll_recv(cx, &mut |_, _| panic!("a callback that panics"))
          }));
          assert!(unwound.is_err());
          Poll::Ready(())
        })
        .await;
      }
      for idx in 0..4u8 {
        let _len = client.send_to(&[idx; 4], sock.local_addr()).unwrap();
      }
      let received = recv(&sock, 4).await;
      let bytes: Vec<Vec<u8>> = received.into_iter().map(|el| el.0).collect();
      assert_eq!(bytes, (0..4u8).map(|el| alloc::vec![el; 4]).collect::<Vec<_>>());
    });
  }

  // A completion for a send slot that holds no train, as a stray or repeated one would be, frees
  // nothing: the slot is not put on the free list a second time, where two sends would share it.
  #[test]
  fn a_stray_send_completion_frees_no_slot() {
    UringRuntime::new().unwrap().block_on(async {
      let sock = UringUdpSocket::bind(V4, &params()).unwrap();
      let free = || sock.shared.sends.borrow().free.len();
      let before = free();
      crate::executor::uring_executor::with_reactor(|reactor| {
        reactor.on_udp_send((7 << 16) | sock.idx, sock.generation, 0, 0);
        // Nor does a stray failure or notification count (task 19 review)
        reactor.on_udp_send((7 << 16) | sock.idx, sock.generation, -libc::EIO, 0);
        reactor.on_udp_send((7 << 16) | sock.idx, sock.generation, i32::MIN, 1 << 3);
        Ok(())
      })
      .unwrap();
      assert_eq!(free(), before);
      assert_eq!(sock.shared.sends_inflight.get(), 0);
      let stats = sock.stats();
      let counted = (stats.send_errors, stats.zc_notifications, stats.zc_copied);
      assert_eq!(counted, (0, 0, 0), "{stats:?}");
    });
  }

  // Resolves at the second poll, having woken itself at the first.
  async fn yield_now() {
    let mut yielded = false;
    poll_fn(|cx| {
      if yielded {
        return Poll::Ready(());
      }
      yielded = true;
      cx.waker().wake_by_ref();
      Poll::Pending
    })
    .await;
  }

  // Once warm, nothing allocates on the thread of a runtime: 10,000 datagrams received and echoed;
  // 1,024 datagrams forwarded into its inbox by another runtime, which wakes it with a message on
  // its ring (nothing allocates on the forwarding thread either); 200 sends whose completion finds
  // the arena borrowed, so that their trains are released at its next borrow.
  #[expect(
    clippy::await_holding_refcell_ref,
    reason = "the arena stays borrowed for a turn, so that a send completes meanwhile"
  )]
  #[test]
  fn udp_steady_state_allocates_nothing() {
    use crate::{
      sync::{Arc, AtomicBool, AtomicU64, AtomicUsize},
      tests::_count_allocations_in,
    };
    use core::sync::atomic::Ordering;
    static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
    static FORWARDER_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
    const WARM_UP: usize = 1_000;
    const COUNTED: usize = 10_000;
    const WINDOW: usize = 64;
    // Whole windows, the warm-up and the counted datagrams included
    const TOTAL: usize = (WARM_UP + COUNTED).div_ceil(WINDOW) * WINDOW;
    const FORWARD_WARM_UP: usize = 4 * WINDOW;
    const FORWARDED: usize = FORWARD_WARM_UP + 16 * WINDOW;
    const LATE_WARM_UP: usize = 8;
    const LATE: usize = LATE_WARM_UP + 200;
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let client = std::thread::spawn(move || {
      let addr: SocketAddr = addr_rx.recv().unwrap();
      let socket = std_socket("127.0.0.1:0");
      let mut buffer = [0; 256];
      for window in 0..TOTAL / WINDOW {
        for idx in 0..WINDOW {
          let seq = (window * WINDOW + idx) as u64;
          let _len = socket.send_to(&[&seq.to_be_bytes()[..], &[7; 92]].concat(), addr).unwrap();
        }
        for idx in 0..WINDOW {
          let seq = (window * WINDOW + idx) as u64;
          let (len, _) = socket.recv_from(&mut buffer).unwrap();
          assert_eq!((len, &buffer[..8]), (100, &seq.to_be_bytes()[..]));
        }
      }
    });
    // Pushes `FORWARDED` datagrams into the inbox, a window at a time, once told to
    let forwarding = Arc::new(AtomicBool::new(false));
    let taken = Arc::new(AtomicUsize::new(0));
    let (inbox_tx, inbox_rx) = std::sync::mpsc::channel();
    let (forwarder_forwarding, forwarder_taken) = (forwarding.clone(), taken.clone());
    let forwarder = std::thread::spawn(move || {
      let inbox: UdpInbox = inbox_rx.recv().unwrap();
      UringRuntime::new().unwrap().block_on(async move {
        let wait = async |done: &dyn Fn() -> bool| {
          let begin = std::time::Instant::now();
          while !done() {
            assert!(begin.elapsed() < TIMEOUT, "the owner stalled");
            Sleep::new(Duration::from_micros(100)).unwrap().await.unwrap();
          }
        };
        wait(&|| forwarder_forwarding.load(Ordering::SeqCst)).await;
        let from = meta(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9), V4.ip());
        let mut before = 0;
        for seq in 0..FORWARDED {
          if seq == FORWARD_WARM_UP {
            _count_allocations_in(&FORWARDER_ALLOCATIONS);
            before = FORWARDER_ALLOCATIONS.load(Ordering::SeqCst);
          }
          assert!(inbox.push(&(seq as u64).to_be_bytes(), from), "{seq}");
          if (seq + 1) % WINDOW == 0 {
            wait(&|| forwarder_taken.load(Ordering::SeqCst) > seq).await;
          }
        }
        FORWARDER_ALLOCATIONS.load(Ordering::SeqCst) - before
      })
    });
    let sink = std_socket("127.0.0.1:0");
    let allocations = UringRuntime::new().unwrap().block_on(async {
      let sock = UringUdpSocket::bind(V4, &params()).unwrap();
      addr_tx.send(sock.local_addr()).unwrap();
      inbox_tx.send(sock.inbox()).unwrap();
      let mut echoed = 0;
      let (mut before, mut after) = (None, None);
      let mut timeout = Sleep::new(Duration::from_secs(60)).unwrap();
      poll_fn(|cx| {
        loop {
          let poll = sock.poll_recv(cx, &mut |bytes, meta| {
            let mut tx = sock.tx();
            let buffer = tx.begin(meta.peer, meta.local, bytes.len()).unwrap();
            buffer.copy_from_slice(bytes);
            tx.commit(bytes.len());
            echoed += 1;
          });
          let _queued = sock.submit().unwrap();
          if echoed >= WARM_UP && before.is_none() {
            _count_allocations_in(&ALLOCATIONS);
            before = Some(ALLOCATIONS.load(Ordering::SeqCst));
          }
          if echoed >= WARM_UP + COUNTED && after.is_none() {
            after = Some(ALLOCATIONS.load(Ordering::SeqCst));
          }
          if echoed >= TOTAL {
            return Poll::Ready(());
          }
          if poll.is_pending() {
            break;
          }
        }
        assert!(Pin::new(&mut timeout).poll(cx).is_pending(), "{echoed} echoed");
        Poll::Pending
      })
      .await;
      // The last window goes out before the next phase
      settle(&sock).await;
      let echoing = after.unwrap() - before.unwrap();
      // The inbox
      forwarding.store(true, Ordering::SeqCst);
      let mut next = 0u64;
      let (mut before, mut after) = (None, None);
      poll_fn(|cx| {
        let _poll = sock.poll_inbox(cx, &mut |bytes, _| {
          assert_eq!(bytes, next.to_be_bytes());
          next += 1;
        });
        let seen = next as usize;
        taken.store(seen, Ordering::SeqCst);
        if seen >= FORWARD_WARM_UP && before.is_none() {
          before = Some(ALLOCATIONS.load(Ordering::SeqCst));
        }
        if seen >= FORWARDED {
          after = Some(ALLOCATIONS.load(Ordering::SeqCst));
          return Poll::Ready(());
        }
        assert!(Pin::new(&mut timeout).poll(cx).is_pending(), "{seen} forwarded");
        Poll::Pending
      })
      .await;
      let forwarded = after.unwrap() - before.unwrap();
      // Sends that complete while the arena is borrowed
      let peer = sink.local_addr().unwrap();
      let mut late_before = 0;
      for round in 0..LATE {
        if round == LATE_WARM_UP {
          late_before = ALLOCATIONS.load(Ordering::SeqCst);
        }
        send(&sock, peer, None, &[round as u8; 100]);
        let held = sock.tx();
        let begin = std::time::Instant::now();
        while sock.shared.sends.borrow().late.is_empty() {
          assert!(begin.elapsed() < TIMEOUT, "the send never completed");
          yield_now().await;
        }
        drop(held);
        drop(sock.tx());
        assert!(sock.shared.sends.borrow().late.is_empty());
      }
      let late = ALLOCATIONS.load(Ordering::SeqCst) - late_before;
      let stats = sock.stats();
      assert_eq!(stats.inbox_in, FORWARDED as u64);
      assert!(stats.inbox_wakes > 0, "{stats:?}");
      (echoing, forwarded, late)
    });
    client.join().unwrap();
    let forwarding_allocations = forwarder.join().unwrap();
    assert_eq!(allocations, (0, 0, 0), "echoing {COUNTED}, forwarded, late releases");
    assert_eq!(forwarding_allocations, 0, "allocations on the forwarding runtime");
  }

  // The TCP paths of a runtime that also has a UDP socket with traffic: an echo over TCP works
  // while datagrams go back and forth on the same ring.
  #[test]
  fn tcp_paths_unaffected() {
    use crate::net::{StreamReader, StreamWriter, TcpListener, TcpParams};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = listener.local_addr().unwrap();
    drop(listener);
    let udp_peer = std_socket("127.0.0.1:0");
    let udp_peer_addr = udp_peer.local_addr().unwrap();
    let client = std::thread::spawn(move || {
      let mut stream = loop {
        if let Ok(elem) = std::net::TcpStream::connect(tcp_addr) {
          break elem;
        }
        std::thread::sleep(Duration::from_millis(5));
      };
      let payload: Vec<u8> = (0..64 * 1024).map(|el: u32| el as u8).collect();
      std::io::Write::write_all(&mut stream, &payload).unwrap();
      let mut echoed = alloc::vec![0; payload.len()];
      std::io::Read::read_exact(&mut stream, &mut echoed).unwrap();
      assert_eq!(echoed, payload);
    });
    UringRuntime::new().unwrap().block_on(async {
      let sock = UringUdpSocket::bind(V4, &params()).unwrap();
      let listener = crate::executor::UringTcpListener::bind(tcp_addr, TcpParams::default()).await;
      let listener = listener.unwrap();
      let (mut stream, _) = listener.accept(TcpParams::default()).await.unwrap();
      let mut buffer = alloc::vec![0; 64 * 1024];
      let mut done = 0;
      let mut datagrams = 0;
      while done < buffer.len() {
        let _len = udp_peer.send_to(&[done as u8; 64], sock.local_addr()).unwrap();
        let len = stream.read((&mut buffer[done..]).into()).await.unwrap().unwrap().get();
        done += len;
        datagrams += recv(&sock, 1).await.len();
        send(&sock, udp_peer_addr, None, &[1; 32]);
      }
      stream.write_all(&buffer).await.unwrap();
      settle(&sock).await;
      assert_eq!(sock.stats().datagrams_in, datagrams as u64);
    });
    client.join().unwrap();
    let mut buffer = [0; 64];
    let (len, _) = udp_peer.recv_from(&mut buffer).unwrap();
    assert_eq!(&buffer[..len], &[1; 32]);
  }
}

#[cfg(test)]
mod miri {
  use crate::{
    executor::uring_executor::{
      BufRing,
      udp::{
        Dropped, InboxQueue, RECV_CONTROL_LEN, RECV_HEADROOM, RECV_NAME_LEN, RECV_OUT_LEN,
        SendDone, SendSlot, SendSlots, SendStep, SendWait, parse_recvmsg, prepare_send, put_cmsg,
      },
    },
    quic::{DatagramMeta, TxArena},
  };
  use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

  // The flags of a CQE (`IORING_CQE_F_MORE`, `IORING_CQE_F_NOTIF`), which the io-uring crate
  // reads but does not export
  const MORE: u32 = 1 << 1;
  const NOTIF: u32 = 1 << 3;

  // Ruling T19-b: a copying send is done at its one completion; a zero-copy one only once both its
  // result (which says that a notification follows) and its notification arrived, in either
  // order; a zero-copy result without a notification to follow is done at once.
  #[test]
  fn send_wait_waits_for_the_result_and_the_notification() {
    let mut copy = SendWait::default();
    assert_eq!(copy.on_completion(0), SendStep::Done);
    let mut zc = SendWait::default();
    assert_eq!(zc.on_completion(MORE), SendStep::Waits);
    assert_eq!(zc.on_completion(NOTIF), SendStep::Done);
    let mut notification_first = SendWait::default();
    assert_eq!(notification_first.on_completion(NOTIF), SendStep::Waits);
    assert_eq!(notification_first.on_completion(MORE), SendStep::Done);
    let mut failed = SendWait::default();
    assert_eq!(failed.on_completion(0), SendStep::Done);
  }

  // Ruling T19-b: the arena never hands out the bytes of a train whose zero-copy send completed
  // but whose notification did not arrive yet, and the slot of that send is not free either;
  // the notification gives both back.
  #[test]
  fn a_train_awaiting_its_notification_is_not_reused() {
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    // Room for one train of 4000 bytes, no more
    let mut tx = TxArena::new(4000).unwrap();
    let mut sends = SendSlots::new(tx.max_trains()).unwrap();
    for nth in 0..2u8 {
      let buffer = tx.begin(peer, None, 4000).unwrap();
      buffer.fill(nth);
      tx.commit(4000);
      let id = tx.pending().next().unwrap().id;
      let slot_idx = sends.free.pop().unwrap();
      let free = sends.free.len();
      sends.slots[usize::from(slot_idx)].start(id, true);
      tx.mark_submitted(id);
      // The send completed; the kernel may still read the bytes
      assert_eq!(sends.complete(slot_idx, MORE), SendDone::Waits { zc: true });
      assert!(tx.begin(peer, None, 1).is_none(), "train {nth}: its bytes were handed out");
      assert_eq!(sends.free.len(), free);
      assert_eq!(sends.complete(slot_idx, NOTIF), SendDone::Released { id, zc: true });
      assert_eq!(sends.free.len(), free + 1);
      tx.release(id);
      // A completion repeated after that frees nothing
      assert_eq!(sends.complete(slot_idx, NOTIF), SendDone::Stray);
      assert_eq!(sends.free.len(), free + 1);
    }
    assert!(tx.begin(peer, None, 4000).is_some());
  }

  // The entries of a buffer ring point at its buffers, one each, and the tail the kernel reads
  // follows what was pushed; a buffer the kernel filled is handed out mutable, within its length.
  #[test]
  fn buffer_ring_entries_point_at_their_buffers() {
    let mut ring = BufRing::new(4, 64).unwrap();
    for bid in 0..4 {
      ring.push(bid);
    }
    ring.publish();
    let base = ring.mem.as_ptr() as u64;
    for idx in 0..4usize {
      // SAFETY: the ring has four entries of 16 bytes
      let (addr, len, bid) = unsafe {
        let entry = ring.entries.add(idx * 16);
        (
          entry.cast::<u64>().read(),
          entry.add(8).cast::<u32>().read(),
          entry.add(12).cast::<u16>().read(),
        )
      };
      assert_eq!((addr, len, usize::from(bid)), (base + idx as u64 * 64, 64, idx));
    }
    // SAFETY: the tail is the `resv` field of the first entry
    let tail = unsafe { ring.entries.add(14).cast::<u16>().read() };
    assert_eq!(tail, 4);
    let buffer = ring.buffer_mut(2, 10).unwrap();
    assert_eq!(buffer.len(), 10);
    buffer.fill(7);
    assert!(ring.mem[128..138].iter().all(|el| *el == 7));
    assert!(ring.buffer_mut(2, 65).is_none());
    assert!(ring.buffer_mut(4, 1).is_none());
  }

  // What the kernel writes for a multishot recvmsg: its header, the name, the control messages,
  // then the payload.
  fn recvmsg_buffer(
    name: &[u8],
    cmsgs: &[(i32, i32, &[u8])],
    payload: &[u8],
    flags: u32,
  ) -> alloc::vec::Vec<u8> {
    let mut buffer = alloc::vec![0; RECV_HEADROOM + payload.len()];
    let mut control = [0; RECV_CONTROL_LEN];
    let mut controllen = 0;
    for (level, ty, data) in cmsgs {
      controllen += put_cmsg(&mut control[controllen..], *level, *ty, data);
    }
    let header = [name.len() as u32, controllen as u32, payload.len() as u32, flags];
    for (idx, field) in header.iter().enumerate() {
      buffer[idx * 4..idx * 4 + 4].copy_from_slice(&field.to_ne_bytes());
    }
    buffer[RECV_OUT_LEN..RECV_OUT_LEN + name.len()].copy_from_slice(name);
    buffer[RECV_OUT_LEN + RECV_NAME_LEN..RECV_HEADROOM].copy_from_slice(&control);
    buffer[RECV_HEADROOM..].copy_from_slice(payload);
    buffer
  }

  fn sockaddr_in(ip: [u8; 4], port: u16) -> alloc::vec::Vec<u8> {
    let mut name = alloc::vec![0; 16];
    name[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    name[2..4].copy_from_slice(&port.to_be_bytes());
    name[4..8].copy_from_slice(&ip);
    name
  }

  fn sockaddr_in6(ip: [u8; 16], port: u16, scope_id: u32) -> alloc::vec::Vec<u8> {
    let mut name = alloc::vec![0; 28];
    name[..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
    name[2..4].copy_from_slice(&port.to_be_bytes());
    name[8..24].copy_from_slice(&ip);
    name[24..28].copy_from_slice(&scope_id.to_ne_bytes());
    name
  }

  fn in_pktinfo(addr: [u8; 4]) -> [u8; 12] {
    let mut info = [0; 12];
    info[..4].copy_from_slice(&1i32.to_ne_bytes());
    info[4..8].copy_from_slice(&[10, 9, 9, 9]);
    info[8..].copy_from_slice(&addr);
    info
  }

  fn in6_pktinfo(addr: [u8; 16]) -> [u8; 20] {
    let mut info = [0; 20];
    info[..16].copy_from_slice(&addr);
    info[16..].copy_from_slice(&1i32.to_ne_bytes());
    info
  }

  // Peers and local addresses of both families, v4-mapped ones reported as IPv4, the segment
  // size of a coalesced datagram, and the payload located in place; truncated datagrams and names
  // that are no address are refused.
  #[test]
  fn recvmsg_buffers_are_parsed_in_place() {
    let v4 = Ipv4Addr::new(10, 1, 2, 3);
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let mapped = v4.to_ipv6_mapped().octets();
    let gro = 1200i32.to_ne_bytes();
    let cases: [(alloc::vec::Vec<u8>, &[(i32, i32, &[u8])], DatagramMeta); 4] = [
      (
        sockaddr_in(v4.octets(), 443),
        &[(libc::SOL_IP, libc::IP_PKTINFO, &in_pktinfo([127, 0, 0, 2]))],
        DatagramMeta {
          peer: SocketAddr::new(IpAddr::V4(v4), 443),
          local: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
          segment_size: None,
        },
      ),
      (
        sockaddr_in6(v6.octets(), 8443, 3),
        &[
          (libc::SOL_UDP, libc::UDP_GRO, &gro),
          (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &in6_pktinfo(Ipv6Addr::LOCALHOST.octets())),
        ],
        DatagramMeta {
          peer: SocketAddr::V6(core::net::SocketAddrV6::new(v6, 8443, 0, 3)),
          local: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
          segment_size: Some(1200),
        },
      ),
      // An IPv4 client of a dual-stack socket: both kinds of packet information
      (
        sockaddr_in6(mapped, 1234, 0),
        &[
          (
            libc::IPPROTO_IPV6,
            libc::IPV6_PKTINFO,
            &in6_pktinfo(Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets()),
          ),
          (libc::SOL_IP, libc::IP_PKTINFO, &in_pktinfo([127, 0, 0, 1])),
        ],
        DatagramMeta {
          peer: SocketAddr::new(IpAddr::V4(v4), 1234),
          local: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
          segment_size: None,
        },
      ),
      (
        sockaddr_in(v4.octets(), 1),
        &[],
        DatagramMeta { peer: SocketAddr::new(IpAddr::V4(v4), 1), local: None, segment_size: None },
      ),
    ];
    for (idx, (name, cmsgs, meta)) in cases.iter().enumerate() {
      let mut buffer = recvmsg_buffer(name, cmsgs, b"payload", 0);
      let received = parse_recvmsg(&buffer).unwrap();
      let (start, parsed) = (received.start, received.meta);
      assert_eq!(parsed, *meta, "{idx}");
      assert_eq!(start, RECV_HEADROOM);
      buffer[start..].copy_from_slice(b"PAYLOAD");
      assert_eq!(&buffer[RECV_HEADROOM..], b"PAYLOAD");
    }
    let empty = recvmsg_buffer(&sockaddr_in(v4.octets(), 1), &[], b"", 0);
    assert_eq!(parse_recvmsg(&empty).map(|el| el.start), Ok(empty.len()));
    let truncated = recvmsg_buffer(&sockaddr_in(v4.octets(), 1), &[], b"x", libc::MSG_TRUNC as u32);
    assert_eq!(parse_recvmsg(&truncated), Err(Dropped::Truncated));
    assert_eq!(parse_recvmsg(&recvmsg_buffer(&[0; 16], &[], b"x", 0)), Err(Dropped::NoAddress));
    assert_eq!(parse_recvmsg(&[0; RECV_HEADROOM - 1]), Err(Dropped::Truncated));
    // Control messages that did not all fit: the datagram is handed out, and says so
    let ctrunc = libc::MSG_CTRUNC as u32;
    let buffer = recvmsg_buffer(&sockaddr_in(v4.octets(), 1), &[], b"x", ctrunc);
    let received = parse_recvmsg(&buffer).unwrap();
    assert_eq!((received.control_truncated, received.meta.peer.port()), (true, 1));
    assert!(!parse_recvmsg(&empty).unwrap().control_truncated);
    // Room for one more control message of 32 bytes than the three the socket asks for (a
    // timestamp, say), wherever the kernel puts it
    let timestamp = [0u8; 16];
    let cmsgs: [(i32, i32, &[u8]); 4] = [
      (libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, &timestamp),
      (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &in6_pktinfo(Ipv6Addr::LOCALHOST.octets())),
      (libc::SOL_IP, libc::IP_PKTINFO, &in_pktinfo([127, 0, 0, 1])),
      (libc::SOL_UDP, libc::UDP_GRO, &gro),
    ];
    let buffer = recvmsg_buffer(&sockaddr_in6(mapped, 1, 0), &cmsgs, b"x", 0);
    let received = parse_recvmsg(&buffer).unwrap();
    assert_eq!(received.meta.segment_size, Some(1200));
    assert_eq!(received.meta.local, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    // A control message whose length runs past the control area ends the walk
    let mut buffer = recvmsg_buffer(&sockaddr_in(v4.octets(), 1), &[], b"x", 0);
    buffer[4..8].copy_from_slice(&(RECV_CONTROL_LEN as u32).to_ne_bytes());
    buffer[RECV_OUT_LEN + RECV_NAME_LEN..][..8].copy_from_slice(&1000usize.to_ne_bytes());
    assert_eq!(parse_recvmsg(&buffer).unwrap().meta.local, None);
  }

  // The control messages of a send, read back the way the kernel walks them.
  fn walk_cmsgs(control: &[u8]) -> alloc::vec::Vec<(i32, i32, alloc::vec::Vec<u8>)> {
    let header = size_of::<libc::cmsghdr>();
    let mut cmsgs = alloc::vec::Vec::new();
    let mut off = 0;
    while off + header <= control.len() {
      let len = usize::from_ne_bytes(control[off..off + 8].try_into().unwrap());
      let level = i32::from_ne_bytes(control[off + 8..off + 12].try_into().unwrap());
      let ty = i32::from_ne_bytes(control[off + 12..off + 16].try_into().unwrap());
      cmsgs.push((level, ty, control[off + header..off + len].to_vec()));
      off += len.next_multiple_of(8);
    }
    cmsgs
  }

  // What the kernel reads of a send: the msghdr points into its own slot for the peer's address,
  // the iovec and the control messages, and the iovec at the train's bytes.
  #[test]
  fn send_msghdr_points_into_its_own_slot() {
    let bytes = [5u8; 3000];
    let v4_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4433);
    let v6_peer = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4434);
    let local_v4 = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
    let local_v6 = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
    let mapped_local = Some(IpAddr::V6(Ipv4Addr::new(127, 0, 0, 2).to_ipv6_mapped()));
    let mut slot = SendSlot::new();
    // (peer, local, v6 socket, family and length of the name, control messages)
    let cases = [
      (v4_peer, local_v4, false, (libc::AF_INET, 16), (libc::SOL_IP, libc::IP_PKTINFO)),
      (v4_peer, mapped_local, true, (libc::AF_INET6, 28), (libc::SOL_IP, libc::IP_PKTINFO)),
      (v6_peer, local_v6, true, (libc::AF_INET6, 28), (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO)),
    ];
    for (idx, (peer, local, v6_socket, (family, namelen), pktinfo)) in cases.into_iter().enumerate()
    {
      prepare_send(&mut slot, &bytes, 1000, peer, local, v6_socket).unwrap();
      let msg = &slot.msg;
      assert_eq!((msg.msg_namelen, msg.msg_iovlen, msg.msg_flags), (namelen, 1, 0), "{idx}");
      // SAFETY: the pointers of the msghdr point into `slot`, and the iovec at `bytes`
      let (name, iov, control) = unsafe {
        let name = core::slice::from_raw_parts(msg.msg_name.cast::<u8>(), namelen as usize);
        let iov = &*msg.msg_iov;
        let control = core::slice::from_raw_parts(msg.msg_control.cast::<u8>(), msg.msg_controllen);
        (name, iov, control)
      };
      assert_eq!(u16::from_ne_bytes([name[0], name[1]]), family as u16, "{idx}");
      assert_eq!(u16::from_be_bytes([name[2], name[3]]), peer.port(), "{idx}");
      let ip = if family == libc::AF_INET { &name[4..8] } else { &name[8..24] };
      let expected = match peer.ip() {
        IpAddr::V4(elem) if family == libc::AF_INET6 => elem.to_ipv6_mapped().octets().to_vec(),
        IpAddr::V4(elem) => elem.octets().to_vec(),
        IpAddr::V6(elem) => elem.octets().to_vec(),
      };
      assert_eq!(ip, &expected[..], "{idx}");
      assert_eq!((iov.iov_base.cast_const().cast::<u8>(), iov.iov_len), (bytes.as_ptr(), 3000));
      let cmsgs = walk_cmsgs(control);
      assert_eq!(cmsgs.len(), 2, "{idx}");
      assert_eq!(cmsgs[0], (libc::SOL_UDP, libc::UDP_SEGMENT, 1000u16.to_ne_bytes().to_vec()));
      assert_eq!((cmsgs[1].0, cmsgs[1].1), pktinfo, "{idx}");
      let addr = if pktinfo.1 == libc::IP_PKTINFO { &cmsgs[1].2[4..8] } else { &cmsgs[1].2[..16] };
      let expected = match local.unwrap() {
        IpAddr::V6(elem) if pktinfo.1 == libc::IP_PKTINFO => {
          elem.to_ipv4_mapped().unwrap().octets().to_vec()
        }
        IpAddr::V4(elem) => elem.octets().to_vec(),
        IpAddr::V6(elem) => elem.octets().to_vec(),
      };
      assert_eq!(addr, &expected[..], "{idx}");
    }
    // One datagram and no local address: no control messages at all
    prepare_send(&mut slot, &bytes[..1000], 1000, v4_peer, None, false).unwrap();
    assert_eq!((slot.msg.msg_controllen, slot.msg.msg_control), (0, core::ptr::null_mut()));
    // An IPv6 peer can not be reached from an IPv4 socket
    assert_eq!(
      prepare_send(&mut slot, &bytes, 1000, v6_peer, None, false),
      Err(libc::EAFNOSUPPORT)
    );
  }

  // A callback that panics while it has a datagram of the inbox still frees its slot: the next
  // pop hands out the next datagram, not the same one again, and the slot takes a new one.
  #[test]
  fn a_panicking_inbox_callback_frees_its_slot() {
    let queue = InboxQueue::new(2).unwrap();
    let meta = DatagramMeta {
      peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
      local: None,
      segment_size: None,
    };
    assert!(queue.push(b"one", meta) && queue.push(b"two", meta));
    let unwound = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
      // SAFETY: this thread is the only consumer
      unsafe { queue.pop(|_, _| panic!("a callback that panics")) }
    }));
    assert!(unwound.is_err());
    let mut next = alloc::vec::Vec::new();
    // SAFETY: this thread is the only consumer
    assert!(unsafe { queue.pop(|bytes, _| next.extend_from_slice(bytes)) });
    assert_eq!(next, b"two");
    assert!(queue.push(b"three", meta));
  }

  // Datagrams pushed from two threads come out whole and in each thread's order; a full queue
  // refuses, and takes again once one is taken.
  #[test]
  fn inbox_queue_carries_datagrams_between_threads() {
    const PER_THREAD: u8 = 20;
    let queue = InboxQueue::new(4).unwrap();
    let meta = |thread: u8| DatagramMeta {
      peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, thread)), 1),
      local: None,
      segment_size: None,
    };
    for idx in 0..4u8 {
      assert!(queue.push(&[idx; 3], meta(9)));
    }
    assert!(!queue.push(&[0; 3], meta(9)));
    let mut taken = 0;
    // SAFETY: this thread is the only consumer
    while unsafe {
      queue.pop(|bytes, _| {
        assert_eq!(bytes, [taken; 3]);
        taken += 1;
      })
    } {}
    assert_eq!(taken, 4);
    std::thread::scope(|scope| {
      for thread in 0..2u8 {
        let queue = &queue;
        let _handle = scope.spawn(move || {
          for seq in 0..PER_THREAD {
            while !queue.push(&[thread, seq], meta(thread)) {
              std::thread::yield_now();
            }
          }
        });
      }
      let mut next = [0u8; 2];
      while next != [PER_THREAD; 2] {
        // SAFETY: this thread is the only consumer
        let popped = unsafe {
          queue.pop(|bytes, from| {
            let thread = bytes[0];
            assert_eq!(from, meta(thread));
            assert_eq!(bytes[1], next[usize::from(thread)]);
            next[usize::from(thread)] += 1;
            bytes[1] = 0xff;
          })
        };
        if !popped {
          std::thread::yield_now();
        }
      }
    });
  }
}
