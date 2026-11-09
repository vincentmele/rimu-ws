//! Path MTU discovery (RFC 9000 section 14.3, RFC 8899): datagrams start at 1200 bytes; once the
//! handshake is confirmed one probe goes at the largest size that the peer accepts and the path
//! can take, and its acknowledgment makes that the size of every datagram. A lost probe is tried
//! again smaller, at 1400 and then 1280 bytes, after which the size stays where it is.
//!
//! A probe is a 1-RTT packet of a PING and PADDING, sent apart, with the don't-fragment bit of the
//! socket of the endpoint. It is ack-eliciting but does not count towards the bytes in flight, and
//! its loss is no congestion signal (ruling T9-e).

use core::net::{IpAddr, SocketAddr};

/// The largest UDP payload of an IPv4 path of 1500 bytes, IPv4-mapped IPv6 peers included.
pub(crate) const PATH_CEILING_V4: usize = 1472;
/// The largest UDP payload of an IPv6 path of 1500 bytes.
pub(crate) const PATH_CEILING_V6: usize = 1452;
/// The size of every datagram before discovery (RFC 9000 section 14).
#[cfg(test)]
pub(crate) const MIN_MTU: usize = 1200;

// The sizes that are tried after a lost probe, from the largest
const FALLBACKS: [usize; 2] = [1400, 1280];

/// See the [module documentation](self).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Pmtud {
  state: State,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
  // Before the handshake is confirmed
  Idle,
  // A probe of this size is to be sent
  Due(u16),
  // The probe went with this packet number
  Sent { pn: u64, size: u16 },
  // Nothing more is tried
  Done,
}

impl Pmtud {
  /// Before the handshake is confirmed.
  #[inline]
  pub(crate) const fn new() -> Self {
    Self { state: State::Idle }
  }

  /// The handshake is confirmed: probes start at the smaller of `peer_max_udp_payload_size` and
  /// the ceiling of the path to `peer`, if that is above `current`.
  #[inline]
  pub(crate) fn start(
    &mut self,
    peer_max_udp_payload_size: u64,
    peer: &SocketAddr,
    current: usize,
  ) {
    if self.state != State::Idle {
      return;
    }
    let peer_max = usize::try_from(peer_max_udp_payload_size).unwrap_or(usize::MAX);
    self.state = due(peer_max.min(path_ceiling(peer)), current);
  }

  /// The size of the probe that is due, if one is.
  #[inline]
  pub(crate) const fn probe_due(&self) -> Option<usize> {
    match self.state {
      State::Due(size) => Some(size as usize),
      State::Done | State::Idle | State::Sent { .. } => None,
    }
  }

  /// The probe that was due went with the packet number `pn`.
  #[inline]
  pub(crate) fn on_probe_sent(&mut self, pn: u64) {
    if let State::Due(size) = self.state {
      self.state = State::Sent { pn, size };
    }
  }

  /// The packet `pn` was acknowledged: the size of the datagrams from now on, if it was the probe.
  #[inline]
  pub(crate) fn on_probe_acked(&mut self, pn: u64) -> Option<usize> {
    match self.state {
      State::Sent { pn: probe, size } if probe == pn => {
        self.state = State::Done;
        Some(usize::from(size))
      }
      _ => None,
    }
  }

  /// The packet `pn` was lost: a smaller probe is due next if it was the probe and one is left
  /// above `current`.
  #[inline]
  pub(crate) fn on_probe_lost(&mut self, pn: u64, current: usize) {
    if let State::Sent { pn: probe, size } = self.state
      && probe == pn
    {
      let next = FALLBACKS.into_iter().find(|el| *el < usize::from(size)).unwrap_or(0);
      self.state = due(next, current);
    }
  }
}

// A probe of `size` bytes if it is above `current`, nothing more otherwise
fn due(size: usize, current: usize) -> State {
  match u16::try_from(size) {
    Ok(elem) if size > current => State::Due(elem),
    _ => State::Done,
  }
}

/// The largest UDP payload of the path to `peer`, by its address family.
#[inline]
pub(crate) fn path_ceiling(peer: &SocketAddr) -> usize {
  match peer.ip() {
    IpAddr::V6(elem) if elem.to_ipv4_mapped().is_none() => PATH_CEILING_V6,
    IpAddr::V4(_) | IpAddr::V6(_) => PATH_CEILING_V4,
  }
}

#[cfg(test)]
mod tests {
  use crate::{
    quic::{
      ConnState,
      pmtud::{MIN_MTU, Pmtud},
      testing::{Behavior, Impairment, Link, LinkOpts, TestApp, run_lossy_requests},
    },
    sync::AtomicU64,
  };
  use alloc::vec::Vec;
  use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::Ordering,
  };

  const V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
  const V6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1);
  const MAPPED: SocketAddr =
    SocketAddr::new(IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped()), 1);

  // The sizes that the probes take, each one lost, after a start with `peer_max` towards `peer`
  fn sizes_tried(peer_max: u64, peer: &SocketAddr) -> Vec<usize> {
    let mut pmtud = Pmtud::new();
    assert_eq!(pmtud.probe_due(), None);
    pmtud.start(peer_max, peer, MIN_MTU);
    let mut rslt = Vec::new();
    let mut pn = 10;
    while let Some(size) = pmtud.probe_due() {
      rslt.push(size);
      pmtud.on_probe_sent(pn);
      // Another packet changes nothing
      pmtud.on_probe_lost(pn + 1, MIN_MTU);
      assert_eq!(pmtud.probe_due(), None);
      pmtud.on_probe_lost(pn, MIN_MTU);
      pn += 5;
      assert!(rslt.len() < 10);
    }
    rslt
  }

  // The first probe is at the smaller of the limit of the peer and of the path, the next ones at
  // 1400 and 1280 bytes when they are smaller; an acknowledged probe gives its size.
  #[test]
  fn probes_start_at_the_ceiling_and_step_down() {
    assert_eq!(sizes_tried(1472, &V4), [1472, 1400, 1280]);
    assert_eq!(sizes_tried(65527, &MAPPED), [1472, 1400, 1280]);
    assert_eq!(sizes_tried(65527, &V6), [1452, 1400, 1280]);
    assert_eq!(sizes_tried(1300, &V4), [1300, 1280]);
    assert_eq!(sizes_tried(1200, &V4), []);
    let mut pmtud = Pmtud::new();
    pmtud.start(1472, &V4, MIN_MTU);
    pmtud.on_probe_sent(3);
    assert_eq!(pmtud.on_probe_acked(2), None);
    assert_eq!(pmtud.on_probe_acked(3), Some(1472));
    assert_eq!(pmtud.probe_due(), None);
    assert_eq!(pmtud.on_probe_acked(3), None);
  }

  // The largest datagram that went from the server to the client
  static LARGEST: AtomicU64 = AtomicU64::new(0);

  fn largest_to_client(to_server: bool, datagram: &[u8], limit: usize) -> bool {
    if to_server {
      return false;
    }
    let dropped = datagram.len() > limit;
    if !dropped {
      let _ = LARGEST.fetch_max(datagram.len() as u64, Ordering::Relaxed);
    }
    dropped
  }

  // After the handshake the server probes at 1472 bytes, the ceiling of an IPv4 path and the
  // limit of the client, and once the probe is acknowledged its datagrams have 1472 bytes. On a
  // path that drops datagrams above 1400 bytes the probe is lost and the next one, at 1400 bytes,
  // is adopted; on one that drops everything above 1200 bytes the size stays 1200 after the
  // probes at 1472, 1400 and 1280 bytes, whose losses do not shrink the congestion window.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn pmtu_probe_adopts_1472_then_falls_back_on_loss() {
    let filters: [(fn(bool, &[u8]) -> bool, usize, u64); 3] = [
      (|to_server, datagram| largest_to_client(to_server, datagram, 1472), 1472, 1),
      (|to_server, datagram| largest_to_client(to_server, datagram, 1400), 1400, 2),
      (|to_server, datagram| largest_to_client(to_server, datagram, 1200), 1200, 3),
    ];
    for (filter, expected, probes) in filters {
      LARGEST.store(0, Ordering::Relaxed);
      let mut opts = LinkOpts::new(None);
      opts.server_app = TestApp::new(Behavior::Echo);
      let mut link = Link::new(&opts);
      link.impair(Impairment::delay(5_000));
      link.filter = Some(filter);
      // Before the handshake is confirmed every datagram has at most 1200 bytes
      let (handshake, _) = (link.server.conn.max_datagram(), ());
      assert_eq!(handshake, MIN_MTU);
      let request: Vec<u8> = (0..20_000u32).map(|el| el as u8).collect();
      let requests = [request.clone(), request.clone(), request.clone(), request];
      let cwnd = link.server.conn.cwnd();
      let run = run_lossy_requests(&mut link, &requests, 1, 30_000_000);
      assert_eq!(run.responses, requests);
      assert_eq!(link.server.conn.state(), ConnState::Confirmed);
      assert_eq!(link.server.conn.max_datagram(), expected, "{expected}");
      assert_eq!(link.server.conn.stats().mtu_probes, probes, "{expected}");
      assert_eq!(LARGEST.load(Ordering::Relaxed), expected as u64);
      // No loss of a probe was a congestion event (review J10)
      assert_eq!(link.server.conn.ssthresh(), usize::MAX, "{expected}");
      assert!(link.server.conn.cwnd() >= cwnd);
      // The client probed the other way, where nothing is dropped
      assert_eq!(link.client.conn.max_datagram(), 1472);
    }
  }
}
