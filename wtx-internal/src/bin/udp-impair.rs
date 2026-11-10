//! A seeded UDP proxy that drops, reorders, duplicates and delays datagrams between a client and a
//! server on this host. Used by `.scripts/h3-interop.sh`; not a benchmark tool.
//!
//! ```text
//! udp-impair --server-port 8443 [--listen-port 0] [--drop P] [--reorder P] [--dup P]
//!            [--delay-us N] [--seed S] [--rebind N]
//! ```
//!
//! * `--listen-port` (default 0: any) is where clients send; the proxy binds `[::]` (dual-stack)
//!   and prints `listening PORT` on its standard output once it does.
//! * `--server-port` is the server's UDP port on the loopback address of the client's family, so
//!   that a client on `127.0.0.1` reaches the server on `127.0.0.1` and one on `::1` on `::1`.
//! * `--drop`, `--reorder` and `--dup` are probabilities from 0 to 1 per datagram. A reordered
//!   datagram is held back 1 to 5 ms more than the others, a duplicate is a second copy that takes
//!   its own turn. `--delay-us` delays every datagram.
//! * `--seed` makes the decisions repeatable: a flow's decisions depend on the seed and on the
//!   order in which flows appeared, not on timing.
//! * `--rebind N` plays a NAT that rebinds every N datagrams of a flow towards the server: the
//!   flow's socket towards the server is replaced by a new one before the Nth datagram leaves, so
//!   that the server sees the client come from another source port, and, at the second rebinding of an IPv4 flow and after it, from
//!   127.0.0.2 instead of 127.0.0.1 (RFC 9000 section 9.3). What the server sends to an old socket
//!   is lost, as with a NAT whose mapping is gone; a datagram that waits in the queue still leaves
//!   from the socket it was queued for. Each rebinding is reported on the standard error as
//!   `rebind CLIENT LOCAL-ADDRESS`. IPv6 flows only change their port: `::1` is the only loopback
//!   address.
//!
//! Each client (address and port) gets a socket of its own towards the server, so the server sees
//! one stable source per client, and its replies go back to that client from the proxy's port. Both
//! directions are impaired, each with its own sequence of decisions.

#![allow(clippy::disallowed_methods, reason = "a test tool")]
#![allow(clippy::disallowed_types, reason = "a test tool")]

use rimu_ws::sync::Arc;
use std::{
  cmp::Reverse,
  collections::{BTreeMap, BinaryHeap},
  io::ErrorKind,
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
  sync::{
    Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
  },
  time::{Duration, Instant},
};

fn main() -> Result<(), String> {
  let opts = Opts::parse(std::env::args().skip(1))?;
  let listen = Arc::new(
    UdpSocket::bind(("::", opts.listen_port)).map_err(|err| format!("binding [::]: {err}"))?,
  );
  let port = listen.local_addr().map_err(|err| err.to_string())?.port();
  println!("listening {port}");
  let queue = Arc::new(Queue::default());
  {
    let queue = queue.clone();
    let _jh = std::thread::spawn(move || queue.run());
  }
  let mut flows: BTreeMap<SocketAddr, Flow> = BTreeMap::new();
  let mut buffer = vec![0u8; 1 << 16];
  loop {
    let Ok((len, from)) = listen.recv_from(&mut buffer) else {
      continue;
    };
    let Some(datagram) = buffer.get(..len) else {
      continue;
    };
    let client = unmap(from);
    if !flows.contains_key(&client) {
      let index = flows.len() as u64;
      let flow = Flow::new(client, from, index, &opts, &listen, &queue)?;
      let _prev = flows.insert(client, flow);
    }
    if let Some(flow) = flows.get_mut(&client) {
      // A NAT rebinds when the client sends: this datagram is the first from the new mapping, so
      // that the server learns of it before it has to answer (a rebinding while the client is
      // silent would leave the server sending to the old mapping, which a NAT keeps until it
      // expires)
      flow.sent = flow.sent.wrapping_add(1);
      if opts.rebind > 0 && flow.sent % opts.rebind == 0 {
        flow.rebind(&opts, &listen, &queue)?;
      }
      let fate = flow.up.fate();
      send_copies(&fate, datagram, &queue, || To::Server(flow.upstream.clone()));
    }
  }
}

/// A client of the proxy.
struct Flow {
  /// The client.
  client: SocketAddr,
  /// The order in which the flow appeared.
  index: u64,
  /// The socket towards the server is still the flow's: what arrives on it goes to the client.
  live: Arc<AtomicBool>,
  /// The rebindings so far.
  rebinds: u64,
  /// Where the replies go: the client, in the form that the dual-stack socket gave.
  reply_to: SocketAddr,
  /// The datagrams sent towards the server.
  sent: u64,
  /// The decisions for the datagrams towards the server.
  up: Impair,
  /// The socket towards the server.
  upstream: Arc<UdpSocket>,
}

impl Flow {
  fn new(
    client: SocketAddr,
    reply_to: SocketAddr,
    index: u64,
    opts: &Opts,
    listen: &Arc<UdpSocket>,
    queue: &Arc<Queue>,
  ) -> Result<Self, String> {
    let local =
      if client.is_ipv4() { Ipv4Addr::LOCALHOST.into() } else { Ipv6Addr::LOCALHOST.into() };
    let stream = index.wrapping_mul(2).wrapping_add(1);
    let (upstream, live) = open_upstream(local, client, reply_to, stream, opts, listen, queue)?;
    Ok(Self {
      client,
      index,
      live,
      rebinds: 0,
      reply_to,
      sent: 0,
      up: Impair::new(opts.params, opts.seed, index.wrapping_mul(2)),
      upstream,
    })
  }

  /// A NAT rebinding: a new socket towards the server, from another port and, for an IPv4 flow
  /// from its second rebinding on, from 127.0.0.2. The old socket's replies are dropped.
  fn rebind(
    &mut self,
    opts: &Opts,
    listen: &Arc<UdpSocket>,
    queue: &Arc<Queue>,
  ) -> Result<(), String> {
    self.rebinds = self.rebinds.wrapping_add(1);
    let local: IpAddr = if self.client.is_ipv4() {
      if self.rebinds >= 2 {
        Ipv4Addr::new(127, 0, 0, 2).into()
      } else {
        Ipv4Addr::LOCALHOST.into()
      }
    } else {
      Ipv6Addr::LOCALHOST.into()
    };
    // Another sequence of decisions for the replies on the new socket
    let stream =
      self.index.wrapping_mul(2).wrapping_add(1).wrapping_add(self.rebinds.wrapping_mul(1 << 32));
    let (upstream, live) =
      open_upstream(local, self.client, self.reply_to, stream, opts, listen, queue)?;
    self.live.store(false, Ordering::Relaxed);
    self.upstream = upstream;
    self.live = live;
    let from = self.upstream.local_addr().map_err(|err| err.to_string())?;
    eprintln!("rebind {} {from}", self.client);
    Ok(())
  }
}

/// A socket from `local` towards the server, connected, whose replies a thread of its own sends
/// to `reply_to` through `listen`, with the decisions of `stream`, while the returned flag is set.
fn open_upstream(
  local: IpAddr,
  client: SocketAddr,
  reply_to: SocketAddr,
  stream: u64,
  opts: &Opts,
  listen: &Arc<UdpSocket>,
  queue: &Arc<Queue>,
) -> Result<(Arc<UdpSocket>, Arc<AtomicBool>), String> {
  let server = if client.is_ipv4() {
    IpAddr::from(Ipv4Addr::LOCALHOST)
  } else {
    IpAddr::from(Ipv6Addr::LOCALHOST)
  };
  let upstream =
    UdpSocket::bind(SocketAddr::new(local, 0)).map_err(|err| format!("binding {local}: {err}"))?;
  upstream.connect(SocketAddr::new(server, opts.server_port)).map_err(|err| err.to_string())?;
  // So that the thread of a socket that a rebinding replaced ends
  upstream.set_read_timeout(Some(Duration::from_millis(500))).map_err(|err| err.to_string())?;
  let upstream = Arc::new(upstream);
  let live = Arc::new(AtomicBool::new(true));
  {
    let (upstream, live, listen, queue) =
      (upstream.clone(), live.clone(), listen.clone(), queue.clone());
    let mut down = Impair::new(opts.params, opts.seed, stream);
    let _jh = std::thread::spawn(move || {
      let mut buffer = vec![0u8; 1 << 16];
      loop {
        let rslt = upstream.recv(&mut buffer);
        if !live.load(Ordering::Relaxed) {
          // The NAT forgot this mapping: what the server still sends to it is lost
          break;
        }
        let len = match rslt {
          Ok(len) => len,
          Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
          Err(_) => break,
        };
        let Some(datagram) = buffer.get(..len) else {
          continue;
        };
        let fate = down.fate();
        send_copies(&fate, datagram, &queue, || To::Client(listen.clone(), reply_to));
      }
    });
  }
  Ok((upstream, live))
}

/// Sends the copies of `fate` now or when their time comes.
fn send_copies(fate: &Fate, datagram: &[u8], queue: &Queue, to: impl Fn() -> To) {
  for delay in fate.copies.iter().flatten() {
    if *delay == 0 {
      to().send(datagram);
    } else {
      queue.push(Instant::now() + Duration::from_micros(u64::from(*delay)), datagram, to());
    }
  }
}

/// The address of a client with a v4-mapped one made plain, so that a client is one flow whatever
/// the form the dual-stack socket gives.
fn unmap(addr: SocketAddr) -> SocketAddr {
  match addr {
    SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
      Some(ip) => SocketAddr::new(ip.into(), v6.port()),
      None => addr,
    },
    SocketAddr::V4(_) => addr,
  }
}

#[derive(Clone, Copy, Debug)]
struct Opts {
  listen_port: u16,
  params: Params,
  rebind: u64,
  seed: u64,
  server_port: u16,
}

impl Opts {
  fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
    let mut opts =
      Self { listen_port: 0, params: Params::default(), rebind: 0, seed: 1, server_port: 0 };
    while let Some(name) = args.next() {
      let mut value = || args.next().ok_or_else(|| format!("{name} needs a value"));
      match name.as_str() {
        "--listen-port" => opts.listen_port = number(&name, &value()?)?,
        "--server-port" => opts.server_port = number(&name, &value()?)?,
        "--drop" => opts.params.drop = probability(&name, &value()?)?,
        "--reorder" => opts.params.reorder = probability(&name, &value()?)?,
        "--dup" => opts.params.dup = probability(&name, &value()?)?,
        "--delay-us" => opts.params.delay_us = number(&name, &value()?)?,
        "--seed" => opts.seed = number(&name, &value()?)?,
        "--rebind" => opts.rebind = number(&name, &value()?)?,
        _ => return Err(format!("unknown argument {name}")),
      }
    }
    if opts.server_port == 0 {
      return Err("--server-port is required".into());
    }
    Ok(opts)
  }
}

fn number<T: core::str::FromStr>(name: &str, value: &str) -> Result<T, String> {
  value.parse().map_err(|_err| format!("{name}: `{value}` is not a number in range"))
}

fn probability(name: &str, value: &str) -> Result<f64, String> {
  match value.parse::<f64>() {
    Ok(elem) if (0.0..=1.0).contains(&elem) => Ok(elem),
    _ => Err(format!("{name}: `{value}` is not a probability from 0 to 1")),
  }
}

/// What the proxy does to datagrams.
#[derive(Clone, Copy, Debug, Default)]
struct Params {
  delay_us: u32,
  drop: f64,
  dup: f64,
  reorder: f64,
}

/// What happens to one datagram: the delays, in microseconds, of the copies that leave; none if it
/// is dropped, two if it is duplicated.
#[derive(Debug, Eq, PartialEq)]
struct Fate {
  copies: [Option<u32>; 2],
}

/// The decisions for one direction of one flow.
struct Impair {
  params: Params,
  rng: SplitMix64,
}

impl Impair {
  fn new(params: Params, seed: u64, stream: u64) -> Self {
    Self { params, rng: SplitMix64(seed ^ stream.wrapping_mul(0x9E37_79B9_7F4A_7C15)) }
  }

  fn fate(&mut self) -> Fate {
    let Params { delay_us, drop, dup, reorder } = self.params;
    // Six draws per datagram, whatever the probabilities are: a run is a function of the seed
    let dropped = self.rng.unit() < drop;
    let duplicated = self.rng.unit() < dup;
    let first_late = self.rng.unit() < reorder;
    let second_late = self.rng.unit() < reorder;
    let (first_extra, second_extra) = (self.extra(), self.extra());
    if dropped {
      return Fate { copies: [None, None] };
    }
    let late = |cond: bool, extra: u32| delay_us.wrapping_add(if cond { extra } else { 0 });
    Fate {
      copies: [Some(late(first_late, first_extra)), duplicated.then(|| late(second_late, second_extra))],
    }
  }

  /// 1 to 5 ms.
  fn extra(&mut self) -> u32 {
    1000 + u32::try_from(self.rng.next() % 4001).unwrap_or(0)
  }
}

struct SplitMix64(u64);

impl SplitMix64 {
  fn next(&mut self) -> u64 {
    self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = self.0;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
  }

  /// A number in `[0, 1)`.
  fn unit(&mut self) -> f64 {
    (self.next() >> 11) as f64 / (1u64 << 53) as f64
  }
}

/// Where a datagram goes.
enum To {
  /// Back to the client, from the proxy's port.
  Client(Arc<UdpSocket>, SocketAddr),
  /// On to the server.
  Server(Arc<UdpSocket>),
}

impl To {
  fn send(&self, datagram: &[u8]) {
    // A full buffer or a closed peer is a loss, as on a network
    let _rslt = match self {
      Self::Client(socket, addr) => socket.send_to(datagram, addr),
      Self::Server(socket) => socket.send(datagram),
    };
  }
}

/// Datagrams waiting for their time.
#[derive(Default)]
struct Queue {
  cond: Condvar,
  state: Mutex<QueueState>,
}

#[derive(Default)]
struct QueueState {
  heap: BinaryHeap<Reverse<Due>>,
  seq: u64,
}

struct Due {
  at: Instant,
  datagram: Vec<u8>,
  seq: u64,
  to: To,
}

impl Queue {
  fn push(&self, at: Instant, datagram: &[u8], to: To) {
    let Ok(mut state) = self.state.lock() else {
      return;
    };
    let seq = state.seq;
    state.seq = seq.wrapping_add(1);
    state.heap.push(Reverse(Due { at, datagram: datagram.to_vec(), seq, to }));
    self.cond.notify_one();
  }

  fn run(&self) {
    let Ok(mut state) = self.state.lock() else {
      return;
    };
    loop {
      let now = Instant::now();
      match state.heap.peek().map(|el| el.0.at) {
        Some(at) if at <= now => {
          if let Some(Reverse(due)) = state.heap.pop() {
            due.to.send(&due.datagram);
          }
        }
        Some(at) => {
          let Ok((guard, _)) = self.cond.wait_timeout(state, at.saturating_duration_since(now))
          else {
            return;
          };
          state = guard;
        }
        None => {
          let Ok(guard) = self.cond.wait(state) else {
            return;
          };
          state = guard;
        }
      }
    }
  }
}

impl PartialEq for Due {
  fn eq(&self, other: &Self) -> bool {
    (self.at, self.seq) == (other.at, other.seq)
  }
}

impl Eq for Due {}

impl PartialOrd for Due {
  fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for Due {
  fn cmp(&self, other: &Self) -> core::cmp::Ordering {
    (self.at, self.seq).cmp(&(other.at, other.seq))
  }
}

#[cfg(test)]
mod tests {
  use super::{Fate, Impair, Opts, Params, unmap};
  use std::net::SocketAddr;

  fn fates(params: Params, seed: u64, stream: u64, n: usize) -> Vec<Fate> {
    let mut impair = Impair::new(params, seed, stream);
    (0..n).map(|_| impair.fate()).collect()
  }

  fn params(drop: f64, reorder: f64, dup: f64, delay_us: u32) -> Params {
    Params { delay_us, drop, dup, reorder }
  }

  // The same seed gives the same decisions, another seed or another stream other ones.
  #[test]
  fn decisions_follow_the_seed() {
    let p = params(0.3, 0.3, 0.3, 0);
    assert_eq!(fates(p, 7, 0, 500), fates(p, 7, 0, 500));
    assert_ne!(fates(p, 7, 0, 500), fates(p, 8, 0, 500));
    assert_ne!(fates(p, 7, 0, 500), fates(p, 7, 1, 500));
  }

  // Without impairment every datagram leaves once and at once; with drop 1 none does.
  #[test]
  fn plain_and_total_loss() {
    for fate in fates(params(0.0, 0.0, 0.0, 0), 1, 0, 1000) {
      assert_eq!(fate, Fate { copies: [Some(0), None] });
    }
    for fate in fates(params(1.0, 0.0, 0.0, 0), 1, 0, 1000) {
      assert_eq!(fate, Fate { copies: [None, None] });
    }
    for fate in fates(params(0.0, 0.0, 1.0, 0), 1, 0, 1000) {
      assert_eq!(fate, Fate { copies: [Some(0), Some(0)] });
    }
  }

  // The rates come out near the probabilities, and a reordered copy is held 1 to 5 ms past the
  // delay.
  #[test]
  fn rates_match_the_probabilities() {
    let all = fates(params(0.05, 0.05, 0.05, 200), 3, 0, 100_000);
    let dropped = all.iter().filter(|el| el.copies[0].is_none()).count();
    let duplicated = all.iter().filter(|el| el.copies[1].is_some()).count();
    let late = all.iter().filter_map(|el| el.copies[0]).filter(|el| *el > 200).count();
    for (name, got) in [("dropped", dropped), ("duplicated", duplicated)] {
      assert!((4_000..6_000).contains(&got), "{name}: {got}");
    }
    // Of the 95,000 that were not dropped
    assert!((4_000..5_500).contains(&late), "late: {late}");
    for fate in &all {
      for delay in fate.copies.iter().flatten() {
        assert!(*delay == 200 || (1_200..=5_200).contains(delay), "{delay}");
      }
    }
  }

  #[test]
  fn arguments() {
    let args = ["--server-port", "8443", "--drop", "0.05", "--seed", "9", "--delay-us", "100"];
    let opts = Opts::parse(args.iter().map(|el| el.to_string())).unwrap();
    assert_eq!((opts.server_port, opts.listen_port, opts.seed, opts.rebind), (8443, 0, 9, 0));
    let args = ["--server-port", "8443", "--rebind", "400"];
    assert_eq!(Opts::parse(args.iter().map(|el| el.to_string())).unwrap().rebind, 400);
    assert_eq!((opts.params.drop, opts.params.delay_us), (0.05, 100));
    for bad in [&["--drop", "2"][..], &["--server-port", "1", "--nope", "1"], &[]] {
      assert!(Opts::parse(bad.iter().map(|el| el.to_string())).is_err());
    }
  }

  #[test]
  fn mapped_addresses_are_plain() {
    let mapped: SocketAddr = "[::ffff:127.0.0.1]:9".parse().unwrap();
    assert_eq!(unmap(mapped), "127.0.0.1:9".parse().unwrap());
    let v6: SocketAddr = "[::1]:9".parse().unwrap();
    assert_eq!(unmap(v6), v6);
  }
}
