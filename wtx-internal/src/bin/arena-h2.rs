//! HttpArena HTTP/2 and HTTP/3 server: `/baseline2`, `/json/{count}` and `/static/{*file}` on h2c
//! (8082) and h2 over TLS (8443), served by the HTTP/2 server framework on the io_uring executor, and
//! on h3 (UDP 8443, dual-stack), served by the HTTP/3 server framework. Used by `.scripts/h2-bench.sh`
//! and `.scripts/h3-bench.sh`.
//!
//! Environment: `CERT_DIR` (default `/certs`, with `server.crt` and `server.key`; without them
//! only h2c is served), `DATASET_PATH` (default `/data/dataset.json`), `STATIC_DIR` (default
//! `/data/static`), `ARENA_PARAMS` (`permissive` for `HttpRecvParams::with_permissive_params`, as
//! upstream's wtx-http2 entry does; otherwise the library defaults) and the `ARENA_H3_*` switches
//! of the table below. The h3 limits are the defaults of `H3Params`, as in the HttpArena entry
//! (`ARENA_H3_QPACK` changes the QPACK settings only);
//! `ARENA_PARAMS` is for h1 and h2 only.
//!
//! # The h3 switches (ruling T16-b)
//!
//! Each selects, at start, one setting of the h3 server, so that one build measures the A/Bs of
//! tasks 16 to 19 (the EC2 variant phase of `/mnt/nvme1tb/claude-tmp/aws-h3`). Unset, each is
//! the library default, but for `ARENA_H3_GRO`. A value outside the table stops the program; the server prints the
//! settings it runs with on one line starting with `arena-h2: h3 knobs`.
//!
//! | variable | values | default | maps to |
//! |---|---|---|---|
//! | `ARENA_H3_HEADERS` | `min`, `full` | `min` | `min`: `content-type` only, no middleware (like cnetmod and zix, not RFC 9110-compliant; decision Q2); `full`: `Http3ServerFramework::set_rfc9110_headers(true)` and the `server` middleware, as on h2 |
//! | `ARENA_H3_DATA` | `reuse`, `fresh` | `reuse` | `Http3ServerFramework::set_reuse_data` (`reuse`: the opt-in, the library default is `fresh`; the data, an `Arc` of the dataset, is never changed by the handlers) |
//! | `ARENA_H3_GRO` | `0`, `1` | `1` | `UdpParams::gro` (on: receive buffers of 64 KiB). On here although the library default is off (ruling T16-h: the ring of a socket, 256 x 65,536 B = exactly 16 MiB, equals a worker's 16 MiB pool budget by itself, leaving nothing for the other pools, 768 MiB over 48 workers; the benchmark has the memory) |
//! | `ARENA_H3_RECV_BUFFERS` | 1 to 32768 | 256 | `UdpParams::recv_buffers` |
//! | `ARENA_H3_TX_ARENA` | bytes, 65536 or more | 768000 | `UdpParams::tx_arena_bytes` |
//! | `ARENA_H3_RCVBUF` | bytes | 4194304 | `UdpParams::rcvbuf` (capped by `net.core.rmem_max`) |
//! | `ARENA_H3_SNDBUF` | bytes | 4194304 | `UdpParams::sndbuf` (capped by `net.core.wmem_max`) |
//! | `ARENA_H3_TRAIN` | 1 to 64 | 64 | `UdpParams::max_train_segments` (datagrams of one GSO send) |
//! | `ARENA_H3_FLUSH_ORDER` | `arrival`, `slot` | `arrival` | `QuicParams::set_flush_in_slot_order` |
//! | `ARENA_H3_STEERING` | `cid`, `kernel` | `cid` | `QuicParams::set_cid_steering` (`kernel`: the kernel's hash, balance off) |
//! | `ARENA_H3_BALANCE` | `0`, `1` | `1` | `QuicParams::set_balance` (with `cid` steering only) |
//! | `ARENA_H3_PIN` | `0`, `1` | `1` | `Http3ServerFramework::set_pin_workers` |
//! | `ARENA_H3_MAX_IN_FLIGHT` | bytes, 16384 or more | 262144 | `QuicParams::set_max_in_flight` |
//! | `ARENA_H3_PACING` | `0`, `1` | `1` | `QuicParams::set_pacing` |
//! | `ARENA_H3_PMTU_PROBE` | `now`, `rtt` | `now` | `QuicParams::set_pmtu_probe_after_rtt` (`rtt`: the first probe one smoothed RTT after the handshake) |
//! | `ARENA_H3_BODIES` | `complete`, `round-robin` | `complete` | `QuicParams::set_bodies_round_robin` (bodies by reference: one to its end, or a frame each in turn) |
//! | `ARENA_H3_HP` | `ring`, `batched` | `ring` | `QuicParams::set_batched_header_protection` (`batched`: the masks of the 1-RTT packets of a flush eight at a time on AES-NI, task 18; ChaCha20 and CPUs without AES-NI stay one at a time; measured: no win, `ring` stays, pass3.md) |
//! | `ARENA_H3_QPACK` | `0`, `4096` | `0` | `H3Params::qpack_max_table_capacity` and `qpack_blocked_streams`: `0` none (the library default), `4096` a dynamic table of 4096 bytes with 100 blocked streams (task 18, ruling T18-c; measured: a loss on baseline-h3, `0` stays, pass3.md) |
//! | `ARENA_H3_ZC` | `0`, `1` | `0` | `UdpParams::zerocopy` (`1`: trains sent with `IORING_OP_SENDMSG_ZC`, each kept until its notification; a kernel that refuses falls back to copying, counted; task 19, ruling T19-b) |
//! | `ARENA_H3_PACING_BURST` | 1 to 64 | 64 | `QuicParams::set_pacing_burst` (datagrams the pacer lets go at once; task 19, ruling T19-c) |
//! | `ARENA_H3_REPEAT_ACK` | `0`, `1` | `1` | `QuicParams::set_repeat_ack` (`1`: a flush with stream data repeats an acknowledgment the client may lack; task 19, ruling T19-d) |
//!
//! With TLS on, SIGUSR1 prints the sums of the counters of the h3 workers on one line starting with
//! `h3-stats` (what `h3-bench.sh` reads), and SIGINT or SIGTERM prints them with one line per
//! worker and exits.

use core::ops::ControlFlow;
use rimu_ws::{
  collections::{ArrayVectorU8, VectorUsize},
  executor::{UringExecutor, UringParams, UringRuntime},
  http::{
    Header, HttpRecvParams, KnownHeaderName, MsgBufferString, MsgDataMut as _, Request, Response,
    StatusCode,
    http2_server_framework::{
      Get, Http2ServerFramework, HttpRouter, JsonReply, Middleware, Path, State, StaticFiles,
      VerbatimParams, get,
    },
    http3_server_framework::{Http3ServerFramework, Http3Stats, Http3WorkerStats},
  },
  misc::JsonWriter,
  rng::{ChaCha20, CryptoSeedableRng as _},
  sync::Arc,
  tls::TlsConfig,
};

macro_rules! paths {
  ($static_root:expr) => {
    rimu_ws::paths!(
      ("/baseline2", get(endpoint_baseline2)),
      ("/json/{count}", get(endpoint_json)),
      ("/static/{*file}", Get(StaticFiles::new($static_root)?))
    )
  };
}

macro_rules! router {
  ($static_root:expr) => {
    HttpRouter::new(paths!($static_root), ServerHeader)
  };
  ($static_root:expr, no_middleware) => {
    HttpRouter::paths(paths!($static_root))
  };
}

fn static_dir() -> String {
  std::env::var("STATIC_DIR").unwrap_or_else(|_| "/data/static".into())
}

fn main() -> rimu_ws::Result<()> {
  let dataset = load_dataset();
  let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "/certs".into());
  let tls_enabled = std::path::Path::new(&cert_dir).join("server.crt").exists();
  // Before any thread exists, so that every thread inherits the mask
  let signals = if tls_enabled { Some(stats_signals::block()) } else { None };
  let (tls, h3) = if tls_enabled {
    let data = dataset.clone();
    let cert = std::fs::read(format!("{cert_dir}/server.crt"))?;
    let key = std::fs::read(format!("{cert_dir}/server.key"))?;
    let (h3_stats, h3) = spawn_h3(&cert, key.clone(), ConnAux { dataset: dataset.clone() })?;
    if let Some(elem) = signals {
      stats_signals::spawn_reporter(elem, h3_stats);
    }
    let tls = std::thread::spawn(move || -> rimu_ws::Result<()> {
      let tls_config = TlsConfig::from_keys_pem(&cert, key.as_slice())?;
      Http2ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new(
        UringExecutor::default(),
        ChaCha20::from_std_random()?,
        tls_config,
      )?
      .set_data(ConnAux { dataset: data })
      .set_error_cb(error_cb)
      .set_http_recv_params(recv_params())
      .set_local_runtime_cb(runtime)
      .run_in_threads("0.0.0.0:8443", router!(static_dir())?)
    });
    (Some(tls), Some(h3))
  } else {
    eprintln!("arena-h2: no {cert_dir}/server.crt, TLS on 8443 disabled");
    (None, None)
  };
  Http2ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new(
    UringExecutor::default(),
    ChaCha20::from_std_random()?,
    TlsConfig::plaintext(),
  )?
  .set_data(ConnAux { dataset })
  .set_error_cb(error_cb)
  .set_http_recv_params(recv_params())
  .set_local_runtime_cb(runtime)
  .run_in_threads("0.0.0.0:8082", router!(static_dir())?)?;
  if let Some(elem) = tls {
    elem.join().map_err(|_| std::io::Error::other("TLS thread panicked"))??;
  }
  if let Some(elem) = h3 {
    elem.join().map_err(|_| std::io::Error::other("h3 thread panicked"))??;
  }
  Ok(())
}

/// Starts the HTTP/3 server on UDP 8443 (`[::]`, dual-stack) on a thread of its own. The framework
/// is built here, so that its counters can be read from the first moment.
fn spawn_h3(
  cert: &[u8],
  key: Vec<u8>,
  data: ConnAux,
) -> rimu_ws::Result<(Http3Stats, std::thread::JoinHandle<rimu_ws::Result<()>>)> {
  let knobs = knobs::H3Knobs::from_vars(|name| std::env::var(name).ok())
    .map_err(|err| rimu_ws::Error::from(std::io::Error::other(err)))?;
  eprintln!("arena-h2: h3 knobs {}", knobs.line());
  let run = H3Run {
    addr: "[::]:8443".into(),
    knobs,
    local_runtimes: None,
    shutdown: None,
    static_root: static_dir(),
  };
  spawn_h3_with(cert, key, data, run, runtime_h3)
}

/// What the h3 server runs with, which the program takes from the environment and tests choose.
struct H3Run {
  /// Where the workers bind.
  addr: String,
  /// The `ARENA_H3_*` switches.
  knobs: knobs::H3Knobs,
  /// The workers; one per CPU if `None`.
  local_runtimes: Option<core::num::NonZeroUsize>,
  /// The signal that ends the server and the time it lets connections drain, if any.
  shutdown: Option<(rimu_ws::http::ShutdownSignal, core::time::Duration)>,
  /// The directory of `/static`.
  static_root: String,
}

/// [`spawn_h3`] with the choices of `run`, and the runtime of each worker built by `rc`.
fn spawn_h3_with<RC>(
  cert: &[u8],
  key: Vec<u8>,
  data: ConnAux,
  run: H3Run,
  rc: RC,
) -> rimu_ws::Result<(Http3Stats, std::thread::JoinHandle<rimu_ws::Result<()>>)>
where
  RC: Clone + Fn() -> rimu_ws::Result<UringRuntime> + Send + 'static,
{
  let H3Run { addr, knobs, local_runtimes, shutdown, static_root } = run;
  let min_headers = knobs.headers == knobs::Headers::Min;
  let mut framework = Http3ServerFramework::<(), fn(rimu_ws::Error), UringExecutor, _, _, _>::new(
    UringExecutor::default(),
    ChaCha20::from_std_random()?,
    TlsConfig::from_keys_pem(cert, key.as_slice())?,
  )?
  .set_data(data)
  .set_error_cb(error_cb)
  .set_reuse_data(knobs.data == knobs::Data::Reuse)
  .set_local_runtime_cb(rc)
  .set_local_runtimes(local_runtimes)
  .set_h3_params(knobs.h3)
  .set_pin_workers(knobs.pin_workers)
  .set_quic_params(knobs.quic)
  .set_udp_params(knobs.udp);
  if let Some((signal, drain)) = shutdown {
    framework = framework.set_shutdown(signal, drain);
  }
  let stats = framework.stats();
  let handle = std::thread::spawn(move || -> rimu_ws::Result<()> {
    let rslt = if min_headers {
      framework.run_in_threads(&addr, router!(static_root.as_str(), no_middleware)?)
    } else {
      framework.set_rfc9110_headers(true).run_in_threads(&addr, router!(static_root.as_str())?)
    };
    if let Err(err) = &rslt {
      eprintln!("arena-h2: the h3 server ended: {err}");
    }
    rslt
  });
  Ok((stats, handle))
}

fn error_cb(err: rimu_ws::Error) {
  if std::env::var("ARENA_LOG_ERRORS").is_ok() {
    eprintln!("arena-h2: {err}");
  }
}

fn recv_params() -> HttpRecvParams {
  if std::env::var("ARENA_PARAMS").is_ok_and(|v| v == "permissive") {
    HttpRecvParams::with_permissive_params()
  } else {
    HttpRecvParams::with_default_params()
  }
}

fn runtime() -> rimu_ws::Result<UringRuntime> {
  UringRuntime::with_params(UringParams::default())
}

/// The runtime of an h3 worker. Its UDP socket has a receive ring of its own, so the ring of TCP
/// receives that every runtime makes (512 buffers of 4 KiB, 2 MiB) is never used: it is made small.
fn runtime_h3() -> rimu_ws::Result<UringRuntime> {
  UringRuntime::with_params(UringParams::default().set_recv_buffers(4, 4096))
}

/// The `ARENA_H3_*` switches: see the table of the program's documentation.
mod knobs {
  use rimu_ws::{executor::UdpParams, http3::H3Params, quic::QuicParams};

  /// The response fields of h3.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(super) enum Headers {
    /// `content-type` only.
    Min,
    /// The RFC 9110 fields and the `server` middleware.
    Full,
  }

  /// The data of the requests.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(super) enum Data {
    /// The clones that requests used go to the next ones.
    Reuse,
    /// A clone per request.
    Fresh,
  }

  /// What the switches select.
  #[derive(Clone, Copy, Debug)]
  pub(super) struct H3Knobs {
    pub(super) data: Data,
    pub(super) h3: H3Params,
    pub(super) headers: Headers,
    pub(super) pin_workers: bool,
    pub(super) quic: QuicParams,
    pub(super) udp: UdpParams,
  }

  impl H3Knobs {
    /// The switches, read with `var`.
    pub(super) fn from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
      let (mut quic, mut udp) = (QuicParams::default(), UdpParams::new());
      let headers = [("min", Headers::Min), ("full", Headers::Full)];
      let headers = one_of(&var, "ARENA_H3_HEADERS", &headers)?.unwrap_or(Headers::Min);
      let data = [("reuse", Data::Reuse), ("fresh", Data::Fresh)];
      let data = one_of(&var, "ARENA_H3_DATA", &data)?.unwrap_or(Data::Reuse);
      // The benchmark path: on unless asked off, unlike the library (ruling T16-h)
      udp.gro = flag(&var, "ARENA_H3_GRO")?.unwrap_or(true);
      if let Some(elem) = number(&var, "ARENA_H3_RECV_BUFFERS", 1, 32_768)? {
        udp.recv_buffers = u16::try_from(elem).map_err(|err| err.to_string())?;
      }
      if let Some(elem) = number(&var, "ARENA_H3_TX_ARENA", 65_536, 1 << 30)? {
        udp.tx_arena_bytes = usize::try_from(elem).map_err(|err| err.to_string())?;
      }
      if let Some(elem) = number(&var, "ARENA_H3_RCVBUF", 4096, 1 << 30)? {
        udp.rcvbuf = usize::try_from(elem).map_err(|err| err.to_string())?;
      }
      if let Some(elem) = number(&var, "ARENA_H3_SNDBUF", 4096, 1 << 30)? {
        udp.sndbuf = usize::try_from(elem).map_err(|err| err.to_string())?;
      }
      if let Some(elem) = number(&var, "ARENA_H3_TRAIN", 1, 64)? {
        udp.max_train_segments = u16::try_from(elem).map_err(|err| err.to_string())?;
      }
      let order = [("arrival", false), ("slot", true)];
      if let Some(elem) = one_of(&var, "ARENA_H3_FLUSH_ORDER", &order)? {
        quic = quic.set_flush_in_slot_order(elem);
      }
      if let Some(elem) = flag(&var, "ARENA_H3_BALANCE")? {
        quic = quic.set_balance(elem);
      }
      if let Some(elem) = one_of(&var, "ARENA_H3_STEERING", &[("cid", true), ("kernel", false)])? {
        quic = quic.set_cid_steering(elem);
        if !elem {
          quic = quic.set_balance(false);
        }
      }
      let pin_workers = flag(&var, "ARENA_H3_PIN")?.unwrap_or(true);
      if let Some(elem) = number(&var, "ARENA_H3_MAX_IN_FLIGHT", 16_384, 1 << 30)? {
        quic = quic.set_max_in_flight(usize::try_from(elem).map_err(|err| err.to_string())?);
      }
      if let Some(elem) = flag(&var, "ARENA_H3_PACING")? {
        quic = quic.set_pacing(elem);
      }
      if let Some(elem) = one_of(&var, "ARENA_H3_PMTU_PROBE", &[("now", false), ("rtt", true)])? {
        quic = quic.set_pmtu_probe_after_rtt(elem);
      }
      let bodies = [("complete", false), ("round-robin", true)];
      if let Some(elem) = one_of(&var, "ARENA_H3_BODIES", &bodies)? {
        quic = quic.set_bodies_round_robin(elem);
      }
      if let Some(elem) = one_of(&var, "ARENA_H3_HP", &[("ring", false), ("batched", true)])? {
        quic = quic.set_batched_header_protection(elem);
      }
      // Task 19 (rulings T19-b to T19-d)
      if let Some(elem) = flag(&var, "ARENA_H3_ZC")? {
        udp.zerocopy = elem;
      }
      if let Some(elem) = number(&var, "ARENA_H3_PACING_BURST", 1, 64)? {
        quic = quic.set_pacing_burst(u16::try_from(elem).map_err(|err| err.to_string())?);
      }
      if let Some(elem) = flag(&var, "ARENA_H3_REPEAT_ACK")? {
        quic = quic.set_repeat_ack(elem);
      }
      let mut h3 = H3Params::default();
      if let Some(elem) = one_of(&var, "ARENA_H3_QPACK", &[("0", false), ("4096", true)])? {
        // Ruling T18-c: the dynamic table that task 18 measures, or none
        (h3.qpack_max_table_capacity, h3.qpack_blocked_streams) =
          if elem { (4096, 100) } else { (0, 0) };
      }
      Ok(Self { data, h3, headers, pin_workers, quic, udp })
    }

    /// The settings, `name=value` each, for the log of the server.
    pub(super) fn line(&self) -> String {
      let (quic, udp) = (&self.quic, &self.udp);
      let pick = |cond: bool, yes: &'static str, no: &'static str| if cond { yes } else { no };
      format!(
        "headers={} data={} gro={} recv_buffers={} tx_arena={} rcvbuf={} sndbuf={} train={} \
         flush_order={} steering={} balance={} pin={} max_in_flight={} pacing={} pmtu_probe={} \
         bodies={} hp={} qpack={} zc={} pacing_burst={} repeat_ack={}",
        pick(self.headers == Headers::Min, "min", "full"),
        pick(self.data == Data::Reuse, "reuse", "fresh"),
        u8::from(udp.gro),
        udp.recv_buffers,
        udp.tx_arena_bytes,
        udp.rcvbuf,
        udp.sndbuf,
        udp.max_train_segments,
        pick(quic.flush_in_slot_order(), "slot", "arrival"),
        pick(quic.cid_steering(), "cid", "kernel"),
        u8::from(quic.balance()),
        u8::from(self.pin_workers),
        quic.max_in_flight(),
        u8::from(quic.pacing()),
        pick(quic.pmtu_probe_after_rtt(), "rtt", "now"),
        pick(quic.bodies_round_robin(), "round-robin", "complete"),
        pick(quic.batched_header_protection(), "batched", "ring"),
        self.h3.qpack_max_table_capacity,
        u8::from(udp.zerocopy),
        quic.pacing_burst(),
        u8::from(quic.repeat_ack()),
      )
    }
  }

  fn one_of<T: Copy>(
    var: &impl Fn(&str) -> Option<String>,
    name: &str,
    values: &[(&str, T)],
  ) -> Result<Option<T>, String> {
    let Some(value) = var(name) else {
      return Ok(None);
    };
    match values.iter().find(|el| el.0 == value) {
      Some(elem) => Ok(Some(elem.1)),
      None => {
        let names: Vec<&str> = values.iter().map(|el| el.0).collect();
        Err(format!("{name} must be one of {names:?}, not `{value}`"))
      }
    }
  }

  fn flag(var: &impl Fn(&str) -> Option<String>, name: &str) -> Result<Option<bool>, String> {
    one_of(var, name, &[("0", false), ("1", true)])
  }

  fn number(
    var: &impl Fn(&str) -> Option<String>,
    name: &str,
    min: u64,
    max: u64,
  ) -> Result<Option<u64>, String> {
    let Some(value) = var(name) else {
      return Ok(None);
    };
    match value.parse::<u64>() {
      Ok(elem) if (min..=max).contains(&elem) => Ok(Some(elem)),
      _ => Err(format!("{name} must be a number from {min} to {max}, not `{value}`")),
    }
  }
}

/// SIGUSR1 prints the counters of the h3 workers; SIGINT and SIGTERM print them and exit.
///
/// The signals are blocked in every thread (the mask is inherited, so it is set before the first
/// thread starts) and one thread takes them with `sigwait`: no handler runs, and no worker's
/// `io_uring_enter` is interrupted.
mod stats_signals {
  use super::{Http3Stats, Http3WorkerStats};

  const REPORTED: [libc::c_int; 3] = [libc::SIGUSR1, libc::SIGINT, libc::SIGTERM];

  pub(super) struct Blocked(libc::sigset_t);

  pub(super) fn block() -> Blocked {
    // SAFETY: `set` is a plain C structure that `sigemptyset` initializes before any other use;
    // the arguments are valid for the calls and `pthread_sigmask` has no other precondition.
    unsafe {
      let mut set = core::mem::zeroed::<libc::sigset_t>();
      libc::sigemptyset(&mut set);
      for sig in REPORTED {
        libc::sigaddset(&mut set, sig);
      }
      // `pthread_sigmask` returns the error number, not -1 with `errno`; a mask that was not set
      // would leave the signals to their default action (SIGUSR1 kills the process)
      let rslt = libc::pthread_sigmask(libc::SIG_BLOCK, &set, core::ptr::null_mut());
      assert_eq!(rslt, 0, "arena-h2: pthread_sigmask failed with error {rslt}");
      Blocked(set)
    }
  }

  pub(super) fn spawn_reporter(blocked: Blocked, stats: Http3Stats) {
    let _jh = std::thread::spawn(move || {
      loop {
        let mut sig: libc::c_int = 0;
        // SAFETY: `blocked.0` was initialized by `sigemptyset`; `sig` is a valid `c_int`. The
        // set is blocked in this thread, which inherited the mask of `block` (called before the
        // first thread started): `sigwait` requires its signals to be blocked, or a signal could
        // run its action instead of being taken here.
        let rslt = unsafe { libc::sigwait(&blocked.0, &mut sig) };
        if rslt != 0 {
          continue;
        }
        let exits = sig != libc::SIGUSR1;
        let workers = stats.workers();
        let mut sum = Counters::default();
        for worker in &workers {
          sum.add(&Counters::of(worker));
        }
        eprintln!("h3-stats workers={} {}", workers.len(), sum.line());
        if exits {
          for (idx, worker) in workers.iter().enumerate() {
            eprintln!("h3-worker {idx} {}", Counters::of(worker).line());
          }
          std::process::exit(0);
        }
      }
    });
  }

  struct Counters([u64; 33]);

  // Arrays of more than 32 elements have no `Default`
  impl Default for Counters {
    fn default() -> Self {
      Self([0; 33])
    }
  }

  impl Counters {
    // The first twelve as before task 16, then the counters of spec section 2.1 (ruling T16-c),
    // then the QPACK sections decoded and those the decode memo replayed (ruling T18-c), then the
    // transfer counters of task 19 (ruling T19-a)
    const NAMES: [&'static str; 33] = [
      "conns",
      "requests",
      "datagrams_in",
      "datagrams_out",
      "packets_out",
      "ack_only_out",
      "forwarded",
      "forward_dropped",
      "retries",
      "stateless_resets",
      "udp_send_errors",
      "handler_panics",
      "fins_out",
      "fin_flushes",
      "fin_flushes_acked",
      "streams_blocked_in",
      "data_blocked_in",
      "stream_data_blocked_in",
      "packets_lost",
      "pto_probes",
      "frames_resent",
      "qpack_sections",
      "qpack_memo_hits",
      "bytes_out",
      "stream_bytes_out",
      "stream_bytes_copied",
      "trains_out",
      "fin_flushes_ack_owed",
      "pacer_holds",
      "zc_sends",
      "zc_copied",
      "zc_fallbacks",
      "fin_flushes_owed_and_acked",
    ];

    fn of(worker: &Http3WorkerStats) -> Self {
      Self([
        worker.conns,
        worker.requests,
        worker.datagrams_in,
        worker.datagrams_out,
        worker.packets_out,
        worker.ack_only_out,
        worker.forwarded,
        worker.forward_dropped,
        worker.retries,
        worker.stateless_resets,
        worker.udp_send_errors,
        worker.handler_panics,
        worker.fins_out,
        worker.fin_flushes,
        worker.fin_flushes_acked,
        worker.streams_blocked_in,
        worker.data_blocked_in,
        worker.stream_data_blocked_in,
        worker.packets_lost,
        worker.pto_probes,
        worker.frames_resent,
        worker.qpack_sections,
        worker.qpack_memo_hits,
        worker.bytes_out,
        worker.stream_bytes_out,
        worker.stream_bytes_copied,
        worker.trains_out,
        worker.fin_flushes_ack_owed,
        worker.pacer_holds,
        worker.zc_sends,
        worker.zc_copied,
        worker.zc_fallbacks,
        worker.fin_flushes_owed_and_acked,
      ])
    }

    fn add(&mut self, other: &Self) {
      for (to, from) in self.0.iter_mut().zip(other.0) {
        *to = to.wrapping_add(from);
      }
    }

    fn line(&self) -> String {
      let mut rslt = String::new();
      for (name, value) in Self::NAMES.iter().zip(self.0) {
        if !rslt.is_empty() {
          rslt.push(' ');
        }
        rslt.push_str(&format!("{name}={value}"));
      }
      rslt
    }
  }
}

/// Adds `server: rimu-ws` to every response.
struct ServerHeader;

impl Middleware<ConnAux, rimu_ws::Error> for ServerHeader {
  type Aux = ();

  fn aux(&self) -> Self::Aux {}

  async fn req(
    &self,
    _: &mut ConnAux,
    _: &mut Self::Aux,
    _: &mut Request<MsgBufferString>,
  ) -> rimu_ws::Result<ControlFlow<StatusCode, ()>> {
    Ok(ControlFlow::Continue(()))
  }

  async fn res(
    &self,
    _: &mut ConnAux,
    _: &mut Self::Aux,
    res: Response<&mut MsgBufferString>,
  ) -> rimu_ws::Result<ControlFlow<StatusCode, ()>> {
    res
      .msg_data
      .headers
      .push_from_iter(Header::from_name_and_value(KnownHeaderName::Server.into(), ["rimu-ws"]))?;
    Ok(ControlFlow::Continue(()))
  }
}

#[derive(Clone, rimu_ws::Lease)]
struct ConnAux {
  dataset: Arc<VectorUsize<DatasetItem>>,
}

async fn endpoint_baseline2(state: State<'_, ConnAux>) -> rimu_ws::Result<VerbatimParams> {
  let mut sum: i64 = 0;
  for (_, value) in state.req.msg_data.uri.query_params() {
    sum = sum.wrapping_add(value.parse()?);
  }
  state.req.msg_data.clear();
  std::io::Write::write_fmt(&mut state.req.msg_data.body, format_args!("{sum}"))?;
  state.req.msg_data.headers.push_from_iter(Header::from_name_and_value(
    KnownHeaderName::ContentType.into(),
    ["text/plain"],
  ))?;
  Ok(VerbatimParams(StatusCode::Ok))
}

async fn endpoint_json(
  state: State<'_, ConnAux>,
  Path(count): Path<usize>,
) -> rimu_ws::Result<JsonReply> {
  let mut m: i64 = 1;
  for (key, value) in state.req.msg_data.uri.query_params() {
    if key == "m" {
      m = value.parse()?;
      break;
    }
  }
  let dataset = &state.data.dataset;
  state.req.msg_data.clear();
  write_json(&mut state.req.msg_data.body, dataset, count, m)?;
  Ok(JsonReply(StatusCode::Ok))
}

/// `{"items":[..],"count":n}` for the first `count` items, with `total = price * quantity * m`,
/// serialized on every request. The dataset's numbers are integers (HttpArena made them so to keep
/// float formatting out of the test) and are written as such.
fn write_json(
  buf: &mut VectorUsize<u8>,
  dataset: &[DatasetItem],
  count: usize,
  m: i64,
) -> rimu_ws::Result<()> {
  let clamped = count.min(dataset.len());
  let mut w = JsonWriter::new(buf);
  // Every item and tag is written with a trailing comma; `end_seq` turns the last one into the
  // closing bracket.
  w.raw(b"{\"items\":[")?;
  for el in dataset.iter().take(clamped) {
    w.raw(b"{\"id\":")?;
    w.i64(el.id)?;
    w.raw(b",\"name\":\"")?;
    w.str_contents(&el.name)?;
    w.raw(b"\",\"category\":\"")?;
    w.str_contents(&el.category)?;
    w.raw(b"\",\"price\":")?;
    w.i64(el.price)?;
    w.raw(b",\"quantity\":")?;
    w.i64(el.quantity)?;
    w.raw(b",\"active\":")?;
    w.bool(el.active)?;
    w.raw(b",\"tags\":[")?;
    for tag in el.tags.iter() {
      w.raw(b"\"")?;
      w.str_contents(tag)?;
      w.raw(b"\",")?;
    }
    w.end_seq(b']')?;
    w.raw(b",\"rating\":{\"score\":")?;
    w.i64(el.rating.score)?;
    w.raw(b",\"count\":")?;
    w.i64(el.rating.count)?;
    w.raw(b"},\"total\":")?;
    w.i64(el.price.wrapping_mul(el.quantity).wrapping_mul(m))?;
    w.raw(b"},")?;
  }
  w.end_seq(b']')?;
  w.raw(b",\"count\":")?;
  w.u64(u64::try_from(clamped).unwrap_or(u64::MAX))?;
  w.raw(b"}")
}

fn load_dataset() -> Arc<VectorUsize<DatasetItem>> {
  let path = std::env::var("DATASET_PATH").unwrap_or_else(|_| "/data/dataset.json".to_string());
  Arc::new(match std::fs::read_to_string(&path) {
    Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
    Err(_) => VectorUsize::new(),
  })
}

#[derive(serde::Deserialize)]
struct DatasetItem {
  id: i64,
  name: String,
  category: String,
  price: i64,
  quantity: i64,
  active: bool,
  tags: ArrayVectorU8<String, 6>,
  rating: Rating,
}

#[derive(serde::Deserialize)]
struct Rating {
  score: i64,
  count: i64,
}

#[cfg(test)]
#[path = "arena_h2/alloc_tests_h3.rs"]
mod alloc_tests_h3;

#[cfg(test)]
mod knob_tests {
  use super::knobs::{Data, H3Knobs, Headers};
  use rimu_ws::{executor::UdpParams, http3::H3Params, quic::QuicParams};

  fn parse(vars: &[(&str, &str)]) -> Result<H3Knobs, String> {
    H3Knobs::from_vars(|name| vars.iter().find(|el| el.0 == name).map(|el| el.1.to_string()))
  }

  // Ruling T16-b: without variables every knob is the library default.
  #[test]
  fn no_variables_give_the_library_defaults() {
    let knobs = parse(&[]).unwrap();
    let (quic, udp) = (QuicParams::default(), UdpParams::new());
    assert_eq!(knobs.quic, quic);
    assert_eq!(
      (knobs.udp.recv_buffers, knobs.udp.recv_buffer_len, knobs.udp.tx_arena_bytes),
      (udp.recv_buffers, udp.recv_buffer_len, udp.tx_arena_bytes)
    );
    assert_eq!(
      (knobs.udp.rcvbuf, knobs.udp.sndbuf, knobs.udp.max_train_segments, knobs.udp.reuseport),
      (udp.rcvbuf, udp.sndbuf, udp.max_train_segments, udp.reuseport)
    );
    assert!(knobs.pin_workers);
    assert_eq!((knobs.data, knobs.headers), (Data::Reuse, Headers::Min));
    // Task 18: header protection one packet at a time and no QPACK dynamic table, as the library
    assert!(!knobs.quic.batched_header_protection());
    // Task 19: copying sends, bursts of one train, the repeated acknowledgment, as the library
    assert!(!knobs.udp.zerocopy && !udp.zerocopy);
    assert_eq!((knobs.quic.pacing_burst(), knobs.quic.repeat_ack()), (64, true));
    assert_eq!(knobs.h3, H3Params::default());
    // Ruling T16-h: the benchmark path has GRO on, the library default has it off
    assert!(knobs.udp.gro && !udp.gro);
    assert!(!parse(&[("ARENA_H3_GRO", "0")]).unwrap().udp.gro);
  }

  // Ruling T16-b: each variable sets the field of the table in the program's documentation.
  #[test]
  fn each_variable_sets_its_field() {
    let knobs = parse(&[
      ("ARENA_H3_BALANCE", "0"),
      ("ARENA_H3_BODIES", "round-robin"),
      ("ARENA_H3_DATA", "fresh"),
      ("ARENA_H3_FLUSH_ORDER", "slot"),
      ("ARENA_H3_GRO", "1"),
      ("ARENA_H3_HEADERS", "full"),
      ("ARENA_H3_HP", "batched"),
      ("ARENA_H3_MAX_IN_FLIGHT", "131072"),
      ("ARENA_H3_PACING", "0"),
      ("ARENA_H3_PACING_BURST", "16"),
      ("ARENA_H3_PIN", "0"),
      ("ARENA_H3_PMTU_PROBE", "rtt"),
      ("ARENA_H3_QPACK", "4096"),
      ("ARENA_H3_RCVBUF", "1048576"),
      ("ARENA_H3_RECV_BUFFERS", "512"),
      ("ARENA_H3_REPEAT_ACK", "0"),
      ("ARENA_H3_SNDBUF", "2097152"),
      ("ARENA_H3_STEERING", "kernel"),
      ("ARENA_H3_TRAIN", "32"),
      ("ARENA_H3_TX_ARENA", "1536000"),
      ("ARENA_H3_ZC", "1"),
    ])
    .unwrap();
    let quic = knobs.quic;
    assert!(!quic.balance() && quic.bodies_round_robin() && quic.flush_in_slot_order());
    assert!(!quic.pacing() && quic.pmtu_probe_after_rtt() && !quic.cid_steering());
    assert_eq!(quic.max_in_flight(), 131_072);
    assert!(quic.batched_header_protection());
    // Task 19 (rulings T19-b to T19-d)
    assert_eq!((quic.pacing_burst(), quic.repeat_ack(), knobs.udp.zerocopy), (16, false, true));
    // Ruling T18-c: a dynamic table of 4096 bytes and 100 blocked streams, the rest as the library
    let h3 = H3Params { qpack_max_table_capacity: 4096, qpack_blocked_streams: 100, ..knobs.h3 };
    assert_eq!(knobs.h3, h3);
    assert_eq!(
      H3Params { qpack_max_table_capacity: 0, qpack_blocked_streams: 0, ..h3 },
      H3Params::default()
    );
    let ring = parse(&[("ARENA_H3_HP", "ring"), ("ARENA_H3_QPACK", "0")]).unwrap();
    assert!(!ring.quic.batched_header_protection());
    assert_eq!(ring.h3, H3Params::default());
    let udp = knobs.udp;
    assert!(udp.gro);
    assert_eq!(
      (udp.recv_buffers, udp.tx_arena_bytes, udp.max_train_segments),
      (512, 1_536_000, 32)
    );
    assert_eq!((udp.rcvbuf, udp.sndbuf), (1 << 20, 2 << 20));
    assert!(!knobs.pin_workers);
    assert_eq!((knobs.data, knobs.headers), (Data::Fresh, Headers::Full));
    // The steering of the kernel has no balance, whatever is asked
    let kernel = parse(&[("ARENA_H3_STEERING", "kernel"), ("ARENA_H3_BALANCE", "1")]).unwrap();
    assert!(!kernel.quic.cid_steering() && !kernel.quic.balance());
    // The line that the server prints names every knob
    let line = knobs.line();
    for name in [
      "gro=1",
      "recv_buffers=512",
      "train=32",
      "steering=kernel",
      "data=fresh",
      "hp=batched",
      "qpack=4096",
      "pacing_burst=16",
      "repeat_ack=0",
      "zc=1",
    ] {
      assert!(line.contains(name), "{line}");
    }
  }

  // A value that is not one of the table is an error that names the variable.
  #[test]
  fn bad_values_are_refused() {
    for (name, value) in [
      ("ARENA_H3_GRO", "yes"),
      ("ARENA_H3_HEADERS", "some"),
      ("ARENA_H3_TRAIN", "65"),
      ("ARENA_H3_TRAIN", "0"),
      ("ARENA_H3_RECV_BUFFERS", "0"),
      ("ARENA_H3_MAX_IN_FLIGHT", "-1"),
      ("ARENA_H3_STEERING", "hash"),
      ("ARENA_H3_FLUSH_ORDER", "random"),
      ("ARENA_H3_HP", "aesni"),
      ("ARENA_H3_QPACK", "1024"),
      ("ARENA_H3_ZC", "on"),
      ("ARENA_H3_PACING_BURST", "0"),
      ("ARENA_H3_PACING_BURST", "65"),
      ("ARENA_H3_REPEAT_ACK", "2"),
    ] {
      let err = parse(&[(name, value)]).unwrap_err();
      assert!(err.contains(name), "{err}");
    }
  }
}

#[cfg(test)]
mod tests {
  use super::{DatasetItem, write_json};
  use rimu_ws::{
    collections::{ArrayVectorU8, VectorUsize},
    misc::Wrapper,
  };

  /// The serde form the endpoint used before `JsonWriter`; the writer must give the same bytes.
  fn serde_json_form(dataset: &[DatasetItem], count: usize, m: i64) -> Vec<u8> {
    let clamped = count.min(dataset.len());
    let items = dataset.iter().take(clamped).map(move |el| {
      Ok(ProcessedItem {
        id: el.id,
        name: &el.name,
        category: &el.category,
        price: el.price,
        quantity: el.quantity,
        active: el.active,
        tags: ArrayVectorU8::from_iterator(el.tags.iter().map(|tag| tag.as_str()))?,
        rating: RatingOut { score: el.rating.score, count: el.rating.count },
        total: el.price.wrapping_mul(el.quantity).wrapping_mul(m),
      })
    });
    let resp = JsonResponse { count: clamped, items: Wrapper(core::cell::RefCell::new(items)) };
    serde_json::to_vec(&resp).unwrap()
  }

  fn check(dataset: &[DatasetItem]) {
    for count in [0, 1, 2, 7, 50, 1000] {
      for m in [1, 3, -2, 0, i64::MAX] {
        let mut buf = VectorUsize::new();
        write_json(&mut buf, dataset, count, m).unwrap();
        assert_eq!(
          String::from_utf8_lossy(buf.as_slice()),
          String::from_utf8_lossy(&serde_json_form(dataset, count, m)),
          "count {count}, m {m}"
        );
      }
    }
  }

  #[test]
  fn json_matches_serde_on_the_dataset() {
    let path = std::env::var("DATASET_PATH")
      .unwrap_or_else(|_| "/mnt/nvme1tb/claude-tmp/arena-main/data/dataset.json".into());
    let Ok(text) = std::fs::read_to_string(&path) else {
      eprintln!("no dataset at {path}: skipped");
      return;
    };
    let dataset: VectorUsize<DatasetItem> = serde_json::from_str(&text).unwrap();
    assert!(dataset.len() >= 50);
    check(&dataset);
  }

  /// The dataset's numbers are integers and stay integers: the body sizes HttpArena computes for
  /// its seven (count, m) pairs.
  #[test]
  fn json_has_the_reference_sizes() {
    let path = std::env::var("DATASET_PATH")
      .unwrap_or_else(|_| "/mnt/nvme1tb/claude-tmp/arena-main/data/dataset.json".into());
    let Ok(text) = std::fs::read_to_string(&path) else {
      eprintln!("no dataset at {path}: skipped");
      return;
    };
    let dataset: VectorUsize<DatasetItem> = serde_json::from_str(&text).unwrap();
    let pairs: [(usize, i32, usize); 7] = [
      (1, 3, 203),
      (5, 7, 888),
      (10, 2, 1695),
      (15, 5, 2556),
      (25, 4, 4190),
      (40, 8, 6707),
      (50, 6, 8397),
    ];
    for (count, m, len) in pairs {
      let mut buf = VectorUsize::new();
      write_json(&mut buf, &dataset, count, m.into()).unwrap();
      assert_eq!(buf.len(), len, "count {count}, m {m}");
    }
  }

  #[test]
  fn json_matches_serde_with_escapes() {
    let text = r#"[{"id":-3,"name":"a \"quoted\" \\ name\n\u0001 é 東","category":"x/y\t","price":1,
      "quantity":3,"active":true,"tags":["","t\"",  "long tag long tag long tag long tag long"],
      "rating":{"score":-4,"count":-7}},
      {"id":9007199254740993,"name":"","category":"c","price":-9223372036854775808,"quantity":9223372036854775807,"active":false,
      "tags":[],"rating":{"score":0,"count":0}}]"#;
    let dataset: VectorUsize<DatasetItem> = serde_json::from_str(text).unwrap();
    check(&dataset);
  }

  #[derive(serde::Serialize)]
  #[serde(bound = "E: serde::Serialize")]
  struct JsonResponse<E, I>
  where
    I: Iterator<Item = rimu_ws::Result<E>>,
    E: serde::Serialize,
  {
    items: Wrapper<core::cell::RefCell<I>>,
    count: usize,
  }

  #[derive(serde::Serialize)]
  struct ProcessedItem<'any> {
    id: i64,
    name: &'any str,
    category: &'any str,
    price: i64,
    quantity: i64,
    active: bool,
    tags: ArrayVectorU8<&'any str, 6>,
    rating: RatingOut,
    total: i64,
  }

  #[derive(serde::Serialize)]
  struct RatingOut {
    score: i64,
    count: i64,
  }
}
