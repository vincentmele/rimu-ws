//! The server seen from outside, once a second: memory, descriptors, CPU and its sockets' states,
//! and the invariants a bounded server keeps. The server is one process (`--pid`), or every
//! process of a container's cgroup (`--cgroup`), summed.

use std::path::PathBuf;

/// Socket states on the server's port (sockets whose local port it is).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TcpStates {
  pub established: u32,
  pub close_wait: u32,
  pub time_wait: u32,
  pub other: u32,
  pub recv_q: u64,
  pub send_q: u64,
}

/// One look at the server.
#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Sample {
  pub rss_kib: u64,
  pub hwm_kib: u64,
  pub fds: u32,
  pub cpu_ticks: u64,
  pub tcp: TcpStates,
  /// Processes summed.
  #[serde(default)]
  pub procs: u32,
  /// Descriptors that are io_uring instances.
  #[serde(default)]
  pub io_uring_fds: u32,
  /// The cgroup's `memory.current`, recorded only: it adds socket buffers and page cache to what
  /// the processes hold, so judging it would be another rule.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub cgroup_mem_kib: Option<u64>,
}

/// `VmRSS` and `VmHWM` in KiB.
pub fn parse_status(text: &str) -> Option<(u64, u64)> {
  let field = |name: &str| {
    text.lines().find_map(|line| line.strip_prefix(name)?.split_whitespace().next()?.parse().ok())
  };
  Some((field("VmRSS:")?, field("VmHWM:")?))
}

/// The `/proc/net/tcp` format.
pub fn parse_tcp_table(text: &str, port: u16) -> TcpStates {
  let mut states = TcpStates::default();
  for line in text.lines().skip(1) {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let (Some(local), Some(state), Some(queues)) = (fields.get(1), fields.get(3), fields.get(4))
    else {
      continue;
    };
    let local_port = local.rsplit(':').next().and_then(|el| u16::from_str_radix(el, 16).ok());
    if local_port != Some(port) {
      continue;
    }
    match *state {
      "01" => states.established += 1,
      "08" => states.close_wait += 1,
      "06" => states.time_wait += 1,
      _ => states.other += 1,
    }
    if let Some((tx, rx)) = queues.split_once(':') {
      states.send_q += u64::from_str_radix(tx, 16).unwrap_or(0);
      states.recv_q += u64::from_str_radix(rx, 16).unwrap_or(0);
    }
  }
  states
}

/// `/proc/<pid>/stat` after the command name (which may hold spaces): the state, then fields 4
/// onwards, so field `n` is `fields[n - 4]`.
fn stat_fields(pid: u32) -> Result<(char, Vec<u64>), MonitorError> {
  let text = read(&format!("/proc/{pid}/stat"))?;
  let rest = text.rsplit_once(')').map(|el| el.1).unwrap_or_default();
  let mut words = rest.split_whitespace();
  let state = words.next().and_then(|el| el.chars().next()).unwrap_or('?');
  Ok((state, words.map(|el| el.parse().unwrap_or(0)).collect()))
}

fn read(path: &str) -> Result<String, MonitorError> {
  std::fs::read_to_string(path).map_err(|err| match err.kind() {
    std::io::ErrorKind::NotFound => MonitorError::PidGone,
    _ => MonitorError::Io(err),
  })
}

#[derive(Debug)]
pub enum MonitorError {
  /// The process is gone, or another one has its pid; or the cgroup has no process left.
  PidGone,
  /// The server's descriptors can't be read (another user's process): judging it would mean
  /// judging zeros.
  Unreadable(String),
  Io(std::io::Error),
}

/// What is sampled.
#[derive(Debug)]
enum Source {
  /// One process, which must stay the same process.
  Pid { pid: u32, start_time: u64 },
  /// Every process in a cgroup directory, read afresh each time.
  Cgroup { dir: PathBuf },
}

/// Samples the server.
#[derive(Debug)]
pub struct Monitor {
  source: Source,
  port: u16,
}

/// One process's share of a sample.
struct ProcSample {
  rss_kib: u64,
  hwm_kib: u64,
  fds: u32,
  io_uring_fds: u32,
  cpu_ticks: u64,
}

/// `pid`'s memory, descriptors and CPU; `start_time` checks it is the same process.
fn sample_proc(pid: u32, start_time: Option<u64>) -> Result<ProcSample, MonitorError> {
  let (state, stat) = stat_fields(pid)?;
  let field = |n: usize| stat.get(n - 4).copied().unwrap_or(0);
  // A zombie has exited; another start time is another process with the same pid.
  if state == 'Z' || start_time.is_some_and(|el| field(22) != el) {
    return Err(MonitorError::PidGone);
  }
  // utime + stime
  let cpu_ticks = field(14) + field(15);
  let (rss_kib, hwm_kib) = parse_status(&read(&format!("/proc/{pid}/status"))?).unwrap_or((0, 0));
  let dir = std::fs::read_dir(format!("/proc/{pid}/fd")).map_err(|err| match err.kind() {
    std::io::ErrorKind::NotFound => MonitorError::PidGone,
    std::io::ErrorKind::PermissionDenied => {
      MonitorError::Unreadable(format!("/proc/{pid}/fd: {err}"))
    }
    _ => MonitorError::Io(err),
  })?;
  let (mut fds, mut io_uring_fds) = (0, 0);
  for entry in dir.flatten() {
    fds += 1;
    if std::fs::read_link(entry.path()).is_ok_and(|el| el.as_os_str() == "anon_inode:[io_uring]") {
      io_uring_fds += 1;
    }
  }
  Ok(ProcSample { rss_kib, hwm_kib, fds, io_uring_fds, cpu_ticks })
}

/// The pids in a cgroup's `cgroup.procs`.
fn cgroup_pids(dir: &std::path::Path) -> Result<Vec<u32>, MonitorError> {
  let text = std::fs::read_to_string(dir.join("cgroup.procs")).map_err(|err| match err.kind() {
    std::io::ErrorKind::NotFound => MonitorError::PidGone,
    _ => MonitorError::Io(err),
  })?;
  Ok(text.lines().filter_map(|el| el.trim().parse().ok()).collect())
}

impl Monitor {
  pub fn new(pid: u32, port: u16) -> Result<Monitor, MonitorError> {
    let start_time = stat_fields(pid)?.1.get(22 - 4).copied().unwrap_or(0);
    Ok(Monitor { source: Source::Pid { pid, start_time }, port })
  }

  /// Every process of the cgroup at `dir` (a container's), summed.
  pub fn cgroup(dir: PathBuf, port: u16) -> Result<Monitor, MonitorError> {
    if cgroup_pids(&dir)?.is_empty() {
      return Err(MonitorError::PidGone);
    }
    Ok(Monitor { source: Source::Cgroup { dir }, port })
  }

  /// The server's processes, for the RSS ceiling's kill.
  pub fn pids(&self) -> Vec<u32> {
    match &self.source {
      Source::Pid { pid, .. } => vec![*pid],
      Source::Cgroup { dir } => cgroup_pids(dir).unwrap_or_default(),
    }
  }

  pub fn sample(&mut self) -> Result<Sample, MonitorError> {
    let mut sample = Sample::default();
    let mut add = |part: ProcSample| {
      sample.procs += 1;
      sample.rss_kib += part.rss_kib;
      sample.hwm_kib += part.hwm_kib;
      sample.fds += part.fds;
      sample.io_uring_fds += part.io_uring_fds;
      sample.cpu_ticks += part.cpu_ticks;
    };
    match &self.source {
      Source::Pid { pid, start_time } => add(sample_proc(*pid, Some(*start_time))?),
      Source::Cgroup { dir } => {
        for pid in cgroup_pids(dir)? {
          match sample_proc(pid, None) {
            Ok(part) => add(part),
            // It exited between the listing and the read.
            Err(MonitorError::PidGone) => {}
            Err(err) => return Err(err),
          }
        }
        if sample.procs == 0 {
          return Err(MonitorError::PidGone);
        }
        sample.cgroup_mem_kib = std::fs::read_to_string(dir.join("memory.current"))
          .ok()
          .and_then(|el| el.trim().parse::<u64>().ok())
          .map(|el| el / 1024);
      }
    }
    let mut tcp = TcpStates::default();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
      if let Ok(text) = std::fs::read_to_string(table) {
        let part = parse_tcp_table(&text, self.port);
        tcp.established += part.established;
        tcp.close_wait += part.close_wait;
        tcp.time_wait += part.time_wait;
        tcp.other += part.other;
        tcp.recv_q += part.recv_q;
        tcp.send_q += part.send_q;
      }
    }
    sample.tcp = tcp;
    Ok(sample)
  }
}

/// What a sample is checked against: the server after warmup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Baseline {
  pub rss_kib: u64,
  pub fds: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Budgets {
  pub slots: u32,
  /// Connections holding a message of up to `max_payload` on the server.
  pub large_inflight: u32,
  pub max_payload: u64,
}

/// A broken invariant.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Violation {
  PidGone,
  Fds {
    fds: u32,
    limit: u32,
  },
  Rss {
    rss_kib: u64,
    limit_kib: u64,
  },
  CloseWait {
    count: u32,
  },
  Busy {
    cpu_pct: f64,
  },
  Latency {
    p99_us: u64,
    limit_us: u64,
  },
  /// Probe echoes that never came (or broke their connection) in one second.
  ProbeFailures {
    failures: u64,
    count: u64,
  },
  NoRecovery(String),
  Leak(String),
  /// Memory after the drain, or its peak, rose cycle after cycle.
  Trend(String),
  /// The server passed `--rss-ceiling` and was killed.
  RssCeiling {
    rss_kib: u64,
    ceiling_kib: u64,
  },
  /// Connections of a burst that were never served.
  Burst {
    unserved: u32,
    n: u32,
  },
  /// The server's descriptors couldn't be read, which ends the run.
  Unreadable(String),
}

/// While clients are connected.
pub fn check_running(
  base: &Baseline,
  s: &Sample,
  live_conns: u32,
  budgets: &Budgets,
  close_wait_streak: &mut u32,
) -> Vec<Violation> {
  let mut found = Vec::new();
  let fd_limit = base.fds + live_conns + 64;
  if s.fds > fd_limit {
    found.push(Violation::Fds { fds: s.fds, limit: fd_limit });
  }
  // A large message costs the server the message, its buffer's doubling, and the echo.
  let large_kib = u64::from(budgets.large_inflight) * 3 * budgets.max_payload.div_ceil(1024);
  let rss_limit = base.rss_kib + 256 * u64::from(budgets.slots) + 65536 + large_kib;
  if s.rss_kib > rss_limit {
    found.push(Violation::Rss { rss_kib: s.rss_kib, limit_kib: rss_limit });
  }
  if s.tcp.close_wait > 64 {
    *close_wait_streak += 1;
    if *close_wait_streak >= 3 {
      found.push(Violation::CloseWait { count: s.tcp.close_wait });
    }
  } else {
    *close_wait_streak = 0;
  }
  found
}

/// After every client has gone.
pub fn check_drained(base: &Baseline, s: &Sample) -> Vec<Violation> {
  let mut found = check_drained_fds(base, s);
  found.extend(check_drained_rss(base, s));
  found
}

/// Descriptors and CLOSE_WAIT after every client has gone, against the warmup.
pub fn check_drained_fds(base: &Baseline, s: &Sample) -> Vec<Violation> {
  let mut found = Vec::new();
  if s.fds > base.fds + 16 {
    found.push(Violation::Leak(format!(
      "{} descriptors after the drain, baseline {}",
      s.fds, base.fds
    )));
  }
  if s.tcp.close_wait > 0 {
    found
      .push(Violation::Leak(format!("{} sockets in CLOSE_WAIT after the drain", s.tcp.close_wait)));
  }
  found
}

/// RSS after every client has gone, against `base` (`cycle::drain_baseline`).
pub fn check_drained_rss(base: &Baseline, s: &Sample) -> Vec<Violation> {
  let rss_limit = base.rss_kib * 11 / 10 + 16384;
  if s.rss_kib > rss_limit {
    return vec![Violation::Leak(format!(
      "RSS {} KiB after the drain, limit {rss_limit} KiB",
      s.rss_kib
    ))];
  }
  Vec::new()
}
