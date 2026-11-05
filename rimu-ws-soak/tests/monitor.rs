use rimu_ws_soak::monitor::{
  Baseline, Budgets, Monitor, MonitorError, Sample, TcpStates, Violation, check_drained,
  check_running, parse_status, parse_tcp_table,
};

#[test]
fn parses_status_fixture() {
  assert_eq!(parse_status(include_str!("fixtures/status.txt")), Some((12345, 23456)));
}

#[test]
fn parses_tcp_fixture() {
  let states = parse_tcp_table(include_str!("fixtures/tcp.txt"), 9080);
  assert_eq!(
    states,
    TcpStates {
      established: 2,
      close_wait: 3,
      time_wait: 1,
      other: 0,
      recv_q: 0x1 + 0x2 + 0x100,
      send_q: 0x10 + 0x20,
    }
  );
}

#[test]
fn samples_own_process() {
  let mut monitor = Monitor::new(std::process::id(), 9).unwrap();
  let sample = monitor.sample().unwrap();
  assert!(sample.fds > 0 && sample.rss_kib > 0, "{sample:?}");
}

#[test]
fn dead_pid_is_pid_gone() {
  let mut child = std::process::Command::new("sleep").arg("0.1").spawn().unwrap();
  let mut monitor = Monitor::new(child.id(), 9).unwrap();
  assert!(monitor.sample().is_ok());
  let _ = child.wait().unwrap();
  assert!(matches!(monitor.sample(), Err(MonitorError::PidGone)));
}

fn sample(fds: u32, rss_kib: u64, close_wait: u32) -> Sample {
  Sample {
    fds,
    rss_kib,
    tcp: TcpStates { close_wait, ..TcpStates::default() },
    ..Sample::default()
  }
}

#[test]
fn close_wait_needs_three_samples() {
  let base = Baseline { rss_kib: 1000, fds: 10 };
  let budgets = Budgets { slots: 10, ..Budgets::default() };
  let mut streak = 0;
  let mut found = Vec::new();
  for _ in 0..4 {
    found.push(check_running(&base, &sample(10, 1000, 100), 0, &budgets, &mut streak));
  }
  assert!(found[0].is_empty() && found[1].is_empty());
  assert_eq!(found[2], [Violation::CloseWait { count: 100 }]);
  assert_eq!(found[3], [Violation::CloseWait { count: 100 }]);
}

#[test]
fn running_limits_on_fds_and_rss() {
  let base = Baseline { rss_kib: 1000, fds: 10 };
  let budgets = Budgets { slots: 100, ..Budgets::default() };
  let mut streak = 0;
  assert!(
    check_running(&base, &sample(10 + 50 + 64, 1000, 0), 50, &budgets, &mut streak).is_empty()
  );
  assert_eq!(
    check_running(&base, &sample(10 + 50 + 65, 1000, 0), 50, &budgets, &mut streak),
    [Violation::Fds { fds: 125, limit: 124 }]
  );
  let limit_kib = 1000 + 256 * 100 + 65536;
  assert_eq!(
    check_running(&base, &sample(10, limit_kib + 1, 0), 0, &budgets, &mut streak),
    [Violation::Rss { rss_kib: limit_kib + 1, limit_kib }]
  );
}

#[test]
fn drained_leak_detected() {
  let base = Baseline { rss_kib: 1000, fds: 10 };
  assert!(check_drained(&base, &sample(26, 1000, 0)).is_empty());
  let found = check_drained(&base, &sample(27, 1000, 0));
  assert_eq!(found.len(), 1);
  assert!(matches!(found[0], Violation::Leak(_)));
}

// A connection may hold a message up to the size limit: each one in flight raises the RSS limit
// by three times the limit (the message, its buffer's doubling, and the echo).
#[test]
fn large_messages_in_flight_raise_the_rss_limit() {
  let base = Baseline { rss_kib: 1000, fds: 10 };
  let budgets = Budgets { slots: 100, large_inflight: 10, max_payload: 1 << 20 };
  let limit_kib = 1000 + 256 * 100 + 65536 + 10 * 3 * 1024;
  let mut streak = 0;
  assert!(check_running(&base, &sample(10, limit_kib, 0), 0, &budgets, &mut streak).is_empty());
  assert_eq!(
    check_running(&base, &sample(10, limit_kib + 1, 0), 0, &budgets, &mut streak),
    [Violation::Rss { rss_kib: limit_kib + 1, limit_kib }]
  );
}

/// A fresh directory standing in for a container's cgroup.
fn fake_cgroup(name: &str, pids: &[u32]) -> std::path::PathBuf {
  let dir = std::path::PathBuf::from(format!(
    "/mnt/nvme1tb/claude-tmp/soak-test/{name}-{}",
    std::process::id()
  ));
  std::fs::create_dir_all(&dir).unwrap();
  let procs: String = pids.iter().map(|el| format!("{el}\n")).collect();
  std::fs::write(dir.join("cgroup.procs"), procs).unwrap();
  dir
}

#[test]
fn cgroup_monitor_sums_every_process() {
  let mut child = std::process::Command::new("sleep").arg("5").spawn().unwrap();
  let own_fds = std::fs::read_dir("/proc/self/fd").unwrap().count() as u32;
  let dir = fake_cgroup("sums", &[std::process::id(), child.id()]);
  let mut monitor = Monitor::cgroup(dir.clone(), 9).unwrap();
  let sample = monitor.sample().unwrap();
  let _ = child.kill();
  let _ = child.wait();
  let _ = std::fs::remove_dir_all(dir);
  assert_eq!(sample.procs, 2, "{sample:?}");
  assert!(sample.fds >= own_fds + 3 - 2, "{sample:?}, own {own_fds}");
  assert!(sample.rss_kib > 0, "{sample:?}");
}

#[test]
fn empty_cgroup_is_pid_gone() {
  let dir = fake_cgroup("empty", &[]);
  let rslt = Monitor::cgroup(dir.clone(), 9).and_then(|mut el| el.sample());
  let _ = std::fs::remove_dir_all(dir);
  assert!(matches!(rslt, Err(MonitorError::PidGone)), "{rslt:?}");
}

#[test]
fn unreadable_fd_dir_is_an_error() {
  // SAFETY: no arguments
  if unsafe { libc::geteuid() } == 0 {
    eprintln!("skipped: running as root, which can read every process's descriptors");
    return;
  }
  let dir = fake_cgroup("unreadable", &[1]);
  let rslt = Monitor::cgroup(dir.clone(), 9).and_then(|mut el| el.sample());
  let _ = std::fs::remove_dir_all(dir);
  assert!(matches!(rslt, Err(MonitorError::Unreadable(_))), "{rslt:?}");
}

#[test]
fn io_uring_expected_but_absent_is_invalid() {
  use rimu_ws_soak::cycle::io_uring_verdict;
  assert!(io_uring_verdict(true, 0).is_some());
  assert_eq!(io_uring_verdict(true, 2), None);
  assert_eq!(io_uring_verdict(false, 0), None);
}

#[test]
fn counts_io_uring_descriptors() {
  // struct io_uring_params is 120 bytes; zeroed asks for the defaults.
  let mut params = [0u64; 15];
  // SAFETY: a valid, writable params struct
  let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 4, params.as_mut_ptr()) };
  if fd < 0 {
    eprintln!("skipped: io_uring_setup is not allowed here");
    return;
  }
  let sample = Monitor::new(std::process::id(), 9).unwrap().sample();
  // SAFETY: the ring's descriptor, closed once
  let _ = unsafe { libc::close(fd as i32) };
  let sample = sample.unwrap();
  assert!(sample.io_uring_fds >= 1, "{sample:?}");
}
