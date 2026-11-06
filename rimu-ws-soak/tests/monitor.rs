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
  let budgets = Budgets { slots: 100, large_inflight: 10, max_payload: 1 << 20, per_slot_kib: 0 };
  let limit_kib = 1000 + 256 * 100 + 65536 + 10 * 3 * 1024;
  let mut streak = 0;
  assert!(check_running(&base, &sample(10, limit_kib, 0), 0, &budgets, &mut streak).is_empty());
  assert_eq!(
    check_running(&base, &sample(10, limit_kib + 1, 0), 0, &budgets, &mut streak),
    [Violation::Rss { rss_kib: limit_kib + 1, limit_kib }]
  );
}


// The HTTP/2 server streaming large responses may hold more per connection than the WebSocket
// server: the budget per slot follows the server.
#[test]
fn per_slot_budget_follows_the_server() {
  let base = Baseline { rss_kib: 1000, fds: 10 };
  let budgets = Budgets { slots: 100, per_slot_kib: 768, ..Budgets::default() };
  let limit_kib = 1000 + 768 * 100 + 65536;
  let mut streak = 0;
  assert!(check_running(&base, &sample(10, limit_kib, 0), 0, &budgets, &mut streak).is_empty());
  assert!(!check_running(&base, &sample(10, limit_kib + 1, 0), 0, &budgets, &mut streak).is_empty());
}
