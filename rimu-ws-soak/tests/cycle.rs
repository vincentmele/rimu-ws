mod support;

use rimu_ws_soak::{
  conn::ConnOpts,
  cycle::{CycleConfig, Verdict, latency_verdict, run},
  probe::{ProbeStats, lag_exceeds},
  runner::RunConfig,
  scenario::{Ctx, Limits, profile},
};
use std::{net::SocketAddr, time::Duration};
use support::{Faults, spawn_fake};

/// A process to monitor in the server's place: the fake runs inside the test, whose own memory
/// is the harness's and grows with the clients'.
fn stand_in() -> std::process::Child {
  std::process::Command::new("sleep").arg("60").spawn().unwrap()
}

fn cfg(addr: SocketAddr, pid: u32) -> CycleConfig {
  let ctx = Ctx {
    addr,
    host: "localhost".into(),
    path: "/".into(),
    limits: Limits::default(),
    opts: ConnOpts::default(),
  };
  CycleConfig {
    run: RunConfig {
      global_seed: 1,
      slots: 20,
      duration: Duration::from_secs(2),
      weights: profile("baseline").unwrap(),
      ctx,
      source_ips: Vec::new(),
    },
    pid: Some(pid),
    port: addr.port(),
    cycles: 1,
    warmup: Duration::from_secs(1),
    drain: Duration::from_secs(1),
    probes: 2,
    probe_rate: 50,
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_cycle_summary() {
  let addr = spawn_fake(Faults::default()).await;
  let mut child = stand_in();
  let mut out = Vec::new();
  let summary = run(cfg(addr, child.id()), &mut out).await;
  let _ = child.kill();
  let _ = child.wait();
  assert_eq!(summary.fails, 0, "{summary:?}");
  assert!(summary.violations.is_empty(), "{summary:?}");
  assert!(summary.records > 0);
  let text = String::from_utf8(out).unwrap();
  let last: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
  assert_eq!(last["kind"], "summary");
  assert!(text.lines().any(|line| line.contains("\"kind\":\"sample\"")));
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_server_counts_fails() {
  let addr = spawn_fake(Faults { corrupt_echo: true, ..Faults::default() }).await;
  let mut child = stand_in();
  let summary = run(cfg(addr, child.id()), &mut Vec::new()).await;
  let _ = child.kill();
  let _ = child.wait();
  assert!(summary.fails > 0, "{summary:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn server_gone_is_one_loud_violation() {
  let addr = spawn_fake(Faults::default()).await;
  let mut child = stand_in();
  let pid = child.id();
  let killer = tokio::spawn(async move {
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let _ = child.kill();
    let _ = child.wait();
  });
  let summary = run(cfg(addr, pid), &mut Vec::new()).await;
  killer.await.unwrap();
  assert_eq!(summary.violations, [rimu_ws_soak::monitor::Violation::PidGone], "{summary:?}");
}

#[test]
fn saturated_probe_lag_skips_latency() {
  assert!(lag_exceeds(1001));
  assert!(!lag_exceeds(1000));
  let lagging =
    ProbeStats { count: 100, p99_us: 100_000, lag_p99_us: 2000, ..ProbeStats::default() };
  assert_eq!(latency_verdict(100, &lagging), Verdict::Saturated);
  let slow = ProbeStats { count: 100, p99_us: 6000, lag_p99_us: 0, ..ProbeStats::default() };
  assert_eq!(latency_verdict(1000, &slow), Verdict::Violation(6000, 5000));
  let fine = ProbeStats { count: 100, p99_us: 1100, ..ProbeStats::default() };
  assert_eq!(latency_verdict(100, &fine), Verdict::Ok);
}
