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
    fd_flood: None,
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
  // Lag counts as saturation 1 ms beyond what the idle harness showed in warmup.
  assert!(lag_exceeds(2001, 1000));
  assert!(!lag_exceeds(2000, 1000));
  let warm =
    |p99_us, lag_p99_us| ProbeStats { count: 100, p99_us, lag_p99_us, ..ProbeStats::default() };
  let lagging =
    ProbeStats { count: 100, p99_us: 100_000, lag_p99_us: 2000, ..ProbeStats::default() };
  assert_eq!(latency_verdict(&warm(100, 0), &lagging), Verdict::Saturated);
  // The idle harness's own timer lateness is not saturation.
  let timer_noise =
    ProbeStats { count: 100, p99_us: 150, lag_p99_us: 1900, ..ProbeStats::default() };
  assert_eq!(latency_verdict(&warm(100, 960), &timer_noise), Verdict::Ok);
  let slow = ProbeStats { count: 100, p99_us: 6000, lag_p99_us: 0, ..ProbeStats::default() };
  assert_eq!(latency_verdict(&warm(1000, 0), &slow), Verdict::Violation(6000, 5000));
  let fine = ProbeStats { count: 100, p99_us: 1100, ..ProbeStats::default() };
  assert_eq!(latency_verdict(&warm(100, 0), &fine), Verdict::Ok);
}

#[test]
fn fd_flood_detects_busy_spin() {
  use rimu_ws_soak::{fdflood::busy_verdict, monitor::Violation};
  assert_eq!(
    busy_verdict(50, Duration::from_secs(1), 100),
    Some(Violation::Busy { cpu_pct: 50.0 })
  );
  assert_eq!(busy_verdict(10, Duration::from_secs(1), 100), None);
  assert_eq!(busy_verdict(0, Duration::ZERO, 100), None);
}

// Review fixes

#[test]
fn probe_failures_break_the_latency_invariant() {
  let failing = ProbeStats { count: 0, failures: 3, ..ProbeStats::default() };
  assert_eq!(latency_verdict(&ProbeStats::default(), &failing), Verdict::Failures(3));
}

#[test]
fn every_cycle_draws_new_inputs() {
  use rimu_ws_soak::cycle::cycle_seed;
  assert_eq!(cycle_seed(7, 0), 7);
  assert_ne!(cycle_seed(7, 1), 7);
  assert_ne!(cycle_seed(7, 1), cycle_seed(7, 2));
}

// A server slower than the probe period makes the probes late, but that is the server's latency,
// not the harness's: lag counts only the timer's lateness.
#[tokio::test(flavor = "multi_thread")]
async fn slow_echoes_are_latency_not_saturation() {
  use rimu_ws_soak::probe::Probes;
  let faults = Faults { echo_delay: Some(Duration::from_millis(25)), ..Faults::default() };
  let addr = spawn_fake(faults).await;
  let ctx = cfg(addr, 0).run.ctx;
  let probes = Probes::spawn(ctx, 2, 100);
  tokio::time::sleep(Duration::from_secs(2)).await;
  let stats = probes.snapshot();
  probes.stop();
  assert!(stats.count > 10, "{stats:?}");
  assert!(stats.p99_us >= 25_000, "{stats:?}");
  assert!(!lag_exceeds(stats.lag_p99_us, 0), "{stats:?}");
  let warm = ProbeStats { count: 100, p99_us: 1000, ..ProbeStats::default() };
  assert!(matches!(latency_verdict(&warm, &stats), Verdict::Violation(..)), "{stats:?}");
}

// Slots that keep running after the server died must not report it again every second.
#[tokio::test(flavor = "multi_thread")]
async fn server_gone_is_reported_once_while_slots_wind_down() {
  let addr = spawn_fake(Faults::default()).await;
  let mut child = stand_in();
  let mut cfg = cfg(addr, child.id());
  // Each idle_post run waits out the idle timeout, so the slots wind down for seconds.
  cfg.run.weights = rimu_ws_soak::scenario::parse_weights("idle_post=1").unwrap();
  cfg.run.ctx.limits.idle = Duration::from_secs(2);
  let killer = tokio::spawn(async move {
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let _ = child.kill();
    let _ = child.wait();
  });
  let summary = run(cfg, &mut Vec::new()).await;
  killer.await.unwrap();
  assert_eq!(summary.violations, [rimu_ws_soak::monitor::Violation::PidGone], "{summary:?}");
}

#[test]
fn failures_in_saturated_seconds_are_marked() {
  use rimu_ws_soak::{cycle::fail_line, runner::Record, scenario::Scenario};
  let record = Record {
    slot: 1,
    generation: 2,
    seed: 3,
    replay: "9:1:2".into(),
    scenario: Scenario::Echo,
    outcome: "fail",
    reason: Some("timed out".into()),
    transcript: None,
    elapsed_ms: 10,
    client_saturated: true,
  };
  let line = fail_line(&record);
  assert!(line.contains("replay=9:1:2") && line.contains("client saturated"), "{line}");
  let calm = Record { client_saturated: false, ..record };
  assert!(!fail_line(&calm).contains("saturated"));
}
