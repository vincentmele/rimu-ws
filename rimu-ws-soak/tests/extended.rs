//! Long runs: records kept only for failures, heartbeats, whole-run latency, profiles rotating by
//! cycle, trend and memory-ceiling checks, a time limit, stopping at the first failure, and the
//! connection burst.

mod support;

use rimu_ws_soak::{
  conn::ConnOpts,
  cycle::{CycleConfig, Extended, RecordMode, run, trend_violation},
  monitor::Violation,
  runner::RunConfig,
  scenario::{Ctx, Limits, parse_weights, profile},
};
use std::{net::SocketAddr, time::Duration};
use support::{Faults, spawn_fake};

fn stand_in() -> std::process::Child {
  std::process::Command::new("sleep").arg("60").spawn().unwrap()
}

fn config(addr: SocketAddr, pid: u32) -> CycleConfig {
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
      slots: 10,
      duration: Duration::from_secs(2),
      weights: profile("baseline").unwrap(),
      ctx,
      source_ips: Vec::new(),
    },
    pid: Some(pid),
    port: addr.port(),
    cycles: 1,
    warmup: Duration::from_millis(500),
    drain: Duration::from_millis(500),
    // The fake shares this process with the other tests, so its latency is theirs: only the
    // heartbeat test runs probes, and judges nothing by them.
    probes: 0,
    probe_rate: 50,
    fd_flood: None,
    ext: Extended::default(),
  }
}

fn lines(out: &[u8], kind: &str) -> Vec<serde_json::Value> {
  String::from_utf8_lossy(out)
    .lines()
    .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
    .filter(|el| el["kind"] == kind)
    .collect()
}

async fn run_with(cfg: CycleConfig) -> (rimu_ws_soak::cycle::Summary, Vec<u8>) {
  let mut out = Vec::new();
  let summary = run(cfg, &mut out).await;
  (summary, out)
}

#[tokio::test(flavor = "multi_thread")]
async fn failures_only_keeps_no_passing_records() {
  let addr = spawn_fake(Faults::default()).await;
  let mut child = stand_in();
  let mut cfg = config(addr, child.id());
  cfg.ext.records = RecordMode::Failures;
  let (summary, out) = run_with(cfg).await;
  let _ = child.kill();
  assert!(summary.records > 0, "{summary:?}");
  assert!(lines(&out, "record").is_empty());

  let addr = spawn_fake(Faults { corrupt_echo: true, ..Faults::default() }).await;
  let mut child = stand_in();
  let mut cfg = config(addr, child.id());
  cfg.ext.records = RecordMode::Failures;
  let (summary, out) = run_with(cfg).await;
  let _ = child.kill();
  let records = lines(&out, "record");
  assert!(!records.is_empty(), "{summary:?}");
  assert!(records.iter().all(|el| el["outcome"] == "fail"));
}

#[tokio::test(flavor = "multi_thread")]
async fn heartbeats_and_whole_run_latency() {
  let addr = spawn_fake(Faults::default()).await;
  let mut child = stand_in();
  let mut cfg = config(addr, child.id());
  cfg.run.duration = Duration::from_secs(3);
  cfg.probes = 2;
  cfg.ext.heartbeat = Some(Duration::from_secs(1));
  let (summary, out) = run_with(cfg).await;
  let _ = child.kill();
  let beats = lines(&out, "heartbeat");
  assert!(beats.len() >= 2, "{} heartbeats", beats.len());
  let last = beats.last().unwrap();
  assert!(last["records"].as_u64().unwrap() > 0, "{last}");
  assert!(last["latency"]["count"].as_u64().unwrap() > 0, "{last}");
  assert!(last["sample"]["rss_kib"].as_u64().unwrap() > 0, "{last}");
  let latency = summary.latency;
  assert!(latency.count > 50, "{latency:?}");
  assert!(latency.p50_us > 0 && latency.p50_us <= latency.p99_us, "{latency:?}");
  assert!(latency.p99_us <= latency.p999_us && latency.p999_us <= latency.max_us, "{latency:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn profiles_rotate_by_cycle() {
  let addr = spawn_fake(Faults::default()).await;
  let mut child = stand_in();
  let mut cfg = config(addr, child.id());
  cfg.cycles = 3;
  cfg.run.duration = Duration::from_secs(1);
  cfg.ext.rotation = vec![
    ("first".into(), parse_weights("echo=1").unwrap()),
    ("second".into(), parse_weights("split_every_byte=1").unwrap()),
  ];
  let (summary, out) = run_with(cfg).await;
  let _ = child.kill();
  assert_eq!(summary.fails, 0, "{summary:?}");
  let profiles: Vec<_> =
    lines(&out, "warmup").iter().map(|el| el["profile"].as_str().unwrap().to_owned()).collect();
  assert_eq!(profiles, ["first", "second", "first"]);
  let scenarios: Vec<_> =
    lines(&out, "record").iter().map(|el| el["scenario"].as_str().unwrap().to_owned()).collect();
  assert!(scenarios.contains(&"echo".to_owned()) && scenarios.contains(&"split_every_byte".into()));
}

#[test]
fn memory_rising_every_cycle_is_a_trend() {
  const MIB: u64 = 1024;
  // Four rises in a row, 80 MiB in all.
  let rising = [100 * MIB, 120 * MIB, 140 * MIB, 160 * MIB, 180 * MIB];
  assert!(trend_violation("RSS after the drain", &rising, 4).is_some());
  // Too few cycles to tell.
  assert!(trend_violation("RSS after the drain", &rising[..4], 4).is_none());
  // A plateau, a dip, or rises too small to matter.
  let plateau = [100 * MIB, 120 * MIB, 120 * MIB, 140 * MIB, 160 * MIB];
  assert!(trend_violation("RSS after the drain", &plateau, 4).is_none());
  let small = [100 * MIB, 101 * MIB, 102 * MIB, 103 * MIB, 104 * MIB];
  assert!(trend_violation("RSS after the drain", &small, 4).is_none());
  // Only the last cycles count.
  let older = [500 * MIB, 100 * MIB, 120 * MIB, 140 * MIB, 160 * MIB, 180 * MIB];
  assert!(trend_violation("RSS after the drain", &older, 4).is_some());
  assert!(trend_violation("RSS after the drain", &rising, 0).is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn rss_ceiling_kills_the_server() {
  let addr = spawn_fake(Faults::default()).await;
  let mut child = stand_in();
  let mut cfg = config(addr, child.id());
  cfg.cycles = 5;
  cfg.ext.rss_ceiling_kib = Some(1);
  let (summary, _) = run_with(cfg).await;
  assert!(
    matches!(summary.violations.as_slice(), [Violation::RssCeiling { ceiling_kib: 1, .. }]),
    "{summary:?}"
  );
  assert_eq!(summary.cycles, 1);
  // Killed, so it has exited.
  let status = child.wait().unwrap();
  assert!(!status.success());
}

#[tokio::test(flavor = "multi_thread")]
async fn max_time_ends_the_run_early() {
  let addr = spawn_fake(Faults::default()).await;
  let mut child = stand_in();
  let mut cfg = config(addr, child.id());
  cfg.cycles = 100;
  cfg.ext.max_time = Some(Duration::from_secs(4));
  let begin = std::time::Instant::now();
  let (summary, _) = run_with(cfg).await;
  let _ = child.kill();
  assert!(begin.elapsed() < Duration::from_secs(8), "{:?}", begin.elapsed());
  assert!(summary.cycles <= 2, "{summary:?}");
  assert_eq!(summary.stopped.as_deref(), Some("max time"), "{summary:?}");
  assert!(summary.violations.is_empty(), "{summary:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_on_first_failure() {
  let addr = spawn_fake(Faults { corrupt_echo: true, ..Faults::default() }).await;
  let mut child = stand_in();
  let mut cfg = config(addr, child.id());
  cfg.cycles = 3;
  cfg.run.duration = Duration::from_secs(10);
  cfg.ext.stop_on_first = true;
  let begin = std::time::Instant::now();
  let (summary, _) = run_with(cfg).await;
  let _ = child.kill();
  assert!(summary.fails > 0, "{summary:?}");
  assert_eq!(summary.cycles, 1, "{summary:?}");
  assert!(begin.elapsed() < Duration::from_secs(5), "{:?}", begin.elapsed());
  assert_eq!(summary.stopped.as_deref(), Some("first failure"), "{summary:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn burst_is_served_by_a_correct_server() {
  let addr = spawn_fake(Faults::default()).await;
  let ctx = config(addr, 0).run.ctx;
  let found = rimu_ws_soak::burst::burst(&ctx, &[], 300, Duration::from_secs(5)).await;
  assert!(found.is_none(), "{found:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn burst_counts_connections_never_served() {
  // Listening but never accepting: connects land in the backlog, upgrades never come.
  let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
  let addr = listener.local_addr().unwrap();
  let ctx = config(addr, 0).run.ctx;
  let found = rimu_ws_soak::burst::burst(&ctx, &[], 20, Duration::from_millis(500)).await;
  assert_eq!(found, Some(Violation::Burst { unserved: 20, n: 20 }));
  drop(listener);
}

#[tokio::test(flavor = "multi_thread")]
async fn burst_phase_runs_after_each_cycle() {
  let addr = spawn_fake(Faults::default()).await;
  let mut child = stand_in();
  let mut cfg = config(addr, child.id());
  cfg.ext.burst = Some(100);
  let (summary, out) = run_with(cfg).await;
  let _ = child.kill();
  assert!(summary.violations.is_empty(), "{summary:?}");
  assert_eq!(lines(&out, "burst").len(), 1);
}
