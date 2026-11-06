//! Each attack and resource oracle passes a correct server and fails a broken one.

mod support;

use rimu_ws_soak::{
  conn::ConnOpts,
  rng::rng,
  scenario::{Proto, 
    Ctx, Limits, Outcome, Scenario, Weights,
    attack::{UpgradeCase, run_upgrade_case},
    parse_weights, profile,
    resource::linger_verdict,
    run,
  },
};
use std::{net::SocketAddr, time::Duration};
use support::{Faults, spawn_fake};

const LIMIT: Duration = Duration::from_millis(300);

fn ctx(addr: SocketAddr) -> Ctx {
  Ctx {
    addr,
    host: "localhost".into(),
    path: "/".into(),
    limits: Limits {
      handshake: LIMIT,
      idle: LIMIT,
      close: LIMIT,
      max_payload: 256 * 1024,
      never_read_budget: Duration::from_secs(5),
      server_sndbuf: None,
    },
    opts: ConnOpts::default(),
    proto: Proto::Ws,
  }
}

fn faults() -> Faults {
  Faults {
    handshake_timeout: Some(LIMIT),
    idle_timeout: Some(LIMIT),
    max_payload: 256 * 1024,
    ..Faults::default()
  }
}

fn is_fail(outcome: &Outcome) -> bool {
  matches!(outcome, Outcome::Fail { .. })
}

#[tokio::test(flavor = "multi_thread")]
async fn every_upgrade_case_passes_a_strict_server() {
  let ctx = ctx(spawn_fake(faults()).await);
  for case in UpgradeCase::ALL {
    for seed in 0..3 {
      let outcome = run_upgrade_case(case, &ctx, &mut rng(seed)).await;
      assert_eq!(outcome, Outcome::Pass, "{case:?} seed {seed}");
    }
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrading_what_must_be_refused_fails() {
  let ctx = ctx(spawn_fake(Faults { lax_upgrade: true, ..faults() }).await);
  for case in UpgradeCase::ALL.into_iter().filter(|el| el.must_refuse()) {
    // A lax server still needs a key to answer.
    if case == UpgradeCase::NoKey {
      continue;
    }
    let outcome = run_upgrade_case(case, &ctx, &mut rng(0)).await;
    assert!(is_fail(&outcome), "{case:?}: {outcome:?}");
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn header_flood_passes_a_capped_server_and_fails_an_uncapped_one() {
  let ctx_ok = ctx(spawn_fake(faults()).await);
  for seed in 0..5 {
    let outcome = run(Scenario::HeaderFlood, &ctx_ok, &mut rng(seed)).await;
    assert_eq!(outcome, Outcome::Pass, "seed {seed}");
  }
  // No cap, and no handshake timeout to save it.
  let uncapped =
    Faults { header_cap: None, handshake_timeout: None, idle_timeout: None, ..faults() };
  let ctx_bad = ctx(spawn_fake(uncapped).await);
  let outcome = run(Scenario::HeaderFlood, &ctx_bad, &mut rng(0)).await;
  assert!(is_fail(&outcome), "{outcome:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn floods_of_tiny_frames_are_echoed() {
  let ctx_ok = ctx(spawn_fake(faults()).await);
  let ctx_bad = ctx(spawn_fake(Faults { corrupt_echo: true, ..faults() }).await);
  for scenario in [Scenario::FragFlood, Scenario::ZeroFlood] {
    for seed in 0..3 {
      let outcome = run(scenario, &ctx_ok, &mut rng(seed)).await;
      assert_eq!(outcome, Outcome::Pass, "{scenario:?} seed {seed}");
    }
  }
  let outcome = run(Scenario::FragFlood, &ctx_bad, &mut rng(0)).await;
  assert!(is_fail(&outcome), "{outcome:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn frag_drip_is_echoed_under_the_limit_and_refused_over_it() {
  let ctx_ok = ctx(spawn_fake(faults()).await);
  for seed in 0..12 {
    let outcome = run(Scenario::FragDrip, &ctx_ok, &mut rng(seed)).await;
    assert_eq!(outcome, Outcome::Pass, "seed {seed}");
  }
  // A server without a limit on fragmented messages: some seed goes over the limit.
  let ctx_bad = ctx(spawn_fake(Faults { max_payload: u64::MAX, ..faults() }).await);
  let mut fails = 0;
  for seed in 0..12 {
    fails += usize::from(is_fail(&run(Scenario::FragDrip, &ctx_bad, &mut rng(seed)).await));
  }
  assert!(fails > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_reader_and_ping_no_read() {
  let ctx_ok = ctx(spawn_fake(faults()).await);
  for scenario in [Scenario::SlowReader, Scenario::PingNoRead] {
    for seed in 0..3 {
      let outcome = run(scenario, &ctx_ok, &mut rng(seed)).await;
      assert_eq!(outcome, Outcome::Pass, "{scenario:?} seed {seed}");
    }
  }
  let ctx_bad = ctx(spawn_fake(Faults { corrupt_echo: true, ..faults() }).await);
  assert!(is_fail(&run(Scenario::SlowReader, &ctx_bad, &mut rng(0)).await));
  // Reads everything and answers nothing: the pings never block.
  let ctx_bad = ctx(spawn_fake(Faults { unbounded_reads: true, ..faults() }).await);
  assert!(is_fail(&run(Scenario::PingNoRead, &ctx_bad, &mut rng(0)).await));
}

#[test]
fn a_close_that_still_arrives_means_the_reply_was_kept() {
  assert!(linger_verdict(false, LIMIT).is_ok());
  assert!(linger_verdict(true, LIMIT).is_err());
}

#[test]
fn close_linger_is_left_out_without_the_server_send_buffer() {
  let weights = parse_weights("echo=1,close_linger=5").unwrap();
  let limits = Limits::default();
  let kept = weights.for_limits(&limits).unwrap();
  assert_eq!(kept.0, [(Scenario::Echo, 1)]);
  let with = Limits { server_sndbuf: Some(16384), ..Limits::default() };
  assert_eq!(weights.for_limits(&with).unwrap().0.len(), 2);
  let only = parse_weights("close_linger=5").unwrap();
  assert!(only.for_limits(&limits).is_err());
}

#[test]
fn every_profile_parses_and_untimed_needs_no_timeouts() {
  for name in ["baseline", "hostile", "attack", "storm", "untimed", "drip"] {
    assert!(profile(name, Proto::Ws).is_some(), "{name}");
  }
  let Weights(untimed) = profile("untimed", Proto::Ws).unwrap();
  for timed in [
    Scenario::Slowloris,
    Scenario::IdlePre,
    Scenario::IdlePost,
    Scenario::Garbage,
    Scenario::HeaderFlood,
    Scenario::CloseLinger,
  ] {
    assert!(untimed.iter().all(|el| el.0 != timed), "{timed:?}");
  }
}
