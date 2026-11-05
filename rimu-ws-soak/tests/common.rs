//! The common mode: the rules every server in the comparison is judged by.

mod support;

use rimu_ws_soak::{
  conn::ConnOpts,
  rng::rng,
  scenario::{
    Ctx, Kind, Limits, Mode, Outcome, Scenario,
    attack::{UpgradeCase, run_upgrade_case},
    invalid::{InvalidCase, run_case},
    profile, run,
  },
};
use std::net::SocketAddr;
use support::{Faults, spawn_fake};

fn ctx_with(addr: SocketAddr, mode: Mode) -> Ctx {
  Ctx {
    addr,
    host: "localhost".into(),
    path: "/".into(),
    limits: Limits::default(),
    mode,
    opts: ConnOpts::default(),
  }
}

fn ctx_common(addr: SocketAddr) -> Ctx {
  ctx_with(addr, Mode::Common)
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_close_without_close_frame_is_should_not_must() {
  let ctx = ctx_common(spawn_fake(Faults { no_close_frame: true, ..Faults::default() }).await);
  for case in [InvalidCase::Unmasked, InvalidCase::BadUtf8, InvalidCase::ReservedOpcode] {
    let outcome = run_case(case, &ctx, &mut rng(1)).await;
    assert!(matches!(outcome, Outcome::Fail { kind: Kind::Should, .. }), "{case:?}: {outcome:?}");
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn correct_fake_passes_every_common_scenario() {
  let ctx = ctx_common(spawn_fake(Faults::default()).await);
  let mut tasks = Vec::new();
  for (scenario, _) in profile("common").unwrap().0 {
    for seed in 0..3 {
      let ctx = ctx.clone();
      tasks.push(tokio::spawn(async move {
        (scenario, seed, run(scenario, &ctx, &mut rng(seed)).await)
      }));
    }
  }
  for task in tasks {
    let (scenario, seed, outcome) = task.await.unwrap();
    assert_eq!(outcome, Outcome::Pass, "{scenario:?} seed {seed}");
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn slowloris_without_handshake_timeout_passes_in_common() {
  let ctx = ctx_common(spawn_fake(Faults::default()).await);
  assert_eq!(run(Scenario::Slowloris, &ctx, &mut rng(1)).await, Outcome::Pass);
}

#[tokio::test(flavor = "multi_thread")]
async fn lax_upgrade_is_a_must_fail_in_common() {
  let ctx = ctx_common(spawn_fake(Faults { lax_upgrade: true, ..Faults::default() }).await);
  let outcome = run_upgrade_case(UpgradeCase::Post, &ctx, &mut rng(1)).await;
  assert!(matches!(outcome, Outcome::Fail { kind: Kind::Must, .. }), "{outcome:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn small_limit_is_marked_not_failed() {
  let ctx = ctx_common(spawn_fake(Faults { max_payload: 64 * 1024, ..Faults::default() }).await);
  for seed in 0..4 {
    let outcome = run(Scenario::FragDrip, &ctx, &mut rng(seed)).await;
    assert!(matches!(outcome, Outcome::Mark { .. }), "seed {seed}: {outcome:?}");
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn late_pong_is_should_in_both_modes() {
  let addr = spawn_fake(Faults { slow_pong: true, ..Faults::default() }).await;
  for mode in [Mode::Strict, Mode::Common] {
    let outcome = run(Scenario::CtrlInFragments, &ctx_with(addr, mode), &mut rng(1)).await;
    assert!(matches!(outcome, Outcome::Fail { kind: Kind::Should, .. }), "{mode:?}: {outcome:?}");
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn strict_mode_is_unchanged_for_missing_close_frame() {
  let addr = spawn_fake(Faults { no_close_frame: true, ..Faults::default() }).await;
  let outcome = run_case(InvalidCase::Unmasked, &ctx_with(addr, Mode::Strict), &mut rng(1)).await;
  assert!(matches!(outcome, Outcome::Fail { .. }), "{outcome:?}");
}

#[test]
fn common_profile_excludes_timed_scenarios() {
  let names: Vec<_> = profile("common").unwrap().0.into_iter().map(|el| el.0).collect();
  for absent in [Scenario::IdlePre, Scenario::IdlePost, Scenario::CloseLinger] {
    assert!(!names.contains(&absent), "{absent:?}");
  }
}
