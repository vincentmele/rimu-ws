mod support;

use rimu_ws_soak::{
  conn::ConnOpts,
  rng::rng,
  scenario::{Ctx, Limits, Outcome, Scenario, run, slack},
};
use std::{net::SocketAddr, time::Duration};
use support::{Faults, spawn_fake};
use tokio::time::Instant;

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
      max_payload: 1 << 20,
      never_read_budget: Duration::from_secs(5),
      server_sndbuf: None,
    },
    mode: rimu_ws_soak::scenario::Mode::Strict,
    opts: ConnOpts::default(),
  }
}

fn timed_out() -> Faults {
  Faults { handshake_timeout: Some(LIMIT), idle_timeout: Some(LIMIT), ..Faults::default() }
}

const ABUSE: [Scenario; 9] = [
  Scenario::NeverRead,
  Scenario::Slowloris,
  Scenario::IdlePre,
  Scenario::IdlePost,
  Scenario::CloseInHandshake,
  Scenario::RstMidframe,
  Scenario::HalfClose,
  Scenario::PingFlood,
  Scenario::Garbage,
];

#[tokio::test(flavor = "multi_thread")]
async fn abuse_scenarios_pass_on_fake_with_timeouts() {
  let ctx = ctx(spawn_fake(timed_out()).await);
  for scenario in ABUSE {
    for seed in 0..20 {
      let outcome = run(scenario, &ctx, &mut rng(seed)).await;
      assert_eq!(outcome, Outcome::Pass, "{scenario:?} seed {seed}");
    }
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_post_fails_without_server_timeout() {
  let ctx = ctx(spawn_fake(Faults::default()).await);
  let begin = Instant::now();
  let outcome = run(Scenario::IdlePost, &ctx, &mut rng(1)).await;
  let elapsed = begin.elapsed();
  assert!(matches!(outcome, Outcome::Fail { .. }), "{outcome:?}");
  assert!(elapsed >= slack(LIMIT) && elapsed < Duration::from_millis(900), "{elapsed:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn slowloris_fails_without_handshake_timeout() {
  // The trickle keeps an idle timeout from firing: only the handshake timeout catches it.
  let faults = Faults { idle_timeout: Some(LIMIT), ..Faults::default() };
  let ctx = ctx(spawn_fake(faults).await);
  let outcome = run(Scenario::Slowloris, &ctx, &mut rng(1)).await;
  assert!(matches!(outcome, Outcome::Fail { .. }), "{outcome:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn timeout_edge() {
  let late = Faults { idle_timeout: Some(LIMIT * 6 / 5), ..Faults::default() };
  let ctx_late = ctx(spawn_fake(late).await);
  assert_eq!(run(Scenario::IdlePost, &ctx_late, &mut rng(2)).await, Outcome::Pass);
  let ctx_never = ctx(spawn_fake(Faults::default()).await);
  let begin = Instant::now();
  let outcome = run(Scenario::IdlePost, &ctx_never, &mut rng(2)).await;
  assert!(matches!(outcome, Outcome::Fail { .. }), "{outcome:?}");
  assert!(begin.elapsed() <= slack(LIMIT) + Duration::from_millis(100), "{:?}", begin.elapsed());
}

#[tokio::test(flavor = "multi_thread")]
async fn never_read_fails_on_unbounded_server() {
  let mut ctx = ctx(spawn_fake(Faults { unbounded_reads: true, ..Faults::default() }).await);
  ctx.limits.never_read_budget = Duration::from_secs(1);
  match run(Scenario::NeverRead, &ctx, &mut rng(3)).await {
    Outcome::Fail { reason, .. } => assert!(reason.contains("without bound"), "{reason}"),
    other => panic!("{other:?}"),
  }
}
