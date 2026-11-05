mod support;

use rimu_ws_soak::{
  conn::ConnOpts,
  rng::{rng, seed_for},
  runner::{Record, RunConfig, replay, replay_id, run_slots},
  scenario::{Ctx, Limits, Outcome, Scenario, Weights, parse_weights, profile, run},
};
use std::{
  net::SocketAddr,
  sync::{Arc, Mutex, atomic::AtomicBool},
  time::Duration,
};
use support::{Faults, spawn_fake};

pub fn ctx(addr: SocketAddr) -> Ctx {
  Ctx {
    addr,
    host: "localhost".into(),
    path: "/".into(),
    limits: Limits {
      handshake: Duration::from_millis(300),
      idle: Duration::from_millis(300),
      close: Duration::from_millis(300),
      max_payload: 1 << 20,
      ..Limits::default()
    },
    mode: rimu_ws_soak::scenario::Mode::Strict,
    opts: ConnOpts::default(),
  }
}

#[test]
fn weights_pick_matches_profile() {
  let weights = profile("hostile").unwrap();
  let mut rng = rng(5);
  let echo = (0..100_000).filter(|_| weights.pick(&mut rng) == Scenario::Echo).count();
  let share = echo as f64 / 100_000.0;
  let total: u32 = weights.0.iter().map(|el| el.1).sum();
  let want =
    f64::from(weights.0.iter().find(|el| el.0 == Scenario::Echo).unwrap().1) / f64::from(total);
  assert!((share - want).abs() < 0.01, "{share} vs {want}");
  assert!(profile("baseline").is_some() && profile("storm").is_some() && profile("x").is_none());
}

#[test]
fn parse_weights_rejects_unknown() {
  let err = parse_weights("echo=1,nope=2").unwrap_err();
  assert!(err.contains("nope"), "{err}");
  let ok = parse_weights("echo=40,garbage=4").unwrap();
  assert_eq!(ok.0, vec![(Scenario::Echo, 40), (Scenario::Garbage, 4)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn echo_scenarios_pass_on_good_server() {
  let ctx = ctx(spawn_fake(Faults::default()).await);
  for scenario in [Scenario::Echo, Scenario::SplitEveryByte, Scenario::CtrlInFragments] {
    for seed in 0..200 {
      let outcome = run(scenario, &ctx, &mut rng(seed)).await;
      assert_eq!(outcome, Outcome::Pass, "{scenario:?} seed {seed}");
    }
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupted_echo_fails_with_transcript() {
  let ctx = ctx(spawn_fake(Faults { corrupt_echo: true, ..Faults::default() }).await);
  let mut failed = false;
  for seed in 0..50 {
    if let Outcome::Fail { transcript, .. } = run(Scenario::Echo, &ctx, &mut rng(seed)).await {
      assert!(!transcript.is_empty());
      failed = true;
    }
  }
  assert!(failed);
}

#[tokio::test(flavor = "multi_thread")]
async fn early_close_is_server_closed_during_echo() {
  let ctx = ctx(spawn_fake(Faults { close_mid_echo_after: Some(1), ..Faults::default() }).await);
  let mut failed = 0;
  for seed in 0..50 {
    match run(Scenario::Echo, &ctx, &mut rng(seed)).await {
      Outcome::Fail { reason, .. } => {
        assert!(reason.contains("server closed during echo"), "{reason}");
        failed += 1;
      }
      Outcome::Pass => {}
      other => panic!("{other:?}"),
    }
  }
  assert!(failed > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_reproduces_scenario_and_bytes() {
  let weights = Weights(vec![(Scenario::Echo, 1), (Scenario::CtrlInFragments, 1)]);
  let cfg = RunConfig {
    global_seed: 42,
    slots: 8,
    duration: Duration::from_secs(1),
    weights: weights.clone(),
    ctx: ctx(spawn_fake(Faults::default()).await),
    source_ips: Vec::new(),
  };
  let (tx, mut rx) = tokio::sync::mpsc::channel::<Record>(1024);
  let stop = Arc::new(AtomicBool::new(false));
  let stopper = stop.clone();
  let _timer = tokio::spawn(async move {
    tokio::time::sleep(Duration::from_secs(1)).await;
    stopper.store(true, std::sync::atomic::Ordering::Relaxed);
  });
  let runner = tokio::spawn(async move { run_slots(&cfg, stop, tx).await });
  let mut target = None;
  while let Some(record) = rx.recv().await {
    assert_eq!(record.outcome, "pass", "{record:?}");
    if (record.slot, record.generation) == (7, 3) {
      target = Some(record);
    }
  }
  runner.await.unwrap();
  let target = target.expect("slot 7 reached generation 3");
  assert_eq!(target.replay, replay_id(42, 7, 3));
  assert_eq!(target.seed, seed_for(42, 7, 3));
  let mut logs = Vec::new();
  for _ in 0..2 {
    let log = Arc::new(Mutex::new(Vec::new()));
    let addr = spawn_fake(Faults { log: Some(log.clone()), ..Faults::default() }).await;
    let again = replay(&ctx(addr), &weights, (42, 7, 3)).await;
    assert_eq!((again.scenario, again.outcome), (target.scenario, "pass"));
    logs.push(log.lock().unwrap().clone());
  }
  assert_eq!(logs[0].len(), 1);
  assert!(!logs[0][0].is_empty());
  assert_eq!(logs[0], logs[1]);
}
