mod support;

use rimu_ws_soak::{
  conn::ConnOpts,
  rng::rng,
  scenario::{Proto, 
    Ctx, Limits, Outcome, Scenario,
    invalid::{InvalidCase, expected_codes, run_case},
    run,
  },
};
use std::net::SocketAddr;
use support::{Faults, spawn_fake};

fn ctx(addr: SocketAddr) -> Ctx {
  Ctx {
    addr,
    host: "localhost".into(),
    path: "/".into(),
    limits: Limits::default(),
    opts: ConnOpts::default(),
    proto: Proto::Ws,
  }
}

#[test]
fn expected_codes_follow_rfc_6455() {
  assert_eq!(expected_codes(InvalidCase::BadUtf8), [1007]);
  assert_eq!(expected_codes(InvalidCase::Oversized), [1009]);
  assert_eq!(expected_codes(InvalidCase::Unmasked), [1002]);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_case_passes_on_fake() {
  let ctx = ctx(spawn_fake(Faults::default()).await);
  for case in InvalidCase::ALL {
    for seed in 0..5 {
      assert_eq!(run_case(case, &ctx, &mut rng(seed)).await, Outcome::Pass, "{case:?} seed {seed}");
    }
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_code_fails() {
  let ctx = ctx(spawn_fake(Faults { close_code_for_bad_utf8: 1002, ..Faults::default() }).await);
  match run_case(InvalidCase::BadUtf8, &ctx, &mut rng(1)).await {
    Outcome::Fail { reason, .. } => {
      assert!(reason.contains("1002") && reason.contains("1007"), "{reason}");
    }
    other => panic!("{other:?}"),
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn huge_len_passes_and_fails_by_code() {
  let good = ctx(spawn_fake(Faults::default()).await);
  let bad = ctx(spawn_fake(Faults { huge_len_code: 1000, ..Faults::default() }).await);
  for seed in 0..6 {
    assert_eq!(run(Scenario::HugeLen, &good, &mut rng(seed)).await, Outcome::Pass, "seed {seed}");
    let outcome = run(Scenario::HugeLen, &bad, &mut rng(seed)).await;
    assert!(matches!(outcome, Outcome::Fail { .. }), "seed {seed}: {outcome:?}");
  }
}
