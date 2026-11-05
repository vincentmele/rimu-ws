//! Client slots, each running scenario after scenario, and replaying one run by its id.

use crate::{
  rng::{rng, seed_for},
  scenario::{self, Ctx, Outcome, Scenario, Weights},
};
use std::{
  net::IpAddr,
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
  time::{Duration, Instant},
};

/// What `run_slots` runs.
#[derive(Clone, Debug)]
pub struct RunConfig {
  pub global_seed: u64,
  pub slots: u32,
  pub duration: Duration,
  pub weights: Weights,
  pub ctx: Ctx,
  /// Slot `i` connects from `source_ips[i % len]`; empty uses the default.
  pub source_ips: Vec<IpAddr>,
}

/// One scenario run.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Record {
  pub slot: u32,
  pub generation: u32,
  pub seed: u64,
  pub replay: String,
  pub scenario: Scenario,
  /// `"pass"`, `"fail"` or `"harness_error"`.
  pub outcome: &'static str,
  pub reason: Option<String>,
  pub transcript: Option<String>,
  pub elapsed_ms: u64,
  /// Set by the cycle when the probes showed the harness's CPU saturated in this run's second.
  #[serde(skip_serializing_if = "core::ops::Not::not")]
  pub client_saturated: bool,
}

pub fn replay_id(global: u64, slot: u32, generation: u32) -> String {
  format!("{global}:{slot}:{generation}")
}

pub fn parse_replay(s: &str) -> Option<(u64, u32, u32)> {
  let mut parts = s.split(':');
  let id = (parts.next()?.parse().ok()?, parts.next()?.parse().ok()?, parts.next()?.parse().ok()?);
  parts.next().is_none().then_some(id)
}

/// Runs every slot until `stop`, sending each run's record to `sink`.
pub async fn run_slots(
  cfg: &RunConfig,
  stop: Arc<AtomicBool>,
  sink: tokio::sync::mpsc::Sender<Record>,
) {
  let weights = Arc::new(cfg.weights.clone());
  let handles: Vec<_> = (0..cfg.slots)
    .map(|slot| {
      let mut ctx = cfg.ctx.clone();
      if !cfg.source_ips.is_empty() {
        ctx.opts.source_ip = Some(cfg.source_ips[slot as usize % cfg.source_ips.len()]);
      }
      let (global, weights, stop, sink) =
        (cfg.global_seed, weights.clone(), stop.clone(), sink.clone());
      tokio::spawn(async move {
        let mut generation = 0;
        while !stop.load(Ordering::Relaxed) {
          let record = run_one(&ctx, &weights, global, slot, generation).await;
          if sink.send(record).await.is_err() {
            break;
          }
          generation += 1;
        }
      })
    })
    .collect();
  drop(sink);
  for handle in handles {
    let _ = handle.await;
  }
}

/// Runs generation `id.2` of slot `id.1` of the run seeded `id.0` again.
pub async fn replay(ctx: &Ctx, weights: &Weights, id: (u64, u32, u32)) -> Record {
  run_one(ctx, weights, id.0, id.1, id.2).await
}

async fn run_one(ctx: &Ctx, weights: &Weights, global: u64, slot: u32, generation: u32) -> Record {
  let seed = seed_for(global, slot, generation);
  let mut rng = rng(seed);
  let scenario = weights.pick(&mut rng);
  let begin = Instant::now();
  let outcome = scenario::run(scenario, ctx, &mut rng).await;
  let elapsed_ms = begin.elapsed().as_millis() as u64;
  let (outcome, reason, transcript) = match outcome {
    Outcome::Pass => ("pass", None, None),
    Outcome::Fail { reason, transcript, .. } => ("fail", Some(reason), Some(transcript)),
    Outcome::Mark { reason } => ("mark", Some(reason), None),
    Outcome::HarnessError(reason) => ("harness_error", Some(reason), None),
  };
  Record {
    slot,
    generation,
    seed,
    replay: replay_id(global, slot, generation),
    scenario,
    outcome,
    reason,
    transcript,
    elapsed_ms,
    client_saturated: false,
  }
}
