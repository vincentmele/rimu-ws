//! Cycles of warmup, mixed load, drain, leak check and recovery check, with the monitor and the
//! probes judging the server throughout.

use crate::{
  codec::client_frame,
  conn::{Conn, Next},
  monitor::{
    Baseline, Budgets, Monitor, MonitorError, Sample, Violation, check_drained, check_running,
  },
  probe::{ProbeStats, Probes, lag_exceeds},
  rng::rng,
  runner::{Record, RunConfig, run_slots},
  scenario::Ctx,
};
use std::{
  io::Write,
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
  time::Duration,
};
use tokio::time::{Instant, interval, sleep, timeout};

/// How long a fresh connection may take to upgrade and echo after a drain.
const RECOVERY: Duration = Duration::from_secs(1);

/// Whether one second of probe results breaks the latency invariant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
  Ok,
  /// p99 and its limit, in microseconds.
  Violation(u64, u64),
  /// The probes ran late: the harness, not the server, set their latency.
  Saturated,
}

pub fn latency_verdict(baseline_p99: u64, stats: &ProbeStats) -> Verdict {
  if lag_exceeds(stats.lag_p99_us) {
    return Verdict::Saturated;
  }
  let limit = (5 * baseline_p99).max(baseline_p99 + 1000);
  if stats.count > 0 && stats.p99_us > limit {
    return Verdict::Violation(stats.p99_us, limit);
  }
  Verdict::Ok
}

#[derive(Clone, Debug)]
pub struct CycleConfig {
  pub run: RunConfig,
  pub pid: Option<u32>,
  pub port: u16,
  pub cycles: u32,
  pub warmup: Duration,
  pub drain: Duration,
  pub probes: u32,
  pub probe_rate: u32,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Summary {
  pub cycles: u32,
  pub records: u64,
  pub fails: u64,
  pub harness_errors: u64,
  pub violations: Vec<Violation>,
  pub client_saturated_cycles: u32,
}

/// Writes `value` as one JSON line tagged with `kind`.
fn line(out: &mut dyn Write, kind: &str, value: impl serde::Serialize) {
  let mut json = serde_json::to_value(value).unwrap_or_default();
  match &mut json {
    serde_json::Value::Object(map) => {
      let _ = map.insert("kind".into(), kind.into());
    }
    other => *other = serde_json::json!({ "kind": kind, "value": other.take() }),
  }
  let _ = serde_json::to_writer(&mut *out, &json);
  let _ = out.write_all(b"\n");
}

/// The run so far, for `Monitor` failures that end it.
struct State<'out> {
  monitor: Option<Monitor>,
  out: &'out mut dyn Write,
  summary: Summary,
}

impl State<'_> {
  fn violation(&mut self, cycle: u32, violation: Violation) {
    eprintln!("VIOLATION cycle {cycle}: {violation:?}");
    line(self.out, "violation", serde_json::json!({ "cycle": cycle, "violation": violation }));
    self.summary.violations.push(violation);
  }

  /// A sample, or `None` (after recording `PidGone`) if the server is gone. Without a monitor,
  /// `Some(None)`.
  fn sample(&mut self, cycle: u32) -> Option<Option<Sample>> {
    let Some(monitor) = &mut self.monitor else { return Some(None) };
    match monitor.sample() {
      Ok(sample) => Some(Some(sample)),
      Err(MonitorError::PidGone) => {
        self.violation(cycle, Violation::PidGone);
        None
      }
      Err(MonitorError::Io(err)) => {
        eprintln!("warning: monitor: {err}");
        Some(None)
      }
    }
  }
}

/// Runs the cycles, writing every sample, record and violation to `out` as JSONL.
pub async fn run(cfg: CycleConfig, out: &mut dyn Write) -> Summary {
  let mut state = State { monitor: None, out, summary: Summary::default() };
  match cfg.pid.map(|pid| Monitor::new(pid, cfg.port)) {
    Some(Ok(monitor)) => state.monitor = Some(monitor),
    Some(Err(_)) => {
      state.violation(0, Violation::PidGone);
      return finish(state);
    }
    None => eprintln!("warning: no --pid, so the server is not monitored"),
  }
  let probes =
    (cfg.probes > 0).then(|| Probes::spawn(cfg.run.ctx.clone(), cfg.probes, cfg.probe_rate));
  let mut first_base: Option<Baseline> = None;
  for cycle in 0..cfg.cycles {
    state.summary.cycles = cycle + 1;
    sleep(cfg.warmup).await;
    let warm = probes.as_ref().map(Probes::snapshot).unwrap_or_default();
    let Some(sample) = state.sample(cycle) else { break };
    let base = sample.map(|el| Baseline { rss_kib: el.rss_kib, fds: el.fds });
    let first = *first_base.get_or_insert(base.unwrap_or(Baseline { rss_kib: 0, fds: 0 }));
    line(
      state.out,
      "warmup",
      serde_json::json!({ "cycle": cycle, "probes": warm, "baseline": base }),
    );
    if !mix(&cfg, cycle, &mut state, probes.as_ref(), base, warm.p99_us).await {
      break;
    }
    sleep(cfg.drain).await;
    let Some(sample) = state.sample(cycle) else { break };
    if let Some(sample) = sample {
      line(
        state.out,
        "sample",
        serde_json::json!({ "cycle": cycle, "phase": "drained", "sample": sample }),
      );
      for violation in check_drained(&first, &sample) {
        state.violation(cycle, violation);
      }
    }
    if let Err(reason) = recovery(&cfg.run.ctx).await {
      state.violation(cycle, Violation::NoRecovery(reason));
    }
  }
  if let Some(probes) = probes {
    probes.stop();
  }
  finish(state)
}

fn finish(state: State<'_>) -> Summary {
  line(state.out, "summary", &state.summary);
  let _ = state.out.flush();
  state.summary
}

/// The mixed load, sampled once a second. `false` if the server is gone.
async fn mix(
  cfg: &CycleConfig,
  cycle: u32,
  state: &mut State<'_>,
  probes: Option<&Probes>,
  base: Option<Baseline>,
  baseline_p99: u64,
) -> bool {
  let (tx, mut rx) = tokio::sync::mpsc::channel::<Record>(4096);
  let stop = Arc::new(AtomicBool::new(false));
  let run = cfg.run.clone();
  let runner = {
    let stop = stop.clone();
    tokio::spawn(async move { run_slots(&run, stop, tx).await })
  };
  let end = Instant::now() + cfg.run.duration;
  let mut tick = interval(Duration::from_secs(1));
  let _ = tick.tick().await;
  let budgets = Budgets { slots: cfg.run.slots };
  let (mut streak, mut saturated, mut alive) = (0, false, true);
  loop {
    tokio::select! {
      record = rx.recv() => {
        let Some(record) = record else { break };
        state.summary.records += 1;
        match record.outcome {
          "fail" => {
            state.summary.fails += 1;
            eprintln!(
              "FAIL {:?} replay={} — {}",
              record.scenario,
              record.replay,
              record.reason.as_deref().unwrap_or_default()
            );
          }
          "harness_error" => state.summary.harness_errors += 1,
          _ => {}
        }
        line(state.out, "record", &record);
      }
      _ = tick.tick() => {
        if Instant::now() >= end {
          stop.store(true, Ordering::Relaxed);
        }
        let Some(sample) = state.sample(cycle) else {
          stop.store(true, Ordering::Relaxed);
          alive = false;
          continue;
        };
        let stats = probes.map(Probes::snapshot).unwrap_or_default();
        line(state.out, "sample", serde_json::json!({ "cycle": cycle, "sample": sample, "probes": stats }));
        if let (Some(sample), Some(base)) = (sample, base) {
          let live = cfg.run.slots + cfg.probes;
          for violation in check_running(&base, &sample, live, &budgets, &mut streak) {
            state.violation(cycle, violation);
          }
        }
        match latency_verdict(baseline_p99, &stats) {
          Verdict::Ok => {}
          Verdict::Saturated => saturated = true,
          Verdict::Violation(p99_us, limit_us) => {
            state.violation(cycle, Violation::Latency { p99_us, limit_us });
          }
        }
      }
    }
  }
  let _ = runner.await;
  if saturated {
    eprintln!(
      "warning: cycle {cycle}: probes lagged over 1 ms, latency not judged for those seconds"
    );
    state.summary.client_saturated_cycles += 1;
  }
  alive
}

/// A fresh connection upgrades and echoes within `RECOVERY`.
async fn recovery(ctx: &Ctx) -> Result<(), String> {
  let attempt = async {
    let mut rng = rng(0);
    let mut conn = Conn::connect(ctx.addr, &ctx.opts).await.map_err(|err| format!("{err:?}"))?;
    conn.upgrade(&ctx.host, &ctx.path, &mut rng).await.map_err(|err| format!("{err:?}"))?;
    let mut frame = Vec::new();
    client_frame(true, 1, b"recovery", [1, 2, 3, 4], &mut frame);
    conn.send(&frame).await.map_err(|err| format!("{err:?}"))?;
    match conn.next_frame(Instant::now() + RECOVERY).await {
      Ok(Next::Frame(echo)) if echo.payload == b"recovery" => Ok(()),
      other => Err(format!("no echo: {other:?}")),
    }
  };
  timeout(RECOVERY, attempt).await.unwrap_or_else(|_| Err(format!("not within {RECOVERY:?}")))
}
