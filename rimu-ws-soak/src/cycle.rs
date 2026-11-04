//! Cycles of warmup, mixed load, drain, leak check and recovery check, with the monitor and the
//! probes judging the server throughout.

use crate::{
  codec::client_frame,
  conn::{Conn, Next},
  monitor::{
    Baseline, Budgets, Monitor, MonitorError, Sample, Violation, check_drained, check_running,
  },
  probe::{ProbeStats, ProbeTotals, Probes, lag_exceeds},
  rng::rng,
  runner::{Record, RunConfig, run_slots},
  scenario::{Ctx, Weights},
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

/// How long a fresh connection may take to upgrade and echo after a drain, and after a flood.
const RECOVERY: Duration = Duration::from_secs(1);
const FLOOD_RECOVERY: Duration = Duration::from_secs(2);
/// How long the flood is held.
const FLOOD_HOLD: Duration = Duration::from_secs(10);
/// How long each connection of a burst may take to connect, upgrade and echo.
const BURST_WITHIN: Duration = Duration::from_secs(5);
/// The least rise, over the cycles judged, that counts as a trend.
const TREND_MIN_KIB: u64 = 8 * 1024;

/// Whether one second of probe results breaks the latency invariant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
  Ok,
  /// p99 and its limit, in microseconds.
  Violation(u64, u64),
  /// The probes ran late: the harness, not the server, set their latency.
  Saturated,
  /// Probes whose echo never came.
  Failures(u64),
}

/// The seed cycle `cycle` runs its slots with: cycle 0 keeps `global`, later cycles draw new
/// inputs. Replay ids carry it, so they replay as they are.
pub fn cycle_seed(global: u64, cycle: u32) -> u64 {
  if cycle == 0 { global } else { crate::rng::seed_for(global, u32::MAX, cycle) }
}

/// The stderr line of a failed run.
pub fn fail_line(record: &Record) -> String {
  format!(
    "FAIL {:?} replay={} — {}{}",
    record.scenario,
    record.replay,
    record.reason.as_deref().unwrap_or_default(),
    if record.client_saturated { " (client saturated: may be the harness)" } else { "" }
  )
}

/// One second of probe results against the warmup's.
pub fn latency_verdict(warm: &ProbeStats, stats: &ProbeStats) -> Verdict {
  if stats.failures > 0 {
    return Verdict::Failures(stats.failures);
  }
  if lag_exceeds(stats.lag_p99_us, warm.lag_p99_us) {
    return Verdict::Saturated;
  }
  let baseline_p99 = warm.p99_us;
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
  /// Connections the descriptor flood opens after each drain check, if any.
  pub fd_flood: Option<u32>,
  pub ext: Extended,
}

/// Which scenario runs `--out` keeps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RecordMode {
  #[default]
  All,
  /// Failures and harness errors only: a long run makes millions of passing records.
  Failures,
}

/// What long runs add to the cycles.
#[derive(Clone, Debug, Default)]
pub struct Extended {
  /// Cycle `i` runs profile `i % len`; empty runs `RunConfig::weights` every cycle.
  pub rotation: Vec<(String, Weights)>,
  pub records: RecordMode,
  /// How often a `heartbeat` line sums up the run so far.
  pub heartbeat: Option<Duration>,
  /// Cycles in a row the memory after the drain, or its peak, may rise before that counts as a
  /// leak. 0 turns the check off.
  pub trend: u32,
  /// RSS past which the server is killed, which ends the run.
  pub rss_ceiling_kib: Option<u64>,
  /// No new cycle, and no more load, this long into the run.
  pub max_time: Option<Duration>,
  /// Ends the run at the first failure or violation.
  pub stop_on_first: bool,
  /// After each cycle's recovery check, this many connections at once.
  pub burst: Option<u32>,
}

/// A `Trend` if `values` (one per cycle, in KiB) rose in each of the last `cycles` cycles, by more
/// than 8 MiB and 2% in all.
pub fn trend_violation(what: &str, values: &[u64], cycles: u32) -> Option<Violation> {
  let k = cycles as usize;
  if k == 0 || values.len() <= k {
    return None;
  }
  let window = &values[values.len() - k - 1..];
  let rising = window.windows(2).all(|el| el[1] > el[0]);
  let rise = window[k].saturating_sub(window[0]);
  (rising && rise > TREND_MIN_KIB.max(window[0] / 50)).then(|| {
    Violation::Trend(format!("{what} rose in each of the last {k} cycles: {window:?} KiB"))
  })
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Summary {
  pub cycles: u32,
  pub records: u64,
  pub fails: u64,
  pub harness_errors: u64,
  pub violations: Vec<Violation>,
  pub client_saturated_cycles: u32,
  /// Fails while the probes showed the harness saturated: some may be the harness's.
  pub fails_while_saturated: u64,
  /// The probes over the whole run.
  pub latency: ProbeTotals,
  /// Why the run ended before its last cycle, if it did: `max time`, `first failure` or `rss
  /// ceiling`.
  pub stopped: Option<String>,
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
  ceiling_kib: Option<u64>,
  // Memory after each drain, and its peak, for the trend check.
  drained: Vec<u64>,
  // Set once the server is gone, which is reported once.
  gone: bool,
  last_beat: Instant,
  last_sample: Option<Sample>,
  monitor: Option<Monitor>,
  out: &'out mut dyn Write,
  peaks: Vec<u64>,
  // The cycle's profile, when they rotate
  profile: Option<String>,
  started: Instant,
  // Why the run is to end early.
  stop: Option<&'static str>,
  stop_on_first: bool,
  summary: Summary,
}

impl State<'_> {
  fn violation(&mut self, cycle: u32, violation: Violation) {
    eprintln!("VIOLATION cycle {cycle}: {violation:?}");
    line(self.out, "violation", serde_json::json!({ "cycle": cycle, "violation": violation }));
    self.summary.violations.push(violation);
    if self.stop_on_first {
      let _ = self.stop.get_or_insert("first failure");
    }
  }

  fn heartbeat(&mut self, cycle: u32, probes: Option<&Probes>) {
    self.last_beat = Instant::now();
    let latency = probes.map(Probes::totals).unwrap_or_default();
    let elapsed_s = self.started.elapsed().as_secs();
    let s = &self.summary;
    eprintln!(
      "heartbeat {elapsed_s}s cycle {cycle}: {} records, {} fails, {} harness errors, {} violations, rss {:?} KiB, p99 {} us",
      s.records,
      s.fails,
      s.harness_errors,
      s.violations.len(),
      self.last_sample.map(|el| el.rss_kib),
      latency.p99_us,
    );
    let beat = serde_json::json!({
      "elapsed_s": elapsed_s,
      "cycle": cycle,
      "records": s.records,
      "fails": s.fails,
      "harness_errors": s.harness_errors,
      "violations": s.violations.len(),
      "sample": self.last_sample,
      "latency": latency,
    });
    line(self.out, "heartbeat", beat);
  }

  /// Checks the memory after a drain, and its peak so far, for a rise over the last `cycles`.
  fn trend(&mut self, cycle: u32, sample: &Sample, cycles: u32) {
    self.drained.push(sample.rss_kib);
    self.peaks.push(sample.hwm_kib);
    for (what, peak) in [("RSS after the drain", false), ("peak RSS", true)] {
      let values = if peak { &mut self.peaks } else { &mut self.drained };
      if let Some(violation) = trend_violation(what, values, cycles) {
        // Judged afresh from here, so a rise is reported once per `cycles` cycles.
        values.clear();
        self.violation(cycle, violation);
      }
    }
  }

  /// A sample, or `None` if the server is gone (recorded the first time). Without a monitor,
  /// `Some(None)`. Sampling reads the whole TCP table, so it runs off the runtime's workers.
  async fn sample(&mut self, cycle: u32) -> Option<Option<Sample>> {
    if self.gone {
      return None;
    }
    let mut monitor = self.monitor.take()?;
    let (monitor, rslt) = match tokio::task::spawn_blocking(move || {
      let rslt = monitor.sample();
      (monitor, rslt)
    })
    .await
    {
      Ok(el) => el,
      Err(_) => return Some(None),
    };
    let pid = monitor.pid();
    self.monitor = Some(monitor);
    match rslt {
      Ok(sample) => {
        self.last_sample = Some(sample);
        if let Some(ceiling_kib) = self.ceiling_kib.filter(|el| sample.rss_kib > *el) {
          // SAFETY: no pointers
          let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
          self.gone = true;
          let _ = self.stop.get_or_insert("rss ceiling");
          self.violation(cycle, Violation::RssCeiling { rss_kib: sample.rss_kib, ceiling_kib });
          return None;
        }
        Some(Some(sample))
      }
      Err(MonitorError::PidGone) => {
        self.gone = true;
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
  let started = Instant::now();
  let mut state = State {
    ceiling_kib: cfg.ext.rss_ceiling_kib,
    drained: Vec::new(),
    gone: false,
    last_beat: started,
    last_sample: None,
    monitor: None,
    out,
    peaks: Vec::new(),
    profile: None,
    started,
    stop: None,
    stop_on_first: cfg.ext.stop_on_first,
    summary: Summary::default(),
  };
  match cfg.pid.map(|pid| Monitor::new(pid, cfg.port)) {
    Some(Ok(monitor)) => state.monitor = Some(monitor),
    Some(Err(_)) => {
      state.violation(0, Violation::PidGone);
      return finish(state);
    }
    None => eprintln!("warning: no --pid, so the server is not monitored"),
  }
  let deadline = cfg.ext.max_time.map(|el| started + el);
  let probes =
    (cfg.probes > 0).then(|| Probes::spawn(cfg.run.ctx.clone(), cfg.probes, cfg.probe_rate));
  let mut first_base: Option<Baseline> = None;
  for cycle in 0..cfg.cycles {
    if deadline.is_some_and(|el| Instant::now() >= el) {
      let _ = state.stop.get_or_insert("max time");
    }
    if state.stop.is_some() {
      break;
    }
    state.summary.cycles = cycle + 1;
    sleep(cfg.warmup).await;
    let warm = probes.as_ref().map(Probes::snapshot).unwrap_or_default();
    let Some(sample) = state.sample(cycle).await else { break };
    let base = sample.map(|el| Baseline { rss_kib: el.rss_kib, fds: el.fds });
    let first = *first_base.get_or_insert(base.unwrap_or(Baseline { rss_kib: 0, fds: 0 }));
    let rotation = (!cfg.ext.rotation.is_empty())
      .then(|| &cfg.ext.rotation[cycle as usize % cfg.ext.rotation.len()]);
    line(
      state.out,
      "warmup",
      serde_json::json!({
        "cycle": cycle,
        "probes": warm,
        "baseline": base,
        "profile": rotation.map(|el| &el.0),
      }),
    );
    let mut run = cfg.run.clone();
    if let Some((name, weights)) = rotation {
      run.weights = weights.clone();
      state.profile = Some(name.clone());
    }
    let end = deadline.map_or(Instant::now() + run.duration, |el| el.min(Instant::now() + run.duration));
    if !mix(&cfg, run, end, cycle, &mut state, probes.as_ref(), base, &warm).await {
      break;
    }
    if state.stop.is_some() {
      break;
    }
    sleep(cfg.drain).await;
    let Some(sample) = state.sample(cycle).await else { break };
    if let Some(sample) = sample {
      line(
        state.out,
        "sample",
        serde_json::json!({ "cycle": cycle, "phase": "drained", "sample": sample }),
      );
      for violation in check_drained(&first, &sample) {
        state.violation(cycle, violation);
      }
      state.trend(cycle, &sample, cfg.ext.trend);
    }
    if let Err(reason) = recovery(&cfg.run.ctx, RECOVERY).await {
      state.violation(cycle, Violation::NoRecovery(reason));
    }
    if let Some(n) = cfg.ext.burst {
      let found = crate::burst::burst(&cfg.run.ctx, &cfg.run.source_ips, n, BURST_WITHIN).await;
      line(state.out, "burst", serde_json::json!({ "cycle": cycle, "n": n, "violation": found }));
      if let Some(violation) = found {
        state.violation(cycle, violation);
      }
    }
    if let Some(n) = cfg.fd_flood {
      let Some(monitor) = state.monitor.as_mut() else {
        eprintln!("warning: the fd flood needs --pid; skipped");
        continue;
      };
      let found =
        crate::fdflood::fd_flood(&cfg.run.ctx, &cfg.run.source_ips, monitor, n, FLOOD_HOLD).await;
      let gone = found.contains(&Violation::PidGone);
      for violation in found {
        state.violation(cycle, violation);
      }
      if gone {
        break;
      }
      // The flood's connections close as it returns: the server must serve again soon after.
      sleep(Duration::from_millis(200)).await;
      if let Err(reason) = recovery(&cfg.run.ctx, FLOOD_RECOVERY).await {
        state.violation(cycle, Violation::NoRecovery(format!("after the fd flood: {reason}")));
      }
    }
  }
  if let Some(probes) = probes {
    state.summary.latency = probes.totals();
    probes.stop();
  }
  finish(state)
}

fn finish(mut state: State<'_>) -> Summary {
  state.summary.stopped = state.stop.map(String::from);
  line(state.out, "summary", &state.summary);
  let _ = state.out.flush();
  state.summary
}

/// The mixed load, sampled once a second. `false` if the server is gone.
#[expect(clippy::too_many_arguments, reason = "the cycle's parts")]
async fn mix(
  cfg: &CycleConfig,
  mut run: RunConfig,
  end: Instant,
  cycle: u32,
  state: &mut State<'_>,
  probes: Option<&Probes>,
  base: Option<Baseline>,
  warm: &ProbeStats,
) -> bool {
  let (tx, mut rx) = tokio::sync::mpsc::channel::<Record>(4096);
  let stop = Arc::new(AtomicBool::new(false));
  run.global_seed = cycle_seed(cfg.run.global_seed, cycle);
  let runner = {
    let stop = stop.clone();
    tokio::spawn(async move { run_slots(&run, stop, tx).await })
  };
  let mut tick = interval(Duration::from_secs(1));
  let _ = tick.tick().await;
  let budgets = Budgets { slots: cfg.run.slots };
  let (mut streak, mut saturated, mut alive) = (0, false, true);
  // Whether the last second's probes showed the harness saturated.
  let mut saturated_now = false;
  loop {
    tokio::select! {
      record = rx.recv() => {
        let Some(mut record) = record else { break };
        record.client_saturated = saturated_now;
        state.summary.records += 1;
        match record.outcome {
          "fail" => {
            state.summary.fails += 1;
            if saturated_now {
              state.summary.fails_while_saturated += 1;
            }
            match &state.profile {
              Some(name) => eprintln!("{} (profile {name})", fail_line(&record)),
              None => eprintln!("{}", fail_line(&record)),
            }
            if cfg.ext.stop_on_first {
              let _ = state.stop.get_or_insert("first failure");
              stop.store(true, Ordering::Relaxed);
            }
          }
          "harness_error" => state.summary.harness_errors += 1,
          _ => {}
        }
        if cfg.ext.records == RecordMode::All || record.outcome != "pass" {
          line(state.out, "record", &record);
        }
      }
      _ = tick.tick() => {
        if Instant::now() >= end || state.stop.is_some() {
          stop.store(true, Ordering::Relaxed);
        }
        let Some(sample) = state.sample(cycle).await else {
          stop.store(true, Ordering::Relaxed);
          alive = false;
          continue;
        };
        let stats = probes.map(Probes::snapshot).unwrap_or_default();
        if let Some(every) = cfg.ext.heartbeat {
          if state.last_beat.elapsed() >= every {
            state.heartbeat(cycle, probes);
          }
        }
        line(state.out, "sample", serde_json::json!({ "cycle": cycle, "sample": sample, "probes": stats }));
        if let (Some(sample), Some(base)) = (sample, base) {
          let live = cfg.run.slots + cfg.probes;
          for violation in check_running(&base, &sample, live, &budgets, &mut streak) {
            state.violation(cycle, violation);
          }
        }
        let verdict = latency_verdict(warm, &stats);
        saturated_now = verdict == Verdict::Saturated;
        match verdict {
          Verdict::Ok => {}
          Verdict::Saturated => saturated = true,
          Verdict::Failures(failures) => {
            state.violation(cycle, Violation::ProbeFailures { failures, count: stats.count });
          }
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

/// A fresh connection upgrades and echoes within `within`.
async fn recovery(ctx: &Ctx, within: Duration) -> Result<(), String> {
  let attempt = async {
    let mut rng = rng(0);
    let mut conn = Conn::connect(ctx.addr, &ctx.opts).await.map_err(|err| format!("{err:?}"))?;
    conn.upgrade(&ctx.host, &ctx.path, &mut rng).await.map_err(|err| format!("{err:?}"))?;
    let mut frame = Vec::new();
    client_frame(true, 1, b"recovery", [1, 2, 3, 4], &mut frame);
    conn.send(&frame).await.map_err(|err| format!("{err:?}"))?;
    match conn.next_frame(Instant::now() + within).await {
      Ok(Next::Frame(echo)) if echo.payload == b"recovery" => Ok(()),
      other => Err(format!("no echo: {other:?}")),
    }
  };
  timeout(within, attempt).await.unwrap_or_else(|_| Err(format!("not within {within:?}")))
}
