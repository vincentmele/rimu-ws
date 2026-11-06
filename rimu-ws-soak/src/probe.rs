//! Fixed-rate echo probes on their own thread, whose round trips measure the server's latency
//! while the slots load it, and whose schedule lag shows when the harness itself is the bottleneck.

use crate::{
  rng::rng,
  scenario::{Ctx, Ready},
};
use hdrhistogram::Histogram;
use std::{
  sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
  },
  thread::JoinHandle,
  time::Duration,
};
use tokio::time::{Instant, sleep, sleep_until};

/// Probe schedule lag, beyond the idle harness's own, past which latencies say more about the
/// harness than the server.
const MAX_LAG_US: u64 = 1000;
/// tokio's timers fire on 1 ms ticks: a wakeup up to a tick late is the timer, not saturation.
const TIMER_TICK: Duration = Duration::from_millis(1);
/// How long an echo may take before the probe counts a failure and reconnects.
const ECHO_TIMEOUT: Duration = Duration::from_secs(1);

/// Probe results since the last snapshot.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct ProbeStats {
  pub count: u64,
  pub p50_us: u64,
  pub p99_us: u64,
  pub max_us: u64,
  pub lag_p99_us: u64,
  pub failures: u64,
}

/// Whether the probes ran so late, compared with `baseline_lag_p99_us` from the warmup (timer
/// lateness the idle harness shows too), that their latencies say more about the harness than the
/// server.
pub fn lag_exceeds(lag_p99_us: u64, baseline_lag_p99_us: u64) -> bool {
  lag_p99_us > baseline_lag_p99_us + MAX_LAG_US
}

/// Probe results over the whole run.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct ProbeTotals {
  pub count: u64,
  pub p50_us: u64,
  pub p99_us: u64,
  pub p999_us: u64,
  pub max_us: u64,
  pub failures: u64,
}

struct Hists {
  failures: u64,
  lag: Histogram<u64>,
  rtt: Histogram<u64>,
  // Never reset: the whole run's
  total: Histogram<u64>,
  total_failures: u64,
}

fn histogram() -> Histogram<u64> {
  Histogram::new_with_bounds(1, 10_000_000, 3).expect("valid bounds")
}

/// Running probes.
pub struct Probes {
  hists: Arc<Mutex<Hists>>,
  stop: Arc<AtomicBool>,
  thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Probes {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Probes").finish()
  }
}

impl Probes {
  /// `connections` connections, each echoing a 32-byte text `rate_hz` times a second, their
  /// schedules spread evenly over the period.
  pub fn spawn(ctx: Ctx, connections: u32, rate_hz: u32) -> Probes {
    let hists = Arc::new(Mutex::new(Hists {
      failures: 0,
      lag: histogram(),
      rtt: histogram(),
      total: histogram(),
      total_failures: 0,
    }));
    let stop = Arc::new(AtomicBool::new(false));
    let (thread_hists, thread_stop) = (hists.clone(), stop.clone());
    let thread = std::thread::spawn(move || {
      let runtime =
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("probe runtime");
      runtime.block_on(async move {
        let period = Duration::from_secs(1) / rate_hz.max(1);
        let tasks: Vec<_> = (0..connections)
          .map(|idx| {
            let (ctx, hists, stop) = (ctx.clone(), thread_hists.clone(), thread_stop.clone());
            let offset = period * idx / connections.max(1);
            tokio::spawn(probe(ctx, idx, period, offset, hists, stop))
          })
          .collect();
        for task in tasks {
          let _ = task.await;
        }
      });
    });
    Probes { hists, stop, thread: Some(thread) }
  }

  /// The results since the last snapshot.
  pub fn snapshot(&self) -> ProbeStats {
    let Ok(mut hists) = self.hists.lock() else { return ProbeStats::default() };
    let stats = ProbeStats {
      count: hists.rtt.len(),
      p50_us: hists.rtt.value_at_quantile(0.5),
      p99_us: hists.rtt.value_at_quantile(0.99),
      max_us: hists.rtt.max(),
      lag_p99_us: hists.lag.value_at_quantile(0.99),
      failures: hists.failures,
    };
    hists.rtt.reset();
    hists.lag.reset();
    hists.failures = 0;
    stats
  }

  /// The results since the probes started.
  pub fn totals(&self) -> ProbeTotals {
    let Ok(hists) = self.hists.lock() else { return ProbeTotals::default() };
    ProbeTotals {
      count: hists.total.len(),
      p50_us: hists.total.value_at_quantile(0.5),
      p99_us: hists.total.value_at_quantile(0.99),
      p999_us: hists.total.value_at_quantile(0.999),
      max_us: hists.total.max(),
      failures: hists.total_failures,
    }
  }

  pub fn stop(mut self) {
    self.stop.store(true, Ordering::Relaxed);
    if let Some(thread) = self.thread.take() {
      let _ = thread.join();
    }
  }
}

impl Drop for Probes {
  fn drop(&mut self) {
    self.stop.store(true, Ordering::Relaxed);
  }
}

async fn probe(
  ctx: Ctx,
  idx: u32,
  period: Duration,
  offset: Duration,
  hists: Arc<Mutex<Hists>>,
  stop: Arc<AtomicBool>,
) {
  let mut rng = rng(u64::from(idx));
  let mut next = Instant::now() + offset;
  let failed = |hists: &Mutex<Hists>| {
    if let Ok(mut el) = hists.lock() {
      el.failures += 1;
      el.total_failures += 1;
    }
  };
  while !stop.load(Ordering::Relaxed) {
    let mut ready = match Ready::open(&ctx, &mut rng).await {
      Ok(ready) => ready,
      Err(_) => {
        failed(&hists);
        sleep(Duration::from_millis(100)).await;
        continue;
      }
    };
    let text = [b'p'; 32];
    // When an echo outlasts the period, the next send is due before the echo is back. That
    // lateness is the server's; lag counts only the timer's, from whichever came last.
    let mut prev_end = Instant::now();
    while !stop.load(Ordering::Relaxed) {
      let due = next.max(prev_end);
      if due > Instant::now() {
        sleep_until(due).await;
      }
      let start = Instant::now();
      let lag = start.saturating_duration_since(due).saturating_sub(TIMER_TICK).as_micros() as u64;
      next += period;
      if next < start {
        // Fell behind by more than a period: skip the missed sends instead of bursting.
        next = start + period;
      }
      let ok = ready.round_trip(&text, &mut rng, start + ECHO_TIMEOUT).await;
      if !ok {
        failed(&hists);
        break;
      }
      prev_end = Instant::now();
      let rtt = (prev_end - start).as_micros() as u64;
      if let Ok(mut el) = hists.lock() {
        let _ = el.rtt.record(rtt.max(1));
        let _ = el.total.record(rtt.max(1));
        let _ = el.lag.record(lag.max(1));
      }
    }
  }
}
