//! Fixed-rate echo probes on their own thread, whose round trips measure the server's latency
//! while the slots load it, and whose schedule lag shows when the harness itself is the bottleneck.

use crate::{
  codec::client_frame,
  conn::{Conn, Next},
  rng::rng,
  scenario::Ctx,
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

/// Probe schedule lag beyond which latencies say more about the harness than the server.
const MAX_LAG_US: u64 = 1000;
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

/// Whether the probes ran so late that their latencies say more about the harness than the server.
pub fn lag_exceeds(lag_p99_us: u64) -> bool {
  lag_p99_us > MAX_LAG_US
}

struct Hists {
  failures: u64,
  lag: Histogram<u64>,
  rtt: Histogram<u64>,
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
    let hists = Arc::new(Mutex::new(Hists { failures: 0, lag: histogram(), rtt: histogram() }));
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
    }
  };
  while !stop.load(Ordering::Relaxed) {
    let mut conn = match Conn::connect(ctx.addr, &ctx.opts).await {
      Ok(conn) => conn,
      Err(_) => {
        failed(&hists);
        sleep(Duration::from_millis(100)).await;
        continue;
      }
    };
    if conn.upgrade(&ctx.host, &ctx.path, &mut rng).await.is_err() {
      failed(&hists);
      sleep(Duration::from_millis(100)).await;
      continue;
    }
    let text = [b'p'; 32];
    while !stop.load(Ordering::Relaxed) {
      sleep_until(next).await;
      let start = Instant::now();
      let lag = start.saturating_duration_since(next).as_micros() as u64;
      next += period;
      if next < start {
        // Fell behind by more than a period: skip the missed sends instead of bursting.
        next = start + period;
      }
      let mut frame = Vec::new();
      client_frame(true, 1, &text, rand::Rng::random(&mut rng), &mut frame);
      let ok = conn.send(&frame).await.is_ok()
        && matches!(
          conn.next_frame(start + ECHO_TIMEOUT).await,
          Ok(Next::Frame(echo)) if echo.opcode == 1 && echo.payload == text
        );
      if !ok {
        failed(&hists);
        break;
      }
      let rtt = start.elapsed().as_micros() as u64;
      if let Ok(mut el) = hists.lock() {
        let _ = el.rtt.record(rtt.max(1));
        let _ = el.lag.record(lag.max(1));
      }
    }
  }
}
