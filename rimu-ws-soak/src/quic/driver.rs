//! The QUIC/HTTP/3 soak: a well-behaved steady client (64 connections × 64 streams) that runs for
//! the whole ~10-minute run beside abusive clients run in sequence, the server watched from
//! outside once a second. Each abuser is bounded by one limit of [`rimu_ws::quic`] (spec section
//! 5.12); its pass rule is the server's RSS staying within 10 % of the plateau the steady client
//! settles at, the steady client never stalling, and the abuser being closed with the named error
//! or rate-limited (rulings T23-a, T23-c).

use crate::{
  monitor::{Monitor, Sample},
  quic::{client, raw, scenario},
};
use std::{
  net::SocketAddr,
  sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
  },
  time::Duration,
};
use tokio::time::Instant;

/// What the soak runs against and for how long.
#[derive(Clone, Debug)]
pub struct H3Config {
  /// The multi-worker server: the steady client and most abusers.
  pub main_addr: SocketAddr,
  pub main_pid: Option<u32>,
  /// A one-worker server for the per-worker caps (idle × 4,096), or [`None`] to skip them.
  pub idle_addr: Option<SocketAddr>,
  pub idle_pid: Option<u32>,
  /// The whole run (steady + abusers), about ten minutes.
  pub duration: Duration,
  /// Probe-only time at the start that sets the RSS plateau.
  pub warmup: Duration,
  /// Steady connections and streams each.
  pub conns: u32,
  pub streams: u32,
  /// Where the JSONL goes.
  pub out: std::path::PathBuf,
  /// The worker count and memlock, for the report.
  pub main_workers: u32,
  pub memlock_kib: Option<u64>,
}

/// What one scenario or the steady client reported.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Line {
  pub kind: &'static str,
  pub name: String,
  pub pass: bool,
  pub detail: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub rss_peak_kib: Option<u64>,
}

/// The counters the steady client keeps for the whole run.
#[derive(Debug, Default)]
pub struct Steady {
  pub ok: AtomicU64,
  pub bad: AtomicU64,
  pub stalls: AtomicU64,
  pub max_rtt_us: AtomicU64,
}

/// A steady request slower than this, or one that failed while the run was live, is a stall of a
/// well-behaved client.
const STALL: Duration = Duration::from_secs(2);

/// Runs the steady client's connections until `stop`. Each connection drives `streams` request
/// loops at a modest rate, each `GET /baseline2` checked for `200` and the body `0`.
async fn steady_client(
  addr: SocketAddr,
  conns: u32,
  streams: u32,
  idle: Duration,
  stop: Arc<AtomicBool>,
  counters: Arc<Steady>,
) {
  let cfg = client::client_config(Some(Duration::from_secs(5)), idle);
  let mut tasks = Vec::new();
  for _ in 0..conns {
    let (cfg, stop, counters) = (cfg.clone(), stop.clone(), counters.clone());
    tasks.push(tokio::spawn(async move {
      let bind: SocketAddr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
      let Ok(ep) = client::endpoint(bind, cfg) else {
        counters.bad.fetch_add(1, Ordering::Relaxed);
        return;
      };
      // Reconnect if the connection drops, until the run ends.
      while !stop.load(Ordering::Relaxed) {
        let Ok(conn) = client::connect(&ep, addr, "localhost").await else {
          counters.bad.fetch_add(1, Ordering::Relaxed);
          tokio::time::sleep(Duration::from_millis(100)).await;
          continue;
        };
        let h3 = h3_quinn::Connection::new(conn.clone());
        let Ok((mut driver, send_request)) = h3::client::new(h3).await else {
          counters.bad.fetch_add(1, Ordering::Relaxed);
          continue;
        };
        let drive = tokio::spawn(async move {
          let _ = driver.wait_idle().await;
        });
        let mut streams_tasks = Vec::new();
        for _ in 0..streams {
          let (mut sr, stop, counters) = (send_request.clone(), stop.clone(), counters.clone());
          streams_tasks.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
              let begin = Instant::now();
              let ok = one_request(&mut sr).await;
              let rtt = begin.elapsed();
              let us = rtt.as_micros() as u64;
              counters.max_rtt_us.fetch_max(us, Ordering::Relaxed);
              if ok {
                counters.ok.fetch_add(1, Ordering::Relaxed);
                if rtt > STALL {
                  counters.stalls.fetch_add(1, Ordering::Relaxed);
                }
              } else {
                // A failed request while the run is live is a stall (the connection may have
                // dropped; the outer loop reconnects).
                counters.bad.fetch_add(1, Ordering::Relaxed);
                if !stop.load(Ordering::Relaxed) {
                  counters.stalls.fetch_add(1, Ordering::Relaxed);
                }
                break;
              }
              tokio::time::sleep(Duration::from_millis(25)).await;
            }
          }));
        }
        for task in streams_tasks {
          let _ = task.await;
        }
        drive.abort();
        if stop.load(Ordering::Relaxed) {
          break;
        }
      }
      ep.close(client::H3_NO_ERROR, b"bye");
    }));
  }
  for task in tasks {
    let _ = task.await;
  }
}

/// One `GET /baseline2`: `true` if it answered `200` with the body `0`.
async fn one_request(
  sr: &mut h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
) -> bool {
  use bytes::Buf as _;
  let Ok(req) = http::Request::builder().method("GET").uri("https://localhost/baseline2").body(())
  else {
    return false;
  };
  let Ok(mut stream) = sr.send_request(req).await else {
    return false;
  };
  if stream.finish().await.is_err() {
    return false;
  }
  let Ok(resp) = stream.recv_response().await else {
    return false;
  };
  if resp.status().as_u16() != 200 {
    return false;
  }
  let mut body = Vec::new();
  loop {
    match stream.recv_data().await {
      Ok(Some(mut chunk)) => {
        while chunk.has_remaining() {
          let n = chunk.chunk().len();
          body.extend_from_slice(chunk.chunk());
          chunk.advance(n);
        }
      }
      Ok(None) => break,
      Err(_) => return false,
    }
  }
  body == b"ok"
}

/// Samples the server once a second until `stop`; returns every sample.
async fn sample_loop(pid: Option<u32>, port: u16, stop: Arc<AtomicBool>) -> Vec<Sample> {
  let mut out = Vec::new();
  let Some(pid) = pid else {
    return out;
  };
  let Ok(mut monitor) = Monitor::new(pid, port) else {
    return out;
  };
  while !stop.load(Ordering::Relaxed) {
    if let Ok(sample) = monitor.sample() {
      out.push(sample);
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
  }
  out
}

/// The RSS plateau: the largest RSS seen in the warmup's samples (the steady client at rest).
fn plateau_kib(warm: &[Sample]) -> u64 {
  warm.iter().map(|el| el.rss_kib).max().unwrap_or(0)
}

/// Runs the whole soak and writes the JSONL, returning the number of failures.
pub async fn run(cfg: H3Config, out: &mut dyn std::io::Write) -> u32 {
  let idle = Duration::from_secs(30);
  let stop = Arc::new(AtomicBool::new(false));
  let counters = Arc::new(Steady::default());

  // Start the steady client and the sampler.
  let steady = tokio::spawn(steady_client(
    cfg.main_addr,
    cfg.conns,
    cfg.streams,
    idle,
    stop.clone(),
    counters.clone(),
  ));
  let sampler_stop = Arc::new(AtomicBool::new(false));
  let sampler = tokio::spawn(sample_loop(cfg.main_pid, cfg.main_addr.port(), sampler_stop.clone()));

  // Warm up: the steady client alone sets the plateau.
  let warm_stop = Arc::new(AtomicBool::new(false));
  let warm_sampler =
    tokio::spawn(sample_loop(cfg.main_pid, cfg.main_addr.port(), warm_stop.clone()));
  tokio::time::sleep(cfg.warmup).await;
  warm_stop.store(true, Ordering::Relaxed);
  let warm = warm_sampler.await.unwrap_or_default();
  let plateau = plateau_kib(&warm);
  let bound = plateau.saturating_mul(110) / 100 + 16 * 1024;
  let mut lines = Vec::new();
  lines.push(Line {
    kind: "plateau",
    name: "steady_warmup".into(),
    pass: plateau > 0,
    detail: format!(
      "plateau {plateau} KiB over {} samples, bound {bound} KiB (+10% +16 MiB)",
      warm.len()
    ),
    rss_peak_kib: Some(plateau),
  });

  // The abusers, in sequence, while the steady client keeps running.
  let deadline = Instant::now() + cfg.duration.saturating_sub(cfg.warmup);
  let results = scenario::run_all(&cfg, deadline).await;
  for result in results {
    lines.push(Line {
      kind: "scenario",
      name: result.name,
      pass: result.pass,
      detail: result.detail,
      rss_peak_kib: None,
    });
  }

  // Stop the steady client and the sampler.
  stop.store(true, Ordering::Relaxed);
  sampler_stop.store(true, Ordering::Relaxed);
  let _ = tokio::time::timeout(Duration::from_secs(15), steady).await;
  let samples = sampler.await.unwrap_or_default();
  let peak = samples.iter().map(|el| el.rss_kib).max().unwrap_or(0).max(plateau);

  let ok = counters.ok.load(Ordering::Relaxed);
  let stalls = counters.stalls.load(Ordering::Relaxed);
  let bad = counters.bad.load(Ordering::Relaxed);
  let max_rtt = counters.max_rtt_us.load(Ordering::Relaxed);
  lines.push(Line {
    kind: "steady",
    name: "steady_64x64".into(),
    pass: stalls == 0,
    detail: format!("{ok} ok, {bad} failed, {stalls} stalls, max rtt {max_rtt} us",),
    rss_peak_kib: None,
  });
  lines.push(Line {
    kind: "rss",
    name: "rss_bound".into(),
    pass: peak <= bound,
    detail: format!("peak {peak} KiB, plateau {plateau} KiB, bound {bound} KiB"),
    rss_peak_kib: Some(peak),
  });

  // Write every line and count failures.
  let mut fails = 0;
  for line in &lines {
    if !line.pass {
      fails += 1;
    }
    if let Ok(text) = serde_json::to_string(line) {
      let _ = writeln!(out, "{text}");
    }
    eprintln!(
      "{} {} {} — {}",
      if line.pass { "PASS" } else { "FAIL" },
      line.kind,
      line.name,
      line.detail
    );
  }
  eprintln!(
    "h3 soak: plateau {plateau} KiB, peak {peak} KiB, steady {ok} ok / {stalls} stalls, {} workers, memlock {}",
    cfg.main_workers,
    cfg.memlock_kib.map_or("unlimited".into(), |el| format!("{el} KiB"))
  );
  let _ = raw::VERSION_1; // keep the raw module linked even if a scenario build drops it
  fails
}
