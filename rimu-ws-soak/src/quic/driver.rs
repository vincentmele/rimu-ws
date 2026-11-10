//! The QUIC/HTTP/3 soak: a well-behaved steady client (64 connections × 64 streams) on the
//! four-worker server, a small steady client (4 × 4) on the one-worker server, both running for the
//! whole ~10-minute run (rulings T23-a/T23-k), beside abusive clients run in sequence. Both servers
//! are watched once a second. Each abuser is bounded by one limit of `rimu-ws` (spec section 5.12);
//! its pass rule is that the server's RSS stays within 10 % of the plateau the steady client
//! settles at (strict, ruling T23-i), the steady client never stalls, and the abuser is closed with
//! the named error or rate-limited (ruling T23-c).

use crate::{
  monitor::{Monitor, Sample},
  quic::{client, scenario},
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
  pub main_addr: SocketAddr,
  pub main_pid: Option<u32>,
  pub idle_addr: Option<SocketAddr>,
  pub idle_pid: Option<u32>,
  pub duration: Duration,
  pub warmup: Duration,
  pub conns: u32,
  pub streams: u32,
  pub out: std::path::PathBuf,
  pub main_workers: u32,
  pub memlock_kib: Option<u64>,
}

/// One JSONL line.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Line {
  pub kind: &'static str,
  pub name: String,
  pub pass: bool,
  pub detail: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub rss_peak_kib: Option<u64>,
}

/// Counters a steady client keeps.
#[derive(Debug, Default)]
pub struct Steady {
  pub ok: AtomicU64,
  pub bad: AtomicU64,
  pub stalls: AtomicU64,
  pub max_rtt_us: AtomicU64,
}

/// A steady request slower than this (or one that fails while the run is live) is a stall of a
/// well-behaved client.
const STALL: Duration = Duration::from_secs(2);

/// One `GET /baseline2`, bounded by [`STALL`]: `Some(true)` = 200/`ok`, `Some(false)` = a bad
/// answer, `None` = timed out (a stall).
async fn one_request(
  sr: &mut h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
) -> Option<bool> {
  use bytes::Buf as _;
  let fut = async {
    let req =
      http::Request::builder().method("GET").uri("https://localhost/baseline2").body(()).ok()?;
    let mut stream = sr.send_request(req).await.ok()?;
    stream.finish().await.ok()?;
    let resp = stream.recv_response().await.ok()?;
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.ok()? {
      while chunk.has_remaining() {
        let n = chunk.chunk().len();
        body.extend_from_slice(chunk.chunk());
        chunk.advance(n);
      }
    }
    Some(resp.status().as_u16() == 200 && body == b"ok")
  };
  match tokio::time::timeout(STALL, fut).await {
    Ok(Some(ok)) => Some(ok),
    Ok(None) => Some(false),
    Err(_) => None,
  }
}

/// Runs a steady client until `stop`: `conns` connections, each driving `streams` concurrent
/// request loops over a shared (cloned) `SendRequest`, each request bounded by [`STALL`].
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
      while !stop.load(Ordering::Relaxed) {
        let Ok(conn) = client::connect(&ep, addr, "localhost").await else {
          counters.bad.fetch_add(1, Ordering::Relaxed);
          if !stop.load(Ordering::Relaxed) {
            counters.stalls.fetch_add(1, Ordering::Relaxed);
          }
          tokio::time::sleep(Duration::from_millis(200)).await;
          continue;
        };
        let h3c = h3_quinn::Connection::new(conn);
        let Ok((mut driver, send_request)) = h3::client::new(h3c).await else {
          counters.bad.fetch_add(1, Ordering::Relaxed);
          tokio::time::sleep(Duration::from_millis(200)).await; // no spin on failure
          continue;
        };
        let drive = tokio::spawn(async move {
          let _ = driver.wait_idle().await;
        });
        let mut stream_tasks = Vec::new();
        for _ in 0..streams {
          let (mut sr, stop, counters) = (send_request.clone(), stop.clone(), counters.clone());
          stream_tasks.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
              let begin = Instant::now();
              let got = one_request(&mut sr).await;
              counters.max_rtt_us.fetch_max(begin.elapsed().as_micros() as u64, Ordering::Relaxed);
              match got {
                Some(true) => {
                  counters.ok.fetch_add(1, Ordering::Relaxed);
                }
                Some(false) => {
                  counters.bad.fetch_add(1, Ordering::Relaxed);
                  if !stop.load(Ordering::Relaxed) {
                    counters.stalls.fetch_add(1, Ordering::Relaxed);
                  }
                  break;
                }
                None => {
                  if !stop.load(Ordering::Relaxed) {
                    counters.stalls.fetch_add(1, Ordering::Relaxed);
                  }
                  break;
                }
              }
              tokio::time::sleep(Duration::from_millis(25)).await;
            }
          }));
        }
        for task in stream_tasks {
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

/// Primes the per-thread static cache by fetching `/static/big.bin` (10 MiB) over `fetches`
/// connections, so the warm-up plateau includes the cache the abuser routes touch (ruling T23-i).
/// Enough connections that CID steering spreads them over all workers.
async fn prime_cache(addr: SocketAddr, fetches: u32, idle: Duration) {
  let cfg = client::client_config(None, idle);
  let bind: SocketAddr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
  let Ok(ep) = client::endpoint(bind, cfg) else { return };
  let mut tasks = Vec::new();
  for _ in 0..fetches {
    let ep = ep.clone();
    tasks.push(tokio::spawn(async move {
      if let Ok(conn) = client::connect(&ep, addr, "localhost").await {
        if let Ok(mut session) = client::H3Session::open(conn.clone()).await {
          let _ = session.get("/static/big.bin").await;
        }
        conn.close(client::H3_NO_ERROR, b"");
      }
    }));
  }
  for task in tasks {
    let _ = task.await;
  }
  ep.wait_idle().await;
}

/// Samples the server once a second until `stop`.
async fn sample_loop(pid: Option<u32>, port: u16, stop: Arc<AtomicBool>) -> Vec<Sample> {
  let mut out = Vec::new();
  let Some(pid) = pid else { return out };
  let Ok(mut monitor) = Monitor::new(pid, port) else { return out };
  while !stop.load(Ordering::Relaxed) {
    if let Ok(sample) = monitor.sample() {
      out.push(sample);
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
  }
  out
}

fn plateau_kib(samples: &[Sample]) -> u64 {
  samples.iter().map(|el| el.rss_kib).max().unwrap_or(0)
}

/// Runs the whole soak and writes the JSONL, returning the number of failures.
pub async fn run(cfg: H3Config, out: &mut dyn std::io::Write) -> u32 {
  let idle_to = Duration::from_secs(30);
  let run_begin = Instant::now();
  let deadline = run_begin + cfg.duration;

  // Prime the static cache on both servers first, so the plateau already holds it.
  prime_cache(cfg.main_addr, 32, idle_to).await; // 32 covers 4 workers with P(miss)≈0.4% (N12)
  if let Some(idle_addr) = cfg.idle_addr {
    prime_cache(idle_addr, 4, idle_to).await;
  }

  let main_stop = Arc::new(AtomicBool::new(false));
  let main_counters = Arc::new(Steady::default());
  let main_steady = tokio::spawn(steady_client(
    cfg.main_addr,
    cfg.conns,
    cfg.streams,
    idle_to,
    main_stop.clone(),
    main_counters.clone(),
  ));
  let idle_stop = Arc::new(AtomicBool::new(false));
  let idle_counters = Arc::new(Steady::default());
  let idle_steady = cfg.idle_addr.map(|idle_addr| {
    tokio::spawn(steady_client(idle_addr, 4, 4, idle_to, idle_stop.clone(), idle_counters.clone()))
  });

  // Plateau: warm-up window only.
  let warm_stop = Arc::new(AtomicBool::new(false));
  let warm_main = tokio::spawn(sample_loop(cfg.main_pid, cfg.main_addr.port(), warm_stop.clone()));
  let warm_idle =
    cfg.idle_addr.map(|a| tokio::spawn(sample_loop(cfg.idle_pid, a.port(), warm_stop.clone())));
  tokio::time::sleep(cfg.warmup).await;
  warm_stop.store(true, Ordering::Relaxed);
  let plateau_main = plateau_kib(&warm_main.await.unwrap_or_default());
  let plateau_idle = match warm_idle {
    Some(h) => plateau_kib(&h.await.unwrap_or_default()),
    None => 0,
  };

  // Whole-run sampling for the peak. The idle sampler is stopped before the idle_4096 phase, so the
  // idle server's RSS gate reflects the steady client plus the raw floods, not the deliberate
  // 4,096-connection spike (idle_4096 does its own per-connection RSS check, ruling T23-k).
  let samp_main_stop = Arc::new(AtomicBool::new(false));
  let samp_idle_stop = Arc::new(AtomicBool::new(false));
  let samp_main =
    tokio::spawn(sample_loop(cfg.main_pid, cfg.main_addr.port(), samp_main_stop.clone()));
  let samp_idle = cfg
    .idle_addr
    .map(|a| tokio::spawn(sample_loop(cfg.idle_pid, a.port(), samp_idle_stop.clone())));

  let mut lines = Vec::new();
  lines.push(Line {
    kind: "env",
    name: "run".into(),
    pass: true,
    detail: format!(
      "main_workers={}, memlock={}, plateau_main={plateau_main} KiB, plateau_idle={plateau_idle} KiB",
      cfg.main_workers,
      cfg.memlock_kib.map_or("unlimited".into(), |el| format!("{el} KiB"))
    ),
    rss_peak_kib: None,
  });

  // Abusers (each with its own deadline), while the steady clients run. idle_4096 is handled
  // separately below, after the idle sampler is stopped.
  let results = scenario::run_all(&cfg, deadline).await;
  for r in results {
    lines.push(Line {
      kind: "scenario",
      name: r.name,
      pass: r.pass,
      detail: r.detail,
      rss_peak_kib: None,
    });
  }

  // idle_4096 phase: stop the idle steady client and its RSS sampler, then run the cap scenario,
  // which does its own per-connection RSS check (ruling T23-k).
  samp_idle_stop.store(true, Ordering::Relaxed);
  let idle_samples = match samp_idle {
    Some(h) => h.await.unwrap_or_default(),
    None => Vec::new(),
  };
  if let (Some(idle_addr), Some(idle_pid)) = (cfg.idle_addr, cfg.idle_pid) {
    idle_stop.store(true, Ordering::Relaxed);
    if let Some(h) = idle_steady {
      let _ = tokio::time::timeout(Duration::from_secs(10), h).await;
    }
    // Let the idle steady client's connections drain from the one-worker server so the cap is free
    // for the 4,096-connection fill.
    tokio::time::sleep(Duration::from_secs(3)).await;
    // Its own deadline (N10): a wedged fill fails the scenario instead of hanging the run.
    let r = match tokio::time::timeout(
      Duration::from_secs(300),
      scenario::idle_connections(idle_addr, idle_pid),
    )
    .await
    {
      Ok(r) => r,
      Err(_) => scenario::ScenarioResult {
        name: "idle_4096".into(),
        pass: false,
        detail: "exceeded its 300 s deadline".into(),
      },
    };
    lines.push(Line {
      kind: "scenario",
      name: r.name,
      pass: r.pass,
      detail: r.detail,
      rss_peak_kib: None,
    });
  } else {
    idle_stop.store(true, Ordering::Relaxed);
    if let Some(h) = idle_steady {
      let _ = tokio::time::timeout(Duration::from_secs(10), h).await;
    }
  }

  // Keep the main steady client running until the full duration elapses (ruling T23-a).
  let remaining = deadline.saturating_duration_since(Instant::now());
  if remaining > Duration::ZERO {
    tokio::time::sleep(remaining).await;
  }

  main_stop.store(true, Ordering::Relaxed);
  samp_main_stop.store(true, Ordering::Relaxed);
  let _ = tokio::time::timeout(Duration::from_secs(20), main_steady).await;
  let main_samples = samp_main.await.unwrap_or_default();

  let mut fails = 0u32;
  let mut emit = |line: Line, fails: &mut u32| {
    if !line.pass {
      *fails = fails.wrapping_add(1);
    }
    if let Ok(text) = serde_json::to_string(&line) {
      let _ = writeln!(out, "{text}");
    }
    eprintln!(
      "{} {} {} — {}",
      if line.pass { "PASS" } else { "FAIL" },
      line.kind,
      line.name,
      line.detail
    );
  };

  for (label, plateau, samples) in
    [("rss_main", plateau_main, &main_samples), ("rss_idle", plateau_idle, &idle_samples)]
  {
    if plateau == 0 && samples.is_empty() {
      continue;
    }
    let peak = samples.iter().map(|el| el.rss_kib).max().unwrap_or(0).max(plateau);
    let bound = plateau.saturating_mul(110) / 100;
    emit(
      Line {
        kind: "rss",
        name: label.into(),
        pass: peak <= bound,
        detail: format!(
          "peak {peak} KiB, plateau {plateau} KiB, bound {bound} KiB (×1.10, no slack)"
        ),
        rss_peak_kib: Some(peak),
      },
      &mut fails,
    );
  }

  for (label, c, present) in [
    ("steady_main", &main_counters, true),
    ("steady_idle", &idle_counters, cfg.idle_addr.is_some()),
  ] {
    if !present {
      continue;
    }
    let (ok, bad, stalls) = (
      c.ok.load(Ordering::Relaxed),
      c.bad.load(Ordering::Relaxed),
      c.stalls.load(Ordering::Relaxed),
    );
    emit(
      Line {
        kind: "steady",
        name: label.into(),
        pass: stalls == 0 && bad == 0,
        detail: format!(
          "{ok} ok, {bad} failed, {stalls} stalls, max rtt {} us",
          c.max_rtt_us.load(Ordering::Relaxed)
        ),
        rss_peak_kib: None,
      },
      &mut fails,
    );
  }

  for line in lines {
    emit(line, &mut fails);
  }

  let wall = run_begin.elapsed();
  eprintln!(
    "h3 soak: wall {:.0}s, plateau main/idle {plateau_main}/{plateau_idle} KiB, {} workers, memlock {}",
    wall.as_secs_f64(),
    cfg.main_workers,
    cfg.memlock_kib.map_or("unlimited".into(), |el| format!("{el} KiB"))
  );
  fails
}
