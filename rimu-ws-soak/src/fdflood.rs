//! The descriptor flood: more connections than the server can hold, held for a while. The server
//! must not spin retrying accepts, and must serve again once they go.

use crate::{
  conn::Conn,
  monitor::{Monitor, MonitorError, Violation},
  rng::rng,
  scenario::Ctx,
};
use std::{net::IpAddr, time::Duration};
use tokio::time::{Instant, sleep, timeout};

/// CPU share of one core the server may use while it holds the flood.
const BUSY_PCT: f64 = 20.0;
/// How long one flood connection may take to connect and upgrade before it counts as unserved.
const OPEN_TIMEOUT: Duration = Duration::from_secs(2);
/// How many connections are opened at once.
const BATCH: usize = 200;

/// `Busy` if `cpu_ticks_delta` over `elapsed` is 20% of a core or more.
pub fn busy_verdict(cpu_ticks_delta: u64, elapsed: Duration, clk_tck: u64) -> Option<Violation> {
  if elapsed.is_zero() || clk_tck == 0 {
    return None;
  }
  let cpu_pct = cpu_ticks_delta as f64 / clk_tck as f64 / elapsed.as_secs_f64() * 100.0;
  (cpu_pct >= BUSY_PCT).then_some(Violation::Busy { cpu_pct })
}

/// Opens `n` upgraded connections spread over `source_ips`, holds them for `hold` while checking
/// the server's CPU once a second, then closes them. Connections the server can't take (refused,
/// reset, never upgraded) are counted, not failed.
pub async fn fd_flood(
  ctx: &Ctx,
  source_ips: &[IpAddr],
  monitor: &mut Monitor,
  n: u32,
  hold: Duration,
) -> Vec<Violation> {
  let mut held = Vec::new();
  let mut unserved = 0u32;
  let ids: Vec<u32> = (0..n).collect();
  for batch in ids.chunks(BATCH) {
    let mut opens = tokio::task::JoinSet::new();
    for &idx in batch {
      let mut ctx = ctx.clone();
      if !source_ips.is_empty() {
        ctx.opts.source_ip = Some(source_ips[idx as usize % source_ips.len()]);
      }
      let _ = opens.spawn(async move {
        let open = async {
          let mut conn = Conn::connect(ctx.addr, &ctx.opts).await.ok()?;
          conn.upgrade(&ctx.host, &ctx.path, &mut rng(u64::from(idx))).await.ok()?;
          Some(conn)
        };
        timeout(OPEN_TIMEOUT, open).await.ok().flatten()
      });
    }
    while let Some(conn) = opens.join_next().await {
      match conn.ok().flatten() {
        Some(conn) => held.push(conn),
        None => unserved += 1,
      }
    }
  }
  eprintln!("fd flood: {} connections held, {unserved} not served", held.len());
  // SAFETY: no arguments
  let clk_tck = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).unwrap_or(100);
  let mut found = Vec::new();
  let end = Instant::now() + hold;
  let mut last = match monitor.sample() {
    Ok(sample) => (Instant::now(), sample.cpu_ticks),
    Err(MonitorError::PidGone) => return vec![Violation::PidGone],
    Err(MonitorError::Io(_)) => return found,
  };
  let mut busiest: Option<Violation> = None;
  while Instant::now() < end {
    sleep(Duration::from_secs(1)).await;
    let sample = match monitor.sample() {
      Ok(sample) => sample,
      Err(MonitorError::PidGone) => return vec![Violation::PidGone],
      Err(MonitorError::Io(_)) => continue,
    };
    let now = Instant::now();
    if let Some(Violation::Busy { cpu_pct }) =
      busy_verdict(sample.cpu_ticks - last.1, now - last.0, clk_tck)
    {
      let worse = !matches!(busiest, Some(Violation::Busy { cpu_pct: prev }) if prev >= cpu_pct);
      if worse {
        busiest = Some(Violation::Busy { cpu_pct });
      }
    }
    last = (now, sample.cpu_ticks);
  }
  found.extend(busiest);
  drop(held);
  found
}
