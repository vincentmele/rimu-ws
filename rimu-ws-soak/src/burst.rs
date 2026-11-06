//! The connection burst: many clients connect at once, which fills the accept queue. Each must
//! still be upgraded and echoed in time.

use crate::{
  monitor::Violation,
  rng::rng,
  scenario::{Ctx, Ready},
};
use std::{net::IpAddr, time::Duration};
use tokio::time::{Instant, timeout};

/// Opens `n` connections at once, spread over `source_ips`. Each must connect, upgrade and echo a
/// text within `within`; `Burst` counts the ones that didn't.
pub async fn burst(
  ctx: &Ctx,
  source_ips: &[IpAddr],
  n: u32,
  within: Duration,
) -> Option<Violation> {
  let deadline = Instant::now() + within;
  let mut opens = tokio::task::JoinSet::new();
  for idx in 0..n {
    let mut ctx = ctx.clone();
    if !source_ips.is_empty() {
      ctx.opts.source_ip = Some(source_ips[idx as usize % source_ips.len()]);
    }
    let _ = opens.spawn(async move {
      let attempt = async {
        let mut rng = rng(u64::from(idx));
        let mut ready = Ready::open(&ctx, &mut rng).await.ok()?;
        ready.round_trip(b"burst", &mut rng, deadline).await.then_some(ready)
      };
      timeout(within, attempt).await.ok().flatten()
    });
  }
  // Every connection stays open until all have finished, so the burst is held at its peak.
  let (mut held, mut unserved) = (Vec::new(), 0u32);
  while let Some(rslt) = opens.join_next().await {
    match rslt.ok().flatten() {
      Some(conn) => held.push(conn),
      None => unserved += 1,
    }
  }
  drop(held);
  (unserved > 0).then_some(Violation::Burst { unserved, n })
}
