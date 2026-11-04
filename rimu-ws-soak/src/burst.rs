//! The connection burst: many clients connect at once, which fills the accept queue. Each must
//! still be upgraded and echoed in time.

use crate::{
  codec::client_frame,
  conn::{Conn, Next},
  monitor::Violation,
  rng::rng,
  scenario::Ctx,
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
        let mut conn = Conn::connect(ctx.addr, &ctx.opts).await.ok()?;
        let mut rng = rng(u64::from(idx));
        conn.upgrade(&ctx.host, &ctx.path, &mut rng).await.ok()?;
        let mut frame = Vec::new();
        client_frame(true, 1, b"burst", rand::Rng::random(&mut rng), &mut frame);
        conn.send(&frame).await.ok()?;
        match conn.next_frame(deadline).await {
          Ok(Next::Frame(echo)) if echo.payload == b"burst" => Some(conn),
          _ => None,
        }
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
