//! What a simulated client does, picked from a weighted mix, and how its run is judged.

mod abuse;
mod echo;
pub mod invalid;

use crate::{
  conn::{Conn, ConnError, ConnOpts, Failure},
  rng::Rng,
};
use rand::Rng as _;
use std::{net::SocketAddr, time::Duration};

/// A client behaviour, with the oracle that judges the server's answer to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum Scenario {
  Echo,
  SplitEveryByte,
  CtrlInFragments,
  NeverRead,
  Slowloris,
  IdlePre,
  IdlePost,
  CloseInHandshake,
  RstMidframe,
  HalfClose,
  PingFlood,
  Garbage,
  Invalid,
  HugeLen,
}

/// Relative weights of the scenarios a client picks from.
#[derive(Clone, Debug)]
pub struct Weights(pub Vec<(Scenario, u32)>);

impl Weights {
  pub fn pick(&self, rng: &mut Rng) -> Scenario {
    let total: u32 = self.0.iter().map(|el| el.1).sum();
    let mut at = rng.random_range(0..total.max(1));
    for &(scenario, weight) in &self.0 {
      if at < weight {
        return scenario;
      }
      at -= weight;
    }
    self.0.first().map_or(Scenario::Echo, |el| el.0)
  }
}

/// `baseline`, `hostile` or `storm`.
pub fn profile(name: &str) -> Option<Weights> {
  let spec = match name {
    "baseline" => "echo=100",
    "hostile" => {
      "echo=40,split_every_byte=5,ctrl_in_fragments=5,never_read=5,slowloris=5,idle_pre=3,\
       idle_post=3,close_in_handshake=4,rst_midframe=6,half_close=4,ping_flood=4,garbage=4,\
       invalid=10,huge_len=2"
    }
    "storm" => "rst_midframe=30,close_in_handshake=30,slowloris=20,never_read=20",
    _ => return None,
  };
  parse_weights(spec).ok()
}

/// `"echo=40,garbage=4"`.
pub fn parse_weights(s: &str) -> Result<Weights, String> {
  let mut weights = Vec::new();
  for item in s.split(',').map(str::trim).filter(|el| !el.is_empty()) {
    let (name, weight) =
      item.split_once('=').ok_or_else(|| format!("`{item}` is not name=weight"))?;
    let scenario = <Scenario as clap::ValueEnum>::from_str(name.trim(), false)
      .map_err(|_| format!("unknown scenario `{}`", name.trim()))?;
    let weight = weight.trim().parse().map_err(|_| format!("bad weight in `{item}`"))?;
    weights.push((scenario, weight));
  }
  if weights.iter().all(|el| el.1 == 0) {
    return Err("no scenario has a weight".into());
  }
  Ok(Weights(weights))
}

/// The server's limits, which the timeout oracles allow for.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
  pub handshake: Duration,
  pub idle: Duration,
  pub close: Duration,
  pub max_payload: u64,
  /// How long `never_read` keeps sending before calling the server unbounded.
  pub never_read_budget: Duration,
}

/// `soak-server-uring`'s defaults.
impl Default for Limits {
  fn default() -> Self {
    Self {
      handshake: Duration::from_secs(2),
      idle: Duration::from_secs(5),
      close: Duration::from_secs(2),
      max_payload: 1 << 20,
      never_read_budget: Duration::from_secs(10),
    }
  }
}

/// How long past a server limit an oracle waits: the server checks a few times per timeout.
pub fn slack(limit: Duration) -> Duration {
  limit * 5 / 4 + Duration::from_millis(250)
}

/// Where and how a scenario connects.
#[derive(Clone, Debug)]
pub struct Ctx {
  pub addr: SocketAddr,
  pub host: String,
  pub path: String,
  pub limits: Limits,
  pub opts: ConnOpts,
}

/// How a scenario run went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
  Pass,
  Fail {
    reason: String,
    transcript: String,
  },
  /// The client, not the server, failed: out of ports or descriptors, say.
  HarnessError(String),
}

pub async fn run(scenario: Scenario, ctx: &Ctx, rng: &mut Rng) -> Outcome {
  // Boxed: inline, every scenario's state would size the future of every run.
  let fut: std::pin::Pin<Box<dyn Future<Output = Outcome> + Send + '_>> = match scenario {
    Scenario::Echo => Box::pin(echo::echo(ctx, rng)),
    Scenario::SplitEveryByte => Box::pin(echo::split_every_byte(ctx, rng)),
    Scenario::CtrlInFragments => Box::pin(echo::ctrl_in_fragments(ctx, rng)),
    Scenario::NeverRead => Box::pin(abuse::never_read(ctx, rng)),
    Scenario::Slowloris => Box::pin(abuse::slowloris(ctx, rng)),
    Scenario::IdlePre => Box::pin(abuse::idle_pre(ctx)),
    Scenario::IdlePost => Box::pin(abuse::idle_post(ctx, rng)),
    Scenario::CloseInHandshake => Box::pin(abuse::close_in_handshake(ctx, rng)),
    Scenario::RstMidframe => Box::pin(abuse::rst_midframe(ctx, rng)),
    Scenario::HalfClose => Box::pin(abuse::half_close(ctx, rng)),
    Scenario::PingFlood => Box::pin(abuse::ping_flood(ctx, rng)),
    Scenario::Garbage => Box::pin(abuse::garbage(ctx, rng)),
    Scenario::Invalid => Box::pin(invalid::invalid(ctx, rng)),
    Scenario::HugeLen => Box::pin(invalid::huge_len(ctx, rng)),
  };
  fut.await
}

/// The outcome of a failed connection operation.
fn from_err(err: ConnError, conn: Option<&Conn>) -> Outcome {
  match err {
    ConnError::Harness(reason) => Outcome::HarnessError(reason),
    ConnError::Server(Failure(reason)) => Outcome::Fail {
      reason,
      transcript: conn.map(|el| el.transcript().dump()).unwrap_or_default(),
    },
  }
}

fn fail(reason: impl Into<String>, conn: &Conn) -> Outcome {
  Outcome::Fail { reason: reason.into(), transcript: conn.transcript().dump() }
}

/// A connection that has completed the upgrade.
async fn upgraded(ctx: &Ctx, opts: &ConnOpts, rng: &mut Rng) -> Result<Conn, Outcome> {
  let mut conn = Conn::connect(ctx.addr, opts).await.map_err(|err| from_err(err, None))?;
  match conn.upgrade(&ctx.host, &ctx.path, rng).await {
    Ok(()) => Ok(conn),
    Err(err) => Err(from_err(err, Some(&conn))),
  }
}
