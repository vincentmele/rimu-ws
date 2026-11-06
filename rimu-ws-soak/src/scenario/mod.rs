//! What a simulated client does, picked from a weighted mix, and how its run is judged.

mod abuse;
pub mod attack;
mod echo;
mod h2;

pub use h2::warm_h2_caches;
pub mod invalid;
pub mod resource;

use crate::{
  codec::client_frame,
  conn::{Conn, ConnError, ConnOpts, Failure, Next},
  h2codec::{DATA, END_STREAM, H2, frame, request},
  rng::Rng,
};
use rand::Rng as _;
use std::{
  net::SocketAddr,
  sync::atomic::{AtomicU32, Ordering},
  time::Duration,
};

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
  BadUpgrade,
  HeaderFlood,
  FragFlood,
  ZeroFlood,
  FragDrip,
  CloseLinger,
  PingNoRead,
  SlowReader,
  H2Steady,
  H2RapidReset,
  H2ContinuationFlood,
  H2SettingsFlood,
  H2PingFlood,
  H2SlowReader,
  H2NeverRead,
  H2WindowStarved,
  H2HalfOpen,
  H2OversizedHeaders,
  H2OversizedBody,
}

/// Scenario runs holding a message of up to `max_payload` on the server, which the memory budget
/// allows for.
pub static LARGE_INFLIGHT: AtomicU32 = AtomicU32::new(0);

/// Counts a run in `LARGE_INFLIGHT` while it lives.
pub(crate) struct LargeInflight;

impl LargeInflight {
  pub(crate) fn new() -> Self {
    let _ = LARGE_INFLIGHT.fetch_add(1, Ordering::Relaxed);
    Self
  }
}

impl Drop for LargeInflight {
  fn drop(&mut self) {
    let _ = LARGE_INFLIGHT.fetch_sub(1, Ordering::Relaxed);
  }
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

  /// Without the scenarios `limits` can't judge: `close_linger` needs the server's send buffer.
  /// Errs if nothing is left.
  pub fn for_limits(&self, limits: &Limits) -> Result<Weights, String> {
    let kept: Vec<_> = self
      .0
      .iter()
      .copied()
      .filter(|(scenario, weight)| {
        let judged = *scenario != Scenario::CloseLinger || limits.server_sndbuf.is_some();
        if !judged && *weight > 0 {
          eprintln!("warning: {scenario:?} needs --server-sndbuf; left out");
        }
        judged
      })
      .collect();
    if kept.iter().all(|el| el.1 == 0) {
      return Err("no scenario left to run".into());
    }
    Ok(Weights(kept))
  }
}

/// - `baseline`: well-behaved clients only.
/// - `hostile`: mostly well-behaved, with a bit of everything else.
/// - `attack`: a public server under attack, with few well-behaved clients.
/// - `storm`: connection churn.
/// - `untimed`: `hostile` without the scenarios that need server timeouts.
/// - `drip`: large messages trickled in fragments, for the memory budget.
///
/// With HTTP/2 (`proto`), `baseline`, `hostile`, `attack` and `storm` are HTTP/2 mixes.
pub fn profile(name: &str, proto: Proto) -> Option<Weights> {
  if proto == Proto::H2 {
    let spec = match name {
      "baseline" => "h2_steady=100",
      "hostile" => {
        "h2_steady=60,h2_rapid_reset=4,h2_continuation_flood=3,h2_settings_flood=3,h2_ping_flood=3,\
         h2_slow_reader=4,h2_never_read=4,h2_window_starved=4,h2_half_open=5,h2_oversized_headers=5,\
         h2_oversized_body=5"
      }
      "attack" => {
        "h2_steady=10,h2_rapid_reset=15,h2_continuation_flood=15,h2_settings_flood=10,\
         h2_ping_flood=10,h2_never_read=10,h2_window_starved=10,h2_oversized_headers=10,\
         h2_oversized_body=10"
      }
      "storm" => "h2_half_open=40,h2_rapid_reset=30,h2_never_read=30",
      _ => return None,
    };
    return parse_weights(spec).ok();
  }
  let spec = match name {
    "baseline" => "echo=100",
    "hostile" => {
      "echo=40,split_every_byte=5,ctrl_in_fragments=5,never_read=5,slowloris=5,idle_pre=3,\
       idle_post=3,close_in_handshake=4,rst_midframe=6,half_close=4,ping_flood=4,garbage=4,\
       invalid=10,huge_len=2,bad_upgrade=4,header_flood=1,frag_flood=1,zero_flood=1,frag_drip=2,\
       close_linger=2,ping_no_read=2,slow_reader=3"
    }
    "attack" => {
      "echo=5,invalid=15,huge_len=5,bad_upgrade=15,header_flood=5,slowloris=8,garbage=8,\
       frag_flood=5,zero_flood=4,ping_flood=4,ping_no_read=5,never_read=5,frag_drip=5,\
       rst_midframe=4,close_in_handshake=4,close_linger=3"
    }
    "storm" => "rst_midframe=30,close_in_handshake=30,slowloris=20,never_read=20",
    "untimed" => {
      "echo=40,split_every_byte=5,ctrl_in_fragments=5,never_read=5,close_in_handshake=4,\
       rst_midframe=6,half_close=4,ping_flood=4,invalid=10,huge_len=2,bad_upgrade=4,frag_flood=1,\
       zero_flood=1,frag_drip=2,ping_no_read=2,slow_reader=3"
    }
    "drip" => "frag_drip=100",
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
  /// The server's `SO_SNDBUF`, which `close_linger` needs; at most 32 KiB, so a reply under the
  /// server's send queue limit still outgrows it.
  pub server_sndbuf: Option<u32>,
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
      server_sndbuf: None,
    }
  }
}

/// How long past a server limit an oracle waits: the server checks a few times per timeout.
pub fn slack(limit: Duration) -> Duration {
  limit * 5 / 4 + Duration::from_millis(250)
}

/// Which protocol the server speaks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Proto {
  /// WebSocket over HTTP/1.1.
  #[default]
  Ws,
  /// HTTP/2 without TLS (prior knowledge).
  H2,
}

/// Where and how a scenario connects.
#[derive(Clone, Debug)]
pub struct Ctx {
  pub addr: SocketAddr,
  pub host: String,
  pub path: String,
  pub limits: Limits,
  pub opts: ConnOpts,
  pub proto: Proto,
}

/// A connection ready for round trips: an upgraded WebSocket, or HTTP/2 past its opening.
#[derive(Debug)]
pub enum Ready {
  Ws(Conn),
  H2 { h2: H2, next_id: u32 },
}

impl Ready {
  /// Connects and upgrades, or sends the HTTP/2 opening.
  pub async fn open(ctx: &Ctx, rng: &mut Rng) -> Result<Ready, ConnError> {
    let mut conn = Conn::connect(ctx.addr, &ctx.opts).await?;
    match ctx.proto {
      Proto::Ws => {
        conn.upgrade(&ctx.host, &ctx.path, rng).await?;
        Ok(Ready::Ws(conn))
      }
      Proto::H2 => Ok(Ready::H2 { h2: H2::open(conn, None).await?, next_id: 1 }),
    }
  }

  /// Sends `payload` and checks it comes back by `deadline`: a WebSocket text echo, or the body
  /// of a `POST /echo`.
  pub async fn round_trip(
    &mut self,
    payload: &[u8],
    rng: &mut Rng,
    deadline: tokio::time::Instant,
  ) -> bool {
    match self {
      Ready::Ws(conn) => {
        let mut bytes = Vec::new();
        client_frame(true, 1, payload, rand::Rng::random(rng), &mut bytes);
        conn.send(&bytes).await.is_ok()
          && matches!(
            conn.next_frame(deadline).await,
            Ok(Next::Frame(echo)) if echo.opcode == 1 && echo.payload == payload
          )
      }
      Ready::H2 { h2, next_id } => {
        let id = *next_id;
        *next_id += 2;
        let mut bytes = request(id, "POST", "/echo", &[], false);
        bytes.extend(frame(DATA, END_STREAM, id, payload));
        if h2.conn.send(&bytes).await.is_err() {
          return false;
        }
        match h2.collect(&[id], deadline).await {
          Ok(got) => got
            .responses
            .get(&id)
            .is_some_and(|el| el.ended && el.status == Some(200) && el.body == payload),
          Err(_) => false,
        }
      }
    }
  }
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
    Scenario::BadUpgrade => Box::pin(attack::bad_upgrade(ctx, rng)),
    Scenario::HeaderFlood => Box::pin(attack::header_flood(ctx, rng)),
    Scenario::FragFlood => Box::pin(attack::frag_flood(ctx, rng)),
    Scenario::ZeroFlood => Box::pin(attack::zero_flood(ctx, rng)),
    Scenario::FragDrip => Box::pin(resource::frag_drip(ctx, rng)),
    Scenario::CloseLinger => Box::pin(resource::close_linger(ctx, rng)),
    Scenario::PingNoRead => Box::pin(resource::ping_no_read(ctx, rng)),
    Scenario::SlowReader => Box::pin(resource::slow_reader(ctx, rng)),
    Scenario::H2Steady => Box::pin(h2::steady(ctx, rng)),
    Scenario::H2RapidReset => Box::pin(h2::rapid_reset(ctx, rng)),
    Scenario::H2ContinuationFlood => Box::pin(h2::continuation_flood(ctx, rng)),
    Scenario::H2SettingsFlood => Box::pin(h2::settings_flood(ctx, rng)),
    Scenario::H2PingFlood => Box::pin(h2::ping_flood(ctx, rng)),
    Scenario::H2SlowReader => Box::pin(h2::slow_reader(ctx, rng)),
    Scenario::H2NeverRead => Box::pin(h2::never_read(ctx, rng)),
    Scenario::H2WindowStarved => Box::pin(h2::window_starved(ctx, rng)),
    Scenario::H2HalfOpen => Box::pin(h2::half_open(ctx, rng)),
    Scenario::H2OversizedHeaders => Box::pin(h2::oversized_headers(ctx, rng)),
    Scenario::H2OversizedBody => Box::pin(h2::oversized_body(ctx, rng)),
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
