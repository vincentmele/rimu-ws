//! `rimu-ws-soak run ...` soaks a server; `rimu-ws-soak replay SEED:SLOT:GEN ...` reruns one
//! scenario run alone and prints its transcript.

use clap::Parser as _;
use rimu_ws_soak::{
  conn::ConnOpts,
  cycle::{self, CycleConfig},
  runner::{RunConfig, parse_replay, replay},
  scenario::{Ctx, Limits, Weights, parse_weights, profile},
};
use std::{
  net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs as _},
  path::PathBuf,
  process::ExitCode,
  time::Duration,
};

#[derive(clap::Parser)]
#[command(about = "Soak and abuse harness for WebSocket servers")]
struct Cli {
  #[command(subcommand)]
  cmd: Cmd,
}

#[derive(clap::Subcommand)]
enum Cmd {
  /// Runs client slots against the server.
  Run(RunArgs),
  /// Reruns one scenario run by its replay id and prints its record and transcript.
  Replay(ReplayArgs),
}

#[derive(clap::Args)]
struct Common {
  /// The server's WebSocket URL (plain `ws://` only).
  #[arg(long, default_value = "ws://127.0.0.1:9080/")]
  url: String,
  /// Weighted mix: `baseline`, `hostile` or `storm`.
  #[arg(long, default_value = "hostile")]
  profile: String,
  /// Overrides `--profile`, as `echo=40,garbage=4`.
  #[arg(long)]
  weights: Option<String>,
  /// The server's handshake (first write) timeout.
  #[arg(long, default_value = "2s", value_parser = parse_duration)]
  handshake_timeout: Duration,
  /// The server's idle timeout.
  #[arg(long, default_value = "5s", value_parser = parse_duration)]
  idle_timeout: Duration,
  /// The server's close timeout.
  #[arg(long, default_value = "2s", value_parser = parse_duration)]
  close_timeout: Duration,
  /// The server's largest message.
  #[arg(long, default_value_t = 1 << 20)]
  max_payload: u64,
}

#[derive(clap::Args)]
struct RunArgs {
  #[command(flatten)]
  common: Common,
  /// The server's pid, for the monitor.
  #[arg(long)]
  pid: Option<u32>,
  #[arg(long, default_value_t = 1)]
  seed: u64,
  #[arg(long, default_value_t = 100)]
  slots: u32,
  /// Length of each cycle's mixed load.
  #[arg(long, default_value = "60s", value_parser = parse_duration)]
  duration: Duration,
  #[arg(long, default_value_t = 1)]
  cycles: u32,
  /// Probes only, before each cycle's load: sets its latency and memory baselines.
  #[arg(long, default_value = "30s", value_parser = parse_duration)]
  warmup: Duration,
  /// Idle time after each cycle's load, before the leak check.
  #[arg(long, default_value = "10s", value_parser = parse_duration)]
  drain: Duration,
  /// Latency probe connections, and echoes per second on each.
  #[arg(long, default_value_t = 8)]
  probes: u32,
  #[arg(long, default_value_t = 100)]
  probe_rate: u32,
  /// After each cycle's drain, open this many connections and hold them (needs --pid).
  #[arg(long)]
  fd_flood: Option<u32>,
  /// JSONL output; defaults to /mnt/nvme1tb/claude-tmp/soak/soak-<seed>.jsonl.
  #[arg(long)]
  out: Option<PathBuf>,
  /// Source addresses to spread the slots over, as `a-b` ranges or a comma list.
  #[arg(long)]
  source_ips: Option<String>,
}

#[derive(clap::Args)]
struct ReplayArgs {
  #[command(flatten)]
  common: Common,
  /// `SEED:SLOT:GEN`, as a failure prints it.
  id: String,
}

fn parse_duration(s: &str) -> Result<Duration, String> {
  let (num, unit) = s.find(|el: char| !el.is_ascii_digit()).map_or((s, "s"), |at| s.split_at(at));
  let num: u64 = num.parse().map_err(|_| format!("bad duration `{s}`"))?;
  match unit {
    "ms" => Ok(Duration::from_millis(num)),
    "s" => Ok(Duration::from_secs(num)),
    "m" => Ok(Duration::from_secs(num * 60)),
    "h" => Ok(Duration::from_secs(num * 3600)),
    _ => Err(format!("bad duration unit in `{s}`")),
  }
}

fn parse_ips(s: &str) -> Result<Vec<IpAddr>, String> {
  let mut ips = Vec::new();
  for part in s.split(',') {
    if let Some((first, last)) = part.split_once('-') {
      let first: Ipv4Addr = first.parse().map_err(|_| format!("bad address `{first}`"))?;
      let last: Ipv4Addr = last.parse().map_err(|_| format!("bad address `{last}`"))?;
      ips.extend((u32::from(first)..=u32::from(last)).map(|el| IpAddr::V4(el.into())));
    } else {
      ips.push(part.parse().map_err(|_| format!("bad address `{part}`"))?);
    }
  }
  Ok(ips)
}

fn ctx(common: &Common) -> Result<(Ctx, Weights), String> {
  let rest = common.url.strip_prefix("ws://").ok_or("only ws:// URLs are supported")?;
  let (authority, path) = rest.find('/').map_or((rest, "/"), |at| rest.split_at(at));
  let addr: SocketAddr = authority
    .to_socket_addrs()
    .map_err(|err| format!("{authority}: {err}"))?
    .next()
    .ok_or_else(|| format!("{authority} resolves to nothing"))?;
  let weights = match &common.weights {
    Some(spec) => parse_weights(spec)?,
    None => {
      profile(&common.profile).ok_or_else(|| format!("unknown profile {}", common.profile))?
    }
  };
  let limits = Limits {
    handshake: common.handshake_timeout,
    idle: common.idle_timeout,
    close: common.close_timeout,
    max_payload: common.max_payload,
    ..Limits::default()
  };
  let host = authority.to_owned();
  Ok((Ctx { addr, host, path: path.to_owned(), limits, opts: ConnOpts::default() }, weights))
}

/// Raises the descriptor limit to its hard limit: every slot holds a socket or two.
fn raise_nofile() {
  let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
  // SAFETY: valid out pointer
  if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
    lim.rlim_cur = lim.rlim_max;
    // SAFETY: valid pointer
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) };
  }
}

fn main() -> ExitCode {
  let cli = Cli::parse();
  raise_nofile();
  let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime");
  let rslt = match cli.cmd {
    Cmd::Run(args) => runtime.block_on(run(args)),
    Cmd::Replay(args) => runtime.block_on(replay_one(args)),
  };
  rslt.unwrap_or_else(|err| {
    eprintln!("error: {err}");
    ExitCode::from(3)
  })
}

async fn run(args: RunArgs) -> Result<ExitCode, String> {
  let (ctx, weights) = ctx(&args.common)?;
  let source_ips = args.source_ips.as_deref().map(parse_ips).transpose()?.unwrap_or_default();
  let out_path = args
    .out
    .unwrap_or_else(|| format!("/mnt/nvme1tb/claude-tmp/soak/soak-{}.jsonl", args.seed).into());
  if let Some(dir) = out_path.parent() {
    std::fs::create_dir_all(dir).map_err(|err| format!("{}: {err}", dir.display()))?;
  }
  let mut out = std::io::BufWriter::new(
    std::fs::File::create(&out_path).map_err(|err| format!("{}: {err}", out_path.display()))?,
  );
  let port = ctx.addr.port();
  let cfg = CycleConfig {
    run: RunConfig {
      global_seed: args.seed,
      slots: args.slots,
      duration: args.duration,
      weights,
      ctx,
      source_ips,
    },
    pid: args.pid,
    port,
    cycles: args.cycles,
    warmup: args.warmup,
    drain: args.drain,
    probes: args.probes,
    probe_rate: args.probe_rate,
    fd_flood: args.fd_flood,
  };
  let summary = cycle::run(cfg, &mut out).await;
  eprintln!(
    "cycles {}, records {}, fails {}, harness errors {}, violations {}, saturated cycles {}; {}",
    summary.cycles,
    summary.records,
    summary.fails,
    summary.harness_errors,
    summary.violations.len(),
    summary.client_saturated_cycles,
    out_path.display()
  );
  Ok(ExitCode::from(if summary.fails > 0 || !summary.violations.is_empty() {
    1
  } else if summary.harness_errors > 0 {
    2
  } else {
    0
  }))
}

async fn replay_one(args: ReplayArgs) -> Result<ExitCode, String> {
  let (ctx, weights) = ctx(&args.common)?;
  let id = parse_replay(&args.id).ok_or_else(|| format!("bad replay id `{}`", args.id))?;
  let record = replay(&ctx, &weights, id).await;
  println!(
    "{:?} {} {}",
    record.scenario,
    record.outcome,
    record.reason.as_deref().unwrap_or_default()
  );
  if let Some(transcript) = &record.transcript {
    println!("{transcript}");
  }
  Ok(ExitCode::from(u8::from(record.outcome != "pass")))
}
