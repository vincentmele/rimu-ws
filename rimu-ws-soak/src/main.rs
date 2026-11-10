//! `rimu-ws-soak run ...` soaks a server; `rimu-ws-soak replay SEED:SLOT:GEN ...` reruns one
//! scenario run alone and prints its transcript.

use clap::Parser as _;
use rimu_ws_soak::{
  conn::ConnOpts,
  cycle::{self, CycleConfig, Extended, RecordMode},
  runner::{RunConfig, parse_replay, replay},
  scenario::{Ctx, Limits, Proto, Weights, parse_weights, profile},
};
use std::{
  net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs as _},
  path::PathBuf,
  process::ExitCode,
  time::Duration,
};

#[derive(clap::Parser)]
// A later occurrence of an option overrides an earlier one: `soak.sh long` puts its defaults first.
#[command(about = "Soak and abuse harness for WebSocket servers", args_override_self = true)]
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
  /// Soaks an HTTP/3 server: a steady client plus the abusive QUIC/HTTP/3 clients (task 23).
  H3(H3Args),
}

#[derive(clap::Args)]
struct H3Args {
  /// The multi-worker h3 server, as `https://127.0.0.1:8443`.
  #[arg(long, default_value = "https://127.0.0.1:8443")]
  url: String,
  /// The server's pid, for the monitor.
  #[arg(long)]
  pid: Option<u32>,
  /// A one-worker h3 server for the per-worker caps (idle × 4,096), as `https://127.0.0.1:8444`.
  #[arg(long)]
  idle_url: Option<String>,
  /// The one-worker server's pid.
  #[arg(long)]
  idle_pid: Option<u32>,
  /// The whole run (steady plus abusers).
  #[arg(long, default_value = "600s", value_parser = parse_duration)]
  duration: Duration,
  /// Probe-only time at the start that sets the RSS plateau.
  #[arg(long, default_value = "30s", value_parser = parse_duration)]
  warmup: Duration,
  /// Steady connections.
  #[arg(long, default_value_t = 64)]
  conns: u32,
  /// Streams per steady connection.
  #[arg(long, default_value_t = 64)]
  streams: u32,
  /// The multi-worker server's worker count, for the report.
  #[arg(long, default_value_t = 4)]
  workers: u32,
  /// JSONL output; defaults to /mnt/nvme1tb/claude-tmp/soak/h3-soak.jsonl.
  #[arg(long)]
  out: Option<PathBuf>,
}

#[derive(clap::Args)]
struct Common {
  /// The server's WebSocket URL (plain `ws://` only), or with `--proto h2` its `http://` URL.
  #[arg(long, default_value = "ws://127.0.0.1:9080/")]
  url: String,
  /// The protocol the server speaks: WebSocket, or HTTP/2 without TLS (prior knowledge).
  #[arg(long, value_enum, default_value_t = Proto::Ws)]
  proto: Proto,
  /// Weighted mix: `baseline`, `hostile`, `storm`, `untimed`, `drip` or `deflate`. A comma
  /// list (`hostile,storm`) rotates them by cycle; replay with the failing cycle's profile.
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
  /// The server's SO_SNDBUF (at most 32 KiB), which `close_linger` needs; without it, that
  /// scenario is left out.
  #[arg(long)]
  server_sndbuf: Option<u32>,
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
  /// Which scenario runs `--out` keeps: `all`, or `failures` (and harness errors) for long runs.
  #[arg(long, value_enum, default_value_t = Records::All)]
  records: Records,
  /// How often to sum up the run so far, on stderr and as a `heartbeat` line.
  #[arg(long, value_parser = parse_duration)]
  heartbeat: Option<Duration>,
  /// Cycles in a row the memory after the drain, or its peak, may rise (by over 8 MiB and 2% in
  /// all) before that is a violation. 0 turns the check off.
  #[arg(long, default_value_t = 0)]
  trend: u32,
  /// Kills the server past this RSS in MiB (needs --pid), which ends the run.
  #[arg(long)]
  rss_ceiling: Option<u64>,
  /// Starts no cycle, and stops the load, this long into the run.
  #[arg(long, value_parser = parse_duration)]
  max_time: Option<Duration>,
  /// Ends the run at the first failure or violation.
  #[arg(long)]
  stop_on_first: bool,
  /// After each cycle's recovery check, opens this many connections at once; each must upgrade
  /// and echo within 5 s.
  #[arg(long)]
  burst: Option<u32>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Records {
  All,
  Failures,
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

/// The context, the first profile's weights, and every profile when `--profile` lists several.
fn ctx(common: &Common) -> Result<(Ctx, Weights, Vec<(String, Weights)>), String> {
  let scheme = if common.proto == Proto::H2 { "http://" } else { "ws://" };
  let rest =
    common.url.strip_prefix(scheme).ok_or_else(|| format!("only {scheme} URLs are supported"))?;
  let (authority, path) = rest.find('/').map_or((rest, "/"), |at| rest.split_at(at));
  let addr: SocketAddr = authority
    .to_socket_addrs()
    .map_err(|err| format!("{authority}: {err}"))?
    .next()
    .ok_or_else(|| format!("{authority} resolves to nothing"))?;
  let mut rotation = Vec::new();
  let weights = match &common.weights {
    Some(spec) => parse_weights(spec)?,
    None => {
      for name in common.profile.split(',').map(str::trim) {
        let weights =
          profile(name, common.proto).ok_or_else(|| format!("unknown profile {name}"))?;
        rotation.push((name.to_owned(), weights));
      }
      let first = rotation.first().map(|el| el.1.clone()).ok_or("no profile")?;
      if rotation.len() == 1 {
        rotation.clear();
      }
      first
    }
  };
  let limits = Limits {
    handshake: common.handshake_timeout,
    idle: common.idle_timeout,
    close: common.close_timeout,
    max_payload: common.max_payload,
    server_sndbuf: common.server_sndbuf,
    ..Limits::default()
  };
  if common.server_sndbuf.is_some_and(|el| el > 32 * 1024) {
    return Err("--server-sndbuf must be at most 32 KiB".into());
  }
  let weights = weights.for_limits(&limits)?;
  let rotation = rotation
    .into_iter()
    .map(|(name, weights)| Ok((name, weights.for_limits(&limits)?)))
    .collect::<Result<Vec<_>, String>>()?;
  let host = authority.to_owned();
  Ok((
    Ctx {
      addr,
      host,
      path: path.to_owned(),
      limits,
      opts: ConnOpts::default(),
      proto: common.proto,
    },
    weights,
    rotation,
  ))
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
    Cmd::H3(args) => runtime.block_on(run_h3(args)),
  };
  rslt.unwrap_or_else(|err| {
    eprintln!("error: {err}");
    ExitCode::from(3)
  })
}

async fn run(args: RunArgs) -> Result<ExitCode, String> {
  let (ctx, weights, rotation) = ctx(&args.common)?;
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
    ext: Extended {
      rotation,
      records: match args.records {
        Records::All => RecordMode::All,
        Records::Failures => RecordMode::Failures,
      },
      heartbeat: args.heartbeat,
      trend: args.trend,
      rss_ceiling_kib: args.rss_ceiling.map(|el| el * 1024),
      max_time: args.max_time,
      stop_on_first: args.stop_on_first,
      burst: args.burst,
    },
  };
  let summary = cycle::run(cfg, &mut out).await;
  eprintln!(
    "cycles {}, records {}, fails {}, harness errors {}, violations {}, saturated cycles {}; probe p50/p99/p99.9/max {}/{}/{}/{} us{}; {}",
    summary.cycles,
    summary.records,
    summary.fails,
    summary.harness_errors,
    summary.violations.len(),
    summary.client_saturated_cycles,
    summary.latency.p50_us,
    summary.latency.p99_us,
    summary.latency.p999_us,
    summary.latency.max_us,
    summary.stopped.as_deref().map(|el| format!("; stopped: {el}")).unwrap_or_default(),
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
  let (ctx, weights, rotation) = ctx(&args.common)?;
  if !rotation.is_empty() {
    return Err("replay one profile: the one of the failing cycle".into());
  }
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

/// Parses an `https://host:port` URL to a socket address (the h3 soak speaks HTTPS only).
fn parse_h3_url(url: &str) -> Result<SocketAddr, String> {
  let rest = url.strip_prefix("https://").ok_or("only https:// URLs are supported")?;
  let authority = rest.split('/').next().unwrap_or(rest);
  authority
    .to_socket_addrs()
    .map_err(|err| format!("{authority}: {err}"))?
    .next()
    .ok_or_else(|| format!("{authority} resolves to nothing"))
}

/// The soft `RLIMIT_MEMLOCK` in KiB, or `None` when it is unlimited (ruling T23-d).
fn memlock_kib() -> Option<u64> {
  let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
  // SAFETY: valid out pointer
  if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) } != 0 {
    return None;
  }
  if lim.rlim_cur == libc::RLIM_INFINITY { None } else { Some(lim.rlim_cur / 1024) }
}

async fn run_h3(args: H3Args) -> Result<ExitCode, String> {
  let main_addr = parse_h3_url(&args.url)?;
  let idle_addr = args.idle_url.as_deref().map(parse_h3_url).transpose()?;
  let out_path = args.out.unwrap_or_else(|| "/mnt/nvme1tb/claude-tmp/soak/h3-soak.jsonl".into());
  if let Some(dir) = out_path.parent() {
    std::fs::create_dir_all(dir).map_err(|err| format!("{}: {err}", dir.display()))?;
  }
  let mut out = std::io::BufWriter::new(
    std::fs::File::create(&out_path).map_err(|err| format!("{}: {err}", out_path.display()))?,
  );
  let cfg = rimu_ws_soak::quic::driver::H3Config {
    main_addr,
    main_pid: args.pid,
    idle_addr,
    idle_pid: args.idle_pid,
    duration: args.duration,
    warmup: args.warmup,
    conns: args.conns,
    streams: args.streams,
    out: out_path.clone(),
    main_workers: args.workers,
    memlock_kib: memlock_kib(),
  };
  let fails = rimu_ws_soak::quic::driver::run(cfg, &mut out).await;
  use std::io::Write as _;
  out.flush().map_err(|err| format!("{}: {err}", out_path.display()))?;
  eprintln!("h3 soak: {fails} failures; {}", out_path.display());
  Ok(ExitCode::from(if fails > 0 { 1 } else { 0 }))
}
