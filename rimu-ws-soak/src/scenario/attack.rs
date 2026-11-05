//! A public server's attackers: malformed and oversized upgrade requests, and floods of tiny
//! frames that cost the server more than they cost the client.

use super::{
  Ctx, Mode, Outcome,
  echo::{Expect, exchange},
  fail, fail_should, from_err,
};
use crate::{
  codec::{accept_key, client_frame},
  conn::{Conn, ConnError, Next},
  rng::Rng,
};
use rand::Rng as _;
use std::time::Duration;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  time::{Instant, timeout, timeout_at},
};

/// How long a complete upgrade request may go unanswered.
const ANSWER: Duration = Duration::from_secs(1);
/// Header bytes a server may read before refusing an endless request.
const HEADER_CAP: usize = 1 << 20;
/// The endless request is sent in steps of this many bytes, one per pause.
const FLOOD_STEP: usize = 16 * 1024;
const FLOOD_PACE: Duration = Duration::from_millis(5);
/// How long a send must block to show the server stopped reading.
const BLOCKED: Duration = Duration::from_millis(500);

/// A malformed or unusual upgrade request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpgradeCase {
  // RFC 6455 4.2.1 has the server refuse these.
  NoKey,
  ShortKey,
  BadVersion,
  Post,
  Http10,
  NoUpgrade,
  NoConnection,
  // A server may refuse these or upgrade them, but must answer at once either way.
  LfOnly,
  NoColon,
  NulInValue,
  LongPath,
  ManyHeaders,
  DuplicateKey,
  ObsFold,
  // Frames right behind the request, in the same write: upgraded, then echoed.
  Pipelined,
}

impl UpgradeCase {
  pub const ALL: [UpgradeCase; 15] = [
    Self::NoKey,
    Self::ShortKey,
    Self::BadVersion,
    Self::Post,
    Self::Http10,
    Self::NoUpgrade,
    Self::NoConnection,
    Self::LfOnly,
    Self::NoColon,
    Self::NulInValue,
    Self::LongPath,
    Self::ManyHeaders,
    Self::DuplicateKey,
    Self::ObsFold,
    Self::Pipelined,
  ];

  /// Whether the server must refuse it.
  pub fn must_refuse(self) -> bool {
    matches!(
      self,
      Self::NoKey
        | Self::ShortKey
        | Self::BadVersion
        | Self::Post
        | Self::Http10
        | Self::NoUpgrade
        | Self::NoConnection
    )
  }
}

fn key(rng: &mut Rng, len: usize) -> String {
  use base64::Engine as _;
  let bytes: Vec<u8> = (0..len).map(|_| rng.random()).collect();
  base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The request bytes of `case`, and the keys a 101 may answer.
pub fn request(case: UpgradeCase, host: &str, path: &str, rng: &mut Rng) -> (Vec<u8>, Vec<String>) {
  let main_key = key(rng, if case == UpgradeCase::ShortKey { 8 } else { 16 });
  let mut keys = vec![main_key.clone()];
  let mut headers: Vec<(String, String)> = [
    ("Host", host),
    ("Upgrade", "websocket"),
    ("Connection", "Upgrade"),
    ("Sec-WebSocket-Key", &main_key),
    ("Sec-WebSocket-Version", "13"),
  ]
  .iter()
  .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
  .collect();
  let (mut method, mut target, mut version, mut eol) = ("GET", path.to_owned(), "HTTP/1.1", "\r\n");
  let mut raw_lines = Vec::new();
  match case {
    UpgradeCase::NoKey => headers.retain(|el| el.0 != "Sec-WebSocket-Key"),
    UpgradeCase::BadVersion => headers[4].1 = "8".into(),
    UpgradeCase::Post => method = "POST",
    UpgradeCase::Http10 => version = "HTTP/1.0",
    UpgradeCase::NoUpgrade => headers.retain(|el| el.0 != "Upgrade"),
    UpgradeCase::NoConnection => headers.retain(|el| el.0 != "Connection"),
    UpgradeCase::LfOnly => eol = "\n",
    UpgradeCase::NoColon => raw_lines.push("X-Broken a header without a colon".to_owned()),
    UpgradeCase::NulInValue => headers.push(("X-Nul".into(), "a\0b".into())),
    UpgradeCase::LongPath => {
      let sep = if target.contains('?') { '&' } else { '?' };
      target = format!("{target}{sep}pad={}", "a".repeat(8192));
    }
    UpgradeCase::ManyHeaders => {
      headers.extend((0..100).map(|idx| (format!("X-Pad-{idx}"), "v".to_owned())));
    }
    UpgradeCase::DuplicateKey => {
      let other = key(rng, 16);
      keys.push(other.clone());
      headers.push(("Sec-WebSocket-Key".into(), other));
    }
    UpgradeCase::ObsFold => raw_lines.push("X-Fold: a\r\n folded".to_owned()),
    UpgradeCase::ShortKey | UpgradeCase::Pipelined => {}
  }
  let mut out = format!("{method} {target} {version}{eol}");
  for (name, value) in &headers {
    out.push_str(&format!("{name}: {value}{eol}"));
  }
  for line in raw_lines {
    out.push_str(&line);
    out.push_str(eol);
  }
  out.push_str(eol);
  (out.into_bytes(), keys)
}

/// A random case.
pub(super) async fn bad_upgrade(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let case = UpgradeCase::ALL[rng.random_range(0..UpgradeCase::ALL.len())];
  run_upgrade_case(case, ctx, rng).await
}

/// Sends `case`'s request: the server must answer within a second, refuse what RFC 6455 has it
/// refuse, and if it upgrades, answer the right key and echo.
pub async fn run_upgrade_case(case: UpgradeCase, ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let (mut req, keys) = request(case, &ctx.host, &ctx.path, rng);
  if case == UpgradeCase::Pipelined {
    client_frame(true, 1, b"piped", rng.random(), &mut req);
  }
  let mut conn = match Conn::connect(ctx.addr, &ctx.opts).await {
    Ok(conn) => conn,
    Err(err) => return from_err(err, None),
  };
  conn.transcript_mut().note(&format!("{case:?}"));
  if let Err(err) = conn.send(&req).await {
    return from_err(err, Some(&conn));
  }
  let res = match conn.read_response(Instant::now() + ANSWER).await {
    Ok(res) => res,
    // Without a handshake timeout a server may leave it unanswered; the monitor judges that.
    Err(ConnError::Server(_)) if ctx.mode == Mode::Common => {
      conn.reset();
      return Outcome::Pass;
    }
    Err(ConnError::Server(_)) => {
      return fail(format!("{case:?}: neither answered nor closed within {ANSWER:?}"), &conn);
    }
    Err(err) => return from_err(err, Some(&conn)),
  };
  let Some(res) = res.filter(|el| el.status == 101) else {
    if case == UpgradeCase::Pipelined {
      // RFC 6455 4.1 lets a client send frames before it has the 101.
      return fail_should("a valid request with frames behind it was refused", &conn);
    }
    conn.reset();
    return Outcome::Pass;
  };
  if case.must_refuse() {
    return fail(format!("{case:?}: upgraded a request RFC 6455 has the server refuse"), &conn);
  }
  if !keys.iter().any(|key| res.accept.as_deref() == Some(accept_key(key).as_str())) {
    return fail(format!("{case:?}: bad Sec-WebSocket-Accept {:?}", res.accept), &conn);
  }
  if case != UpgradeCase::Pipelined {
    let mut frame = Vec::new();
    client_frame(true, 1, b"piped", rng.random(), &mut frame);
    if let Err(err) = conn.send(&frame).await {
      return from_err(err, Some(&conn));
    }
  }
  match conn.next_frame(Instant::now() + ANSWER).await {
    Ok(Next::Frame(echo)) if echo.opcode == 1 && echo.payload == b"piped" => {
      conn.reset();
      Outcome::Pass
    }
    Ok(other) => fail(format!("{case:?}: upgraded, then {other:?} instead of the echo"), &conn),
    Err(err) => from_err(err, Some(&conn)),
  }
}

/// A request whose last header never ends, at about 3 MB/s. The server must refuse it, or close,
/// before reading 1 MiB of it: a server that buffers it holds memory, and one that re-parses it on
/// every read burns CPU, both growing with the attacker's bandwidth.
pub(super) async fn header_flood(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let opts = crate::conn::ConnOpts { nodelay: true, ..ctx.opts.clone() };
  let mut conn = match Conn::connect(ctx.addr, &opts).await {
    Ok(conn) => conn,
    Err(err) => return from_err(err, None),
  };
  let head = format!("GET {} HTTP/1.1\r\nHost: {}\r\nX-Pad: ", ctx.path, ctx.host);
  let step: Vec<u8> = (0..FLOOD_STEP).map(|_| rng.random_range(b'a'..=b'z')).collect();
  let mut buf = vec![0; 4096];
  let mut sent = 0usize;
  let mut next: &[u8] = head.as_bytes();
  loop {
    if sent >= HEADER_CAP {
      if ctx.mode == Mode::Common {
        // What it holds is the monitor's to judge.
        conn.reset();
        return Outcome::Pass;
      }
      return fail(format!("still reading an unterminated request after {sent} bytes"), &conn);
    }
    match timeout(BLOCKED, conn.raw().write_all(next)).await {
      Ok(Ok(())) => sent += next.len(),
      // Closed on us: refused.
      Ok(Err(_)) => return Outcome::Pass,
      // A server that stopped reading holds what it read; the monitor judges that.
      Err(_) if ctx.mode == Mode::Common => {
        conn.reset();
        return Outcome::Pass;
      }
      // It stopped reading without closing: it must close before the handshake timeout ends.
      Err(_) => {
        let deadline = Instant::now() + super::slack(ctx.limits.handshake);
        return match conn.expect_eof(deadline).await {
          Ok(()) => Outcome::Pass,
          Err(err) => from_err(err, Some(&conn)),
        };
      }
    }
    next = &step;
    match timeout_at(Instant::now() + FLOOD_PACE, conn.raw().read(&mut buf)).await {
      Err(_) => {}
      Ok(Ok(0) | Err(_)) => return Outcome::Pass,
      Ok(Ok(len)) if buf[..len].starts_with(b"HTTP/1.1 101") => {
        return fail("an unterminated request was answered 101", &conn);
      }
      Ok(Ok(_)) => return Outcome::Pass,
    }
  }
}

/// One message in 10 000 to 40 000 one-byte fragments: echoed whole.
pub(super) async fn frag_flood(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let len = rng.random_range(10_000..=40_000);
  let text: Vec<u8> = (0..len).map(|_| rng.random_range(b'a'..=b'z')).collect();
  let mut data = Vec::with_capacity(len * 7);
  for (idx, byte) in text.iter().enumerate() {
    let opcode = if idx == 0 { 1 } else { 0 };
    client_frame(idx + 1 == len, opcode, &[*byte], rng.random(), &mut data);
  }
  client_frame(true, 8, &1000u16.to_be_bytes(), rng.random(), &mut data);
  let expected = vec![Expect::Message(1, text), Expect::Close(1000)];
  exchange(ctx, &ctx.opts, rng, data, vec![65536], expected).await
}

/// 10 000 to 30 000 empty messages: each echoed.
pub(super) async fn zero_flood(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let count = rng.random_range(10_000..=30_000);
  let mut data = Vec::with_capacity(count * 6);
  let mut expected = Vec::with_capacity(count + 1);
  for _ in 0..count {
    client_frame(true, 2, &[], rng.random(), &mut data);
    expected.push(Expect::Message(2, Vec::new()));
  }
  client_frame(true, 8, &1000u16.to_be_bytes(), rng.random(), &mut data);
  expected.push(Expect::Close(1000));
  exchange(ctx, &ctx.opts, rng, data, vec![65536], expected).await
}
