//! HTTP/2 clients against `soak-server-h2`: steady traffic with checked bodies, and the attacks
//! and resource abuse an HTTP/2 server meets (rapid reset, CONTINUATION, SETTINGS and PING
//! floods, slow and absent readers, starved windows, half-open connections, oversized messages).

use super::{Ctx, Outcome, fail, from_err, slack};
use crate::{
  conn::{Conn, ConnError, ConnOpts},
  h2codec::{
    CONTINUATION, DATA, END_HEADERS, END_STREAM, H2, HEADERS, PING, RST_STREAM, SETTINGS, frame,
    header_block, request,
  },
  rng::Rng,
};
use rand::Rng as _;
use std::time::Duration;
use tokio::time::{Instant, sleep};

/// How long a response may take.
const RESPONSE: Duration = Duration::from_secs(5);
/// How long a server may take to close once it has every reason to.
const CLOSE: Duration = Duration::from_secs(2);
/// ENHANCE_YOUR_CALM.
const CALM: u32 = 11;
/// The size of `/static/big.bin`.
const BIG: usize = 10 << 20;

async fn open(ctx: &Ctx, opts: &ConnOpts, initial_window: Option<u32>) -> Result<H2, Outcome> {
  let conn = Conn::connect(ctx.addr, opts).await.map_err(|err| from_err(err, None))?;
  H2::open(conn, initial_window).await.map_err(|err| from_err(err, None))
}

fn h2_fail(reason: impl Into<String>, h2: &H2) -> Outcome {
  fail(reason, &h2.conn)
}

/// Byte `i` of a soak static file.
fn static_byte(idx: usize) -> u8 {
  (idx % 251) as u8
}

/// One connection, 100 streams in batches of 25: `GET /baseline2` answers `ok`, `POST /echo` its
/// body (up to 2 KiB, so a batch stays within the initial windows).
pub(super) async fn steady(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let mut h2 = match open(ctx, &ctx.opts, None).await {
    Ok(elem) => elem,
    Err(outcome) => return outcome,
  };
  let mut id = 1;
  for _ in 0..4 {
    let mut bytes = Vec::new();
    let mut expected = Vec::new();
    for _ in 0..25 {
      if rng.random_bool(0.5) {
        bytes.extend(request(id, "GET", "/baseline2", &[], true));
        expected.push((id, b"ok".to_vec()));
      } else {
        let body: Vec<u8> = (0..rng.random_range(1..=2048)).map(|_| rng.random()).collect();
        bytes.extend(request(id, "POST", "/echo", &[], false));
        bytes.extend(frame(DATA, END_STREAM, id, &body));
        expected.push((id, body));
      }
      id += 2;
    }
    if let Err(err) = h2.conn.send(&bytes).await {
      return from_err(err, Some(&h2.conn));
    }
    let ids: Vec<u32> = expected.iter().map(|el| el.0).collect();
    let got = match h2.collect(&ids, Instant::now() + RESPONSE).await {
      Ok(elem) => elem,
      Err(err) => return from_err(err, Some(&h2.conn)),
    };
    for (stream, body) in expected {
      let Some(response) = got.responses.get(&stream) else {
        return h2_fail(format!("no response on stream {stream} ({:?})", got.go_away), &h2);
      };
      if response.status != Some(200) || !response.ended || response.body != body {
        let reason = format!(
          "stream {stream}: status {:?}, ended {}, reset {:?}, {} of {} body bytes",
          response.status,
          response.ended,
          response.reset,
          response.body.len(),
          body.len()
        );
        return h2_fail(reason, &h2);
      }
    }
  }
  Outcome::Pass
}

/// Sends `bytes` (a flood), then expects GOAWAY with `code` and the close. A send that fails
/// halfway means the server closed already, which still has to show its GOAWAY.
async fn flood(ctx: &Ctx, bytes: &[u8], code: u32, what: &str) -> Outcome {
  let mut h2 = match open(ctx, &ctx.opts, None).await {
    Ok(elem) => elem,
    Err(outcome) => return outcome,
  };
  if let Err(err @ ConnError::Harness(_)) = h2.conn.send(bytes).await {
    return from_err(err, Some(&h2.conn));
  }
  let got = match h2.collect(&[u32::MAX], Instant::now() + slack(CLOSE) + RESPONSE).await {
    Ok(elem) => elem,
    Err(err) => return from_err(err, Some(&h2.conn)),
  };
  match got.go_away {
    Some((got_code, _)) if got_code == code || code == 0 && got_code != 0 => {}
    other => return h2_fail(format!("{what}: GOAWAY {other:?}, expected code {code}"), &h2),
  }
  match h2.conn.expect_eof(Instant::now() + slack(CLOSE)).await {
    Ok(()) => Outcome::Pass,
    Err(err) => from_err(err, Some(&h2.conn)),
  }
}

/// Streams opened and reset at once, past the server's reset budget (CVE-2023-44487).
pub(super) async fn rapid_reset(ctx: &Ctx, _: &mut Rng) -> Outcome {
  let mut bytes = Vec::new();
  for idx in 0..1000u32 {
    let id = 2 * idx + 1;
    // A request with a body to come keeps the stream open until the reset.
    bytes.extend(request(id, "POST", "/echo", &[], false));
    bytes.extend(frame(RST_STREAM, 0, id, &8u32.to_be_bytes()));
  }
  flood(ctx, &bytes, CALM, "rapid reset").await
}

/// A header block that never ends: CONTINUATION after CONTINUATION.
pub(super) async fn continuation_flood(ctx: &Ctx, _: &mut Rng) -> Outcome {
  let block = header_block("GET", "/baseline2", &[("x-pad", &"p".repeat(64))]);
  let mut bytes = frame(HEADERS, END_STREAM, 1, &block[..8]);
  for _ in 0..1000 {
    bytes.extend(frame(CONTINUATION, 0, 1, &[0x40, 1, b'x', 1, b'y']));
  }
  flood(ctx, &bytes, 0, "CONTINUATION flood").await
}

/// SETTINGS frames, each owed an acknowledgement, past the control-frame budget.
pub(super) async fn settings_flood(ctx: &Ctx, _: &mut Rng) -> Outcome {
  let mut bytes = Vec::new();
  for _ in 0..3000 {
    bytes.extend(frame(SETTINGS, 0, 0, &[]));
  }
  flood(ctx, &bytes, CALM, "SETTINGS flood").await
}

/// PINGs past the control-frame budget.
pub(super) async fn ping_flood(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let mut bytes = Vec::new();
  for _ in 0..3000 {
    bytes.extend(frame(PING, 0, 0, &rng.random::<[u8; 8]>()));
  }
  flood(ctx, &bytes, CALM, "PING flood").await
}

/// Reads a 10 MiB response 1 KiB a second for 8 s, through a 4 KiB receive buffer: what arrives
/// is right, and the server's memory (the monitor) and other clients (the probes) don't suffer.
pub(super) async fn slow_reader(ctx: &Ctx, _: &mut Rng) -> Outcome {
  let opts = ConnOpts { rcvbuf: Some(4096), ..ctx.opts.clone() };
  let mut h2 = match open(ctx, &opts, None).await {
    Ok(elem) => elem,
    Err(outcome) => return outcome,
  };
  if let Err(err) = h2.conn.send(&request(1, "GET", "/static/big.bin", &[], true)).await {
    return from_err(err, Some(&h2.conn));
  }
  let mut body = 0usize;
  for _ in 0..8 {
    sleep(Duration::from_secs(1)).await;
    if let Err(err) = h2.read_at_most(1024, Instant::now() + RESPONSE).await {
      return from_err(err, Some(&h2.conn));
    }
    let frames = match h2.buffered_frames() {
      Ok(elem) => elem,
      Err(err) => return from_err(err, Some(&h2.conn)),
    };
    for frame in frames.iter().filter(|el| el.stream == 1) {
      if frame.ty == RST_STREAM {
        return h2_fail("the slow read was reset", &h2);
      }
      if frame.ty != DATA {
        continue;
      }
      if frame.payload.iter().enumerate().any(|(idx, byte)| *byte != static_byte(body + idx)) {
        return h2_fail(format!("wrong bytes at {body}"), &h2);
      }
      body += frame.payload.len();
    }
  }
  h2.conn.reset();
  Outcome::Pass
}

/// Asks for 20 copies of a 10 MiB file through a 4 KiB receive buffer and never reads: once its
/// sends stall, the server must close within its idle timeout, long before sending them all.
pub(super) async fn never_read(ctx: &Ctx, _: &mut Rng) -> Outcome {
  let opts = ConnOpts { rcvbuf: Some(4096), ..ctx.opts.clone() };
  let mut h2 = match open(ctx, &opts, None).await {
    Ok(elem) => elem,
    Err(outcome) => return outcome,
  };
  let mut bytes = Vec::new();
  for idx in 0..20u32 {
    bytes.extend(request(2 * idx + 1, "GET", "/static/big.bin", &[], true));
  }
  if let Err(err) = h2.conn.send(&bytes).await {
    return from_err(err, Some(&h2.conn));
  }
  sleep(slack(ctx.limits.idle) + Duration::from_millis(500)).await;
  // Draining what the server had sent before it closed ends in EOF.
  let deadline = Instant::now() + Duration::from_secs(10);
  let mut read = 0usize;
  loop {
    match h2.read_at_most(1 << 20, deadline).await {
      Ok(0) if Instant::now() >= deadline => {
        return h2_fail(format!("still sending after the idle timeout: {read} bytes read"), &h2);
      }
      Ok(0) => {
        // EOF (or a reset): what was read must be far short of the 200 MiB asked for.
        return if read < 20 * BIG / 2 {
          Outcome::Pass
        } else {
          h2_fail(format!("{read} bytes read: the server never stalled"), &h2)
        };
      }
      Ok(len) => {
        read += len;
        let _frames = h2.buffered_frames();
      }
      Err(_) => return Outcome::Pass,
    }
  }
}

/// A client whose windows are 0 for good asks for a file: no DATA may come, and with nothing
/// moving the server closes within its idle timeout.
pub(super) async fn window_starved(ctx: &Ctx, _: &mut Rng) -> Outcome {
  let mut h2 = match open(ctx, &ctx.opts, Some(0)).await {
    Ok(elem) => elem,
    Err(outcome) => return outcome,
  };
  if let Err(err) = h2.conn.send(&request(1, "GET", "/static/big.bin", &[], true)).await {
    return from_err(err, Some(&h2.conn));
  }
  let deadline = Instant::now() + slack(ctx.limits.idle) + slack(CLOSE);
  loop {
    match h2.next(deadline).await {
      Ok(None) => return Outcome::Pass,
      Ok(Some(frame)) if frame.ty == DATA && !frame.payload.is_empty() => {
        return h2_fail("DATA past a window of 0", &h2);
      }
      Ok(Some(_)) => {}
      Err(ConnError::Server(failure)) => {
        return h2_fail(format!("not closed within the idle timeout: {}", failure.0), &h2);
      }
      Err(err) => return from_err(err, Some(&h2.conn)),
    }
  }
}

/// FIN right after the preface: the server closes too.
pub(super) async fn half_open(ctx: &Ctx, _: &mut Rng) -> Outcome {
  let mut h2 = match open(ctx, &ctx.opts, None).await {
    Ok(elem) => elem,
    Err(outcome) => return outcome,
  };
  h2.conn.shutdown_write().await;
  match h2.conn.expect_eof(Instant::now() + slack(CLOSE)).await {
    Ok(()) => Outcome::Pass,
    Err(err) => from_err(err, Some(&h2.conn)),
  }
}

/// After a refused request, the connection still serves, unless the server sent GOAWAY.
async fn still_serves(mut h2: H2, refused: u32, next: u32) -> Outcome {
  let got = match h2.collect(&[refused], Instant::now() + RESPONSE).await {
    Ok(elem) => elem,
    Err(err) => return from_err(err, Some(&h2.conn)),
  };
  let response = got.responses.get(&refused).cloned().unwrap_or_default();
  if response.status == Some(200) {
    return h2_fail(format!("stream {refused} was served"), &h2);
  }
  if got.go_away.is_some() || got.eof {
    return Outcome::Pass;
  }
  if response.reset.is_none() && response.status.is_none() {
    return h2_fail(format!("stream {refused}: no answer"), &h2);
  }
  if let Err(err) = h2.conn.send(&request(next, "GET", "/baseline2", &[], true)).await {
    return from_err(err, Some(&h2.conn));
  }
  match h2.collect(&[next], Instant::now() + RESPONSE).await {
    Ok(got)
      if got.responses.get(&next).is_some_and(|el| el.status == Some(200) && el.body == b"ok") =>
    {
      Outcome::Pass
    }
    Ok(got) => h2_fail(format!("no answer after the refusal: {:?}", got.responses.get(&next)), &h2),
    Err(err) => from_err(err, Some(&h2.conn)),
  }
}

/// A 100 KiB header field, over HEADERS and CONTINUATIONs of 16 KiB: refused (reset, 431 or
/// GOAWAY), never served.
pub(super) async fn oversized_headers(ctx: &Ctx, _: &mut Rng) -> Outcome {
  let mut h2 = match open(ctx, &ctx.opts, None).await {
    Ok(elem) => elem,
    Err(outcome) => return outcome,
  };
  let block = header_block("GET", "/baseline2", &[("x-big", &"b".repeat(100 << 10))]);
  let chunks: Vec<&[u8]> = block.chunks(16_384).collect();
  let mut bytes = Vec::new();
  for (idx, chunk) in chunks.iter().enumerate() {
    let last = idx + 1 == chunks.len();
    let (ty, flags) = if idx == 0 { (HEADERS, END_STREAM) } else { (CONTINUATION, 0) };
    bytes.extend(frame(ty, flags | if last { END_HEADERS } else { 0 }, 1, chunk));
  }
  if let Err(err @ ConnError::Harness(_)) = h2.conn.send(&bytes).await {
    return from_err(err, Some(&h2.conn));
  }
  still_serves(h2, 1, 3).await
}

/// A body announced at 100 MB, past the server's limit: refused (reset, 413 or GOAWAY) after at
/// most a few windows of it, never served.
pub(super) async fn oversized_body(ctx: &Ctx, _: &mut Rng) -> Outcome {
  let mut h2 = match open(ctx, &ctx.opts, None).await {
    Ok(elem) => elem,
    Err(outcome) => return outcome,
  };
  let mut bytes = request(1, "POST", "/echo", &[("content-length", "100000000")], false);
  bytes.extend(frame(DATA, 0, 1, &[b'x'; 16_384]));
  if let Err(err @ ConnError::Harness(_)) = h2.conn.send(&bytes).await {
    return from_err(err, Some(&h2.conn));
  }
  still_serves(h2, 1, 3).await
}

/// Fills the server's caches before the baseline is measured: `/static/big.bin` and
/// `/static/small.txt` over enough connections to reach every runtime thread. Errors are left to
/// the scenarios.
pub async fn warm_h2_caches(ctx: &Ctx) {
  let mut fetches = tokio::task::JoinSet::new();
  for _ in 0..96 {
    let ctx = ctx.clone();
    let _ = fetches.spawn(async move {
      let Ok(mut h2) = open(&ctx, &ctx.opts, None).await else {
        return;
      };
      let mut bytes = request(1, "GET", "/static/big.bin", &[], true);
      bytes.extend(request(3, "GET", "/static/small.txt", &[], true));
      if h2.conn.send(&bytes).await.is_ok() {
        let _got = h2.collect(&[1, 3], Instant::now() + Duration::from_secs(30)).await;
      }
    });
  }
  while fetches.join_next().await.is_some() {}
}
