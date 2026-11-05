//! Hostile connections: clients that never read, trickle or abandon their handshake, sit idle,
//! reset mid-frame, half-close, flood pings or send garbage.

use super::{
  Ctx, Mode, Outcome,
  echo::{Expect, Oracle, encode_message, judged, message, read_expected},
  fail, from_err, slack, upgraded,
};
use crate::{
  codec::{ServerFrame, client_frame, close_code, upgrade_request},
  conn::{Conn, ConnError, ConnOpts, Exchange, Flow},
  rng::Rng,
};
use rand::Rng as _;
use std::{collections::HashSet, time::Duration};
use tokio::{
  io::AsyncReadExt,
  time::{Instant, timeout, timeout_at},
};

/// How long a send must block to show the server stopped reading.
const BLOCKED: Duration = Duration::from_millis(500);
/// How long the common mode reads what a never-read client was sent, once it starts reading.
const READ_BACK: Duration = Duration::from_millis(500);
/// How long a server may take to close once it has every reason to.
const CLOSE: Duration = Duration::from_secs(2);
/// The gap between the bytes of a trickled handshake.
const TRICKLE: Duration = Duration::from_millis(100);

fn key(rng: &mut Rng) -> String {
  use base64::Engine as _;
  base64::engine::general_purpose::STANDARD.encode(rng.random::<[u8; 16]>())
}

async fn connect(ctx: &Ctx, opts: &ConnOpts) -> Result<Conn, Outcome> {
  Conn::connect(ctx.addr, opts).await.map_err(|err| from_err(err, None))
}

async fn eof_by(mut conn: Conn, deadline: Instant) -> Outcome {
  match conn.expect_eof(deadline).await {
    Ok(()) => Outcome::Pass,
    Err(err) => from_err(err, Some(&conn)),
  }
}

/// Sends 64-byte texts with a 4 KiB receive buffer and never reads: a bounded server stops
/// reading, so a send soon blocks, or it closes.
pub(super) async fn never_read(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let text: Vec<u8> = (0..64).map(|_| rng.random_range(b'a'..=b'z')).collect();
  let mut batch = Vec::new();
  for _ in 0..64 {
    client_frame(true, 1, &text, rng.random(), &mut batch);
  }
  unread_flood(ctx, rng, &batch, &|frame| frame.opcode == 1 && frame.payload == text).await
}

/// Sends `batch` over and over with a 4 KiB receive buffer and never reads: a bounded server stops
/// reading, so a send soon blocks, or it closes.
///
/// In the common mode, a server that keeps reading is judged by its memory (the monitor), not
/// failed here: RFC 6455 lets it answer only the latest ping. The client then reads for a moment,
/// and every frame must be one the server owed it (`owed`), or a close.
pub(super) async fn unread_flood(
  ctx: &Ctx,
  rng: &mut Rng,
  batch: &[u8],
  owed: &(dyn Fn(&ServerFrame) -> bool + Sync),
) -> Outcome {
  let opts = ConnOpts { rcvbuf: Some(4096), ..ctx.opts.clone() };
  let mut conn = match upgraded(ctx, &opts, rng).await {
    Ok(conn) => conn,
    Err(outcome) => return outcome,
  };
  let begin = Instant::now();
  let mut sent = 0usize;
  loop {
    if begin.elapsed() >= ctx.limits.never_read_budget {
      if ctx.mode == Mode::Common {
        break;
      }
      let reason = format!(
        "server buffered without bound: {sent} bytes sent in {:?} without blocking",
        begin.elapsed()
      );
      return fail(reason, &conn);
    }
    match timeout(BLOCKED, conn.send(batch)).await {
      Err(_) | Ok(Err(ConnError::Server(_))) => break,
      Ok(Err(err @ ConnError::Harness(_))) => return from_err(err, Some(&conn)),
      Ok(Ok(())) => sent += batch.len(),
    }
  }
  if ctx.mode == Mode::Common {
    let deadline = Instant::now() + READ_BACK;
    loop {
      match conn.next_frame(deadline).await {
        Ok(crate::conn::Next::Frame(frame)) if frame.opcode == 8 => break,
        Ok(crate::conn::Next::Frame(frame)) if owed(&frame) => {}
        Ok(crate::conn::Next::Frame(frame)) => {
          let reason = format!("a frame the client was not owed: opcode {}", frame.opcode);
          return fail(reason, &conn);
        }
        Ok(crate::conn::Next::Eof) | Err(ConnError::Server(_)) => break,
        Err(err) => return from_err(err, Some(&conn)),
      }
    }
  }
  conn.reset();
  Outcome::Pass
}

/// Sends the upgrade request a byte every 100 ms, which keeps an idle timeout from firing: the
/// server must cut it off within its handshake timeout.
///
/// In the common mode, a server without a handshake timeout may wait for the whole request, which
/// the monitor judges; answering 101 before the request is complete is still a failure.
pub(super) async fn slowloris(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let opts = ConnOpts { nodelay: true, ..ctx.opts.clone() };
  let mut conn = match connect(ctx, &opts).await {
    Ok(conn) => conn,
    Err(outcome) => return outcome,
  };
  let common = ctx.mode == Mode::Common;
  let req = upgrade_request(&ctx.host, &ctx.path, &key(rng));
  let deadline = if common {
    Instant::now() + TRICKLE * u32::try_from(req.len()).unwrap_or(u32::MAX) + CLOSE
  } else {
    Instant::now() + slack(ctx.limits.handshake)
  };
  let mut buf = vec![0; 1024];
  let total = req.len();
  for (idx, byte) in req.into_iter().enumerate() {
    if Instant::now() >= deadline {
      let reason =
        format!("still open after {:?} of a trickled handshake", slack(ctx.limits.handshake));
      return fail(reason, &conn);
    }
    match conn.send(&[byte]).await {
      Ok(()) => {}
      Err(ConnError::Server(_)) => return Outcome::Pass,
      Err(err) => return from_err(err, Some(&conn)),
    }
    let pause = (Instant::now() + TRICKLE).min(deadline);
    match timeout_at(pause, conn.raw().read(&mut buf)).await {
      Err(_) => {}
      Ok(Ok(0) | Err(_)) => return Outcome::Pass,
      Ok(Ok(len)) => {
        conn.transcript_mut().note(&String::from_utf8_lossy(&buf[..len]));
        if buf[..len].starts_with(b"HTTP/1.1 101") {
          if idx + 1 < total {
            return fail("a trickled, incomplete request was answered 101", &conn);
          }
          break;
        }
      }
    }
  }
  if common {
    conn.reset();
    return Outcome::Pass;
  }
  fail("the whole trickled request got through before the handshake timeout", &conn)
}

/// Connects and sends nothing.
pub(super) async fn idle_pre(ctx: &Ctx) -> Outcome {
  match connect(ctx, &ctx.opts).await {
    Ok(conn) => {
      let limit = ctx.limits.handshake.min(ctx.limits.idle);
      eof_by(conn, Instant::now() + slack(limit)).await
    }
    Err(outcome) => outcome,
  }
}

/// Upgrades and sends nothing.
pub(super) async fn idle_post(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  match upgraded(ctx, &ctx.opts, rng).await {
    Ok(conn) => eof_by(conn, Instant::now() + slack(ctx.limits.idle)).await,
    Err(outcome) => outcome,
  }
}

/// Sends part of the upgrade request, then half-closes (the server must close) or resets.
pub(super) async fn close_in_handshake(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let req = upgrade_request(&ctx.host, &ctx.path, &key(rng));
  let cut = rng.random_range(1..req.len());
  let half_close = rng.random_bool(0.5);
  let mut conn = match connect(ctx, &ctx.opts).await {
    Ok(conn) => conn,
    Err(outcome) => return outcome,
  };
  if let Err(err) = conn.send(&req[..cut]).await {
    return from_err(err, Some(&conn));
  }
  if !half_close {
    conn.reset();
    return Outcome::Pass;
  }
  conn.shutdown_write().await;
  eof_by(conn, Instant::now() + CLOSE).await
}

/// Sends a frame header and part of its payload, then resets. Leaks show in the monitor.
pub(super) async fn rst_midframe(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let mut conn = match upgraded(ctx, &ctx.opts, rng).await {
    Ok(conn) => conn,
    Err(outcome) => return outcome,
  };
  let len = rng.random_range(10..5000);
  let payload: Vec<u8> = (0..len).map(|_| rng.random()).collect();
  let mut frame = Vec::new();
  client_frame(true, 2, &payload, rng.random(), &mut frame);
  let cut = rng.random_range(frame.len() - len..frame.len());
  if let Err(err) = conn.send(&frame[..cut]).await {
    return from_err(err, Some(&conn));
  }
  conn.reset();
  Outcome::Pass
}

/// Sends a few messages, with or without a close, then half-closes: every echo must still arrive,
/// then the close (if one was sent) and the server's FIN.
pub(super) async fn half_close(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let with_close = rng.random_bool(0.5);
  let (mut data, mut expected) = (Vec::new(), Vec::new());
  for _ in 0..rng.random_range(1..=5) {
    let (opcode, payload) = message(rng, Some(2000));
    encode_message(rng, opcode, &payload, &mut data);
    expected.push(Expect::Message(opcode, payload));
  }
  if with_close {
    client_frame(true, 8, &1000u16.to_be_bytes(), rng.random(), &mut data);
    expected.push(Expect::Close(1000));
  }
  let mut conn = match upgraded(ctx, &ctx.opts, rng).await {
    Ok(conn) => conn,
    Err(outcome) => return outcome,
  };
  if let Err(err) = conn.send(&data).await {
    return from_err(err, Some(&conn));
  }
  conn.shutdown_write().await;
  let mut oracle = Oracle::new(expected);
  match read_expected(&mut conn, &mut oracle, Instant::now() + CLOSE).await {
    Err(err) => return from_err(err, Some(&conn)),
    Ok(_) if oracle.failure.is_some() => return judged(ctx, &mut oracle, &conn),
    Ok(true) => return judged(ctx, &mut oracle, &conn),
    Ok(false) => {}
  }
  if !with_close && ctx.mode == Mode::Common {
    // Whether the server closes after the client's FIN alone is the monitor's (CLOSE_WAIT).
    conn.reset();
    return Outcome::Pass;
  }
  let wait = if with_close { CLOSE } else { slack(ctx.limits.close) + CLOSE };
  eof_by(conn, Instant::now() + wait).await
}

/// 10 000 pings while reading: every pong must answer a ping, then a text sent after them must
/// come back and the close be answered.
pub(super) async fn ping_flood(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let mut data = Vec::new();
  let mut pings = HashSet::new();
  for _ in 0..10_000 {
    let ping: Vec<u8> = (0..rng.random_range(0..=125)).map(|_| rng.random()).collect();
    client_frame(true, 9, &ping, rng.random(), &mut data);
    let _ = pings.insert(ping);
  }
  client_frame(true, 1, b"after", rng.random(), &mut data);
  client_frame(true, 8, &1000u16.to_be_bytes(), rng.random(), &mut data);
  let mut conn = match upgraded(ctx, &ctx.opts, rng).await {
    Ok(conn) => conn,
    Err(outcome) => return outcome,
  };
  let (mut pongs, mut after, mut failure) = (0usize, false, None);
  let mut on_frame = |frame: ServerFrame| {
    let problem = match frame.opcode {
      10 if pings.contains(&frame.payload) => {
        pongs += 1;
        return Flow::More;
      }
      10 => "a pong that answers no ping".to_owned(),
      1 if frame.fin && frame.payload == b"after" && !after => {
        after = true;
        return Flow::More;
      }
      8 if after && close_code(&frame) == Some(1000) => return Flow::Done,
      8 => format!("close {:?} before the text after the flood", close_code(&frame)),
      other => format!("unexpected opcode {other} during the flood"),
    };
    failure = Some(problem);
    Flow::Done
  };
  let deadline = Instant::now() + Duration::from_secs(10);
  match conn.exchange(&data, &[65536], deadline, &mut on_frame).await {
    Err(err) => return from_err(err, Some(&conn)),
    Ok(Exchange::Eof) if failure.is_none() => {
      return fail(format!("server closed during the flood after {pongs} pongs"), &conn);
    }
    Ok(_) => {}
  }
  if let Some(reason) = failure {
    return fail(reason, &conn);
  }
  if pongs == 0 {
    return fail("no pong for 10 000 pings", &conn);
  }
  eof_by(conn, Instant::now() + CLOSE).await
}

/// Random bytes after the upgrade: the server must close, at the latest when it goes idle.
pub(super) async fn garbage(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let bytes: Vec<u8> = (0..rng.random_range(1..=4096)).map(|_| rng.random()).collect();
  let mut conn = match upgraded(ctx, &ctx.opts, rng).await {
    Ok(conn) => conn,
    Err(outcome) => return outcome,
  };
  if let Err(err) = conn.send(&bytes).await {
    return from_err(err, Some(&conn));
  }
  if ctx.mode == Mode::Common {
    // Random bytes can form a valid frame with a large length, which a server may legally wait
    // for: judged by the monitor.
    tokio::time::sleep(Duration::from_secs(1)).await;
    conn.reset();
    return Outcome::Pass;
  }
  eof_by(conn, Instant::now() + slack(ctx.limits.idle)).await
}
