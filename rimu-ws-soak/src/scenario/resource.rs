//! What a connection may hold on the server: a message trickled in fragments up to the size
//! limit, a reply nobody reads after the close, pongs nobody reads, and a slow reader.

use super::{
  Ctx, LargeInflight, Mode, Outcome,
  abuse::unread_flood,
  echo::{Expect, Oracle, judged, read_expected},
  fail, from_err, slack, upgraded,
};
use crate::{
  codec::client_frame,
  conn::{ConnError, ConnOpts, Exchange, Failure, Next},
  rng::Rng,
};
use rand::Rng as _;
use std::time::Duration;
use tokio::time::{Instant, sleep};

/// Fragment size of a trickled message, and how long it takes to trickle.
const DRIP_FRAGMENT: usize = 16 * 1024;
const DRIP_TIME: Duration = Duration::from_secs(3);
/// How long the server has to send its close, then to close the connection.
const CLOSE: Duration = Duration::from_secs(2);
/// How long an echo to a slow reader may take.
const SLOW: Duration = Duration::from_secs(20);

/// A message of 3/4 to all of the size limit, or one byte over it (a quarter of the time), in
/// 16 KiB fragments over about 3 s. Under the limit it is echoed whole; over it, the server refuses
/// with 1009 once the fragments pass the limit. Many at once show what the server holds per
/// connection: up to the limit, which the monitor's budget allows for.
pub(super) async fn frag_drip(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let max = usize::try_from(ctx.limits.max_payload).unwrap_or(usize::MAX);
  // The common mode never goes over the limit: refusing that needs a configured limit.
  let over = rng.random_bool(0.25) && ctx.mode == Mode::Strict;
  let len = if over { max + 1 } else { rng.random_range(max * 3 / 4..max) };
  let payload: Vec<u8> = (0..len).map(|_| rng.random()).collect();
  let _large = LargeInflight::new();
  let mut conn = match upgraded(ctx, &ctx.opts, rng).await {
    Ok(conn) => conn,
    Err(outcome) => return outcome,
  };
  conn.transcript_mut().note(&format!("{len} bytes in fragments, limit {max}"));
  let parts = len.div_ceil(DRIP_FRAGMENT);
  let pause =
    (DRIP_TIME / u32::try_from(parts).unwrap_or(u32::MAX)).min(Duration::from_millis(100));
  let mut frame = Vec::new();
  for (idx, chunk) in payload.chunks(DRIP_FRAGMENT).enumerate() {
    frame.clear();
    client_frame(idx + 1 == parts, if idx == 0 { 2 } else { 0 }, chunk, rng.random(), &mut frame);
    // A failed send is the server closing, which the reads below judge.
    if conn.send(&frame).await.is_err() {
      break;
    }
    sleep(pause).await;
  }
  if over {
    if let Err(err) = conn.expect_close(&[1009], Instant::now() + CLOSE).await {
      return from_err(err, Some(&conn));
    }
  } else {
    let mut close = Vec::new();
    client_frame(true, 8, &1000u16.to_be_bytes(), rng.random(), &mut close);
    // As above: a failed send is the server closing, which the reads judge.
    let _ = conn.send(&close).await;
    let mut oracle = Oracle::new(vec![Expect::Message(2, payload), Expect::Close(1000)]);
    match read_expected(&mut conn, &mut oracle, Instant::now() + SLOW).await {
      Err(err) => return from_err(err, Some(&conn)),
      Ok(_) if oracle.failure.is_some() => return judged(ctx, &mut oracle, &conn),
      Ok(true) => return judged(ctx, &mut oracle, &conn),
      Ok(false) => {}
    }
  }
  match conn.expect_eof(Instant::now() + CLOSE).await {
    Ok(()) => Outcome::Pass,
    Err(err) => from_err(err, Some(&conn)),
  }
}

/// Whether the server dropped a reply nobody read: `saw_close` is whether its close frame, queued
/// behind the reply, still arrived once the client started reading.
pub fn linger_verdict(saw_close: bool, close_timeout: Duration) -> Result<(), String> {
  if saw_close {
    return Err(format!(
      "the whole reply and the close reached a client that read nothing for longer than the \
       close timeout ({close_timeout:?}): the server kept it queued"
    ));
  }
  Ok(())
}

/// Sends messages whose echoes outgrow the server's socket (`--server-sndbuf`) and ours, then a
/// close, and reads nothing: the server's handler is done, and the connection must be dropped
/// within its close timeout of its last progress, with what is left of the reply.
pub(super) async fn close_linger(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let Some(sndbuf) = ctx.limits.server_sndbuf else { return Outcome::Pass };
  let opts = ConnOpts { rcvbuf: Some(4096), ..ctx.opts.clone() };
  let mut conn = match upgraded(ctx, &opts, rng).await {
    Ok(conn) => conn,
    Err(outcome) => return outcome,
  };
  // The kernel doubles SO_SNDBUF: this is more than both sockets hold, and under the server's
  // send queue limit (256 KiB by default) for a send buffer of up to 32 KiB.
  let total = 4 * sndbuf as usize + 32 * 1024;
  let mut data = Vec::new();
  for _ in 0..3 {
    let part: Vec<u8> = (0..total / 3).map(|_| rng.random()).collect();
    client_frame(true, 2, &part, rng.random(), &mut data);
  }
  client_frame(true, 8, &1000u16.to_be_bytes(), rng.random(), &mut data);
  if let Err(err) = conn.send(&data).await {
    return from_err(err, Some(&conn));
  }
  sleep(slack(ctx.limits.close) + Duration::from_secs(1)).await;
  conn.transcript_mut().note("reading now");
  let deadline = Instant::now() + CLOSE;
  let mut saw_close = false;
  loop {
    match conn.next_frame(deadline).await {
      Ok(Next::Frame(frame)) => saw_close |= frame.opcode == 8,
      Ok(Next::Eof) => break,
      Err(ConnError::Server(Failure(reason))) => {
        return fail(format!("still open after the close timeout: {reason}"), &conn);
      }
      Err(err) => return from_err(err, Some(&conn)),
    }
  }
  match linger_verdict(saw_close, ctx.limits.close) {
    Ok(()) => Outcome::Pass,
    Err(reason) => fail(reason, &conn),
  }
}

/// Pings with full 125-byte payloads and never reads the pongs: the server must stop reading, or
/// close, rather than queue pongs without bound.
pub(super) async fn ping_no_read(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let ping: Vec<u8> = (0..125).map(|_| rng.random()).collect();
  let mut batch = Vec::new();
  for _ in 0..64 {
    client_frame(true, 9, &ping, rng.random(), &mut batch);
  }
  unread_flood(ctx, rng, &batch, &|frame| frame.opcode == 10 && frame.payload == ping).await
}

/// 2 to 4 messages of 64 to 200 KB, read 8 KiB every 10 ms through a 16 KiB receive buffer: every
/// echo arrives whole and in order.
pub(super) async fn slow_reader(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let (mut data, mut expected) = (Vec::new(), Vec::new());
  for _ in 0..rng.random_range(2..=4) {
    let payload: Vec<u8> = (0..rng.random_range(65_536..=200_000)).map(|_| rng.random()).collect();
    client_frame(true, 2, &payload, rng.random(), &mut data);
    expected.push(Expect::Message(2, payload));
  }
  client_frame(true, 8, &1000u16.to_be_bytes(), rng.random(), &mut data);
  expected.push(Expect::Close(1000));
  let opts = ConnOpts { rcvbuf: Some(16384), ..ctx.opts.clone() };
  let mut conn = match upgraded(ctx, &opts, rng).await {
    Ok(conn) => conn,
    Err(outcome) => return outcome,
  };
  let mut oracle = Oracle::new(expected);
  let pace = Some((8192, Duration::from_millis(10)));
  let ended = conn
    .exchange_paced(&data, &[65536], pace, Instant::now() + SLOW, |frame| oracle.on_frame(frame))
    .await;
  match ended {
    Err(err) => return from_err(err, Some(&conn)),
    Ok(_) if oracle.failure.is_some() => return judged(ctx, &mut oracle, &conn),
    Ok(Exchange::Eof) => return judged(ctx, &mut oracle, &conn),
    Ok(Exchange::Done) => {}
  }
  match conn.expect_eof(Instant::now() + CLOSE).await {
    Ok(()) => Outcome::Pass,
    Err(err) => from_err(err, Some(&conn)),
  }
}
