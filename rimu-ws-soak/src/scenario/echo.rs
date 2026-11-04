//! Echo scenarios: messages whose echoes must come back byte for byte and in order.

use super::{Ctx, Outcome, fail, from_err, upgraded};
use crate::{
  codec::{ServerFrame, client_frame, close_code},
  conn::{Exchange, Flow},
  rng::Rng,
};
use rand::Rng as _;
use std::{collections::VecDeque, time::Duration};
use tokio::time::Instant;

/// How long a whole exchange may take, and the server's close after it.
const EXCHANGE: Duration = Duration::from_secs(10);
const CLOSE: Duration = Duration::from_secs(2);

/// What the server must send next.
#[derive(Debug)]
pub(super) enum Expect {
  Message(u8, Vec<u8>),
  Pong(Vec<u8>),
  Close(u16),
}

/// Checks server frames against the expected sequence, reassembling fragmented messages.
pub(super) struct Oracle {
  pub(super) expected: VecDeque<Expect>,
  pub(super) failure: Option<String>,
  messages: usize,
  partial: Option<(u8, Vec<u8>)>,
  received: usize,
}

impl Oracle {
  pub(super) fn new(expected: Vec<Expect>) -> Self {
    let messages = expected.iter().filter(|el| matches!(el, Expect::Message(..))).count();
    Self { expected: expected.into(), failure: None, messages, partial: None, received: 0 }
  }

  fn fail(&mut self, reason: String) -> Flow {
    self.failure = Some(reason);
    Flow::Done
  }

  pub(super) fn closed_early(&self) -> String {
    format!("server closed during echo ({} of {} echoes)", self.received, self.messages)
  }

  fn on_frame(&mut self, frame: ServerFrame) -> Flow {
    match frame.opcode {
      0 => match &mut self.partial {
        Some((_, data)) => data.extend_from_slice(&frame.payload),
        None => return self.fail("continuation frame without a message".into()),
      },
      1 | 2 => {
        if self.partial.is_some() {
          return self.fail("new message inside a fragmented one".into());
        }
        self.partial = Some((frame.opcode, frame.payload));
      }
      8 => {
        let code = close_code(&frame);
        return match self.expected.pop_front() {
          Some(Expect::Close(want)) if code == Some(want) => Flow::Done,
          Some(Expect::Close(want)) => self.fail(format!("close code {code:?}, expected {want}")),
          _ => {
            let reason = format!("{} with close {code:?}", self.closed_early());
            self.fail(reason)
          }
        };
      }
      9 => return Flow::More,
      10 => {
        return match self.expected.pop_front() {
          Some(Expect::Pong(want)) if want == frame.payload => Flow::More,
          other => self.fail(format!("unexpected pong {:?}, expected {other:?}", frame.payload)),
        };
      }
      other => return self.fail(format!("server sent opcode {other}")),
    }
    if !frame.fin {
      return Flow::More;
    }
    let Some((opcode, data)) = self.partial.take() else { return Flow::More };
    match self.expected.pop_front() {
      Some(Expect::Message(want_op, want)) if want_op == opcode && want == data => {
        self.received += 1;
        Flow::More
      }
      Some(Expect::Message(want_op, want)) => {
        let at = want.iter().zip(&data).position(|(a, b)| a != b);
        self.fail(format!(
          "echo {} differs: opcode {opcode} len {} (expected {want_op}, {}), first difference at {at:?}",
          self.received,
          data.len(),
          want.len()
        ))
      }
      other => self.fail(format!("unexpected message (opcode {opcode}), expected {other:?}")),
    }
  }
}

/// A random message: mostly small, sometimes up to 4 KiB, one in ten 70 to 200 KB.
pub(super) fn message(rng: &mut Rng, max_len: Option<usize>) -> (u8, Vec<u8>) {
  let len = match max_len {
    Some(max) => rng.random_range(0..max),
    None => match rng.random_range(0..10) {
      0..6 => rng.random_range(0..=125),
      6..9 => rng.random_range(0..=4096),
      _ => rng.random_range(70_000..=200_000),
    },
  };
  if rng.random_bool(0.5) {
    (1, (0..len).map(|_| rng.random_range(b'a'..=b'z')).collect())
  } else {
    (2, (0..len).map(|_| rng.random()).collect())
  }
}

/// Encodes a message, split into 2 to 4 fragments a quarter of the time.
pub(super) fn encode_message(rng: &mut Rng, opcode: u8, data: &[u8], out: &mut Vec<u8>) {
  let parts = if rng.random_bool(0.25) { rng.random_range(2..=4) } else { 1 };
  if data.is_empty() || parts == 1 {
    client_frame(true, opcode, data, rng.random(), out);
    return;
  }
  let step = data.len().div_ceil(parts);
  let mut chunks = data.chunks(step).peekable();
  let mut first = true;
  while let Some(chunk) = chunks.next() {
    let op = if first { opcode } else { 0 };
    client_frame(chunks.peek().is_none(), op, chunk, rng.random(), out);
    first = false;
  }
}

/// Sends `data` while checking the server's frames against `expected`, then waits for its close.
async fn exchange(
  ctx: &Ctx,
  opts: &crate::conn::ConnOpts,
  rng: &mut Rng,
  data: Vec<u8>,
  chunks: Vec<usize>,
  expected: Vec<Expect>,
) -> Outcome {
  let mut conn = match upgraded(ctx, opts, rng).await {
    Ok(conn) => conn,
    Err(outcome) => return outcome,
  };
  let mut oracle = Oracle::new(expected);
  let ended =
    conn.exchange(&data, &chunks, Instant::now() + EXCHANGE, |frame| oracle.on_frame(frame)).await;
  match ended {
    Err(err) => return from_err(err, Some(&conn)),
    Ok(_) if oracle.failure.is_some() => {
      return fail(oracle.failure.take().unwrap_or_default(), &conn);
    }
    Ok(Exchange::Eof) => return fail(oracle.closed_early(), &conn),
    Ok(Exchange::Done) => {}
  }
  match conn.expect_eof(Instant::now() + CLOSE).await {
    Ok(()) => Outcome::Pass,
    Err(err) => from_err(err, Some(&conn)),
  }
}

/// 1 to 20 messages written in random pieces, then a close.
pub(super) async fn echo(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let count = rng.random_range(1..=20);
  let (data, expected) = batch(rng, count, None);
  let chunks = (0..64).map(|_| rng.random_range(1..=70_000)).collect();
  exchange(ctx, &ctx.opts, rng, data, chunks, expected).await
}

/// Up to 3 messages under 300 bytes, written a byte at a time.
pub(super) async fn split_every_byte(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let count = rng.random_range(1..=3);
  let (data, expected) = batch(rng, count, Some(300));
  let opts = crate::conn::ConnOpts { nodelay: true, ..ctx.opts.clone() };
  exchange(ctx, &opts, rng, data, vec![1], expected).await
}

/// A text in 3 fragments with a ping between the first two: the pong comes before the echo.
pub(super) async fn ctrl_in_fragments(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let len: usize = rng.random_range(3..=300);
  let text: Vec<u8> = (0..len).map(|_| rng.random_range(b'a'..=b'z')).collect();
  let ping: Vec<u8> = (0..rng.random_range(0..=125)).map(|_| rng.random()).collect();
  let step = len.div_ceil(3);
  let mut data = Vec::new();
  client_frame(false, 1, &text[..step], rng.random(), &mut data);
  client_frame(true, 9, &ping, rng.random(), &mut data);
  client_frame(false, 0, &text[step..2 * step], rng.random(), &mut data);
  client_frame(true, 0, &text[2 * step..], rng.random(), &mut data);
  client_frame(true, 8, &1000u16.to_be_bytes(), rng.random(), &mut data);
  let expected = vec![Expect::Pong(ping), Expect::Message(1, text), Expect::Close(1000)];
  let chunks = (0..8).map(|_| rng.random_range(1..=64)).collect();
  exchange(ctx, &ctx.opts, rng, data, chunks, expected).await
}

/// Reads frames into `oracle` until it has everything it expected, fails, or the server closes.
/// `Ok(true)` if the server closed first.
pub(super) async fn read_expected(
  conn: &mut crate::conn::Conn,
  oracle: &mut Oracle,
  deadline: Instant,
) -> Result<bool, crate::conn::ConnError> {
  while !oracle.expected.is_empty() {
    match conn.next_frame(deadline).await? {
      crate::conn::Next::Frame(frame) => {
        if oracle.on_frame(frame) == Flow::Done {
          return Ok(false);
        }
      }
      crate::conn::Next::Eof => return Ok(true),
    }
  }
  Ok(false)
}

/// `count` random messages and a close, with the frames the server must answer them with.
fn batch(rng: &mut Rng, count: usize, max_len: Option<usize>) -> (Vec<u8>, Vec<Expect>) {
  let (mut data, mut expected) = (Vec::new(), Vec::new());
  for _ in 0..count {
    let (opcode, payload) = message(rng, max_len);
    encode_message(rng, opcode, &payload, &mut data);
    expected.push(Expect::Message(opcode, payload));
  }
  client_frame(true, 8, &1000u16.to_be_bytes(), rng.random(), &mut data);
  expected.push(Expect::Close(1000));
  (data, expected)
}
