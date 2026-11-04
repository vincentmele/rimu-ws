//! Protocol violations, each of which the server must answer with a specific close code, and
//! declared lengths the server must refuse without allocating them.

use super::{
  Ctx, Outcome,
  echo::{Expect, Oracle, encode_message, message, read_expected},
  fail, from_err, upgraded,
};
use crate::{
  codec::{FrameSpec, LenForm, close_code, encode},
  conn::{ConnError, Failure, Next},
  rng::Rng,
};
use rand::Rng as _;
use std::time::Duration;
use tokio::time::Instant;

/// How long the server has to send its close, then to close the connection.
const CLOSE: Duration = Duration::from_secs(2);
/// How long a huge declared length may go unanswered, and the trickle meanwhile.
const HUGE: Duration = Duration::from_secs(1);
const TRICKLE: Duration = Duration::from_millis(100);

/// A protocol violation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidCase {
  BadUtf8,
  ReservedOpcode,
  Rsv1NoExtension,
  Unmasked,
  FragmentedControl,
  ControlTooLong,
  BadCloseCode,
  OneByteClose,
  StrayContinuation,
  DataInsideFragmented,
  Oversized,
}

impl InvalidCase {
  pub const ALL: [InvalidCase; 11] = [
    Self::BadUtf8,
    Self::ReservedOpcode,
    Self::Rsv1NoExtension,
    Self::Unmasked,
    Self::FragmentedControl,
    Self::ControlTooLong,
    Self::BadCloseCode,
    Self::OneByteClose,
    Self::StrayContinuation,
    Self::DataInsideFragmented,
    Self::Oversized,
  ];
}

/// The close codes RFC 6455 has the server answer `case` with.
pub fn expected_codes(case: InvalidCase) -> &'static [u16] {
  match case {
    InvalidCase::BadUtf8 => &[1007],
    InvalidCase::Oversized => &[1009],
    _ => &[1002],
  }
}

/// The bytes of `case`.
fn case_bytes(case: InvalidCase, max_payload: u64, rng: &mut Rng) -> Vec<u8> {
  let mut out = Vec::new();
  let base = FrameSpec {
    fin: true,
    rsv: 0,
    opcode: 1,
    mask: Some(rng.random()),
    payload: b"x",
    declared_len: None,
    len_form: LenForm::Minimal,
  };
  let long = [b'p'; 126];
  let spec = match case {
    InvalidCase::BadUtf8 => FrameSpec { payload: &[0xC3, 0x28], ..base },
    InvalidCase::ReservedOpcode => FrameSpec { opcode: 3, ..base },
    InvalidCase::Rsv1NoExtension => FrameSpec { rsv: 4, ..base },
    InvalidCase::Unmasked => FrameSpec { mask: None, ..base },
    InvalidCase::FragmentedControl => FrameSpec { fin: false, opcode: 9, ..base },
    InvalidCase::ControlTooLong => FrameSpec { opcode: 9, payload: &long, ..base },
    InvalidCase::BadCloseCode => {
      let code: u16 = if rng.random_bool(0.5) { 999 } else { 1005 };
      let payload = code.to_be_bytes();
      encode(&FrameSpec { opcode: 8, payload: &payload, ..base }, &mut out);
      return out;
    }
    InvalidCase::OneByteClose => FrameSpec { opcode: 8, payload: &[0x03], ..base },
    InvalidCase::StrayContinuation => FrameSpec { opcode: 0, ..base },
    InvalidCase::DataInsideFragmented => {
      encode(&FrameSpec { fin: false, payload: b"a", ..base }, &mut out);
      FrameSpec { mask: Some(rng.random()), payload: b"b", ..base }
    }
    InvalidCase::Oversized => {
      FrameSpec { opcode: 2, payload: &[], declared_len: Some(max_payload + 1), ..base }
    }
  };
  encode(&spec, &mut out);
  out
}

/// A random case.
pub(super) async fn invalid(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let case = InvalidCase::ALL[rng.random_range(0..InvalidCase::ALL.len())];
  run_case(case, ctx, rng).await
}

/// Upgrades, echoes a few valid messages, sends `case`, and expects its close code.
pub async fn run_case(case: InvalidCase, ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let mut conn = match upgraded(ctx, &ctx.opts, rng).await {
    Ok(conn) => conn,
    Err(outcome) => return outcome,
  };
  let (mut data, mut expected) = (Vec::new(), Vec::new());
  for _ in 0..rng.random_range(0..=3) {
    let (opcode, payload) = message(rng, Some(500));
    encode_message(rng, opcode, &payload, &mut data);
    expected.push(Expect::Message(opcode, payload));
  }
  if !data.is_empty() {
    if let Err(err) = conn.send(&data).await {
      return from_err(err, Some(&conn));
    }
    let mut oracle = Oracle::new(expected);
    match read_expected(&mut conn, &mut oracle, Instant::now() + CLOSE).await {
      Err(err) => return from_err(err, Some(&conn)),
      Ok(_) if oracle.failure.is_some() => {
        return fail(oracle.failure.take().unwrap_or_default(), &conn);
      }
      Ok(true) => return fail(oracle.closed_early(), &conn),
      Ok(false) => {}
    }
  }
  conn.transcript_mut().note(&format!("{case:?}"));
  if let Err(err) = conn.send(&case_bytes(case, ctx.limits.max_payload, rng)).await {
    return from_err(err, Some(&conn));
  }
  let codes = expected_codes(case);
  if let Err(err) = conn.expect_close(codes, Instant::now() + CLOSE).await {
    return from_err(err, Some(&conn));
  }
  match conn.expect_eof(Instant::now() + CLOSE).await {
    Ok(()) => Outcome::Pass,
    Err(err) => from_err(err, Some(&conn)),
  }
}

/// Declares a length the server can't accept, then trickles payload: the server must close with
/// 1009 (or 1002) at once, without waiting for, or allocating, the payload.
pub(super) async fn huge_len(ctx: &Ctx, rng: &mut Rng) -> Outcome {
  let declared = match rng.random_range(0..3) {
    0 => u64::MAX >> 1,
    1 => 1 << 32,
    _ => ctx.limits.max_payload + 1,
  };
  let mut conn = match upgraded(ctx, &ctx.opts, rng).await {
    Ok(conn) => conn,
    Err(outcome) => return outcome,
  };
  let mut header = Vec::new();
  let spec = FrameSpec {
    fin: true,
    rsv: 0,
    opcode: 2,
    mask: Some(rng.random()),
    payload: &[],
    declared_len: Some(declared),
    len_form: LenForm::Minimal,
  };
  encode(&spec, &mut header);
  conn.transcript_mut().note(&format!("declares {declared} bytes"));
  if let Err(err) = conn.send(&header).await {
    return from_err(err, Some(&conn));
  }
  let deadline = Instant::now() + HUGE;
  loop {
    match conn.next_frame((Instant::now() + TRICKLE).min(deadline)).await {
      Ok(Next::Frame(frame)) if frame.opcode == 8 => {
        let code = close_code(&frame);
        if !matches!(code, Some(1009 | 1002)) {
          return fail(format!("close code {code:?}, expected [1009, 1002]"), &conn);
        }
        break;
      }
      Ok(Next::Frame(_)) => {}
      Ok(Next::Eof) => return fail("EOF instead of a close [1009, 1002]", &conn),
      Err(ConnError::Server(Failure(_))) if Instant::now() < deadline => {
        // Still nothing: one more payload byte. A failed send means the server closed, which
        // the next read reports.
        let _ = conn.send(&[0]).await;
      }
      Err(ConnError::Server(Failure(_))) => {
        return fail(format!("no close within {HUGE:?} of declaring {declared} bytes"), &conn);
      }
      Err(err) => return from_err(err, Some(&conn)),
    }
  }
  match conn.expect_eof(Instant::now() + CLOSE).await {
    Ok(()) => Outcome::Pass,
    Err(err) => from_err(err, Some(&conn)),
  }
}
