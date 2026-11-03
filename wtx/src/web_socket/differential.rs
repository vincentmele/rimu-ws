//! Differential testing of the server read and echo paths.
//!
//! The same client byte stream, delivered in the same read sizes, goes through the draining loop
//! (`read_buffered_frame`, `try_write_frame_buffered` and the queued writes) and through the plain
//! `read_frame`/`write_frame` loop, and both are compared with an independent RFC 6455 model:
//! the frames handed to the application, the bytes sent back (echoes, pongs, the close reply) and
//! how the stream ends must all agree.
//!
//! Inputs come from a seeded generator of mostly valid frame sequences with occasional protocol
//! violations, or, for the fuzzer, straight from arbitrary bytes.

use crate::{
  collections::{MaybeUninitSlice, VectorUsize},
  net::{Stream, StreamCommon, StreamReader, StreamWriter},
  rng::Xorshift64,
  tls::{KeySchedule, PlaintextCtx, TlsBuffer, TlsStream},
  web_socket::{Frame, OpCode, WebSocket, WebSocketBuffer, WebSocketPayloadOrigin},
};
use alloc::{format, vec::Vec};
use core::{
  num::NonZeroUsize,
  pin::pin,
  task::{Context, Poll, Waker},
};

const MAX_PAYLOAD_LEN: usize = crate::MAX_PAYLOAD_LEN;

/// What the application saw.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
  /// A complete text (1) or binary (2) message.
  Data(u8, Vec<u8>),
  /// A ping, already answered.
  Ping(Vec<u8>),
  /// A pong.
  Pong(Vec<u8>),
  /// A close frame, already answered.
  Close(Vec<u8>),
}

/// How the stream ended.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum End {
  /// The peer closed with a close frame.
  Close,
  /// The peer broke the protocol.
  Error,
  /// The bytes ran out, between frames or inside one.
  Eof,
}

/// Everything that is compared.
#[derive(Clone, Debug, PartialEq)]
pub struct Outcome {
  /// Messages and control frames, in order.
  pub events: Vec<Event>,
  /// The ending.
  pub end: End,
  /// The bytes written back to the peer.
  pub output: Vec<u8>,
}

/// Runs `input`, read `chunks` bytes at a time (cycling), through the model and both server
/// loops, and panics if they disagree.
pub fn check(input: &[u8], chunks: &[usize], consistent: bool) {
  let expected = reference(input);
  let origin =
    if consistent { WebSocketPayloadOrigin::Consistent } else { WebSocketPayloadOrigin::Adaptive };
  for drain in [true, false] {
    let got = run(input, chunks, origin, drain);
    if got != expected {
      let which = if drain { "draining" } else { "plain" };
      panic!(
        "{which} loop disagrees with the model (chunks {chunks:?}, consistent {consistent}, {} input bytes): {}",
        input.len(),
        describe(&got, &expected)
      );
    }
  }
}

fn describe(got: &Outcome, expected: &Outcome) -> alloc::string::String {
  let short = |event: Option<&Event>| match event {
    None => alloc::string::String::from("none"),
    Some(Event::Data(op, el)) => {
      format!("Data({op}, {} bytes, starts {:?})", el.len(), &el[..el.len().min(8)])
    }
    Some(Event::Ping(el)) => {
      format!("Ping({} bytes, starts {:?})", el.len(), &el[..el.len().min(8)])
    }
    Some(Event::Pong(el)) => format!("Pong({} bytes)", el.len()),
    Some(Event::Close(el)) => format!("Close({el:?})"),
  };
  let idx = got
    .events
    .iter()
    .zip(&expected.events)
    .position(|(a, b)| a != b)
    .unwrap_or(got.events.len().min(expected.events.len()));
  let out = got.output.iter().zip(&expected.output).position(|(a, b)| a != b);
  format!(
    "first differing event #{idx}: got {} expected {}; events {} vs {}; end {:?} vs {:?}; output {} vs {} bytes, first difference at {out:?}",
    short(got.events.get(idx)),
    short(expected.events.get(idx)),
    got.events.len(),
    expected.events.len(),
    got.end,
    expected.end,
    got.output.len(),
    expected.output.len(),
  )
}

/// Interprets arbitrary bytes as a test case, for the fuzzer: the first byte picks raw wire bytes
/// or a generated sequence, the next ones the read sizes and the payload origin.
pub fn check_bytes(data: &[u8]) {
  let [mode, c0, c1, c2, rest @ ..] = data else {
    return;
  };
  let chunks = [usize::from(*c0).max(1), usize::from(*c1).max(1), usize::from(*c2).max(1) * 64];
  if mode % 2 == 0 {
    check(rest, &chunks, mode % 4 == 0);
  } else {
    let mut seed = 0u64;
    for (idx, byte) in rest.iter().take(8).enumerate() {
      seed |= u64::from(*byte) << (idx * 8);
    }
    let mut rng = Gen(seed);
    let (input, chunks, consistent) = rng.case();
    check(&input, &chunks, consistent);
  }
}

/// Generates and checks `iterations` cases from `seed`.
pub fn check_generated(seed: u64, iterations: usize) {
  let mut rng = Gen(seed);
  for iteration in 0..iterations {
    let (input, chunks, consistent) = rng.case();
    #[cfg(feature = "std")]
    if let Ok(dir) = std::env::var("WTX_DIFF_DUMP") {
      let _rslt = std::fs::write(format!("{dir}/case.bin"), &input);
      let _rslt =
        std::fs::write(format!("{dir}/case.txt"), format!("{iteration} {chunks:?} {consistent}"));
    }
    check(&input, &chunks, consistent);
  }
}

// ---- the model

#[expect(
  clippy::disallowed_methods,
  reason = "the model checks UTF-8 with the standard validator on purpose, independently of wtx's"
)]
fn reference(input: &[u8]) -> Outcome {
  let mut events = Vec::new();
  let mut output = Vec::new();
  let mut fragment: Option<(u8, Vec<u8>)> = None;
  let mut rest = input;
  let end = loop {
    let [b0, b1, ..] = rest else {
      break End::Eof;
    };
    let fin = b0 & 0x80 != 0;
    let op = b0 & 0x0F;
    if b0 & 0x70 != 0 || !matches!(op, 0 | 1 | 2 | 8 | 9 | 10) {
      break End::Error;
    }
    let ext = match b1 & 0x7F {
      126 => 2,
      127 => 8,
      _ => 0,
    };
    if rest.len() < 2 + ext {
      break End::Eof;
    }
    if b1 & 0x80 == 0 {
      break End::Error;
    }
    let header_len = 2 + ext + 4;
    if rest.len() < header_len {
      break End::Eof;
    }
    let len = match ext {
      2 => u64::from(u16::from_be_bytes([rest[2], rest[3]])),
      8 => u64::from_be_bytes(rest[2..10].try_into().unwrap()),
      _ => u64::from(b1 & 0x7F),
    };
    let control = op >= 8;
    if (control && (!fin || len > 125)) || len >= MAX_PAYLOAD_LEN as u64 {
      break End::Error;
    }
    let len = len as usize;
    if rest.len() < header_len + len {
      break End::Eof;
    }
    let mask = &rest[header_len - 4..header_len];
    let payload: Vec<u8> = rest[header_len..header_len + len]
      .iter()
      .enumerate()
      .map(|(idx, el)| el ^ mask[idx % 4])
      .collect();
    rest = &rest[header_len + len..];
    match op {
      9 => {
        encode(&mut output, 0xA, &payload);
        events.push(Event::Ping(payload));
      }
      10 => events.push(Event::Pong(payload)),
      8 => {
        if !close_payload_is_valid(&payload) {
          break End::Error;
        }
        encode(&mut output, 0x8, &payload);
        events.push(Event::Close(payload));
        break End::Close;
      }
      1 | 2 => {
        if fragment.is_some() {
          break End::Error;
        }
        if fin {
          if op == 1 && core::str::from_utf8(&payload).is_err() {
            break End::Error;
          }
          encode(&mut output, op, &payload);
          events.push(Event::Data(op, payload));
        } else {
          if op == 1 && !is_utf8_prefix(&payload) {
            break End::Error;
          }
          fragment = Some((op, payload));
        }
      }
      _ => {
        let Some((first, mut message)) = fragment.take() else {
          break End::Error;
        };
        message.extend_from_slice(&payload);
        if first == 1 {
          let valid =
            if fin { core::str::from_utf8(&message).is_ok() } else { is_utf8_prefix(&message) };
          if !valid {
            break End::Error;
          }
        }
        if fin {
          encode(&mut output, first, &message);
          events.push(Event::Data(first, message));
        } else {
          fragment = Some((first, message));
        }
      }
    }
  };
  Outcome { events, end, output }
}

#[expect(
  clippy::disallowed_methods,
  reason = "the model checks UTF-8 with the standard validator on purpose, independently of wtx's"
)]
fn close_payload_is_valid(payload: &[u8]) -> bool {
  match payload {
    [] => true,
    [_] => false,
    [b0, b1, reason @ ..] => {
      let code = u16::from_be_bytes([*b0, *b1]);
      matches!(code, 1000..=1003 | 1007..=1013 | 3000..=4999)
        && core::str::from_utf8(reason).is_ok()
    }
  }
}

#[expect(
  clippy::disallowed_methods,
  reason = "the model checks UTF-8 with the standard validator on purpose, independently of wtx's"
)]
fn is_utf8_prefix(bytes: &[u8]) -> bool {
  match core::str::from_utf8(bytes) {
    Ok(_) => true,
    Err(err) => err.error_len().is_none(),
  }
}

fn encode(out: &mut Vec<u8>, op: u8, payload: &[u8]) {
  out.push(0x80 | op);
  let len = payload.len();
  if len < 126 {
    out.push(len as u8);
  } else if len <= 0xFFFF {
    out.push(126);
    out.extend_from_slice(&(len as u16).to_be_bytes());
  } else {
    out.push(127);
    out.extend_from_slice(&(len as u64).to_be_bytes());
  }
  out.extend_from_slice(payload);
}

// ---- the server loops

struct Mem {
  chunk_idx: usize,
  chunks: Vec<usize>,
  input: Vec<u8>,
  output: Vec<u8>,
  pos: usize,
}

impl Stream for Mem {
  type BridgeOwned = ();
  type ReadHalfOwned = ();
  type WriteHalfOwned = ();

  fn into_split(self) -> crate::Result<((), (), ())> {
    Ok(((), (), ()))
  }
}

impl StreamCommon for Mem {}

impl StreamReader for Mem {
  async fn read(
    &mut self,
    mut bytes: MaybeUninitSlice<'_, u8>,
  ) -> crate::Result<Option<NonZeroUsize>> {
    let available = self.input.get(self.pos..).unwrap_or_default();
    if available.is_empty() {
      return Ok(None);
    }
    let want = self.chunks.get(self.chunk_idx % self.chunks.len()).copied().unwrap_or(1).max(1);
    self.chunk_idx = self.chunk_idx.wrapping_add(1);
    let dst = bytes.uninitialized_mut();
    let len = want.min(available.len()).min(dst.len());
    // SAFETY: `dst` has room for `len` bytes and doesn't overlap the input
    unsafe { core::ptr::copy_nonoverlapping(available.as_ptr(), dst.as_mut_ptr().cast(), len) };
    self.pos += len;
    Ok(NonZeroUsize::new(len))
  }
}

impl StreamWriter for Mem {
  async fn write_all(&mut self, bytes: &[u8]) -> crate::Result<()> {
    self.output.extend_from_slice(bytes);
    Ok(())
  }

  async fn write_all_vectored(&mut self, bytes: &[&[u8]]) -> crate::Result<()> {
    for elem in bytes {
      self.output.extend_from_slice(elem);
    }
    Ok(())
  }
}

fn block_on<F>(future: F) -> F::Output
where
  F: Future,
{
  let mut future = pin!(future);
  let mut cx = Context::from_waker(Waker::noop());
  loop {
    if let Poll::Ready(elem) = future.as_mut().poll(&mut cx) {
      return elem;
    }
  }
}

fn classify(err: &crate::Error) -> End {
  let debug = format!("{err:?}");
  if ["ClosedConnection", "AbruptDisconnect", "UnexpectedStreamReadEOF"]
    .iter()
    .any(|el| debug.contains(el))
  {
    End::Eof
  } else {
    End::Error
  }
}

fn event(frame_op: OpCode, payload: &[u8]) -> Event {
  let payload = payload.to_vec();
  match frame_op {
    OpCode::Text => Event::Data(1, payload),
    OpCode::Binary => Event::Data(2, payload),
    OpCode::Ping => Event::Ping(payload),
    OpCode::Pong => Event::Pong(payload),
    OpCode::Close | OpCode::Continuation => Event::Close(payload),
  }
}

fn run(input: &[u8], chunks: &[usize], origin: WebSocketPayloadOrigin, drain: bool) -> Outcome {
  let mem = Mem {
    chunk_idx: 0,
    chunks: chunks.to_vec(),
    input: input.to_vec(),
    output: Vec::new(),
    pos: 0,
  };
  let stream = TlsStream::<_, PlaintextCtx, false>::new(
    TlsBuffer::default(),
    KeySchedule::default(),
    16384,
    16384,
    mem,
  )
  .unwrap();
  let mut ws = WebSocket::<(), _, _, false>::new(
    (),
    false,
    Xorshift64::from(7),
    stream,
    WebSocketBuffer::new(),
  );
  let mut events = Vec::new();
  let end = block_on(async {
    let mut buffer = VectorUsize::new();
    if drain {
      let (mut common, mut reader, mut writer) = ws.split_mut();
      let end = 'outer: loop {
        loop {
          match reader.read_buffered_frame(&mut buffer, &common, origin) {
            Ok(Some(mut frame)) => {
              events.push(event(frame.op_code(), frame.payload()));
              if !writer.try_write_frame_buffered(&mut common, &mut frame).unwrap() {
                writer.write_frame_buffered(&mut common, &mut frame).await.unwrap();
              }
            }
            Ok(None) => break,
            Err(err) => break 'outer classify(&err),
          }
        }
        match reader.read_frame(&mut buffer, &mut common, origin).await {
          Ok(mut frame) => {
            let op = frame.op_code();
            events.push(event(op, frame.payload()));
            match op {
              OpCode::Text | OpCode::Binary => {
                writer.write_frame_buffered(&mut common, &mut frame).await.unwrap();
              }
              OpCode::Close => break End::Close,
              _ => {}
            }
          }
          Err(err) => break classify(&err),
        }
      };
      // Like a handler that returns on errors: only a clean close flushes here, so frames queued
      // before an error must already have been sent by the library.
      if end == End::Close {
        writer.flush(&mut common).await.unwrap();
      }
      end
    } else {
      loop {
        let rslt = ws.read_frame(&mut buffer, origin).await;
        let (op, payload) = match rslt {
          Ok(frame) => (frame.op_code(), frame.payload().to_vec()),
          Err(err) => break classify(&err),
        };
        events.push(event(op, &payload));
        match op {
          OpCode::Text | OpCode::Binary => {
            let mut payload = payload;
            ws.write_frame(&mut Frame::new_fin(op, &mut payload).unwrap()).await.unwrap();
          }
          OpCode::Close => break End::Close,
          _ => {}
        }
      }
    }
  });
  Outcome { events, end, output: core::mem::take(&mut ws.stream.stream.output) }
}

// ---- inputs

struct Gen(u64);

impl Gen {
  fn next(&mut self) -> u64 {
    // splitmix64
    self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = self.0;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
  }

  fn below(&mut self, n: u64) -> u64 {
    if n == 0 { 0 } else { self.next() % n }
  }

  fn chance(&mut self, percent: u64) -> bool {
    self.below(100) < percent
  }

  fn bytes(&mut self, len: usize) -> Vec<u8> {
    (0..len).map(|_| self.next() as u8).collect()
  }

  fn payload_len(&mut self) -> usize {
    match self.below(20) {
      0 => 0,
      1 => 125,
      2 => 126,
      3 => 127,
      4 => 65535,
      5 => 65536 + self.below(300) as usize,
      6..=8 => 128 + self.below(2000) as usize,
      _ => 1 + self.below(40) as usize,
    }
  }

  // Valid UTF-8 with multi-byte characters, so that fragments can split them.
  fn text(&mut self, len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while out.len() < len {
      let ch = match self.below(4) {
        0 => 'a',
        1 => 'é',
        2 => '€',
        _ => '𝄞',
      };
      let mut buf = [0; 4];
      out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
    }
    out
  }

  fn frame(&mut self, out: &mut Vec<u8>, fin: bool, op: u8, payload: &[u8]) {
    let mut b0 = if fin { 0x80 } else { 0 } | op;
    if self.chance(1) {
      b0 |= 0x10 << self.below(3);
    }
    let masked = !self.chance(1);
    let mask = if masked { 0x80 } else { 0 };
    let len = payload.len();
    // mostly the shortest length encoding, sometimes a longer one
    let wide = self.below(10);
    if len < 126 && wide > 1 {
      out.extend_from_slice(&[b0, mask | len as u8]);
    } else if len <= 0xFFFF && wide > 0 {
      out.extend_from_slice(&[b0, mask | 126]);
      out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
      out.extend_from_slice(&[b0, mask | 127]);
      out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let key: [u8; 4] = (self.next() as u32).to_be_bytes();
    if masked {
      out.extend_from_slice(&key);
      out.extend(payload.iter().enumerate().map(|(idx, el)| el ^ key[idx % 4]));
    } else {
      out.extend_from_slice(payload);
    }
  }

  fn case(&mut self) -> (Vec<u8>, Vec<usize>, bool) {
    let mut out = Vec::new();
    let frames = 1 + self.below(12);
    for _ in 0..frames {
      match self.below(20) {
        0..=5 => {
          let len = self.payload_len();
          let payload = self.text(len);
          self.frame(&mut out, true, 1, &payload);
        }
        6..=8 => {
          let len = self.payload_len();
          let payload = self.bytes(len);
          self.frame(&mut out, true, 2, &payload);
        }
        9..=11 => {
          // a fragmented message, sometimes with control frames between the fragments
          let text = self.chance(60);
          let len = self.payload_len().max(3);
          let payload = if text { self.text(len) } else { self.bytes(len) };
          let parts = 2 + self.below(3) as usize;
          let mut cuts: Vec<usize> =
            (0..parts - 1).map(|_| self.below(payload.len() as u64) as usize).collect();
          cuts.sort_unstable();
          let mut begin = 0;
          for (idx, cut) in cuts.iter().chain(core::iter::once(&payload.len())).enumerate() {
            let end = (*cut).max(begin);
            let op = if idx == 0 { if text { 1 } else { 2 } } else { 0 };
            self.frame(&mut out, idx == parts - 1, op, &payload[begin..end]);
            begin = end;
            if self.chance(20) {
              let ping = {
                let len = self.below(20) as usize;
                self.bytes(len)
              };
              self.frame(&mut out, true, 9, &ping);
            }
          }
        }
        12..=14 => {
          let ping = {
            let len = self.below(126) as usize;
            self.bytes(len)
          };
          self.frame(&mut out, true, 9, &ping);
        }
        15 => {
          let pong = {
            let len = self.below(126) as usize;
            self.bytes(len)
          };
          self.frame(&mut out, true, 10, &pong);
        }
        16 => {
          // protocol violations
          match self.below(7) {
            0 => {
              let mut bad = self.text(10);
              bad[3] = 0xFF;
              self.frame(&mut out, true, 1, &bad);
            }
            1 => {
              let op = 3 + self.below(5) as u8;
              self.frame(&mut out, true, op, b"x");
            }
            2 => {
              let payload = self.bytes(126);
              self.frame(&mut out, true, 9, &payload);
            }
            3 => self.frame(&mut out, false, 9, b"p"),
            4 => self.frame(&mut out, true, 0, b"orphan"),
            5 => {
              self.frame(&mut out, false, 1, b"ab");
              self.frame(&mut out, true, 2, b"cd");
            }
            _ => self.frame(&mut out, true, 8, &[0x03]),
          }
        }
        17 => {
          let codes = [
            1000u16, 1001, 1003, 1007, 1011, 1013, 3000, 4999, 0, 999, 1004, 1005, 1006, 1014,
            1015, 2000, 5000,
          ];
          let code = codes[self.below(codes.len() as u64) as usize];
          let mut payload = code.to_be_bytes().to_vec();
          payload.extend_from_slice(if self.chance(20) { &[0xC3, 0x28] } else { b"bye" });
          self.frame(&mut out, true, 8, &payload);
        }
        _ => {
          let payload = {
            let len = self.below(10) as usize;
            self.bytes(len)
          };
          self.frame(&mut out, true, 2, &payload);
        }
      }
    }
    if self.chance(10) {
      let cut = self.below(out.len() as u64) as usize;
      out.truncate(cut);
    }
    let chunks = match self.below(5) {
      0 => alloc::vec![usize::MAX],
      1 => alloc::vec![1],
      2 => (0..8).map(|_| 1 + self.below(16) as usize).collect(),
      3 => (0..8).map(|_| 1 + self.below(300) as usize).collect(),
      _ => (0..8).map(|_| 1 + self.below(8192) as usize).collect(),
    };
    (out, chunks, self.chance(30))
  }
}

#[cfg(test)]
mod tests {
  fn masked(fin: bool, op: u8, payload: &[u8]) -> alloc::vec::Vec<u8> {
    let mask = [1, 2, 3, 4];
    let mut out = alloc::vec![if fin { 0x80 } else { 0 } | op, 0x80 | payload.len() as u8];
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(idx, el)| el ^ mask[idx % 4]));
    out
  }

  // Upstream returned the fragments received so far as the ping's payload when the origin was
  // `Consistent`, and appended the ping's bytes to the message.
  #[cfg_attr(miri, ignore = "the test build links ring, whose C code Miri cannot run")]
  #[test]
  fn control_frame_between_fragments() {
    let mut input = masked(false, 1, b"ab");
    input.extend(masked(true, 9, b"xy"));
    input.extend(masked(true, 0, b"cd"));
    for chunk in [1, 3, usize::MAX] {
      super::check(&input, &[chunk], true);
      super::check(&input, &[chunk], false);
    }
  }

  // Upstream only checked RSV1 when a compression type was configured, so without one a frame
  // claiming to be compressed was accepted.
  #[cfg_attr(miri, ignore = "the test build links ring, whose C code Miri cannot run")]
  #[test]
  fn rsv1_without_compression() {
    let mut input = masked(true, 1, b"ok");
    let mut bad = masked(true, 1, b"compressed?");
    bad[0] |= 0x40;
    input.extend(bad);
    super::check(&input, &[usize::MAX], false);
  }

  #[cfg_attr(miri, ignore = "the test build links ring, whose C code Miri cannot run")]
  #[test]
  fn generated_cases_agree_with_the_model() {
    let seed = std::env::var("WTX_DIFF_SEED").ok().and_then(|el| el.parse().ok()).unwrap_or(1);
    let iterations =
      std::env::var("WTX_DIFF_ITERS").ok().and_then(|el| el.parse().ok()).unwrap_or(2000);
    super::check_generated(seed, iterations);
  }
}
