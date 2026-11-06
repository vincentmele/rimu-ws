//! Differential testing of the server connection core against a model of what a client may expect.
//!
//! The bytes drive a generator of client frames: requests (some split into HEADERS and
//! CONTINUATION, some with bodies), DATA, WINDOW_UPDATE, SETTINGS, PING, PRIORITY, RST_STREAM,
//! unknown frames and garbage. The frames are fed to [`Http2Conn`] in chunks cut at offsets the bytes
//! choose; every request the core completes is answered with the decimal string of its stream id.
//! The output is checked against the client's view:
//!
//! - every request the client completed gets exactly one response with that body, or a reset,
//!   unless the connection failed;
//! - nothing is sent on a stream after the server reset it, and no HEADERS or DATA after its
//!   END_STREAM;
//! - DATA never exceeds what the client's SETTINGS and WINDOW_UPDATEs allowed;
//! - nothing is answered above the last stream id of a GOAWAY;
//! - the core never panics.

use crate::{
  http::{HttpRecvParams, MsgBufferString, StatusCode, U31},
  http2::conn::{
    ConnEvent, Http2Conn,
    scan::PREFACE,
    test_frames::{frame, headers_req, parse_all, settings},
  },
  rng::Xorshift64,
};
use alloc::{
  collections::{BTreeMap, BTreeSet},
  format,
  string::{String, ToString as _},
  vec::Vec,
};

const CONTINUATION: u8 = 9;
const DATA: u8 = 0;
const GOAWAY: u8 = 7;
const HEADERS: u8 = 1;
const RST_STREAM: u8 = 3;
/// Resets the core remembers (`RecentResets`).
const RESETS_REMEMBERED: usize = 32;
/// Streams a run opens at most.
const MAX_STREAMS: u32 = 300;

/// Runs the bytes as a generator seed, panicking on a disagreement with the model.
pub fn run(seed_bytes: &[u8]) {
  if let Err(msg) = check(seed_bytes) {
    panic!("{msg}");
  }
}

/// [`run`], with the disagreement as an error, else the responses checked and whether the
/// connection failed.
pub(crate) fn check(seed_bytes: &[u8]) -> Result<(usize, bool), String> {
  let mut bytes = Bytes { bytes: seed_bytes, idx: 0 };
  let mut client = Client::default();
  let input = client.generate(&mut bytes);
  let mut conn = Http2Conn::<false>::new(HttpRecvParams::with_default_params(), &mut Xorshift64::from(7u64));
  let mut model = Model::new(&client);
  let mut pending = Vec::new();
  let mut out = Vec::new();
  let mut fed = 0;
  let mut failed = false;
  while fed < input.len() && !failed {
    let chunk = usize::from(bytes.next().unwrap_or(u8::MAX)).wrapping_mul(7).wrapping_add(1);
    let end = fed.saturating_add(chunk).min(input.len());
    pending.extend_from_slice(&input[fed..end]);
    fed = end;
    match conn.feed(&pending) {
      Ok(consumed) => {
        let _ = pending.drain(..consumed);
      }
      Err(_) => failed = true,
    }
    answer(&mut conn);
    drain(&mut conn, &mut out);
    model.observe(&mut out)?;
  }
  model.finish(failed)
}

/// Answers every request the core completed.
fn answer(conn: &mut Http2Conn<false>) {
  while let Some(event) = conn.poll_event() {
    let stream_id = match event {
      ConnEvent::Headers { end_stream: true, stream_id }
      | ConnEvent::Data { end_stream: true, stream_id }
      | ConnEvent::Trailers { stream_id } => stream_id,
      _ => continue,
    };
    respond(conn, stream_id);
  }
}

fn respond(conn: &mut Http2Conn<false>, stream_id: U31) {
  let mut msg = MsgBufferString::default();
  let body = stream_id.u32().to_string();
  if msg.body.extend_from_copyable_slice(body.as_bytes()).is_err() {
    return;
  }
  // A stream reset meanwhile, or a full send queue, refuses the response.
  let _rslt = conn.send_response(stream_id, StatusCode::Ok, &mut msg);
}

/// Appends everything the core queued to `out`.
fn drain(conn: &mut Http2Conn<false>, out: &mut Vec<u8>) {
  while conn.has_output() {
    let mut slices = crate::collections::ArrayVectorCopy::<&[u8], 16>::new();
    conn.output(&mut slices);
    let mut len = 0;
    for slice in slices.iter() {
      out.extend_from_slice(slice);
      len += slice.len();
    }
    conn.advance_output(len);
  }
}

/// The generator's input.
struct Bytes<'any> {
  bytes: &'any [u8],
  idx: usize,
}

impl Bytes<'_> {
  fn next(&mut self) -> Option<u8> {
    let byte = self.bytes.get(self.idx).copied()?;
    self.idx = self.idx.wrapping_add(1);
    Some(byte)
  }

  fn u32(&mut self) -> Option<u32> {
    Some(u32::from_be_bytes([self.next()?, self.next()?, self.next()?, self.next()?]))
  }
}

/// What the client sent.
#[derive(Default)]
struct Client {
  /// Whether this run may break the protocol (about a quarter do); the others stay valid, so
  /// that their connections live to be checked.
  breaks: bool,
  /// Streams the client ended (END_STREAM sent) and did not reset.
  completed: BTreeSet<u32>,
  /// Connection WINDOW_UPDATE increments.
  conn_updates: i64,
  /// Garbage was sent: what the server makes of the frames after it is anyone's guess (it may
  /// even wait for the rest of a frame the garbage announced).
  garbage: bool,
  /// The largest SETTINGS_INITIAL_WINDOW_SIZE sent, starting from the default.
  max_initial_window: i64,
  next_id: u32,
  /// Requests with a body still to come.
  open_bodies: Vec<u32>,
  /// Streams the client reset.
  reset: BTreeSet<u32>,
  /// Stream WINDOW_UPDATE increments.
  stream_updates: BTreeMap<u32, i64>,
}

impl Client {
  fn generate(&mut self, bytes: &mut Bytes<'_>) -> Vec<u8> {
    self.max_initial_window = 65_535;
    self.next_id = 1;
    self.breaks = bytes.next().is_some_and(|el| el.is_multiple_of(4));
    let mut input = PREFACE.to_vec();
    input.extend(settings(&[]));
    // The acknowledgement of the server's SETTINGS.
    input.extend(frame(4, 1, 0, &[]));
    while let Some(op) = bytes.next() {
      let Some(arg) = bytes.next() else {
        break;
      };
      match op % 16 {
        0..=5 => self.request(bytes, &mut input, arg, true),
        6 | 7 => self.request(bytes, &mut input, arg, false),
        8 | 9 => self.data(&mut input, arg),
        10 => self.window_update(bytes, &mut input, arg),
        11 => self.settings(bytes, &mut input, arg),
        12 => input.extend(frame(6, 0, 0, &[arg; 8])),
        13 => self.reset(&mut input, arg),
        14 => input.extend(frame(2, 0, self.some_id(arg).max(1), &[0, 0, 0, 0, 16])),
        _ => {
          if self.breaks && arg.is_multiple_of(8) {
            // Garbage, which most likely ends the connection.
            self.garbage = true;
            for _ in 0..arg % 21 {
              input.push(bytes.next().unwrap_or(0));
            }
          } else {
            // An unknown frame type, which must be ignored.
            input.extend(frame(0xA0, arg, self.some_id(arg), &[arg; 3]));
          }
        }
      }
    }
    input
  }

  /// A stream the client opened, or 0 if none: frames on a stream never opened are connection
  /// errors, which only breaking runs send (an id past the last one opened).
  fn some_id(&self, arg: u8) -> u32 {
    let opened = self.next_id / 2;
    if self.breaks && arg.is_multiple_of(16) {
      return self.next_id;
    }
    if opened == 0 {
      return 0;
    }
    (u32::from(arg) % opened).wrapping_mul(2).wrapping_add(1)
  }

  fn request(&mut self, bytes: &mut Bytes<'_>, input: &mut Vec<u8>, arg: u8, end_stream: bool) {
    if self.next_id > MAX_STREAMS.wrapping_mul(2) {
      return;
    }
    let id = self.next_id;
    self.next_id = self.next_id.wrapping_add(2);
    let path = format!("/{arg}");
    let (method, extra): (&str, &[(&str, &str)]) =
      if end_stream { ("GET", &[]) } else { ("POST", &[("x-pad", "0123456789abcdef")]) };
    let whole = headers_req(id, method, &path, extra, end_stream);
    if arg.is_multiple_of(4) {
      // The block split into HEADERS and CONTINUATIONs, cut anywhere, mid-field included.
      let block = &whole[9..];
      let first = usize::from(bytes.next().unwrap_or(1)) % block.len().max(1);
      let second = first.wrapping_add(usize::from(bytes.next().unwrap_or(1)) % 7).min(block.len());
      input.extend(frame(HEADERS, u8::from(end_stream), id, &block[..first]));
      input.extend(frame(CONTINUATION, 0, id, &block[first..second]));
      input.extend(frame(CONTINUATION, 0b100, id, &block[second..]));
    } else {
      input.extend(whole);
    }
    if end_stream {
      let _ = self.completed.insert(id);
    } else {
      self.open_bodies.push(id);
    }
  }

  fn data(&mut self, input: &mut Vec<u8>, arg: u8) {
    if self.open_bodies.is_empty() {
      return;
    }
    let idx = usize::from(arg) % self.open_bodies.len();
    let id = self.open_bodies[idx];
    let end_stream = arg.is_multiple_of(3);
    let payload = [arg].repeat(usize::from(arg % 32));
    input.extend(frame(DATA, u8::from(end_stream), id, &payload));
    if end_stream {
      let _ = self.open_bodies.swap_remove(idx);
      let _ = self.completed.insert(id);
    }
  }

  fn window_update(&mut self, bytes: &mut Bytes<'_>, input: &mut Vec<u8>, arg: u8) {
    let increment = match arg % 16 {
      // Zero and an overflow: protocol and flow-control errors.
      0 if self.breaks => 0,
      1 if self.breaks => 0x7FFF_FFFF,
      _ => bytes.u32().unwrap_or(1) % 65_536 + 1,
    };
    let stream = if arg.is_multiple_of(2) { 0 } else { self.some_id(arg) };
    input.extend(frame(8, 0, stream, &increment.to_be_bytes()));
    if stream == 0 {
      self.conn_updates = self.conn_updates.saturating_add(i64::from(increment));
    } else {
      let entry = self.stream_updates.entry(stream).or_default();
      *entry = entry.saturating_add(i64::from(increment));
    }
  }

  fn settings(&mut self, bytes: &mut Bytes<'_>, input: &mut Vec<u8>, arg: u8) {
    let value = bytes.u32().unwrap_or(0);
    if arg.is_multiple_of(2) {
      // SETTINGS_INITIAL_WINDOW_SIZE: room enough for any body here, up to an overflow.
      let window = if self.breaks && arg.is_multiple_of(32) { 0x8000_0000 } else { 16 + value % (1 << 20) };
      input.extend(settings(&[(4, window)]));
      self.max_initial_window = self.max_initial_window.max(i64::from(window));
    } else {
      // SETTINGS_MAX_FRAME_SIZE, valid or not.
      let max_frame =
        if self.breaks && arg % 16 == 1 { 100 } else { 16_384 + value % (16_777_215 - 16_384) };
      input.extend(settings(&[(5, max_frame)]));
    }
  }

  fn reset(&mut self, input: &mut Vec<u8>, arg: u8) {
    let id = self.some_id(arg);
    if id == 0 && !self.breaks {
      return;
    }
    input.extend(frame(RST_STREAM, 0, id, &8u32.to_be_bytes()));
    let _ = self.reset.insert(id);
    let _ = self.completed.remove(&id);
    self.open_bodies.retain(|el| *el != id);
  }
}

/// The client's view of the server's output.
struct Model {
  bodies: BTreeMap<u32, Vec<u8>>,
  client_completed: BTreeSet<u32>,
  client_reset: BTreeSet<u32>,
  conn_allowance: i64,
  conn_sent: i64,
  ended: BTreeSet<u32>,
  garbage: bool,
  go_away: Option<(u32, u32)>,
  responses: BTreeMap<u32, u32>,
  /// Streams the server reset, with how many resets it had sent before.
  server_reset: BTreeMap<u32, usize>,
  server_resets: usize,
  stream_allowance: BTreeMap<u32, i64>,
  stream_initial: i64,
  stream_sent: BTreeMap<u32, i64>,
}

impl Model {
  /// The allowances are the client's whole grants, counted as soon as generated: the server, which
  /// sees them later, can only have less.
  fn new(client: &Client) -> Self {
    Self {
      bodies: BTreeMap::new(),
      client_completed: client.completed.clone(),
      client_reset: client.reset.clone(),
      conn_allowance: 65_535i64.saturating_add(client.conn_updates),
      conn_sent: 0,
      ended: BTreeSet::new(),
      garbage: client.garbage,
      go_away: None,
      responses: BTreeMap::new(),
      server_reset: BTreeMap::new(),
      server_resets: 0,
      stream_allowance: client.stream_updates.clone(),
      stream_initial: client.max_initial_window,
      stream_sent: BTreeMap::new(),
    }
  }

  /// Takes the whole frames at the start of `out`.
  fn observe(&mut self, out: &mut Vec<u8>) -> Result<(), String> {
    let complete = complete_len(out);
    let frames = parse_all(&out[..complete]);
    let _ = out.drain(..complete);
    for (ty, flags, id, payload) in frames {
      if id != 0
        && let Some(at) = self.server_reset.get(&id)
      {
        // The server remembers its last resets only (RFC 9113 §5.1 lets it limit that): past
        // them, a late frame may draw RST_STREAM(STREAM_CLOSED) again.
        let forgotten = self.server_resets.wrapping_sub(*at) >= RESETS_REMEMBERED;
        let stream_closed = ty == RST_STREAM && payload.get(..4) == Some(&5u32.to_be_bytes()[..]);
        if !(forgotten && stream_closed) {
          return Err(format!("frame type {ty} on stream {id} after the server reset it"));
        }
      }
      match ty {
        HEADERS | CONTINUATION | DATA if self.ended.contains(&id) => {
          return Err(format!("frame type {ty} on stream {id} after its END_STREAM"));
        }
        HEADERS => {
          if self.go_away.is_some_and(|el| id > el.0) {
            return Err(format!("response on stream {id} above GOAWAY {:?}", self.go_away));
          }
          *self.responses.entry(id).or_default() += 1;
          if flags & 1 == 1 {
            let _ = self.ended.insert(id);
          }
        }
        DATA => {
          let len = i64::try_from(payload.len()).unwrap_or(i64::MAX);
          self.conn_sent = self.conn_sent.saturating_add(len);
          let sent = self.stream_sent.entry(id).or_default();
          *sent = sent.saturating_add(len);
          let allowance =
            self.stream_initial.saturating_add(self.stream_allowance.get(&id).copied().unwrap_or(0));
          if *sent > allowance || self.conn_sent > self.conn_allowance {
            return Err(format!("DATA past the windows on stream {id}"));
          }
          self.bodies.entry(id).or_default().extend_from_slice(&payload);
          if flags & 1 == 1 {
            let _ = self.ended.insert(id);
          }
        }
        RST_STREAM => {
          self.server_resets = self.server_resets.wrapping_add(1);
          let _ = self.server_reset.entry(id).or_insert(self.server_resets);
        }
        GOAWAY => {
          let last = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7FFF_FFFF;
          let code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
          if self.go_away.is_some_and(|el| last > el.0) {
            return Err(format!("a later GOAWAY raised the last stream id to {last}"));
          }
          if let Some((&above, _)) = self.responses.range(last.wrapping_add(1)..).next() {
            return Err(format!("GOAWAY {last} after a response on stream {above}"));
          }
          self.go_away = Some((last, code));
        }
        _ => {}
      }
    }
    Ok(())
  }

  fn finish(&self, failed: bool) -> Result<(usize, bool), String> {
    for (id, count) in &self.responses {
      if *count > 1 {
        return Err(format!("{count} responses on stream {id}"));
      }
    }
    // A failed connection (GOAWAY with an error) owes nothing more, nor one fed garbage.
    if failed || self.garbage || self.go_away.is_some_and(|el| el.1 != 0) {
      return Ok((0, true));
    }
    let mut checked = 0;
    for id in &self.client_completed {
      if self.client_reset.contains(id) || self.server_reset.contains_key(id) {
        continue;
      }
      if self.go_away.is_some_and(|el| *id > el.0) {
        continue;
      }
      let body = self.bodies.get(id).map(Vec::as_slice).unwrap_or_default();
      if !self.ended.contains(id) || body != id.to_string().as_bytes() {
        return Err(format!("stream {id}: no complete response (body {body:?})"));
      }
      checked += 1;
    }
    Ok((checked, false))
  }
}

/// Bytes of whole frames at the start of `bytes`.
fn complete_len(bytes: &[u8]) -> usize {
  let mut idx: usize = 0;
  while let Some([l0, l1, l2]) = bytes.get(idx..idx.wrapping_add(3)).and_then(|el| el.first_chunk()) {
    let len = usize::try_from(u32::from_be_bytes([0, *l0, *l1, *l2])).unwrap_or(usize::MAX);
    let end = idx.wrapping_add(9).wrapping_add(len);
    if end > bytes.len() {
      break;
    }
    idx = end;
  }
  idx
}

#[cfg(test)]
mod tests {
  use crate::rng::{Rng as _, Xorshift64};
  use alloc::vec::Vec;

  // Garbage whose bytes, with the next frame's header, announce a long frame: the server waits for
  // it and never sees the request behind it, which the model must not hold against it.
  #[test]
  fn differential_garbage_swallows_a_request() {
    super::run(&[0xd4, 0x2f, 0xd8, 0, 0x3a, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
  }

  // Over 32 resets later the server has forgotten an old one: a late frame on that stream may
  // draw RST_STREAM(STREAM_CLOSED) again (found by the fuzzer).
  #[test]
  fn differential_old_resets_are_forgotten() {
    super::run(&[
      136, 5, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246,
      246, 246, 246, 246, 246, 246, 246, 246, 246, 118, 246, 246, 246, 246, 246, 246, 246, 246, 0, 0, 137, 126, 126, 126,
      129, 129, 193, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246,
      246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 118, 246, 246,
      246, 246, 246, 246, 246, 246, 35, 246, 246, 246, 211, 143, 0, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246,
      246, 246, 246, 246, 246, 246, 246, 246, 129, 193, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246,
      246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 65, 246, 246, 246, 246, 246, 246, 246, 246, 246,
      246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 0, 1, 246, 246, 246, 246, 246, 246,
      246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246,
      246, 246, 246, 246, 246, 246, 246, 246, 10, 9, 9, 3, 246, 246, 246, 246, 246, 126, 0, 246, 246, 246, 246, 246,
      246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246,
      246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246,
      246, 246, 246, 246, 118, 246, 246, 246, 246, 246, 246, 246, 246, 35, 246, 246, 246, 211, 143, 0, 246, 246, 246, 246,
      246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 129, 193, 246, 246, 246, 246, 246, 246, 246,
      246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 65, 246, 246,
      246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 0,
      1, 246, 40, 246, 246, 246, 65, 65, 39, 39, 39, 39, 39, 39, 65, 39, 39, 39, 39, 39, 246, 246, 246, 129,
      133, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 129, 246, 246, 246, 246, 246, 246, 246, 246, 246, 9,
      9, 9, 9, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 10, 9, 9, 3, 246, 246, 246, 118, 246, 246, 246,
      246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246, 246,
      246, 246, 246, 129, 193, 39, 39, 39, 39, 246, 246, 246, 129, 133, 129, 74, 129, 129, 129, 129, 129, 129, 129, 137,
      129, 129, 129, 129, 129, 137,
    ]);
  }

  #[test]
  fn differential_fixed_seeds() {
    let mut rng = Xorshift64::from(0x5EED_u64);
    let (mut checked, mut failed) = (0, 0);
    for seed in 0..2000 {
      let mut bytes = Vec::new();
      for _ in 0..64 {
        bytes.extend_from_slice(&rng.u8_8());
      }
      match super::check(&bytes) {
        Ok((responses, conn_failed)) => {
          checked += responses;
          failed += usize::from(conn_failed);
        }
        Err(msg) => panic!("seed {seed}: {msg}\nbytes: {bytes:?}"),
      }
    }
    std::eprintln!("differential: {checked} responses checked, {failed} of 2000 connections failed");
    // The runs must reach the checks: most connections survive to answer their requests.
    assert!(failed < 1500 && checked > 10_000, "{checked} checked, {failed} failed");
  }
}
