//! An HTTP/3 server connection driven by generated input, for the fuzzer and for tests.
//!
//! The server is an [`H3App`] of a handler that answers `200` with a small body, parks the requests
//! to `/park`, fails the ones to `/err` and answers `/big` with 40 KB, as the application of a
//! server connection of [`Duo`](crate::quic::Duo); the client is a QUIC connection whose streams
//! the script writes: the control stream and the QPACK streams of a client, requests (valid ones,
//! with bodies and trailers, and damaged ones), frames of every type, resets and STOP_SENDING
//! frames, together with every action on the QUIC packets of the module of [`Duo`].
//!
//! Whatever the script is, the server must hold these:
//!
//! - it never panics;
//! - every close of the connection that it owes has a code of RFC 9000 section 20.1, or one of
//!   RFC 9114 section 8.1 and RFC 9204 section 6;
//! - if the script was only valid requests, an acceptable control stream, time and round trips,
//!   every request is answered with a complete `200` and the body of the handler, and the
//!   connection is not closed.

use crate::{
  collections::VectorUsize,
  http3::{
    DecodeOutcome, H3App, H3FrameTy, H3Handler, H3Params, H3ReqCtx, H3Request, H3Settings,
    QpackDecoder, ReqOutcome, decode_frame_header, encode_frame_header, encode_static,
  },
  quic::{ConnState, Duo, Input, StreamId},
};
use alloc::{vec, vec::Vec};

const BIG: &[u8] = &[0x61; 40_000];
const BODY: &[u8] = b"hello";
const MAX_ACTIONS: usize = 96;
const MAX_ROUNDS: usize = 64;

/// Answers as the module says.
#[derive(Debug, Default)]
struct FuzzHandler {
  parked: Vec<StreamId>,
}

impl H3Handler for FuzzHandler {
  fn on_request(
    &mut self,
    cx: &mut H3ReqCtx<'_, '_>,
    req: &H3Request<'_>,
  ) -> crate::Result<ReqOutcome> {
    if req.path.starts_with(b"/park") {
      self.parked.push(req.stream);
      return Ok(ReqOutcome::Parked);
    }
    if req.path.starts_with(b"/err") {
      return Err(crate::Error::ProgrammingError);
    }
    let body = if req.path.starts_with(b"/big") { BIG } else { BODY };
    cx.respond_fields(&[(b":status", b"200"), (b"content-type", b"text/plain")], body)?;
    Ok(ReqOutcome::Responded)
  }

  fn resume(&mut self, cx: &mut H3ReqCtx<'_, '_>, _: StreamId) -> crate::Result<ReqOutcome> {
    cx.respond_fields(&[(b":status", b"200")], b"resumed")?;
    Ok(ReqOutcome::Responded)
  }
}

type Server = H3App<FuzzHandler>;

/// A frame of type `ty`.
fn frame(ty: u64, payload: &[u8]) -> Vec<u8> {
  let mut header = [0u8; 16];
  let len = encode_frame_header(H3FrameTy::Unknown(ty), payload.len() as u64, &mut header).unwrap();
  let mut rslt = header[..len].to_vec();
  rslt.extend_from_slice(payload);
  rslt
}

fn section(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
  let mut out = VectorUsize::new();
  encode_static(fields, &mut out).unwrap();
  out.to_vec()
}

/// The fields of a request: valid, or one thing wrong with it, as the byte `kind` says.
fn request_fields(input: &mut Input<'_>, kind: u8) -> Vec<(Vec<u8>, Vec<u8>)> {
  let method: &[u8] = match input.byte() % 6 {
    0 | 1 | 2 => b"GET",
    3 => b"POST",
    4 => b"CONNECT",
    _ => b"G E T",
  };
  let path: &[u8] = match input.byte() % 6 {
    0..=2 => b"/",
    3 => b"/park",
    4 => b"/err",
    _ => b"/big",
  };
  let mut fields: Vec<(Vec<u8>, Vec<u8>)> = vec![
    (b":method".to_vec(), method.to_vec()),
    (b":scheme".to_vec(), b"https".to_vec()),
    (b":authority".to_vec(), b"localhost".to_vec()),
    (b":path".to_vec(), path.to_vec()),
  ];
  match kind % 16 {
    // A pseudo-header field twice, missing, late or unknown
    1 => fields.push((b":method".to_vec(), b"GET".to_vec())),
    2 => drop(fields.remove(usize::from(input.byte() % 4))),
    3 => fields.insert(2, (b"x-early".to_vec(), b"1".to_vec())),
    4 => fields.push((b":status".to_vec(), b"200".to_vec())),
    // Fields that HTTP/3 forbids
    5 => fields.push((b"connection".to_vec(), b"close".to_vec())),
    6 => fields.push((b"transfer-encoding".to_vec(), b"chunked".to_vec())),
    7 => fields.push((b"te".to_vec(), b"trailers".to_vec())),
    8 => fields.push((b"te".to_vec(), b"gzip".to_vec())),
    9 => fields.push((b"Upper".to_vec(), b"case".to_vec())),
    10 => fields.push((b"content-length".to_vec(), input.sized(6).to_vec())),
    11 => fields.push((input.sized(12).to_vec(), input.sized(12).to_vec())),
    12 => fields.push((b"cookie".to_vec(), vec![b'c'; 200])),
    13 => fields.push((b"x-big".to_vec(), vec![b'b'; 20_000])),
    _ => {}
  }
  fields
}

/// What the client of a script has done that makes the answers of the server unpredictable.
#[derive(Debug, Default)]
struct Plan {
  /// The requests that must be answered: stream, and whether their path is `/big`.
  good: Vec<(StreamId, bool)>,
  /// Something other than valid requests, an acceptable control stream and time.
  noisy: bool,
  /// The control stream of the client, once opened.
  control: Option<StreamId>,
  /// The time that the script let pass.
  elapsed_us: u64,
  /// The streams the script opened.
  streams: Vec<StreamId>,
}

fn open_uni(duo: &mut Duo<Server>, ty: u8, bytes: &[u8]) -> Option<StreamId> {
  let now_us = duo.now_us;
  duo.with_client_ctx(now_us, |cx| {
    let id = cx.open_uni().ok()?;
    cx.write(id, &[ty], false).ok()?;
    cx.write(id, bytes, false).ok()?;
    Some(id)
  })
}

fn write(duo: &mut Duo<Server>, id: StreamId, bytes: &[u8], fin: bool) {
  let now_us = duo.now_us;
  duo.with_client_ctx(now_us, |cx| {
    let _rslt = cx.write(id, bytes, fin);
  });
}

fn action(duo: &mut Duo<Server>, input: &mut Input<'_>, plan: &mut Plan) {
  let now_us = duo.now_us;
  match input.byte() % 18 {
    // The control stream, once: acceptable settings or any bytes
    0 => {
      if plan.control.is_none() {
        let valid = input.byte() % 3 != 0;
        let mut payload = vec![0u8; 64];
        let settings = H3Settings {
          qpack_max_table_capacity: u64::from(input.byte() % 2) * 4096,
          qpack_blocked_streams: u64::from(input.byte() % 4),
          max_field_section_size: None,
        };
        let len = settings.encode(&mut payload).unwrap();
        payload.truncate(len);
        // `encode` writes the whole SETTINGS frame
        let bytes = if valid { payload } else { input.sized(64).to_vec() };
        plan.noisy |= !valid;
        plan.control = open_uni(duo, 0, &bytes);
      } else {
        // Frames on the control stream
        let ty = match input.byte() % 6 {
          0 => 7,
          1 => 0xd,
          2 => 3,
          3 => 0x21,
          4 => u64::from(input.byte()),
          _ => 4,
        };
        let bytes = frame(ty, input.sized(16));
        plan.noisy = true;
        if let Some(id) = plan.control {
          write(duo, id, &bytes, false);
        }
      }
    }
    // The QPACK streams: instructions of an encoder, or of a decoder
    1 | 2 => {
      plan.noisy = true;
      let (ty, first): (u8, u8) = if input.byte() % 2 == 0 { (2, 0x20) } else { (3, 0x00) };
      let mut bytes = vec![first | input.byte() % 32];
      bytes.extend_from_slice(input.sized(64));
      if let Some(id) = open_uni(duo, ty, &bytes) {
        plan.streams.push(id);
      }
    }
    // A request, valid or not
    3..=8 => {
      let kind = if input.byte() % 4 == 0 { input.byte() } else { 0 };
      let fields = request_fields(input, kind);
      let refs: Vec<(&[u8], &[u8])> =
        fields.iter().map(|(name, value)| (name.as_slice(), value.as_slice())).collect();
      let mut bytes = frame(1, &section(&refs));
      let post = fields[0].1 == b"POST";
      let body = input.sized(200).to_vec();
      if post || input.byte() % 8 == 0 {
        bytes.extend(frame(0, &body));
      }
      // Trailers
      if input.byte() % 8 == 0 {
        bytes.extend(frame(1, &section(&[(b"x-trailer", b"1")])));
        plan.noisy = true;
      }
      let fin = input.byte() % 16 != 0;
      let valid = kind % 16 == 0
        && fields[0].1 != b"CONNECT"
        && fields[0].1 != b"G E T"
        && fields[3].1 != b"/park"
        && fields[3].1 != b"/err"
        && fin;
      plan.noisy |= !valid;
      let opened = duo.with_client_ctx(now_us, |cx| {
        let id = cx.open_bidi().ok()?;
        cx.write(id, &bytes, fin).ok()?;
        Some(id)
      });
      if let Some(id) = opened {
        plan.streams.push(id);
        if valid {
          plan.good.push((id, fields[3].1 == b"/big"));
        }
      }
    }
    // Any bytes on a stream of the script, or a frame of any type
    9 | 10 => {
      plan.noisy = true;
      let Some(id) = pick(&plan.streams, input) else {
        return;
      };
      let bytes = if input.byte() % 2 == 0 {
        frame(u64::from(input.byte() % 16) | u64::from(input.byte() % 4) << 8, input.sized(48))
      } else {
        input.sized(96).to_vec()
      };
      write(duo, id, &bytes, input.byte() % 8 == 0);
    }
    // A field section with a reference to the dynamic table, to an encoder that was not told
    11 => {
      plan.noisy = true;
      let mut bytes = vec![input.byte() % 4, input.byte() % 4];
      bytes.extend_from_slice(input.sized(32));
      let bytes = frame(1, &bytes);
      let opened = duo.with_client_ctx(now_us, |cx| {
        let id = cx.open_bidi().ok()?;
        cx.write(id, &bytes, input.byte() % 2 == 0).ok()?;
        Some(id)
      });
      plan.streams.extend(opened);
    }
    // A reset or a STOP_SENDING of a stream of the script
    12 => {
      plan.noisy = true;
      let Some(id) = pick(&plan.streams, input) else {
        return;
      };
      let code = u64::from(input.byte());
      let reset = input.byte() % 2 == 0;
      duo.with_client_ctx(now_us, |cx| {
        if reset {
          cx.reset(id, code);
        } else {
          cx.stop_sending(id, code);
        }
      });
    }
    // The server resumes a parked request
    13 => {
      let parked = duo.s_app.handler.parked.pop();
      if let Some(id) = parked {
        let Duo { server, s_app, s_pools, .. } = duo;
        server.with_ctx(now_us, s_pools, |cx| {
          let _rslt = s_app.resume(cx, id);
        });
      }
    }
    // Round trips as they are
    14 | 15 => duo.exchange(usize::from(input.byte() % 8) + 1),
    // Time
    16 => {
      let us = match input.byte() % 4 {
        0 => 1_000,
        1 => 25_000,
        2 => 300_000,
        _ => 1_000_000,
      };
      // Quiet for long enough, a connection idles out
      plan.elapsed_us += us;
      if plan.elapsed_us >= 1_000_000 {
        plan.noisy = true;
      }
      duo.advance(us);
      duo.exchange(4);
    }
    // An action on the packets
    _ => {
      plan.noisy = true;
      duo.tainted = true;
      duo.action(input);
    }
  }
}

fn pick(streams: &[StreamId], input: &mut Input<'_>) -> Option<StreamId> {
  let idx = usize::from(input.byte()).checked_rem(streams.len())?;
  streams.get(idx).copied()
}

/// What the client got on stream `id`: the types of the frames and the DATA, and whether the FIN
/// came.
fn response(duo: &Duo<Server>, id: StreamId) -> Option<(Vec<u64>, Vec<u8>, bool, Vec<u8>)> {
  let data = duo.c_app.streams.get(&id.0)?;
  let mut rslt = (Vec::new(), Vec::new(), duo.c_app.fins.contains(&id.0), Vec::new());
  let mut decoder = QpackDecoder::new(0, 0).unwrap();
  let mut scratch = VectorUsize::new();
  let mut rest = data.as_slice();
  while let Some((ty, len, header_len)) = decode_frame_header(rest).ok()? {
    let len = usize::try_from(len).ok()?;
    let payload = rest.get(header_len..header_len + len)?;
    rslt.0.push(ty.code());
    match ty {
      H3FrameTy::Headers => {
        let mut status = Vec::new();
        let outcome = decoder
          .decode(id.0, payload, &mut scratch, &mut |name, value| {
            if name == b":status" {
              status = value.to_vec();
            }
            Ok(())
          })
          .ok()?;
        rslt.3 = status;
        assert_eq!(outcome, DecodeOutcome::Done { referenced_dynamic: false });
      }
      H3FrameTy::Data => rslt.1.extend_from_slice(payload),
      _ => {}
    }
    rest = rest.get(header_len + len..)?;
  }
  Some(rslt)
}

fn check_codes(duo: &Duo<Server>) {
  if let Some((true, code)) = duo.server_close() {
    assert!(
      (0x100..=0x110).contains(&code) || (0x200..=0x202).contains(&code),
      "the server owes an application CONNECTION_CLOSE with the code {code:#x}"
    );
  }
}

/// Runs `input` as a script against `duo`, whose handshake is done, and checks the rules.
fn drive(duo: &mut Duo<Server>, input: &mut Input<'_>, tight: bool) {
  // Limits that a valid request can exceed (413, 431) make the answers unpredictable
  let mut plan = Plan { noisy: tight, ..Plan::default() };
  for _ in 0..MAX_ACTIONS {
    if input.is_empty() {
      break;
    }
    action(duo, input, &mut plan);
    duo.check();
    check_codes(duo);
  }
  duo.settle(MAX_ROUNDS);
  duo.check();
  check_codes(duo);
  if !plan.noisy && !duo.tainted {
    assert_ne!(duo.server.state(), ConnState::Closing, "the server closed on valid requests");
    for (id, big) in &plan.good {
      let Some((frames, body, fin, status)) = response(duo, *id) else {
        panic!("no answer to the valid request of stream {}", id.0);
      };
      let want = if *big { BIG } else { BODY };
      assert_eq!(status, b"200", "stream {}", id.0);
      assert!(fin && frames.first() == Some(&1) && body == want, "{frames:?} {fin} {}", body.len());
    }
  }
}

/// A server connection that waits for the script: its handshake is done.
fn duo_of(input: &mut Input<'_>) -> (Duo<Server>, bool) {
  let seed = input.byte();
  let presets = (input.byte(), input.byte());
  let dcid_len = input.byte();
  let params = H3Params {
    qpack_max_table_capacity: u32::from(input.byte() % 2) * 4096,
    qpack_blocked_streams: u16::from(input.byte() % 4),
    max_field_section_size: if input.byte() % 4 == 0 { 256 } else { 16 * 1024 },
    max_request_body: if input.byte() % 4 == 0 { 100 } else { 1 << 20 },
    max_buffered_body_per_conn: if input.byte() % 4 == 0 { 1000 } else { 16 << 20 },
  };
  let tight = params.max_field_section_size < 1024
    || params.max_request_body < 1024
    || params.max_buffered_body_per_conn < 1 << 20;
  let mut duo = Duo::new(seed, presets, dcid_len, H3App::new(FuzzHandler::default(), params));
  duo.c_app.record = true;
  duo.start();
  duo.exchange(16);
  (duo, tight)
}

/// Runs the bytes as a script against an HTTP/3 server connection, panicking if it breaks a rule of
/// the module.
#[inline]
pub fn run(data: &[u8]) {
  let mut input = Input::new(data);
  let (mut duo, tight) = duo_of(&mut input);
  drive(&mut duo, &mut input, tight);
  duo.finish();
}

#[cfg(test)]
mod tests {
  use super::{BODY, Input, drive, duo_of, response, run};
  use crate::quic::ConnState;
  use alloc::vec::Vec;

  // Rule: a valid request of the script is answered with the answer of the handler and nothing
  // closes the connection; the script reaches the handler through the QUIC connection.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn valid_request_of_a_script_is_answered() {
    // Seed, presets, CID length, settings (five bytes); then a GET of `/` with a FIN, and round
    // trips
    let script = [1, 0, 0, 0, 1, 1, 1, 1, 1, 3, 1, 0, 0, 0, 1, 1, 1, 14, 7];
    let mut input = Input::new(&script);
    let (mut duo, tight) = duo_of(&mut input);
    assert!(!tight);
    assert_eq!(duo.server.state(), ConnState::Confirmed);
    drive(&mut duo, &mut input, tight);
    // The first stream of the client
    let (frames, body, fin, status) = response(&duo, crate::quic::StreamId(0)).unwrap();
    assert_eq!((frames, body.as_slice(), fin), (alloc::vec![1, 0], BODY, true));
    assert_eq!(status, b"200");
    duo.finish();
  }

  // The inputs that stopped the first version of the target `h3_conn`: a valid request after an
  // acceptable control stream, which the script of the target had wrapped in a frame twice (the
  // server rightly closed with H3_SETTINGS_ERROR). The target takes them now.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn valid_request_after_a_control_stream_is_answered() {
    for hex in [
      "0200000300000101010e070001000003010000000101010e07",
      "1900170000000000000007032504050000000101010e07",
      "0700000300000101010e0703010005000101010e070e07",
      "0400000300000101010e0700010000030100000001010103010000000101010301000000010101030100000001010103010000000101010301000000010101030100000001010103010000000101010301000000010101030100000001010103010000000101010301000000010101030100000001010103010000000101010301000000010101030100000001010103010000000101010301000000010101030100000001010103010000000101010e07",
    ] {
      let data: Vec<u8> = (0..hex.len() / 2)
        .map(|idx| u8::from_str_radix(&hex[idx * 2..idx * 2 + 2], 16).unwrap())
        .collect();
      run(&data);
    }
  }

  // The input that stopped the second version of the target: tight limits, with which a request that
  // is valid is answered with 413, which the script did not expect.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn tight_limits_make_the_answers_unpredictable() {
    for hex in [
      "280000003a617574686f726974790000000000000000000000ff494949494949494949494949404949494949494949494949494949494949494949494949494949494949494949494949494949494904090203000328e1e1e1e125e1e1e1d3e1e1e1e1e1e1e1e1e1e1e1e125e1fffefefee1e1d3e1e1e1e1e1e1e1e1e1e1e12498f101757be311031122fe",
    ] {
      let data: Vec<u8> = (0..hex.len() / 2)
        .map(|idx| u8::from_str_radix(&hex[idx * 2..idx * 2 + 2], 16).unwrap())
        .collect();
      run(&data);
    }
  }

  // Rule: whatever the script is, the server holds the rules of the module.
  #[cfg_attr(miri, ignore)]
  #[test]
  fn generated_scripts_do_not_break_the_server() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      state
    };
    for round in 0..300 {
      let len = usize::try_from(next() % 800).unwrap();
      let mut data: Vec<u8> = (0..len).map(|_| u8::try_from(next() & 0xff).unwrap()).collect();
      if round % 2 == 0 {
        // Requests and round trips
        for (idx, byte) in data.iter_mut().enumerate().skip(9) {
          if idx % 3 == 0 {
            *byte = [3, 14, 4, 0][idx % 4];
          }
        }
      }
      run(&data);
    }
  }
}
