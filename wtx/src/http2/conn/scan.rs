//! Cuts complete frames out of a byte slice.

use crate::{
  http2::{Http2Error, Http2ErrorCode, frame_init::FrameInit},
  misc::Usize,
};

/// The client connection preface (RFC 9113 §3.4).
pub(crate) const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// How far the connection preface has arrived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Preface {
  /// Every byte so far matches, but fewer than 24 have arrived.
  Incomplete,
  /// The preface is complete and occupies this many bytes.
  Done(usize),
  /// A byte does not match.
  Invalid,
}

/// The next complete frame in `input`: its header (`None` for a frame type this implementation
/// does not know, which the caller ignores), its payload and the bytes it occupies. `Ok(None)` when
/// `input` ends before the frame does.
///
/// A payload longer than `max_frame_len` is a connection error of type FRAME_SIZE_ERROR.
pub(crate) fn next_frame(
  input: &[u8],
  max_frame_len: u32,
) -> crate::Result<Option<(Option<FrameInit>, &[u8], usize)>> {
  let [b0, b1, b2, b3, b4, b5, b6, b7, b8, rest @ ..] = input else {
    return Ok(None);
  };
  let (fi, data_len) = FrameInit::from_array([*b0, *b1, *b2, *b3, *b4, *b5, *b6, *b7, *b8]);
  if data_len > max_frame_len {
    return Err(crate::Error::Http2ErrorGoAway(
      Http2ErrorCode::FrameSizeError,
      Http2Error::LargeArbitraryFrameLen { received: data_len },
    ));
  }
  let len = *Usize::from_u32(data_len);
  let Some(payload) = rest.get(..len) else {
    return Ok(None);
  };
  Ok(Some((fi, payload, len.wrapping_add(9))))
}

/// Matches the start of `input` against the connection preface.
pub(crate) fn strip_preface(input: &[u8]) -> Preface {
  let len = input.len().min(PREFACE.len());
  if input.get(..len) != PREFACE.get(..len) {
    return Preface::Invalid;
  }
  if len < PREFACE.len() { Preface::Incomplete } else { Preface::Done(PREFACE.len()) }
}

#[cfg(test)]
mod tests {
  use crate::http2::{
    Http2ErrorCode,
    conn::{
      scan::{PREFACE, Preface, next_frame, strip_preface},
      test_frames::{data, frame, headers_req, settings},
    },
    frame_init::FrameInitTy,
  };
  use alloc::vec::Vec;

  fn all_frames(input: &[u8]) -> Vec<(Option<FrameInitTy>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = input;
    while let Some((fi, payload, consumed)) = next_frame(rest, 16_384).unwrap() {
      out.push((fi.map(|el| el.ty), payload.to_vec()));
      rest = &rest[consumed..];
    }
    assert!(rest.is_empty());
    out
  }

  #[test]
  fn scan_every_split_offset() {
    let mut input = settings(&[(3, 100)]);
    input.extend(headers_req(1, "POST", "/a", &[], false));
    input.extend(data(1, b"hello", true));
    let expected = all_frames(&input);
    assert_eq!(expected.len(), 3);
    for split in 0..=input.len() {
      let mut got = Vec::new();
      let mut buffer = input[..split].to_vec();
      let mut fed_rest = false;
      loop {
        match next_frame(&buffer, 16_384).unwrap() {
          Some((fi, payload, consumed)) => {
            got.push((fi.map(|el| el.ty), payload.to_vec()));
            let _ = buffer.drain(..consumed);
          }
          None if !fed_rest => {
            buffer.extend_from_slice(&input[split..]);
            fed_rest = true;
          }
          None => break,
        }
      }
      assert!(buffer.is_empty(), "split {split}");
      assert_eq!(got, expected, "split {split}");
    }
  }

  #[test]
  fn scan_rejects_oversized() {
    let input = frame(0, 0, 1, &[0; 101]);
    let Err(crate::Error::Http2ErrorGoAway(code, _)) = next_frame(&input, 100) else {
      panic!("expected a FRAME_SIZE_ERROR");
    };
    assert_eq!(code, Http2ErrorCode::FrameSizeError);
    assert!(next_frame(&input, 101).unwrap().is_some());
  }

  #[test]
  fn scan_skips_unknown_type() {
    let mut input = frame(0x20, 0, 0, &[7; 40]);
    input.extend(settings(&[]));
    let (fi, payload, consumed) = next_frame(&input, 16_384).unwrap().unwrap();
    assert!(fi.is_none());
    assert_eq!(payload.len(), 40);
    assert_eq!(consumed, 49);
    let (fi, _, _) = next_frame(&input[consumed..], 16_384).unwrap().unwrap();
    assert_eq!(fi.map(|el| el.ty), Some(FrameInitTy::Settings));
  }

  #[test]
  fn preface_partial_reads() {
    for len in 0..24 {
      assert_eq!(strip_preface(&PREFACE[..len]), Preface::Incomplete, "len {len}");
    }
    assert_eq!(strip_preface(PREFACE), Preface::Done(24));
    let mut longer = PREFACE.to_vec();
    longer.extend(settings(&[]));
    assert_eq!(strip_preface(&longer), Preface::Done(24));
    let mut wrong = *PREFACE;
    wrong[5] = b'X';
    assert_eq!(strip_preface(&wrong), Preface::Invalid);
    assert_eq!(strip_preface(&wrong[..6]), Preface::Invalid);
  }
}
