//! HTTP/1.1 request body decoder.

use crate::http1::BodyKind;
use alloc::vec::Vec;

/// Progress of a [`BodyDecoder`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyStatus {
  /// More input is required.
  NeedMore,
  /// The body is complete.
  Complete {
    /// Number of bytes of the last `feed` input that belong to this body.
    consumed: usize,
  },
}

/// Incremental decoder of `Content-Length` and chunked bodies.
#[derive(Debug)]
pub struct BodyDecoder {
  state: State,
}

#[derive(Clone, Copy, Debug)]
enum State {
  /// The body has ended.
  Done,
  /// `Content-Length` payload with the remaining amount of bytes.
  Length(usize),
  /// Reading hexadecimal chunk-size digits.
  Size { any: bool, value: usize },
  /// Skipping chunk extensions until `\r`.
  Ext { value: usize },
  /// Expecting `\n` after the chunk-size line.
  SizeLf { value: usize },
  /// Chunk payload with the remaining amount of bytes.
  Data(usize),
  /// Expecting `\r` after the chunk payload.
  DataCr,
  /// Expecting `\n` after the chunk payload.
  DataLf,
  /// Start of a trailer line or of the final empty line.
  TrailerStart,
  /// Skipping a trailer line until `\r`.
  TrailerLine,
  /// Expecting `\n` after a trailer line.
  TrailerLf,
  /// Expecting `\n` of the final empty line.
  FinalLf,
}

impl BodyDecoder {
  /// New decoder for the given framing.
  #[inline]
  pub const fn new(kind: BodyKind) -> Self {
    let state = match kind {
      BodyKind::None | BodyKind::ContentLength(0) => State::Done,
      BodyKind::ContentLength(len) => State::Length(len),
      BodyKind::Chunked => State::Size { any: false, value: 0 },
    };
    Self { state }
  }

  /// Decodes `input`, appending the payload to `out`.
  ///
  /// Once the body is complete, the bytes after `consumed` belong to the next message.
  #[inline]
  pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> crate::Result<BodyStatus> {
    let mut idx = 0usize;
    loop {
      match self.state {
        State::Done => return Ok(BodyStatus::Complete { consumed: idx }),
        State::Length(remaining) => {
          let (taken, finished) = copy(input, &mut idx, remaining, out);
          if finished {
            self.state = State::Done;
          } else {
            self.state = State::Length(remaining.wrapping_sub(taken));
            return Ok(BodyStatus::NeedMore);
          }
        }
        State::Data(remaining) => {
          let (taken, finished) = copy(input, &mut idx, remaining, out);
          if finished {
            self.state = State::DataCr;
          } else {
            self.state = State::Data(remaining.wrapping_sub(taken));
            return Ok(BodyStatus::NeedMore);
          }
        }
        state => {
          let Some(&byte) = input.get(idx) else {
            return Ok(BodyStatus::NeedMore);
          };
          idx = idx.wrapping_add(1);
          self.state = step(state, byte)?;
        }
      }
    }
  }
}

/// Copies up to `remaining` bytes. Returns the copied amount and if `remaining` was reached.
#[inline]
fn copy(input: &[u8], idx: &mut usize, remaining: usize, out: &mut Vec<u8>) -> (usize, bool) {
  let rest = input.get(*idx..).unwrap_or_default();
  let taken = remaining.min(rest.len());
  out.extend_from_slice(rest.get(..taken).unwrap_or_default());
  *idx = idx.wrapping_add(taken);
  (taken, taken == remaining)
}

/// Advances the byte-wise part of the chunked state machine.
#[inline]
fn step(state: State, byte: u8) -> crate::Result<State> {
  Ok(match state {
    State::Size { any, value } => {
      if let Some(digit) = hex_digit(byte) {
        let new = value
          .checked_mul(16)
          .and_then(|elem| elem.checked_add(digit))
          .ok_or_else(bad_request)?;
        State::Size { any: true, value: new }
      } else if !any {
        return Err(bad_request());
      } else if byte == b'\r' {
        State::SizeLf { value }
      } else if byte == b';' {
        State::Ext { value }
      } else {
        return Err(bad_request());
      }
    }
    State::Ext { value } => {
      if byte == b'\r' {
        State::SizeLf { value }
      } else {
        State::Ext { value }
      }
    }
    State::SizeLf { value } => {
      if byte != b'\n' {
        return Err(bad_request());
      }
      if value == 0 { State::TrailerStart } else { State::Data(value) }
    }
    State::DataCr => {
      if byte != b'\r' {
        return Err(bad_request());
      }
      State::DataLf
    }
    State::DataLf => {
      if byte != b'\n' {
        return Err(bad_request());
      }
      State::Size { any: false, value: 0 }
    }
    State::TrailerStart => {
      if byte == b'\r' {
        State::FinalLf
      } else {
        State::TrailerLine
      }
    }
    State::TrailerLine => {
      if byte == b'\r' {
        State::TrailerLf
      } else {
        State::TrailerLine
      }
    }
    State::TrailerLf => {
      if byte != b'\n' {
        return Err(bad_request());
      }
      State::TrailerStart
    }
    State::FinalLf => {
      if byte != b'\n' {
        return Err(bad_request());
      }
      State::Done
    }
    State::Done | State::Length(_) | State::Data(_) => return Err(crate::Error::ProgrammingError),
  })
}

#[inline]
const fn hex_digit(byte: u8) -> Option<usize> {
  match byte {
    b'0'..=b'9' => Some((byte - b'0') as usize),
    b'a'..=b'f' => Some((byte - b'a') as usize + 10),
    b'A'..=b'F' => Some((byte - b'A') as usize + 10),
    _ => None,
  }
}

#[inline]
fn bad_request() -> crate::Error {
  crate::http::HttpError::BadRequest.into()
}

#[cfg(test)]
mod tests {
  use crate::http1::{BodyDecoder, BodyKind, BodyStatus};
  use alloc::vec::Vec;

  fn byte_wise(input: &[u8]) -> (Vec<u8>, usize) {
    let mut decoder = BodyDecoder::new(BodyKind::Chunked);
    let mut out = Vec::new();
    let mut total = 0;
    for (idx, byte) in input.iter().enumerate() {
      match decoder.feed(core::slice::from_ref(byte), &mut out).unwrap() {
        BodyStatus::NeedMore => {
          assert!(idx + 1 < input.len());
          total += 1;
        }
        BodyStatus::Complete { consumed } => {
          assert_eq!(idx + 1, input.len());
          total += consumed;
        }
      }
    }
    (out, total)
  }

  #[test]
  fn content_length_exact() {
    let mut decoder = BodyDecoder::new(BodyKind::ContentLength(2));
    let mut out = Vec::new();
    assert_eq!(decoder.feed(b"20", &mut out).unwrap(), BodyStatus::Complete { consumed: 2 });
    assert_eq!(out, b"20");
  }

  #[test]
  fn content_length_split() {
    let mut decoder = BodyDecoder::new(BodyKind::ContentLength(2));
    let mut out = Vec::new();
    assert_eq!(decoder.feed(b"2", &mut out).unwrap(), BodyStatus::NeedMore);
    assert_eq!(decoder.feed(b"0", &mut out).unwrap(), BodyStatus::Complete { consumed: 1 });
    assert_eq!(out, b"20");
  }

  #[test]
  fn content_length_leaves_pipelined_bytes() {
    let mut decoder = BodyDecoder::new(BodyKind::ContentLength(2));
    let mut out = Vec::new();
    assert_eq!(decoder.feed(b"20GET", &mut out).unwrap(), BodyStatus::Complete { consumed: 2 });
    assert_eq!(out, b"20");
  }

  #[test]
  fn empty_bodies_complete_at_once() {
    let mut out = Vec::new();
    let mut decoder = BodyDecoder::new(BodyKind::None);
    assert_eq!(decoder.feed(b"GET", &mut out).unwrap(), BodyStatus::Complete { consumed: 0 });
    let mut decoder = BodyDecoder::new(BodyKind::ContentLength(0));
    assert_eq!(decoder.feed(b"", &mut out).unwrap(), BodyStatus::Complete { consumed: 0 });
    assert!(out.is_empty());
  }

  #[test]
  fn chunked_single() {
    let mut decoder = BodyDecoder::new(BodyKind::Chunked);
    let mut out = Vec::new();
    let input = b"2\r\n20\r\n0\r\n\r\n";
    assert_eq!(
      decoder.feed(input, &mut out).unwrap(),
      BodyStatus::Complete { consumed: input.len() }
    );
    assert_eq!(out, b"20");
  }

  #[test]
  fn chunked_split_mid_size() {
    let (out, total) = byte_wise(b"a\r\n0123456789\r\n0\r\n\r\n");
    assert_eq!(out, b"0123456789");
    assert_eq!(total, 20);
  }

  #[test]
  fn chunked_split_mid_terminator() {
    let input = b"2\r\n20\r\n0\r\n\r\n";
    let (out, total) = byte_wise(input);
    assert_eq!(out, b"20");
    assert_eq!(total, input.len());
  }

  #[test]
  fn chunked_zero_only() {
    let mut decoder = BodyDecoder::new(BodyKind::Chunked);
    let mut out = Vec::new();
    assert_eq!(decoder.feed(b"0\r\n\r\n", &mut out).unwrap(), BodyStatus::Complete { consumed: 5 });
    assert!(out.is_empty());
  }

  #[test]
  fn chunked_multi_chunk_extension_trailer_and_pipelined() {
    let mut decoder = BodyDecoder::new(BodyKind::Chunked);
    let mut out = Vec::new();
    let input = b"3;ext=1\r\nabc\r\nA\r\n0123456789\r\n0\r\nX-T: v\r\n\r\nGET /";
    assert_eq!(
      decoder.feed(input, &mut out).unwrap(),
      BodyStatus::Complete { consumed: input.len() - 5 }
    );
    assert_eq!(out, b"abc0123456789");
  }

  #[test]
  fn rejects_bad_chunk_size() {
    let mut decoder = BodyDecoder::new(BodyKind::Chunked);
    assert!(decoder.feed(b"zz\r\n", &mut Vec::new()).is_err());
    let mut decoder = BodyDecoder::new(BodyKind::Chunked);
    assert!(decoder.feed(b"\r\n", &mut Vec::new()).is_err());
  }

  #[test]
  fn rejects_chunk_size_overflow() {
    let mut decoder = BodyDecoder::new(BodyKind::Chunked);
    assert!(decoder.feed(b"fffffffffffffffffffffffff\r\n", &mut Vec::new()).is_err());
  }

  #[test]
  fn rejects_missing_chunk_terminator() {
    let mut decoder = BodyDecoder::new(BodyKind::Chunked);
    assert!(decoder.feed(b"2\r\n20XX", &mut Vec::new()).is_err());
  }
}
