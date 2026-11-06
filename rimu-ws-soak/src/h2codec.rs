//! HTTP/2 for the harness, in raw bytes: frames written and read, an HPACK encoder of literals
//! only, and a decoder for the `:status` a server sends a client that allowed it no dynamic table
//! (static entries and literals, Huffman-coded or not).

use crate::conn::{Conn, ConnError};
use std::collections::HashMap;
use tokio::time::Instant;

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const DATA: u8 = 0;
pub const HEADERS: u8 = 1;
pub const PRIORITY: u8 = 2;
pub const RST_STREAM: u8 = 3;
pub const SETTINGS: u8 = 4;
pub const PING: u8 = 6;
pub const GOAWAY: u8 = 7;
pub const WINDOW_UPDATE: u8 = 8;
pub const CONTINUATION: u8 = 9;
pub const END_STREAM: u8 = 1;
pub const END_HEADERS: u8 = 4;
pub const ACK: u8 = 1;
/// The largest window a client may grant.
pub const MAX_WINDOW: u32 = 0x7FFF_FFFF;
/// The largest frame a client accepts.
const MAX_FRAME: usize = 16 << 20;

pub fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
  let len = u32::try_from(payload.len()).unwrap_or(u32::MAX).to_be_bytes();
  let mut out = Vec::with_capacity(9 + payload.len());
  out.extend_from_slice(&[len[1], len[2], len[3], ty, flags]);
  out.extend_from_slice(&(stream & MAX_WINDOW).to_be_bytes());
  out.extend_from_slice(payload);
  out
}

pub fn settings(pairs: &[(u16, u32)]) -> Vec<u8> {
  let mut payload = Vec::new();
  for (id, value) in pairs {
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(&value.to_be_bytes());
  }
  frame(SETTINGS, 0, 0, &payload)
}

/// The preface and SETTINGS of a client that allows no HPACK dynamic table, no push, and windows
/// so large it never has to update them; `initial_window` overrides the streams' window.
pub fn opening(initial_window: Option<u32>) -> Vec<u8> {
  let mut out = PREFACE.to_vec();
  out.extend(settings(&[(1, 0), (2, 0), (4, initial_window.unwrap_or(MAX_WINDOW))]));
  out.extend(frame(WINDOW_UPDATE, 0, 0, &(MAX_WINDOW - 65_535).to_be_bytes()));
  out
}

/// A request header block, every field a literal without indexing.
pub fn header_block(method: &str, path: &str, extra: &[(&str, &str)]) -> Vec<u8> {
  let mut block = Vec::new();
  let fields = [(":method", method), (":scheme", "http"), (":path", path), (":authority", "soak")];
  for (name, value) in fields.into_iter().chain(extra.iter().copied()) {
    block.push(0);
    string(&mut block, name.as_bytes());
    string(&mut block, value.as_bytes());
  }
  block
}

/// HEADERS (END_HEADERS) for a request.
pub fn request(
  stream: u32,
  method: &str,
  path: &str,
  extra: &[(&str, &str)],
  end: bool,
) -> Vec<u8> {
  let flags = END_HEADERS | if end { END_STREAM } else { 0 };
  frame(HEADERS, flags, stream, &header_block(method, path, extra))
}

fn string(block: &mut Vec<u8>, bytes: &[u8]) {
  integer(block, 0, 7, bytes.len());
  block.extend_from_slice(bytes);
}

fn integer(block: &mut Vec<u8>, first: u8, prefix: u32, mut n: usize) {
  let max = (1usize << prefix) - 1;
  if n < max {
    block.push(first | n as u8);
    return;
  }
  block.push(first | max as u8);
  n -= max;
  while n >= 128 {
    block.push((n % 128) as u8 | 0x80);
    n /= 128;
  }
  block.push(n as u8);
}

/// One received frame.
#[derive(Clone, Debug)]
pub struct Frame {
  pub ty: u8,
  pub flags: u8,
  pub stream: u32,
  pub payload: Vec<u8>,
}

/// Takes the first whole frame off `buf`. An oversized length is the server's fault.
fn parse(buf: &mut Vec<u8>) -> Result<Option<Frame>, ConnError> {
  let Some(head) = buf.get(..9) else {
    return Ok(None);
  };
  let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
  if len > MAX_FRAME {
    return Err(ConnError::Server(crate::conn::Failure(format!("a {len}-byte frame"))));
  }
  if buf.len() < 9 + len {
    return Ok(None);
  }
  let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & MAX_WINDOW;
  let frame = Frame { ty: head[3], flags: head[4], stream, payload: buf[9..9 + len].to_vec() };
  let _ = buf.drain(..9 + len);
  Ok(Some(frame))
}

/// `(code, last stream id)` of a GOAWAY.
pub fn go_away(frame: &Frame) -> Option<(u32, u32)> {
  let p = frame.payload.get(..8)?;
  let last = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & MAX_WINDOW;
  Some((u32::from_be_bytes([p[4], p[5], p[6], p[7]]), last))
}

/// The error code of a RST_STREAM.
pub fn reset_code(frame: &Frame) -> Option<u32> {
  frame.payload.get(..4).map(|p| u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
}

/// The `:status` of a response header block that uses no dynamic table.
pub fn status(mut block: &[u8]) -> Option<u16> {
  // Dynamic table size updates come first.
  while let Some(&byte) = block.first() {
    if byte & 0xE0 != 0x20 {
      break;
    }
    let (_, rest) = read_integer(block, 5)?;
    block = rest;
  }
  let &first = block.first()?;
  if first & 0x80 != 0 {
    let (idx, _) = read_integer(block, 7)?;
    return match idx {
      8 => Some(200),
      9 => Some(204),
      10 => Some(206),
      11 => Some(304),
      12 => Some(400),
      13 => Some(404),
      14 => Some(500),
      _ => None,
    };
  }
  // A literal whose name is static index 8 (`:status`): incremental indexing, or not, or never.
  let (idx, rest) =
    if first & 0xC0 == 0x40 { read_integer(block, 6)? } else { read_integer(block, 4)? };
  if !(8..=14).contains(&idx) {
    return None;
  }
  let &len_byte = rest.first()?;
  let (len, rest) = read_integer(rest, 7)?;
  let value = rest.get(..len)?;
  let text = if len_byte & 0x80 != 0 {
    huffman_digits(value)?
  } else {
    String::from_utf8(value.to_vec()).ok()?
  };
  text.parse().ok()
}

fn read_integer(block: &[u8], prefix: u32) -> Option<(usize, &[u8])> {
  let max = (1usize << prefix) - 1;
  let (&first, mut rest) = block.split_first()?;
  let mut n = usize::from(first) & max;
  if n < max {
    return Some((n, rest));
  }
  let mut shift = 0;
  loop {
    let (&byte, after) = rest.split_first()?;
    rest = after;
    n += (usize::from(byte) & 0x7F) << shift;
    shift += 7;
    if byte & 0x80 == 0 || shift > 28 {
      return Some((n, rest));
    }
  }
}

/// Huffman decoding of digits only (RFC 7541 Appendix B): what a status code needs.
fn huffman_digits(bytes: &[u8]) -> Option<String> {
  let mut out = String::new();
  let (mut code, mut bits) = (0u32, 0u32);
  for byte in bytes {
    for shift in (0..8).rev() {
      code = code << 1 | u32::from(byte >> shift & 1);
      bits += 1;
      let digit = match (bits, code) {
        (5, 0..=2) => Some(b'0' + code as u8),
        (6, 0x19..=0x1F) => Some(b'3' + (code - 0x19) as u8),
        _ => None,
      };
      if let Some(digit) = digit {
        out.push(char::from(digit));
        code = 0;
        bits = 0;
      } else if bits >= 6 && code != (1 << bits) - 1 {
        // Not a digit, and not the all-ones padding either.
        return None;
      }
    }
  }
  // What is left must be padding: fewer than 8 bits, all ones.
  (bits < 8 && code == (1 << bits) - 1).then_some(out)
}

/// A response as the client saw it.
#[derive(Clone, Debug, Default)]
pub struct Response {
  pub status: Option<u16>,
  pub body: Vec<u8>,
  pub ended: bool,
  pub reset: Option<u32>,
}

/// What reading responses produced.
#[derive(Debug, Default)]
pub struct Collected {
  pub responses: HashMap<u32, Response>,
  /// `(code, last stream id)`.
  pub go_away: Option<(u32, u32)>,
  pub eof: bool,
}

impl Collected {
  /// Every stream of `ids` ended or was reset.
  pub fn has_all(&self, ids: &[u32]) -> bool {
    ids.iter().all(|id| self.responses.get(id).is_some_and(|el| el.ended || el.reset.is_some()))
  }
}

/// A client connection speaking HTTP/2.
#[derive(Debug)]
pub struct H2 {
  pub conn: Conn,
  buf: Vec<u8>,
}

impl H2 {
  /// Sends the opening on `conn`.
  pub async fn open(mut conn: Conn, initial_window: Option<u32>) -> Result<H2, ConnError> {
    conn.send(&opening(initial_window)).await?;
    Ok(H2 { conn, buf: Vec::new() })
  }

  /// The next frame, `None` at EOF. SETTINGS are acknowledged and PINGs answered on the way.
  pub async fn next(&mut self, deadline: Instant) -> Result<Option<Frame>, ConnError> {
    loop {
      if let Some(frame) = parse(&mut self.buf)? {
        if frame.ty == SETTINGS && frame.flags & ACK == 0 {
          self.conn.send(&frame_ack(SETTINGS, &[])).await?;
        } else if frame.ty == PING && frame.flags & ACK == 0 {
          self.conn.send(&frame_ack(PING, &frame.payload)).await?;
        }
        return Ok(Some(frame));
      }
      if self.conn.read_some(&mut self.buf, deadline).await? == 0 {
        return Ok(None);
      }
    }
  }

  /// Reads at most `n` more bytes into the frame buffer: a slow reader's read.
  pub async fn read_at_most(&mut self, n: usize, deadline: Instant) -> Result<usize, ConnError> {
    let mut chunk = vec![0; n];
    match tokio::time::timeout_at(
      deadline,
      tokio::io::AsyncReadExt::read(self.conn.raw(), &mut chunk),
    )
    .await
    {
      Err(_) => Ok(0),
      Ok(Ok(len)) => {
        self.buf.extend_from_slice(&chunk[..len]);
        Ok(len)
      }
      Ok(Err(err)) => Err(ConnError::Server(crate::conn::Failure(format!("read: {err}")))),
    }
  }

  /// The whole frames read so far, without reading more.
  pub fn buffered_frames(&mut self) -> Result<Vec<Frame>, ConnError> {
    let mut out = Vec::new();
    while let Some(frame) = parse(&mut self.buf)? {
      out.push(frame);
    }
    Ok(out)
  }

  /// Reads until every stream of `ids` ended or was reset, GOAWAY ends the hope of that, or EOF.
  pub async fn collect(&mut self, ids: &[u32], deadline: Instant) -> Result<Collected, ConnError> {
    let mut out = Collected::default();
    let mut blocks: HashMap<u32, Vec<u8>> = HashMap::new();
    while !out.has_all(ids) {
      let Some(frame) = self.next(deadline).await? else {
        out.eof = true;
        return Ok(out);
      };
      let response = out.responses.entry(frame.stream).or_default();
      match frame.ty {
        HEADERS | CONTINUATION => {
          let block = blocks.entry(frame.stream).or_default();
          block.extend_from_slice(&frame.payload);
          if frame.flags & END_HEADERS != 0 {
            if response.status.is_none() {
              response.status = status(block);
            }
            block.clear();
          }
          if frame.ty == HEADERS && frame.flags & END_STREAM != 0 {
            response.ended = true;
          }
        }
        DATA => {
          response.body.extend_from_slice(&frame.payload);
          if frame.flags & END_STREAM != 0 {
            response.ended = true;
          }
        }
        RST_STREAM => response.reset = reset_code(&frame),
        GOAWAY => {
          out.go_away = go_away(&frame);
          // Streams above the last one processed will get nothing.
          if out.go_away.is_some_and(|el| ids.iter().all(|id| *id > el.1 || out.has_all(&[*id]))) {
            return Ok(out);
          }
        }
        _ => {}
      }
    }
    Ok(out)
  }
}

fn frame_ack(ty: u8, payload: &[u8]) -> Vec<u8> {
  frame(ty, ACK, 0, payload)
}

#[cfg(test)]
mod tests {
  use super::{huffman_digits, status};

  #[test]
  fn status_forms() {
    assert_eq!(status(&[0x88]), Some(200));
    assert_eq!(status(&[0x3f, 0xe1, 0x1f, 0x8d]), Some(404));
    // Literal, name index 8, value "413" raw and Huffman-coded (011010 00001 011001, padded).
    assert_eq!(status(&[0x08, 3, b'4', b'1', b'3']), Some(413));
    assert_eq!(status(&[0x48, 0x83, 0x68, 0x2c, 0xff]), Some(413));
    assert_eq!(huffman_digits(&[0x10, 0x01]).as_deref(), Some("200"));
    assert_eq!(huffman_digits(&[0x10, 0x00]), None);
  }
}
