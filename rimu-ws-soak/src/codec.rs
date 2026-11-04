//! Client frames with any header, server frames parsed incrementally, and the upgrade handshake.

/// How the payload length is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LenForm {
  /// The shortest form that fits.
  Minimal,
  /// The 16-bit extended form, even if the length fits in 7 bits.
  Ext16,
  /// The 64-bit extended form, even if the length fits in fewer.
  Ext64,
}

/// A frame to encode, valid or not.
#[derive(Clone, Copy, Debug)]
pub struct FrameSpec<'a> {
  pub fin: bool,
  /// RSV1..3 as the 3 low bits (RSV1 = 4).
  pub rsv: u8,
  pub opcode: u8,
  /// `None` sends the payload unmasked.
  pub mask: Option<[u8; 4]>,
  pub payload: &'a [u8],
  /// Written as the length instead of `payload.len()`; only `payload` is sent.
  pub declared_len: Option<u64>,
  pub len_form: LenForm,
}

/// Appends the encoded frame to `out`.
pub fn encode(spec: &FrameSpec<'_>, out: &mut Vec<u8>) {
  out.push(if spec.fin { 0x80 } else { 0 } | (spec.rsv & 7) << 4 | spec.opcode & 0xF);
  let mask_bit = if spec.mask.is_some() { 0x80 } else { 0 };
  let len = spec.declared_len.unwrap_or(spec.payload.len() as u64);
  let form = match spec.len_form {
    LenForm::Minimal if len < 126 => None,
    LenForm::Minimal if len <= 0xFFFF => Some(LenForm::Ext16),
    LenForm::Minimal => Some(LenForm::Ext64),
    other => Some(other),
  };
  match form {
    None => out.push(mask_bit | len as u8),
    Some(LenForm::Ext16) => {
      out.push(mask_bit | 126);
      out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    Some(_) => {
      out.push(mask_bit | 127);
      out.extend_from_slice(&len.to_be_bytes());
    }
  }
  match spec.mask {
    Some(mask) => {
      out.extend_from_slice(&mask);
      out.extend(spec.payload.iter().enumerate().map(|(idx, el)| el ^ mask[idx % 4]));
    }
    None => out.extend_from_slice(spec.payload),
  }
}

/// A final, masked frame with the minimal length encoding.
pub fn client_frame(fin: bool, opcode: u8, payload: &[u8], mask: [u8; 4], out: &mut Vec<u8>) {
  let spec = FrameSpec {
    fin,
    rsv: 0,
    opcode,
    mask: Some(mask),
    payload,
    declared_len: None,
    len_form: LenForm::Minimal,
  };
  encode(&spec, out);
}

/// A frame received from the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerFrame {
  pub fin: bool,
  pub rsv: u8,
  pub opcode: u8,
  pub payload: Vec<u8>,
}

/// What a server sent that a client can't accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
  MaskedServerFrame,
  TooLong(u64),
  BadResponse(&'static str),
}

/// Server frames from bytes pushed in any pieces.
#[derive(Debug)]
pub struct Parser {
  buf: Vec<u8>,
  max_len: usize,
  off: usize,
}

impl Parser {
  pub fn new(max_len: usize) -> Self {
    Self { buf: Vec::new(), max_len, off: 0 }
  }

  pub fn push(&mut self, bytes: &[u8]) {
    if self.off > 0 && self.off * 2 >= self.buf.len() {
      let _ = self.buf.drain(..self.off);
      self.off = 0;
    }
    self.buf.extend_from_slice(bytes);
  }

  /// The next whole frame, `None` until its bytes are in.
  pub fn next_frame(&mut self) -> Result<Option<ServerFrame>, ParseError> {
    let avail = &self.buf[self.off..];
    let [b0, b1, ..] = *avail else {
      return Ok(None);
    };
    if b1 & 0x80 != 0 {
      return Err(ParseError::MaskedServerFrame);
    }
    let (len, header) = match b1 & 0x7F {
      126 => match avail.get(2..4) {
        Some(el) => (u64::from(u16::from_be_bytes([el[0], el[1]])), 4),
        None => return Ok(None),
      },
      127 => match avail.get(2..10) {
        Some(el) => (u64::from_be_bytes(el.try_into().unwrap_or_default()), 10),
        None => return Ok(None),
      },
      short => (u64::from(short), 2),
    };
    if len > self.max_len as u64 {
      return Err(ParseError::TooLong(len));
    }
    let end = header + len as usize;
    let Some(payload) = avail.get(header..end) else {
      return Ok(None);
    };
    let frame = ServerFrame {
      fin: b0 & 0x80 != 0,
      rsv: b0 >> 4 & 7,
      opcode: b0 & 0xF,
      payload: payload.to_vec(),
    };
    self.off += end;
    Ok(Some(frame))
  }
}

/// The status code of a close frame, if it carries one.
pub fn close_code(frame: &ServerFrame) -> Option<u16> {
  let [hi, lo, ..] = *frame.payload.as_slice() else {
    return None;
  };
  Some(u16::from_be_bytes([hi, lo]))
}

/// An HTTP/1.1 upgrade request.
pub fn upgrade_request(host: &str, path: &str, key: &str) -> Vec<u8> {
  format!(
    "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
  )
  .into_bytes()
}

/// The `Sec-WebSocket-Accept` a server must answer `key` with.
pub fn accept_key(key: &str) -> String {
  use base64::Engine as _;
  let mut sha = sha1_smol::Sha1::new();
  sha.update(key.as_bytes());
  sha.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  base64::engine::general_purpose::STANDARD.encode(sha.digest().bytes())
}

/// The head of the server's answer to an upgrade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeResponse {
  /// Bytes up to and including the blank line.
  pub header_len: usize,
  pub status: u16,
  pub accept: Option<String>,
}

/// `Ok(None)` until the header's blank line has arrived.
pub fn parse_upgrade_response(buf: &[u8]) -> Result<Option<UpgradeResponse>, ParseError> {
  let Some(end) = buf.windows(4).position(|el| el == b"\r\n\r\n") else {
    return Ok(None);
  };
  let head = core::str::from_utf8(&buf[..end]).map_err(|_| ParseError::BadResponse("not UTF-8"))?;
  let mut lines = head.split("\r\n");
  let status = lines
    .next()
    .and_then(|el| el.strip_prefix("HTTP/1.1 "))
    .and_then(|el| el.get(..3))
    .and_then(|el| el.parse().ok())
    .ok_or(ParseError::BadResponse("status line"))?;
  let accept = lines.find_map(|line| {
    let (name, value) = line.split_once(':')?;
    name.trim().eq_ignore_ascii_case("sec-websocket-accept").then(|| value.trim().to_owned())
  });
  Ok(Some(UpgradeResponse { header_len: end + 4, status, accept }))
}

#[cfg(test)]
mod tests {
  use super::*;

  const MASK: [u8; 4] = [1, 2, 3, 4];

  fn spec(payload: &[u8]) -> FrameSpec<'_> {
    FrameSpec {
      fin: true,
      rsv: 0,
      opcode: 2,
      mask: Some(MASK),
      payload,
      declared_len: None,
      len_form: LenForm::Minimal,
    }
  }

  fn server(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode(&FrameSpec { mask: None, opcode, ..spec(payload) }, &mut out);
    out
  }

  #[test]
  fn accept_key_matches_rfc_example() {
    assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
  }

  #[test]
  fn encode_masks_and_picks_minimal_length() {
    for (len, header) in [(0, 6), (125, 6), (126, 8), (65535, 8), (65536, 14)] {
      let payload: Vec<u8> = (0..len).map(|el| el as u8).collect();
      let mut out = Vec::new();
      encode(&spec(&payload), &mut out);
      assert_eq!(out.len(), header + len, "len {len}");
      assert_eq!(out[1] & 0x80, 0x80);
      let unmasked: Vec<u8> =
        out[header..].iter().enumerate().map(|(idx, el)| el ^ MASK[idx % 4]).collect();
      assert_eq!(unmasked, payload);
    }
  }

  #[test]
  fn encode_forced_forms_and_declared_len() {
    let mut out = Vec::new();
    encode(&FrameSpec { len_form: LenForm::Ext64, ..spec(b"hello") }, &mut out);
    assert_eq!(out[1], 0x80 | 127);
    assert_eq!(u64::from_be_bytes(out[2..10].try_into().unwrap()), 5);
    assert_eq!(out.len(), 2 + 8 + 4 + 5);
    let mut out = Vec::new();
    encode(&FrameSpec { declared_len: Some(u64::MAX >> 1), ..spec(b"ab") }, &mut out);
    assert_eq!(out[1], 0x80 | 127);
    assert_eq!(u64::from_be_bytes(out[2..10].try_into().unwrap()), u64::MAX >> 1);
    assert_eq!(out.len(), 2 + 8 + 4 + 2);
  }

  #[test]
  fn parser_reassembles_byte_by_byte() {
    let big: Vec<u8> = (0..70_000u32).map(|el| el as u8).collect();
    let mut bytes = server(1, b"abc");
    bytes.extend(server(2, &big));
    bytes.extend(server(8, &1000u16.to_be_bytes()));
    let mut parser = Parser::new(1 << 20);
    let mut frames = Vec::new();
    for byte in bytes {
      parser.push(&[byte]);
      while let Some(frame) = parser.next_frame().unwrap() {
        frames.push(frame);
      }
    }
    assert_eq!(frames.len(), 3);
    assert_eq!((frames[0].opcode, frames[0].payload.as_slice()), (1, &b"abc"[..]));
    assert_eq!((frames[1].opcode, &frames[1].payload), (2, &big));
    assert_eq!(close_code(&frames[2]), Some(1000));
    assert_eq!(parser.next_frame().unwrap(), None);
  }

  #[test]
  fn parser_rejects_masked_and_too_long() {
    let mut parser = Parser::new(100);
    let mut masked = Vec::new();
    encode(&spec(b"x"), &mut masked);
    parser.push(&masked);
    assert_eq!(parser.next_frame(), Err(ParseError::MaskedServerFrame));
    let mut parser = Parser::new(100);
    let mut long = Vec::new();
    encode(&FrameSpec { mask: None, declared_len: Some(101), ..spec(&[]) }, &mut long);
    parser.push(&long);
    assert_eq!(parser.next_frame(), Err(ParseError::TooLong(101)));
  }

  #[test]
  fn close_code_reads_first_two_bytes() {
    let frame = ServerFrame { fin: true, rsv: 0, opcode: 8, payload: vec![0x03, 0xE8, b'x'] };
    assert_eq!(close_code(&frame), Some(1000));
    assert_eq!(close_code(&ServerFrame { payload: vec![], ..frame }), None);
  }

  #[test]
  fn upgrade_response_partial_then_complete() {
    let head = b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: abc\r\n";
    assert_eq!(parse_upgrade_response(head), Ok(None));
    let mut full = head.to_vec();
    full.extend_from_slice(b"\r\n");
    let res = parse_upgrade_response(&full).unwrap().unwrap();
    assert_eq!(res.status, 101);
    assert_eq!(res.accept.as_deref(), Some("abc"));
    assert_eq!(res.header_len, full.len());
  }

  #[test]
  fn upgrade_request_carries_key_and_path() {
    let req = String::from_utf8(upgrade_request("h", "/p", "k")).unwrap();
    assert!(req.starts_with("GET /p HTTP/1.1\r\n"));
    assert!(req.contains("\r\nSec-WebSocket-Key: k\r\n"));
    assert!(req.ends_with("\r\n\r\n"));
  }
}
