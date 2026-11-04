//! An in-process WebSocket echo server with fault knobs, to show that each oracle passes a correct
//! server and fails a broken one.

#![allow(dead_code, reason = "each test binary uses part of it")]

use rimu_ws_soak::codec::{FrameSpec, LenForm, accept_key, encode};
use std::{
  net::SocketAddr,
  sync::{Arc, Mutex},
  time::Duration,
};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::{TcpListener, TcpStream},
  time::{Instant, timeout_at},
};

/// What the fake server gets wrong. `Default` is a correct server.
#[derive(Clone, Debug)]
pub struct Faults {
  pub corrupt_echo: bool,
  pub close_mid_echo_after: Option<usize>,
  pub idle_timeout: Option<Duration>,
  pub handshake_timeout: Option<Duration>,
  pub close_code_for_protocol_errors: u16,
  pub close_code_for_bad_utf8: u16,
  /// Every byte each connection sent, one entry per connection in accept order.
  pub log: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
  /// After the upgrade, reads everything into memory and never answers.
  pub unbounded_reads: bool,
  /// The largest message, and the code a longer declared length is refused with.
  pub max_payload: u64,
  pub huge_len_code: u16,
  /// How long each echo of a data message is held back.
  pub echo_delay: Option<Duration>,
  /// Upgrade request bytes read before refusing it with 431; `None` reads without bound.
  pub header_cap: Option<usize>,
  /// Upgrades any request with a key, as RFC 6455 says not to.
  pub lax_upgrade: bool,
}

impl Default for Faults {
  fn default() -> Self {
    Self {
      corrupt_echo: false,
      close_mid_echo_after: None,
      idle_timeout: None,
      handshake_timeout: None,
      close_code_for_protocol_errors: 1002,
      close_code_for_bad_utf8: 1007,
      log: None,
      unbounded_reads: false,
      max_payload: 1 << 20,
      huge_len_code: 1009,
      echo_delay: None,
      header_cap: Some(16 * 1024),
      lax_upgrade: false,
    }
  }
}

pub async fn spawn_fake(faults: Faults) -> SocketAddr {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let _task = tokio::spawn(async move {
    loop {
      let Ok((stream, _)) = listener.accept().await else { return };
      let _conn = tokio::spawn(serve(stream, faults.clone()));
    }
  });
  addr
}

struct Peer {
  buf: Vec<u8>,
  // Where the unparsed bytes of `buf` start
  pos: usize,
  faults: Faults,
  // Index of this connection's entry in `faults.log`
  log_idx: usize,
  stream: TcpStream,
}

impl Peer {
  /// More bytes, or `false` on EOF, error or a timeout.
  async fn fill(&mut self, deadline: Option<Instant>) -> bool {
    let mut chunk = vec![0; 16384];
    let read = self.stream.read(&mut chunk);
    let rslt = match deadline {
      Some(el) => match timeout_at(el, read).await {
        Ok(el) => el,
        Err(_) => return false,
      },
      None => read.await,
    };
    match rslt {
      Ok(0) | Err(_) => false,
      Ok(len) => {
        if self.pos > 0 {
          let _ = self.buf.drain(..self.pos);
          self.pos = 0;
        }
        self.buf.extend_from_slice(&chunk[..len]);
        if let Some(log) = &self.faults.log {
          log.lock().unwrap()[self.log_idx].extend_from_slice(&chunk[..len]);
        }
        true
      }
    }
  }

  async fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> bool {
    let mut out = Vec::new();
    let spec = FrameSpec {
      fin: true,
      rsv: 0,
      opcode,
      mask: None,
      payload,
      declared_len: None,
      len_form: LenForm::Minimal,
    };
    encode(&spec, &mut out);
    self.stream.write_all(&out).await.is_ok()
  }

  async fn close(&mut self, code: u16) {
    let _ = self.send_frame(8, &code.to_be_bytes()).await;
    let _ = self.stream.shutdown().await;
  }
}

/// A client frame parsed from the front of `buf`: (fin, rsv, opcode, masked, payload, consumed).
struct ClientFrame {
  fin: bool,
  rsv: u8,
  opcode: u8,
  masked: bool,
  declared: u64,
  payload: Vec<u8>,
}

enum Parsed {
  Frame(ClientFrame, usize),
  Partial { declared: Option<u64> },
}

fn parse(buf: &[u8]) -> Parsed {
  let [b0, b1, ..] = *buf else { return Parsed::Partial { declared: None } };
  let (declared, mut at) = match b1 & 0x7F {
    126 => match buf.get(2..4) {
      Some(el) => (u64::from(u16::from_be_bytes([el[0], el[1]])), 4),
      None => return Parsed::Partial { declared: None },
    },
    127 => match buf.get(2..10) {
      Some(el) => (u64::from_be_bytes(el.try_into().unwrap()), 10),
      None => return Parsed::Partial { declared: None },
    },
    short => (u64::from(short), 2),
  };
  let masked = b1 & 0x80 != 0;
  let mut mask = [0; 4];
  if masked {
    let Some(el) = buf.get(at..at + 4) else { return Parsed::Partial { declared: Some(declared) } };
    mask.copy_from_slice(el);
    at += 4;
  }
  let Some(raw) = usize::try_from(declared).ok().and_then(|len| buf.get(at..at.checked_add(len)?))
  else {
    return Parsed::Partial { declared: Some(declared) };
  };
  let payload = raw.iter().enumerate().map(|(idx, el)| el ^ mask[idx % 4]).collect();
  let frame = ClientFrame {
    fin: b0 & 0x80 != 0,
    rsv: b0 >> 4 & 7,
    opcode: b0 & 0xF,
    masked,
    declared,
    payload,
  };
  Parsed::Frame(frame, at + raw.len())
}

async fn serve(stream: TcpStream, faults: Faults) {
  let log_idx = faults.log.as_ref().map_or(0, |log| {
    let mut log = log.lock().unwrap();
    log.push(Vec::new());
    log.len() - 1
  });
  let mut peer = Peer { buf: Vec::new(), pos: 0, faults, log_idx, stream };
  let handshake_deadline = peer.faults.handshake_timeout.map(|el| Instant::now() + el);
  let end = loop {
    let crlf = peer.buf.windows(4).position(|el| el == b"\r\n\r\n").map(|el| el + 4);
    let lf = peer.buf.windows(2).position(|el| el == b"\n\n").map(|el| el + 2);
    if let Some(end) = crlf.into_iter().chain(lf).min() {
      break end;
    }
    if peer.faults.header_cap.is_some_and(|el| peer.buf.len() > el) {
      let _ = peer.stream.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n").await;
      return;
    }
    let deadline = earliest(handshake_deadline, peer.faults.idle_timeout);
    if !peer.fill(deadline).await {
      return;
    }
  };
  let head = String::from_utf8_lossy(&peer.buf[..end]).into_owned();
  let _ = peer.buf.drain(..end);
  let Some(key) = upgrade_key(&head, peer.faults.lax_upgrade) else {
    let _ = peer.stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
    return;
  };
  let res = format!(
    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
    accept_key(&key)
  );
  if peer.stream.write_all(res.as_bytes()).await.is_err() {
    return;
  }
  if peer.faults.unbounded_reads {
    while peer.fill(None).await {}
    return;
  }
  echo(&mut peer).await;
}

/// The key of a request RFC 6455 lets a server upgrade; with `lax`, of any request with a key.
fn upgrade_key(head: &str, lax: bool) -> Option<String> {
  let mut lines = head.split('\n').map(|el| el.strip_suffix('\r').unwrap_or(el));
  let request_line = lines.next()?;
  let mut headers = Vec::new();
  for line in lines.filter(|el| !el.is_empty()) {
    if line.starts_with([' ', '\t']) {
      return None;
    }
    let (name, value) = line.split_once(':')?;
    headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
  }
  let values = |name: &str| -> Vec<String> {
    headers.iter().filter(|el| el.0 == name).map(|el| el.1.clone()).collect()
  };
  let keys = values("sec-websocket-key");
  if lax {
    return keys.first().cloned();
  }
  let has_token = |name: &str, token: &str| {
    values(name).iter().any(|el| el.split(',').any(|el| el.trim().eq_ignore_ascii_case(token)))
  };
  let decoded_len = |key: &str| {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(key).map(|el| el.len()).ok()
  };
  let valid = request_line.starts_with("GET ")
    && request_line.ends_with(" HTTP/1.1")
    && has_token("upgrade", "websocket")
    && has_token("connection", "upgrade")
    && values("sec-websocket-version") == ["13"]
    && keys.len() == 1
    && decoded_len(&keys[0]) == Some(16);
  valid.then(|| keys[0].clone())
}

fn earliest(deadline: Option<Instant>, idle: Option<Duration>) -> Option<Instant> {
  let idle = idle.map(|el| Instant::now() + el);
  match (deadline, idle) {
    (Some(a), Some(b)) => Some(a.min(b)),
    (a, b) => a.or(b),
  }
}

async fn echo(peer: &mut Peer) {
  let protocol = peer.faults.close_code_for_protocol_errors;
  let mut message: Option<(u8, Vec<u8>)> = None;
  let mut echoed = 0;
  loop {
    let (frame, used) = match parse(&peer.buf[peer.pos..]) {
      Parsed::Frame(frame, used) => (frame, used),
      Parsed::Partial { declared } => {
        if declared.is_some_and(|el| el > peer.faults.max_payload) {
          return peer.close(peer.faults.huge_len_code).await;
        }
        if !peer.fill(earliest(None, peer.faults.idle_timeout)).await {
          return;
        }
        continue;
      }
    };
    peer.pos += used;
    if frame.declared > peer.faults.max_payload {
      return peer.close(peer.faults.huge_len_code).await;
    }
    if !frame.masked || frame.rsv != 0 {
      return peer.close(protocol).await;
    }
    if frame.opcode >= 8 && (!frame.fin || frame.payload.len() > 125) {
      return peer.close(protocol).await;
    }
    match frame.opcode {
      8 => {
        let code = match frame.payload.len() {
          0 => 1000,
          1 => return peer.close(protocol).await,
          _ => u16::from_be_bytes([frame.payload[0], frame.payload[1]]),
        };
        let valid = matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999);
        return peer.close(if valid { code } else { protocol }).await;
      }
      9 => {
        if !peer.send_frame(10, &frame.payload).await {
          return;
        }
        continue;
      }
      10 => continue,
      0 => match &mut message {
        Some((_, data)) => {
          data.extend_from_slice(&frame.payload);
          if data.len() as u64 > peer.faults.max_payload {
            return peer.close(peer.faults.huge_len_code).await;
          }
        }
        None => return peer.close(protocol).await,
      },
      1 | 2 => {
        if message.is_some() {
          return peer.close(protocol).await;
        }
        message = Some((frame.opcode, frame.payload));
      }
      _ => return peer.close(protocol).await,
    }
    if !frame.fin {
      continue;
    }
    let Some((opcode, mut data)) = message.take() else { continue };
    if opcode == 1 && core::str::from_utf8(&data).is_err() {
      return peer.close(peer.faults.close_code_for_bad_utf8).await;
    }
    if peer.faults.close_mid_echo_after == Some(echoed) {
      return;
    }
    if let Some(delay) = peer.faults.echo_delay {
      tokio::time::sleep(delay).await;
    }
    if peer.faults.corrupt_echo && !data.is_empty() {
      data[0] ^= 0xFF;
    }
    if !peer.send_frame(opcode, &data).await {
      return;
    }
    echoed += 1;
  }
}
