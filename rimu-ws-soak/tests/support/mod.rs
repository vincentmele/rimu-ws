//! An in-process WebSocket echo server with fault knobs, to show that each oracle passes a correct
//! server and fails a broken one.

#![allow(dead_code, reason = "each test binary uses part of it")]

use rimu_ws_soak::codec::{FrameSpec, LenForm, accept_key, encode};
use std::{net::SocketAddr, time::Duration};
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
  faults: Faults,
  stream: TcpStream,
}

impl Peer {
  /// More bytes, or `false` on EOF, error or a timeout.
  async fn fill(&mut self, deadline: Option<Instant>) -> bool {
    let mut chunk = [0; 16384];
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
        self.buf.extend_from_slice(&chunk[..len]);
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
  let mut peer = Peer { buf: Vec::new(), faults, stream };
  let handshake_deadline = peer.faults.handshake_timeout.map(|el| Instant::now() + el);
  let end = loop {
    if let Some(end) = peer.buf.windows(4).position(|el| el == b"\r\n\r\n") {
      break end + 4;
    }
    let deadline = earliest(handshake_deadline, peer.faults.idle_timeout);
    if !peer.fill(deadline).await {
      return;
    }
  };
  let head = String::from_utf8_lossy(&peer.buf[..end]).into_owned();
  let _ = peer.buf.drain(..end);
  let Some(key) = head.split("\r\n").find_map(|line| {
    let (name, value) = line.split_once(':')?;
    name.trim().eq_ignore_ascii_case("sec-websocket-key").then(|| value.trim().to_owned())
  }) else {
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
  echo(&mut peer).await;
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
    let (frame, used) = match parse(&peer.buf) {
      Parsed::Frame(frame, used) => (frame, used),
      Parsed::Partial { .. } => {
        if !peer.fill(earliest(None, peer.faults.idle_timeout)).await {
          return;
        }
        continue;
      }
    };
    let _ = peer.buf.drain(..used);
    let _ = (frame.rsv, frame.declared);
    if !frame.masked {
      return peer.close(protocol).await;
    }
    match frame.opcode {
      8 => {
        let code = frame.payload.get(..2).map_or(1000, |el| u16::from_be_bytes([el[0], el[1]]));
        return peer.close(code).await;
      }
      9 => {
        if !peer.send_frame(10, &frame.payload).await {
          return;
        }
        continue;
      }
      10 => continue,
      0 => match &mut message {
        Some((_, data)) => data.extend_from_slice(&frame.payload),
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
    if peer.faults.corrupt_echo && !data.is_empty() {
      data[0] ^= 0xFF;
    }
    if !peer.send_frame(opcode, &data).await {
      return;
    }
    echoed += 1;
  }
}
