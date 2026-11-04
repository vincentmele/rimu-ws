//! A client connection that records what it sends and receives, and the reads scenarios check
//! the server with.

use crate::{
  codec::{Parser, ServerFrame, accept_key, close_code, parse_upgrade_response, upgrade_request},
  rng::Rng,
};
use std::{
  collections::VecDeque,
  fmt::Write as _,
  io,
  net::{IpAddr, SocketAddr},
  time::Duration,
};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::{TcpSocket, TcpStream},
  time::{Instant, timeout_at},
};

/// The largest server frame a client accepts.
const MAX_FRAME: usize = 64 << 20;
/// Events a transcript keeps, and bytes of each.
const TRANSCRIPT_EVENTS: usize = 64;
const TRANSCRIPT_BYTES: usize = 64;
/// How long an upgrade may take.
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(10);

/// Socket options of a client connection.
#[derive(Clone, Debug, Default)]
pub struct ConnOpts {
  pub rcvbuf: Option<u32>,
  pub nodelay: bool,
  pub source_ip: Option<IpAddr>,
}

/// What a read produced.
#[derive(Debug)]
pub enum Next {
  Frame(ServerFrame),
  Eof,
}

/// Whether `Conn::exchange` wants more frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
  More,
  Done,
}

/// How `Conn::exchange` ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exchange {
  /// The frame callback had what it wanted.
  Done,
  /// The server closed (or reset) first.
  Eof,
}

/// Something the server did wrong.
#[derive(Debug)]
pub struct Failure(pub String);

/// Why a connection operation failed.
#[derive(Debug)]
pub enum ConnError {
  /// The client ran out of something (ports, descriptors, buffers): not the server's fault.
  Harness(String),
  Server(Failure),
}

impl ConnError {
  fn server(reason: impl Into<String>) -> Self {
    Self::Server(Failure(reason.into()))
  }
}

/// Errors that mean the client, not the server, ran out of something.
fn is_client_resource(err: &io::Error) -> bool {
  matches!(
    err.raw_os_error(),
    Some(libc::EADDRNOTAVAIL | libc::EADDRINUSE | libc::EMFILE | libc::ENFILE | libc::ENOBUFS)
  )
}

fn classify(context: &str, err: &io::Error) -> ConnError {
  if is_client_resource(err) {
    ConnError::Harness(format!("{context}: {err}"))
  } else {
    ConnError::server(format!("{context}: {err}"))
  }
}

/// A read error that means the peer is gone.
fn is_reset(err: &io::Error) -> bool {
  matches!(err.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)
}

#[derive(Clone, Copy, Debug)]
enum Dir {
  Sent,
  Received,
  Note,
}

/// The last events of a connection, for failure reports.
#[derive(Debug)]
pub struct Transcript {
  events: VecDeque<(u64, Dir, usize, Vec<u8>)>,
  start: Instant,
}

impl Transcript {
  fn new() -> Self {
    Self { events: VecDeque::with_capacity(TRANSCRIPT_EVENTS), start: Instant::now() }
  }

  fn record(&mut self, dir: Dir, bytes: &[u8]) {
    if self.events.len() == TRANSCRIPT_EVENTS {
      let _ = self.events.pop_front();
    }
    let at = self.start.elapsed().as_micros() as u64;
    let kept = bytes[..bytes.len().min(TRANSCRIPT_BYTES)].to_vec();
    self.events.push_back((at, dir, bytes.len(), kept));
  }

  /// Adds a line of text, such as what a scenario was about to do.
  pub fn note(&mut self, text: &str) {
    self.record(Dir::Note, text.as_bytes());
  }

  /// One line per event: time, direction, length and up to 64 bytes in hex.
  pub fn dump(&self) -> String {
    let mut out = String::new();
    for (at, dir, len, bytes) in &self.events {
      let _ = write!(out, "{at:>9}us {dir:<8?} {len:>7}B ");
      if let Dir::Note = dir {
        out.push_str(&String::from_utf8_lossy(bytes).replace(char::is_whitespace, "_"));
      } else {
        for byte in bytes {
          let _ = write!(out, "{byte:02x}");
        }
      }
      out.push('\n');
    }
    out
  }
}

/// A client connection.
#[derive(Debug)]
pub struct Conn {
  parser: Parser,
  stream: TcpStream,
  transcript: Transcript,
}

impl Conn {
  pub async fn connect(addr: SocketAddr, opts: &ConnOpts) -> Result<Conn, ConnError> {
    let socket = if addr.is_ipv4() { TcpSocket::new_v4() } else { TcpSocket::new_v6() }
      .map_err(|err| classify("socket", &err))?;
    if let Some(len) = opts.rcvbuf {
      socket.set_recv_buffer_size(len).map_err(|err| classify("SO_RCVBUF", &err))?;
    }
    if let Some(ip) = opts.source_ip {
      socket.bind(SocketAddr::new(ip, 0)).map_err(|err| classify("bind", &err))?;
    }
    let stream = socket.connect(addr).await.map_err(|err| classify("connect", &err))?;
    stream.set_nodelay(opts.nodelay).map_err(|err| classify("TCP_NODELAY", &err))?;
    Ok(Conn { parser: Parser::new(MAX_FRAME), stream, transcript: Transcript::new() })
  }

  pub async fn send(&mut self, bytes: &[u8]) -> Result<(), ConnError> {
    self.transcript.record(Dir::Sent, bytes);
    self.stream.write_all(bytes).await.map_err(|err| classify("send", &err))
  }

  /// Sends an upgrade request and checks the 101 and its `Sec-WebSocket-Accept`.
  pub async fn upgrade(&mut self, host: &str, path: &str, rng: &mut Rng) -> Result<(), ConnError> {
    use base64::Engine as _;
    let key = base64::engine::general_purpose::STANDARD.encode(rand::Rng::random::<[u8; 16]>(rng));
    self.send(&upgrade_request(host, path, &key)).await?;
    let deadline = Instant::now() + UPGRADE_TIMEOUT;
    let mut head = Vec::new();
    let res = loop {
      match parse_upgrade_response(&head) {
        Ok(Some(res)) => break res,
        Ok(None) => {}
        Err(err) => return Err(ConnError::server(format!("upgrade response: {err:?}"))),
      }
      if self.read_some(&mut head, deadline).await? == 0 {
        return Err(ConnError::server("EOF during the upgrade"));
      }
    };
    if res.status != 101 {
      return Err(ConnError::server(format!("upgrade answered {}", res.status)));
    }
    if res.accept.as_deref() != Some(accept_key(&key).as_str()) {
      return Err(ConnError::server(format!("bad Sec-WebSocket-Accept {:?}", res.accept)));
    }
    self.parser.push(&head[res.header_len..]);
    Ok(())
  }

  /// Appends what one read returns to `buf`; 0 on EOF or reset.
  async fn read_some(&mut self, buf: &mut Vec<u8>, deadline: Instant) -> Result<usize, ConnError> {
    let mut chunk = vec![0; 65536];
    match timeout_at(deadline, self.stream.read(&mut chunk)).await {
      Err(_) => Err(ConnError::server("timed out")),
      Ok(Ok(len)) => {
        if len > 0 {
          self.transcript.record(Dir::Received, &chunk[..len]);
        } else {
          self.transcript.note("EOF");
        }
        buf.extend_from_slice(&chunk[..len]);
        Ok(len)
      }
      Ok(Err(err)) if is_reset(&err) => {
        self.transcript.note("reset");
        Ok(0)
      }
      Ok(Err(err)) => Err(classify("read", &err)),
    }
  }

  pub async fn next_frame(&mut self, deadline: Instant) -> Result<Next, ConnError> {
    loop {
      match self.parser.next_frame() {
        Ok(Some(frame)) => return Ok(Next::Frame(frame)),
        Ok(None) => {}
        Err(err) => return Err(ConnError::server(format!("server frame: {err:?}"))),
      }
      let mut buf = Vec::new();
      if self.read_some(&mut buf, deadline).await? == 0 {
        return Ok(Next::Eof);
      }
      self.parser.push(&buf);
    }
  }

  /// Writes `data` in pieces of the sizes `chunks` cycles through, while reading the server's
  /// frames into `on_frame`, until it returns `Flow::Done` or the server closes. Reading while
  /// writing keeps a large batch from deadlocking against a server that stops reading until its
  /// replies are read. A failed write (the server closed) stops writing, not reading.
  pub async fn exchange(
    &mut self,
    data: &[u8],
    chunks: &[usize],
    deadline: Instant,
    mut on_frame: impl FnMut(ServerFrame) -> Flow,
  ) -> Result<Exchange, ConnError> {
    let Conn { parser, stream, transcript } = self;
    let transcript = std::sync::Mutex::new(transcript);
    let record = |dir: Dir, bytes: &[u8]| {
      if let Ok(mut el) = transcript.lock() {
        el.record(dir, bytes);
      }
    };
    let (mut rd, mut wr) = stream.split();
    let writer = async {
      let mut at = 0;
      for len in chunks.iter().cycle() {
        if at >= data.len() {
          break;
        }
        let end = data.len().min(at + len.max(&1));
        record(Dir::Sent, &data[at..end]);
        if let Err(err) = wr.write_all(&data[at..end]).await {
          record(Dir::Note, format!("write failed: {err}").as_bytes());
          break;
        }
        at = end;
      }
    };
    let reader = async {
      let mut chunk = vec![0; 65536];
      loop {
        loop {
          match parser.next_frame() {
            Ok(Some(frame)) => {
              if on_frame(frame) == Flow::Done {
                return Ok(Exchange::Done);
              }
            }
            Ok(None) => break,
            Err(err) => return Err(ConnError::server(format!("server frame: {err:?}"))),
          }
        }
        match rd.read(&mut chunk).await {
          Ok(0) => {
            record(Dir::Note, b"EOF");
            return Ok(Exchange::Eof);
          }
          Ok(len) => {
            record(Dir::Received, &chunk[..len]);
            parser.push(&chunk[..len]);
          }
          Err(err) if is_reset(&err) => {
            record(Dir::Note, b"reset");
            return Ok(Exchange::Eof);
          }
          Err(err) => return Err(classify("read", &err)),
        }
      }
    };
    let both = async {
      let (mut writer, mut reader) = (std::pin::pin!(writer), std::pin::pin!(reader));
      let mut written = false;
      loop {
        tokio::select! {
          () = &mut writer, if !written => written = true,
          rslt = &mut reader => return rslt,
        }
      }
    };
    match timeout_at(deadline, both).await {
      Ok(rslt) => rslt,
      Err(_) => Err(ConnError::server("timed out")),
    }
  }

  /// Skips data frames until a close frame with one of `codes`.
  pub async fn expect_close(&mut self, codes: &[u16], deadline: Instant) -> Result<(), ConnError> {
    loop {
      let frame = match self.next_frame(deadline).await {
        Ok(Next::Frame(frame)) => frame,
        Ok(Next::Eof) => {
          return Err(ConnError::server(format!("EOF instead of a close {codes:?}")));
        }
        Err(ConnError::Server(Failure(reason))) => {
          return Err(ConnError::server(format!("waiting for a close {codes:?}: {reason}")));
        }
        Err(err) => return Err(err),
      };
      if frame.opcode != 8 {
        continue;
      }
      return match close_code(&frame) {
        Some(code) if codes.contains(&code) => Ok(()),
        code => Err(ConnError::server(format!("close code {code:?}, expected {codes:?}"))),
      };
    }
  }

  /// Discards bytes until the server closes (a reset counts).
  pub async fn expect_eof(&mut self, deadline: Instant) -> Result<(), ConnError> {
    let mut sink = Vec::new();
    loop {
      sink.clear();
      match self.read_some(&mut sink, deadline).await {
        Ok(0) => return Ok(()),
        Ok(_) => {}
        Err(ConnError::Server(Failure(reason))) => {
          return Err(ConnError::server(format!("still open: {reason}")));
        }
        Err(err) => return Err(err),
      }
    }
  }

  /// Closes with `SO_LINGER 0`, which sends a reset.
  pub fn reset(self) {
    let _ = self.stream.set_zero_linger();
  }

  pub async fn shutdown_write(&mut self) {
    self.transcript.note("shutdown(SHUT_WR)");
    let _ = self.stream.shutdown().await;
  }

  pub fn transcript(&self) -> &Transcript {
    &self.transcript
  }

  pub fn transcript_mut(&mut self) -> &mut Transcript {
    &mut self.transcript
  }

  pub fn raw(&mut self) -> &mut TcpStream {
    &mut self.stream
  }
}
