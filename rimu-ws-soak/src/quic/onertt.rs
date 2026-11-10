//! A raw 1-RTT QUIC client (ruling T23-j #5). It drives a real TLS 1.3 handshake through
//! `rustls::quic::ClientConnection` (ring provider) but keeps its own QUIC codecs: long/short
//! headers, packet-number spaces, CRYPTO reassembly, the ACK writer, transport-parameter encoding
//! and every frame encoder. rustls supplies only the handshake bytes and the per-level packet and
//! header-protection keys ([`rustls::quic::Keys`]); the packet framing, the frames the floods
//! inject, and the close-code parsing are the harness's own, so a bug the harness and rimu-ws share
//! could not hide (ruling T23-b). rustls is not rimu-ws's TLS stack, so independence holds.
//!
//! It exists for what `quinn` will not send: a conforming client emits no PING, PATH_CHALLENGE,
//! NEW_CONNECTION_ID or RETIRE_CONNECTION_ID flood, no empty 1-RTT packet, no out-of-order STREAM
//! gaps past the limit, no STREAM past the flow-control window and no 10,000-range ACK. Each of
//! those is one of the server's documented limits (spec section 5.12).

use crate::quic::raw::{put_varint, read_varint};
use rustls::quic::{ClientConnection, DirectionalKeys, KeyChange, Keys, Version};
use std::{net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::Instant};

/// The three packet-number spaces (RFC 9000 section 12.3). 0-RTT is not used.
const INITIAL: usize = 0;
const HANDSHAKE: usize = 1;
const ONE_RTT: usize = 2;

/// How a 1-RTT connection ended, so a flood scenario can assert the exact limit it tripped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Close {
  /// CONNECTION_CLOSE with an application code (HTTP/3 codes such as H3_EXCESSIVE_LOAD 0x0107).
  App(u64),
  /// CONNECTION_CLOSE with a transport code (QUIC codes such as PROTOCOL_VIOLATION 0x0a).
  Transport(u64),
  /// No CONNECTION_CLOSE arrived within the wait.
  None,
}

/// A key pair for one packet-number space: `local` protects what we send, `remote` removes the
/// protection of what the server sends.
struct Level {
  local: DirectionalKeys,
  remote: DirectionalKeys,
}

impl From<Keys> for Level {
  fn from(keys: Keys) -> Self {
    Level { local: keys.local, remote: keys.remote }
  }
}

/// Encodes the client's QUIC transport parameters (RFC 9000 section 18). `initial_source_connection_id`
/// must equal the Source Connection ID of the client's Initial packets or the server fails the
/// handshake (RFC 9001 section 8.1), so it is always included; the rest grant enough flow control
/// for the abuse streams.
fn transport_params(scid: &[u8]) -> Vec<u8> {
  let mut out = Vec::new();
  let tp = |out: &mut Vec<u8>, id: u64, value: u64| {
    let mut v = Vec::new();
    put_varint(&mut v, value);
    put_varint(out, id);
    put_varint(out, v.len() as u64);
    out.extend_from_slice(&v);
  };
  tp(&mut out, 0x01, 30_000); // max_idle_timeout (ms)
  tp(&mut out, 0x03, 1452); // max_udp_payload_size
  tp(&mut out, 0x04, 1 << 20); // initial_max_data
  tp(&mut out, 0x05, 1 << 20); // initial_max_stream_data_bidi_local
  tp(&mut out, 0x06, 1 << 20); // initial_max_stream_data_bidi_remote
  tp(&mut out, 0x07, 1 << 20); // initial_max_stream_data_uni
  tp(&mut out, 0x08, 16); // initial_max_streams_bidi
  tp(&mut out, 0x09, 16); // initial_max_streams_uni
  tp(&mut out, 0x0a, 3); // ack_delay_exponent
  tp(&mut out, 0x0b, 25); // max_ack_delay (ms)
  // initial_source_connection_id: a byte string, not a varint value.
  put_varint(&mut out, 0x0f);
  put_varint(&mut out, scid.len() as u64);
  out.extend_from_slice(scid);
  out
}

/// The RFC 9001 Initial keys for a destination connection ID, as `rustls` derives them (one code
/// path with the Handshake and 1-RTT keys). AES-128-GCM, the only suite the server offers first.
fn initial_level(dcid: &[u8]) -> Level {
  let suite =
    rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256.tls13().expect("tls13 suite");
  let algo = suite.quic.expect("quic algorithm");
  Keys::initial(Version::V1, suite, algo, dcid, rustls::Side::Client).into()
}

/// A frame payload that a 1-RTT packet carries: the floods build these.
pub mod frames {
  use crate::quic::raw::put_varint;

  /// A PING frame (RFC 9000 section 19.2).
  pub fn ping() -> Vec<u8> {
    vec![0x01]
  }

  /// `count` PING frames packed into one payload (each is a single 0x01 byte), to spend the PING
  /// budget quickly inside few packets.
  pub fn pings(count: usize) -> Vec<u8> {
    vec![0x01; count]
  }

  /// An ACK frame acking a single packet number `largest` (first range only).
  pub fn ack_simple(largest: u64) -> Vec<u8> {
    let mut out = vec![0x02];
    put_varint(&mut out, largest);
    put_varint(&mut out, 0); // ack delay
    put_varint(&mut out, 0); // range count
    put_varint(&mut out, 0); // first ack range: acks `largest` only
    out
  }

  /// A PATH_CHALLENGE frame with eight bytes of data (RFC 9000 section 19.17).
  pub fn path_challenge(data: [u8; 8]) -> Vec<u8> {
    let mut out = vec![0x1a];
    out.extend_from_slice(&data);
    out
  }

  /// A NEW_CONNECTION_ID frame (RFC 9000 section 19.15): a fresh 8-byte CID, a 16-byte reset token.
  /// `retire_prior_to` retires the peer's lower-sequence CIDs, so a flood can keep the active count
  /// under the peer's `active_connection_id_limit` and reach the per-second budget instead.
  pub fn new_connection_id(
    seq: u64,
    retire_prior_to: u64,
    cid: [u8; 8],
    token: [u8; 16],
  ) -> Vec<u8> {
    let mut out = vec![0x18];
    put_varint(&mut out, seq);
    put_varint(&mut out, retire_prior_to);
    out.push(cid.len() as u8);
    out.extend_from_slice(&cid);
    out.extend_from_slice(&token);
    out
  }

  /// A RETIRE_CONNECTION_ID frame (RFC 9000 section 19.16).
  pub fn retire_connection_id(seq: u64) -> Vec<u8> {
    let mut out = vec![0x19];
    put_varint(&mut out, seq);
    out
  }

  /// A STREAM frame with an explicit offset and length (type 0x0e = OFF|LEN), no FIN (RFC 9000
  /// section 19.8).
  pub fn stream(id: u64, offset: u64, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x0e];
    put_varint(&mut out, id);
    put_varint(&mut out, offset);
    put_varint(&mut out, data.len() as u64);
    out.extend_from_slice(data);
    out
  }

  /// A MAX_DATA frame (type 0x10): an ack-eliciting frame with no budget, so a flood of it raises
  /// the server's 1-RTT packet numbers (each draws an ACK) without tripping any limit.
  pub fn max_data(max: u64) -> Vec<u8> {
    let mut out = vec![0x10];
    put_varint(&mut out, max);
    out
  }

  /// An ACK frame of `ranges` extra ranges after the first, each gap 0 / length 0, walking down
  /// from `largest` by two (RFC 9000 section 19.3): every acknowledged packet number is a real one
  /// the server sent, provided `largest >= 2 * ranges`. For the valid 257+ range flood (N1).
  pub fn ack_ranges(largest: u64, ranges: u64) -> Vec<u8> {
    let mut out = vec![0x02];
    put_varint(&mut out, largest);
    put_varint(&mut out, 0); // ack delay
    put_varint(&mut out, ranges);
    put_varint(&mut out, 0); // first ack range: acks `largest` only
    for _ in 0..ranges {
      put_varint(&mut out, 0); // gap 0: skip one packet number
      put_varint(&mut out, 0); // range length 0
    }
    out
  }

  /// A deliberately malformed ACK: a first range or extra ranges that reach below packet number 0
  /// (RFC 9000 section 19.3.1 makes it a FRAME_ENCODING_ERROR). With `largest` 0 and one extra
  /// range the second range implies packet number −2.
  pub fn ack_below_zero() -> Vec<u8> {
    ack_many(0, 1)
  }

  /// An ACK frame with `range_count` extra ranges after the first, each a 1-gap, 0-length range
  /// walking down from `largest` (RFC 9000 section 19.3). Reaches below packet number 0 when
  /// `largest` is small, so it is the malformed case; prefer [`ack_ranges`] for a valid flood.
  pub fn ack_many(largest: u64, range_count: u64) -> Vec<u8> {
    let mut out = vec![0x02];
    put_varint(&mut out, largest);
    put_varint(&mut out, 0); // ack delay
    put_varint(&mut out, range_count);
    put_varint(&mut out, 0); // first ack range (acks `largest` only)
    for _ in 0..range_count {
      put_varint(&mut out, 0); // gap: skip one packet
      put_varint(&mut out, 0); // range length
    }
    out
  }
}

/// Decodes a truncated packet number against the largest seen in its space (RFC 9000 appendix A).
fn decode_pn(largest: Option<u64>, truncated: u64, pn_len: u32) -> u64 {
  let Some(largest) = largest else { return truncated };
  let expected = largest.wrapping_add(1);
  let win = 1u64 << (pn_len.wrapping_mul(8));
  let half = win >> 1;
  let candidate = (expected & !(win.wrapping_sub(1))).wrapping_add(truncated);
  if candidate.wrapping_add(half) <= expected
    && candidate.wrapping_add(win) <= expected.wrapping_add(half)
  {
    candidate.wrapping_add(win)
  } else if candidate > expected.wrapping_add(half) && candidate >= win {
    candidate.wrapping_sub(win)
  } else {
    candidate
  }
}

/// Scans decrypted frame bytes for a CONNECTION_CLOSE and returns its (is_application, code),
/// skipping the frames a server may place before it. Returns `None` if there is no close.
fn scan_close(frames: &[u8]) -> Option<(bool, u64)> {
  let mut at = 0usize;
  while at < frames.len() {
    let (ty, vl) = read_varint(frames.get(at..)?)?;
    at = at.checked_add(vl)?;
    match ty {
      0x00 | 0x01 => {} // PADDING, PING
      0x1c | 0x1d => {
        let (code, _cvl) = read_varint(frames.get(at..)?)?;
        return Some((ty == 0x1d, code));
      }
      0x02 | 0x03 => {
        // ACK: largest, delay, count, first, then count*(gap,len), and for 0x03 three ECN counts.
        let (_largest, a) = read_varint(frames.get(at..)?)?;
        at = at.checked_add(a)?;
        let (_delay, b) = read_varint(frames.get(at..)?)?;
        at = at.checked_add(b)?;
        let (count, c) = read_varint(frames.get(at..)?)?;
        at = at.checked_add(c)?;
        let (_first, d) = read_varint(frames.get(at..)?)?;
        at = at.checked_add(d)?;
        for _ in 0..count {
          let (_gap, g) = read_varint(frames.get(at..)?)?;
          at = at.checked_add(g)?;
          let (_len, l) = read_varint(frames.get(at..)?)?;
          at = at.checked_add(l)?;
        }
        if ty == 0x03 {
          for _ in 0..3 {
            let (_, e) = read_varint(frames.get(at..)?)?;
            at = at.checked_add(e)?;
          }
        }
      }
      0x06 => {
        // CRYPTO: offset, length, data.
        let (_off, a) = read_varint(frames.get(at..)?)?;
        at = at.checked_add(a)?;
        let (dlen, b) = read_varint(frames.get(at..)?)?;
        at = at.checked_add(b)?.checked_add(usize::try_from(dlen).ok()?)?;
      }
      0x1e => {} // HANDSHAKE_DONE
      0x18 => {
        // NEW_CONNECTION_ID: seq, retire, cid_len, cid, 16-byte token.
        let (_seq, a) = read_varint(frames.get(at..)?)?;
        at = at.checked_add(a)?;
        let (_rp, b) = read_varint(frames.get(at..)?)?;
        at = at.checked_add(b)?;
        let cid_len = usize::from(*frames.get(at)?);
        at = at.checked_add(1)?.checked_add(cid_len)?.checked_add(16)?;
      }
      0x08..=0x0f => {
        // A server STREAM frame (control/QPACK/push): skip it to its end — it is the last frame
        // the server coalesces, so stop scanning.
        return None;
      }
      _ => return None, // an unexpected frame: stop rather than misparse.
    }
  }
  None
}

/// Extracts CRYPTO frames `(offset, data)` from decrypted frame bytes, for feeding `read_hs`.
fn scan_crypto(frames: &[u8]) -> Vec<(u64, Vec<u8>)> {
  let mut out = Vec::new();
  let mut at = 0usize;
  while at < frames.len() {
    let Some((ty, vl)) = read_varint(&frames[at..]) else { break };
    at += vl;
    match ty {
      0x00 | 0x01 | 0x1e => {}
      0x06 => {
        let Some((off, a)) = read_varint(&frames[at..]) else { break };
        at += a;
        let Some((len, b)) = read_varint(&frames[at..]) else { break };
        at += b;
        let len = len as usize;
        if at + len > frames.len() {
          break;
        }
        out.push((off, frames[at..at + len].to_vec()));
        at += len;
      }
      0x02 | 0x03 => {
        let Some((_l, a)) = read_varint(&frames[at..]) else { break };
        at += a;
        let Some((_d, b)) = read_varint(&frames[at..]) else { break };
        at += b;
        let Some((count, c)) = read_varint(&frames[at..]) else { break };
        at += c;
        let Some((_f, d)) = read_varint(&frames[at..]) else { break };
        at += d;
        let mut ok = true;
        for _ in 0..count {
          let Some((_g, g)) = read_varint(&frames[at..]) else {
            ok = false;
            break;
          };
          at += g;
          let Some((_le, le)) = read_varint(&frames[at..]) else {
            ok = false;
            break;
          };
          at += le;
        }
        if !ok {
          break;
        }
      }
      _ => break,
    }
  }
  out
}

/// A raw 1-RTT client: after [`Self::connect`] returns, the handshake is complete and 1-RTT frames
/// can be injected with [`Self::send_1rtt`].
pub struct OneRttClient {
  sock: UdpSocket,
  dcid: Vec<u8>,
  scid: Vec<u8>,
  pn_1rtt: u64,
  levels: [Option<Level>; 3],
  largest_recv: [Option<u64>; 3],
}

/// The outcome of a raw per-datagram flap (ruling T23-j #4 / N4).
pub struct RawFlap {
  /// Datagrams sent (one per flip).
  pub flips: u64,
  /// Bytes sent from \[validated socket 0, unvalidated socket 1].
  pub bytes_out: [u64; 2],
  /// Bytes received on \[socket 0, socket 1].
  pub bytes_in: [u64; 2],
  /// How the connection ended, if it did.
  pub closed: Close,
}

impl OneRttClient {
  /// Binds a loopback socket, runs the QUIC/TLS handshake against `target`, and returns once the
  /// 1-RTT keys are in hand (or an error / timeout).
  pub async fn connect(target: SocketAddr) -> Result<OneRttClient, String> {
    let bind: &str = if target.is_ipv6() { "[::1]:0" } else { "127.0.0.1:0" };
    let sock = UdpSocket::bind(bind).await.map_err(|err| format!("bind: {err}"))?;
    sock.connect(target).await.map_err(|err| format!("connect: {err}"))?;

    let mut rng = crate::quic::scenario::tiny_rng(0x0ca7_b3ef ^ (target.port() as u64));
    let dcid: Vec<u8> = (0..8).map(|_| rng() as u8).collect();
    let scid: Vec<u8> = (0..8).map(|_| rng() as u8).collect();

    let mut conn = ClientConnection::new(
      std::sync::Arc::new(super::client::rustls_config()),
      Version::V1,
      rustls::pki_types::ServerName::try_from("localhost").map_err(|err| format!("name: {err}"))?,
      transport_params(&scid),
    )
    .map_err(|err| format!("rustls client: {err}"))?;

    let mut client = OneRttClient {
      sock,
      dcid: dcid.clone(),
      scid: scid.clone(),
      pn_1rtt: 0,
      levels: [Some(initial_level(&dcid)), None, None],
      largest_recv: [None; 3],
    };

    let mut send_pn = [0u64; 3];
    let mut crypto_off = [0u64; 3];
    let mut write_space = INITIAL;
    let mut server_scid: Option<Vec<u8>> = None;
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(8);

    // Received datagrams are buffered so that a coalesced packet of a higher level (e.g. the
    // Handshake part of a datagram that leads with the Initial ServerHello) can be decrypted once
    // its keys are installed, by re-decoding the buffer. `recv_crypto` tracks the next contiguous
    // CRYPTO offset fed to rustls per space, so re-decoding never double-feeds (loopback is
    // in-order).
    let mut datagrams: Vec<Vec<u8>> = Vec::new();
    let mut recv_crypto = [0u64; 3];

    loop {
      // Drain the TLS layer into per-space CRYPTO and install any new keys, re-feeding buffered
      // datagrams between each pump so newly decryptable levels are consumed in order.
      loop {
        let outs = client.pump(&mut conn, &mut write_space);
        for (space, data) in &outs {
          let mut payload = Vec::new();
          encode_crypto(&mut payload, crypto_off[*space], data);
          crypto_off[*space] = crypto_off[*space].wrapping_add(data.len() as u64);
          let _ = client.send_space(*space, &scid, send_pn[*space], &payload).await;
          send_pn[*space] = send_pn[*space].wrapping_add(1);
        }
        let mut fed = false;
        for datagram in &datagrams {
          for (space, frames, pn) in client.decode_datagram(datagram) {
            client.largest_recv[space] = Some(match client.largest_recv[space] {
              Some(prev) => prev.max(pn),
              None => pn,
            });
            if let Some((app, code)) = scan_close(&frames) {
              return Err(format!("server closed during handshake: app={app} code=0x{code:x}"));
            }
            for (off, data) in scan_crypto(&frames) {
              // Feed only new contiguous CRYPTO; skip what was already given to rustls.
              let end = off.wrapping_add(data.len() as u64);
              if off <= recv_crypto[space] && end > recv_crypto[space] {
                let skip = (recv_crypto[space] - off) as usize;
                if conn.read_hs(&data[skip..]).is_err() {
                  return Err("read_hs rejected server CRYPTO".into());
                }
                recv_crypto[space] = end;
                fed = true;
              }
            }
          }
        }
        if !fed && outs.is_empty() {
          break;
        }
      }

      if client.levels[ONE_RTT].is_some() {
        // The 1-RTT keys are available: the handshake produced everything we need. Send a final ACK
        // of each long-header space so the server confirms, then return.
        for space in [INITIAL, HANDSHAKE] {
          if let Some(largest) = client.largest_recv[space] {
            let ack = frames::ack_simple(largest);
            let _ = client.send_space(space, &scid, send_pn[space], &ack).await;
            send_pn[space] = send_pn[space].wrapping_add(1);
          }
        }
        return Ok(client);
      }

      let recv = tokio::time::timeout(Duration::from_millis(400), client.sock.recv(&mut buf)).await;
      let len = match recv {
        Ok(Ok(len)) => len,
        Ok(Err(err)) => return Err(format!("recv: {err}")),
        Err(_) => {
          if Instant::now() >= deadline {
            return Err("handshake timed out".into());
          }
          continue;
        }
      };
      if Instant::now() >= deadline {
        return Err("handshake timed out".into());
      }
      let datagram = buf[..len].to_vec();
      if server_scid.is_none() {
        if let Some(scid) = long_header_scid(&datagram) {
          server_scid = Some(scid.clone());
          client.dcid = scid; // our packets now go to the server's chosen CID.
        }
      }
      datagrams.push(datagram);
    }
  }

  /// Drains `write_hs` into `(space, crypto_bytes)` pairs and installs any new keys, advancing the
  /// write space on each key change (the bytes a call yields belong to the space before the change).
  fn pump(
    &mut self,
    conn: &mut ClientConnection,
    write_space: &mut usize,
  ) -> Vec<(usize, Vec<u8>)> {
    let mut outs = Vec::new();
    loop {
      let mut data = Vec::new();
      let kc = conn.write_hs(&mut data);
      if !data.is_empty() {
        outs.push((*write_space, data));
      }
      match kc {
        None => break,
        Some(KeyChange::Handshake { keys }) => {
          self.levels[HANDSHAKE] = Some(keys.into());
          *write_space = HANDSHAKE;
        }
        Some(KeyChange::OneRtt { keys, next: _ }) => {
          self.levels[ONE_RTT] = Some(keys.into());
          *write_space = ONE_RTT;
        }
      }
    }
    outs
  }

  /// Sends one packet in `space` carrying `payload` (already-encoded frames), with a 4-byte packet
  /// number. Initial and Handshake use a long header; 1-RTT a short header. A datagram with an
  /// Initial is padded to 1,200 bytes (RFC 9000 section 14.1).
  async fn send_space(
    &self,
    space: usize,
    scid: &[u8],
    pn: u64,
    payload: &[u8],
  ) -> std::io::Result<usize> {
    let Some(level) = self.levels[space].as_ref() else {
      return Ok(0);
    };
    let pad_to = if space == INITIAL { 1200 } else { 0 };
    let packet = build_packet(space, &self.dcid, scid, pn, &level.local, payload, pad_to);
    self.sock.send(&packet).await
  }

  /// Injects one 1-RTT packet carrying `payload` (already-encoded frames). Each call uses a fresh
  /// packet number, so the server never dedupes it away.
  pub async fn send_1rtt(&mut self, payload: &[u8]) -> Result<(), String> {
    let Some(level) = self.levels[ONE_RTT].as_ref() else {
      return Err("no 1-RTT keys".into());
    };
    let packet = build_short(&self.dcid, self.pn_1rtt, &level.local, payload);
    self.pn_1rtt = self.pn_1rtt.wrapping_add(1);
    self.sock.send(&packet).await.map(|_| ()).map_err(|err| format!("send: {err}"))
  }

  /// Decodes a received datagram into `(space, decrypted_frames, packet_number)` for each packet it
  /// coalesces, stopping at the first packet it cannot parse or decrypt.
  fn decode_datagram(&self, datagram: &[u8]) -> Vec<(usize, Vec<u8>, u64)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < datagram.len() {
      let Some(&first) = datagram.get(at) else { break };
      if first & 0x80 == 0 {
        // Short header (1-RTT): its DCID is our own connection ID (the SCID we chose), so the
        // packet-number offset skips that length (N7). Runs to the end of the datagram.
        if let Some(res) = self.decode_one(ONE_RTT, &datagram[at..], 1 + self.scid.len()) {
          out.push(res);
        }
        break;
      }
      // Long header: Initial (type 0b00) or Handshake (type 0b10). 0-RTT/Retry are not expected.
      let space = match (first & 0x30) >> 4 {
        0b00 => INITIAL,
        0b10 => HANDSHAKE,
        _ => break,
      };
      let Some((packet_len, header_pn_off)) = long_header_bounds(&datagram[at..]) else { break };
      let end = at + packet_len;
      if end > datagram.len() {
        break;
      }
      if let Some(res) = self.decode_one(space, &datagram[at..end], header_pn_off) {
        out.push(res);
      }
      at = end;
    }
    out
  }

  /// Removes header protection and AEAD from one packet (`pn_offset` is the offset of its packet
  /// number). Returns `(space, frames, pn)` or `None` if it cannot be decrypted.
  fn decode_one(
    &self,
    space: usize,
    packet: &[u8],
    pn_offset: usize,
  ) -> Option<(usize, Vec<u8>, u64)> {
    let level = self.levels[space].as_ref()?;
    let (frames, pn) = decrypt_packet(level, self.largest_recv[space], packet, pn_offset)?;
    Some((space, frames, pn))
  }

  /// Reads datagrams until the server sends a CONNECTION_CLOSE or `within` elapses, returning how
  /// it closed. Drives nothing else: used after a flood to capture the close code.
  pub async fn wait_close(&mut self, within: Duration) -> Close {
    let deadline = Instant::now() + within;
    let mut buf = [0u8; 2048];
    loop {
      let left = deadline.saturating_duration_since(Instant::now());
      if left.is_zero() {
        return Close::None;
      }
      match tokio::time::timeout(left, self.sock.recv(&mut buf)).await {
        Ok(Ok(len)) => {
          let datagram = buf[..len].to_vec();
          for (space, frames, pn) in self.decode_datagram(&datagram) {
            self.largest_recv[space] = Some(match self.largest_recv[space] {
              Some(prev) => prev.max(pn),
              None => pn,
            });
            if let Some((app, code)) = scan_close(&frames) {
              return if app { Close::App(code) } else { Close::Transport(code) };
            }
          }
        }
        Ok(Err(_)) | Err(_) => return Close::None,
      }
    }
  }

  /// Reads datagrams for `within`, updating the largest 1-RTT packet number seen, and returns it.
  /// Used to learn the server's current packet numbers before an ACK flood.
  pub async fn drain(&mut self, within: Duration) -> Option<u64> {
    let deadline = Instant::now() + within;
    let mut buf = [0u8; 2048];
    loop {
      let left = deadline.saturating_duration_since(Instant::now());
      if left.is_zero() {
        break;
      }
      match tokio::time::timeout(left.min(Duration::from_millis(50)), self.sock.recv(&mut buf))
        .await
      {
        Ok(Ok(len)) => {
          let datagram = buf[..len].to_vec();
          for (space, _frames, pn) in self.decode_datagram(&datagram) {
            self.largest_recv[space] =
              Some(self.largest_recv[space].map_or(pn, |prev| prev.max(pn)));
          }
        }
        Ok(Err(_)) => break,
        Err(_) => {
          if Instant::now() >= deadline {
            break;
          }
        }
      }
    }
    self.largest_recv[ONE_RTT]
  }

  /// A per-datagram migration flapper that sends no PING (ruling T23-j #4 / N4): one MAX_DATA
  /// packet per datagram, alternating between the handshake socket (address 0, validated) and
  /// `alt` (address 1, perpetually unvalidated). Both sockets must be connected to the server.
  /// Counts bytes in and out per address and records the close, so a 3× amplification check can be
  /// applied to the unvalidated address.
  pub async fn raw_flap(&mut self, alt: &UdpSocket, dur: Duration) -> RawFlap {
    let mut res = RawFlap { flips: 0, bytes_out: [0; 2], bytes_in: [0; 2], closed: Close::None };
    let Some(local) = self.levels[ONE_RTT].as_ref().map(|lvl| &lvl.local) else {
      return res;
    };
    let begin = Instant::now();
    let mut buf = [0u8; 2048];
    let mut fc = 1u64 << 20;
    while begin.elapsed() < dur && matches!(res.closed, Close::None) {
      let idx = (res.flips % 2) as usize;
      let pn = self.pn_1rtt;
      self.pn_1rtt = self.pn_1rtt.wrapping_add(1);
      fc = fc.wrapping_add(1);
      let packet = build_short(&self.dcid, pn, local, &frames::max_data(fc));
      let sock = if idx == 0 { &self.sock } else { alt };
      if sock.send(&packet).await.is_ok() {
        res.bytes_out[idx] = res.bytes_out[idx].wrapping_add(packet.len() as u64);
      }
      res.flips = res.flips.wrapping_add(1);
      // Drain both sockets without blocking the flap rate.
      for (j, s) in [(0usize, &self.sock), (1usize, alt)] {
        while let Ok(len) = s.try_recv(&mut buf) {
          res.bytes_in[j] = res.bytes_in[j].wrapping_add(len as u64);
          let datagram = buf[..len].to_vec();
          for (_space, frames, _pn) in self.decode_datagram(&datagram) {
            if let Some((app, code)) = scan_close(&frames) {
              res.closed = if app { Close::App(code) } else { Close::Transport(code) };
            }
          }
        }
      }
      tokio::time::sleep(Duration::from_millis(1)).await;
    }
    res
  }
}

/// Removes header protection and AEAD from one packet with `level`'s remote keys (`pn_offset` is
/// the offset of its packet number, `largest` the largest packet number seen in the space for
/// packet-number reconstruction). Returns `(frames, pn)` or `None` if it cannot be decrypted.
fn decrypt_packet(
  level: &Level,
  largest: Option<u64>,
  packet: &[u8],
  pn_offset: usize,
) -> Option<(Vec<u8>, u64)> {
  let remote = &level.remote;
  let sample_len = remote.header.sample_len();
  let mut pkt = packet.to_vec();
  let sample_at = pn_offset.checked_add(4)?;
  let sample = pkt.get(sample_at..sample_at.checked_add(sample_len)?)?.to_vec();
  let mut first = pkt[0];
  let mut pn_bytes = pkt.get(pn_offset..pn_offset.checked_add(4)?)?.to_vec();
  remote.header.decrypt_in_place(&sample, &mut first, &mut pn_bytes).ok()?;
  let pn_len = usize::from(first & 0x03) + 1;
  pkt[0] = first;
  pkt.get_mut(pn_offset..pn_offset + pn_len)?.copy_from_slice(&pn_bytes[..pn_len]);
  let mut truncated = 0u64;
  for &byte in &pn_bytes[..pn_len] {
    truncated = (truncated << 8) | u64::from(byte);
  }
  let pn = decode_pn(largest, truncated, pn_len as u32);
  let header_end = pn_offset + pn_len;
  let header = pkt.get(..header_end)?.to_vec();
  let mut payload = pkt.get(header_end..)?.to_vec();
  let plain = remote.packet.decrypt_in_place(pn, &header, &mut payload).ok()?;
  Some((plain.to_vec(), pn))
}

/// Encodes a CRYPTO frame (type 0x06) into `out`.
fn encode_crypto(out: &mut Vec<u8>, offset: u64, data: &[u8]) {
  put_varint(out, 0x06);
  put_varint(out, offset);
  put_varint(out, data.len() as u64);
  out.extend_from_slice(data);
}

/// Builds a long-header (Initial/Handshake) packet, header-protected and AEAD-sealed, padded to
/// `pad_to` bytes if positive.
fn build_packet(
  space: usize,
  dcid: &[u8],
  scid: &[u8],
  pn: u64,
  local: &DirectionalKeys,
  frames: &[u8],
  pad_to: usize,
) -> Vec<u8> {
  if space == ONE_RTT {
    return build_short(dcid, pn, local, frames);
  }
  let ty: u8 = if space == INITIAL { 0x00 } else { 0x02 };
  let mut header = Vec::new();
  header.push(0xc0 | (ty << 4) | 0x03); // long header, 4-byte packet number.
  header.extend_from_slice(&0x0000_0001u32.to_be_bytes()); // version 1
  header.push(dcid.len() as u8);
  header.extend_from_slice(dcid);
  header.push(scid.len() as u8);
  header.extend_from_slice(scid);
  if space == INITIAL {
    put_varint(&mut header, 0); // token length 0
  }
  let mut payload = frames.to_vec();
  // Pad the whole datagram to `pad_to` (PADDING frames are 0x00).
  let overhead = header.len() + 2 /* length varint */ + 4 /* pn */ + 16 /* tag */;
  if overhead + payload.len() < pad_to {
    payload.resize(pad_to - overhead, 0);
  }
  let length = 4 + payload.len() + 16;
  header.extend_from_slice(&((length as u16) | 0x4000).to_be_bytes());
  let pn_offset = header.len();
  header.extend_from_slice(&(pn as u32).to_be_bytes());
  seal(header, payload, pn, pn_offset, local)
}

/// Builds a short-header (1-RTT) packet.
fn build_short(dcid: &[u8], pn: u64, local: &DirectionalKeys, frames: &[u8]) -> Vec<u8> {
  let mut header = Vec::new();
  header.push(0x40 | 0x03); // short header, fixed bit, 4-byte packet number.
  header.extend_from_slice(dcid);
  let pn_offset = header.len();
  header.extend_from_slice(&(pn as u32).to_be_bytes());
  seal(header, frames.to_vec(), pn, pn_offset, local)
}

/// AEAD-seals `payload` with `header` as AAD, appends the tag, then applies header protection.
fn seal(
  header: Vec<u8>,
  mut payload: Vec<u8>,
  pn: u64,
  pn_offset: usize,
  local: &DirectionalKeys,
) -> Vec<u8> {
  let tag = local.packet.encrypt_in_place(pn, &header, &mut payload).expect("seal");
  let mut packet = header.clone();
  packet.append(&mut payload);
  packet.extend_from_slice(tag.as_ref());
  // Header protection: the sample starts four bytes into the packet number field.
  let sample_at = pn_offset + 4;
  let sample = packet[sample_at..sample_at + local.header.sample_len()].to_vec();
  let mut first = packet[0];
  let mut pn_bytes = packet[pn_offset..pn_offset + 4].to_vec();
  local.header.encrypt_in_place(&sample, &mut first, &mut pn_bytes).expect("hp");
  packet[0] = first;
  packet[pn_offset..pn_offset + 4].copy_from_slice(&pn_bytes);
  packet
}

/// The Source Connection ID of a long-header packet, if it is one.
fn long_header_scid(datagram: &[u8]) -> Option<Vec<u8>> {
  let first = *datagram.first()?;
  if first & 0x80 == 0 {
    return None;
  }
  let mut at = 1 + 4;
  let dcid_len = usize::from(*datagram.get(at)?);
  at = at + 1 + dcid_len;
  let scid_len = usize::from(*datagram.get(at)?);
  at += 1;
  Some(datagram.get(at..at + scid_len)?.to_vec())
}

/// The total length of the first long-header packet of `datagram` and the offset of its packet
/// number (RFC 9000 section 17.2), so coalesced packets can be split.
fn long_header_bounds(datagram: &[u8]) -> Option<(usize, usize)> {
  let first = *datagram.first()?;
  if first & 0x80 == 0 {
    return None;
  }
  let mut at = 1 + 4;
  let dcid_len = usize::from(*datagram.get(at)?);
  at = at + 1 + dcid_len;
  let scid_len = usize::from(*datagram.get(at)?);
  at = at + 1 + scid_len;
  if (first & 0x30) >> 4 == 0b00 {
    // Initial: a token length and token precede the Length field.
    let (token_len, tvl) = read_varint(datagram.get(at..)?)?;
    at = at.checked_add(tvl)?.checked_add(usize::try_from(token_len).ok()?)?;
  }
  let (length, lvl) = read_varint(datagram.get(at..)?)?;
  let pn_offset = at.checked_add(lvl)?;
  let total = pn_offset.checked_add(usize::try_from(length).ok()?)?;
  Some((total, pn_offset))
}

#[cfg(test)]
mod tests {
  use super::*;

  // A full client→server Initial packet round-trips through the harness's own long-header codec:
  // build it with the client Initial keys, then strip protection and AEAD with the server Initial
  // keys derived from the same DCID (RFC 9001 appendix A path). This exercises the header
  // protection sample offset, the 4-byte packet number, the Length field and the AEAD AAD — the
  // framing that the floods depend on — without a live server.
  #[test]
  fn initial_packet_round_trips() {
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let scid = [1u8, 2, 3, 4];
    let client = initial_level(&dcid);
    let server = server_initial_level(&dcid);
    let mut payload = Vec::new();
    encode_crypto(&mut payload, 0, b"hello quic");
    let packet = build_packet(INITIAL, &dcid, &scid, 7, &client.local, &payload, 1200);
    assert!(packet.len() >= 1200);
    let Some((_, pn_off)) = long_header_bounds(&packet) else { panic!("bounds") };
    // Decrypt with the server-side Initial keys (server's `remote` = client→server decrypt).
    let (frames, pn) = decrypt_packet(&server, None, &packet, pn_off).expect("decrypt");
    assert_eq!(pn, 7);
    let crypto = scan_crypto(&frames);
    assert_eq!(crypto, vec![(0u64, b"hello quic".to_vec())]);
  }

  #[test]
  fn pn_decoding_follows_rfc9000_appendix_a() {
    // RFC 9000 appendix A.3: largest 0xa82f30ea, truncated 0x9b32, pn_len 2 → 0xa82f9b32.
    assert_eq!(decode_pn(Some(0xa82f_30ea), 0x9b32, 2), 0xa82f_9b32);
    assert_eq!(decode_pn(None, 0, 4), 0);
    assert_eq!(decode_pn(Some(5), 6, 1), 6);
  }

  #[test]
  fn ack_many_has_the_range_count() {
    let ack = frames::ack_many(3, 10_000);
    assert_eq!(ack[0], 0x02);
    // The frame is bounded: a two-value tail per range, so well under a megabyte.
    assert!(ack.len() < 40_000);
  }

  fn server_initial_level(dcid: &[u8]) -> Level {
    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256.tls13().unwrap();
    let algo = suite.quic.unwrap();
    Keys::initial(Version::V1, suite, algo, dcid, rustls::Side::Server).into()
  }

  // A live smoke test of the whole handshake and the PING flood against a soak-server-h3 on
  // 127.0.0.1:8443 (ignored by default: run with the server up, `cargo test ... -- --ignored
  // smoke_handshake`). Confirms the raw 1-RTT client completes the TLS handshake and that a PING
  // flood draws H3_EXCESSIVE_LOAD (App 0x0107).
  #[tokio::test]
  #[ignore = "needs a running soak-server-h3 on 127.0.0.1:8443"]
  async fn smoke_handshake_and_ping_flood() {
    let target = "127.0.0.1:8443".parse().unwrap();
    let mut client = OneRttClient::connect(target).await.expect("handshake");
    for _ in 0..40u32 {
      client.send_1rtt(&frames::pings(1200)).await.expect("send");
    }
    let close = client.wait_close(Duration::from_secs(3)).await;
    eprintln!("smoke close = {close:?}");
    assert_eq!(close, Close::App(0x0107));
  }

  // Runs the whole 1-RTT flood battery against a live soak-server-h3 on 127.0.0.1:8443 and prints
  // each result (ignored by default). A quick way to validate every close code without the full
  // soak harness.
  #[tokio::test]
  #[ignore = "needs a running soak-server-h3 on 127.0.0.1:8443"]
  async fn smoke_all_floods() {
    let target = "127.0.0.1:8443".parse().unwrap();
    let results = crate::quic::scenario::onertt_floods(target).await;
    let mut failed = Vec::new();
    for r in &results {
      eprintln!("{} pass={} — {}", r.name, r.pass, r.detail);
      if !r.pass {
        failed.push(r.name.clone());
      }
    }
    assert!(failed.is_empty(), "failed: {failed:?}");
  }
}
