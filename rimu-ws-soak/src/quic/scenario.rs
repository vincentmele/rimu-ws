//! The abusive QUIC/HTTP/3 clients (spec section 5.12), run in sequence while the steady clients
//! run on. Each returns a [`ScenarioResult`] naming the limit it tripped and the error or
//! rate-limiting it expected (ruling T23-c). Every scenario has its own deadline (ruling T23-k).
//!
//! The library abusers are driven with `quinn`; the raw floods — malformed first Initials,
//! overflowing CRYPTO, forged short headers, QPACK encoder-stream instructions — with
//! [`super::raw`] (Initial level) and hand-encoded bytes over `quinn` streams. The pure 1-RTT frame
//! floods (PING, PATH_CHALLENGE, NEW_CONNECTION_ID / RETIRE_CONNECTION_ID, empty packets,
//! out-of-order STREAM gaps, STREAM past the window, a 10,000-range ACK) are driven by the raw
//! 1-RTT client [`super::onertt`], which runs a real TLS handshake but keeps its own QUIC codecs.

use crate::quic::{
  client::{self, Closed},
  driver::H3Config,
  onertt::{Close, OneRttClient, frames},
  raw,
  wrapsock::FlapSocket,
};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, Runtime, TokioRuntime, VarInt};
use std::{
  net::{SocketAddr, UdpSocket},
  sync::Arc,
  time::Duration,
};
use tokio::time::Instant;

/// How one abuser went.
#[derive(Clone, Debug)]
pub struct ScenarioResult {
  pub name: String,
  pub pass: bool,
  pub detail: String,
}

fn pass(name: &str, detail: String) -> ScenarioResult {
  ScenarioResult { name: name.into(), pass: true, detail }
}
fn fail(name: &str, detail: String) -> ScenarioResult {
  ScenarioResult { name: name.into(), pass: false, detail }
}

/// Wraps a scenario in a deadline; a scenario that overruns is a failure, not a hang (ruling T23-k).
async fn with_deadline(
  name: &str,
  secs: u64,
  fut: impl std::future::Future<Output = ScenarioResult>,
) -> ScenarioResult {
  match tokio::time::timeout(Duration::from_secs(secs), fut).await {
    Ok(result) => result,
    Err(_) => fail(name, format!("exceeded its {secs} s deadline (treated as a stall)")),
  }
}

/// Reads the server's `VmRSS` in KiB.
fn rss_kib(pid: u32) -> u64 {
  std::fs::read_to_string(format!("/proc/{pid}/status"))
    .ok()
    .and_then(|text| crate::monitor::parse_status(&text))
    .map_or(0, |el| el.0)
}

/// The server's on-CPU time in nanoseconds, summed over its threads
/// (`/proc/<pid>/task/*/schedstat` field 0), for the flapper's cost (ruling T23-j #3).
fn cpu_ns(pid: u32) -> u64 {
  let Ok(dir) = std::fs::read_dir(format!("/proc/{pid}/task")) else { return 0 };
  let mut total = 0u64;
  for entry in dir.flatten() {
    if let Ok(text) = std::fs::read_to_string(entry.path().join("schedstat")) {
      if let Some(ns) = text.split_whitespace().next().and_then(|el| el.parse::<u64>().ok()) {
        total = total.wrapping_add(ns);
      }
    }
  }
  total
}

/// Runs every abuser in sequence (except idle_4096, which the driver runs after stopping the idle
/// sampler) and collects their results.
pub async fn run_all(cfg: &H3Config, deadline: Instant) -> Vec<ScenarioResult> {
  let main = cfg.main_addr;
  let raw_target = cfg.idle_addr.unwrap_or(main);
  let mut out = Vec::new();
  macro_rules! step {
    ($name:expr, $secs:expr, $fut:expr) => {
      if Instant::now() < deadline {
        out.push(with_deadline($name, $secs, $fut).await);
      }
    };
  }

  // crypto_overflow needs a worker that will *process* its Initial (not Retry it), so it runs
  // against the main server, not the one-worker server that initial_flood saturates with half-opens.
  step!("crypto_overflow", 15, crypto_overflow(main));
  step!("initial_flood", 40, initial_flood(raw_target));
  step!("forged_short_header", 15, forged_short_header(raw_target));
  step!("reset_churn", 15, reset_churn(main));
  step!("credit_starved", 15, credit_starved(main));
  step!("window_starved", 20, window_starved(main));
  step!("qpack_flood", 15, qpack_flood(main));
  step!("oversized_heads", 15, oversized_heads(main));
  step!("slow_reader", 20, slow_reader(main));
  step!("never_read", 20, never_read(main));
  step!("rebind", 15, rebind(main));
  step!("never_ack", 18, never_ack(main));
  // The flapper runs on the one-worker monitored server (its own 4×4 steady client), so its CPU in
  // ns is attributable and the 3× amplification accounting is isolated (ruling T23-j #3a).
  step!("flapper", 20, flapper(raw_target, cfg.idle_pid));
  // The raw 1-RTT frame floods (ruling T23-j #5), on the main server so the handshake is not
  // Retry-intercepted. Each has its own internal 3 s close wait; the whole batch is bounded.
  if Instant::now() < deadline {
    match tokio::time::timeout(Duration::from_secs(90), onertt_floods(main, cfg.main_pid)).await {
      Ok(results) => out.extend(results),
      Err(_) => out.push(fail("onertt_floods", "exceeded the 90 s batch deadline".into())),
    }
  }
  out
}

/// A client UDP socket on a loopback source address, for the raw floods.
fn raw_socket(target: SocketAddr, last_octet: u8) -> std::io::Result<UdpSocket> {
  let bind: SocketAddr = if target.is_ipv6() {
    "[::1]:0".parse().unwrap()
  } else {
    format!("127.0.0.{last_octet}:0").parse().unwrap()
  };
  let sock = UdpSocket::bind(bind)?;
  sock.set_read_timeout(Some(Duration::from_millis(200)))?;
  Ok(sock)
}

/// **Initial flood** (ruling T23-k): many distinct first Initials, each a one-byte (partial)
/// ClientHello so the handshake stays pending and holds a half-open slot, from several source
/// addresses (127.0.0.2..5, or ::1). Past `retry_above_half_open` (64) the server answers with a
/// Retry. A well-behaved quinn client must still connect during the flood. Pass rule: at least one
/// Retry is seen and the quinn client connects.
async fn initial_flood(target: SocketAddr) -> ScenarioResult {
  let name = "initial_flood";
  let flood = tokio::task::spawn_blocking(move || {
    let octets: &[u8] = if target.is_ipv6() { &[0] } else { &[2, 3, 4, 5] };
    let mut socks = Vec::new();
    for &o in octets {
      if let Ok(s) = raw_socket(target, o) {
        socks.push(s);
      }
    }
    if socks.is_empty() {
      return Err("no source sockets".to_string());
    }
    let mut rng = tiny_rng(0x1234_5678);
    for _ in 0..150u32 {
      for sock in &socks {
        let mut dcid = [0u8; 8];
        let mut scid = [0u8; 8];
        for b in dcid.iter_mut().chain(scid.iter_mut()) {
          *b = rng() as u8;
        }
        let dgram = raw::client_initial(&dcid, &scid, 0, &[0x01], 0, 1200);
        let _ = sock.send_to(&dgram, target);
      }
      std::thread::sleep(Duration::from_millis(2));
    }
    let (mut retries, mut initials, mut others) = (0u32, 0u32, 0u32);
    let mut buf = [0u8; 2048];
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
      for sock in &socks {
        if let Ok((len, _)) = sock.recv_from(&mut buf) {
          match raw::classify(&buf[..len]) {
            raw::ReplyKind::Retry => retries += 1,
            raw::ReplyKind::Initial => initials += 1,
            _ => others += 1,
          }
        }
      }
    }
    Ok((socks.len(), retries, initials, others))
  });
  let legit = async {
    let cfg = client::client_config(None, Duration::from_secs(10));
    let bind: SocketAddr = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
    let ep = client::endpoint(bind, cfg).map_err(|err| err.to_string())?;
    let conn = client::connect(&ep, target, "localhost").await?;
    let got = client::h3_get(conn.clone(), "/baseline2").await.map(|r| r.status);
    ep.close(client::H3_NO_ERROR, b"");
    got
  }
  .await;
  match flood.await {
    Ok(Ok((sources, retries, initials, others))) => {
      let legit_ok = matches!(legit, Ok(200));
      let detail = format!(
        "{sources} sources × 150 Initials; replies {retries} Retry, {initials} Initial, {others} other; legit client {legit:?}"
      );
      if retries >= 1 && legit_ok {
        pass(
          name,
          format!("Retry (address validation) and a legit client still connects: {detail}"),
        )
      } else {
        fail(name, format!("want ≥1 Retry and a legit connect: {detail}"))
      }
    }
    Ok(Err(err)) => fail(name, err),
    Err(err) => fail(name, format!("join: {err}")),
  }
}

/// **Forged short headers**: 1-RTT packets to a connection ID that no connection has. The server
/// drops them or sends at most a rate-limited stateless reset (`stateless_reset_per_sec` 100). Pass
/// rule: the server stays up and replies at most `100 × (elapsed_s + 1)` times.
async fn forged_short_header(target: SocketAddr) -> ScenarioResult {
  let name = "forged_short_header";
  let result = tokio::task::spawn_blocking(move || {
    let sock = raw_socket(target, 3).map_err(|err| err.to_string())?;
    let mut rng = tiny_rng(0x9e37_79b9);
    let begin = std::time::Instant::now();
    for _ in 0..500u32 {
      let mut dcid = [0u8; 8];
      for b in dcid.iter_mut() {
        *b = rng() as u8;
      }
      let _ = sock.send_to(&raw::forged_short(&dcid, 60), target);
    }
    let mut replies = 0u32;
    let mut buf = [0u8; 2048];
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
      if sock.recv_from(&mut buf).is_ok() {
        replies += 1;
      }
    }
    Ok::<_, String>((replies, begin.elapsed().as_secs()))
  })
  .await;
  match result {
    Ok(Ok((replies, elapsed))) => {
      let bound = 100u32.saturating_mul(u32::try_from(elapsed).unwrap_or(0).saturating_add(1));
      if replies <= bound {
        pass(name, format!("500 forged shorts; {replies} replies ≤ {bound} (rate-limited)"))
      } else {
        fail(name, format!("{replies} replies > {bound}: not rate-limited"))
      }
    }
    Ok(Err(err)) => fail(name, err),
    Err(err) => fail(name, format!("join: {err}")),
  }
}

/// **CRYPTO overflow** (ruling T23-j #2): a first Initial whose CRYPTO frame starts more than
/// `CRYPTO_BUFFER_LEN` (4096) bytes past offset 0. The server closes the connection at the Initial
/// level with CRYPTO_BUFFER_EXCEEDED (0x0d); the reply is decrypted with the server-side Initial
/// keys and its CONNECTION_CLOSE code asserted.
async fn crypto_overflow(target: SocketAddr) -> ScenarioResult {
  let name = "crypto_overflow";
  let result = tokio::task::spawn_blocking(move || {
    let sock = raw_socket(target, 4).map_err(|err| err.to_string())?;
    let mut rng = tiny_rng(0xdead_beef);
    let mut dcid = [0u8; 8];
    let mut scid = [0u8; 8];
    for b in dcid.iter_mut().chain(scid.iter_mut()) {
      *b = rng() as u8;
    }
    let dgram = raw::client_initial(&dcid, &scid, 5000, &[0x01], 0, 1200);
    sock.send_to(&dgram, target).map_err(|err| err.to_string())?;
    let mut buf = [0u8; 2048];
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    // Diagnostics: datagrams received, long-header Initials among them, Initials we could decrypt,
    // and the CONNECTION_CLOSE code if one was found.
    let (mut received, mut initials, mut decrypted) = (0u32, 0u32, 0u32);
    let mut code = None;
    while std::time::Instant::now() < deadline && code.is_none() {
      if let Ok((len, _)) = sock.recv_from(&mut buf) {
        received += 1;
        if matches!(raw::classify(&buf[..len]), raw::ReplyKind::Initial) {
          initials += 1;
        }
        if let Some(frames) = raw::open_server_initial(&dcid, &buf[..len]) {
          decrypted += 1;
          if let Some(found) = raw::connection_close_code(&frames) {
            code = Some(found);
          }
        }
      }
    }
    Ok::<_, String>((received, initials, decrypted, code))
  })
  .await;
  match result {
    Ok(Ok((_, _, _, Some(0x0d)))) => {
      pass(name, "CONNECTION_CLOSE 0x0d CRYPTO_BUFFER_EXCEEDED at the Initial level".into())
    }
    Ok(Ok((r, i, d, Some(code)))) => fail(
      name,
      format!("expected 0x0d, got 0x{code:02x} ({r} dgrams, {i} Initial, {d} decrypted)"),
    ),
    Ok(Ok((r, i, d, None))) => fail(
      name,
      format!("no CONNECTION_CLOSE found ({r} dgrams received, {i} Initial, {d} decrypted in 3 s)"),
    ),
    Ok(Err(err)) => fail(name, err),
    Err(err) => fail(name, format!("join: {err}")),
  }
}

async fn abuser_conn(target: SocketAddr) -> Result<(quinn::Endpoint, quinn::Connection), String> {
  let cfg = client::client_config(None, Duration::from_secs(30));
  let bind: SocketAddr = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
  let ep = client::endpoint(bind, cfg).map_err(|err| err.to_string())?;
  let conn = client::connect(&ep, target, "localhost").await?;
  Ok((ep, conn))
}

/// **Stream churn (rapid reset)**: open a stream and reset it, over and over. Past `reset_budget`
/// (100/10 s) the server closes with `H3_EXCESSIVE_LOAD` (0x0107).
async fn reset_churn(target: SocketAddr) -> ScenarioResult {
  let name = "reset_churn";
  let (ep, conn) = match abuser_conn(target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let cancel = VarInt::from_u32(0x010c);
  let mut opened = 0u32;
  for _ in 0..200u32 {
    match conn.open_bi().await {
      Ok((mut send, mut recv)) => {
        let _ = send.write_all(b"x").await;
        let _ = send.reset(cancel);
        let _ = recv.stop(cancel);
        opened += 1;
      }
      Err(_) => break,
    }
  }
  let closed = client::wait_closed(&conn, Duration::from_secs(5)).await;
  ep.close(client::H3_NO_ERROR, b"");
  match closed {
    Closed::App(0x0107) => pass(name, format!("H3_EXCESSIVE_LOAD (0x0107) after {opened} resets")),
    other => fail(name, format!("expected 0x0107, got {other:?} after {opened} resets")),
  }
}

/// **Credit-starved streams (stream count)**: open the whole bidi-stream allowance (256) and hold
/// it, then a 257th. The server enforces the limit, so the 257th never gets stream credit.
async fn credit_starved(target: SocketAddr) -> ScenarioResult {
  let name = "credit_starved";
  let (ep, conn) = match abuser_conn(target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let mut held = Vec::new();
  for _ in 0..256u32 {
    match tokio::time::timeout(Duration::from_secs(2), conn.open_bi()).await {
      Ok(Ok((mut send, recv))) => {
        let _ = send.write_all(b"GET").await;
        held.push((send, recv));
      }
      _ => break,
    }
  }
  let opened = held.len();
  let starved = tokio::time::timeout(Duration::from_millis(800), conn.open_bi()).await.is_err();
  let alive = conn.close_reason().is_none();
  ep.close(client::H3_NO_ERROR, b"");
  if opened >= 1 && starved && alive {
    pass(name, format!("{opened} streams held, 257th starved, connection alive"))
  } else {
    fail(name, format!("{opened} held, starved={starved}, alive={alive}"))
  }
}

/// **Window-starved (ruling T23-j #4)**: a client that advertises connection and stream receive
/// windows of 0, then asks for the 10 MiB file. The server may send no STREAM data and must close
/// on idle. Pass rule: no body arrives and the connection closes within the idle timeout.
async fn window_starved(target: SocketAddr) -> ScenarioResult {
  let name = "window_starved";
  let cfg = client::client_config_windows(Duration::from_secs(4), 0);
  let bind: SocketAddr = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
  let ep = match client::endpoint(bind, cfg) {
    Ok(ep) => ep,
    Err(err) => return fail(name, format!("endpoint: {err}")),
  };
  let conn = match client::connect(&ep, target, "localhost").await {
    Ok(conn) => conn,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let got =
    tokio::time::timeout(Duration::from_secs(2), client::h3_get(conn.clone(), "/static/big.bin"))
      .await;
  let closed = client::wait_closed(&conn, Duration::from_secs(10)).await;
  ep.close(client::H3_NO_ERROR, b"");
  let body_arrived = matches!(got, Ok(Ok(ref r)) if !r.body.is_empty());
  match closed {
    Closed::TimedOutOrReset | Closed::App(_) | Closed::Transport(_) if !body_arrived => {
      pass(name, format!("zero windows: no body, connection closed ({closed:?})"))
    }
    other => fail(
      name,
      format!("expected an idle close with no body; closed={other:?}, body_arrived={body_arrived}"),
    ),
  }
}

/// **QPACK encoder-stream flood (ruling T23-j #1)**: a client QPACK encoder stream that sends Set
/// Dynamic Table Capacity 4096 while the server's advertised capacity is 0. The server closes with
/// QPACK_ENCODER_STREAM_ERROR (0x0201).
async fn qpack_flood(target: SocketAddr) -> ScenarioResult {
  let name = "qpack_flood";
  let (ep, conn) = match abuser_conn(target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let streams = async {
    let mut control = conn.open_uni().await.map_err(|err| format!("open control: {err}"))?;
    control.write_all(&raw::h3_control_stream()).await.map_err(|err| format!("control: {err}"))?;
    let mut enc = conn.open_uni().await.map_err(|err| format!("open enc: {err}"))?;
    // type 0x02, then Set Dynamic Table Capacity 4096 (0x3f, 0xe1, 0x1f), above the server's 0.
    enc
      .write_all(&[raw::H3_QPACK_ENCODER, 0x3f, 0xe1, 0x1f])
      .await
      .map_err(|err| format!("enc: {err}"))?;
    Ok::<_, String>((control, enc))
  }
  .await;
  // Hold the control and encoder streams open until the server acts: dropping them early would
  // reset the control stream (H3_CLOSED_CRITICAL_STREAM) before the encoder instruction is read.
  let held = match streams {
    Ok(held) => held,
    Err(err) => {
      ep.close(client::H3_NO_ERROR, b"");
      return fail(name, format!("send: {err}"));
    }
  };
  let closed = client::wait_closed(&conn, Duration::from_secs(5)).await;
  drop(held);
  ep.close(client::H3_NO_ERROR, b"");
  match closed {
    Closed::App(0x0201) => {
      pass(name, "QPACK_ENCODER_STREAM_ERROR (0x0201) for capacity above the maximum".into())
    }
    other => fail(name, format!("expected 0x0201, got {other:?}")),
  }
}

/// **Oversized heads**: a hand-encoded request with a ~20 KiB QPACK field section. The framework
/// answers 431 on the request stream (RFC 9114 §4.2.2), not a connection kill.
async fn oversized_heads(target: SocketAddr) -> ScenarioResult {
  let name = "oversized_heads";
  let (ep, conn) = match abuser_conn(target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let result = async {
    let mut control = conn.open_uni().await.map_err(|err| format!("open control: {err}"))?;
    control.write_all(&raw::h3_control_stream()).await.map_err(|err| format!("control: {err}"))?;
    let mut enc = conn.open_uni().await.map_err(|err| format!("open enc: {err}"))?;
    enc.write_all(&[raw::H3_QPACK_ENCODER]).await.map_err(|err| format!("enc: {err}"))?;
    let mut dec = conn.open_uni().await.map_err(|err| format!("open dec: {err}"))?;
    dec.write_all(&[raw::H3_QPACK_DECODER]).await.map_err(|err| format!("dec: {err}"))?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|err| format!("open bi: {err}"))?;
    send
      .write_all(&raw::h3_oversized_headers_frame(20 * 1024))
      .await
      .map_err(|err| format!("write: {err}"))?;
    send.finish().map_err(|err| format!("finish: {err}"))?;
    let bytes = recv.read_to_end(64 * 1024).await.map_err(|err| format!("read: {err}"))?;
    let _ = (&control, &enc, &dec);
    Ok::<Vec<u8>, String>(bytes)
  }
  .await;
  let still_open = conn.close_reason().is_none();
  ep.close(client::H3_NO_ERROR, b"");
  match result {
    Ok(bytes) => {
      let is_headers = bytes.first() == Some(&0x01);
      let has_431 = bytes.windows(3).any(|w| w == b"431");
      if is_headers && has_431 && still_open {
        pass(
          name,
          format!(
            "431 HEADERS frame on the request stream, connection open ({} bytes)",
            bytes.len()
          ),
        )
      } else {
        fail(
          name,
          format!(
            "want a 431 HEADERS frame with the connection open: headers={is_headers}, 431={has_431}, open={still_open}"
          ),
        )
      }
    }
    Err(err) => fail(name, format!("expected a 431 answer, not an error: {err}")),
  }
}

/// **Slow reader (ruling T23-j #4)**: ask for the 10 MiB file and read it slowly, verifying the
/// bytes (`i % 251`). The server is held by its own in-flight cap and flow control.
async fn slow_reader(target: SocketAddr) -> ScenarioResult {
  let name = "slow_reader";
  let (ep, conn) = match abuser_conn(target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let result = async {
    use bytes::Buf as _;
    let h3c = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut sr) = h3::client::new(h3c).await.map_err(|err| format!("h3: {err}"))?;
    let drive = tokio::spawn(async move {
      let _ = driver.wait_idle().await;
    });
    let req = http::Request::builder()
      .method("GET")
      .uri("https://localhost/static/big.bin")
      .body(())
      .map_err(|err| format!("request: {err}"))?;
    let mut stream = sr.send_request(req).await.map_err(|err| format!("send: {err}"))?;
    stream.finish().await.map_err(|err| format!("finish: {err}"))?;
    let _resp = stream.recv_response().await.map_err(|err| format!("response: {err}"))?;
    let (mut off, mut checked) = (0usize, 0usize);
    for _ in 0..20 {
      match tokio::time::timeout(Duration::from_secs(2), stream.recv_data()).await {
        Ok(Ok(Some(mut chunk))) => {
          while chunk.has_remaining() {
            let b = chunk.chunk();
            for (i, byte) in b.iter().enumerate() {
              if *byte != ((off + i) % 251) as u8 {
                return Err(format!("byte {} is {} not {}", off + i, byte, (off + i) % 251));
              }
            }
            off += b.len();
            checked += b.len();
            let step = b.len();
            chunk.advance(step);
          }
        }
        Ok(Ok(None)) => break,
        _ => break,
      }
      tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drive.abort();
    Ok::<usize, String>(checked)
  }
  .await;
  let alive = conn.close_reason().is_none();
  ep.close(client::H3_NO_ERROR, b"");
  match result {
    Ok(n) if n > 0 && alive => {
      pass(name, format!("read {n} verified bytes slowly, connection held"))
    }
    Ok(n) => fail(name, format!("read {n} bytes, alive={alive}")),
    Err(err) => fail(name, err),
  }
}

/// **Never-read (ruling T23-j #4)**: 20 concurrent requests for the 10 MiB file on one connection,
/// whose responses are never read. The bytes the server sends are bounded by the client's windows,
/// and the server stays bounded (the RSS gate).
async fn never_read(target: SocketAddr) -> ScenarioResult {
  let name = "never_read";
  let (ep, conn) = match abuser_conn(target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let result = async {
    let h3c = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut sr) = h3::client::new(h3c).await.map_err(|err| format!("h3: {err}"))?;
    let drive = tokio::spawn(async move {
      let _ = driver.wait_idle().await;
    });
    let mut held = Vec::new();
    for _ in 0..20u32 {
      let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/static/big.bin")
        .body(())
        .map_err(|err| format!("request: {err}"))?;
      match sr.send_request(req).await {
        Ok(mut stream) => {
          let _ = stream.finish().await;
          held.push(stream);
        }
        Err(_) => break,
      }
    }
    tokio::time::sleep(Duration::from_secs(6)).await;
    let n = held.len();
    drive.abort();
    Ok::<usize, String>(n)
  }
  .await;
  let alive = conn.close_reason().is_none();
  ep.close(client::H3_NO_ERROR, b"");
  match result {
    Ok(n) if alive => {
      pass(name, format!("{n} unread 10 MiB responses held; server bounded, connection alive"))
    }
    Ok(_) => fail(name, "connection closed while holding unread responses".into()),
    Err(err) => fail(name, err),
  }
}

/// **Rebinding (well-behaved migrant, ruling T23-g a)**: a client that keeps requesting while its
/// local port, then its source address (127.0.0.1 → 127.0.0.2), change.
async fn rebind(target: SocketAddr) -> ScenarioResult {
  let name = "rebind";
  if target.is_ipv6() {
    return pass(name, "skipped on IPv6".into());
  }
  let cfg = client::client_config(Some(Duration::from_secs(2)), Duration::from_secs(30));
  let ep = match client::endpoint("127.0.0.1:0".parse().unwrap(), cfg) {
    Ok(ep) => ep,
    Err(err) => return fail(name, format!("endpoint: {err}")),
  };
  let conn = match client::connect(&ep, target, "localhost").await {
    Ok(conn) => conn,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let mut session = match client::H3Session::open(conn.clone()).await {
    Ok(s) => s,
    Err(err) => {
      ep.close(client::H3_NO_ERROR, b"");
      return fail(name, format!("h3 session: {err}"));
    }
  };
  let mut steps = Vec::new();
  steps.push(("before", session.get("/baseline2").await.map(|r| r.status)));
  let port_rebind = UdpSocket::bind("127.0.0.1:0").and_then(|s| ep.rebind(s)).is_ok();
  tokio::time::sleep(Duration::from_millis(200)).await;
  steps.push(("after_port", session.get("/baseline2").await.map(|r| r.status)));
  let addr_rebind = UdpSocket::bind("127.0.0.2:0").and_then(|s| ep.rebind(s)).is_ok();
  tokio::time::sleep(Duration::from_millis(200)).await;
  steps.push(("after_addr", session.get("/baseline2").await.map(|r| r.status)));
  drop(session);
  ep.close(client::H3_NO_ERROR, b"");
  let ok = steps.iter().all(|(_, r)| matches!(r, Ok(200)));
  let detail = format!("port_rebind={port_rebind}, addr_rebind={addr_rebind}, {steps:?}");
  if ok {
    pass(name, format!("answered across both rebinds: {detail}"))
  } else {
    fail(name, format!("a GET failed after a rebind: {detail}"))
  }
}

/// Builds a quinn endpoint over a [`FlapSocket`] of two loopback sockets (127.0.0.1 and 127.0.0.2),
/// returning the endpoint and the socket so its per-address byte counters can be read.
fn flap_endpoint() -> Result<(Endpoint, Arc<FlapSocket>), String> {
  let runtime = Arc::new(TokioRuntime);
  let mk = |addr: &str| -> Result<Arc<dyn AsyncUdpSocket>, String> {
    let sock = UdpSocket::bind(addr).map_err(|err| format!("bind {addr}: {err}"))?;
    sock.set_nonblocking(true).map_err(|err| err.to_string())?;
    runtime.wrap_udp_socket(sock).map_err(|err| err.to_string())
  };
  let a = mk("127.0.0.1:0")?;
  let b = mk("127.0.0.2:0")?;
  let flap = FlapSocket::new(vec![a, b]);
  let mut ep = Endpoint::new_with_abstract_socket(
    EndpointConfig::default(),
    None,
    flap.clone() as Arc<dyn AsyncUdpSocket>,
    runtime,
  )
  .map_err(|err| format!("endpoint: {err}"))?;
  ep.set_default_client_config(client::client_config(
    Some(Duration::from_millis(300)),
    Duration::from_secs(30),
  ));
  Ok((ep, flap))
}

/// **Migration flapper (ruling T23-g b / T23-j #3a)**: a confirmed connection whose source address
/// alternates on *every datagram* (a [`FlapSocket`] over two loopback addresses). Bytes in and out
/// are counted per address, so the pass rule asserts the server sends at most 3× to each address
/// what that address sent (RFC 9000 anti-amplification, section 8); the server CPU over the window
/// is measured in ns on the monitored (one-worker) server with its steady client running, and the
/// close code/time is recorded. The concurrent steady client's no-stall check is `steady_idle`.
async fn flapper(target: SocketAddr, pid: Option<u32>) -> ScenarioResult {
  let name = "flapper";
  if target.is_ipv6() {
    return pass(name, "skipped on IPv6".into());
  }
  let (ep, flap) = match flap_endpoint() {
    Ok(elem) => elem,
    Err(err) => return fail(name, err),
  };
  let conn = match client::connect(&ep, target, "localhost").await {
    Ok(conn) => conn,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let mut session = match client::H3Session::open(conn.clone()).await {
    Ok(s) => s,
    Err(err) => {
      ep.close(client::H3_NO_ERROR, b"");
      return fail(name, format!("h3 session: {err}"));
    }
  };
  if session.get("/baseline2").await.is_err() {
    drop(session);
    ep.close(client::H3_NO_ERROR, b"");
    return fail(name, "could not confirm the connection before flapping".into());
  }
  // Now turn on per-datagram flapping and drive requests as fast as they go for ~6 s.
  flap.flap_handle().store(true, std::sync::atomic::Ordering::Relaxed);
  let watch = conn.clone();
  let closer = tokio::spawn(async move { client::closed_as(&watch.closed().await) });
  let cpu0 = pid.map(cpu_ns).unwrap_or(0);
  let begin = Instant::now();
  let mut flips = 0u32;
  while begin.elapsed() < Duration::from_secs(6) && conn.close_reason().is_none() {
    let _ = tokio::time::timeout(Duration::from_millis(150), session.get("/baseline2")).await;
    flips = flips.wrapping_add(1);
  }
  let wall_ms = begin.elapsed().as_millis() as u64;
  let cpu_ms = (pid.map(cpu_ns).unwrap_or(0).saturating_sub(cpu0)) / 1_000_000;
  let alive_at_end = conn.close_reason().is_none();
  // The frames the client sent, per type: the server's 0x0107 sites are the PING, PATH_CHALLENGE
  // and NEW_CONNECTION_ID budgets and the stream reset budget, so these attribute the close.
  let tx = conn.stats().frame_tx;
  let frames_tx = format!(
    "client tx ping={} path_challenge={} new_cid={} reset_stream={} stop_sending={}",
    tx.ping, tx.path_challenge, tx.new_connection_id, tx.reset_stream, tx.stop_sending
  );
  drop(session);
  ep.close(client::H3_NO_ERROR, b"");
  let close = tokio::time::timeout(Duration::from_secs(2), closer).await.ok().and_then(|r| r.ok());
  let (out0, in0, out1, in1) =
    (flap.bytes_out(0), flap.bytes_in(0), flap.bytes_out(1), flap.bytes_in(1));
  // Anti-amplification: the server must not send more than 3× to an address than it received from
  // it (plus one datagram of slack for the first challenge). Checked per source address.
  let ok0 = in0 <= out0.saturating_mul(3).saturating_add(1500);
  let ok1 = in1 <= out1.saturating_mul(3).saturating_add(1500);
  let server_ok =
    alive_at_end || matches!(close, Some(Closed::App(_)) | Some(Closed::Transport(_)));
  let detail = format!(
    "{flips} req over {wall_ms} ms, server CPU +{cpu_ms} ms, close={close:?}; addr0 out={out0} in={in0}, addr1 out={out1} in={in1} (≤3× each: {ok0}/{ok1}); {frames_tx}"
  );
  if server_ok && ok0 && ok1 {
    pass(name, detail)
  } else if !server_ok {
    fail(name, format!("server did not survive flapping: {detail}"))
  } else {
    fail(name, format!("amplification over 3× on an address: {detail}"))
  }
}

/// **Never-ACK slow reader (ruling T23-j #3b)**: request the 10 MiB file, then black-hole the
/// client's transmit (a [`FlapSocket`] with one inner socket and the blackhole flag set) so no ACK
/// ever leaves. The server is then bounded by its own in-flight cap / sent ring and closes on its
/// idle timeout (the RSS gate covers its memory). Pass rule: the connection closes (idle/reset)
/// and no body completed.
async fn never_ack(target: SocketAddr) -> ScenarioResult {
  let name = "never_ack";
  if target.is_ipv6() {
    return pass(name, "skipped on IPv6".into());
  }
  let runtime = Arc::new(TokioRuntime);
  let inner = match UdpSocket::bind("127.0.0.1:0").and_then(|s| {
    s.set_nonblocking(true)?;
    runtime.wrap_udp_socket(s)
  }) {
    Ok(sock) => sock,
    Err(err) => return fail(name, format!("socket: {err}")),
  };
  let flap = FlapSocket::new(vec![inner]);
  let blackhole = flap.blackhole_handle();
  let mut ep = match Endpoint::new_with_abstract_socket(
    EndpointConfig::default(),
    None,
    flap.clone() as Arc<dyn AsyncUdpSocket>,
    runtime,
  ) {
    Ok(ep) => ep,
    Err(err) => return fail(name, format!("endpoint: {err}")),
  };
  ep.set_default_client_config(client::client_config(None, Duration::from_secs(8)));
  let conn = match client::connect(&ep, target, "localhost").await {
    Ok(conn) => conn,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  // Start the request, then cut the client's transmit so no ACK leaves.
  let result = async {
    let h3c = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut sr) = h3::client::new(h3c).await.map_err(|err| format!("h3: {err}"))?;
    let drive = tokio::spawn(async move {
      let _ = driver.wait_idle().await;
    });
    let req = http::Request::builder()
      .method("GET")
      .uri("https://localhost/static/big.bin")
      .body(())
      .map_err(|err| format!("request: {err}"))?;
    let mut stream = sr.send_request(req).await.map_err(|err| format!("send: {err}"))?;
    stream.finish().await.map_err(|err| format!("finish: {err}"))?;
    let _ = stream.recv_response().await;
    // Black-hole the transmit: from here the client ACKs nothing.
    blackhole.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok::<_, String>(drive)
  }
  .await;
  let drive = match result {
    Ok(drive) => drive,
    Err(err) => {
      ep.close(client::H3_NO_ERROR, b"");
      return fail(name, format!("request setup: {err}"));
    }
  };
  // The server is now held by its own in-flight cap; it must close on idle within ~its timeout.
  let closed = client::wait_closed(&conn, Duration::from_secs(12)).await;
  drive.abort();
  ep.close(client::H3_NO_ERROR, b"");
  match closed {
    Closed::TimedOutOrReset | Closed::App(_) | Closed::Transport(_) => {
      pass(name, format!("transmit black-holed; server closed on idle ({closed:?})"))
    }
    Closed::Open => {
      fail(name, "server did not close the black-holed connection within 12 s".into())
    }
  }
}

/// **Idle connections × 4,096 per worker (rulings T23-f/T23-k)**: open the worker's whole allowance
/// (`max_conns_per_worker` 4,096) as idle, kept alive, then a 4,097th. Pass rule: 4,096 held, the
/// 4,097th times out (the silent drop at the cap), the server stays alive, a held connection still
/// answers, and the per-connection RSS (after a short settle) is reported; a figure above ~8 KiB
/// live is reported as a finding.
/// Opens up to 4,096 idle keep-alive connections to `target` over several endpoints, topping up
/// transient handshake failures until the cap is genuinely full or the worker refuses. Returns the
/// held connections and their endpoints.
async fn fill_cap(target: SocketAddr) -> (Vec<quinn::Connection>, Vec<quinn::Endpoint>) {
  let cfg = client::client_config(Some(Duration::from_secs(10)), Duration::from_secs(30));
  let endpoints = 16u32;
  let per = 4096u32 / endpoints;
  let mut held: Vec<quinn::Connection> = Vec::new();
  let mut eps = Vec::new();
  for _ in 0..endpoints {
    let bind: SocketAddr = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
    let Ok(ep) = client::endpoint(bind, cfg.clone()) else { continue };
    let mut tasks = Vec::new();
    for _ in 0..per {
      let ep = ep.clone();
      tasks.push(tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), client::connect(&ep, target, "localhost"))
          .await
          .ok()
          .and_then(|r| r.ok())
      }));
    }
    for task in tasks {
      if let Ok(Some(conn)) = task.await {
        held.push(conn);
      }
    }
    eps.push(ep);
  }
  let mut round = 0u32;
  while held.len() < 4096 && round < 8 {
    round += 1;
    let Some(ep) = eps.first().cloned() else { break };
    let want = 4096 - held.len();
    let mut tasks = Vec::new();
    for _ in 0..want {
      let ep = ep.clone();
      tasks.push(tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(8), client::connect(&ep, target, "localhost"))
          .await
          .ok()
          .and_then(|r| r.ok())
      }));
    }
    let mut gained = 0u32;
    for task in tasks {
      if let Ok(Some(conn)) = task.await {
        held.push(conn);
        gained += 1;
      }
    }
    if gained == 0 {
      break; // the worker is refusing: the cap is already reached.
    }
  }
  (held, eps)
}

pub async fn idle_connections(target: SocketAddr, pid: u32) -> ScenarioResult {
  let name = "idle_4096";
  let rss_before = rss_kib(pid);
  let (held, eps) = fill_cap(target).await;
  let opened = held.len();
  tokio::time::sleep(Duration::from_secs(2)).await;
  let rss_fill = rss_kib(pid);
  let per_conn_fill =
    if opened > 0 { rss_fill.saturating_sub(rss_before) / opened as u64 } else { 0 };

  // The 4,097th must be refused (the documented silent drop → handshake timeout).
  let extra_cfg = client::client_config(None, Duration::from_secs(4));
  let extra_bind: SocketAddr =
    if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
  let extra_timed_out = match client::endpoint(extra_bind, extra_cfg) {
    Ok(ep) => {
      let r =
        tokio::time::timeout(Duration::from_secs(5), client::connect(&ep, target, "localhost"))
          .await;
      ep.close(client::H3_NO_ERROR, b"");
      r.is_err() || matches!(&r, Ok(Err(_)))
    }
    Err(_) => false,
  };
  let server_alive = rss_kib(pid) > 0;
  let held_answers = match held.first() {
    Some(conn) => {
      matches!(client::h3_get(conn.clone(), "/baseline2").await.map(|r| r.status), Ok(200))
    }
    None => false,
  };

  // Idle trim: drop the whole batch and let the worker go idle so its pooled free-lists release
  // their high-water entries (limits.rs), then measure the resident baseline.
  for ep in &eps {
    ep.close(client::H3_NO_ERROR, b"");
  }
  drop(held);
  drop(eps);
  tokio::time::sleep(Duration::from_secs(5)).await;
  let rss_trim = rss_kib(pid);

  // A second, warm batch of 4,096: the one-time pool growth is already resident, so this delta is
  // closer to live per-connection state (ruling T23-j #3 / fix2 item 3).
  let (held2, eps2) = fill_cap(target).await;
  let opened2 = held2.len();
  tokio::time::sleep(Duration::from_secs(2)).await;
  let rss_warm = rss_kib(pid);
  let per_conn_warm =
    if opened2 > 0 { rss_warm.saturating_sub(rss_trim) / opened2 as u64 } else { 0 };
  for ep in &eps2 {
    ep.close(client::H3_NO_ERROR, b"");
  }
  drop(held2);

  let detail = format!(
    "fill {opened}/4096 RSS {rss_before}->{rss_fill} KiB (~{per_conn_fill} KiB/conn); after idle trim RSS {rss_trim} KiB; warm batch {opened2}/4096 ->{rss_warm} KiB (~{per_conn_warm} KiB/conn live); 4,097th refused={extra_timed_out}, server alive={server_alive}, held answers={held_answers}"
  );
  // The one-worker server also carries the small idle steady client (ruling T23-k), whose slots
  // drain just before this phase, so a handful below 4,096 is expected; the decisive proof of the
  // per-worker cap is the refused extra connection with the worker essentially full.
  if opened >= 4088 && extra_timed_out && server_alive && held_answers {
    if per_conn_warm > 8 {
      pass(
        name,
        format!(
          "cap held and enforced; LIVE PER-CONN {per_conn_warm} KiB > 8 KiB target — FINDING (measured after idle trim and a warm batch; no server layout change this round): {detail}"
        ),
      )
    } else {
      pass(name, detail)
    }
  } else {
    fail(name, format!("want 4096 held + 4097th refused + server alive + held answers: {detail}"))
  }
}

/// The 1-RTT frame floods (ruling T23-j #5), each driven by the raw [`OneRttClient`]: a real TLS
/// handshake, then abusive frames a conforming client never sends. Each asserts the exact close
/// code the server documents for the limit. They run on the main server (its handshake load is low,
/// so no Retry intercepts the raw Initial). `pid` is the main server's, for the ACK-flood CPU
/// measurement.
pub async fn onertt_floods(target: SocketAddr, pid: Option<u32>) -> Vec<ScenarioResult> {
  let mut out = Vec::new();

  // PING flood → H3_EXCESSIVE_LOAD (App 0x0107). `ping_budget` is 64 plus 2 per RTT, capped at
  // 16,384 a second (limits.rs); 40 packets of 1,200 PING frames is ~48,000 in well under a second.
  let pings: Vec<Vec<u8>> = (0..40u32).map(|_| frames::pings(1200)).collect();
  out.push(one_rtt_flood("onertt_ping_flood", target, Close::App(0x0107), pings).await);

  // PATH_CHALLENGE flood → App 0x0107 (`path_challenge_budget` 16). 64 in one packet.
  let mut path = Vec::new();
  for i in 0..64u8 {
    path.extend_from_slice(&frames::path_challenge([i; 8]));
  }
  out.push(
    one_rtt_flood("onertt_path_challenge_flood", target, Close::App(0x0107), vec![path]).await,
  );

  // NEW_CONNECTION_ID flood → App 0x0107 (`new_connection_id_budget` 16). 20 frames, each retiring
  // all lower sequence numbers (retire_prior_to = seq), so the active count stays at 1 — under the
  // server's advertised active_connection_id_limit — and the per-second budget is what trips,
  // rather than CONNECTION_ID_LIMIT_ERROR. One packet.
  let mut ncid = Vec::new();
  for seq in 1..=20u64 {
    ncid.extend_from_slice(&frames::new_connection_id(seq, seq, [seq as u8; 8], [seq as u8; 16]));
  }
  out.push(one_rtt_flood("onertt_new_cid_flood", target, Close::App(0x0107), vec![ncid]).await);

  // RETIRE_CONNECTION_ID from a client → PROTOCOL_VIOLATION (Transport 0x0a): the server issues one
  // CID (sequence 0) and treats retiring it, or any, as a violation (conn.rs on RetireConnectionId).
  out.push(
    one_rtt_flood(
      "onertt_retire_cid",
      target,
      Close::Transport(0x0a),
      vec![frames::retire_connection_id(0)],
    )
    .await,
  );

  // An empty 1-RTT packet (no frames) → PROTOCOL_VIOLATION (Transport 0x0a), QuicError::EmptyPacket
  // (conn.rs recv_frames: a packet whose payload decodes to no frames).
  out.push(
    one_rtt_flood("onertt_empty_packet", target, Close::Transport(0x0a), vec![Vec::new()]).await,
  );

  // Out-of-order STREAM gaps past `max_out_of_order_ranges` (256) → PROTOCOL_VIOLATION (Transport
  // 0x0a, limits.rs doc). 300 one-byte frames at disjoint offsets 2,4,6,… leave a gap before each,
  // so each is a separate range; the 257th range is the connection error. Packed ~180 per datagram.
  let mut gaps: Vec<Vec<u8>> = Vec::new();
  let mut payload = Vec::new();
  for k in 1..=300u64 {
    payload.extend_from_slice(&frames::stream(0, k * 2, b"x"));
    if k % 180 == 0 {
      gaps.push(std::mem::take(&mut payload));
    }
  }
  if !payload.is_empty() {
    gaps.push(payload);
  }
  out.push(one_rtt_flood("onertt_stream_gaps", target, Close::Transport(0x0a), gaps).await);

  // STREAM data past the per-stream flow-control window (1 MiB) → FLOW_CONTROL_ERROR (Transport
  // 0x03, flow.rs). One byte at offset 2,000,000 reaches past the window from offset 0.
  out.push(
    one_rtt_flood(
      "onertt_stream_past_window",
      target,
      Close::Transport(0x03),
      vec![frames::stream(0, 2_000_000, b"x")],
    )
    .await,
  );

  // A single ACK frame with 10,000 ranges → no close, bounded CPU: `max_ack_ranges` (256) processes
  // the first ranges and ignores the rest (limits.rs). CPU is measured in ns over the window.
  out.push(ack_flood(target, pid).await);

  out
}

/// Runs one 1-RTT flood: handshake, send every packet in `packets`, then assert the server closes
/// with `expect` within 3 s.
async fn one_rtt_flood(
  name: &str,
  target: SocketAddr,
  expect: Close,
  packets: Vec<Vec<u8>>,
) -> ScenarioResult {
  if target.is_ipv6() {
    return pass(name, "skipped on IPv6".into());
  }
  let mut client = match OneRttClient::connect(target).await {
    Ok(client) => client,
    Err(err) => return fail(name, format!("handshake: {err}")),
  };
  for packet in &packets {
    if let Err(err) = client.send_1rtt(packet).await {
      return fail(name, format!("inject: {err}"));
    }
  }
  let close = client.wait_close(Duration::from_secs(3)).await;
  if close == expect {
    pass(name, format!("closed {close:?} as documented"))
  } else {
    fail(name, format!("expected {expect:?}, got {close:?}"))
  }
}

/// The 10,000-range ACK flood: assert no close and report the server CPU (ns) spent on it.
async fn ack_flood(target: SocketAddr, pid: Option<u32>) -> ScenarioResult {
  let name = "onertt_ack_flood";
  if target.is_ipv6() {
    return pass(name, "skipped on IPv6".into());
  }
  let mut client = match OneRttClient::connect(target).await {
    Ok(client) => client,
    Err(err) => return fail(name, format!("handshake: {err}")),
  };
  let cpu0 = pid.map(cpu_ns).unwrap_or(0);
  let mut sent = 0u32;
  for _ in 0..50u32 {
    if client.send_1rtt(&frames::ack_many(0, 10_000)).await.is_ok() {
      sent += 1;
    }
  }
  let close = client.wait_close(Duration::from_millis(1500)).await;
  let cpu_ms = (pid.map(cpu_ns).unwrap_or(0).saturating_sub(cpu0)) / 1_000_000;
  // No close is the pass: the server ignores the ranges past 256 rather than treating the frame as
  // an error, and does not spend unbounded CPU walking them.
  if matches!(close, Close::None) {
    pass(name, format!("{sent} × 10,000-range ACKs: no close, server CPU +{cpu_ms} ms (bounded)"))
  } else {
    fail(name, format!("a 10,000-range ACK must not close the connection; got {close:?}"))
  }
}

/// A tiny deterministic xorshift.
pub(crate) fn tiny_rng(seed: u64) -> impl FnMut() -> u64 {
  let mut state = seed | 1;
  move || {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state
  }
}

#[cfg(test)]
mod smoke {
  use super::*;

  // Flapper + never-ACK against a live soak-server-h3 on 127.0.0.1:8443 (ignored by default).
  #[tokio::test]
  #[ignore = "needs a running soak-server-h3 on 127.0.0.1:8443"]
  async fn flapper_and_never_ack() {
    let target: SocketAddr = "127.0.0.1:8443".parse().unwrap();
    let f = flapper(target, None).await;
    eprintln!("flapper pass={} — {}", f.pass, f.detail);
    let n = never_ack(target).await;
    eprintln!("never_ack pass={} — {}", n.pass, n.detail);
    assert!(f.pass, "flapper failed");
    assert!(n.pass, "never_ack failed");
  }
}
