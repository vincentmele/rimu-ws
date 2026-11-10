//! The abusive QUIC/HTTP/3 clients (spec section 5.12), run in sequence while the steady client
//! runs on. Each returns a [`ScenarioResult`] naming the limit it tripped and the error or
//! rate-limiting it expected (ruling T23-c).
//!
//! The library abusers are driven with `quinn`; the raw floods — malformed first Initials,
//! fragmented CRYPTO, forged short headers — with [`super::raw`], which a conforming library will
//! not send. The 1-RTT frame floods of section 5.12 (PATH_CHALLENGE, NEW_CONNECTION_ID, PING, ACK
//! ranges) and the QPACK encoder-stream insert flood need 1-RTT packets, which only a full TLS
//! handshake yields: no independent client (quinn, which will not send them, or the Initial-only
//! raw sender) can inject them, so they stay covered by the server's own unit tests in
//! `rimu_ws::quic::limits` and `rimu_ws::quic::recv_tracker` (noted in the report). The migration
//! flapper (ruling T23-g) exercises the PATH_CHALLENGE path a library does drive.

use crate::quic::{
  client::{self, Closed},
  driver::H3Config,
  raw,
};
use quinn::VarInt;
use std::{
  net::{SocketAddr, UdpSocket},
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

/// Reads the server's `VmRSS` in KiB, for the per-connection figure of the idle scenario.
fn rss_kib(pid: u32) -> u64 {
  std::fs::read_to_string(format!("/proc/{pid}/status"))
    .ok()
    .and_then(|text| crate::monitor::parse_status(&text))
    .map_or(0, |el| el.0)
}

/// The sum of the server's user and system CPU ticks, for the flapper's cost.
fn cpu_ticks(pid: u32) -> u64 {
  let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
    return 0;
  };
  let rest = text.rsplit_once(')').map(|el| el.1).unwrap_or_default();
  let fields: Vec<u64> = rest.split_whitespace().map(|el| el.parse().unwrap_or(0)).collect();
  // After the state char, field 14 (utime) and 15 (stime) are indices 11 and 12 here.
  fields.get(11).copied().unwrap_or(0) + fields.get(12).copied().unwrap_or(0)
}

/// Runs every abuser in sequence and collects their results. Stops early if the overall `deadline`
/// is reached.
pub async fn run_all(cfg: &H3Config, deadline: Instant) -> Vec<ScenarioResult> {
  let mut out = Vec::new();
  let addr = cfg.main_addr;

  macro_rules! step {
    ($fut:expr) => {
      if Instant::now() < deadline {
        out.push($fut.await);
      }
    };
  }

  // The raw floods run against the one-worker server when there is one, so the per-worker
  // Retry/half-open thresholds are deterministic; they finish before the idle scenario fills it.
  let raw_target = cfg.idle_addr.unwrap_or(addr);
  step!(initial_flood(raw_target));
  step!(forged_short_header(raw_target));
  step!(reset_churn(addr));
  step!(credit_starved(addr));
  step!(oversized_heads(addr));
  step!(slow_reader(addr));
  step!(never_read(addr));
  step!(rebind(addr));
  // The flapper's cost is measured against the quiet one-worker server when there is one: the
  // four-worker main server runs the steady client, whose load would swamp the CPU delta.
  let (flap_addr, flap_pid) = match (cfg.idle_addr, cfg.idle_pid) {
    (Some(idle_addr), idle_pid) => (idle_addr, idle_pid),
    _ => (addr, cfg.main_pid),
  };
  step!(flapper(flap_addr, flap_pid));
  if let (Some(idle_addr), Some(idle_pid)) = (cfg.idle_addr, cfg.idle_pid) {
    step!(idle_connections(idle_addr, idle_pid));
  } else {
    out.push(pass("idle_4096", "skipped: no one-worker server given (--idle-url)".into()));
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

/// **Initial flood / fragmented CRYPTO** (spec section 5.12): many distinct first Initials, each a
/// one-byte (partial) ClientHello so the handshake stays pending and holds a half-open slot. Past
/// `retry_above_half_open` (64) the server answers with a Retry (address validation before a
/// signature or a slot is spent). Pass rule: at least one Retry is seen, and the server stays up.
async fn initial_flood(target: SocketAddr) -> ScenarioResult {
  let name = "initial_flood";
  let result = tokio::task::spawn_blocking(move || {
    let sock = raw_socket(target, 2).map_err(|err| err.to_string())?;
    let mut rng = tiny_rng(0x1234_5678);
    let n = 600u32;
    let mut sent = 0u32;
    for _ in 0..n {
      let mut dcid = [0u8; 8];
      let mut scid = [0u8; 8];
      for b in dcid.iter_mut().chain(scid.iter_mut()) {
        *b = rng() as u8;
      }
      // A one-byte CRYPTO (0x01 = the ClientHello handshake type): the server buffers it and waits
      // for the rest of the handshake, so the slot stays half-open until the handshake deadline.
      let dgram = raw::client_initial(&dcid, &scid, 0, &[0x01], 0, 1200);
      let _ = sock.send_to(&dgram, target);
      // Paced so the server's receive ring (256 datagrams) does not overflow and drop a burst
      // before the per-worker half-open count climbs to the Retry threshold.
      if sent % 32 == 31 {
        std::thread::sleep(Duration::from_millis(2));
      }
      sent += 1;
    }
    // Drain replies for a short window and classify them.
    let (mut retries, mut initials, mut others) = (0u32, 0u32, 0u32);
    let mut buf = [0u8; 2048];
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
      match sock.recv_from(&mut buf) {
        Ok((len, _)) => match raw::classify(&buf[..len]) {
          raw::ReplyKind::Retry => retries += 1,
          raw::ReplyKind::Initial => initials += 1,
          _ => others += 1,
        },
        Err(_) => {}
      }
    }
    Ok::<_, String>((retries, initials, others))
  })
  .await;
  match result {
    Ok(Ok((retries, initials, others))) => {
      let detail = format!(
        "{} Initials sent; replies: {retries} Retry, {initials} Initial, {others} other",
        600
      );
      if retries >= 1 {
        pass(name, format!("rate-limited with Retry (address validation): {detail}"))
      } else {
        fail(name, format!("expected at least one Retry: {detail}"))
      }
    }
    Ok(Err(err)) => fail(name, err),
    Err(err) => fail(name, format!("join: {err}")),
  }
}

/// **Forged short headers**: 1-RTT packets to a connection ID that no connection has, with random
/// protected bytes. The server cannot decrypt them, so it must drop them or send at most a
/// rate-limited stateless reset (`stateless_reset_per_sec`, default 100), never crash or leak. Pass
/// rule: the server stays up and sends no more than a bounded number of replies.
async fn forged_short_header(target: SocketAddr) -> ScenarioResult {
  let name = "forged_short_header";
  let result = tokio::task::spawn_blocking(move || {
    let sock = raw_socket(target, 3).map_err(|err| err.to_string())?;
    let mut rng = tiny_rng(0x9e37_79b9);
    let n = 500u32;
    for _ in 0..n {
      let mut dcid = [0u8; 8];
      for b in dcid.iter_mut() {
        *b = rng() as u8;
      }
      let dgram = raw::forged_short(&dcid, 60);
      let _ = sock.send_to(&dgram, target);
    }
    let mut replies = 0u32;
    let mut buf = [0u8; 2048];
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
      if sock.recv_from(&mut buf).is_ok() {
        replies += 1;
      }
    }
    Ok::<_, String>(replies)
  })
  .await;
  match result {
    Ok(Ok(replies)) => {
      // At most ~2 s of stateless resets at 100/s, with slack.
      if replies <= 300 {
        pass(
          name,
          format!("500 forged shorts sent; {replies} replies (stateless resets rate-limited)"),
        )
      } else {
        fail(name, format!("{replies} replies to 500 forged shorts: not rate-limited"))
      }
    }
    Ok(Err(err)) => fail(name, err),
    Err(err) => fail(name, format!("join: {err}")),
  }
}

/// A short-lived client endpoint for an abuser.
async fn abuser_conn(target: SocketAddr) -> Result<(quinn::Endpoint, quinn::Connection), String> {
  let cfg = client::client_config(None, Duration::from_secs(30));
  let bind: SocketAddr = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
  let ep = client::endpoint(bind, cfg).map_err(|err| err.to_string())?;
  let conn = client::connect(&ep, target, "localhost").await?;
  Ok((ep, conn))
}

/// **Stream churn (QUIC rapid reset)**: open a stream and reset it, over and over. Past
/// `reset_budget` (100 in ten seconds) the server closes the connection with `H3_EXCESSIVE_LOAD`
/// (0x0107). Pass rule: the connection is closed with that application code.
async fn reset_churn(target: SocketAddr) -> ScenarioResult {
  let name = "reset_churn";
  let (ep, conn) = match abuser_conn(target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let cancel = VarInt::from_u32(0x010c); // H3_REQUEST_CANCELLED
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
  let detail = format!("{opened} streams opened+reset, closed as {closed:?}");
  match closed {
    Closed::App(0x0107) => pass(name, format!("H3_EXCESSIVE_LOAD (0x0107): {detail}")),
    other => fail(name, format!("expected H3_EXCESSIVE_LOAD (0x0107), got {other:?}: {detail}")),
  }
}

/// **Credit-starved streams**: open the connection's whole bidirectional-stream allowance
/// (`max_streams_bidi`, 256) and hold them, then try one more. The server enforces the limit, so
/// the extra open never gets credit. Pass rule: the connection stays up, the 257th open is starved
/// (times out), and the server holds the slots within its cap.
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
        let _ = send.write_all(b"GET").await; // a partial head, never finished
        held.push((send, recv));
      }
      _ => break,
    }
  }
  let opened = held.len();
  // The next open must be starved of stream credit: it should not complete.
  let extra = tokio::time::timeout(Duration::from_millis(800), conn.open_bi()).await;
  let starved = extra.is_err();
  tokio::time::sleep(Duration::from_secs(2)).await;
  let alive = conn.close_reason().is_none();
  ep.close(client::H3_NO_ERROR, b"");
  let detail = format!("{opened} streams held, 257th starved={starved}, conn alive={alive}");
  if opened >= 1 && starved && alive {
    pass(name, format!("stream limit enforced, connection bounded: {detail}"))
  } else {
    fail(name, format!("expected the extra open starved and the connection alive: {detail}"))
  }
}

/// **Oversized heads**: a request whose field section decodes to more than the advertised
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` (16 KiB). The framework answers it with 431 and stops reading
/// it (RFC 9114 section 4.2.2), never a connection kill. The `h3` client refuses to *send* a field
/// section over the peer's advertised size, so this hand-encodes the request over raw `quinn`
/// streams (control stream + SETTINGS, QPACK streams, then a request stream with the oversized
/// HEADERS frame). Pass rule: the server answers on the request stream (it does not kill the
/// connection), and the response carries `431`.
async fn oversized_heads(target: SocketAddr) -> ScenarioResult {
  let name = "oversized_heads";
  let (ep, conn) = match abuser_conn(target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let result = async {
    // The client control stream with SETTINGS, then the QPACK encoder/decoder streams, kept open.
    let mut control = conn.open_uni().await.map_err(|err| format!("open control: {err}"))?;
    control.write_all(&raw::h3_control_stream()).await.map_err(|err| format!("control: {err}"))?;
    let mut enc = conn.open_uni().await.map_err(|err| format!("open enc: {err}"))?;
    enc.write_all(&[raw::H3_QPACK_ENCODER]).await.map_err(|err| format!("enc: {err}"))?;
    let mut dec = conn.open_uni().await.map_err(|err| format!("open dec: {err}"))?;
    dec.write_all(&[raw::H3_QPACK_DECODER]).await.map_err(|err| format!("dec: {err}"))?;
    // The request stream: a HEADERS frame whose field section is ~20 KiB.
    let (mut send, mut recv) = conn.open_bi().await.map_err(|err| format!("open bi: {err}"))?;
    let frame = raw::h3_oversized_headers_frame(20 * 1024);
    send.write_all(&frame).await.map_err(|err| format!("write: {err}"))?;
    send.finish().map_err(|err| format!("finish: {err}"))?;
    let bytes = recv.read_to_end(64 * 1024).await.map_err(|err| format!("read: {err}"))?;
    // The control streams stay open until the block ends (resetting them early is itself an
    // H3_CLOSED_CRITICAL_STREAM); the response is already read.
    let _ = (&control, &enc, &dec);
    Ok::<Vec<u8>, String>(bytes)
  }
  .await;
  ep.close(client::H3_NO_ERROR, b"");
  match result {
    Ok(bytes) => {
      // The server answers 431 on the request stream (a HEADERS frame, type 0x01) rather than
      // killing the connection before responding: the response carries the ASCII `431`.
      let answered = bytes.first() == Some(&0x01) || bytes.windows(2).any(|w| w == [0x01, 0x00]);
      let has_431 = bytes.windows(3).any(|w| w == b"431");
      if answered && has_431 {
        pass(
          name,
          format!(
            "431-equivalent: server answered the oversized head with a HEADERS frame carrying 431 ({} resp bytes)",
            bytes.len()
          ),
        )
      } else {
        fail(
          name,
          format!(
            "expected a 431 answer: HEADERS frame={answered}, '431' bytes={has_431}, {} bytes",
            bytes.len()
          ),
        )
      }
    }
    Err(err) => fail(name, format!("expected a 431 answer, not an error: {err}")),
  }
}

/// **Slow reader**: ask for the 10 MiB static file and never read the body. The server is held to
/// `max_in_flight` (256 KiB) by our stream flow control and never buffers the whole body. Pass
/// rule: the connection stays up for the hold and the server stays bounded (the RSS check).
async fn slow_reader(target: SocketAddr) -> ScenarioResult {
  let name = "slow_reader";
  let (ep, conn) = match abuser_conn(target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let h3c = h3_quinn::Connection::new(conn.clone());
  let result = async {
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
    // Never read the body: hold the stream open so the server is flow-controlled.
    tokio::time::sleep(Duration::from_secs(8)).await;
    drive.abort();
    Ok::<(), String>(())
  }
  .await;
  let alive = conn.close_reason().is_none();
  ep.close(client::H3_NO_ERROR, b"");
  match result {
    Ok(()) if alive => {
      pass(name, "10 MiB response held by in-flight cap, connection bounded".into())
    }
    Ok(()) => fail(name, "connection closed under a slow reader".into()),
    Err(err) => fail(name, err),
  }
}

/// **Never-read**: open a bidirectional stream, send a partial request, and never read the reply,
/// holding it idle. The server must stay bounded. Pass rule: the server stays up (the RSS check)
/// and the connection is not forced to buffer.
async fn never_read(target: SocketAddr) -> ScenarioResult {
  let name = "never_read";
  let (ep, conn) = match abuser_conn(target).await {
    Ok(elem) => elem,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  let held = match conn.open_bi().await {
    Ok((mut send, recv)) => {
      let _ = send.write_all(b"partial request, never finished").await;
      Some((send, recv))
    }
    Err(err) => return fail(name, format!("open: {err}")),
  };
  tokio::time::sleep(Duration::from_secs(5)).await;
  let alive = conn.close_reason().is_none();
  drop(held);
  ep.close(client::H3_NO_ERROR, b"");
  if alive {
    pass(name, "partial request held without a read; server bounded".into())
  } else {
    fail(name, "connection closed while holding a partial request".into())
  }
}

/// **Rebinding (well-behaved migrant, ruling T23-g a)**: a client that keeps requesting while its
/// local port changes, then its source address (127.0.0.1 → 127.0.0.2). The server validates the
/// new path and keeps answering. Pass rule: a `GET` succeeds after each rebind.
async fn rebind(target: SocketAddr) -> ScenarioResult {
  let name = "rebind";
  if target.is_ipv6() {
    return pass(name, "skipped on IPv6 (loopback source-address rebinds use 127.0.0.0/8)".into());
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
  // One HTTP/3 session, reused across the rebinds (a fresh session per request would open a second
  // control stream and be a protocol error).
  let mut session = match client::H3Session::open(conn.clone()).await {
    Ok(session) => session,
    Err(err) => {
      ep.close(client::H3_NO_ERROR, b"");
      return fail(name, format!("h3 session: {err}"));
    }
  };
  let mut steps = Vec::new();
  steps.push(("before", session.get("/baseline2").await.map(|r| r.status)));
  // Rebind the local port (same address).
  let port_rebind = UdpSocket::bind("127.0.0.1:0").and_then(|s| ep.rebind(s)).is_ok();
  tokio::time::sleep(Duration::from_millis(200)).await;
  steps.push(("after_port", session.get("/baseline2").await.map(|r| r.status)));
  // Rebind the source address.
  let addr_rebind = UdpSocket::bind("127.0.0.2:0").and_then(|s| ep.rebind(s)).is_ok();
  tokio::time::sleep(Duration::from_millis(200)).await;
  steps.push(("after_addr", session.get("/baseline2").await.map(|r| r.status)));
  drop(session);
  ep.close(client::H3_NO_ERROR, b"");
  let ok = steps.iter().all(|(_, r)| matches!(r, Ok(200)));
  let detail = format!("port_rebind={port_rebind}, addr_rebind={addr_rebind}, steps={steps:?}");
  if ok {
    pass(name, format!("answered across both rebinds: {detail}"))
  } else {
    fail(name, format!("a GET failed after a rebind: {detail}"))
  }
}

/// **Migration flapper (ruling T23-g b)**: a confirmed connection whose source address alternates
/// between two loopback addresses as fast as it can. Pass rule: bounded server CPU and RSS (the
/// RSS check and this CPU measurement), no steady-client stall (checked globally). The 22b review
/// deferred rate-limiting the flap; this measures its cost and reports it (if it is cheap, leave
/// it; if it is a real CPU sink, the report flags a follow-up limit).
async fn flapper(target: SocketAddr, pid: Option<u32>) -> ScenarioResult {
  let name = "flapper";
  if target.is_ipv6() {
    return pass(name, "skipped on IPv6".into());
  }
  let cfg = client::client_config(Some(Duration::from_millis(500)), Duration::from_secs(30));
  let ep = match client::endpoint("127.0.0.1:0".parse().unwrap(), cfg) {
    Ok(ep) => ep,
    Err(err) => return fail(name, format!("endpoint: {err}")),
  };
  let conn = match client::connect(&ep, target, "localhost").await {
    Ok(conn) => conn,
    Err(err) => return fail(name, format!("connect: {err}")),
  };
  // One HTTP/3 session, reused to confirm the connection and drive traffic through the flaps.
  let mut session = match client::H3Session::open(conn.clone()).await {
    Ok(session) => session,
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
  let cpu0 = pid.map(cpu_ticks).unwrap_or(0);
  let begin = Instant::now();
  let mut flips = 0u32;
  while begin.elapsed() < Duration::from_secs(10) {
    let octet = if flips % 2 == 0 { 2 } else { 1 };
    if let Ok(sock) = UdpSocket::bind(format!("127.0.0.{octet}:0")) {
      if ep.rebind(sock).is_ok() {
        flips += 1;
        // Drive a request from the new address, so the server validates each flipped path.
        let _ = tokio::time::timeout(Duration::from_millis(150), session.get("/baseline2")).await;
      }
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
  }
  let wall = begin.elapsed();
  let cpu1 = pid.map(cpu_ticks).unwrap_or(0);
  let alive = conn.close_reason().is_none();
  let still = session.get("/baseline2").await.map(|r| r.status);
  drop(session);
  ep.close(client::H3_NO_ERROR, b"");
  let hz = 100u64; // CLK_TCK on this host
  let cpu_ms = (cpu1.saturating_sub(cpu0)) * 1000 / hz;
  let wall_ms = wall.as_millis() as u64;
  let detail = format!(
    "{flips} flips in {wall_ms} ms, server CPU +{cpu_ms} ms, conn alive={alive}, still-serves={still:?}"
  );
  // Ruling T23-g(b): the pass rule is bounded server CPU/RSS and no stall of the concurrent steady
  // client (the RSS and steady checks cover RSS/stalls); the flapper's own connection need not
  // survive — the server closing it (observed: H3_EXCESSIVE_LOAD) is legitimate rate-limiting. A
  // sustained over-one-core cost (cpu_ms > wall_ms) would be the real sink the 22b review feared
  // and would call for a dedicated flap rate limit (ruling T23-e); below that, report and leave it.
  if cpu_ms <= wall_ms {
    pass(name, format!("bounded server CPU under flapping (under one core): {detail}"))
  } else {
    fail(
      name,
      format!(
        "flapping cost over one core of server CPU — add a bounded flap rate limit: {detail}"
      ),
    )
  }
}

/// **Idle connections × 4,096 per worker (ruling T23-f)**: open the worker's whole connection
/// allowance (`max_conns_per_worker`, 4,096) as idle, kept alive, then one more. Pass rule: the
/// held connections stay within the cap with bounded memory (RSS per connection reported) and the
/// extra connection is refused (no room: its handshake times out).
async fn idle_connections(target: SocketAddr, pid: u32) -> ScenarioResult {
  let name = "idle_4096";
  let rss_before = rss_kib(pid);
  // A keep-alive under the 30 s idle timeout holds the connections.
  let cfg = client::client_config(Some(Duration::from_secs(10)), Duration::from_secs(30));
  let endpoints = 16u32;
  let per = 4096u32 / endpoints;
  let mut held: Vec<quinn::Connection> = Vec::new();
  let mut eps = Vec::new();
  for _ in 0..endpoints {
    let bind: SocketAddr = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
    let Ok(ep) = client::endpoint(bind, cfg.clone()) else {
      continue;
    };
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
  let opened = held.len();
  let rss_after = rss_kib(pid);
  let per_conn =
    if opened > 0 { (rss_after.saturating_sub(rss_before)) / opened as u64 } else { 0 };
  // One more connection, which the worker has no room for.
  let extra_cfg = client::client_config(None, Duration::from_secs(5));
  let extra_bind: SocketAddr =
    if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap();
  let extra_refused = match client::endpoint(extra_bind, extra_cfg) {
    Ok(ep) => {
      let r =
        tokio::time::timeout(Duration::from_secs(4), client::connect(&ep, target, "localhost"))
          .await;
      ep.close(client::H3_NO_ERROR, b"");
      // Refused = timed out (dropped, no room) or an error.
      !matches!(r, Ok(Ok(_)))
    }
    Err(_) => true,
  };
  for ep in &eps {
    ep.close(client::H3_NO_ERROR, b"");
  }
  drop(held);
  let detail = format!(
    "held {opened}/4096 idle, server RSS {rss_before}->{rss_after} KiB (~{per_conn} KiB/conn), 4097th refused={extra_refused}"
  );
  // Within a few of the cap, bounded, and the extra refused. (Fewer than 4096 can mean the client
  // ran out of ports; report it but do not fail if the cap and refusal held.)
  if opened >= 4000 && extra_refused {
    pass(name, detail)
  } else if opened < 4000 {
    fail(
      name,
      format!("held only {opened} of 4096 (client limit or server cap too low?): {detail}"),
    )
  } else {
    fail(name, format!("the 4097th connection was not refused: {detail}"))
  }
}

/// A tiny deterministic xorshift, so the raw floods do not pull a real RNG into the hot path.
fn tiny_rng(seed: u64) -> impl FnMut() -> u64 {
  let mut state = seed | 1;
  move || {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state
  }
}
