//! `quinn` plumbing for the library-driven abusers and the steady client: a client endpoint that
//! trusts any certificate (loopback tests only), an HTTP/3 `GET` over `h3`, and the close codes a
//! connection ended with, so a scenario can assert the exact error of the limit it tripped.

use bytes::Buf as _;
use quinn::{ClientConfig, Connection, ConnectionError, Endpoint, TransportConfig, VarInt};
use std::{net::SocketAddr, sync::Arc, time::Duration};

/// A certificate verifier that accepts anything: the soak runs on loopback against a self-signed
/// certificate, and the point is to test the server's QUIC, not its certificate.
#[derive(Debug)]
struct TrustAny(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for TrustAny {
  fn verify_server_cert(
    &self,
    _end_entity: &rustls::pki_types::CertificateDer<'_>,
    _intermediates: &[rustls::pki_types::CertificateDer<'_>],
    _server_name: &rustls::pki_types::ServerName<'_>,
    _ocsp: &[u8],
    _now: rustls::pki_types::UnixTime,
  ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
    Ok(rustls::client::danger::ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    _message: &[u8],
    _cert: &rustls::pki_types::CertificateDer<'_>,
    _dss: &rustls::DigitallySignedStruct,
  ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
  }

  fn verify_tls13_signature(
    &self,
    _message: &[u8],
    _cert: &rustls::pki_types::CertificateDer<'_>,
    _dss: &rustls::DigitallySignedStruct,
  ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
  }

  fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
    self.0.signature_verification_algorithms.supported_schemes()
  }
}

/// The bare `rustls` TLS 1.3 client config (ALPN `h3`, trust-any verifier) that both the `quinn`
/// clients and the raw 1-RTT client ([`super::onertt`]) build on. Loopback only.
pub(crate) fn rustls_config() -> rustls::ClientConfig {
  let provider = Arc::new(rustls::crypto::ring::default_provider());
  let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("tls13")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(TrustAny(provider)))
    .with_no_client_auth();
  tls.alpn_protocols = vec![b"h3".to_vec()];
  tls
}

/// A client config that speaks HTTP/3 (ALPN `h3`), trusts any certificate, and keeps connections
/// alive under the server's idle timeout so idle scenarios can hold them.
pub fn client_config(keep_alive: Option<Duration>, idle: Duration) -> ClientConfig {
  let tls = rustls_config();
  let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic client config");
  let mut cfg = ClientConfig::new(Arc::new(qcc));
  let mut transport = TransportConfig::default();
  transport.max_idle_timeout(Some(idle.try_into().expect("idle")));
  if let Some(ka) = keep_alive {
    transport.keep_alive_interval(Some(ka));
  }
  cfg.transport_config(Arc::new(transport));
  cfg
}

/// Like [`client_config`] but with the connection and per-stream receive windows forced to
/// `window` bytes (0 for the credit-starved `window_starved` scenario, so the server may send no
/// STREAM data and must close on idle). `idle` is kept short so the idle close is quick.
pub fn client_config_windows(idle: Duration, window: u64) -> ClientConfig {
  let provider = Arc::new(rustls::crypto::ring::default_provider());
  let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("tls13")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(TrustAny(provider)))
    .with_no_client_auth();
  tls.alpn_protocols = vec![b"h3".to_vec()];
  let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic client config");
  let mut cfg = ClientConfig::new(Arc::new(qcc));
  let mut transport = TransportConfig::default();
  transport.max_idle_timeout(Some(idle.try_into().expect("idle")));
  // Only the per-stream window is starved; the connection window stays at its default so the
  // server's own (mandatory) control and QPACK uni streams can still be sent, and the request
  // stream alone is the one that gets no data — the server then closes on idle.
  transport.stream_receive_window(VarInt::from_u64(window).unwrap_or(VarInt::from_u32(0)));
  cfg.transport_config(Arc::new(transport));
  cfg
}

/// A client endpoint bound to `bind`, already carrying `cfg` as its default.
pub fn endpoint(bind: SocketAddr, cfg: ClientConfig) -> std::io::Result<Endpoint> {
  let mut ep = Endpoint::client(bind)?;
  ep.set_default_client_config(cfg);
  Ok(ep)
}

/// Connects to `addr`, with `server_name` for SNI (the certificate is not checked). A bad address
/// or config (a harness fault) and a failed handshake are both reported as a string.
pub async fn connect(
  ep: &Endpoint,
  addr: SocketAddr,
  server_name: &str,
) -> Result<Connection, String> {
  ep.connect(addr, server_name)
    .map_err(|err| format!("connect: {err}"))?
    .await
    .map_err(|err| format!("handshake: {err}"))
}

/// How a connection ended, named so a scenario can assert the limit it expected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Closed {
  /// CONNECTION_CLOSE with an application error code (HTTP/3 codes such as H3_EXCESSIVE_LOAD).
  App(u64),
  /// CONNECTION_CLOSE with a transport error code (QUIC codes such as FLOW_CONTROL_ERROR).
  Transport(u64),
  /// The connection timed out (idle or handshake), or was reset without a code.
  TimedOutOrReset,
  /// The peer is still up (used when a scenario expects the connection to survive).
  Open,
}

/// Classifies the error a connection closed with.
pub fn closed_as(err: &ConnectionError) -> Closed {
  match err {
    ConnectionError::ApplicationClosed(ac) => Closed::App(ac.error_code.into_inner()),
    ConnectionError::ConnectionClosed(cc) => Closed::Transport(u64::from(cc.error_code)),
    ConnectionError::TimedOut | ConnectionError::Reset | ConnectionError::LocallyClosed => {
      Closed::TimedOutOrReset
    }
    _ => Closed::TimedOutOrReset,
  }
}

/// Waits for the connection to close and reports how, or times out (treated as still open).
pub async fn wait_closed(conn: &Connection, within: Duration) -> Closed {
  match tokio::time::timeout(within, conn.closed()).await {
    Ok(err) => closed_as(&err),
    Err(_) => Closed::Open,
  }
}

/// The HTTP/3 response to a `GET`: its `:status` and its body.
pub struct H3Response {
  pub status: u16,
  pub body: Vec<u8>,
}

/// A live HTTP/3 connection over one quinn connection: its control streams are opened once, so
/// many requests (and requests across NAT rebindings) reuse it. A fresh `h3::client::new` per
/// request would open a second control stream and the server would close the connection with
/// `H3_CLOSED_CRITICAL_STREAM`.
pub struct H3Session {
  send: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
  driver: tokio::task::JoinHandle<()>,
}

impl H3Session {
  /// Sets up the HTTP/3 connection (control stream, QPACK streams) over `conn`.
  pub async fn open(conn: Connection) -> Result<H3Session, String> {
    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, send) =
      h3::client::new(h3_conn).await.map_err(|err| format!("h3 new: {err}"))?;
    let handle = tokio::spawn(async move {
      let _ = driver.wait_idle().await;
    });
    Ok(H3Session { send, driver: handle })
  }

  /// One HTTP/3 `GET` of `path`, reusing the session. The authority is `localhost`, matching the
  /// server's certificate.
  pub async fn get(&mut self, path: &str) -> Result<H3Response, String> {
    let uri = format!("https://localhost{path}");
    let req = http::Request::builder()
      .method("GET")
      .uri(&uri)
      .body(())
      .map_err(|err| format!("request: {err}"))?;
    let mut stream = self.send.send_request(req).await.map_err(|err| format!("send: {err}"))?;
    stream.finish().await.map_err(|err| format!("finish: {err}"))?;
    let resp = stream.recv_response().await.map_err(|err| format!("response: {err}"))?;
    let status = resp.status().as_u16();
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.map_err(|err| format!("data: {err}"))? {
      while chunk.has_remaining() {
        let n = chunk.chunk().len();
        body.extend_from_slice(chunk.chunk());
        chunk.advance(n);
      }
    }
    Ok(H3Response { status, body })
  }
}

impl Drop for H3Session {
  fn drop(&mut self) {
    self.driver.abort();
  }
}

/// One HTTP/3 `GET` over a fresh session on `conn` (for a single request).
pub async fn h3_get(conn: Connection, path: &str) -> Result<H3Response, String> {
  let mut session = H3Session::open(conn).await?;
  session.get(path).await
}

/// A convenience error code: HTTP/3 `H3_NO_ERROR`, used to close a stream or connection cleanly.
pub const H3_NO_ERROR: VarInt = VarInt::from_u32(0x0100);
