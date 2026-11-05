use crate::http::{Headers, KnownHeaderName, Method, Protocol};

/// Verifies if the initial received HTTP/2 headers represent a WebSocket connection.
#[inline]
pub fn is_web_socket_handshake(
  headers: &Headers,
  method: Method,
  protocol: Option<Protocol>,
) -> bool {
  let header = KnownHeaderName::SecWebsocketVersion.into();
  method == Method::Connect
    && protocol == Some(Protocol::WebSocket)
    && headers.get_by_name(header).map(|el| el.value) == Some("13")
}

#[cfg(any(feature = "http2-client-pool", feature = "http2-server-framework"))]
pub(crate) fn push_h2_alpn<TCX>(tc: &mut crate::tls::TlsConfig<TCX>) -> crate::Result<()> {
  tc.alpn_mut().get_or_insert_default().protocol_name_list.push("h2".as_bytes().try_into()?)?;
  Ok(())
}

/// Reports a failed accept to the error callback. Unless the connection only went away before it
/// was taken, the next accept would most likely fail the same way at once (out of descriptors,
/// say), so the loop waits a moment first instead of spinning.
#[cfg(any(feature = "http2-server-framework", feature = "web-socket-server-framework"))]
pub(crate) async fn on_accept_error<EC, ER>(error_cb: &EC, err: crate::Error)
where
  EC: Fn(ER),
  ER: From<crate::Error>,
{
  let transient = cfg_select! {
    feature = "std" => matches!(
      &err,
      crate::Error::Io(elem) if matches!(
        elem.kind(),
        std::io::ErrorKind::ConnectionAborted
          | std::io::ErrorKind::ConnectionReset
          | std::io::ErrorKind::Interrupted
          | std::io::ErrorKind::WouldBlock
      )
    ),
    _ => false,
  };
  error_cb(err.into());
  if !transient
    && let Ok(sleep) = crate::futures::Sleep::new(core::time::Duration::from_millis(100))
  {
    let _rslt = sleep.await;
  }
}
