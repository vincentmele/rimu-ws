use crate::http::{Headers, KnownHeaderName, Method, Protocol};
#[cfg(any(
  feature = "http1-server-framework",
  feature = "http2-server-framework",
  feature = "web-socket-server-framework"
))]
use crate::{
  futures::Sleep,
  http::ShutdownSignal,
  sync::{Arc, AtomicUsize},
};
#[cfg(any(
  feature = "http1-server-framework",
  feature = "http2-server-framework",
  feature = "web-socket-server-framework"
))]
use core::{
  future::poll_fn, num::NonZeroUsize, pin::pin, sync::atomic::Ordering, task::Poll, time::Duration,
};

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
#[cfg(any(
  feature = "http1-server-framework",
  feature = "http2-server-framework",
  feature = "web-socket-server-framework"
))]
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

/// The next accepted connection, or `None` once `shutdown` is triggered.
#[cfg(any(
  feature = "http1-server-framework",
  feature = "http2-server-framework",
  feature = "web-socket-server-framework"
))]
pub(crate) async fn accept_or_shutdown<T>(
  accept: impl Future<Output = T>,
  shutdown: Option<&ShutdownSignal>,
) -> Option<T> {
  let Some(signal) = shutdown else {
    return Some(accept.await);
  };
  let mut accept = pin!(accept);
  poll_fn(|cx| {
    if signal.poll_triggered(cx).is_ready() {
      return Poll::Ready(None);
    }
    accept.as_mut().poll(cx).map(Some)
  })
  .await
}

/// `fut`'s output, or [`crate::Error::ExpiredFuture`] if `timeout` passes first.
#[cfg(any(
  feature = "http1-server-framework",
  feature = "http2-server-framework",
  feature = "web-socket-server-framework"
))]
pub(crate) async fn within<T>(
  fut: impl Future<Output = crate::Result<T>>,
  timeout: Option<Duration>,
) -> crate::Result<T> {
  let Some(duration) = timeout else {
    return fut.await;
  };
  let mut fut = pin!(fut);
  let mut sleep = pin!(Sleep::new(duration)?);
  poll_fn(|cx| {
    if let Poll::Ready(elem) = fut.as_mut().poll(cx) {
      return Poll::Ready(elem);
    }
    sleep.as_mut().poll(cx).map(|elem| elem.and(Err(crate::Error::ExpiredFuture)))
  })
  .await
}

/// The count of open connections, when a shutdown has to wait for them or a limit caps them.
#[cfg(any(
  feature = "http1-server-framework",
  feature = "http2-server-framework",
  feature = "web-socket-server-framework"
))]
pub(crate) fn counter(
  shutdown: Option<&(ShutdownSignal, Duration)>,
  max_connections: Option<NonZeroUsize>,
) -> Option<Arc<AtomicUsize>> {
  (shutdown.is_some() || max_connections.is_some()).then(|| Arc::new(AtomicUsize::new(0)))
}

/// Counts a new connection in `active`, unless that would take it past `max`. Counted first and
/// then checked, so that runtimes accepting at the same time can't together pass the limit.
#[cfg(any(
  feature = "http1-server-framework",
  feature = "http2-server-framework",
  feature = "web-socket-server-framework"
))]
pub(crate) fn admit(active: &AtomicUsize, max: Option<NonZeroUsize>) -> bool {
  let prev = active.fetch_add(1, Ordering::AcqRel);
  if max.is_some_and(|el| prev >= el.get()) {
    let _prev = active.fetch_sub(1, Ordering::AcqRel);
    return false;
  }
  true
}

/// A connection's task, counted in `active` while it runs.
#[cfg(any(
  feature = "http1-server-framework",
  feature = "http2-server-framework",
  feature = "web-socket-server-framework"
))]
pub(crate) async fn tracked(fut: impl Future<Output = ()>, active: Arc<AtomicUsize>) {
  struct Guard(Arc<AtomicUsize>);

  #[cfg(any(
    feature = "http1-server-framework",
    feature = "http2-server-framework",
    feature = "web-socket-server-framework"
  ))]
  impl Drop for Guard {
    fn drop(&mut self) {
      let _prev = self.0.fetch_sub(1, Ordering::AcqRel);
    }
  }

  #[cfg(any(
    feature = "http1-server-framework",
    feature = "http2-server-framework",
    feature = "web-socket-server-framework"
  ))]
  let _guard = Guard(active);
  fut.await;
}

/// Waits until no connection is left, or `drain` has passed.
#[cfg(any(
  feature = "http1-server-framework",
  feature = "http2-server-framework",
  feature = "web-socket-server-framework"
))]
pub(crate) async fn drain_connections(active: &AtomicUsize, drain: Duration) {
  let begin = crate::calendar::Instant::new();
  while active.load(Ordering::Acquire) > 0 && begin.elapsed().is_ok_and(|el| el < drain) {
    let Ok(sleep) = Sleep::new(Duration::from_millis(10)) else {
      break;
    };
    let _rslt = sleep.await;
  }
}
