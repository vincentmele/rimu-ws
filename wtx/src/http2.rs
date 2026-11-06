//! Low-level HTTP/2. You should probably look into higher abstractions like the HTTP server
//! framework.
//!
//! 1. Does not support padded headers when writing.
//! 2. Does not support push promises (Deprecated by major third-parties).
//! 3. Does not support prioritization (Deprecated by the RFC).

#[macro_use]
mod macros;

mod client_conn;
mod client_stream;
#[allow(
  dead_code,
  reason = "upstream's frame code, kept for merges; the connection core writes frames itself"
)]
mod common_flags;
mod common_stream;
pub(crate) mod conn;
#[allow(
  dead_code,
  reason = "upstream's frame code, kept for merges; the connection core writes frames itself"
)]
mod continuation_frame;
#[allow(
  dead_code,
  reason = "upstream's frame code, kept for merges; the connection core writes frames itself"
)]
mod data_frame;
mod frame_init;
#[allow(
  dead_code,
  reason = "upstream's frame code, kept for merges; the connection core writes frames itself"
)]
mod go_away_frame;
#[allow(
  dead_code,
  reason = "upstream's frame code, kept for merges; the connection core writes frames itself"
)]
mod headers_frame;
#[allow(
  dead_code,
  reason = "upstream's frame code, kept for merges; the connection core writes frames itself"
)]
pub(crate) mod hpack_decoder;
#[allow(
  dead_code,
  reason = "upstream's frame code, kept for merges; the connection core writes frames itself"
)]
mod hpack_encoder;
mod hpack_header;
mod hpack_headers;
#[allow(
  dead_code,
  reason = "upstream's frame code, kept for merges; the connection core writes frames itself"
)]
mod hpack_static_headers;
mod http2_buffer;
mod http2_error;
mod http2_error_code;
mod http2_status;
mod huffman;
mod huffman_tables;
mod misc;
mod ping_frame;
#[allow(
  dead_code,
  reason = "upstream's frame code, kept for merges; the connection core writes frames itself"
)]
mod reset_stream_frame;
pub(crate) mod server_stream;
#[allow(
  dead_code,
  reason = "upstream's frame code, kept for merges; the connection core writes frames itself"
)]
mod settings_frame;
#[cfg(test)]
mod tests;
#[cfg(feature = "web-socket")]
mod web_socket_over_stream;
#[allow(
  dead_code,
  reason = "upstream's frame code, kept for merges; the connection core writes frames itself"
)]
mod window_update_frame;

use crate::{
  collections::SingleTypeStorage,
  http::HttpRecvParams,
  http2::{client_conn::ClientShared, conn::Http2Conn},
  misc::{Lease, LeaseMut},
  net::{ConnectionState, StreamReader, StreamWriter},
  sync::Arc,
  tls::{TlsCtx, TlsStreamBridge, TlsStreamReader, TlsStreamWriter},
};
pub use client_stream::ClientStream;
pub use common_stream::CommonStream;
use core::{future::poll_fn, task::Poll};
pub use http2_buffer::Http2Buffer;
pub use http2_error::Http2Error;
pub use http2_error_code::Http2ErrorCode;
pub use http2_status::{Http2RecvStatus, Http2SendStatus};
pub use server_stream::ServerStream;
#[cfg(feature = "web-socket")]
pub use web_socket_over_stream::WebSocketOverStream;

/// A client connection: opens streams. The connection itself runs in the task [`Self::connect`]
/// returns.
///
/// `SW` and `TCX` are the writing half and the TLS context of the connection; `IS_CLIENT` is
/// always `true`.
#[derive(Debug)]
pub struct Http2<SW, TCX, const IS_CLIENT: bool> {
  shared: Arc<ClientShared<SW, TCX>>,
}

impl<SW, TCX, const IS_CLIENT: bool> Http2<SW, TCX, IS_CLIENT> {
  /// Closes the connection at once: the task stops and every waiting stream wakes.
  #[cfg(feature = "http2-client-pool")]
  pub(crate) fn close_abruptly(&self) {
    self.shared.state.lock().close_abruptly();
  }

  /// See [`ConnectionState`].
  #[inline]
  pub fn connection_state(&self) -> ConnectionState {
    self.shared.state.lock().connection_state()
  }
}

impl<SW, TCX, const IS_CLIENT: bool> Http2<SW, TCX, IS_CLIENT>
where
  SW: StreamWriter,
  TCX: TlsCtx,
{
  send_go_away_method!();
}

impl<SW, TCX> Http2<SW, TCX, true>
where
  SW: StreamWriter,
  TCX: TlsCtx,
{
  /// Starts a connection to a server: the returned future is the connection task, which the
  /// caller spawns. It sends the preface and the local SETTINGS first.
  #[inline]
  pub async fn connect<SR>(
    hb: Http2Buffer,
    hrp: HttpRecvParams,
    (stream_bridge, stream_reader, stream_writer): (
      TlsStreamBridge<true>,
      TlsStreamReader<SR, TCX, true>,
      TlsStreamWriter<SW, TCX, true>,
    ),
  ) -> crate::Result<(impl Future<Output = ()>, Self)>
  where
    SR: StreamReader,
  {
    let Http2Buffer { mut rng, mut rx } = hb;
    rx.clear();
    let conn = Http2Conn::<true>::new(hrp.set_enable_connect_protocol(false), &mut rng);
    let shared = Arc::new(ClientShared::new(conn, stream_writer));
    let task = client_conn::conn_task(shared.clone(), rx, stream_bridge, stream_reader);
    Ok((task, Self { shared }))
  }

  /// Opens a local stream. Waits for the server's first SETTINGS, and while its limit on
  /// concurrent streams is reached. The stream id is assigned when the request is sent, so
  /// streams may send in any order.
  #[inline]
  pub async fn stream(&self) -> crate::Result<ClientStream<SW, TCX>> {
    poll_fn(|cx| {
      let mut state = self.shared.state.lock();
      if state.is_ended() || !state.conn.accepts_streams() {
        return Poll::Ready(Err(crate::Error::ClosedHttpConnection));
      }
      if !state.conn.can_open_stream(state.reserved) {
        state.wait_open(cx.waker())?;
        return Poll::Pending;
      }
      state.reserved = state.reserved.wrapping_add(1);
      Poll::Ready(Ok(()))
    })
    .await?;
    Ok(ClientStream::new(self.shared.clone()))
  }
}

impl<SW, TCX, const IS_CLIENT: bool> Lease<Http2<SW, TCX, IS_CLIENT>>
  for Http2<SW, TCX, IS_CLIENT>
{
  #[inline]
  fn lease(&self) -> &Http2<SW, TCX, IS_CLIENT> {
    self
  }
}

impl<SW, TCX, const IS_CLIENT: bool> LeaseMut<Http2<SW, TCX, IS_CLIENT>>
  for Http2<SW, TCX, IS_CLIENT>
{
  #[inline]
  fn lease_mut(&mut self) -> &mut Http2<SW, TCX, IS_CLIENT> {
    self
  }
}

impl<SW, TCX, const IS_CLIENT: bool> SingleTypeStorage for Http2<SW, TCX, IS_CLIENT> {
  type Item = (Http2Buffer, SW);
}

impl<SW, TCX, const IS_CLIENT: bool> Clone for Http2<SW, TCX, IS_CLIENT> {
  #[inline]
  fn clone(&self) -> Self {
    Self { shared: self.shared.clone() }
  }
}
