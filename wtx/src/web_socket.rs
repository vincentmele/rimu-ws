//! A computer communications protocol, providing full-duplex communication channels over a single
//! TCP connection.

mod close_code;
#[cfg(any(test, feature = "_fuzz"))]
#[doc(hidden)]
pub mod differential;
mod frame;
mod handshake;
mod is_in_continuation_frame;
mod mask_op;
mod misc;
mod op_code;
pub(crate) mod read_frame;
pub(crate) mod read_frame_info;
mod web_socket_acceptor;
mod web_socket_bridge;
mod web_socket_buffer;
pub mod web_socket_compression;
mod web_socket_connector;
mod web_socket_error;
pub(crate) mod web_socket_mut;
pub(crate) mod web_socket_owned;
mod web_socket_payload_origin;
pub(crate) mod write_frame;

use crate::{
  MAX_PAYLOAD_LEN,
  collections::VectorUsize,
  misc::LeaseMut,
  net::{ConnectionState, Stream},
  rng::{SeedableRng as _, Xorshift64},
  tls::{TlsCtx, TlsStream},
  web_socket::{web_socket_compression::NegotiatedWsCompression, write_frame::QueuedStream},
};
pub use close_code::CloseCode;
use core::marker::PhantomData;
pub use frame::{
  Frame, FrameControlArray, FrameMut, FrameRef, FrameVector, FrameVectorMut, FrameVectorRef,
};
pub use op_code::OpCode;
pub use web_socket_acceptor::WebSocketAcceptor;
pub use web_socket_bridge::{WebSocketBridge, WebSocketBridgeData};
pub use web_socket_buffer::WebSocketBuffer;
pub use web_socket_compression::{DeflateConfig, WsCompression};
pub use web_socket_connector::WebSocketConnector;
pub use web_socket_error::WebSocketError;
pub use web_socket_mut::{Fill, WebSocketCommonMut, WebSocketReaderMut, WebSocketWriterMut};
pub use web_socket_owned::{WebSocketReaderOwned, WebSocketWriterOwned};
pub use web_socket_payload_origin::WebSocketPayloadOrigin;

const FIN_MASK: u8 = 0b1000_0000;
const MASK_MASK: u8 = 0b1000_0000;
const MAX_CONTROL_PAYLOAD_LEN: usize = 125;
const MAX_HEADER_LEN: usize = 14;
const OP_CODE_MASK: u8 = 0b0000_1111;
const PAYLOAD_MASK: u8 = 0b0111_1111;
const RSV1_MASK: u8 = 0b0100_0000;
const RSV2_MASK: u8 = 0b0010_0000;
const RSV3_MASK: u8 = 0b0001_0000;

type IntoSplitTy<NC, S, TCX, const IS_CLIENT: bool> = (
  WebSocketBridge<IS_CLIENT>,
  WebSocketReaderOwned<
    <NC as NegotiatedWsCompression>::Decompression,
    <S as Stream>::ReadHalfOwned,
    TCX,
    IS_CLIENT,
  >,
  WebSocketWriterOwned<
    <NC as NegotiatedWsCompression>::Compression,
    <S as Stream>::WriteHalfOwned,
    TCX,
    IS_CLIENT,
  >,
);

/// Full-duplex communication over an asynchronous stream.
///
/// <https://tools.ietf.org/html/rfc6455>
// `repr(C)` with what every frame reads first: the frame checks, then the buffers (whose hot
// fields lead), then the stream (likewise). In the compiler's order those fields sat on five
// cache lines of a 360-byte struct; this way they take three.
#[derive(Debug)]
#[repr(C)]
pub struct WebSocket<NC, S, TCX, const IS_CLIENT: bool> {
  max_payload_len: usize,
  is_in_continuation_frame: Option<is_in_continuation_frame::IsInContinuationFrame>,
  nc_rsv1: u8,
  no_masking: bool,
  nc: NC,
  wsb: WebSocketBuffer,
  stream: TlsStream<S, TCX, IS_CLIENT>,
  rng: Xorshift64,
}

impl<NC, S, TCX, const IS_CLIENT: bool> WebSocket<NC, S, TCX, IS_CLIENT> {
  /// Sets whether to automatically close the connection when a received frame payload length
  /// exceeds `max_payload_len`. Defaults to `64 * 1024 * 1024` bytes (64 MiB).
  #[inline]
  pub const fn max_payload_len_mut(&mut self) -> &mut usize {
    &mut self.max_payload_len
  }
}

impl<NC, S, TCX, const IS_CLIENT: bool> WebSocket<NC, S, TCX, IS_CLIENT>
where
  NC: NegotiatedWsCompression,
  S: Stream,
  TCX: TlsCtx,
{
  /// Creates a new instance from a stream that supposedly has already completed the handshake.
  #[inline]
  pub fn new(
    nc: NC,
    no_masking: bool,
    rng: Xorshift64,
    stream: TlsStream<S, TCX, IS_CLIENT>,
    wsb: WebSocketBuffer,
  ) -> Self {
    let nc_rsv1 = nc.rsv1();
    Self {
      is_in_continuation_frame: None,
      max_payload_len: MAX_PAYLOAD_LEN,
      nc,
      nc_rsv1,
      no_masking,
      rng,
      stream,
      wsb,
    }
  }

  /// Reads a frame from the stream.
  ///
  /// If a frame is made up of other sub-frames or continuations, then everything is collected
  /// until all fragments are received.
  #[inline]
  pub async fn read_frame<'buffer, 'frame, 'this>(
    &'this mut self,
    buffer: &'buffer mut VectorUsize<u8>,
    payload_origin: WebSocketPayloadOrigin,
  ) -> crate::Result<FrameMut<'frame>>
  where
    'buffer: 'frame,
    'this: 'frame,
  {
    let WebSocket {
      is_in_continuation_frame,
      max_payload_len,
      nc,
      nc_rsv1,
      no_masking,
      rng,
      stream,
      wsb,
    } = self;
    let WebSocketBuffer { network_buffer, reader_buffer, writer_buffer: _, write_queue } = wsb;
    let rslt: crate::Result<FrameMut<'frame>> = 'read: {
      if is_in_continuation_frame.is_none() {
        buffer.clear();
        loop {
          match read_frame::buffered_data_frame::<NC, IS_CLIENT>(
            *max_payload_len,
            *nc_rsv1,
            network_buffer.following(),
            *no_masking,
          ) {
            read_frame::BufferedFrame::Data(rslt) => {
              let (rfi, header_len) = match rslt {
                Ok(elem) => elem,
                Err(err) => break 'read Err(err),
              };
              break 'read read_frame::take_buffered_data_frame::<IS_CLIENT>(
                header_len,
                network_buffer,
                *nc_rsv1,
                *no_masking,
                payload_origin,
                &rfi,
                buffer,
              );
            }
            read_frame::BufferedFrame::Incomplete(frame_len) => {
              let local_stream =
                &mut QueuedStream { stream: &mut *stream, write_queue: &mut *write_queue };
              match network_buffer.read_following(frame_len, local_stream).await {
                Ok(true) => {}
                Ok(false) => break 'read Err(WebSocketError::ClosedConnection.into()),
                Err(err) => break 'read Err(err),
              }
            }
            read_frame::BufferedFrame::Other => break,
          }
        }
      }
      read_frame::read_frame::<_, _, _, _, _, true, IS_CLIENT>(
        is_in_continuation_frame,
        *max_payload_len,
        nc,
        *nc_rsv1,
        network_buffer,
        *no_masking,
        payload_origin,
        reader_buffer,
        rng,
        &mut QueuedStream { stream: &mut *stream, write_queue: &mut *write_queue },
        None,
        buffer,
        |el| el.stream.connection_state = ConnectionState::ClosedGracefully,
        |local_stream| local_stream,
        |local_stream| local_stream,
      )
      .await
    };
    if rslt.is_err() {
      // Frames queued before the error still go out, in front of whatever the caller sends next.
      core::hint::cold_path();
      let _rslt = write_frame::flush_write_queue(stream, write_queue).await;
    }
    rslt
  }

  /// Different mutable parts that allow sending received frames using common elements.
  #[inline]
  pub const fn split_mut(
    &mut self,
  ) -> (
    WebSocketCommonMut<'_, NC, S, TCX, IS_CLIENT>,
    WebSocketReaderMut<'_, NC, S, TCX, IS_CLIENT>,
    WebSocketWriterMut<'_, NC, S, TCX, IS_CLIENT>,
  ) {
    let WebSocket {
      is_in_continuation_frame,
      nc,
      nc_rsv1,
      no_masking,
      rng,
      stream,
      wsb,
      max_payload_len,
    } = self;
    let WebSocketBuffer { network_buffer, reader_buffer, writer_buffer, write_queue } = wsb;
    (
      WebSocketCommonMut { nc, nc_rsv1: *nc_rsv1, rng, stream, write_queue },
      WebSocketReaderMut {
        is_in_continuation_frame,
        max_payload_len: *max_payload_len,
        network_buffer,
        no_masking: *no_masking,
        phantom: PhantomData,
        reader_buffer,
      },
      WebSocketWriterMut { no_masking: *no_masking, phantom: PhantomData, writer_buffer },
    )
  }

  /// Sends the frames queued by [`Self::write_frame_buffered`], if any.
  #[inline]
  pub async fn flush(&mut self) -> crate::Result<()> {
    write_frame::flush_write_queue(&mut self.stream, &mut self.wsb.write_queue).await
  }

  /// Writes a frame to the stream, after any frames queued by [`Self::write_frame_buffered`].
  #[inline]
  pub async fn write_frame<P>(&mut self, frame: &mut Frame<P>) -> crate::Result<()>
  where
    P: LeaseMut<[u8]>,
  {
    write_frame::write_frame::<_, _, _, _, IS_CLIENT>(
      frame,
      self.no_masking,
      &mut self.nc,
      self.nc_rsv1,
      &mut self.rng,
      &mut QueuedStream { stream: &mut self.stream, write_queue: &mut self.wsb.write_queue },
      &mut self.wsb.writer_buffer,
      |el| el.stream.connection_state = ConnectionState::WriteClosed,
    )
    .await
  }

  /// Queues a frame instead of writing it, so that several frames can go out in one syscall.
  ///
  /// Queued frames are sent before the next read from the stream would wait for the peer, by
  /// [`Self::write_frame`] and [`Self::flush`], or once the queue holds 16 KiB. A close frame is
  /// sent at once, with everything queued in front of it. Large payloads are not copied.
  ///
  /// Call [`Self::flush`] when no further read follows, for example before dropping the
  /// instance or splitting it with `into_split`.
  #[inline]
  pub async fn write_frame_buffered<P>(&mut self, frame: &mut Frame<P>) -> crate::Result<()>
  where
    P: LeaseMut<[u8]>,
  {
    if write_frame::try_queue_frame::<NC, _, _, IS_CLIENT>(
      frame,
      write_frame::WRITE_QUEUE_FLUSH_LEN,
      self.no_masking,
      self.nc_rsv1,
      &mut self.rng,
      &mut self.wsb.write_queue,
    )? {
      return Ok(());
    }
    write_frame::write_frame_buffered::<_, _, _, _, IS_CLIENT>(
      frame,
      self.no_masking,
      &mut self.nc,
      self.nc_rsv1,
      &mut self.rng,
      &mut self.stream,
      &mut self.wsb.writer_buffer,
      &mut self.wsb.write_queue,
      |el| el.connection_state = ConnectionState::WriteClosed,
    )
    .await
  }
}

impl<NC, S, TCX, const IS_CLIENT: bool> WebSocket<NC, S, TCX, IS_CLIENT>
where
  NC: NegotiatedWsCompression,
  S: Stream,
  TCX: TlsCtx,
{
  /// Splits this instance into owned parts that can be used in concurrent scenarios.
  #[inline]
  pub fn into_split(self) -> crate::Result<IntoSplitTy<NC, S, TCX, IS_CLIENT>> {
    let WebSocket {
      is_in_continuation_frame,
      nc,
      nc_rsv1,
      no_masking,
      mut rng,
      stream,
      wsb,
      max_payload_len,
    } = self;
    let (compression, decompression) = nc.into_split();
    let WebSocketBuffer { network_buffer, reader_buffer, writer_buffer, write_queue: _ } = wsb;
    let (stream_bridge_tls, stream_reader, stream_writer) = stream.into_split()?;
    let stream_bridge_ws = WebSocketBridge::new(stream_bridge_tls);
    Ok((
      stream_bridge_ws.clone(),
      WebSocketReaderOwned {
        is_in_continuation_frame,
        max_payload_len,
        nc: decompression,
        nc_rsv1,
        network_buffer,
        no_masking,
        phantom: PhantomData,
        reader_buffer,
        rng: Xorshift64::from_rng(&mut rng)?,
        stream_bridge: stream_bridge_ws,
        stream_reader,
      },
      WebSocketWriterOwned {
        nc: compression,
        nc_rsv1,
        no_masking,
        rng,
        stream_writer,
        writer_buffer,
      },
    ))
  }
}
