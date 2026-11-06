//! Tools to manage WebSocket connections in HTTP/2 streams

use crate::{
  MAX_PAYLOAD_LEN,
  collections::VectorUsize,
  http::{Headers, StatusCode},
  http2::{Http2Error, Http2ErrorCode, Http2RecvStatus, ServerStream, misc::protocol_err},
  misc::LeaseMut,
  rng::Xorshift64,
  web_socket::{
    Frame, FrameMut, OpCode,
    read_frame::{manage_auto_reply, manage_op_code_of_first_final_frame, unmask_nb},
    read_frame_info::ReadFrameInfo,
    write_frame::mask_frame,
  },
};

/// WebSocket tunneling
/// A WebSocket connection carried by an HTTP/2 stream (RFC 8441).
#[derive(Debug)]
pub struct WebSocketOverStream<S> {
  no_masking: bool,
  rng: Xorshift64,
  /// Received bytes not yet consumed as frames.
  rx: VectorUsize<u8>,
  stream: S,
}

impl<S> WebSocketOverStream<S>
where
  S: LeaseMut<ServerStream>,
{
  /// Accepts the extended CONNECT by answering 200 with `headers`.
  #[inline]
  pub async fn new(
    headers: &Headers,
    no_masking: bool,
    rng: Xorshift64,
    mut stream: S,
  ) -> crate::Result<Self> {
    let hss = stream.lease_mut().send_headers(headers, false, StatusCode::Ok).await?;
    if hss.is_closed() {
      return Err(crate::Error::ClosedHttpConnection);
    }
    Ok(Self { no_masking, rng, rx: VectorUsize::new(), stream })
  }

  /// Closes the stream as well as the WebSocket connection.
  #[inline]
  pub async fn close(&mut self) -> crate::Result<()> {
    self.write_frame(&mut Frame::new(true, OpCode::Close, &mut [], 0)).await?;
    self.stream.lease_mut().send_reset(Http2ErrorCode::NoError).await;
    Ok(())
  }

  /// Reads a frame from the stream.
  ///
  /// If a frame is made up of other sub-frames or continuations, then everything is collected
  /// until all fragments are received.
  #[inline]
  pub async fn read_frame<'buffer>(
    &mut self,
    buffer: &'buffer mut VectorUsize<u8>,
  ) -> crate::Result<FrameMut<'buffer>> {
    buffer.clear();
    let rfi = loop {
      if let Some(rfi) = take_frame(&mut self.rx, buffer, self.no_masking)? {
        break rfi;
      }
      match self.stream.lease_mut().recv_data(&mut self.rx).await? {
        Http2RecvStatus::Ongoing(()) => {}
        Http2RecvStatus::Eos(()) => {
          if let Some(rfi) = take_frame(&mut self.rx, buffer, self.no_masking)? {
            break rfi;
          }
          return Err(crate::Error::ClosedHttpConnection);
        }
        Http2RecvStatus::ClosedConnection | Http2RecvStatus::ClosedStream(()) => {
          return Err(crate::Error::ClosedHttpConnection);
        }
      }
    };
    if rfi.fin {
      let _is_control_frame = manage_auto_reply::<_, _, true, false>(
        self.stream.lease_mut(),
        self.no_masking,
        rfi.op_code,
        buffer,
        &mut self.rng,
        None,
        write_control_frame_cb,
      )
      .await?;
      manage_op_code_of_first_final_frame(rfi.op_code, buffer)?;
      return Ok(FrameMut::new(true, rfi.op_code, buffer, 0));
    }
    Err(protocol_err(Http2Error::WebSocketContinuationFrame))
  }

  /// Writes a frame to the stream.
  #[inline]
  pub async fn write_frame<P>(&mut self, frame: &mut Frame<P>) -> crate::Result<()>
  where
    P: LeaseMut<[u8]>,
  {
    mask_frame::<_, _, false>(frame, self.no_masking, &mut self.rng);
    let (header, payload) = frame.header_and_payload();
    write_control_frame_cb(self.stream.lease_mut(), header, payload.lease()).await
  }
}

/// Moves the payload of the first complete frame of `rx` into `buffer`, unmasked.
fn take_frame(
  rx: &mut VectorUsize<u8>,
  buffer: &mut VectorUsize<u8>,
  no_masking: bool,
) -> crate::Result<Option<ReadFrameInfo>> {
  let Some(frame_len) = frame_len(rx.as_slice()) else {
    return Ok(None);
  };
  let mut slice = rx.get(..frame_len).unwrap_or_default();
  let rfi = ReadFrameInfo::from_bytes::<(), false>(&mut slice, MAX_PAYLOAD_LEN, 0, no_masking)?;
  if slice.len() != rfi.payload_len {
    return Err(crate::Error::UnexpectedBufferState);
  }
  let before = buffer.len();
  buffer.extend_from_copyable_slice(slice)?;
  unmask_nb::<false>(rfi.mask, buffer.get_mut(before..).unwrap_or_default(), no_masking)?;
  let len = rx.len();
  rx.as_slice_mut().copy_within(frame_len..len, 0);
  rx.truncate(len.wrapping_sub(frame_len));
  Ok(Some(rfi))
}

/// Length of the first frame of `bytes` (header and payload) if it is all there.
fn frame_len(bytes: &[u8]) -> Option<usize> {
  let [_, second, rest @ ..] = bytes else {
    return None;
  };
  let masked = second & 0b1000_0000 != 0;
  let (extended, payload_len) = match second & 0b0111_1111 {
    126 => (2, usize::from(u16::from_be_bytes([*rest.first()?, *rest.get(1)?]))),
    127 => {
      let array: [u8; 8] = rest.get(..8)?.try_into().ok()?;
      (8, usize::try_from(u64::from_be_bytes(array)).ok()?)
    }
    len => (0, usize::from(len)),
  };
  let header_len = 2usize.wrapping_add(extended).wrapping_add(if masked { 4 } else { 0 });
  let total = header_len.checked_add(payload_len)?;
  (bytes.len() >= total).then_some(total)
}

async fn write_control_frame_cb(
  stream: &mut ServerStream,
  header: &[u8],
  payload: &[u8],
) -> crate::Result<()> {
  if stream.send_data(header, false).await?.is_closed()
    || stream.send_data(payload, false).await?.is_closed()
  {
    return Err(crate::Error::ClosedHttpConnection);
  }
  Ok(())
}
