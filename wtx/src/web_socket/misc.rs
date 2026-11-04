use crate::{
  collections::ArrayVectorCopy,
  futures::FnMutFut,
  misc::from_utf8_basic,
  net::{ConnectionState, StreamWriter},
  rng::Rng,
  tls::{TlsCtx, TlsStream},
  web_socket::{
    CloseCode, Frame, MASK_MASK, MAX_CONTROL_PAYLOAD_LEN, MAX_HEADER_LEN, OP_CODE_MASK, OpCode,
    WebSocketError, write_frame::mask_frame,
  },
};

// Inlined so that a frame's header can stay in registers: out of line, it is returned through
// memory, built with byte stores and read back wider, which stalls store forwarding.
#[inline(always)]
pub(crate) fn header_from_params(
  fin: bool,
  op_code: OpCode,
  payload_len: usize,
  rsv1: u8,
) -> ArrayVectorCopy<u8, MAX_HEADER_LEN> {
  #[inline(always)]
  fn first_header_byte(fin: bool, op_code: OpCode, rsv1: u8) -> u8 {
    (u8::from(fin) << 7) | rsv1 | u8::from(op_code)
  }

  let mut header = ArrayVectorCopy::new();
  match payload_len {
    0..=125 => {
      let _rslt = header.extend_from_copyable_slice(&[
        first_header_byte(fin, op_code, rsv1),
        u8::try_from(payload_len).unwrap_or_default(),
      ]);
    }
    126..=65_535 => {
      let [len_c, len_d] = u16::try_from(payload_len).map_or_default(u16::to_be_bytes);
      let _rslt = header.extend_from_copyable_slice(&[
        first_header_byte(fin, op_code, rsv1),
        126,
        len_c,
        len_d,
      ]);
    }
    _ => {
      let len = u64::try_from(payload_len).map_or_default(u64::to_be_bytes);
      let [len_c, len_d, len_e, len_f, len_g, len_h, len_i, len_j] = len;
      let _rslt = header.extend_from_copyable_slice(&[
        first_header_byte(fin, op_code, rsv1),
        127,
        len_c,
        len_d,
        len_e,
        len_f,
        len_g,
        len_h,
        len_i,
        len_j,
      ]);
    }
  }
  header
}

pub(crate) const fn has_masked_frame(second_header_byte: u8) -> bool {
  second_header_byte & MASK_MASK != 0
}

/// Returns `true` if `payload` is greater than the maximum allowed length.
#[inline]
pub(crate) fn manage_read_close_frame(
  close_code: CloseCode,
  payload: &mut [u8],
) -> crate::Result<bool> {
  match payload {
    [] => Ok(false),
    [_] => Err(WebSocketError::InvalidCloseFrame.into()),
    [b1, b2, rest @ ..] => {
      let _str_validation = from_utf8_basic(rest)?;
      let read_close_code = CloseCode::try_from(u16::from_be_bytes([*b1, *b2]))?;
      if !read_close_code.is_allowed() || rest.len() > MAX_CONTROL_PAYLOAD_LEN - 2 {
        let [b3, b4] = close_code.bytes();
        *b1 = b3;
        *b2 = b4;
        Ok(true)
      } else {
        Ok(false)
      }
    }
  }
}

pub(crate) fn op_code(first_header_byte: u8) -> crate::Result<OpCode> {
  OpCode::try_from(first_header_byte & OP_CODE_MASK)
}

pub(crate) async fn write_control_frame<A, RNG, const IS_CLIENT: bool>(
  aux: A,
  no_masking: bool,
  op_code: OpCode,
  payload: &mut [u8],
  rng: &mut RNG,
  mut wsc_cb: impl for<'any> FnMutFut<(A, &'any [u8], &'any [u8]), Result = crate::Result<()>>,
) -> crate::Result<()>
where
  RNG: Rng,
{
  let mut frame = Frame::new(true, op_code, payload, 0);
  mask_frame::<_, _, IS_CLIENT>(&mut frame, no_masking, rng);
  wsc_cb.call((aux, frame.header(), frame.payload())).await?;
  Ok(())
}

pub(crate) async fn write_control_frame_cb<SW>(
  stream: &mut SW,
  header: &[u8],
  payload: &[u8],
) -> crate::Result<()>
where
  SW: StreamWriter,
{
  stream.write_all_vectored(&[header, payload]).await?;
  Ok(())
}

/// The close code RFC 6455 has an endpoint send when a frame it received breaks the protocol
/// (1002), carries invalid UTF-8 (1007) or is too large (1009). `None` for errors that are not
/// about the peer's frames, such as I/O errors or the end of the stream.
pub(crate) fn read_error_close_code(err: &crate::Error) -> Option<CloseCode> {
  match err {
    crate::Error::InvalidUTF8 => Some(CloseCode::Invalid),
    // A reserved op code or close code
    crate::Error::UnexpectedUint { .. } => Some(CloseCode::Protocol),
    crate::Error::WebSocket(elem) => match elem {
      WebSocketError::VeryLargePayload => Some(CloseCode::Size),
      WebSocketError::InvalidCloseFrame
      | WebSocketError::InvalidCompressionHeaderParameter
      | WebSocketError::InvalidControlFrame
      | WebSocketError::InvalidMaskBit
      | WebSocketError::MissingFrameMask
      | WebSocketError::UnexpectedFragmentedControlFrame
      | WebSocketError::UnexpectedFrame
      | WebSocketError::VeryLargeControlFrame => Some(CloseCode::Protocol),
      WebSocketError::ClosedConnection
      | WebSocketError::ClosedHandshake
      | WebSocketError::DuplicatedHeader
      | WebSocketError::InvalidCloseFrameParams
      | WebSocketError::InvalidHandshakeRequest
      | WebSocketError::MissingSwitchingProtocols { .. }
      | WebSocketError::VeryLargeHandshake => None,
    },
    _ => None,
  }
}

/// Fails the connection after a read returned `err` (RFC 6455, 7.1.7): if a received frame was
/// at fault and no close frame was sent yet, sends one with the code for it. Best effort, as the
/// connection is dropped next either way.
#[cold]
#[inline(never)]
pub(crate) async fn write_error_close_frame<RNG, S, TCX, const IS_CLIENT: bool>(
  err: &crate::Error,
  no_masking: bool,
  rng: &mut RNG,
  stream: &mut TlsStream<S, TCX, IS_CLIENT>,
) where
  RNG: Rng,
  S: StreamWriter,
  TCX: TlsCtx,
{
  if !matches!(stream.connection_state, ConnectionState::Open) {
    return;
  }
  let Some(close_code) = read_error_close_code(err) else {
    return;
  };
  let mut payload = close_code.bytes();
  let mut frame = Frame::new(true, OpCode::Close, &mut payload[..], 0);
  mask_frame::<_, _, IS_CLIENT>(&mut frame, no_masking, rng);
  stream.connection_state = ConnectionState::WriteClosed;
  let _rslt = stream.write_all_vectored(&[frame.header(), frame.payload()]).await;
}
