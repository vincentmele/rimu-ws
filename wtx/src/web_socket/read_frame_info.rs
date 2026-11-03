use crate::{
  net::{BufStreamReader, StreamReader},
  web_socket::{
    FIN_MASK, MAX_CONTROL_PAYLOAD_LEN, MAX_HEADER_LEN, OpCode, PAYLOAD_MASK, RSV1_MASK, RSV2_MASK, RSV3_MASK,
    WebSocketError,
    misc::{has_masked_frame, op_code},
    web_socket_compression::WebSocketDecompression,
  },
};

/// Parameters of an WebSocket frame.
#[derive(Debug)]
pub(crate) struct ReadFrameInfo {
  pub(crate) fin: bool,
  pub(crate) mask: Option<[u8; 4]>,
  pub(crate) op_code: OpCode,
  pub(crate) payload_len: usize,
  pub(crate) should_decompress: bool,
}

impl ReadFrameInfo {
  /// Creates a new instance based on a sequence of bytes.
  #[cfg(feature = "http2")]
  #[inline]
  pub(crate) fn from_bytes<NC, const IS_CLIENT: bool>(
    bytes: &mut &[u8],
    max_payload_len: usize,
    nc_rsv1: u8,
    no_masking: bool,
  ) -> crate::Result<Self>
  where
    NC: crate::web_socket::web_socket_compression::NegotiatedWsCompression,
  {
    let first_two = {
      let [b0, b1, rest @ ..] = bytes else {
        return Err(crate::Error::UnexpectedBufferState);
      };
      *bytes = rest;
      [*b0, *b1]
    };
    let tuple = Self::manage_first_two_bytes::<NC>(first_two, nc_rsv1)?;
    let (fin, length_code, masked, op_code, should_decompress) = tuple;
    let payload_len = match length_code {
      126 => {
        let [b0, b1, rest @ ..] = bytes else {
          return Err(crate::Error::UnexpectedBufferState);
        };
        *bytes = rest;
        u16::from_be_bytes([*b0, *b1]).into()
      }
      127 => {
        let [b0, b1, b2, b3, b4, b5, b6, b7, rest @ ..] = bytes else {
          return Err(crate::Error::UnexpectedBufferState);
        };
        *bytes = rest;
        u64::from_be_bytes([*b0, *b1, *b2, *b3, *b4, *b5, *b6, *b7]).try_into()?
      }
      _ => length_code.into(),
    };
    let mask = if Self::manage_mask::<IS_CLIENT>(masked, no_masking)? {
      let [b0, b1, b2, b3, rest @ ..] = bytes else {
        return Err(crate::Error::UnexpectedBufferState);
      };
      *bytes = rest;
      Some([*b0, *b1, *b2, *b3])
    } else {
      None
    };
    Self::manage_final_params(fin, op_code, max_payload_len, payload_len)?;
    Ok(ReadFrameInfo { fin, mask, op_code, payload_len, should_decompress })
  }

  pub(crate) async fn from_stream<D, SR, const IS_CLIENT: bool>(
    max_payload_len: usize,
    nc_rsv1: u8,
    network_buffer: &mut BufStreamReader,
    no_masking: bool,
    stream: &mut SR,
  ) -> crate::Result<Self>
  where
    D: WebSocketDecompression,
    SR: StreamReader,
  {
    loop {
      if let Some(rslt) =
        Self::from_following::<D, IS_CLIENT>(max_payload_len, nc_rsv1, network_buffer, no_masking)
      {
        return rslt;
      }
      if !network_buffer.read_following(MAX_HEADER_LEN, stream).await? {
        return Err(WebSocketError::ClosedConnection.into());
      }
    }
  }

  /// Parses the header in one pass if it is buffered. `None` if more bytes have to be read first.
  #[inline]
  fn from_following<D, const IS_CLIENT: bool>(
    max_payload_len: usize,
    nc_rsv1: u8,
    network_buffer: &mut BufStreamReader,
    no_masking: bool,
  ) -> Option<crate::Result<Self>>
  where
    D: WebSocketDecompression,
  {
    let following = network_buffer.following();
    let [b0, b1, rest @ ..] = following else {
      return None;
    };
    let (fin, length_code, masked, op_code, should_decompress) =
      match Self::manage_first_two_bytes::<D>([*b0, *b1], nc_rsv1) {
        Ok(elem) => elem,
        Err(err) => return Some(Err(err)),
      };
    let (payload_len, rest): (usize, _) = match length_code {
      126 => {
        let [l0, l1, rest @ ..] = rest else {
          return None;
        };
        (u16::from_be_bytes([*l0, *l1]).into(), rest)
      }
      127 => {
        let [l0, l1, l2, l3, l4, l5, l6, l7, rest @ ..] = rest else {
          return None;
        };
        match u64::from_be_bytes([*l0, *l1, *l2, *l3, *l4, *l5, *l6, *l7]).try_into() {
          Ok(elem) => (elem, rest),
          Err(err) => return Some(Err(err.into())),
        }
      }
      _ => (length_code.into(), rest),
    };
    let (mask, rest) = match Self::manage_mask::<IS_CLIENT>(masked, no_masking) {
      Ok(true) => {
        let [m0, m1, m2, m3, rest @ ..] = rest else {
          return None;
        };
        (Some([*m0, *m1, *m2, *m3]), rest)
      }
      Ok(false) => (None, rest),
      Err(err) => return Some(Err(err)),
    };
    let header_len = following.len().wrapping_sub(rest.len());
    if let Err(err) = Self::manage_final_params(fin, op_code, max_payload_len, payload_len) {
      return Some(Err(err));
    }
    network_buffer.consume_following(header_len);
    Some(Ok(ReadFrameInfo { fin, mask, op_code, payload_len, should_decompress }))
  }

  fn manage_final_params(
    fin: bool,
    op_code: OpCode,
    max_payload_len: usize,
    payload_len: usize,
  ) -> crate::Result<()> {
    if op_code.is_control() && !fin {
      return Err(WebSocketError::UnexpectedFragmentedControlFrame.into());
    }
    if op_code.is_control() && payload_len > MAX_CONTROL_PAYLOAD_LEN {
      return Err(WebSocketError::VeryLargeControlFrame.into());
    }
    if payload_len >= max_payload_len {
      return Err(WebSocketError::VeryLargePayload.into());
    }
    Ok(())
  }

  fn manage_first_two_bytes<D>(
    [b0, b1]: [u8; 2],
    nc_rsv1: u8,
  ) -> crate::Result<(bool, u8, bool, OpCode, bool)>
  where
    D: WebSocketDecompression,
  {
    let rsv1 = b0 & RSV1_MASK;
    let rsv2 = b0 & RSV2_MASK;
    let rsv3 = b0 & RSV3_MASK;
    if rsv2 != 0 || rsv3 != 0 {
      return Err(WebSocketError::InvalidCompressionHeaderParameter.into());
    }
    let should_decompress = if D::IS_NOOP {
      false
    } else if nc_rsv1 == 0 {
      if rsv1 != 0 {
        return Err(WebSocketError::InvalidCompressionHeaderParameter.into());
      }
      false
    } else {
      rsv1 != 0
    };
    let fin = b0 & FIN_MASK != 0;
    let length_code = b1 & PAYLOAD_MASK;
    let masked = has_masked_frame(b1);
    let op_code = op_code(b0)?;
    Ok((fin, length_code, masked, op_code, should_decompress))
  }

  fn manage_mask<const IS_CLIENT: bool>(masked: bool, no_masking: bool) -> crate::Result<bool> {
    Ok(if IS_CLIENT {
      false
    } else if no_masking {
      if masked {
        return Err(WebSocketError::InvalidMaskBit.into());
      }
      false
    } else {
      if !masked {
        return Err(WebSocketError::InvalidMaskBit.into());
      }
      true
    })
  }
}
