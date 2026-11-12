use crate::{
  net::{BufStreamReader, StreamReader},
  web_socket::{
    FIN_MASK, MAX_CONTROL_PAYLOAD_LEN, MAX_HEADER_LEN, OpCode, PAYLOAD_MASK, RSV1_MASK, RSV2_MASK,
    RSV3_MASK, WebSocketError,
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
    let rslt = Self::parse_header::<D, IS_CLIENT>(
      network_buffer.following(),
      max_payload_len,
      nc_rsv1,
      no_masking,
    )?;
    Some(rslt.map(|(rfi, header_len)| {
      network_buffer.consume_following(header_len);
      rfi
    }))
  }

  /// Parses the header at the start of `bytes` without consuming anything, returning it with its
  /// length. `None` if `bytes` ends before the header does.
  #[inline(always)]
  pub(crate) fn parse_header<D, const IS_CLIENT: bool>(
    bytes: &[u8],
    max_payload_len: usize,
    nc_rsv1: u8,
    no_masking: bool,
  ) -> Option<crate::Result<(Self, usize)>>
  where
    D: WebSocketDecompression,
  {
    let [b0, b1, rest @ ..] = bytes else {
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
    let header_len = bytes.len().wrapping_sub(rest.len());
    if let Err(err) = Self::manage_final_params(fin, op_code, max_payload_len, payload_len) {
      return Some(Err(err));
    }
    Some(Ok((ReadFrameInfo { fin, mask, op_code, payload_len, should_decompress }, header_len)))
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
    let should_decompress = if D::IS_NOOP || nc_rsv1 == 0 {
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
      // RFC 6455 5.1: a server MUST NOT mask its frames, and a client that gets one closes.
      if masked {
        return Err(WebSocketError::InvalidMaskBit.into());
      }
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

#[cfg(test)]
mod tests {
  use super::ReadFrameInfo;

  const MAX: usize = 1024 * 1024;

  fn server(bytes: &[u8]) -> Option<crate::Result<(ReadFrameInfo, usize)>> {
    ReadFrameInfo::parse_header::<(), false>(bytes, MAX, 0, false)
  }

  fn client(bytes: &[u8]) -> Option<crate::Result<(ReadFrameInfo, usize)>> {
    ReadFrameInfo::parse_header::<(), true>(bytes, MAX, 0, false)
  }

  // The header checks every frame reader leans on, in the shape Autobahn's fuzzing client
  // sends them: reserved bits, reserved opcodes, fragmented or oversized control frames, the
  // client mask, and the payload cap.
  #[test]
  fn server_side_header_checks() {
    for (name, bytes) in [
      ("rsv1", [0xC1, 0x81, 1, 2, 3, 4].as_slice()),
      ("rsv2", [0xA1, 0x81, 1, 2, 3, 4].as_slice()),
      ("rsv3", [0x91, 0x81, 1, 2, 3, 4].as_slice()),
      ("opcode 3", [0x83, 0x81, 1, 2, 3, 4].as_slice()),
      ("opcode 7", [0x87, 0x81, 1, 2, 3, 4].as_slice()),
      ("opcode 0xB", [0x8B, 0x81, 1, 2, 3, 4].as_slice()),
      ("opcode 0xF", [0x8F, 0x81, 1, 2, 3, 4].as_slice()),
      ("fragmented ping", [0x09, 0x81, 1, 2, 3, 4].as_slice()),
      ("control of 126", [0x89, 0xFE, 0x00, 0x7E, 1, 2, 3, 4].as_slice()),
      ("unmasked", [0x81, 0x01, b'x'].as_slice()),
    ] {
      assert!(server(bytes).unwrap().is_err(), "{name}");
    }
    // A payload of exactly the cap is already too large: the check is `>=`.
    let mut at_cap = [0x81, 0x7F].to_vec();
    at_cap.extend((MAX as u64).to_be_bytes());
    at_cap.extend_from_slice(&[1, 2, 3, 4]);
    assert!(server(&at_cap).unwrap().is_err());
    // A well-formed masked text frame parses.
    let (rfi, len) = server(&[0x81, 0x81, 1, 2, 3, 4, b'x' ^ 1]).unwrap().unwrap();
    assert_eq!((rfi.op_code, rfi.payload_len, len), (crate::web_socket::OpCode::Text, 1, 6));
  }

  // RFC 6455 5.1: a server MUST NOT mask; the client must refuse the frame, as gorilla's does.
  #[test]
  fn client_rejects_a_masked_server_frame() {
    assert!(client(&[0x81, 0x82, 1, 2, 3, 4, b'x' ^ 1, b'y' ^ 2]).unwrap().is_err());
  }

  // RFC 6455 5.2 has the sender use the minimal length field but doesn't make the receiver
  // refuse a longer one, and Autobahn doesn't test it: a five-byte payload behind a 16-bit or
  // 64-bit length is read, by choice.
  #[test]
  fn non_minimal_length_encoding_is_accepted() {
    let (rfi, len) = server(&[0x81, 0xFE, 0x00, 0x05, 1, 2, 3, 4, 1, 2, 3, 4, 5]).unwrap().unwrap();
    assert_eq!((rfi.payload_len, len), (5, 8));
    let mut sixty_four = [0x81, 0xFF, 0, 0, 0, 0, 0, 0, 0, 5, 1, 2, 3, 4].to_vec();
    sixty_four.extend_from_slice(&[1, 2, 3, 4, 5]);
    let (rfi, len) = server(&sixty_four).unwrap().unwrap();
    assert_eq!((rfi.payload_len, len), (5, 14));
  }
}
