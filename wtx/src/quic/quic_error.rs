//! Error types of the QUIC wire codecs and, later, of the QUIC connection.

// The crate-wide `Error` must stay small.
const _: () = {
  assert!(size_of::<TransportErrorCode>() <= 2);
  assert!(size_of::<QuicError>() == 1);
};

/// Why a QUIC element could not be processed.
///
/// Alone, in [`crate::Error::Quic`], the offending packet is dropped. Together with a
/// [`TransportErrorCode`], in [`crate::Error::QuicClose`], the connection must be closed with that code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum QuicError {
  /// An ACK range reaches below packet number zero.
  AckRangeUnderflow,
  /// An output buffer is too small for what should be written to it.
  BufferTooSmall,
  /// A connection ID has more bytes than QUIC version 1 allows (20) or than the wire format can
  /// express (255).
  CidTooLong,
  /// CRYPTO data arrived at an encryption level that TLS is not reading: an earlier one, whose
  /// data was complete (with [`TransportErrorCode::ProtocolViolation`]), or a later one, or any
  /// level once the handshake is over (with the `unexpected_message` alert).
  CryptoDataAtWrongLevel,
  /// The same transport parameter was sent more than once.
  DuplicateTransportParameter,
  /// A frame type is not allowed in the type of the packet that carries it.
  FrameNotAllowed,
  /// A TLS handshake message is longer than the 16 KiB that are buffered for one.
  HandshakeMessageTooLong,
  /// The fixed bit of a packet of version 1 is not set.
  InvalidFixedBit,
  /// A field of a frame has a value that the frame cannot have.
  InvalidFrame,
  /// The value or the length of a transport parameter is not valid.
  InvalidTransportParameter,
  /// A frame type is encoded with more bytes than it needs.
  NonMinimalFrameType,
  /// A packet is too short to hold the sample that header protection requires.
  PacketTooShort,
  /// A client sent a transport parameter that only servers can send.
  ServerOnlyTransportParameter,
  /// The TLS handshake failed, with the alert that the transport error code carries.
  TlsAlert,
  /// TLS moved past an encryption level whose traffic secrets were not taken yet.
  TlsSecretsNotTaken,
  /// The input ended before a field or before the number of bytes announced by a length.
  Truncated,
  /// A frame type that this implementation does not know.
  UnknownFrameType,
  /// A value does not fit in a variable-length integer (at most 2^62 - 1).
  VarintOverflow,
}

/// Transport error codes (RFC 9000 section 20.1), the reason in a `CONNECTION_CLOSE` frame of type
/// `0x1c`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorCode {
  /// An endpoint uses this with CONNECTION_CLOSE to signal that the connection is being closed
  /// abruptly in the absence of any error.
  NoError,
  /// The endpoint encountered an internal error and cannot continue with the connection.
  InternalError,
  /// The server refused to accept a new connection.
  ConnectionRefused,
  /// An endpoint received more data than it permitted in its advertised data limits.
  FlowControlError,
  /// An endpoint received a frame for a stream identifier that exceeded its advertised stream
  /// limit for the corresponding stream type.
  StreamLimitError,
  /// An endpoint received a frame for a stream that was not in a state that permitted that frame.
  StreamStateError,
  /// An endpoint received a STREAM frame containing data that exceeded the previously established
  /// final size, a frame that changes a final size or a frame that sets a final size smaller than
  /// the data already received.
  FinalSizeError,
  /// An endpoint received a frame that was badly formatted.
  FrameEncodingError,
  /// An endpoint received transport parameters that were badly formatted, included an invalid
  /// value, was absent even though it is mandatory, was present though it is forbidden, or is
  /// otherwise in error.
  TransportParameterError,
  /// The number of connection IDs provided by the peer exceeds the advertised
  /// `active_connection_id_limit`.
  ConnectionIdLimitError,
  /// An endpoint detected an error with protocol compliance that was not covered by more specific
  /// error codes.
  ProtocolViolation,
  /// A server received a client Initial that contained an invalid Token field.
  InvalidToken,
  /// The application or application protocol caused the connection to be closed.
  ApplicationError,
  /// An endpoint has received more data in CRYPTO frames than it can buffer.
  CryptoBufferExceeded,
  /// An endpoint detected errors in performing key updates.
  KeyUpdateError,
  /// An endpoint has reached the confidentiality or integrity limit for the AEAD algorithm used by
  /// the given connection.
  AeadLimitReached,
  /// An endpoint has determined that the network path is incapable of supporting QUIC.
  NoViablePath,
  /// A TLS alert, `0x0100` plus its description.
  Crypto(u8),
}

impl TransportErrorCode {
  /// The value that goes on the wire.
  #[inline]
  pub const fn code(self) -> u64 {
    match self {
      Self::NoError => 0x00,
      Self::InternalError => 0x01,
      Self::ConnectionRefused => 0x02,
      Self::FlowControlError => 0x03,
      Self::StreamLimitError => 0x04,
      Self::StreamStateError => 0x05,
      Self::FinalSizeError => 0x06,
      Self::FrameEncodingError => 0x07,
      Self::TransportParameterError => 0x08,
      Self::ConnectionIdLimitError => 0x09,
      Self::ProtocolViolation => 0x0a,
      Self::InvalidToken => 0x0b,
      Self::ApplicationError => 0x0c,
      Self::CryptoBufferExceeded => 0x0d,
      Self::KeyUpdateError => 0x0e,
      Self::AeadLimitReached => 0x0f,
      Self::NoViablePath => 0x10,
      Self::Crypto(alert) => 0x100 | alert as u64,
    }
  }

  /// The code of a value that came from the wire, or `None` if it is not defined by the RFC.
  #[inline]
  pub const fn from_code(code: u64) -> Option<Self> {
    Some(match code {
      0x00 => Self::NoError,
      0x01 => Self::InternalError,
      0x02 => Self::ConnectionRefused,
      0x03 => Self::FlowControlError,
      0x04 => Self::StreamLimitError,
      0x05 => Self::StreamStateError,
      0x06 => Self::FinalSizeError,
      0x07 => Self::FrameEncodingError,
      0x08 => Self::TransportParameterError,
      0x09 => Self::ConnectionIdLimitError,
      0x0a => Self::ProtocolViolation,
      0x0b => Self::InvalidToken,
      0x0c => Self::ApplicationError,
      0x0d => Self::CryptoBufferExceeded,
      0x0e => Self::KeyUpdateError,
      0x0f => Self::AeadLimitReached,
      0x10 => Self::NoViablePath,
      0x100..=0x1ff => Self::Crypto((code & 0xff) as u8),
      _ => return None,
    })
  }
}

#[cfg(test)]
mod tests {
  use crate::quic::TransportErrorCode;

  #[test]
  fn transport_error_codes_match_rfc9000_section_20_1() {
    let all = [
      (TransportErrorCode::NoError, 0x00),
      (TransportErrorCode::InternalError, 0x01),
      (TransportErrorCode::ConnectionRefused, 0x02),
      (TransportErrorCode::FlowControlError, 0x03),
      (TransportErrorCode::StreamLimitError, 0x04),
      (TransportErrorCode::StreamStateError, 0x05),
      (TransportErrorCode::FinalSizeError, 0x06),
      (TransportErrorCode::FrameEncodingError, 0x07),
      (TransportErrorCode::TransportParameterError, 0x08),
      (TransportErrorCode::ConnectionIdLimitError, 0x09),
      (TransportErrorCode::ProtocolViolation, 0x0a),
      (TransportErrorCode::InvalidToken, 0x0b),
      (TransportErrorCode::ApplicationError, 0x0c),
      (TransportErrorCode::CryptoBufferExceeded, 0x0d),
      (TransportErrorCode::KeyUpdateError, 0x0e),
      (TransportErrorCode::AeadLimitReached, 0x0f),
      (TransportErrorCode::NoViablePath, 0x10),
      (TransportErrorCode::Crypto(0), 0x100),
      // handshake_failure
      (TransportErrorCode::Crypto(40), 0x128),
      // no_application_protocol
      (TransportErrorCode::Crypto(120), 0x178),
      // missing_extension
      (TransportErrorCode::Crypto(109), 0x16d),
      (TransportErrorCode::Crypto(255), 0x1ff),
    ];
    for (code, value) in all {
      assert_eq!(code.code(), value);
      assert_eq!(TransportErrorCode::from_code(value), Some(code));
    }
    for unknown in [0x11, 0xff, 0x200, 0x4242, u64::MAX] {
      assert_eq!(TransportErrorCode::from_code(unknown), None);
    }
  }
}
