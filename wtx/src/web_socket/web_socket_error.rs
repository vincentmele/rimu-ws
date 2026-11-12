/// WebSocket Error
#[derive(Clone, Copy, Debug)]
pub enum WebSocketError {
  /// Peer closed the connection with or without a graceful stop
  ClosedConnection,
  /// User manually closed the handshake process midway.
  ClosedHandshake,
  /// HTTP headers must be unique.
  DuplicatedHeader,
  /// Received close frame has invalid parameters.
  InvalidCloseFrame,
  /// It was not possible to create a close frame with the given parameters.
  InvalidCloseFrameParams,
  /// Control frames can not exceed 125 bytes.
  InvalidControlFrame,
  /// An upgrade request RFC 6455 has the server refuse; it was answered 400.
  InvalidHandshakeRequest,
  /// Received an invalid header compression parameter.
  InvalidCompressionHeaderParameter,
  /// A frame's mask bit is wrong for its sender: unmasked from a client or masked from a server.
  InvalidMaskBit,
  /// Server received a frame without a mask.
  MissingFrameMask,
  /// Handshake response should return a 101 code.
  MissingSwitchingProtocols {
    /// The actual response code received
    found: Option<u16>,
  },
  /// Received control frame wasn't supposed to be fragmented.
  UnexpectedFragmentedControlFrame,
  /// For example, the first frame of a message is a continuation.
  UnexpectedFrame,
  /// Control frames have a maximum allowed size.
  VeryLargeControlFrame,
  /// An upgrade request or response grew past 16 KiB without ending.
  VeryLargeHandshake,
  /// Frame payload exceeds the defined threshold.
  VeryLargePayload,
}
