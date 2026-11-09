//! Error types of the HTTP/3 frame and QPACK codecs and, later, of the HTTP/3 connection.

// The crate-wide `Error` must stay small.
const _: () = {
  assert!(size_of::<H3ErrorCode>() == 1);
  assert!(size_of::<Http3Error>() == 1);
};

/// Why an HTTP/3 element could not be processed.
///
/// Alone, in [`crate::Error::Http3`], the element is refused and nothing is closed because of it.
/// Together with an [`H3ErrorCode`], in [`crate::Error::Http3Close`], the connection must be closed
/// with that code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Http3Error {
  /// An output buffer is too small for what should be written to it.
  BufferTooSmall,
  /// A Set Dynamic Table Capacity instruction asks for more than the advertised
  /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (with [`H3ErrorCode::QpackEncoderStreamError`], RFC 9204
  /// section 4.3.1).
  CapacityAboveMaximum,
  /// The decoder-stream instructions that wait to be written grew past their bound (16 KiB): the
  /// peer does not read the decoder stream (with [`H3ErrorCode::ExcessiveLoad`]).
  DecoderStreamBacklog,
  /// A SETTINGS frame carries the same identifier twice (with [`H3ErrorCode::SettingsError`], RFC
  /// 9114 section 7.2.4).
  DuplicateSetting,
  /// More encoder-stream instructions arrived, or more bytes were copied out of the dynamic table,
  /// in one receive turn than the budget of the decoder allows (with
  /// [`H3ErrorCode::ExcessiveLoad`]).
  EncoderInstructionBudget,
  /// An insert is larger than the capacity of the dynamic table (with
  /// [`H3ErrorCode::QpackEncoderStreamError`], RFC 9204 section 3.2.2).
  EntryTooLarge,
  /// A Huffman string decodes to more bytes than its destination allows.
  HuffmanOutputTooLong,
  /// A prefixed integer is larger than 2^62 - 1 (RFC 9204 section 4.1.1).
  IntegerOverflow,
  /// The Base of a field section is negative or does not fit in 64 bits (with
  /// [`H3ErrorCode::QpackDecompressionFailed`], RFC 9204 section 4.5.1.2).
  InvalidBase,
  /// A reference to a dynamic table entry that was evicted, is not inserted yet or, in a field
  /// section, is at or above the Required Insert Count of the section (RFC 9204 section 2.2.3).
  InvalidDynamicIndex,
  /// A Huffman string has a bad code, an EOS symbol or padding that is not a prefix of EOS.
  InvalidHuffman,
  /// An encoded Required Insert Count that no conformant encoder produces (with
  /// [`H3ErrorCode::QpackDecompressionFailed`], RFC 9204 section 4.5.1.1).
  InvalidRequiredInsertCount,
  /// An index past the end of the static table (RFC 9204 section 3.1).
  InvalidStaticIndex,
  /// A frame payload ends inside a field or has bytes after its fields (with
  /// [`H3ErrorCode::FrameError`], RFC 9114 section 7.1).
  MalformedFrame,
  /// A frame type that HTTP/2 used and HTTP/3 reserves: 0x02, 0x06, 0x08 or 0x09 (with
  /// [`H3ErrorCode::FrameUnexpected`], RFC 9114 section 7.2.8).
  ReservedFrameType,
  /// A setting identifier that HTTP/2 used and HTTP/3 reserves: 0x02 to 0x05 (with
  /// [`H3ErrorCode::SettingsError`], RFC 9114 section 7.2.4.1).
  ReservedSetting,
  /// The Required Insert Count of a field section is larger than its largest reference needs
  /// (with [`H3ErrorCode::QpackDecompressionFailed`], RFC 9204 section 2.2.1).
  RequiredInsertCountTooLarge,
  /// A field section would block more streams than the advertised
  /// `SETTINGS_QPACK_BLOCKED_STREAMS` (with [`H3ErrorCode::QpackDecompressionFailed`], RFC 9204
  /// section 2.1.2).
  TooManyBlockedStreams,
  /// A SETTINGS frame has more parameters than are checked for duplicates (64) (with
  /// [`H3ErrorCode::ExcessiveLoad`]).
  TooManySettings,
  /// A field section ends inside a representation (with
  /// [`H3ErrorCode::QpackDecompressionFailed`]).
  Truncated,
}

/// HTTP/3 error codes (RFC 9114 section 8.1) and QPACK error codes (RFC 9204 section 6), the reason
/// in a `CONNECTION_CLOSE` frame of type `0x1d`, a `RESET_STREAM` or a `STOP_SENDING`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H3ErrorCode {
  /// No error. This is used when the connection or stream needs to be closed, but there is no
  /// error to signal.
  NoError,
  /// Peer violated protocol requirements in a way that does not match a more specific error code
  /// or endpoint declines to use the more specific error code.
  GeneralProtocolError,
  /// An internal error has occurred in the HTTP stack.
  InternalError,
  /// The endpoint detected that its peer created a stream that it will not accept.
  StreamCreationError,
  /// A stream required by the HTTP/3 connection was closed or reset.
  ClosedCriticalStream,
  /// A frame was received that was not permitted in the current state or on the current stream.
  FrameUnexpected,
  /// A frame that fails to satisfy layout requirements or with an invalid size was received.
  FrameError,
  /// The endpoint detected that its peer is exhibiting a behavior that might be generating
  /// excessive load.
  ExcessiveLoad,
  /// A stream ID or push ID was used incorrectly, such as exceeding a limit, reducing a limit, or
  /// being reused.
  IdError,
  /// An endpoint detected an error in the payload of a SETTINGS frame.
  SettingsError,
  /// No SETTINGS frame was received at the beginning of the control stream.
  MissingSettings,
  /// A server rejected a request without performing any application processing.
  RequestRejected,
  /// The request or its response (including pushed response) is cancelled.
  RequestCancelled,
  /// The client's stream terminated without containing a fully formed request.
  RequestIncomplete,
  /// An HTTP message was malformed and cannot be processed.
  MessageError,
  /// The TCP connection established in response to a CONNECT request was reset or abnormally
  /// closed.
  ConnectError,
  /// The requested operation cannot be served over HTTP/3. The peer should retry over HTTP/1.1.
  VersionFallback,
  /// The decoder failed to interpret an encoded field section and is not able to continue
  /// decoding that field section.
  QpackDecompressionFailed,
  /// The decoder failed to interpret an encoder instruction received on the encoder stream.
  QpackEncoderStreamError,
  /// The encoder failed to interpret a decoder instruction received on the decoder stream.
  QpackDecoderStreamError,
}

impl H3ErrorCode {
  /// The value that goes on the wire.
  #[inline]
  pub const fn code(self) -> u64 {
    match self {
      Self::NoError => 0x0100,
      Self::GeneralProtocolError => 0x0101,
      Self::InternalError => 0x0102,
      Self::StreamCreationError => 0x0103,
      Self::ClosedCriticalStream => 0x0104,
      Self::FrameUnexpected => 0x0105,
      Self::FrameError => 0x0106,
      Self::ExcessiveLoad => 0x0107,
      Self::IdError => 0x0108,
      Self::SettingsError => 0x0109,
      Self::MissingSettings => 0x010a,
      Self::RequestRejected => 0x010b,
      Self::RequestCancelled => 0x010c,
      Self::RequestIncomplete => 0x010d,
      Self::MessageError => 0x010e,
      Self::ConnectError => 0x010f,
      Self::VersionFallback => 0x0110,
      Self::QpackDecompressionFailed => 0x0200,
      Self::QpackEncoderStreamError => 0x0201,
      Self::QpackDecoderStreamError => 0x0202,
    }
  }

  /// The code of a value that came from the wire, or `None` if neither RFC defines it (RFC 9114
  /// section 8: an unknown code is treated as [`Self::NoError`]).
  #[inline]
  pub const fn from_code(code: u64) -> Option<Self> {
    Some(match code {
      0x0100 => Self::NoError,
      0x0101 => Self::GeneralProtocolError,
      0x0102 => Self::InternalError,
      0x0103 => Self::StreamCreationError,
      0x0104 => Self::ClosedCriticalStream,
      0x0105 => Self::FrameUnexpected,
      0x0106 => Self::FrameError,
      0x0107 => Self::ExcessiveLoad,
      0x0108 => Self::IdError,
      0x0109 => Self::SettingsError,
      0x010a => Self::MissingSettings,
      0x010b => Self::RequestRejected,
      0x010c => Self::RequestCancelled,
      0x010d => Self::RequestIncomplete,
      0x010e => Self::MessageError,
      0x010f => Self::ConnectError,
      0x0110 => Self::VersionFallback,
      0x0200 => Self::QpackDecompressionFailed,
      0x0201 => Self::QpackEncoderStreamError,
      0x0202 => Self::QpackDecoderStreamError,
      _ => return None,
    })
  }
}

#[cfg(test)]
mod tests {
  use crate::http3::H3ErrorCode;

  #[test]
  fn h3_error_codes_match_rfc9114_section_8_1_and_rfc9204_section_6() {
    let all = [
      (H3ErrorCode::NoError, 0x0100),
      (H3ErrorCode::GeneralProtocolError, 0x0101),
      (H3ErrorCode::InternalError, 0x0102),
      (H3ErrorCode::StreamCreationError, 0x0103),
      (H3ErrorCode::ClosedCriticalStream, 0x0104),
      (H3ErrorCode::FrameUnexpected, 0x0105),
      (H3ErrorCode::FrameError, 0x0106),
      (H3ErrorCode::ExcessiveLoad, 0x0107),
      (H3ErrorCode::IdError, 0x0108),
      (H3ErrorCode::SettingsError, 0x0109),
      (H3ErrorCode::MissingSettings, 0x010a),
      (H3ErrorCode::RequestRejected, 0x010b),
      (H3ErrorCode::RequestCancelled, 0x010c),
      (H3ErrorCode::RequestIncomplete, 0x010d),
      (H3ErrorCode::MessageError, 0x010e),
      (H3ErrorCode::ConnectError, 0x010f),
      (H3ErrorCode::VersionFallback, 0x0110),
      (H3ErrorCode::QpackDecompressionFailed, 0x0200),
      (H3ErrorCode::QpackEncoderStreamError, 0x0201),
      (H3ErrorCode::QpackDecoderStreamError, 0x0202),
    ];
    for (code, value) in all {
      assert_eq!(code.code(), value);
      assert_eq!(H3ErrorCode::from_code(value), Some(code));
    }
    // Unassigned, and the reserved 0x1f * N + 0x21 space
    for unknown in [0x00, 0xff, 0x0111, 0x01ff, 0x0203, 0x21, 0x40, u64::MAX] {
      assert_eq!(H3ErrorCode::from_code(unknown), None);
    }
  }
}
