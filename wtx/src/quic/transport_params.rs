//! Transport parameters (RFC 9000 section 18), the contents of the TLS extension that carries them.

use crate::quic::{
  Cid, QuicError, TransportErrorCode,
  varint::{VARINT_MAX, decode_varint, encode_varint, varint_len},
};
use core::hint::cold_path;

const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
const MAX_IDLE_TIMEOUT: u64 = 0x01;
const STATELESS_RESET_TOKEN: u64 = 0x02;
const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
const INITIAL_MAX_DATA: u64 = 0x04;
const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
const ACK_DELAY_EXPONENT: u64 = 0x0a;
const MAX_ACK_DELAY: u64 = 0x0b;
const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
const PREFERRED_ADDRESS: u64 = 0x0d;
const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
const RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;

const DEFAULT_ACK_DELAY_EXPONENT: u8 = 3;
const DEFAULT_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;
const DEFAULT_MAX_ACK_DELAY_MS: u64 = 25;
const DEFAULT_MAX_UDP_PAYLOAD_SIZE: u64 = 65527;

const STATELESS_RESET_TOKEN_LEN: usize = 16;

/// The transport parameters of an endpoint.
///
/// Parameters that are absent have the default value that the RFC defines for them, therefore
/// only the ones that differ from it are encoded. `preferred_address` is not supported: it is
/// ignored when a server sends it and refused when a client does.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportParams {
  /// Server only. The destination CID of the first Initial packet of the client.
  pub original_destination_connection_id: Option<Cid>,
  /// Milliseconds after which an idle connection is closed. Zero disables the timeout.
  pub max_idle_timeout_ms: u64,
  /// Server only. Token of the stateless reset of the connection.
  pub stateless_reset_token: Option<[u8; 16]>,
  /// The largest UDP payload that the endpoint is willing to receive.
  pub max_udp_payload_size: u64,
  /// Connection-wide flow control limit.
  pub initial_max_data: u64,
  /// Flow control limit of the data that flows in the streams that the sender opens in the
  /// bidirectional direction.
  pub initial_max_stream_data_bidi_local: u64,
  /// Flow control limit of the data that flows in the streams that the receiver opens in the
  /// bidirectional direction.
  pub initial_max_stream_data_bidi_remote: u64,
  /// Flow control limit of the data that flows in unidirectional streams.
  pub initial_max_stream_data_uni: u64,
  /// Number of bidirectional streams that the peer can open.
  pub initial_max_streams_bidi: u64,
  /// Number of unidirectional streams that the peer can open.
  pub initial_max_streams_uni: u64,
  /// Exponent of the ACK Delay field of ACK frames.
  pub ack_delay_exponent: u8,
  /// The maximum delay in milliseconds that the endpoint adds before acknowledging.
  pub max_ack_delay_ms: u64,
  /// If the endpoint does not support connection migration to a new address.
  pub disable_active_migration: bool,
  /// The number of connection IDs that the endpoint stores.
  pub active_connection_id_limit: u64,
  /// The source CID of the first Initial packet of the endpoint.
  pub initial_source_connection_id: Option<Cid>,
  /// Server only. The source CID of the Retry packet that it sent.
  pub retry_source_connection_id: Option<Cid>,
}

impl TransportParams {
  /// Parses the parameters of a peer.
  ///
  /// `from_server` tells whether the peer is a server, which is the only role that can send the
  /// parameters marked as server only. Unknown parameters are skipped. Parameters that are
  /// duplicated, truncated or have an invalid value are an error of type
  /// [`TransportErrorCode::TransportParameterError`], as well as server-only parameters from a
  /// client. Only the parameters that RFC 9000 defines are checked for duplicates because
  /// remembering unknown ones would need space.
  ///
  /// The presence of the mandatory parameters is left to the caller, who knows what to compare
  /// them with.
  pub fn decode(mut bytes: &[u8], from_server: bool) -> crate::Result<Self> {
    let mut this = Self::default();
    // Bit `n` is set once the parameter with id `n` is parsed
    let mut seen = 0u32;
    while !bytes.is_empty() {
      let (id, rest) = take_varint(bytes)?;
      let (len, rest) = take_varint(rest)?;
      let Some((value, rest)) =
        usize::try_from(len).ok().and_then(|elem| rest.split_at_checked(elem))
      else {
        return Err(error(QuicError::Truncated));
      };
      bytes = rest;
      if id <= RETRY_SOURCE_CONNECTION_ID {
        let bit = 1u32 << id;
        if seen & bit != 0 {
          return Err(error(QuicError::DuplicateTransportParameter));
        }
        seen |= bit;
      }
      if !from_server
        && matches!(
          id,
          ORIGINAL_DESTINATION_CONNECTION_ID
            | STATELESS_RESET_TOKEN
            | PREFERRED_ADDRESS
            | RETRY_SOURCE_CONNECTION_ID
        )
      {
        return Err(error(QuicError::ServerOnlyTransportParameter));
      }
      match id {
        ORIGINAL_DESTINATION_CONNECTION_ID => {
          this.original_destination_connection_id = Some(cid(value)?);
        }
        MAX_IDLE_TIMEOUT => this.max_idle_timeout_ms = varint_value(value)?,
        STATELESS_RESET_TOKEN => {
          let Ok(token) = <[u8; STATELESS_RESET_TOKEN_LEN]>::try_from(value) else {
            return Err(error(QuicError::InvalidTransportParameter));
          };
          this.stateless_reset_token = Some(token);
        }
        MAX_UDP_PAYLOAD_SIZE => {
          this.max_udp_payload_size = bounded(varint_value(value)?, 1200, VARINT_MAX)?;
        }
        INITIAL_MAX_DATA => this.initial_max_data = varint_value(value)?,
        INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
          this.initial_max_stream_data_bidi_local = varint_value(value)?;
        }
        INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
          this.initial_max_stream_data_bidi_remote = varint_value(value)?;
        }
        INITIAL_MAX_STREAM_DATA_UNI => this.initial_max_stream_data_uni = varint_value(value)?,
        INITIAL_MAX_STREAMS_BIDI => {
          this.initial_max_streams_bidi = bounded(varint_value(value)?, 0, 1 << 60)?;
        }
        INITIAL_MAX_STREAMS_UNI => {
          this.initial_max_streams_uni = bounded(varint_value(value)?, 0, 1 << 60)?;
        }
        ACK_DELAY_EXPONENT => {
          this.ack_delay_exponent = u8::try_from(bounded(varint_value(value)?, 0, 20)?)
            .map_err(|_| error(QuicError::InvalidTransportParameter))?;
        }
        MAX_ACK_DELAY => this.max_ack_delay_ms = bounded(varint_value(value)?, 0, (1 << 14) - 1)?,
        DISABLE_ACTIVE_MIGRATION => {
          if !value.is_empty() {
            return Err(error(QuicError::InvalidTransportParameter));
          }
          this.disable_active_migration = true;
        }
        ACTIVE_CONNECTION_ID_LIMIT => {
          this.active_connection_id_limit = bounded(varint_value(value)?, 2, VARINT_MAX)?;
        }
        INITIAL_SOURCE_CONNECTION_ID => this.initial_source_connection_id = Some(cid(value)?),
        RETRY_SOURCE_CONNECTION_ID => this.retry_source_connection_id = Some(cid(value)?),
        // `PREFERRED_ADDRESS`, extensions and reserved ids
        _ => {}
      }
    }
    Ok(this)
  }

  /// Writes, in ascending order of id, the parameters that differ from their default value.
  ///
  /// Returns the number of written bytes.
  pub fn encode(&self, out: &mut [u8]) -> crate::Result<usize> {
    let mut writer = Writer { out, pos: 0 };
    if let Some(elem) = &self.original_destination_connection_id {
      writer.bytes(ORIGINAL_DESTINATION_CONNECTION_ID, elem.as_slice())?;
    }
    writer.varint_if(MAX_IDLE_TIMEOUT, self.max_idle_timeout_ms, 0)?;
    if let Some(elem) = &self.stateless_reset_token {
      writer.bytes(STATELESS_RESET_TOKEN, elem)?;
    }
    writer.varint_if(
      MAX_UDP_PAYLOAD_SIZE,
      self.max_udp_payload_size,
      DEFAULT_MAX_UDP_PAYLOAD_SIZE,
    )?;
    writer.varint_if(INITIAL_MAX_DATA, self.initial_max_data, 0)?;
    writer.varint_if(
      INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
      self.initial_max_stream_data_bidi_local,
      0,
    )?;
    writer.varint_if(
      INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
      self.initial_max_stream_data_bidi_remote,
      0,
    )?;
    writer.varint_if(INITIAL_MAX_STREAM_DATA_UNI, self.initial_max_stream_data_uni, 0)?;
    writer.varint_if(INITIAL_MAX_STREAMS_BIDI, self.initial_max_streams_bidi, 0)?;
    writer.varint_if(INITIAL_MAX_STREAMS_UNI, self.initial_max_streams_uni, 0)?;
    writer.varint_if(
      ACK_DELAY_EXPONENT,
      self.ack_delay_exponent.into(),
      DEFAULT_ACK_DELAY_EXPONENT.into(),
    )?;
    writer.varint_if(MAX_ACK_DELAY, self.max_ack_delay_ms, DEFAULT_MAX_ACK_DELAY_MS)?;
    if self.disable_active_migration {
      writer.bytes(DISABLE_ACTIVE_MIGRATION, &[])?;
    }
    writer.varint_if(
      ACTIVE_CONNECTION_ID_LIMIT,
      self.active_connection_id_limit,
      DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    )?;
    if let Some(elem) = &self.initial_source_connection_id {
      writer.bytes(INITIAL_SOURCE_CONNECTION_ID, elem.as_slice())?;
    }
    if let Some(elem) = &self.retry_source_connection_id {
      writer.bytes(RETRY_SOURCE_CONNECTION_ID, elem.as_slice())?;
    }
    Ok(writer.pos)
  }
}

impl Default for TransportParams {
  /// The values that RFC 9000 section 18.2 assigns to absent parameters.
  #[inline]
  fn default() -> Self {
    Self {
      original_destination_connection_id: None,
      max_idle_timeout_ms: 0,
      stateless_reset_token: None,
      max_udp_payload_size: DEFAULT_MAX_UDP_PAYLOAD_SIZE,
      initial_max_data: 0,
      initial_max_stream_data_bidi_local: 0,
      initial_max_stream_data_bidi_remote: 0,
      initial_max_stream_data_uni: 0,
      initial_max_streams_bidi: 0,
      initial_max_streams_uni: 0,
      ack_delay_exponent: DEFAULT_ACK_DELAY_EXPONENT,
      max_ack_delay_ms: DEFAULT_MAX_ACK_DELAY_MS,
      disable_active_migration: false,
      active_connection_id_limit: DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
      initial_source_connection_id: None,
      retry_source_connection_id: None,
    }
  }
}

// Returns `value` if it is in the range.
fn bounded(value: u64, min: u64, max: u64) -> crate::Result<u64> {
  if (min..=max).contains(&value) {
    Ok(value)
  } else {
    Err(error(QuicError::InvalidTransportParameter))
  }
}

fn cid(value: &[u8]) -> crate::Result<Cid> {
  Cid::new(value).map_err(|_| error(QuicError::CidTooLong))
}

#[inline(always)]
fn error(kind: QuicError) -> crate::Error {
  cold_path();
  crate::Error::QuicClose(TransportErrorCode::TransportParameterError, kind)
}

fn take_varint(bytes: &[u8]) -> crate::Result<(u64, &[u8])> {
  match decode_varint(bytes).and_then(|(value, len)| Some((value, bytes.get(len..)?))) {
    Some(elem) => Ok(elem),
    None => Err(error(QuicError::Truncated)),
  }
}

// The value of a parameter that is a single variable-length integer that takes all the bytes
fn varint_value(value: &[u8]) -> crate::Result<u64> {
  match decode_varint(value) {
    Some((elem, len)) if len == value.len() => Ok(elem),
    _ => Err(error(QuicError::InvalidTransportParameter)),
  }
}

struct Writer<'out> {
  out: &'out mut [u8],
  pos: usize,
}

impl Writer<'_> {
  // A parameter with arbitrary content
  fn bytes(&mut self, id: u64, value: &[u8]) -> crate::Result<()> {
    self.varint(id)?;
    self.varint(u64::try_from(value.len()).unwrap_or(u64::MAX))?;
    let end = self.pos.wrapping_add(value.len());
    let Some(dst) = self.out.get_mut(self.pos..end) else {
      return Err(buffer_too_small());
    };
    dst.copy_from_slice(value);
    self.pos = end;
    Ok(())
  }

  fn varint(&mut self, value: u64) -> crate::Result<()> {
    if value > VARINT_MAX {
      return Err(crate::Error::Quic(QuicError::VarintOverflow));
    }
    let Some(len) = self.out.get_mut(self.pos..).and_then(|dst| encode_varint(value, dst)) else {
      return Err(buffer_too_small());
    };
    self.pos = self.pos.wrapping_add(len);
    Ok(())
  }

  // A parameter whose value is a variable-length integer, unless it is the default one
  fn varint_if(&mut self, id: u64, value: u64, default: u64) -> crate::Result<()> {
    if value == default {
      return Ok(());
    }
    if value > VARINT_MAX {
      return Err(crate::Error::Quic(QuicError::VarintOverflow));
    }
    self.varint(id)?;
    self.varint(u64::try_from(varint_len(value)).unwrap_or_default())?;
    self.varint(value)
  }
}

#[cold]
fn buffer_too_small() -> crate::Error {
  crate::Error::Quic(QuicError::BufferTooSmall)
}

#[cfg(test)]
mod tests {
  use crate::{
    Error,
    quic::{
      Cid, QuicError, TransportErrorCode, TransportParams,
      varint::{encode_varint, varint_len},
    },
  };
  use alloc::vec::Vec;

  fn param(id: u64, value: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    let mut buffer = [0; 8];
    for elem in [id, u64::try_from(value.len()).unwrap()] {
      let len = encode_varint(elem, &mut buffer).unwrap();
      vec.extend_from_slice(&buffer[..len]);
    }
    vec.extend_from_slice(value);
    vec
  }

  fn varint_param(id: u64, value: u64) -> Vec<u8> {
    let mut buffer = [0; 8];
    let len = encode_varint(value, &mut buffer).unwrap();
    assert_eq!(len, varint_len(value));
    param(id, &buffer[..len])
  }

  fn encoded(params: &TransportParams) -> Vec<u8> {
    let mut buffer = [0; 512];
    let len = params.encode(&mut buffer).unwrap();
    buffer[..len].to_vec()
  }

  #[track_caller]
  fn assert_tp_error(result: crate::Result<TransportParams>, expected: QuicError) {
    match result {
      Err(Error::QuicClose(TransportErrorCode::TransportParameterError, error)) => {
        assert_eq!(error, expected)
      }
      other => panic!("{other:?} instead of {expected:?}"),
    }
  }

  fn full_server_params() -> TransportParams {
    TransportParams {
      original_destination_connection_id: Some(Cid::new(&[0x83, 0x94, 0xc8, 0xf0]).unwrap()),
      max_idle_timeout_ms: 30_000,
      stateless_reset_token: Some([0xab; 16]),
      max_udp_payload_size: 1452,
      initial_max_data: 10_485_760,
      initial_max_stream_data_bidi_local: 1_048_576,
      initial_max_stream_data_bidi_remote: 2_097_152,
      initial_max_stream_data_uni: 262_144,
      initial_max_streams_bidi: 100,
      initial_max_streams_uni: 3,
      ack_delay_exponent: 5,
      max_ack_delay_ms: 20,
      disable_active_migration: true,
      active_connection_id_limit: 8,
      initial_source_connection_id: Some(Cid::new(&[1; 8]).unwrap()),
      retry_source_connection_id: Some(Cid::new(&[2; 8]).unwrap()),
    }
  }

  #[test]
  fn defaults_are_the_rfc9000_ones() {
    let params = TransportParams::default();
    assert_eq!(params.original_destination_connection_id, None);
    assert_eq!(params.max_idle_timeout_ms, 0);
    assert_eq!(params.stateless_reset_token, None);
    assert_eq!(params.max_udp_payload_size, 65527);
    assert_eq!(params.initial_max_data, 0);
    assert_eq!(params.initial_max_stream_data_bidi_local, 0);
    assert_eq!(params.initial_max_stream_data_bidi_remote, 0);
    assert_eq!(params.initial_max_stream_data_uni, 0);
    assert_eq!(params.initial_max_streams_bidi, 0);
    assert_eq!(params.initial_max_streams_uni, 0);
    assert_eq!(params.ack_delay_exponent, 3);
    assert_eq!(params.max_ack_delay_ms, 25);
    assert!(!params.disable_active_migration);
    assert_eq!(params.active_connection_id_limit, 2);
    assert_eq!(params.initial_source_connection_id, None);
    assert_eq!(params.retry_source_connection_id, None);
    // Values that are the default are not sent
    assert_eq!(encoded(&params), []);
    assert_eq!(TransportParams::decode(&[], false).unwrap(), params);
    assert_eq!(TransportParams::decode(&[], true).unwrap(), params);
  }

  #[test]
  fn transport_params_round_trip_and_reject_duplicates() {
    let params = full_server_params();
    let bytes = encoded(&params);
    assert_eq!(TransportParams::decode(&bytes, true).unwrap(), params);

    // The same parameters from a client, which can not send the server-only ones
    let client = TransportParams {
      original_destination_connection_id: None,
      stateless_reset_token: None,
      retry_source_connection_id: None,
      ..params
    };
    let bytes = encoded(&client);
    assert_eq!(TransportParams::decode(&bytes, false).unwrap(), client);

    // Every parameter that is sent twice is an error
    for (id, value) in [
      (0x00, &[1u8][..]),
      (0x01, &[0x40, 0x10]),
      (0x02, &[0; 16]),
      (0x03, &[0x44, 0xb0]),
      (0x04, &[1]),
      (0x05, &[1]),
      (0x06, &[1]),
      (0x07, &[1]),
      (0x08, &[1]),
      (0x09, &[1]),
      (0x0a, &[1]),
      (0x0b, &[1]),
      (0x0c, &[]),
      (0x0d, &[0; 41]),
      (0x0e, &[2]),
      (0x0f, &[1]),
      (0x10, &[1]),
    ] {
      let once = param(id, value);
      let mut twice = once.clone();
      twice.extend_from_slice(&once);
      assert!(TransportParams::decode(&once, true).is_ok(), "{id:#x}");
      assert_tp_error(
        TransportParams::decode(&twice, true),
        QuicError::DuplicateTransportParameter,
      );
    }
    // Not adjacent
    let mut bytes = varint_param(0x04, 10);
    bytes.extend_from_slice(&varint_param(0x05, 10));
    bytes.extend_from_slice(&varint_param(0x04, 20));
    assert_tp_error(TransportParams::decode(&bytes, false), QuicError::DuplicateTransportParameter);
  }

  #[test]
  fn transport_params_server_only_id_from_client_rejected() {
    for (id, value) in [(0x00, &[1u8; 8][..]), (0x02, &[7; 16]), (0x0d, &[0; 41]), (0x10, &[1; 8])]
    {
      let bytes = param(id, value);
      assert_tp_error(
        TransportParams::decode(&bytes, false),
        QuicError::ServerOnlyTransportParameter,
      );
      // Unless it comes from a server
      assert!(TransportParams::decode(&bytes, true).is_ok(), "{id:#x}");
    }
    // A client's own parameters before the server-only one do not hide it
    let mut bytes = varint_param(0x04, 10);
    bytes.extend_from_slice(&param(0x02, &[7; 16]));
    assert_tp_error(
      TransportParams::decode(&bytes, false),
      QuicError::ServerOnlyTransportParameter,
    );
  }

  #[test]
  fn transport_params_from_a_server_ignore_the_preferred_address() {
    let mut bytes = param(0x0d, &[0; 41]);
    bytes.extend_from_slice(&varint_param(0x04, 99));
    let params = TransportParams::decode(&bytes, true).unwrap();
    assert_eq!(params.initial_max_data, 99);
  }

  #[test]
  fn transport_params_skip_unknown_ids() {
    let mut bytes = Vec::new();
    // Reserved ids 31 * N + 27, a large id and some extensions seen in the wild
    bytes.extend_from_slice(&param(31 * 7 + 27, b"grease"));
    bytes.extend_from_slice(&varint_param(0x04, 4096));
    bytes.extend_from_slice(&param(0x20, &[0x44, 0x00]));
    bytes.extend_from_slice(&param(0x2ab2, &[]));
    bytes.extend_from_slice(&param(0x11, &[0; 12]));
    bytes.extend_from_slice(&param(0x3fff_ffff_ffff_ffff, &[0xff; 300]));
    bytes.extend_from_slice(&param(0x20, &[0x44, 0x00]));
    let params = TransportParams::decode(&bytes, false).unwrap();
    assert_eq!(params, TransportParams { initial_max_data: 4096, ..TransportParams::default() });
    // Unknown ids are not tracked, so a repeated one is ignored too
    assert_eq!(TransportParams::decode(&bytes, true).unwrap(), params);
  }

  #[test]
  fn transport_params_reject_invalid_values() {
    let invalid = [
      // max_udp_payload_size below 1200
      varint_param(0x03, 1199),
      varint_param(0x03, 0),
      // ack_delay_exponent above 20
      varint_param(0x0a, 21),
      varint_param(0x0a, 255),
      // max_ack_delay of 2^14 or more
      varint_param(0x0b, 1 << 14),
      varint_param(0x0b, 1 << 30),
      // active_connection_id_limit below 2
      varint_param(0x0e, 1),
      varint_param(0x0e, 0),
      // Streams above 2^60
      varint_param(0x08, (1 << 60) + 1),
      varint_param(0x09, (1 << 60) + 1),
      // Reset token with the wrong length
      param(0x02, &[0; 15]),
      param(0x02, &[0; 17]),
      param(0x02, &[]),
      // disable_active_migration carries nothing
      param(0x0c, &[0]),
      // CIDs of more than 20 bytes
      param(0x00, &[0; 21]),
      param(0x0f, &[0; 21]),
      param(0x10, &[0; 255]),
      // A varint whose length is not the length of the parameter
      param(0x04, &[0x25, 0x00]),
      param(0x04, &[0x40]),
      param(0x04, &[0x40, 0x25, 0x00]),
      param(0x04, &[]),
      param(0x01, &[0x80, 0, 0]),
      // A varint value that fills the 8 bytes with a wrong length
      param(0x05, &[0xc0, 0, 0, 0, 0, 0, 0]),
    ];
    for bytes in invalid {
      let from_server = TransportParams::decode(&bytes, true);
      assert!(
        matches!(
          from_server,
          Err(Error::QuicClose(
            TransportErrorCode::TransportParameterError,
            QuicError::InvalidTransportParameter | QuicError::CidTooLong
          ))
        ),
        "{bytes:x?}: {from_server:?}"
      );
    }
    // The limits themselves are valid
    for bytes in [
      varint_param(0x03, 1200),
      varint_param(0x0a, 20),
      varint_param(0x0b, (1 << 14) - 1),
      varint_param(0x0e, 2),
      varint_param(0x08, 1 << 60),
      varint_param(0x09, 1 << 60),
      param(0x00, &[0; 20]),
      param(0x0c, &[]),
    ] {
      assert!(TransportParams::decode(&bytes, true).is_ok(), "{bytes:x?}");
    }
  }

  #[test]
  fn transport_params_reject_truncated_input() {
    let bytes = encoded(&full_server_params());
    assert!(TransportParams::decode(&bytes, true).is_ok());
    let mut errors = 0;
    for len in 0..bytes.len() {
      // A prefix that ends exactly between two parameters is a valid, smaller, set of parameters
      match TransportParams::decode(&bytes[..len], true) {
        Ok(_) => {}
        Err(Error::QuicClose(TransportErrorCode::TransportParameterError, error)) => {
          assert!(
            matches!(error, QuicError::Truncated | QuicError::InvalidTransportParameter),
            "{error:?}"
          );
          errors += 1;
        }
        Err(other) => panic!("{other:?}"),
      }
    }
    assert!(errors > bytes.len() / 2);
    // A length that goes beyond the input
    assert_tp_error(TransportParams::decode(&[0x04, 0x08, 0x01], false), QuicError::Truncated);
    assert_tp_error(TransportParams::decode(&[0x04], false), QuicError::Truncated);
    assert_tp_error(TransportParams::decode(&[0x40], false), QuicError::Truncated);
    assert_tp_error(
      TransportParams::decode(&[0x04, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], false),
      QuicError::Truncated,
    );
  }

  #[test]
  fn transport_params_encode_checks_the_buffer_and_the_values() {
    let params = full_server_params();
    let bytes = encoded(&params);
    let mut buffer = [0; 512];
    assert_eq!(params.encode(&mut buffer[..bytes.len()]).unwrap(), bytes.len());
    for len in 0..bytes.len() {
      assert!(
        matches!(params.encode(&mut buffer[..len]), Err(Error::Quic(QuicError::BufferTooSmall))),
        "{len}"
      );
    }
    let too_large = TransportParams { initial_max_data: 1 << 62, ..TransportParams::default() };
    assert!(matches!(too_large.encode(&mut buffer), Err(Error::Quic(QuicError::VarintOverflow))));
  }

  #[test]
  fn transport_params_encoding_is_in_ascending_id_order() {
    let bytes = encoded(&full_server_params());
    let mut rest = &bytes[..];
    let mut last = None;
    while !rest.is_empty() {
      let (id, n) = crate::quic::varint::decode_varint(rest).unwrap();
      let (len, m) = crate::quic::varint::decode_varint(&rest[n..]).unwrap();
      assert!(last < Some(id));
      last = Some(id);
      rest = &rest[n + m + usize::try_from(len).unwrap()..];
    }
    assert_eq!(last, Some(0x10));
  }
}
