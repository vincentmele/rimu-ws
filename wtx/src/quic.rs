//! QUIC version 1 (RFC 9000): the wire codecs that the rest of the protocol is built on.
//!
//! Everything here is sans-I/O and does not allocate: decoders return slices of their input and
//! encoders write into buffers of the caller.

mod cid;
#[allow(dead_code, reason = "consumed by the connection of the later QUIC tasks")]
mod crypto;
#[allow(dead_code, reason = "consumed by the connection of the later QUIC tasks")]
mod frame;
#[cfg(any(test, feature = "_fuzz"))]
#[doc(hidden)]
pub mod frame_check;
#[allow(dead_code, reason = "consumed by the connection and the endpoint of the later QUIC tasks")]
mod packet;
#[cfg(any(test, feature = "_fuzz"))]
#[doc(hidden)]
pub mod packet_check;
mod quic_error;
mod transport_params;
mod varint;
mod writer;

pub use cid::{Cid, MAX_CID_LEN};
#[allow(unused_imports, reason = "consumed by the connection of the later tasks")]
pub(crate) use crypto::{
  DirectionalKeys, PacketKeys, QuicAead, QuicHp, initial_keys, keys_from_secret, open_payload,
  protect, remove_header_protection,
};
#[allow(unused_imports, reason = "consumed by the connection of the later tasks")]
pub(crate) use frame::{AckFrame, Frame, FrameReader, FrameWriter, Space};
#[allow(unused_imports, reason = "consumed by the connection and endpoint of the later tasks")]
pub(crate) use packet::{
  PacketHeader, PacketTy, QUIC_V1, decode_pn, parse_header, pn_len_for, write_retry,
  write_version_negotiation,
};
pub use quic_error::{QuicError, TransportErrorCode};
pub use transport_params::TransportParams;
#[allow(unused_imports, reason = "consumed by the frame codec of the later tasks")]
pub(crate) use varint::{VARINT_MAX, decode_varint, encode_varint, varint_len};
