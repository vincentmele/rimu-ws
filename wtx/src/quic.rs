//! QUIC version 1 (RFC 9000): the wire codecs, packet protection, the connection core and its
//! streams, flow control and application interface.
//!
//! Everything here is sans-I/O: decoders return slices of their input, encoders write into
//! buffers of the caller and connections are fed datagrams and drained into a [`TxArena`].

#[allow(dead_code, reason = "reached through the endpoint of the later QUIC tasks")]
mod app;
#[allow(dead_code, reason = "reached through the endpoint of the later QUIC tasks")]
mod cc;
mod cid;
#[allow(dead_code, reason = "reached through the endpoint of the later QUIC tasks")]
mod conn;
#[allow(dead_code, reason = "consumed by the connection of the later QUIC tasks")]
mod crypto;
#[allow(dead_code, reason = "reached through the endpoint of the later QUIC tasks")]
mod flow;
#[allow(dead_code, reason = "consumed by the connection of the later QUIC tasks")]
mod frame;
#[cfg(any(test, feature = "_fuzz"))]
#[doc(hidden)]
pub mod frame_check;
mod limits;
#[allow(dead_code, reason = "consumed by the connection and the endpoint of the later QUIC tasks")]
mod packet;
#[cfg(any(test, feature = "_fuzz"))]
#[doc(hidden)]
pub mod packet_check;
#[allow(dead_code, reason = "reached through the endpoint of the later QUIC tasks")]
mod pmtud;
#[allow(dead_code, reason = "reached through the endpoint of the later QUIC tasks")]
mod pools;
mod quic_error;
#[allow(dead_code, reason = "reached through the endpoint of the later QUIC tasks")]
mod recovery;
#[allow(dead_code, reason = "reached through the endpoint of the later QUIC tasks")]
mod recv_tracker;
#[allow(dead_code, reason = "reached through the endpoint of the later QUIC tasks")]
mod sent;
#[allow(dead_code, reason = "reached through the endpoint of the later QUIC tasks")]
mod stream;
#[cfg(test)]
pub(crate) mod testing;
mod transport_params;
mod tx_arena;
mod varint;
mod writer;

#[allow(unused_imports, reason = "reached through the endpoint of the later QUIC tasks")]
pub(crate) use app::{BodyRef, ConnCtx, QuicApp};
pub use cid::{Cid, MAX_CID_LEN};
#[allow(unused_imports, reason = "reached through the endpoint of the later QUIC tasks")]
pub(crate) use conn::{ConnParams, ConnState, ConnStats, FlushOutcome, QuicConn};
use core::net::{IpAddr, SocketAddr};
#[allow(unused_imports, reason = "consumed by the connection of the later tasks")]
pub(crate) use crypto::{
  DirectionalKeys, PacketKeys, QuicAead, QuicHp, initial_keys, keys_from_secret, open_payload,
  protect, remove_header_protection, wipe,
};
#[allow(unused_imports, reason = "consumed by the connection of the later tasks")]
pub(crate) use frame::{AckFrame, Frame, FrameReader, FrameWriter, Space};
pub use limits::QuicLimits;
#[allow(unused_imports, reason = "consumed by the connection and endpoint of the later tasks")]
pub(crate) use packet::{
  PacketHeader, PacketTy, QUIC_V1, decode_pn, parse_header, pn_len_for, write_retry,
  write_version_negotiation,
};
pub use quic_error::{QuicError, TransportErrorCode};
#[allow(unused_imports, reason = "reached through the endpoint of the later QUIC tasks")]
pub(crate) use stream::StreamId;
pub use transport_params::TransportParams;
pub use tx_arena::{TrainId, TxArena, TxTrain};
#[allow(unused_imports, reason = "consumed by the frame codec of the later tasks")]
pub(crate) use varint::{VARINT_MAX, decode_varint, encode_varint, varint_len};

/// Where a datagram came from and went to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatagramMeta {
  /// The address of the peer.
  pub peer: SocketAddr,
  /// The local address that the peer sent the datagram to, if the socket reports it: replies
  /// leave from it.
  pub local: Option<IpAddr>,
  /// The size of the datagrams that the kernel coalesced into this one (generic receive
  /// offload), if it did.
  pub segment_size: Option<u16>,
}
