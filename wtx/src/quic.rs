//! QUIC version 1 (RFC 9000): the wire codecs, packet protection, the connection core and its
//! streams, flow control and application interface.
//!
//! Everything here is sans-I/O: decoders return slices of their input, encoders write into
//! buffers of the caller and connections are fed datagrams and drained into a [`TxArena`].

#[allow(dead_code, reason = "the application interface, which the HTTP/3 layer of task 13 uses")]
mod app;
mod cc;
mod cid;
mod cid_table;
mod conn;
mod crypto;
#[cfg(feature = "_h3-loopback-client")]
#[doc(hidden)]
pub mod diag;
#[cfg_attr(
  not(feature = "http3-server-framework"),
  allow(dead_code, reason = "only the HTTP/3 server framework creates and drives endpoints")
)]
mod endpoint;
mod flow;
mod frame;
#[cfg(any(test, feature = "_fuzz"))]
#[doc(hidden)]
pub mod frame_check;
mod key_phase;
mod limits;
mod packet;
#[cfg(any(test, feature = "_fuzz"))]
#[doc(hidden)]
pub mod packet_check;
mod pmtud;
mod pools;
mod quic_error;
mod recovery;
mod recv_tracker;
mod sent;
#[cfg(all(feature = "libc", target_os = "linux"))]
mod steer;
mod stream;
#[cfg(test)]
pub(crate) mod testing;
mod timer_wheel;
mod token;
mod transport_params;
mod tx_arena;
mod varint;
mod writer;

pub(crate) use app::{BodyRef, ConnCtx, ConnHandle, QuicApp};
pub use cid::{Cid, MAX_CID_LEN};
#[cfg(any(test, feature = "_fuzz-conn"))]
#[doc(hidden)]
pub use conn::check as conn_check;
#[cfg(any(test, feature = "_fuzz-conn"))]
pub(crate) use conn::check::{Duo, Input};
#[cfg(any(test, feature = "_fuzz-conn"))]
#[doc(hidden)]
pub use endpoint::check as endpoint_check;
pub(crate) use conn::{ConnParams, ConnState, FlushOutcome, QuicConn};
use core::net::{IpAddr, SocketAddr};
#[cfg(test)]
pub(crate) use crypto::keys_from_secret;
pub(crate) use crypto::{
  DirectionalKeys, HpBatch, PacketKeys, initial_keys, keys_from_secret_with, open_payload, protect,
  protect_deferred, remove_header_protection, wipe,
};
pub use endpoint::WorkerLoads;
#[cfg_attr(
  not(feature = "http3-server-framework"),
  allow(unused_imports, reason = "only the HTTP/3 server framework creates endpoints")
)]
pub(crate) use endpoint::{Endpoint, RecvOutcome};
pub(crate) use frame::{AckFrame, Frame, FrameReader, FrameWriter, Space};
pub use limits::{QuicLimits, QuicParams};
pub(crate) use packet::{
  PacketTy, QUIC_V1, decode_pn, parse_header, pn_len_for, write_retry, write_version_negotiation,
};
#[cfg(feature = "_h3-loopback-client")]
pub(crate) use pools::QuicPools;
pub use quic_error::{QuicError, TransportErrorCode};
#[cfg(all(feature = "libc", target_os = "linux"))]
pub use steer::{STEERING_PROGRAM_LEN, SteeringProgram, steering_cbpf};
#[allow(
  unused_imports,
  reason = "the application interface, which the HTTP/3 layer of task 13 uses"
)]
pub(crate) use stream::StreamId;
#[cfg_attr(
  not(feature = "http3-server-framework"),
  allow(unused_imports, reason = "only the HTTP/3 server framework makes the keys of a process")
)]
pub(crate) use token::EndpointKeys;
pub use transport_params::TransportParams;
pub use tx_arena::{TrainId, TxArena, TxTrain};
#[allow(
  unused_imports,
  reason = "for tests and the QPACK and HTTP/3 codecs of tasks 12 and 13"
)]
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
