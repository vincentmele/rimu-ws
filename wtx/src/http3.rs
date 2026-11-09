//! HTTP/3 (RFC 9114) and QPACK (RFC 9204).
//!
//! Everything here is sans-I/O: the frame and settings codecs read and write byte slices, the QPACK
//! decoder is fed the bytes of the encoder stream and of field sections and is drained of the
//! bytes of the decoder stream, and the connection layer ([`H3App`]) is the application of QUIC
//! connections, which are fed datagrams and drained into an arena.

#[cfg_attr(
  not(feature = "http3-server-framework"),
  allow(dead_code, reason = "only the HTTP/3 server framework runs the connection layer")
)]
mod frame;
#[cfg_attr(
  not(feature = "http3-server-framework"),
  allow(dead_code, reason = "only the HTTP/3 server framework runs the connection layer")
)]
mod h3_app;
#[cfg_attr(
  not(feature = "http3-server-framework"),
  allow(dead_code, reason = "only the HTTP/3 server framework runs the connection layer")
)]
mod h3_conn_state;
mod http3_error;
#[cfg(feature = "_h3-loopback-client")]
#[doc(hidden)]
pub mod loopback_client;
#[cfg_attr(
  not(feature = "http3-server-framework"),
  allow(dead_code, reason = "only the HTTP/3 server framework runs the connection layer")
)]
mod qpack;
#[cfg(any(test, feature = "_fuzz"))]
#[doc(hidden)]
pub mod qpack_check;
#[cfg_attr(
  not(feature = "http3-server-framework"),
  allow(dead_code, reason = "only the HTTP/3 server framework runs the connection layer")
)]
mod request;
#[cfg_attr(
  not(feature = "http3-server-framework"),
  allow(dead_code, reason = "only the HTTP/3 server framework runs the connection layer")
)]
mod settings;
#[cfg(test)]
pub(crate) mod testing;

#[cfg_attr(
  not(feature = "http3-server-framework"),
  allow(unused_imports, reason = "only the HTTP/3 server framework runs the connection layer")
)]
pub(crate) use frame::{H3FrameTy, decode_frame_header, encode_frame_header};
pub use h3_app::H3Params;
#[cfg_attr(
  not(feature = "http3-server-framework"),
  allow(unused_imports, reason = "only the HTTP/3 server framework runs the connection layer")
)]
pub(crate) use h3_app::{H3App, H3Handler, H3ReqCtx, ReqOutcome};
#[cfg_attr(
  not(test),
  allow(unused_imports, reason = "the state of a connection, which tests read")
)]
pub(crate) use h3_conn_state::H3ConnState;
pub use http3_error::{H3ErrorCode, Http3Error};
#[cfg_attr(
  not(feature = "http3-server-framework"),
  allow(unused_imports, reason = "only the HTTP/3 server framework encodes field lines")
)]
pub(crate) use qpack::{
  DecodeMemo, DecodeOutcome, QpackDecoder, encode_static, encode_static_line, encode_static_prefix,
};
#[allow(unused_imports, reason = "the static table, for the checks of tests and fuzzing")]
pub(crate) use qpack::{STATIC_TABLE, find_exact, find_name};
#[cfg_attr(
  not(feature = "http3-server-framework"),
  allow(unused_imports, reason = "only the HTTP/3 server framework runs the connection layer")
)]
pub(crate) use request::H3Request;
#[cfg_attr(
  not(feature = "http3-server-framework"),
  allow(unused_imports, reason = "only the HTTP/3 server framework runs the connection layer")
)]
pub(crate) use settings::H3Settings;
