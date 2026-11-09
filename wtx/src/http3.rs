//! HTTP/3 (RFC 9114) and QPACK (RFC 9204).
//!
//! Everything here is sans-I/O: the frame and settings codecs read and write byte slices, the QPACK
//! decoder is fed the bytes of the encoder stream and of field sections and is drained of the
//! bytes of the decoder stream, and the connection layer ([`H3App`]) is the application of QUIC
//! connections, which are fed datagrams and drained into an arena.

#[allow(dead_code, reason = "the HTTP/3 server of task 14 runs the connection layer")]
mod frame;
#[allow(dead_code, reason = "the HTTP/3 server of task 14 runs the connection layer")]
mod h3_app;
#[allow(dead_code, reason = "the HTTP/3 server of task 14 runs the connection layer")]
mod h3_conn_state;
mod http3_error;
#[allow(dead_code, reason = "the HTTP/3 server of task 14 runs the connection layer")]
mod qpack;
#[cfg(any(test, feature = "_fuzz"))]
#[doc(hidden)]
pub mod qpack_check;
#[allow(dead_code, reason = "the HTTP/3 server of task 14 runs the connection layer")]
mod request;
#[allow(dead_code, reason = "the HTTP/3 server of task 14 runs the connection layer")]
mod settings;
#[cfg(test)]
pub(crate) mod testing;

#[allow(unused_imports, reason = "the HTTP/3 server of task 14 runs the connection layer")]
pub(crate) use frame::{H3FrameTy, decode_frame_header, encode_frame_header};
pub use h3_app::H3Params;
#[allow(unused_imports, reason = "the HTTP/3 server of task 14 runs the connection layer")]
pub(crate) use h3_app::{H3App, H3Handler, H3ReqCtx, ReqOutcome};
#[allow(unused_imports, reason = "the HTTP/3 server of task 14 runs the connection layer")]
pub(crate) use h3_conn_state::H3ConnState;
pub use http3_error::{H3ErrorCode, Http3Error};
#[allow(unused_imports, reason = "the HTTP/3 server of task 14 runs the connection layer")]
pub(crate) use qpack::{
  DecodeMemo, DecodeOutcome, QpackDecoder, STATIC_TABLE, encode_static, find_exact, find_name,
};
#[allow(unused_imports, reason = "the HTTP/3 server of task 14 runs the connection layer")]
pub(crate) use request::H3Request;
#[allow(unused_imports, reason = "the HTTP/3 server of task 14 runs the connection layer")]
pub(crate) use settings::H3Settings;
