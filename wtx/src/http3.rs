//! HTTP/3 (RFC 9114) and QPACK (RFC 9204).
//!
//! Everything here is sans-I/O: the frame and settings codecs read and write byte slices, the QPACK
//! decoder is fed the bytes of the encoder stream and of field sections and is drained of the
//! bytes of the decoder stream.

#[allow(dead_code, reason = "the HTTP/3 connection of task 13 reads and writes frames")]
mod frame;
mod http3_error;
#[allow(dead_code, reason = "the HTTP/3 connection of task 13 decodes and encodes field sections")]
mod qpack;
#[cfg(any(test, feature = "_fuzz"))]
#[doc(hidden)]
pub mod qpack_check;
#[allow(dead_code, reason = "the HTTP/3 connection of task 13 exchanges settings")]
mod settings;

#[allow(unused_imports, reason = "the HTTP/3 connection of task 13 reads and writes frames")]
pub(crate) use frame::{H3FrameTy, decode_frame_header, encode_frame_header};
pub use http3_error::{H3ErrorCode, Http3Error};
#[allow(
  unused_imports,
  reason = "the HTTP/3 connection of task 13 decodes and encodes field sections"
)]
pub(crate) use qpack::{
  DecodeMemo, DecodeOutcome, QpackDecoder, STATIC_TABLE, encode_static, find_exact, find_name,
};
#[allow(unused_imports, reason = "the HTTP/3 connection of task 13 exchanges settings")]
pub(crate) use settings::H3Settings;
