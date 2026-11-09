//! Generic HTTP elements

#[cfg(feature = "http-cookie")]
pub mod cookie;
#[cfg(all(feature = "http2-server-framework", feature = "std"))]
mod date_header;
mod generic_header;
mod generic_request;
mod generic_response;
mod header_name;
mod headers;
#[cfg(feature = "http1-server-framework")]
mod http1_server_framework;
#[cfg(feature = "http2-client-pool")]
pub mod http2_client_pool;
#[cfg(feature = "http2-server-framework")]
pub mod http2_server_framework;
mod http_client;
mod http_error;
mod http_recv_params;
#[cfg(any(feature = "http2", feature = "http3"))]
#[cfg_attr(
  not(feature = "http2"),
  allow(dead_code, reason = "QPACK writes its literals raw, only HPACK encodes Huffman strings")
)]
pub(crate) mod huffman;
#[cfg(any(feature = "http2", feature = "http3"))]
mod huffman_tables;
mod method;
mod mime;
mod misc;
mod msg_buffer;
mod msg_builder;
mod msg_data;
mod operation_mode;
#[allow(dead_code, reason = "the HTTP/3 connection of task 13 runs the QPACK codecs")]
#[cfg(feature = "http3")]
pub(crate) mod prefix_int;
mod protocol;
mod request;
mod response;
mod router;
mod same_site;
#[cfg(feature = "http-session")]
mod session;
#[cfg(any(
  feature = "http1-server-framework",
  feature = "http2-server-framework",
  feature = "web-socket-server-framework"
))]
mod shutdown_signal;
mod status_code;
mod u31;
mod version;
pub mod web_authn;
#[cfg(feature = "web-socket-server-framework")]
mod web_socket_server_framework;

pub use generic_header::GenericHeader;
pub use generic_request::GenericRequest;
pub use generic_response::GenericResponse;
pub use header_name::*;
pub use headers::{Header, Headers, HeadersIter, Trailers};
pub use http_client::HttpClient;
pub use http_error::HttpError;
pub use http_recv_params::HttpRecvParams;
#[cfg(feature = "http1-server-framework")]
pub use http1_server_framework::{
  Http1Middleware, Http1Req, Http1Res, Http1Router, Http1ServerFramework, Http1ServerHeader,
};
pub use method::Method;
pub use mime::Mime;
pub use misc::*;
pub use msg_buffer::{MsgBuffer, MsgBufferStr, MsgBufferString};
pub use msg_builder::{MsgBuilder, MsgBuilderInput, ReqBuilder, ResBuilder};
pub use msg_data::{MsgData, MsgDataMut};
pub use operation_mode::*;
pub use protocol::Protocol;
pub use request::Request;
pub use response::Response;
pub use router::{Router, RouterBuilder, RouterError, RouterMatch, RouterMatchParam};
pub use same_site::SameSite;
#[cfg(feature = "http-session")]
pub use session::*;
#[cfg(any(
  feature = "http1-server-framework",
  feature = "http2-server-framework",
  feature = "web-socket-server-framework"
))]
pub use shutdown_signal::ShutdownSignal;
pub use status_code::StatusCode;
pub use u31::U31;
pub use version::Version;
#[cfg(feature = "web-socket-server-framework")]
pub use web_socket_server_framework::{WebSocketRouter, WebSocketServerFramework};

/// Maximum number of bytes for the name of a header.
pub const MAX_HEADER_NAME_LEN: usize = 48;
/// Maximum number of bytes for the value of a header.
pub const MAX_HEADER_VALUE_LEN: usize = 1024 * 3;
/// Current user agent of this project
pub const WTX_USER_AGENT: &str = concat!("wtx/", env!("CARGO_PKG_VERSION"));

pub(crate) const DEFAULT_INITIAL_WINDOW_LEN: u32 = 64 * 1024 - 1;
pub(crate) const DEFAULT_MAX_CHILDREN: usize = 18;
pub(crate) const DEFAULT_MAX_CONCURRENT_STREAMS_NUM: u32 = 128;
pub(crate) const DEFAULT_MAX_DEPTH: usize = 16;
pub(crate) const DEFAULT_MAX_FRAME_LEN: u32 = 16 * 1024;
pub(crate) const DEFAULT_MAX_HEADERS_LEN: u32 = 4 * 1024;
pub(crate) const DEFAULT_MAX_HPACK_LEN: u32 = 4 * 1024;
pub(crate) const MAX_FRAME_LEN_LOWER_BOUND: u32 = 16 * 1024;
pub(crate) const MAX_FRAME_LEN_UPPER_BOUND: u32 = 16 * 1024 * 1024 - 1;

pub(crate) type _HeaderNameBuffer = crate::collections::ArrayVectorU8<u8, MAX_HEADER_NAME_LEN>;
