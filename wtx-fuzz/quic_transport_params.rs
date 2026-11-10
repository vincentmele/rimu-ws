//! The transport parameters over arbitrary bytes, read as a client and as a server: errors with
//! the code of RFC 9000 section 20.1, values within their ranges, writing and reading again, and
//! duplicates.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
  rimu_ws::quic::packet_check::check_transport_params_bytes(data);
});
