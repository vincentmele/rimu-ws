//! The QUIC wire codecs over arbitrary bytes: packet headers (also coalesced), variable-length
//! integers, transport parameters and the packets that need no connection (Version Negotiation and
//! Retry). The first byte selects the length of the connection IDs of short headers.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
  rimu_ws::quic::packet_check::check_bytes(data);
});
