//! Two endpoints (workers) of a QUIC server against datagrams from eight addresses made of the bytes: Initial packets and the ones that follow a Retry, 1-RTT bytes to CIDs of the server or not, unknown versions, coalesced and repeated datagrams, real clients, time and shutdown (see `rimu_ws::quic::endpoint_check`). The heap of an input is capped.

#![no_main]

#[path = "lib/cap_alloc.rs"]
mod cap_alloc;

#[global_allocator]
static ALLOC: cap_alloc::CapAlloc = cap_alloc::CapAlloc;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
  let base = cap_alloc::start();
  rimu_ws::quic::endpoint_check::run(data);
  cap_alloc::check(base);
});
