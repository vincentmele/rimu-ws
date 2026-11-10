//! A server QUIC connection against a client and a script made of the bytes: the datagrams of the client, damaged or not, Initial, Handshake and 1-RTT packets with any frame, operations of the application and time (see `rimu_ws::quic::conn_check`). The heap of an input is capped.

#![no_main]

#[path = "lib/cap_alloc.rs"]
mod cap_alloc;

#[global_allocator]
static ALLOC: cap_alloc::CapAlloc = cap_alloc::CapAlloc;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
  let base = cap_alloc::start();
  rimu_ws::quic::conn_check::run(data);
  cap_alloc::check(base);
});
