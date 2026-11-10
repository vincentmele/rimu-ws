//! A server HTTP/3 connection against a script made of the bytes: the streams of a client (control, QPACK, requests, any frame), resets, the packets of the QUIC script and time (see `rimu_ws::http3::h3_check`). The heap of an input is capped.

#![no_main]

#[path = "lib/cap_alloc.rs"]
mod cap_alloc;

#[global_allocator]
static ALLOC: cap_alloc::CapAlloc = cap_alloc::CapAlloc;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
  let base = cap_alloc::start();
  rimu_ws::http3::h3_check::run(data);
  cap_alloc::check(base);
});
