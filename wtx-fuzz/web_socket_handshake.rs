//! The server's upgrade over arbitrary client bytes, read in a size the input picks: it upgrades,
//! answers 400 or 431, or closes, never reads more than the request limit and one read, and never
//! panics or hangs (run with `-timeout`).

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
  rimu_ws::web_socket::handshake_check::check_bytes(data);
});
