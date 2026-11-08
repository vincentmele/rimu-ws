//! The QUIC frame codec over arbitrary bytes: the reader of every packet number space, writing
//! and reading again what was read and ACK frames built from the input.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
  rimu_ws::quic::frame_check::check_bytes(data);
});
