//! WebSocket server read and echo paths against an independent RFC 6455 model: the bytes are
//! either raw client frames or the seed of a generated frame sequence, read in varying sizes.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
  wtx::web_socket::differential::check_bytes(data);
});
