//! The HTTP/2 server connection core against a model of what a client may expect: the bytes are
//! the seed of a generated client frame sequence, fed in chunks the bytes also choose.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
  rimu_ws::http2::differential::run(data);
});
