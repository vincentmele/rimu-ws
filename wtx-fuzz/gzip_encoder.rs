//! The one-shot gzip encoder over arbitrary bytes and search parameters: every member must
//! inflate to its input, stay within the bound and carry the right trailer.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
  rimu_ws::codec::gzip_check::check_bytes(data);
});
