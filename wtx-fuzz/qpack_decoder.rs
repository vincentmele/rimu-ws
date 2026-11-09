//! The QPACK decoder over arbitrary bytes: two decoders, one with the decode memo, fed the same
//! encoder stream and field sections; a model encoder whose instructions and sections, delivered
//! in pieces and out of order, must decode to what it put in; the frame header, settings and
//! static encoder codecs.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
  rimu_ws::http3::qpack_check::check_bytes(data);
});
