//! Pem

#![no_main]

use core::ops::Range;
use rimu_ws::{
  codec::{Decode, DecodeWrapper, Pem},
  collections::VectorUsize,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
  let mut buffer = VectorUsize::new();
  let _rslt = Pem::<Range<usize>, 8>::decode(&mut DecodeWrapper::new(data, &mut buffer));
});
