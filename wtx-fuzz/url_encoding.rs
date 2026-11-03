//! URL encoding

#![no_main]

use rimu_ws::{
  codec::{FormUrlDecode, PercentDecode},
  collections::VectorUsize,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
  let mut decoded = VectorUsize::new();
  let _rslt0 = FormUrlDecode::new(data).decode(&mut decoded);
  let _rslt1 = PercentDecode::new(data).decode(&mut decoded);
});
