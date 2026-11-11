//! The json-comp effort sweep of the rimu-ws gzip encoder (plan Task 6), an ignored test:
//!
//! ```sh
//! taskset -c 0 cargo test -p rimu-ws-internal --features arena-h1 --release --bin arena-h1 -- --ignored sweep --nocapture
//! ```
//!
//! The profile's three bodies (`/json/25?m=4`, `/json/40?m=8`, `/json/50?m=6`) are built with the
//! entry's own writer from the arena dataset. Every parameter set encodes each body `ENCODES`
//! times on this thread; the median time per encode is scaled to the server under load by zlib-rs
//! level 6, which the json-comp profile of 11 Nov measured at 62.0 µs a request (67.9 % of 91.4 µs
//! of server thread time at 131.3 K req/s), beside the 29.3 µs of everything else a request costs
//! (`docs/benchmarks/2026-11-11-json-comp-baseline/README.md`). The score is json-comp's:
//! `1 / ((T_OTHER + t) × bpr²)`, `bpr` the mean of rimu's header bytes plus the body.

use crate::{DatasetItem, GZIP_WINDOW_BITS, write_json};
use rimu_ws::{
  codec::{GzipEncoder, GzipParams},
  collections::VectorUsize,
};
use std::time::Instant;

const ENCODES: usize = 2_000;

/// One gzip member of `input` from the reused zlib-rs stream `deflate` (what arena-h1 sent before
/// the rimu-ws encoder), into the empty `out`.
fn zlib_gzip(deflate: &mut zlib_rs::Deflate, input: &[u8], out: &mut Vec<u8>) {
  deflate.reset();
  out.clear();
  out.resize(zlib_rs::compress_bound(input.len()) + 64, 0);
  let status = deflate.compress(input, out, zlib_rs::DeflateFlush::Finish).unwrap();
  assert_eq!(status, zlib_rs::Status::StreamEnd);
  out.truncate(usize::try_from(deflate.total_out()).unwrap());
}
const BODIES: [(usize, i64); 3] = [(25, 4), (40, 8), (50, 6)];
/// rimu's header bytes on the three bodies (status line through the blank line)
const HEADERS: [usize; 3] = [119, 120, 120];
const T_OTHER_US: f64 = 29.3;
const ZLIB6_LOADED_US: f64 = 62.0;

fn dataset() -> VectorUsize<DatasetItem> {
  let path = std::env::var("DATASET_PATH")
    .unwrap_or_else(|_| "/mnt/nvme1tb/claude-tmp/arena-main/data/dataset.json".into());
  serde_json::from_str(&std::fs::read_to_string(&path).expect("the arena dataset")).unwrap()
}

/// The median of `ENCODES` runs of `f`, in µs.
fn median_us(mut f: impl FnMut()) -> f64 {
  let mut samples = Vec::with_capacity(ENCODES);
  for _ in 0..ENCODES {
    let begin = Instant::now();
    f();
    samples.push(begin.elapsed().as_nanos() as u64);
  }
  samples.sort_unstable();
  samples[ENCODES / 2] as f64 / 1_000.0
}

struct Row {
  label: String,
  bytes: [usize; 3],
  us: f64,
}

fn measure(label: String, bodies: &[Vec<u8>], mut encode: impl FnMut(&[u8], &mut Vec<u8>)) -> Row {
  let mut out = Vec::new();
  let mut bytes = [0; 3];
  let mut us = 0.0;
  for (i, body) in bodies.iter().enumerate() {
    out.clear();
    encode(body, &mut out);
    bytes[i] = out.len();
    us += median_us(|| {
      out.clear();
      encode(body, &mut out);
    });
  }
  Row { label, bytes, us: us / bodies.len() as f64 }
}

#[ignore = "a measurement: run it alone on a quiet, pinned core"]
#[test]
fn sweep() {
  let dataset = dataset();
  let bodies: Vec<Vec<u8>> = BODIES
    .iter()
    .map(|&(count, m)| {
      let mut buf = VectorUsize::new();
      write_json(&mut buf, &dataset, count, m).unwrap();
      buf.as_slice().to_vec()
    })
    .collect();
  let zlib = |level: i32| {
    let mut stream = zlib_rs::Deflate::new_with_config(zlib_rs::DeflateConfig {
      window_bits: GZIP_WINDOW_BITS,
      ..zlib_rs::DeflateConfig::new(level)
    });
    measure(format!("zlib-rs level {level}"), &bodies, |body, out| {
      zlib_gzip(&mut stream, body, out)
    })
  };
  let zlib6 = zlib(6);
  let zlib1 = zlib(1);
  let factor = ZLIB6_LOADED_US / zlib6.us;
  let hdr = HEADERS.iter().sum::<usize>() as f64 / 3.0;
  let score = |row: &Row| {
    let bpr = hdr + row.bytes.iter().sum::<usize>() as f64 / 3.0;
    1.0 / ((T_OTHER_US + factor * row.us) * bpr * bpr)
  };
  let mut rows = Vec::new();
  for lazy in [true, false] {
    for search_depth in [1, 2, 3, 4, 6, 8, 12, 16] {
      for nice_match in [16, 24, 32, 48, 64, 128] {
        for good_match in if lazy { &[4, 8, 16, 32][..] } else { &[8][..] } {
          for max_insert in [1, 2, 4, 8, 16, 258] {
            let good_match = *good_match;
            let params = GzipParams { search_depth, nice_match, good_match, max_insert, lazy };
            let mut encoder = GzipEncoder::with_params(params);
            rows.push(measure(
              format!(
                "{} depth {search_depth:2} nice {nice_match:3} good {good_match:2} insert {max_insert:3}",
                if lazy { "lazy  " } else { "greedy" }
              ),
              &bodies,
              |body, out| encoder.encode(body, out).unwrap(),
            ));
          }
        }
      }
    }
  }
  let base = score(&zlib6);
  let print = |row: &Row| {
    let bpr = hdr + row.bytes.iter().sum::<usize>() as f64 / 3.0;
    println!(
      "{:42} bodies {:5} {:5} {:5} bpr {:7.1} encode {:6.2} us (loaded {:6.2}) score {:.3}",
      row.label,
      row.bytes[0],
      row.bytes[1],
      row.bytes[2],
      bpr,
      row.us,
      factor * row.us,
      score(row) / base
    );
  };
  println!(
    "calibration: zlib-rs level 6 {:.2} us here = {ZLIB6_LOADED_US} us loaded (factor {factor:.2})",
    zlib6.us
  );
  print(&zlib6);
  print(&zlib1);
  rows.sort_by(|a, b| score(b).total_cmp(&score(a)));
  for row in rows.iter().take(25) {
    print(row);
  }
}

/// Encodes the three bodies with `GZIP_PARAMS` ("depth,nice,good,insert[,lazy]") for `SECONDS` (default 10),
/// for a profiler to attach: `perf record -g -- <test binary> --ignored profile_loop`.
#[ignore = "a profiling loop"]
#[test]
fn profile_loop() {
  let dataset = dataset();
  let bodies: Vec<Vec<u8>> = BODIES
    .iter()
    .map(|&(count, m)| {
      let mut buf = VectorUsize::new();
      write_json(&mut buf, &dataset, count, m).unwrap();
      buf.as_slice().to_vec()
    })
    .collect();
  let p: Vec<u16> = std::env::var("GZIP_PARAMS")
    .unwrap_or_else(|_| "8,16,4,2".into())
    .split(',')
    .map(|el| el.parse().unwrap())
    .collect();
  let params = GzipParams {
    search_depth: p[0],
    nice_match: p[1],
    good_match: p[2],
    max_insert: p[3],
    lazy: p.get(4).is_none_or(|&el| el != 0),
  };
  let seconds: u64 = std::env::var("SECONDS").ok().and_then(|el| el.parse().ok()).unwrap_or(10);
  let mut encoder = GzipEncoder::with_params(params);
  let mut out = Vec::new();
  let begin = Instant::now();
  let mut n = 0u64;
  while begin.elapsed().as_secs() < seconds {
    for body in &bodies {
      out.clear();
      encoder.encode(body, &mut out).unwrap();
      n += 1;
    }
  }
  println!("{n} encodes, {:.2} us each", begin.elapsed().as_secs_f64() * 1e6 / n as f64);
}
