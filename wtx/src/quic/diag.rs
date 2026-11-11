//! Measurement of the frame-reference pool and of the sent rings of server workers (task 23d):
//! test-only (`_h3-loopback-client`), hidden from the documentation, process-wide counters that
//! the in-process tests read. They cost nothing in a build without the feature.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Chunks per record are counted up to this many, the last bucket holds more.
pub const CHUNK_BUCKETS: usize = 40;

static EXHAUSTED: AtomicU64 = AtomicU64::new(0);
static PEAK_INFLIGHT: AtomicUsize = AtomicUsize::new(0);
static PEAK_LIVE: AtomicUsize = AtomicUsize::new(0);
static RECORDS: AtomicU64 = AtomicU64::new(0);
static BY_CHUNKS: [AtomicU64; CHUNK_BUCKETS] = [const { AtomicU64::new(0) }; CHUNK_BUCKETS];

/// What was measured since the last [`reset`].
#[derive(Debug, Clone)]
pub struct Diag {
  /// Times a frame-reference pool answered `PoolExhausted`.
  pub exhausted: u64,
  /// The most records in flight that one connection of a worker held.
  pub peak_inflight_records: usize,
  /// The most chunks that the pool of one worker held live.
  pub peak_live_chunks: usize,
  /// Records of ack-eliciting packets sent by workers.
  pub records: u64,
  /// Records by the number of chunks they hold (index 0 is none).
  pub by_chunks: [u64; CHUNK_BUCKETS],
}

impl Diag {
  /// The (min, mean, max) of chunks per record, of the records with at least one chunk.
  pub fn chunks_per_record(&self) -> Option<(usize, f64, usize)> {
    let (mut min, mut max, mut sum, mut n) = (None, 0usize, 0u64, 0u64);
    for (chunks, count) in self.by_chunks.iter().enumerate().skip(1) {
      if *count != 0 {
        min = min.or(Some(chunks));
        max = chunks;
        sum += *count * chunks as u64;
        n += *count;
      }
    }
    Some((min?, sum as f64 / n as f64, max))
  }
}

/// Zeroes the counters.
pub fn reset() {
  EXHAUSTED.store(0, Ordering::SeqCst);
  PEAK_INFLIGHT.store(0, Ordering::SeqCst);
  PEAK_LIVE.store(0, Ordering::SeqCst);
  RECORDS.store(0, Ordering::SeqCst);
  for el in &BY_CHUNKS {
    el.store(0, Ordering::SeqCst);
  }
}

/// The counters now.
pub fn snapshot() -> Diag {
  let mut by_chunks = [0; CHUNK_BUCKETS];
  for (dst, src) in by_chunks.iter_mut().zip(&BY_CHUNKS) {
    *dst = src.load(Ordering::SeqCst);
  }
  Diag {
    exhausted: EXHAUSTED.load(Ordering::SeqCst),
    peak_inflight_records: PEAK_INFLIGHT.load(Ordering::SeqCst),
    peak_live_chunks: PEAK_LIVE.load(Ordering::SeqCst),
    records: RECORDS.load(Ordering::SeqCst),
    by_chunks,
  }
}

pub(crate) fn on_exhausted() {
  let _ = EXHAUSTED.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn on_live(live: usize) {
  let _ = PEAK_LIVE.fetch_max(live, Ordering::Relaxed);
}

/// A server connection sent a record of `chunks` chunks and holds `in_flight` records in flight.
pub(crate) fn on_record(chunks: usize, in_flight: usize) {
  let _ = PEAK_INFLIGHT.fetch_max(in_flight, Ordering::Relaxed);
  if chunks != 0 {
    let _ = RECORDS.fetch_add(1, Ordering::Relaxed);
    if let Some(el) = BY_CHUNKS.get(chunks.min(CHUNK_BUCKETS.wrapping_sub(1))) {
      let _ = el.fetch_add(1, Ordering::Relaxed);
    }
  }
}
