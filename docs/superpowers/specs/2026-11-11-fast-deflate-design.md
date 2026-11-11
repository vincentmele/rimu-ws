# A fast one-shot gzip encoder for small response bodies (json-comp)

Date: 11 Nov 2026. Branch `feat/fast-deflate` from `main` 1a3c3b08 (worktree /mnt/nvme1tb/claude-tmp/rimu-h3).

## 1. Intent

Win HttpArena's h1 **json-comp** profile in the experimental league. rimu loses it on speed, not size: its gzip body
is already the smallest in the field, but zlib-rs at level 6 is too slow for a score that multiplies throughput by the
square of the size ratio. viltrum, the league leader, wins with its own small DEFLATE encoder built for exactly this
shape of input. This project builds rimu-ws's equivalent: a one-shot gzip encoder for bodies of a few KB, tuned for
the score, inside the library.

## 2. The score and where rimu stands

```
avgRps = mean(rps@4096, rps@16384);  bpr = bytes per response as gcannon reads them (status line + headers + body)
minBpr = the smallest bpr of any entry in the league;  eff = avgRps × (minBpr / bpr)²
```

Local head-to-head on colossus (6 server cores; h1bench, 7 Nov; json-comp gzip-preferred):

| entry | rps | bpr | eff (relative) |
|---|---|---|---|
| viltrum | 209K | 967 B | 1.00 |
| plod | 207K | 1,008 B | 0.91 |
| rimu (zlib-rs level 6) | 131K (≈ 138K after the zero-allocation work) | 947 B (smallest) | ≈ 0.66 |

A zlib-level sweep (L1–L6) left eff flat at ≈ 0.65–0.68: smaller levels gain speed and lose it back to bytes². zlib
clears its whole window and hash state (~100 KB) on every call and streams through a ring buffer; at a few KB of input
that overhead dominates. Because the league's smallest bpr sets everyone's penalty, staying the smallest while
reaching viltrum's speed is enough to lead; being smaller still lowers every rival's score.

viltrum's encoder (`/mnt/nvme1tb/claude-tmp/httpwin/rivals/viltrum/http1/deflate.v`, ~500 lines, V; read for ideas,
not copied): the body is matched where it lies in chunks of up to 64 KB, positions fit in u16, the hash table is
sized to the chunk (a 6 KB body clears 16 KB); 4-byte hashes; hash chains searched 4 deep with one step of lazy
matching (nice 32, good 8, at most 4 positions inserted per long match); one block per chunk, written dynamic, fixed
or stored, whichever is fewest bits; CLMUL CRC32; everything allocated once per worker.

## 3. Goals

1. A gzip encoder (RFC 1951 DEFLATE inside an RFC 1952 gzip member) in the rimu-ws library, one-shot: one input
   slice in, one complete gzip member out.
2. Zero allocation per call after warm-up (the h1 zero-allocation invariant): state reused per thread, sized to the
   input, never cleared beyond what the input uses.
3. Output any conformant inflater accepts; bytes may differ from zlib's.
4. Tunable search effort, swept on the profile's three bodies with the real dataset to maximise rps / bpr².
5. arena-h1's `/json` gzip path uses it in place of zlib-rs; brotli stays on the brotli crate (quality 2) as the
   fallback coding.
6. **Success:** rimu has the highest json-comp eff among the experimental entries (viltrum, plod, aegon) in a local
   head-to-head on colossus, by at least 5 %; no other h1 profile regresses (the h1 regression rule: none worse than
   1 %).

## 4. Non-goals

- Decompression (the existing zlib-rs inflater is used for tests).
- Streaming or incremental input; a raw-DEFLATE or zlib-wrapper API (may come later; the design must not preclude a
  raw-DEFLATE entry point, since gzip is DEFLATE plus a header and trailer).
- Brotli; WebSocket permessage-deflate; a general response-compression middleware in the h1 framework.
- A JSON-aware path that emits matches during serialisation (considered and declined by the user for now).
- Beating zlib's ratio in general; the target is small JSON-like bodies.

## 5. Anti-goals (would be a failure even if it scores)

- Any pre-compressed, pre-serialised or cached response body, or caching encoder output across requests (forbidden
  in every HttpArena mode: "serialized and compressed per request").
- Custom or preset dictionaries, or any encoding a standard `gzip` decoder does not accept.
- Per-request allocation, unbounded memory, or a panic on any input.
- Tuning that only works on the three benchmark URLs (the validator draws random sizes; bodies of any size and
  content must compress correctly and reasonably).

## 6. Decisions (the user's, 11 Nov)

- **Location:** a feature-gated module in the rimu-ws library (`wtx/src/codec/…`), used by arena-h1. Library grade:
  docs, tests, Miri on unsafe, fuzzing.
- **Ambition:** a generic fast DEFLATE (viltrum-style), no JSON-aware fast path.
- **Codec:** gzip only.
- **Measurement:** local head-to-head on colossus against the rivals' Docker images, benchmark pinned to CPUs 0-10 and
  12-22 (core 11/23 left free for colossus's live services), no sysctl or service changes, started only when the
  machine is quiet (no foreign load such as `xauhft`). No EC2.

## 7. Design

### 7.1 API (the builder may refine names)

```rust
// wtx/src/codec/gzip_encoder.rs (feature `gzip-encoder`, no_std + alloc)
pub struct GzipEncoder { /* reusable state */ }
impl GzipEncoder {
  pub fn new() -> Self;                                   // allocates nothing until first use
  pub fn with_params(params: GzipParams) -> Self;         // search effort knobs (7.3)
  /// Appends one complete gzip member for `input` to `out`. Allocates only to grow
  /// internal state or `out` beyond their high-water marks.
  pub fn encode(&mut self, input: &[u8], out: &mut Vec<u8>) -> crate::Result<()>;
  pub fn bound(len: usize) -> usize;                      // worst-case output size (stored blocks + framing)
}
```

`out` is a `Vec<u8>` or the crate's own vector type, whichever arena-h1's response path needs without a copy. The
gzip header is the minimal 10 bytes (no name, no mtime, OS byte as zlib writes for Unix), trailer CRC32 + ISIZE.

### 7.2 Matching

- Input is processed in chunks of at most 65,534 bytes so positions fit in u16 (0 = none); json-comp bodies are one
  chunk. Window 32 KiB (DEFLATE's maximum distance).
- Hash of 4 bytes (multiplicative), table of `2^k` heads with `k` from the chunk length (≤ 15 bits), plus a `prev`
  chain array of chunk length; only the used prefix is cleared per call.
- Hash chains with bounded depth, one-step lazy evaluation, `nice` and `good` thresholds and a cap on positions
  inserted per long match (viltrum's shape; values from the sweep, 7.3).
- Match extension compares 8 bytes at a time (u64 XOR + trailing-zero count), with an AVX2 32-byte compare where
  available behind runtime detection if the sweep shows it pays; a portable path always exists.
- Minimum match 4 (3-byte matches rarely pay); maximum 258.

### 7.3 Tunable effort and the sweep

`GzipParams { search_depth, nice_match, good_match, max_insert, … }` with a library default chosen by the sweep. An
in-process microbenchmark (not a load test: one core, the three json-comp bodies built from the real dataset with
the profile's `(count, m)` pairs) reports output bytes and ns per encode for each parameter set and ranks them by
`1 / (time_per_response_total × bpr²)`, where the per-response total includes the measured non-compression cost of
the request (serialisation, framing, syscalls), so the ranking matches the end-to-end score. The winner is confirmed
end to end (7.7).

### 7.4 Block coding

- Each chunk becomes one block (or a few, if a cost-based split pays in the sweep; optional).
- Literal/length and distance frequencies counted during matching; Huffman code lengths built with a length limit of
  15 (package-merge or a heap with a limiting pass); code-length codes RLE-encoded (16/17/18) and limited to 7.
- The block is written as dynamic, fixed or stored, whichever costs the fewest bits, computed exactly from the
  frequencies before writing.
- A 64-bit bit buffer flushed in whole bytes.

### 7.5 CRC32

PCLMULQDQ folding where the CPU has it (runtime detection), slice-by-8 otherwise. Reusing zlib-rs's CRC32 (already a
dependency of the library and of arena-h1) is preferred if its API allows it without pulling the deflater in;
otherwise a small in-crate implementation, tested against the zlib-rs CRC.

### 7.6 Memory

Per encoder: head table ≤ 2^15 × 2 B, `prev` ≤ 64 KiB × 2 B, a token buffer for the chunk, frequency and code tables:
under ~400 KB at the 64 KiB chunk maximum, a few tens of KB for json-comp bodies. arena-h1 keeps one encoder per
thread (as it keeps the zlib-rs stream today, `GZIP` thread-local in `wtx-internal/src/bin/arena-h1.rs`).

### 7.7 Correctness and measurement gates

- Round trip: every output inflates (zlib-rs inflate and one independent inflater, e.g. `miniz_oxide`, as dev
  dependencies) to the input; CRC and ISIZE checked; property tests over random, repetitive, JSON-like, empty,
  1-byte, 64 KiB-boundary and > 64 KiB inputs.
- A fuzz target in `wtx-fuzz` (differential: encode then inflate must equal the input; bounded memory; no panic), run
  30 minutes.
- Miri (strict provenance) on any `unsafe` (SIMD paths gated so Miri runs the portable path too).
- Zero allocation after warm-up, with the crate's counting-allocator test helper.
- arena-h1: the json-comp validator passes (5/5) and the h1 validator suite stays green; `Content-Encoding: gzip`
  unchanged; headers unchanged (header bytes count in bpr).
- End to end on colossus: json-comp head-to-head (gcannon, 4096 and 16384 connections, the profile's three bodies)
  of rimu vs viltrum, plod and aegon images, interleaved passes, eff computed with the league minimum; plus an h1
  regression A/B (all eight h1 profiles, new build vs `main`) under the 1 % rule.

## 8. What is left to the builder

Exact type and module names; whether block splitting earns its cost; the sweep's parameter grid; whether AVX2 match
extension pays over u64; the CRC source (reuse vs own); test helper choices; the microbenchmark harness location
(`wtx-internal` or a bench target).

## 9. Risks

- **Speed target not reached:** the score needs ≈ 1.5× today's json-comp throughput at about the same size. If the
  sweep cannot get there at ≤ 967 bpr, the fallback is to report the best eff found and stop (no rule-bending).
- **Header bytes:** rimu sends `Vary: Accept-Encoding` (~23 B) that viltrum may not; bpr includes headers. Removing a
  header is out of scope unless the validator and HTTP semantics allow it (decide with the user, separately).
- **Measurement noise on a shared machine:** runs start only when colossus is quiet; interleaved passes; spreads
  reported.
