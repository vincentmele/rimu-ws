# Fast One-Shot gzip Encoder (json-comp) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A library gzip encoder for bodies of a few KB, fast enough that rimu leads HttpArena's json-comp in the experimental league.

**Architecture:** A new `no_std + alloc` module `wtx/src/codec/gzip_encoder/` (feature `gzip-encoder`): one-shot DEFLATE in an RFC 1952 member, matched in place with u16 hash chains sized to the input, one block per ≤ 65,534-byte chunk written dynamic/fixed/stored by exact bit cost, CRC from `zlib_rs::crc32`. arena-h1's `/json` gzip path switches to it; a sweep picks the effort defaults; a local head-to-head on colossus decides success.

**Tech Stack:** Rust (workspace toolchain), rimu-ws (`wtx/`), zlib-rs 0.6.8 (CRC, test inflater), miniz_oxide (dev-only inflater), cargo-fuzz (`wtx-fuzz`), HttpArena harness (gcannon, rival Docker images).

**Spec:** `docs/superpowers/specs/2026-11-11-fast-deflate-design.md` (approved 11 Nov; decisions §6, settled calls §8a).

## Global Constraints

- Worktree `/mnt/nvme1tb/claude-tmp/rimu-h3`, branch `feat/fast-deflate`. Never `git worktree add` (the `.git` is shared); never `git stash`; use a scratch `git clone --local` under `/mnt/nvme1tb/claude-tmp` for another revision.
- `CARGO_TARGET_DIR=/mnt/nvme1tb/claude-tmp/target-h3`, `TMPDIR=/mnt/nvme1tb/claude-tmp/tmp`; one cargo (or docker build) process at a time; never build while a benchmark runs.
- Commit trailer exactly `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; `git add` only intended files (a format hook rewrites unrelated files: confirm they are formatting-only, then `git checkout -- <file>`). Never push anything; HttpArena (`~/src/HttpArena`, branch `add-rimu-ws`) gets local commits only.
- Output must be standard gzip (RFC 1951 inside RFC 1952): no preset dictionary, no caching of encoder output or response bodies across requests.
- Zero allocation per call after warm-up; no panic on any input; every `unsafe` has `// SAFETY:` and a Miri-run test of its portable twin.
- Portable code path always present and correct on every target; x86_64 fast paths selected by `std` runtime detection or `target_feature`.
- `Vary: Accept-Encoding` and every other json-comp response header stay as they are.
- Benchmarks only on colossus: server CPUs `0-5,12-17`, generator `6-10,18-22` (core 11/23 left free), no sysctl or service changes, a run starts only when the load average is < 2 and no process outside the run uses > 50 % of a CPU; kill only PIDs you started, never `pkill -f`; no AWS of any kind.
- Success (spec Goal 6): rimu's local json-comp eff ≥ 1.05 × viltrum's; no h1 profile measured locally worse than 1 % vs `main` 1a3c3b08.

## Review Focus

1. **Empty and 1-byte input** — a valid gzip member that inflates to the input (Task 2 test `empty_and_one_byte_inputs_round_trip`).
2. **Incompressible input** (random bytes) — stored blocks, never larger than `GzipEncoder::bound(len)` (Task 4 test `random_input_stays_within_bound`).
3. **Chunk boundaries** — inputs of 65,533, 65,534, 65,535, 131,068 and 200,000 bytes round-trip; no match crosses a chunk (Task 3 test `chunk_boundaries_round_trip`).
4. **Degenerate repetition** (200 KB of one byte; a 2-byte pattern) — maximum-length matches, encode time linear (bounded chain walks) (Task 3 test `long_runs_encode_in_linear_time`).
5. **Reuse with changing sizes** (a 60 KB body, then a 10-byte body, then a 6 KB body on one encoder; a call after an error) — no stale positions from an earlier input (Task 3 test `reuse_across_sizes_has_no_stale_matches`).

---

### Task 1: Baseline bytes and the ceiling gate (measurement only)

**Files:**
- Create: `docs/benchmarks/2026-11-11-json-comp-baseline/README.md` (+ `data/` with raw outputs)
- Create (scratch, not committed): scripts under `/mnt/nvme1tb/claude-tmp/jsoncomp/`

**Interfaces:**
- Produces: for rimu (current `main` arena-h1), viltrum, plod, aegon: header bytes, body bytes and bpr for `/json/25?m=4`, `/json/40?m=8`, `/json/50?m=6` with `Accept-Encoding: gzip, br`; rimu's per-request time split `T_comp` (gzip) vs `T_other`; the go/no-go verdict. Task 6 consumes `T_other`.

- [ ] **Step 1: Measure bytes.** For each server (rimu: `wtx-internal` arena-h1 release build of 1a3c3b08 with `DATASET_PATH=/mnt/nvme1tb/claude-tmp/arena-main/data/dataset.json`; rivals: images `httparena-viltrum`, `httparena-plod`, `httparena-aegon` run as `/mnt/nvme1tb/claude-tmp/h1bench/bench-jsoncomp.sh` does), `curl -s -D- -o body -H "Accept-Encoding: gzip, br"` each of the three URLs; record header bytes (status line through the blank line), body bytes, `content-encoding`. Expected: rimu body 947 B on `/json/50?m=6` within ±2 B.
- [ ] **Step 2: Profile rimu's json-comp request.** Under the json-comp load (`bench-jsoncomp.sh` shape, 4096 conns, CPU split from Global Constraints, quiet-machine check first), `perf record -g -C 0-5,12-17` for 5 s; report the share of server cycles in zlib-rs deflate (`T_comp / (T_comp + T_other)`) and rps.
- [ ] **Step 3: Compute the ceiling.** With rimu's measured bpr and rps: `rps_ceiling = rps / (1 − comp_share)`; `eff_rimu_ceiling = rps_ceiling × (minBpr / bpr_rimu)²`, `eff_viltrum = rps_viltrum × (minBpr / bpr_viltrum)²` with `minBpr` the smallest measured bpr (mean over the three URLs). Verdict GO if `eff_rimu_ceiling ≥ 1.05 × eff_viltrum`, else NO-GO.
- [ ] **Step 4: Write the README** (method, CPU split, machine state, the byte table, the profile share, the verdict) and commit.

```bash
git add docs/benchmarks/2026-11-11-json-comp-baseline/
git commit -m "docs: json-comp baseline bytes and the ceiling gate"
```

If the verdict is NO-GO, stop the plan and report (spec §9: no rule-bending).

---

### Task 2: Module, bit writer, gzip framing, stored and fixed blocks (literals only)

**Files:**
- Create: `wtx/src/codec/gzip_encoder.rs` (pub API, framing), `wtx/src/codec/gzip_encoder/bits.rs` (bit writer), `wtx/src/codec/gzip_encoder/tests.rs`
- Modify: `wtx/src/codec.rs` (module + re-exports under `#[cfg(feature = "gzip-encoder")]`), `wtx/Cargo.toml` (feature `gzip-encoder = ["dep:zlib-rs"]`; dev-dependency `miniz_oxide = "0.8"`), `.scripts/internal-tests4.sh` (a `cargo check -p rimu-ws --lib --no-default-features --features gzip-encoder` line and a `std,gzip-encoder` line)

**Interfaces:**
- Produces:
  - `pub struct GzipEncoder` with `pub fn new() -> Self` (allocates nothing), `pub fn with_params(params: GzipParams) -> Self`, `pub fn encode(&mut self, input: &[u8], out: &mut Vec<u8>) -> crate::Result<()>` (appends one gzip member), `pub fn bound(len: usize) -> usize`.
  - `pub struct GzipParams { pub search_depth: u16, pub nice_match: u16, pub good_match: u16, pub max_insert: u16 }` with `Default` = viltrum's starting point `4, 32, 8, 4` (Task 6 replaces it).
  - `pub(crate) struct BitWriter<'a>` over `&'a mut Vec<u8>`: `put(bits: u64, n: u32)`, `align()`, `finish()`; a 64-bit accumulator flushed in whole bytes.
- Framing: header `1f 8b 08 00 00 00 00 00 00 03` (no name, no mtime, XFL 0, OS 3); trailer `crc32` (`zlib_rs::crc32::crc32(0, input)`) and ISIZE (`len mod 2^32`), little-endian.

- [ ] **Step 1: Write the failing tests** in `tests.rs`:
  - `empty_and_one_byte_inputs_round_trip`: `encode(b"")` and `encode(b"x")`, inflate with `miniz_oxide::inflate::decompress_to_vec` after stripping the 10-byte header and 8-byte trailer, and with `zlib_rs::decompress_slice` (gzip window bits 31), equal to the input; trailer CRC = `zlib_rs::crc32::crc32(0, input)`, ISIZE = len.
  - `literals_round_trip`: 1,000 pseudo-random JSON-ish byte strings (seeded) of 0–8,000 bytes round-trip through both inflaters.
  - `encode_appends`: `out` pre-filled with `b"abc"` keeps its prefix.
  - `bound_holds`: for lengths 0, 1, 100, 65,534, 65,535, 200,000, encoded random input length ≤ `bound(len)`.
- [ ] **Step 2: Run, verify they fail** — `cargo test -p rimu-ws --lib --features std,gzip-encoder -- codec::gzip_encoder` → FAIL (types missing).
- [ ] **Step 3: Implement** the framing, the bit writer, and per-chunk block choice between stored and fixed-Huffman-literals-only (exact bit count of each), chunks of at most 65,534 bytes (`const MAX_CHUNK: usize = 65_534`), last block flagged final. `bound(len)` = stored-block worst case: `len + 5 × ceil(len / 65_535).max(1) + 18`.
- [ ] **Step 4: Run, verify pass**; also `cargo check -p rimu-ws --lib --no-default-features --features gzip-encoder` and `cargo check -p rimu-ws --lib --all-features`.
- [ ] **Step 5: Commit** — `codec: gzip encoder skeleton (framing, bit writer, stored and fixed blocks)`.

---

### Task 3: Matcher (hash chains, lazy evaluation) into fixed-Huffman tokens

**Files:**
- Create: `wtx/src/codec/gzip_encoder/matcher.rs`, `wtx/src/codec/gzip_encoder/tokens.rs` (token buffer + frequency counts)
- Modify: `wtx/src/codec/gzip_encoder.rs`, `tests.rs`

**Interfaces:**
- Consumes: `BitWriter`, `GzipParams`, framing (Task 2).
- Produces: `pub(crate) struct Matcher` (`head: Vec<u16>`, `prev: Vec<u16>`, reused) with `fn find(&mut self, chunk: &[u8], params: &GzipParams, tokens: &mut Tokens)`; `pub(crate) struct Tokens` holding literals and (length, distance) pairs in one `Vec<u32>` (length 3..=258, distance 1..=32,768) plus `lit_freq: [u32; 286]`, `dist_freq: [u32; 30]`; both cleared per chunk. Task 4 consumes `Tokens`.
- Rules (spec §7.2): 4-byte multiplicative hash, `2^k` heads with `k = clamp(ceil(log2(chunk_len)), 8, 15)`, positions stored + 1 in u16 (0 = none), only the used prefix of `head`/`prev` cleared; min match 4, max 258; window 32,768; chains walked at most `search_depth` links (a quarter of that once the current match ≥ `good_match`); a match ≥ `nice_match` ends the search and the lazy step; one-step lazy evaluation; a match longer than `max_insert` inserts only its first `max_insert` positions. Match extension compares 8 bytes at a time (`u64::from_le_bytes` XOR, `trailing_zeros / 8`), with a byte loop for the tail.

- [ ] **Step 1: Write the failing tests:**
  - `matches_shrink_json`: a deterministic JSON fixture shaped like the arena dataset (an array of 50 objects with keys `id`, `name`, `category`, `price`, `quantity`, `active`, `tags`, `rating`, `total`; generator in `tests.rs`) encodes to ≤ 25 % of its length and round-trips.
  - `chunk_boundaries_round_trip`: inputs of 65,533, 65,534, 65,535, 131,068 and 200,000 bytes (JSON fixture repeated) round-trip.
  - `long_runs_encode_in_linear_time`: 200,000 bytes of `b'a'` and of `b"ab"` repeated round-trip, and encoding 2,000,000 bytes takes ≤ 20 × the time of 100,000 bytes (linear, with headroom).
  - `reuse_across_sizes_has_no_stale_matches`: one encoder encodes a 60 KB fixture, a 10-byte input, a 6 KB fixture, then the 60 KB fixture again into an `out` truncated to 0 after the previous call; each output round-trips.
  - `zero_allocations_after_warm_up`: with `crate::tests::_count_allocations_in(&COUNTER)`, a second `encode` of the 6 KB fixture into an `out` with enough capacity allocates 0 times.
- [ ] **Step 2: Run, verify fail** (size test fails: literals only).
- [ ] **Step 3: Implement** `Matcher::find` and `Tokens`; the fixed-Huffman writer now emits length/distance codes (RFC 1951 §3.2.5 tables as `const` arrays) — block choice still fixed vs stored.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `codec: gzip encoder matcher (u16 hash chains, lazy evaluation)`.

---

### Task 4: Dynamic Huffman blocks and the exact cost choice

**Files:**
- Create: `wtx/src/codec/gzip_encoder/huffman.rs`
- Modify: `wtx/src/codec/gzip_encoder.rs`, `tests.rs`

**Interfaces:**
- Consumes: `Tokens` (Task 3), `BitWriter` (Task 2).
- Produces: `pub(crate) fn code_lengths(freq: &[u32], max_bits: u8, out: &mut [u8])` (length-limited: 15 for literal/length and distance, 7 for code-length codes; any correct limiting method, e.g. package-merge or heap + limiting pass, using fixed-size scratch, no allocation); `pub(crate) fn canonical_codes(lengths: &[u8], codes: &mut [u16])` (bit-reversed for LSB-first writing); the dynamic header writer with 16/17/18 run-length coding of the code lengths (RFC 1951 §3.2.7) and HLIT/HDIST/HCLEN trimming; per chunk the encoder computes the exact bit cost of dynamic, fixed and stored and writes the cheapest.

- [ ] **Step 1: Write the failing tests:**
  - `lengths_are_limited_and_complete`: for frequency sets including all-equal, Fibonacci (forces depth > 15), one symbol, two symbols and zeros, every length ≤ max and the Kraft sum is exactly 1 (or a single code of length 1).
  - `json_is_within_five_percent_of_zlib_l6`: for the JSON fixture at 25, 40 and 50 items, `encode` output ≤ 1.05 × zlib-rs level 6 gzip output (built in the test with `zlib_rs` at level 6, window bits 31).
  - `random_input_stays_within_bound`: 50 random inputs of 1–100,000 bytes produce stored blocks (output ≤ `bound(len)` and ≥ len) and round-trip.
  - `block_type_is_the_cheapest`: a test-only accessor reports the chosen type; JSON → dynamic, 20-byte text → fixed, random → stored.
- [ ] **Step 2: Run, verify fail** (size vs zlib fails without dynamic blocks).
- [ ] **Step 3: Implement** `huffman.rs` and the dynamic writer; block choice by exact bit cost.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `codec: gzip encoder dynamic Huffman blocks, cheapest block type`.

---

### Task 5: Robustness — fuzzing, Miri, independent inflaters, optional SIMD

**Files:**
- Create: `wtx-fuzz/gzip_encoder.rs`; `wtx/src/codec/gzip_encoder/check.rs` (`#[doc(hidden)] pub fn check_bytes(data: &[u8])`, `cfg(any(test, feature = "_fuzz-gzip"))`)
- Modify: `wtx-fuzz/Cargo.toml` (`[[bin]] gzip_encoder`, feature `gzip-encoder` + `_fuzz-gzip` on rimu-ws), `wtx/Cargo.toml` (`_fuzz-gzip = ["gzip-encoder"]`), `wtx/src/codec.rs` (`#[cfg(feature = "_fuzz-gzip")] #[doc(hidden)] pub use gzip_encoder::check as gzip_check;`), optionally `matcher.rs` (AVX2 32-byte compare behind `is_x86_feature_detected!("avx2")` under `std`)

**Interfaces:**
- Consumes: `GzipEncoder`, `GzipParams` (Tasks 2–4).
- Produces: `check_bytes(data)`: the first 8 bytes of `data` pick `GzipParams` (each field clamped to 1..=258, `search_depth` 1..=4096) and a split of the rest into 1–3 inputs encoded on one encoder in turn; each output inflates (zlib-rs) to its input, is ≤ `bound`, and the CRC/ISIZE trailer matches.

- [ ] **Step 1: Write the failing test** `check_bytes_accepts_a_seed_corpus` in `tests.rs`: `check_bytes` over 200 seeded random byte strings and the JSON fixtures returns without panic.
- [ ] **Step 2: Run, verify fail** (missing).
- [ ] **Step 3: Implement** `check.rs` and the fuzz target (`libfuzzer_sys::fuzz_target!(|data: &[u8]| rimu_ws::codec::gzip_check::check_bytes(data));` with the matching re-export).
- [ ] **Step 4: Run** the test; `cargo fuzz run gzip_encoder -- -max_total_time=1800 -rss_limit_mb=2048 -timeout=10` from `wtx-fuzz` with `CARGO_TARGET_DIR=/mnt/nvme1tb/claude-tmp/target-fuzz` in the background → 0 crashes, 0 timeouts; Miri: `cargo +nightly-2026-10-12 miri test -p rimu-ws --lib --features std,gzip-encoder -- codec::gzip_encoder` with `MIRIFLAGS="-Zmiri-strict-provenance"` → PASS (large-input tests `#[cfg_attr(miri, ignore)]` with a reason; at least one test reaches every `unsafe`).
- [ ] **Step 5: (optional) AVX2 match extension** only if a microbenchmark of `Matcher::find` on the JSON fixtures shows ≥ 5 % less time; it must have a `// SAFETY:` comment and the portable path must stay tested; otherwise record "not worth it" in the commit message.
- [ ] **Step 6: Commit** — `codec: gzip encoder fuzz target, Miri coverage`.

---

### Task 6: The effort sweep and the defaults

**Files:**
- Modify: `wtx-internal/src/bin/arena-h1.rs` (add `#[cfg(test)] mod gzip_sweep;`), create `wtx-internal/src/bin/arena_h1/gzip_sweep.rs`; `wtx/src/codec/gzip_encoder.rs` (`GzipParams::default` values + doc of the measured reason)
- Create: `docs/benchmarks/2026-11-11-json-comp-sweep/README.md`

**Interfaces:**
- Consumes: `GzipParams`, `GzipEncoder` (Tasks 2–5); `T_other` and the rival bpr table (Task 1); arena-h1's `write_json` and dataset loader.
- Produces: `GzipParams::default()` = the sweep winner.

- [ ] **Step 1: Write the ignored test** `sweep` in `gzip_sweep.rs`: load `/mnt/nvme1tb/claude-tmp/arena-main/data/dataset.json`, build the three bodies with `write_json` for `(25, 4)`, `(40, 8)`, `(50, 6)`; for each point of the grid `search_depth ∈ {1, 2, 3, 4, 6, 8, 12, 16}` × `nice_match ∈ {16, 24, 32, 48, 64, 128}` × `good_match ∈ {4, 8, 16, 32}` × `max_insert ∈ {2, 4, 8, 16, 258}` measure output bytes per body and the median ns per encode over 2,000 encodes per body on one pinned core (CPU 0), then score `1 / ((T_other + t_enc) × (hdr + body)²)` averaged over the bodies, with `hdr` rimu's measured header bytes and `T_other` from Task 1; print the top 20 and the zlib-rs level 1/6 reference rows.
- [ ] **Step 2: Run** `cargo test -p rimu-ws-internal --features arena-h1 --release --bin arena-h1 -- --ignored sweep --nocapture` (quiet machine, `taskset -c 0`) → a ranked table.
- [ ] **Step 3: Set `GzipParams::default()`** to the winner (if several are within 1 %, the one with the fewest bytes); its doc comment states the measured score, bytes and ns.
- [ ] **Step 4: Run** `cargo test -p rimu-ws --lib --features std,gzip-encoder -- codec::gzip_encoder` → PASS (the zlib-L6 size bound of Task 4 still holds at the new default; if it does not, the bound in that test is the controller's call — report).
- [ ] **Step 5: Write the README** (grid, top rows, chosen defaults, machine state) and **commit** — `codec: gzip encoder defaults from the json-comp sweep`.

---

### Task 7: arena-h1 uses the encoder

**Files:**
- Modify: `wtx-internal/src/bin/arena-h1.rs` (gzip path: `GZIP` thread-local becomes `RefCell<Option<GzipEncoder>>`, `gzip()` calls `encode`; zlib-rs stays for nothing else in arena-h1 → drop the `zlib-rs` dependency from the `arena-h1` feature if unused), `wtx-internal/Cargo.toml` (`arena-h1` feature gains `rimu-ws/gzip-encoder`)
- Modify: `~/src/HttpArena` branch `add-rimu-ws` entry `frameworks/rimu-ws-h1` via its `local-src.sh` (LOCAL commit only)

**Interfaces:**
- Consumes: `GzipEncoder::{new, encode}` (Tasks 2–6).

- [ ] **Step 1: Write the failing test** in arena-h1's test module: `json_gzip_uses_the_new_encoder` — `/json/50?m=6` with `Accept-Encoding: gzip` returns `content-encoding: gzip`, the body inflates (zlib-rs) to `write_json`'s output for the same `(count, m)`, and its length equals `GzipEncoder::new().encode(...)`'s output length for those bytes.
- [ ] **Step 2: Run, verify fail** (zlib output length differs).
- [ ] **Step 3: Implement** the switch.
- [ ] **Step 4: Run** the arena-h1 tests (`cargo test -p rimu-ws-internal --features arena-h1 --bin arena-h1`), including its zero-allocation tests (the `/json` gzip path must stay at 0 allocations per request after warm-up) → PASS; run the h1 validators (`/mnt/nvme1tb/claude-tmp/h1val`, json-comp validator 5/5 and the rest green); sync the HttpArena entry (`frameworks/rimu-ws-h1/local-src.sh`), rebuild its image, `validate.sh rimu-ws-h1` → all pass.
- [ ] **Step 5: Commit** (rimu-ws) — `arena-h1: json-comp gzip uses the rimu-ws gzip encoder`; (HttpArena, local) — `rimu-ws-h1: synced with rimu-ws <sha>`.

---

### Task 8: Head-to-head on colossus and the regression check

**Files:**
- Create: `docs/benchmarks/2026-11-11-json-comp-colossus/README.md` (+ `data/`); scratch harness under `/mnt/nvme1tb/claude-tmp/jsoncomp/` (not committed; copied into `data/` as text)

**Interfaces:**
- Consumes: arena-h1 release build of this branch's HEAD (built before any run) and of `main` 1a3c3b08 (scratch clone); rival images; Task 1's method.

- [ ] **Step 1: json-comp head-to-head.** Servers rimu (new), rimu (`main`), viltrum, plod, aegon; gcannon with the profile's shape (`--raw json-gzip-25.raw,json-gzip-40.raw,json-gzip-50.raw -p 1 -r 25`, `-t 10` on the generator CPUs) at 4,096 and 16,384 connections, 5 s per run, best of 3 runs per start, 3 interleaved passes with the server order rotated; quiet-machine check before each pass. Compute per server `avgRps`, bpr from gcannon's bytes read ÷ responses, the league `minBpr`, and eff.
- [ ] **Step 2: Regression A/B.** `main` vs this branch for the h1 profiles the local harness covers — `/mnt/nvme1tb/claude-tmp/aws-final/remote/regress.sh` with `LOCAL=1`, `PROFILES="h1-baseline h1-jsoncomp-4096 h1-json-tls h1-8gbit"`, `SCPU=0-5,12-17 LCPU=6-10,18-22`, 4 passes (with variant B rebuilt from this branch by `aws-final/build.sh regress` with `REV=<HEAD>`) — plus h1bench async (`bench-async.sh`) and latency-10k (`lat.sh`) once each for both builds. Rule: none worse than 1 % (rps; 8gbit by CPU per request), changes inside the pass spread marked as such.
- [ ] **Step 3: Write the README**: machine state (load per pass), CPU split, the eff table, the regression table, verdict against Goal 6 (eff ≥ 1.05 × viltrum, no h1 regression > 1 %). Commit — `docs: json-comp head-to-head on colossus (fast gzip encoder)`.
- [ ] **Step 4: Report** the verdict. If the success bar is missed, report the best eff and the gap; do not tune headers or bend rules.
