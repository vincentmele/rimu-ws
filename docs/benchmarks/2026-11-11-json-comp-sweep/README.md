# json-comp effort sweep of the rimu-ws gzip encoder — colossus, 11 Nov 2026

Task 6 of `docs/superpowers/plans/2026-11-11-fast-deflate.md`. Not a load test: one pinned core (CPU 0) of colossus
(Ryzen 9 5900X), the ignored test `gzip_sweep::sweep` in `wtx-internal/src/bin/arena_h1/gzip_sweep.rs`, release
build. Machine load average 1.3–2.5 during the runs, no other process above half a CPU.

## Method
The profile's three bodies (`/json/25?m=4`, `/json/40?m=8`, `/json/50?m=6`) built with arena-h1's own `write_json` from
the arena dataset; every parameter set encodes each body 2,000 times; the median per body is averaged. To rank by
json-comp's score the one-core time is scaled to the loaded server by zlib-rs level 6, measured the same way and known
to cost 62.0 µs a request under the json-comp load (baseline write-up, 67.9 % of 91.4 µs of server thread time), beside
the 29.3 µs of everything else; score = `1 / ((29.3 + t_loaded) × bpr²)` with `bpr` = rimu's mean header bytes (119.7)
plus the mean body, reported relative to zlib-rs level 6.

## Runs
1. **Before the hot-path work** (`data/sweep1-before-hot-path.txt`, 960 sets): best `depth 8 nice 16 good 4 insert 2`
   at 16.5 µs, bpr 1,402.7, score 1.30 — projected ≈ 178 K req/s, short of the ≈ 208 K needed. A profile showed the
   matcher's helpers not inlined, the hashed word read byte by byte, the Huffman builder clearing ~8.6 KB per tree and
   two writes per code; fixed in commit `84b01f01` (17.35 → 13.1 µs in the profiling loop), which also added the
   `lazy` knob.
2. **After** (`data/sweep2.txt`, 1,440 sets incl. greedy): zlib-rs level 6 27.17 µs (factor 2.28), level 1 0.974.

| set (lazy unless noted) | bodies (B) | bpr | µs (one core) | loaded µs | score |
|---|---|---|---|---|---|
| depth 6 nice 16 good 8 insert 1 (best score) | 969 / 1,330 / 1,564 | 1,407.3 | 11.33 | 25.9 | 1.581 |
| depth 6 nice 64 good 8 insert 2 (**chosen**) | 958 / 1,313 / 1,544 | 1,391.3 | 12.08 | 27.6 | 1.569 |
| zlib-rs level 6 (today's rimu) | 947 / 1,301 / 1,519 | 1,375.3 | 27.17 | 62.0 | 1.000 |
| zlib-rs level 1 | 1,266 / 1,828 / 2,212 | 1,888.3 | 8.94 | 20.4 | 0.974 |

No greedy (non-lazy) set reached the top 25. Shallow inserts (`max_insert` 1–2) and depth 4–8 dominate.

## Choice
`GzipParams::default()` = lazy, `search_depth` 6, `nice_match` 64, `good_match` 8, `max_insert` 2: of the sets within 1 %
of the best score, the one with the fewest bytes (rimu sets the league's smallest bpr, which lowers every rival's score).

Projection (to be confirmed end to end, Task 8): ≈ 131 K × 91.4 / (29.3 + 27.6) ≈ 210 K req/s at bpr 1,391; viltrum
(209 K on 7 Nov at bpr 1,441) would score × (1,391 / 1,441)² = 0.932 → rimu ≈ 8 % ahead.
