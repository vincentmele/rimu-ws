# json-comp baseline and the ceiling gate — colossus, 11 Nov 2026

Task 1 of `docs/superpowers/plans/2026-11-11-fast-deflate.md`: what every entry sends on the three json-comp requests,
how much of rimu's request time is compression, and whether a faster compressor can win. No product code changed.

## Machine and method
colossus (AMD Ryzen 9 5900X, 12 cores / 24 threads, kernel 7.0.0-38). rimu = arena-h1 of `main` 1a3c3b08 (release,
`-C target-cpu=znver2`, the aws-final kit's `bin/regress/B/h1`); rivals = local images `httparena-viltrum`,
`httparena-plod`, `httparena-aegon`. Server CPUs 0-5,12-17, generator 6-10,18-22; no sysctl changes. colossus was
shared with other jobs (load average 3–15 during the session): the byte counts are load-independent; the profile is
per process (`perf record -p`), so its shares are not affected by other processes, but its absolute rps is.

- Bytes: `data/bytes.sh` — `curl -D` with `Accept-Encoding: gzip, br` on the profile's three requests
  (`/json/25?m=4`, `/json/40?m=8`, `/json/50?m=6`, from `arena-main/requests/json-gzip-{25,40,50}.raw`).
- Profile: `data/profile.sh` — gcannon with the profile's shape (`--raw json-gzip-25/40/50.raw -c 4096 -t 10 -p 1
  -r 25`, 12 s), `perf record -F 999 -g -p <rimu>` for 5 s in the middle.

## Bytes per response (header = status line through the blank line)

| entry | /json/25?m=4 | /json/40?m=8 | /json/50?m=6 | mean bpr |
|---|---|---|---|---|
| rimu | 119 + 947 | 120 + 1,301 | 120 + 1,519 | **1,375** |
| viltrum | 156 + 967 | 157 + 1,322 | 157 + 1,563 | 1,441 |
| aegon | 157 + 1,023 | 157 + 1,412 | 157 + 1,704 | 1,537 |
| plod | 172 + 1,008 | 172 + 1,420 | 172 + 1,703 | 1,549 |

rimu (zlib-rs level 6, with `Vary: Accept-Encoding`) is the smallest on every request and in headers. As the league
minimum it cuts viltrum's eff by (1,375 / 1,441)² = 0.911. Note: the earlier "947 B vs 967 B" figures were the
`/json/25` bodies.

## Where rimu's json-comp time goes
gcannon: 131.3 K req/s (4096 connections, shared machine). Server cycles (`data/perf-symbols.txt`): zlib-rs **67.9 %**
(`deflate_medium` 30.7, `longest_match` 13.4, CRC32 braid 8.7, `flush_block_only` 6.0, Huffman heap 4.9, …), plus
memset 4.4 % (mostly zlib's per-call state reset); `write_json` 3.4 %; the rest is the h1 path and the kernel.
Server CPU per request ≈ 12 threads / 131.3 K = 91 µs (thread time, SMT shared), of which **T_other ≈ 29 µs** is not
compression — the figure the sweep (Task 6) uses.

## The gate
- To beat viltrum by 5 %: `rps_rimu ≥ 1.05 × 0.911 × rps_viltrum ≈ 0.957 × rps_viltrum` (≈ 200 K at viltrum's 209 K of
  7 Nov), if rimu stays the smallest.
- Ceiling with a zero-cost compressor at today's size: 131 K / (1 − 0.68) ≈ 410 K.
- **Verdict: GO** — the target needs about a third of zlib-rs's per-request cost removed, well inside the ceiling.
