# HTTP/3 request-path follow-up A/B on AWS EC2 — 9 Nov 2026

The third EC2 run: a short A/B of Task 16's completed request-path work (`base` = `a99e6332`) against the build the
variant batch measured (`prev` = `d73a785d`), with zix as the fixed reference. Method and box as in
[`../2026-11-09-h3-ec2/README.md`](../2026-11-09-h3-ec2/README.md); kit and variant phase as in
[`../2026-11-09-h3-ec2-variants/README.md`](../2026-11-09-h3-ec2-variants/README.md).

## Why
Task 16's review found that the first commit (`d73a785d`) did only part of Ruling T16-a; the fix round (`dd589387`,
`a99e6332`) completed it: QPACK static-index classification of request fields, one validation pass per field (ASCII bit
folded into the field-content check; an unchecked UTF-8 conversion for all-ASCII heads), and one gathered stream write
per response (no frame buffer). This run measures whether that completion pays.

## Run
m6a.24xlarge spot, sa-east-1b; launched 16:55:05 UTC, kit uploaded in 16 s, setup done 16:55:51, 3 passes of 6 starts
(16:55:52–17:04:44, ≈ 3 min each), profile of `base` until 17:06:13, terminated and cleaned up (verified): **12 min wall,
≈ $0.15**. Both builds with `ARENA_H3_HEADERS=min`, `ARENA_H3_DATA=reuse`, all other knobs at their defaults.

## Results (median of 3 passes)
| profile | variant | req/s | server CPU µs/req | spread | lost / resent (window) |
|---|---|---|---|---|---|
| baseline-h3 | base (a99e6332) | 5,809k | 2.13 | 0.7 % | 0 / 0 |
| baseline-h3 | prev (d73a785d) | 5,792k | 2.08 | 0.9 % | 0 / 0 |
| baseline-h3 | zix | 5,964k | 1.40 | 1.2 % | |
| static-h3 | base | 948k | 43.17 | 2.9 % | 18,064 / 32,729 |
| static-h3 | prev | 951k | 41.36 | 2.2 % | 23,097 / 38,380 |
| static-h3 | zix | 579k | 52.20 | 7.0 % | |

The completion is **neutral within spread** on both profiles (baseline +0.3 % rps, +2.2 % CPU/req; static −0.3 %,
+4.4 % CPU/req). Spec §2.1 counters unchanged (62 responses per packet, 0 % ACK-only, 100 % of baseline flushes carry an
ACK, no blocked frames).

## What the profile says (base, baseline-h3)
`RequestHead::push` fell from 4.8 % (variant batch) to 2.8 % of server cycles — the static-index classification and the
single validation pass work — but `SendPart::append_bytes` rose to 3.4 % (from below the top 10): the gathered write
appends each piece separately, which costs about what the removed frame-buffer copy saved. Net ≈ 0, matching the A/B.

## static-h3 on this host
Both builds were slower than in the variant batch (43 vs 30 µs/req) while zix was not (52 vs 48): the profile shows
`kernel_init_pages` at **31.5 %** of server cycles (15 % in the variant batch on another m6a host). The kernel zeroes the
pages it allocates for outgoing skb data (Ubuntu's init_on_alloc default), and its cost depends strongly on the
physical host. rimu, sending large GSO trains, allocates more page memory per call than zix's per-datagram sendmsg; this
is the main static-h3 lead for Task 19 (fewer page allocations per byte sent: send-buffer reuse / zero-copy / smaller
trains under memory pressure), and a reminder that A/B comparisons must stay within one host.

## Conclusions and rulings
1. Ruling T16-g: keep the static-index classification and the single validation pass (profile gain), revert the
   gathered single-copy response write (profile cost ≈ its saving, no measured win; the plan keeps only wins); the next
   EC2 batch re-measures.
2. rimu vs zix on baseline-h3 is now 2.7 % on throughput; the server-CPU gap remains (2.1 vs 1.4 µs/req).
3. static-h3 numbers move with the host's page-zeroing cost: compare only within a run.

## Data
`data/summary.txt`, `data/vbench.jsonl` (18 rows), `data/vprofile.jsonl`, `data/host.txt`, `data/uptime.log`,
`data/{setup,variants}.log`, `data/launch.log` (redacted), `data/raw.tar.zst`, `data/vprofile/` (text + folded stacks).
Full archive: `~/benchmarks-archive/rimu-h3/2026-11-09-h3-ec2-followup-run-20261109-165451.tar.zst` (`ARCHIVE.sha256`).
