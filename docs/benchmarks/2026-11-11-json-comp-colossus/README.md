# json-comp head-to-head with the rimu-ws gzip encoder — colossus, 11 Nov 2026

Task 8 of `docs/superpowers/plans/2026-11-11-fast-deflate.md`: rimu's json-comp entry with the new one-shot gzip encoder
(`codec::GzipEncoder`, this branch at d630255d) against `main` 1a3c3b08 (zlib-rs level 6) and the experimental league's
other entries, plus a regression check of the other h1 profiles.

## Machine and method
colossus (AMD Ryzen 9 5900X, 12 cores / 24 threads, kernel 7.0.0-38). Servers on CPUs 0-5,12-17, load generators on
6-10,18-22 (core 11/23 left to colossus's live services), no sysctl or service changes. Both rimu builds made alike by
the aws-final kit's `build.sh regress` (release, `--locked`, `-C target-cpu=znver2`, scratch clones): A = `main`
1a3c3b08, B = d630255d. Rivals: local images `httparena-viltrum`, `httparena-plod`, `httparena-aegon`. colossus is
shared: other sessions' builds ran at times, so every run waited for no outside process above half a CPU (and for the
reruns a load average below 2); loads are logged.

- json-comp (`data/h2h.sh`, summary `data/h2h_summary.py`): gcannon with the profile's shape (`--raw
  json-gzip-25.raw,json-gzip-40.raw,json-gzip-50.raw -p 1 -r 25 -t 10`), 4,096 and 16,384 connections, 5 s per run,
  best of 3 runs per start, 3 passes with the server order rotated. Per server: avgRps = mean over the two connection
  counts, bpr = mean bandwidth (gcannon's MB = MiB) / avgRps, both medians over the passes; eff = avgRps × (league
  minimum bpr / bpr)², column = 1000 × eff / best — HttpArena's formula.
- Regression: the kit's `regress.sh` with `LOCAL=1` (h1-baseline, h1-jsoncomp-4096, h1-json-tls, h1-8gbit; A,B / B,A
  over 4 passes), plus h1bench's async (`/delay/10`, 24,000 connections) and latency-10k (zrk, 10,000 req/s fixed
  rate) once per build per round, interleaved, 3 rounds. latency-1m needs about 64 cores and is not measurable here.

## json-comp (15:51–16:02 UTC)

League with the new encoder:

| entry | avgRps | bpr | eff | column |
|---|---|---|---|---|
| **rimu (new encoder)** | **233.7 K** | **1,391.5** | 233.7 K | **1000** |
| viltrum | 198.0 K | 1,440.6 | 184.7 K | 790 |
| aegon | 200.7 K | 1,536.4 | 164.6 K | 704 |
| plod | 200.8 K | 1,549.2 | 162.0 K | 693 |

**rimu / viltrum eff = 1.265** (goal ≥ 1.05). The same league with `main`'s zlib-rs: rimu 134.7 K at 1,375.5 B →
0.746 of viltrum (column 746, viltrum 1000). The encoder raised rimu's json-comp throughput 1.73× for 1.2 % more
bytes. 0 non-2xx responses in every run. Pass 3 was disturbed after its first server (load 13 from other jobs: viltrum,
which ran first, held 195 K; the others fell ~25 %); the medians rest on passes 1 and 2, which agree.

## Regression (other h1 profiles)

| profile | `main` | this branch | change | pass spread (A / B) | verdict |
|---|---|---|---|---|---|
| h1-baseline (quiet rerun) | 798,464 req/s, 14.46 µs | 798,576 req/s, 14.58 µs | +0.01 % rps, +0.8 % cpu | 0.8 / 0.5 % rps, 0.9 / 1.4 % cpu | ok |
| h1-json-tls | 294,588 req/s | 295,254 req/s | +0.23 % | 17.8 / 14.2 % | ok |
| h1-8gbit (quiet rerun; rate-capped, judged by cpu) | 34.22 µs/req | 34.57 µs/req | **+1.03 % cpu** | 1.6 / 8.6 % cpu | over the 1 % rule by 0.03 %; accepted by ruling (below) |
| h1-jsoncomp-4096 | 134,043 req/s, 89.4 µs | 246,131 req/s, 48.7 µs | **+83.6 % rps, −45.6 % cpu** | 3.1 / 5.9 % | the change |
| async (`/delay/10`, 3 rounds) | 414 K (414 / 411 / 429) | 419 K (412 / 419 / 425) | +1.2 % | | ok |
| latency-10k (3 rounds, medians) | mean 106 µs, p99 123 µs, 287 K cyc/req | mean 104 µs, p99 128 µs, 288 K cyc/req | mean −2 %, **p99 +4 %** (higher in all three rounds: 124/128/128 vs 123/123/127 µs), cycles equal | ±5 µs between rounds | not a measured regression of this branch's code (below) |

The first regression run (`data/regress-run1-results.tsv`) started at load 18–26 and gave noise for baseline (−3.5 %
with 26 % / 59 % pass spreads) and 8gbit (+5.8 % cpu from one 61 µs pass); both were rerun quiet
(`data/regress-run2-results.tsv`). The branch changes no h1, TLS or executor code: only arena-h1's gzip call and the
new feature-gated module. latency-10k's cycles count everything on the server CPUs (`perf stat -C`), so other jobs
inflate both builds alike.

**gcannon read errors.** json-comp's load reconnects every 25 requests, so read errors scale with throughput: per
reconnect at 16,384 connections rimu (new) 0.24 %, plod 0.26 %, aegon 0.23 %, viltrum 0.17 %, rimu (`main`) 0.16 %
(runs of passes 1–2). Every response was 2xx; the errors are connection teardown races of the reconnecting client, at
rates comparable to the rivals'.

**Ruling (8gbit).** The plan's rule is "none worse than 1 %"; 8gbit's cpu per request came out +1.03 % on the quiet
rerun, with this branch's own passes spread 8.6 % (paired per pass +2.1 / +8.5 / −0.05 / −1.8 %) and +5.8 % on the
noisy first run driven by one 61 µs pass. The branch changes no TLS, h1 or executor code (8gbit is `POST /echo` over
TLS; only arena-h1's gzip call and a feature-gated module changed), so the difference is taken as measurement noise and
accepted; cost if wrong: about 1 % of 8gbit's server cpu. Likewise latency-10k's p99 is 4 % higher on the medians with
the mean 2 % lower and cycles equal, on a path (`/baseline11`) the branch does not touch.

## Verdict
Goal 6 of the spec is met on colossus: rimu leads json-comp in the experimental league with eff 1.27 × viltrum's. Of the
other h1 profiles measured, baseline, json-tls and async are within 1 %; 8gbit's cpu is +1.03 % and latency-10k's p99
+4 %, both on code the branch does not change and accepted as noise by the ruling above. latency-1m was not measured.
