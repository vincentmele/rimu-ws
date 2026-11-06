# HTTP/2 benchmark results

Measured with `.scripts/h2-bench.sh` on colossus (Ryzen 9 5900X, 12 cores / 24 threads).

- **Server:** CPUs 0-5,12-17.
- **h2load:** CPUs 6-11,18-23. It is nghttp2 1.59 (the official board's version) in the
  `httparena-h2load` image, run as `-t 12 -D 5s`.
- **Runs:** best of 3, with a fresh server for each (profile, connections) pair.
- **Composite:** from `.scripts/h2-composite.py`, which uses the board formula over the scored
  connection counts.
- **Raw rows:** each run's JSON line is kept under `docs/perf/`.

## Baseline (old driver), 6 Nov 2026

- rimu is `arena-h2` on the upstream server framework, on `UringExecutor`, with
  `ARENA_PARAMS=permissive` (upstream's wtx-http2 settings).
- Under the library defaults, the old server fails h2load's 100 concurrent streams: GOAWAY with
  ExceedAmountOfOpenedStreams, 18% of requests errored. Task 13 fixes the defaults.
- Rivals are the HttpArena images, built from upstream main 76e0fad.
- Raw rows: `http2-baseline-2026-11-06.jsonl`.

```
server     composite           baseline-h2             static-h2          baseline-h2c              json-h2c
plod            4000        4913k (1000)         370k (1000)        5108k (1000)        1454k (1000)
viltrum         2835        4459k ( 908)         109k ( 295)        4699k ( 920)        1037k ( 713)
aegon           2172        2879k ( 586)         183k ( 493)        3024k ( 592)         728k ( 501)
rimu            1096        1713k ( 349)           0k (   0)        1817k ( 356)         569k ( 391)
```

| server | profile | conns | best rps | h2load CPU % | server user cycles/req |
|---|---|---|---|---|---|
| aegon | baseline-h2 | 256 | 2968810 | 51.6 | None |
| plod | baseline-h2 | 256 | 5080138 | 97.8 | None |
| rimu | baseline-h2 | 256 | 1738405 | 58.9 | 17052 |
| viltrum | baseline-h2 | 256 | 4552198 | 73.8 | None |
| aegon | baseline-h2 | 1024 | 2789409 | 50.9 | None |
| plod | baseline-h2 | 1024 | 4745846 | 100.0 | None |
| rimu | baseline-h2 | 1024 | 1687169 | 58.2 | 17343 |
| viltrum | baseline-h2 | 1024 | 4365878 | 81.7 | None |
| aegon | static-h2 | 256 | 203537 | 77.8 | None |
| plod | static-h2 | 256 | 379685 | 68.6 | None |
| viltrum | static-h2 | 256 | 218064 | 54.8 | None |
| aegon | static-h2 | 1024 | 161502 | 68.6 | None |
| plod | static-h2 | 1024 | 360687 | 72.2 | None |
| viltrum | static-h2 | 1024 | 0 | 49.9 | None |
| aegon | baseline-h2c | 256 | 3113988 | 44.8 | None |
| plod | baseline-h2c | 256 | 5425149 | 95.5 | None |
| rimu | baseline-h2c | 256 | 1905244 | 33.5 | 16189 |
| viltrum | baseline-h2c | 256 | 4796178 | 72.7 | None |
| aegon | baseline-h2c | 1024 | 3004705 | 48.7 | None |
| plod | baseline-h2c | 1024 | 5057811 | 96.4 | None |
| rimu | baseline-h2c | 1024 | 1821953 | 38.0 | 16663 |
| viltrum | baseline-h2c | 1024 | 4747258 | 78.0 | None |
| aegon | baseline-h2c | 4096 | 2953255 | 48.6 | None |
| plod | baseline-h2c | 4096 | 4841965 | 100.0 | None |
| rimu | baseline-h2c | 4096 | 1724611 | 36.9 | 17836 |
| viltrum | baseline-h2c | 4096 | 4554358 | 81.9 | None |
| aegon | json-h2c | 1024 | 748830 | 38.4 | None |
| plod | json-h2c | 1024 | 1490832 | 53.9 | None |
| rimu | json-h2c | 1024 | 581838 | 28.1 | 62023 |
| viltrum | json-h2c | 1024 | 1053698 | 35.7 | None |
| aegon | json-h2c | 4096 | 708156 | 40.3 | None |
| plod | json-h2c | 4096 | 1417280 | 61.4 | None |
| rimu | json-h2c | 4096 | 556648 | 28.5 | 64577 |
| viltrum | json-h2c | 4096 | 1019515 | 42.1 | None |

Notes:
- **The load generator is the limit for the leader.** On baseline-h2 and baseline-h2c, h2load sits
  at 95–100% CPU against plod. On this box those columns measure h2load, not plod. That makes
  static-h2 and json-h2c, where h2load is at 35–72%, the deciding profiles locally.
- **viltrum static-h2 at 1024 connections:** viltrum stalls streams, h2load never finishes
  (59 min in one run), and every run fails. The script now stops h2load after 30 s and scores
  the run 0.
- **Old rimu cost:** about 17k user cycles per request on baseline and about 62k on json-h2c.
