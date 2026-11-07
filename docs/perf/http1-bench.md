# HTTP/1.1 benchmark results

A validation-scale figure for `arena-h1` (`/baseline11`), not a gate.

- **Machine:** colossus (Ryzen 9 5900X, 12 cores / 24 threads).
- **Server:** `arena-h1` (release, no spin), pinned to CPUs 0-5,12-17.
- **Load:** native `gcannon` on CPUs 6-11,18-23, as the `baseline` profile runs it: the mixed
  `get.raw` / `post_cl.raw` / `post_chunked.raw` rotation, `-c 4096 -t 12 -d 5s -p 1`.
- **Cycles per request:** `perf stat -e cycles:u -p <server>` over 2 s in the middle of a run,
  divided by the requests answered in that time (user mode only).
- **Runs:** 3 against one server; the best is kept.

| Profile  | Conns | Run 1  | Run 2  | Run 3 (best) | User cycles/req (best) |
| -------- | ----: | -----: | -----: | -----------: | ---------------------: |
| baseline |  4096 | 880.05K | 878.76K | 890.22K     | 6380                   |

All 2xx; p50 latency 4.4 ms. Raw gcannon output: run 1 `Throughput: 880.05K req/s`, run 2
`878.76K req/s`, run 3 `890.22K req/s`.
