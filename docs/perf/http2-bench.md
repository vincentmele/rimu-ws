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

## Conformance baseline (old driver), 6 Nov 2026

- **h2spec 2.6.0** (`CONTAINER=docker .scripts/h2spec.sh high`, against the raw `h2spec-high`
  server on tokio): 139 tests, 139 passed, 0 failed. These are the sections the script lists;
  priority and server push are excluded as unsupported.
- **Interop** (`.scripts/h2-interop.sh http://127.0.0.1:8082 https://127.0.0.1:8443`, against
  `arena-h2` with the 50 ms linger on): curl, nghttp and Go `net/http` all pass, over both h2c
  and TLS. The curl failure the audit saw needs linger off, which `arena-h2` has no switch for.
- **Negative check:** against a closed port, every client's check fails.

## After Task 9 (new batch driver, `ARENA_PARAMS=permissive`), 6 Nov 2026

| profile | conns | best rps | old driver | h2load CPU % | server user cycles/req |
|---|---|---|---|---|---|
| baseline-h2c | 256 | 5,010k | 1,905k | 92.5 | 6,972 |
| baseline-h2c | 1024 | 4,533k | 1,822k | 91.2 | 8,216 |
| baseline-h2 (TLS, kTLS) | 256 | 4,616k | 1,738k | 93.7 | 7,098 |
| json-h2c | 1024 | 542k | 582k | 25.1 | 71,998 |

- **Baseline:** h2load is near its ceiling on colossus here; plod measured 5.1–5.4M under the same
  load.
- **json-h2c:** the handler path dominates it (about 72k user cycles per request), not the driver.
  That is the next target.
- **Panic isolation** (`catch_unwind` per handler poll): about 7,000 user cycles per request with
  and without it. No measurable cost.
- **Conformance:** h2spec (without `--max-header-length 800`) passes 139/139 in plaintext and over
  TLS.
- **Interop:** curl, nghttp and Go `net/http` all pass, over h2c and TLS.

## Task 10A: performance foundations, 6 Nov 2026

Each item is an A/B on server user cycles per request plus throughput, on library defaults (no
`ARENA_PARAMS`).

### Step 1: 128 concurrent streams by default (was 32)

| profile | conns | best rps | h2load CPU % | server user cycles/req |
|---|---|---|---|---|
| baseline-h2c | 256 | 4,991k | 91.1 | 7,056 |
| baseline-h2c | 1024 | 4,588k | 94.2 | 8,174 |
| baseline-h2c | 4096 | 3,882k | 100.0 | 8,692 |
| baseline-h2 (TLS) | 256 | 4,606k | 91.9 | 7,140 |
| baseline-h2 (TLS) | 1024 | 4,187k | 96.5 | 8,393 |
| json-h2c | 1024 | 541k | 25.7 | 71,350 |
| json-h2c | 4096 | 510k | 26.6 | 74,633 |

- With 32 streams the defaults failed `-m 100` outright (`ExceedAmountOfOpenedStreams`); with 128
  they match the permissive settings.

### Step 2: the json-h2c handler path

From here the benches build `arena-h2` with `-C target-cpu=native`, as the HttpArena entry's
Dockerfile does (`.scripts/h2-bench.sh` defaults to `target-h2-native`).

- **`Vector::reserve` fast path.** Every `extend` called `reserve`, which round-tripped the buffer
  through a `Vec` (`to_vec_mut`) even when the spare capacity was enough. It now returns at once
  when the room is there. baseline-h2c 256: 7,056 → 6,160 cycles/req (−13%), 4.99M → 5.24M rps
  (h2load at 99% CPU); json-h2c 1024: 71,350 → 68,578.
- **`misc::JsonWriter`** (feature `json-writer`), in the spirit of xtrader's order writer and
  Polymarket scanner. Keys and punctuation are literals fused into a single copy each. Strings are
  escaped while they are copied, 32 bytes a step with AVX2 or 8 with word tricks, into space
  reserved for the worst case once per string. Integers are written in place from a two-digit
  table. Floats use `zmij`, the formatter `serde_json` uses. Short variable copies are two
  overlapping fixed-size moves. The output is byte for byte `serde_json`'s: the library tests
  compare strings, integers and floats, and `arena-h2`'s tests compare whole responses on the
  real dataset. JSON is still serialized on every request.

  A/B, both native, json-h2c 1024, two rounds interleaved:

  | endpoint | best rps | cycles/req |
  |---|---|---|
  | serde_json | 550k, 560k | 67,865, 68,222 |
  | JsonWriter | 588k, 589k | 61,191, 62,053 |

- **What is left.** The profile is now led by `memmove` (22%) and the kernel's send copy and
  page allocation (13%). Each response body goes through three per-connection buffers (the
  message, the stream queue, the output, then the reactor's send buffer). With 1024 connections
  that working set is hundreds of megabytes, so every copy misses cache. Steps 3 and 4 remove
  those copies. Floats (`zmij`, about 37 cycles each, 200 a response) and string escaping are
  next after that.

### Step 4a: DATA straight from the handler's buffer

When nothing is queued on the stream and the windows take the whole body, `send_data` writes the
DATA frames from the borrowed body straight into the output, without the copy into the stream's
queue. A/B, native, interleaved:

| build | json-h2c 1024 rps | cycles/req | baseline-h2c 256 rps | cycles/req |
|---|---|---|---|---|
| before | 590k, 583k | 62,205, 61,784 | 5,205k | 5,932 |
| direct DATA | 703k, 717k | 48,422, 48,264 | 5,385k | 5,516 |

json-h2c: −22% cycles, +21% throughput. Each body copy costs this much because the buffers are
per connection and cold (see Step 2).

### Step 3: the output buffer handed to io_uring, not copied

`StreamWriter::try_send_owned` lets a stream take a buffer instead of copying it. The uring
reactor, when nothing is in flight, makes the caller's buffer the send and hands back a recycled
one from a per-thread pool (16 buffers of up to 1 MiB, most recent first). Behind a send in flight
it copies, as before. TLS forwards it in plaintext and with kernel TLS. The driver hands over the
core's output whenever it is one run of bytes (always, without shared bodies), and the core writes
its next output into the recycled buffer, which is warm in cache.

| build | json-h2c 1024 rps | cycles/req | baseline-h2c 256 | baseline-h2 256 (kTLS) |
|---|---|---|---|---|
| Step 4a | 715k | 48,560 | 5,333k / 5,430 | 5,003k / 5,527 |
| owned send | 863k | 38,776 | 5,342k / 5,636 | 5,048k / 5,639 |

json-h2c: −20% cycles, +21% throughput. Baseline is unchanged within noise (h2load at 99% CPU).

### Steps 2 (cont.), 4, 6 and 9: fast paths, a warm body buffer, one route lookup, `date` cached

Cumulative builds, interleaved, native (json-h2c two rounds; baseline-h2c one, h2load at 100%):

| build | json-h2c 1024 rps | cycles/req | baseline-h2c 256 rps | cycles/req |
|---|---|---|---|---|
| owned send (Step 3) | 861k, 859k | 38,935, 39,215 | 5,384k | 5,713 |
| + JsonWriter fast paths | 876k, 864k | 37,785, 37,966 | 5,380k | 5,589 |
| + warm response-body buffer | 1,127k, 1,125k | 27,659, 27,878 | 5,272k | 5,954 |
| + one route lookup | 1,156k, 1,149k | 27,246, 27,238 | 5,415k | 5,325 |
| + `date` in the cached header block | 1,160k, 1,151k | 26,864, 26,950 | 5,608k | 4,864 |

- **JsonWriter fast paths.**
  - A float with at most two decimals and below 10^13 is printed from its integer cents. It is
    the double nearest to a decimal of at most 15 significant digits, so that decimal is its
    shortest round-trip form. This was checked against `zmij` on all ±cents up to 20,000.00 and
    on random values.
  - A string of at most 32 bytes with nothing to escape is checked with overlapping 8-byte
    words and copied once.
- **Warm body buffer.** A handler writes its response into the body buffer the last response on
  this thread released, from a per-thread pool (most recent first). Before, it was the stream
  slot's own buffer, cold among 1024 connections. −27% cycles, +29% throughput: the largest
  single item.
- **One route lookup.** The driver looks the path up once, when the headers arrive, and hands
  the match to the auto or manual handler. Before, `is_manual` swapped the message out and back
  and looked the path up, then the auto future looked it up again.
- **`date` in the cached header block.** The block changes once a second; within the second a
  response's header block is one copy plus `content-length`.
