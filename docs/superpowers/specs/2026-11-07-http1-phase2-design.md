# rimu-ws HTTP/1.1 phase 2: async, json-comp, json-tls, 8gbit (design)

**Status:** draft for approval, 7 Nov 2026.
**Builds on:** the h1 MVP (`2026-11-07-http1-driver-design.md`, merged to `main` @ `cf196b25`): the sans-I/O `Http1Conn` core, `Http1ServerFramework` + io_uring driver, parser/body/response. This phase completes the h1 family — the other 4 of 8 scored profiles.
**Author decision captured:** json-comp uses **brotli q2–q3** (new `brotli` dependency; tuned tier allows tuned compression libs).
**Related:** `/mnt/nvme1tb/claude-tmp/httpwin/rules.md` §2.3 (async), §2.5 (json-comp), §2.6 (json-tls), §2.7 (8gbit), §3 (fixed-rate), §4 (json-comp scoring); `rivals.md` (async won by viltrum at 2.84M; json-comp quadratic size term). The h2 arena (`wtx-internal/src/bin/arena-h2.rs`) has the reusable `JsonWriter`, `write_json`, dataset loader, and serde cross-check.

## 1. Intent
Finish the h1 family. Each remaining profile reuses the MVP core + framework, plus two shared additions: **h1-over-TLS** (json-tls, 8gbit) and a **timed-response path** (async). The gate per profile is the HttpArena validator green + a head-to-head vs the rival images on colossus (harness in `/mnt/nvme1tb/claude-tmp/h1bench`).

## 2. Profiles (exact behaviour from the rules)
### async (`/delay/{ms}`, plaintext 8080)
- `GET /delay/{ms}` → wait `ms` ms, then 200, body = the parsed integer, `Content-Type: text/plain`. `/delay/0` answers immediately with `0`. `ms` read from the path every request.
- Benchmark: 32,000 connections held, `/delay/10`, 10 s. Ceiling 32000/10ms = 3.20M rps. viltrum 2.84M (avg 11.2 ms, close to target); plod 1.95M (coarse 1 ms rounding + 1 s cap).
- Rule: **must not answer before the delay elapses**; tuned may use timer wheels/coarse granularity, but accuracy drives the score (answer near the target, never early, never far over).

### json-comp (`/json/{count}?m=N`, plaintext 8080)
- `GET /json/{count}?m=N` with `Accept-Encoding: gzip, br` → body = the dataset JSON (`{"items":[...], "count":count}`, each item's fields unchanged + `total = price*quantity*m`), `Content-Type: application/json`, `Content-Encoding: br` (or `gzip`). Without `Accept-Encoding`: no `Content-Encoding`, plain JSON.
- Compression **per request** (no precompressed/cached bodies, any tier). **brotli q2–q3** (chosen); also honour `gzip` when the client offers only gzip.
- Scored rps × (min_bytes_per_resp / own_bytes)² over conns 4096 and 16384, `-r 25` (connection churn). Response **header bytes count** toward bytes_per_resp — trim headers (no Date/Server; short Content-Type).
- Reuse `JsonWriter` for the JSON; compress the produced buffer.

### json-tls (`/json/{count}?m=N`, TLS 8081, h1)
- Same JSON body over HTTPS on 8081, HTTP/1.1, ALPN selects `http/1.1` or nothing (never anything else), **no** `Accept-Encoding`, no compression. Cert = mounted RSA-2048.
- Reuse `JsonWriter` + the h1-TLS foundation.

### 8gbit (`POST /echo`, TLS 8081, fixed-rate)
- `POST /echo` → 200, body = request body verbatim, `Content-Type: application/octet-stream`, Content-Length framing. Body = 10,240 B constant. Read the body via the framework body API (streaming encouraged); never answer from Content-Length or a canned buffer.
- Fixed-rate score (CPU/req + p99 + mean), full credit at 47,500 rps.

## 3. Shared foundations
### 3.1 h1-over-TLS (json-tls, 8gbit)
Add TLS to `Http1ServerFramework`, mirroring `Http2ServerFramework::new(executor, rng, tls_config)` and the user-space record sealing both h2 and WebSocket already use. ALPN offers `http/1.1`. Plaintext stays the default (`new(executor)`); a TLS constructor (`new_tls(executor, rng, tls_config)` or a `set_tls_config`) adds 8081. The driver's read/write path wraps the stream in the existing user-space TLS stream, exactly as h2 does — no new TLS code, only wiring.

### 3.2 Timed-response path (async)
The MVP framework runs **synchronous** handlers, which cannot block across 32,000 held connections. Add a path where a handler can request a delay without blocking: the handler returns (or sets on the response) a "delay `d`, then this body" intent; the driver's per-connection future — already async on the io_uring executor — `await`s an executor timer for `d` before writing the response. One io_uring timeout per in-flight delayed request (32,000 concurrent timers); wake near the target, never early. No thread blocks. (A timer wheel is a later option only if per-request timeouts measure worse.)

## 4. Goals / non-goals / anti-goals
- **Goals:** the four profiles above pass their HttpArena validators; json-comp emits valid `br`/`gzip` per request; async never answers early and averages near the target; 8gbit echoes byte-exact; json-tls negotiates only `http/1.1`. Each measured vs the rival images on colossus.
- **Non-goals:** h3/QUIC; the reference-only h1 profiles (pipelined, async-db, fortunes, static-tls, latency-500k); kernel TLS (user-space, as h2).
- **Anti-goals:** no precomputed/cached/precompressed response bodies in any tier (json-comp/json-tls validators draw random count/m after startup); no answering 8gbit from Content-Length; no model identifiers (commit trailer only).

## 5. Done means
Per profile: the HttpArena validator passes (async timing checks incl. the 32-concurrent-distinct-delay case; json-comp decode + no-Accept-Encoding-no-encoding + random count/m diffed; json-tls TLS posture + ALPN + JSON diffed; 8gbit random-size byte-exact echo incl. chunked + empty). The full wtx suite + the MVP fragmentation gauntlet stay green. A head-to-head vs plod/viltrum/aegon on colossus recorded for each profile. **Correctness is the gate; a number is reported, not required.**

## 6. HttpArena entry
Extend the local `rimu-ws-h1` entry: add `async`, `json-comp`, `json-tls`, `8gbit` to `meta.json` (experimental, tuned), serve 8081 TLS alongside 8080, mount the dataset + cert. `local-src.sh` as before. **Never push.** The brotli dep is added to the entry's build.

## 7. Review focus (inputs the tests must exercise)
1. async: 32 concurrent requests with distinct delays 100–499 ms, each ≥ 0.9× its own delay and never early; `/delay/0` immediate.
2. json-comp: a client offering only `gzip` gets `gzip`; `br` offered gets `br`; no `Accept-Encoding` gets no `Content-Encoding`; decoded body matches the dataset for random count/m; the `-r 25` connection churn.
3. json-tls: ALPN never selects anything but `http/1.1`; weak TLS refused (reuse h2's posture); JSON correct.
4. 8gbit: 1 B / 1 KiB / 10 KiB / 100 KiB and chunked bodies echoed byte-exact; empty body → 200.
5. The TLS foundation does not regress the plaintext MVP profiles (baseline/limited/latency still green).

## 8. Calls left to the builder
- The exact async handler/response API (a `Http1Res::delay(Duration)` the driver honours, vs an async handler trait) — pick what fits the framework with least churn; pin it in the owning task.
- brotli crate choice + the q2–q3 setting; gzip via the in-tree `zlib-rs`.
- Whether 8081 is a second listener in the same process or the entry runs plaintext+TLS as the h2 entry does (two `run_in_threads`).
