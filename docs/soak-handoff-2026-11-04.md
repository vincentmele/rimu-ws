# rimu-ws soak harness: handoff (2026-11-04)

For an agent continuing this work. Read it all before acting: the constraints section is binding.

## The goal

The user owns **rimu-ws** (`~/src/rimu-ws`), a fork of the wtx Rust networking library. It aims to
be a fast and robust WebSocket server. The user's words for this phase: *"simulate as if this was a
public facing websocket server. Subject to uncontrolled clients. Abuse and unconforming clients.
Hackers trying to hack my program."*

The tool is **rimu-ws-soak** (`~/src/rimu-ws/rimu-ws-soak`), a soak and abuse harness. Its client
speaks raw bytes through its own codec and does not depend on rimu-ws, so a bug the two shared
cannot hide. The job:

1. Expand the harness: long runs, more hostile scenarios, more server configurations,
   compression, and a handshake fuzz target.
2. Use it to find and fix bugs in rimu-ws, test-first.

The user asked for everything on a review list. Four items remain (see "What is left").

## Constraints (binding)

- **Git:**
  - Work on branch `feat/soak-extended` in `~/src/rimu-ws`. It is cut from `perf/ws-write-queue`,
    which equals local `main` (fc8581b4).
  - Remote `rimu` (git@github.com:vincentmele/rimu-ws.git) is the user's fork. **Never push to
    `origin`** (upstream c410-f3r/wtx). Push nowhere unless the user asks.
  - Only commit files you changed. Pre-existing unrelated rustfmt changes sit in `wtx-examples/`,
    `wtx-internal/src/bin/{autobahn*,boringssl*,ccadb,h2spec*,x509-limbo}.rs`,
    `wtx-internal/src/lib.rs`, `wtx-ui/`, `wtx-fuzz/csv.rs`, `wtx/src/tests.rs` and
    `wtx/src/tls/tls_{acceptor,connector}.rs`. Never commit those.
  - Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and name
    no model.
- **The box:** colossus is a trading box with other load.
  - Never run two wtx/soak test processes, servers or benchmarks at once. Check
    `ps -eo pid,cmd | grep -E "soak-server|rimu-ws-soak"` before starting one.
  - Kill by pid, never `pkill -f`.
- **Temp files** go under `/mnt/nvme1tb/claude-tmp`, never `/tmp`. Build with
  `CARGO_TARGET_DIR=/mnt/nvme1tb/claude-tmp/target-rimu`; `.scripts/soak.sh` uses `./target`.
- **No AWS testing.** Never run HttpArena's `system_tune`. Never push the HttpArena entry (local
  branch `add-rimu-ws` in `~/src/HttpArena`).
- **Oracles:** do not loosen a soak oracle (timeouts, slack, budgets) without the user's agreement.
  Tightening the server to meet an oracle is fine.
- **Clippy:** `cargo clippy` on the workspace already fails on pre-existing issues: the
  `clippy.toml` disallowed types (Arc, HashSet, `from_utf8`) in the soak crate, and `len` without
  `is_empty` in wtx. Fix only what your own edit adds.

## How to run things

| What | Command |
|---|---|
| Lib tests | `CARGO_TARGET_DIR=/mnt/nvme1tb/claude-tmp/target-rimu cargo test -q -p rimu-ws --features io-uring,web-socket --lib` (208 pass) |
| Soak crate tests | `CARGO_TARGET_DIR=/mnt/nvme1tb/claude-tmp/target-rimu cargo test -q -p rimu-ws-soak` (66 pass, about 2 min) |
| Soak run | `.scripts/soak.sh --profile hostile --slots 50 --duration 15s --warmup 3s --drain 3s --records failures --out /mnt/nvme1tb/claude-tmp/soak/x.jsonl` |
| Replay one failure | `./target/release/rimu-ws-soak replay SEED:SLOT:GEN --profile <that cycle's profile>` |
| Build a server | `cargo build --release -p rimu-ws-internal --bin soak-server-{uring,tokio} --features soak-server-{uring,tokio}` |

How `soak.sh` runs: it builds `soak-server-uring` and the harness, pins the server to CPUs
0-5,12-17 and the harness to 6-11,18-23. Its modes are `soak` (the default), `fd-plain` and
`fd-direct`. Environment variables pass through to the server.

Server environment variables:

- `WTX_LOOP=plain|drain|queue` (default `queue`)
- `WTX_DEFLATE=1`
- `WTX_SNDBUF=<bytes>`
- `WTX_MAX_PAYLOAD`
- `WTX_HANDSHAKE_MS`, `WTX_IDLE_MS`, `WTX_CLOSE_MS`, `WTX_RX_HIGH_WATER`, `WTX_DIRECT` (uring only)
- `WTX_LOG_ERRORS=1`

## What is done (commits on `feat/soak-extended`)

1. **5cda5844, uring timer precision** (`wtx/src/executor/uring_executor.rs`)
   - The tick is now an eighth of the shortest timeout (was a quarter), and the idle sweep runs
     every sixteenth of the idle timeout (was a quarter).
   - Cause found: handshake deadlines fired up to 1.25x late and idle closes up to two sweeps
     late. That was behind the 19 idle-timeout flakes (0.02%) in earlier soaks.
   - Tests `handshake_timeout_fires_within_an_eighth_of_its_length` and
     `idle_timeout_fires_within_an_eighth_of_its_length`: watched failing on the old timing
     (1.25 s, 960 ms), then passing.
2. **ab0e5967, long runs** (`rimu-ws-soak/src/cycle.rs`, `burst.rs`, `probe.rs`, `monitor.rs`,
   `main.rs`; tests in `tests/extended.rs`). New flags:
   - `--records failures`
   - `--heartbeat 60s` (stderr plus `heartbeat` JSON lines)
   - whole-run probe p50/p99/p99.9/max in the summary
   - `--profile a,b,c` rotates profiles by cycle
   - `--trend N`: drained RSS or peak RSS rising N cycles in a row, by more than 8 MiB and 2%
   - `--rss-ceiling MiB`: kills the server with SIGKILL and ends the run
   - `--max-time`, `--stop-on-first`
   - `--burst N`: N connections at once after each cycle; each must upgrade and echo within 5 s
3. **1e0514f3, attack and resource scenarios** (`src/scenario/attack.rs`, `resource.rs`; tests in
   `tests/attack.rs`; the fake server in `tests/support/mod.rs` is now strict about upgrades and
   caps the header at 16 KiB)
   - `bad_upgrade`: 15 cases in `attack::UpgradeCase`.
     - 7 must be refused: NoKey, ShortKey, BadVersion, Post, Http10, NoUpgrade, NoConnection.
     - 7 may be refused or upgraded, but must be answered within 1 s.
     - Pipelined must upgrade and echo the frame sent behind the request.
   - `header_flood`: an endless last header at about 3 MB/s, which must be refused before 1 MiB.
   - `frag_flood` (10k-40k one-byte fragments) and `zero_flood` (10k-30k empty messages).
   - `frag_drip`: a message up to `max_payload` trickled in 16 KiB fragments; a quarter of runs go
     one byte over and expect close 1009. The RSS budget allows 3 x `max_payload` per one in
     flight (`scenario::LARGE_INFLIGHT`).
   - `close_linger`: needs `--server-sndbuf` of at most 32 KiB, otherwise it is filtered out by
     `Weights::for_limits`. A reply nobody reads after the close must be dropped within the close
     timeout.
   - `ping_no_read` and `slow_reader`.
   - New profiles: `attack`, `untimed` (no server timeouts needed; for tokio) and `drip`.
4. **81c0bcac, servers** (`wtx-internal/src/bin/common/soak_echo.rs`, `soak-server-uring.rs`, new
   `soak-server-tokio.rs`)
   - Shared echo loops chosen by `WTX_LOOP`.
   - `WTX_DEFLATE`, using zlib-rs.
   - `WTX_SNDBUF`, through `TcpParams::set_send_buffer_size` on the listener.
   - Both servers build. Only uring with `WTX_LOOP=plain` and no compression has been run (the
     smoke test below).

### Findings from the first smoke run (uring, plain loop, hostile, 50 slots, 15 s)

Output: `/mnt/nvme1tb/claude-tmp/soak/smoke-plain.jsonl`. All 53 fails are real rimu-ws bugs; every
other scenario passed.

- **F-A, security: unbounded upgrade request (27 of 27 `header_flood` runs failed).**
  - In `wtx/src/web_socket/handshake.rs`, `WebSocketAcceptor::accept` loops `read_arbitrary(1024)`
    and re-runs `httparse` over the whole buffer on every partial read. Nothing caps the request
    below the `BufStreamReader` limit of 32 MiB.
  - Memory: up to 32 MiB per connection.
  - CPU: quadratic re-parsing, the bug class of tungstenite's CVE-2023-43669.
  - On uring only the handshake timeout ends it; tokio has none.
  - The RSS violations in the smoke run came with these runs.
  - Fix: cap the request at about 16 KiB and answer `431` or `400`, then close. The client side
    (`connect`, line ~161) has the same loop; cap the response too.
- **F-B, conformance and security: upgrades it must refuse** (`check_req_headers`,
  `handshake.rs:102`).
  - It checks only Sec-WebSocket-Key, Sec-WebSocket-Version and Extensions, so it upgrades:
    - a key that does not decode to 16 bytes (ShortKey, 9 fails);
    - no `Upgrade: websocket` (8 fails);
    - no `Connection: Upgrade` (5 fails);
    - HTTP/1.0 (4 fails).
  - RFC 6455 4.2.1 requires the method to be GET (already checked), HTTP/1.1 or later, Host,
    Upgrade containing `websocket` and Connection containing `Upgrade` (case-insensitive tokens),
    a key that base64-decodes to 16 bytes, and version 13. A 400 is the answer; for a wrong
    version, it should carry `Sec-WebSocket-Version: 13` (RFC 4.4).
  - Missing Upgrade/Connection matters for cross-protocol attacks. The fake server's
    `upgrade_key` in `tests/support/mod.rs` is a reference implementation.
- **F-C, robustness, not yet tested: `MAX_HEADERS = 16`** (`handshake.rs:36`).
  - Browsers send about 13 headers on an upgrade, and proxies or CDNs (Cloudflare, nginx) add
    X-Forwarded-For, CF-*, Via and similar. More than 16 makes `httparse` fail with
    TooManyHeaders, and the connection drops with no answer.
  - `bad_upgrade::ManyHeaders` (100 headers) passes today only because "no answer, closed" counts
    as refusal for that case.
  - Suggest raising to 64 (it is a stack array of `EMPTY_HEADER`) and answering 431 when exceeded.

## What is left (in order)

1. **Fix F-A and F-B in rimu-ws, test-first.**
   - Add unit tests next to `wtx/src/web_socket/handshake/tests.rs`: an endless header is refused
     at the cap without growing past it, and each must-refuse case gets a 400. Watch them fail,
     then fix.
   - Re-run the smoke soak with `--profile attack`: `bad_upgrade` and `header_flood` must pass.
   - Consider F-C at the same time.
2. **`soak.sh` updates** (planned, not done):
   - Set `MALLOC_MMAP_THRESHOLD_=262144` for the server by default (`SOAK_MALLOC=0` to skip).
     Without it, glibc keeps about 700 MB the server has freed after a hostile cycle, and the
     drain leak check (10% + 16 MiB) reports a leak that isn't one. This was established in the
     previous session.
   - A `SOAK_SERVER=uring|tokio` switch, picking `--profile untimed` for tokio.
   - A `SOAK_SNDBUF` pass-through that also adds `--server-sndbuf`.
   - A `long` mode preset, for example `--profile hostile,attack,storm --cycles 1000
     --duration 20m --max-time ${SOAK_HOURS:-6}h --records failures --heartbeat 60s --trend 4
     --rss-ceiling 4096 --burst 2000`, with `WTX_SNDBUF=16384 --server-sndbuf 16384` so
     `close_linger` runs.
   - Document all of this in `rimu-ws-soak/README.md`. The README does not yet describe any of
     commits 2-4: new flags, scenarios, profiles, servers or environment variables.
3. **Run the matrix**, short runs first and one at a time:
   - uring with `WTX_LOOP` plain, drain and queue, each under hostile and attack;
   - tokio under untimed;
   - drip;
   - close_linger with a send buffer.
   Triage every fail: a rimu-ws bug gets a failing unit test, then a fix; an oracle problem goes to
   the user.
4. **Compression (permessage-deflate).** Nothing is done in the harness. Plan:
   - Add `flate2` (rust backend, miniz_oxide) to `rimu-ws-soak` only, which keeps it independent of
     zlib-rs.
   - Add `--deflate` (sets `Limits.deflate`; `Weights::for_limits` drops deflate scenarios
     without it). The upgrade sends `Sec-WebSocket-Extensions: permessage-deflate;
     client_no_context_takeover; server_no_context_takeover`, so each message stands alone.
   - Teach the codec RSV1 plus raw deflate with the trailing `00 00 ff ff` stripped, and inflate
     RSV1 server messages in `Oracle`.
   - Scenarios:
     - `deflate_echo`;
     - `deflate_bomb`: a small frame inflating past `max_payload`, which must close 1009 with no
       RSS jump;
     - `deflate_corrupt`: an invalid deflate stream. Check what close code rimu-ws sends:
       `web_socket/misc.rs::read_error_close_code` maps unknown errors to `None`, so probably no
       close frame. Expect 1007 or 1002, and add the mapping if missing;
     - `deflate_drip`: a compressed message trickled byte by byte;
     - RSV1 on a control frame or a continuation, which must close 1002.
   - Add a `deflate` profile and the fake-server support.
5. **Handshake fuzz target** in `wtx-fuzz`: none exists (`ls wtx-fuzz/*.rs`). Model it on
   tungstenite's and yawc's targets.
   - Fuzzer bytes are the client, fed through an in-memory stream in chunk sizes the input chooses.
   - The oracle is `WebSocketAcceptor::accept`: it returns 101 (with a correct
     Sec-WebSocket-Accept), 400, or an error, never panics or hangs.
   - Run under `-timeout=2 -rss_limit_mb=512`. With F-A fixed, the timeout guards against the
     quadratic re-parse coming back.
   - Also run the existing `web_socket_differential` target with `-malloc_limit_mb=64`.
6. **Report** to the user what was found and fixed; update the memory file
   `~/.claude/projects/-home-vince-xvenue-recorder/memory/wtx-fork-httparena-2026-11-03.md`.

## Recommendations from an independent review (2026-11-04), checked against the code

A review session verified this document against the repository and the smoke-run evidence. Its
recommendations, corrected where the code says otherwise, amend the plan above:

1. **Fix F-A, F-B and F-C together, then build the handshake fuzz target (item 5) straight
   away, not last.** The request cap gives the fuzzer its oracle ("101, 400 or an error; never a
   panic or a hang; bounded bytes"), and the fuzzer keeps the cap from regressing.
2. **F-A is a vulnerability in the default configuration.**
   - `UringParams::new()` has `handshake_timeout: None` (`uring_executor.rs:138`); the smoke
     server sets one only through `WTX_HANDSHAKE_MS`.
   - The only other backstop is the reader's general 32 MiB `capacity_ub`
     (`BufStreamReader::manage_capacity`), which errors past it. So it is bounded per connection,
     but at 32 MiB, with quadratic re-parsing, and unbounded across connections.
   - Fix: a small request cap (~16 KiB) that is always on.
3. **Fix F-B as the full RFC 6455 4.2.1 gate**, not just the four cases the smoke run failed:
   - `Upgrade` containing `websocket` and `Connection` containing `Upgrade` (case-insensitive
     tokens);
   - `Host`;
   - HTTP/1.1 or later;
   - a key that decodes to 16 bytes;
   - version 13. The 400 for a wrong version carries `Sec-WebSocket-Version: 13`.
4. **In the matrix (item 3), run `WTX_LOOP=queue` under `attack` first.** `queue` is the loop
   that ships and the one HttpArena uses; the smoke run tested `plain` only.
5. **The test counts were executed, not just counted:**
   - lib 208/208, after the timer commit; later commits did not touch the lib;
   - soak 66/66, after the last soak-crate change.

   Re-run both as a baseline anyway before changing anything.
6. **README:** `--records failures` writes only failing (and harness-error) runs to the output
   file, while `summary.records` counts every run.
7. **Compression (item 4): two separate defenses.**
   - **Bombs:** the decompressed size is bounded by `max_payload_len`, which every `decompress`
     call already receives (`read_frame.rs:518-553`). `deflate_bomb` must show that going over
     it closes with 1009, with no truncated message and no memory jump.
   - **Per-connection deflate memory:** every client can make the server allocate a compressor
     and a decompressor (zlib defaults are roughly 256 KiB a connection). Bound it by capping
     `server_max_window_bits` and the memory level. It is worth a test of its own: RSS per
     connection with compression negotiated.

## Where further work could go

- **TLS (`wss://`).** Public servers usually terminate TLS. Malformed ClientHellos, slow TLS
  handshakes (TLS-level slowloris), renegotiation and early-data abuse belong to rimu-ws's TLS
  path, which the soak never touches. The harness would need a TLS client (rustls), and the
  server a cert.
- **Many-address scale.** `--source-ips 127.0.0.2-127.0.0.50` gets past 28k connections per
  source port range, but no run above 2000 slots has been done; try 50k–100k mostly-idle
  connections.
- **Real-network faults.** Toxiproxy between harness and server (latency, `slicer`, `reset_peer`,
  `limit_data`), or `tc netem` (needs root; ask the user).
- **Subprotocols and Origin.** `Sec-WebSocket-Protocol` negotiation, and whether the framework lets
  an application check `Origin` (CSWSH protection), are untested.
- **Per-IP limits.** Nothing stops one address from opening thousands of connections; a public
  deployment needs a per-IP connection cap and rate limits. That is a feature decision for the
  user, which the harness can then test with `--source-ips`.
- **Fault-injecting io_uring backend.** CQE results (ENOBUFS, ECANCELED, short sends) chosen by
  fuzz input, like uWebSockets' libEpollFuzzer on OSS-Fuzz.
- **Long soaks.** Six hours or more with the `long` preset once the bugs above are fixed. Watch
  `--trend` and the heartbeat p99.9.
- **Known open item from before:** small-message latency stalls behind large echoes on the same
  thread ("F3"), measured but not fixed.
