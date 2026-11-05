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

## Progress on 2026-11-05

**Fixed and committed** (lib 217/217; 219/219 with zlib-rs, framework and ring):

- **164d445b, handshake:**
  - F-A: a 16 KiB request cap, answered with 431, and re-parsing only once a blank line can have
    arrived (linear, not quadratic).
  - F-B: the full RFC 6455 4.2.1 gate, with a 400 naming version 13 when the version is wrong.
  - F-C: 64 headers; too many get a 431.
  - Two more bugs:
    - **A request or response split across reads was never parsed** (upstream wtx has it too).
      `read_arbitrary` reads went to `current`, which the next read cleared, so any upgrade head
      bigger than one TCP segment failed on a real network. Reads now go to `following`.
    - **The client accepted any 101.** The Sec-WebSocket-Accept, Upgrade and Connection checks
      were computed and dropped with `drop(...)`. It now fails as RFC 6455 4.1 says.
- **de4b8234, framework:** the route is matched on the path without its query, and before the
  101. Before, a `?query` or a path over 255 bytes got a 101 and was then dropped. A path with no
  route gets a 400.
- **d2667dc5, fuzz target:** `wtx-fuzz/web_socket_handshake.rs`; the oracle is
  `web_socket::handshake_check`, shared with the tests. 3.3M runs in 3 minutes found nothing.
  Run it with `cargo +nightly-2026-10-12 fuzz run --fuzz-dir wtx-fuzz web_socket_handshake --
  -timeout=2 -rss_limit_mb=512`.
- **soak-server-tokio** had no crypto backend, so the upgrade panicked; fixed.

**Soak results** (100 slots, 30 s, `MALLOC_MMAP_THRESHOLD_=262144`, `--rss-ceiling 2048`):

| Server | Profile | Runs | Fails | Violations | Probe p50/p99/p99.9 |
|---|---|---|---|---|---|
| rimu-ws uring, queue loop | attack | 7,977 | 0 | drain check (see below), 2 latency seconds | 41/859/5635 us |
| rimu-ws tokio, queue loop | untimed | 24,247 | 0 | none | 40/298/1150 us |
| tokio-tungstenite 0.30, defaults | untimed | died | | RSS climbed about 4 GB/s to 23 GB on `ping_no_read`, then the process was gone | |
| tokio-tungstenite, defaults, without `ping_no_read` | untimed | 27,829 | 3,475 | latency | 43/371/2049 us |
| tokio-tungstenite, `max_write_buffer_size` 1 MiB | untimed | 9,786 | 1,375 | latency | 2025/10487/16343 us |

The tokio-tungstenite echo server is in `/mnt/nvme1tb/claude-tmp/tt-echo` (not in the repo); the
runner is `/mnt/nvme1tb/claude-tmp/soak/run-other.sh`. **Always pass `--rss-ceiling` against
other servers:** colossus is a trading box, and the default tokio-tungstenite took 23 GB.

tokio-tungstenite findings:

- With the default `max_write_buffer_size` (unbounded), pongs to a peer that never reads are
  queued without bound.
- It closes TCP without a close frame on protocol errors, oversized lengths, bad UTF-8 and an
  over-limit fragmented message. That is the RFC 6455 7.1.7 gap rimu-ws closed in F2.
- It refuses frames pipelined behind the upgrade request.

**Questions for the user, about oracles (do not change these without them):**

1. `bad_upgrade::Pipelined` requires an upgrade. RFC 6455 4.1 says a client must wait for the 101
   before sending frames, so a refusal is allowed too. Suggestion: accept a refusal, or an
   upgrade followed by the echo.
2. `ping_no_read` requires a send to block. A server may answer only the most recent ping (RFC
   6455 5.5.3) and keep reading without growing, as hardened tokio-tungstenite does. Suggestion:
   judge it by memory (the monitor) plus a pong check, not by blocking.
3. The drain leak check compares against the warmup's RSS. On uring the receive buffers (about
   2 MiB per thread) are only touched under load, so after an attack cycle the drained RSS is
   about 32 MB over the warmup without being a leak. Confirm it stays flat across several cycles
   (`--cycles 3`); if so, take the baseline after the first cycle's drain and rely on `--trend`.

**Still to do:**

- item 2 (`soak.sh` modes: malloc setting, `SOAK_SERVER`, `SOAK_SNDBUF`, the `long` preset;
  README);
- the rest of the matrix (plain and drain loops, the drip profile, `close_linger` with a send
  buffer, deflate);
- item 4 (compression);
- the open questions above.

## Other Rust WebSocket servers under the soak (2026-11-05)

**Setup:**

- Echo servers live in `/mnt/nvme1tb/claude-tmp/{tt-echo,sk-echo,fw-echo}` (not in the repo):
  - tokio-tungstenite 0.30;
  - sockudo-ws 3.1.0 at commit 35933d7, through `WebSocketServer::accept`, with `idle_timeout`
    5 s;
  - fastwebsockets 0.10.0, as its own `echo_server` example (hyper upgrade,
    `FragmentCollector`), on a multi-thread runtime.
- All have 1 MiB message and frame limits.
- Runner: `/mnt/nvme1tb/claude-tmp/soak/run-other.sh BIN NAME ARGS` (same CPU pinning as
  `soak.sh`).
- Runs: 100 slots, 30 s, `--rss-ceiling 2048`, `MALLOC_MMAP_THRESHOLD_=262144`. Single 30 s runs
  on a shared box, so the latencies are indicative.

**Profile `untimed`** (the fair comparison: no server timeouts needed):

| Server | Runs | Fails | Probe p50/p99/p99.9 (idle p50/p99) |
|---|---|---|---|
| rimu-ws, tokio, queue loop | 24,247 | **0** | 40/298/1150 us (36/65) |
| tokio-tungstenite, defaults | died | | RSS climbed about 4 GB/s to 23 GB on `ping_no_read`, then the process was gone |
| tokio-tungstenite, defaults, without `ping_no_read` | 27,829 | 3,475 | 43/371/2049 us (39/63) |
| tokio-tungstenite, `max_write_buffer_size` 1 MiB | 9,786 | 1,375 | 2025/10487/16343 us |
| sockudo-ws | 14,594 | 2,657 | 2153/16767/24175 us (35/54) |
| fastwebsockets | 20,902 | 2,786 | 43/719/2517 us (37/109) |

**Profile `attack`** (a public server under attack; tokio-tungstenite with the 1 MiB write
buffer):

| Server | Runs | Fails | Notes |
|---|---|---|---|
| rimu-ws, uring, queue loop | 7,977 | **0** | drain-baseline violation (question 3 above) |
| sockudo-ws | 4,191 | 1,364 | slowloris 376, `ping_no_read` about 80, protocol errors |
| fastwebsockets | 6,455 | 2,212 | slowloris 528, upgrades it must refuse 361, protocol errors |
| tokio-tungstenite | 3,085 | 1,104 | slowloris 294, `ping_no_read` about 130, protocol errors |

**What the others get wrong** (rimu-ws passes every item):

- **No close frame on protocol errors (all three).** Every invalid-frame case, oversized lengths,
  bad UTF-8 and an over-limit fragmented message end in a bare TCP close, not the close code RFC
  6455 7.1.7 asks for. The exception is fastwebsockets, which sends 1002 for a bad close code.
- **Slowloris (all three).** None has a handshake deadline: an upgrade request trickled a byte
  every 100 ms holds a connection indefinitely.
- **tokio-tungstenite:**
  - With the default config, pongs to a peer that never reads are queued without bound (23 GB).
  - With a write-buffer limit it stays bounded, but keeps reading pings without pushing back.
  - It refuses frames sent right behind the upgrade request (RFC 6455 4.1 allows that; see
    question 1 above).
- **sockudo-ws:**
  - Keeps reading pings without pushing back (memory stayed bounded).
  - Sometimes sends a pong after the echo of the message the ping was in the middle of (about
    20 of some 700 `ctrl_in_fragments` runs).
  - Latency degrades sharply under load: p50 2.1 ms against about 40 us for the others, and the
    fewest runs per 30 s.
- **fastwebsockets:**
  - **Accepts unmasked client frames** and echoes them; RFC 6455 5.1 says the server must close.
  - Its example upgrade (`upgrade::upgrade` without `is_upgrade_request`) upgrades POST, a short
    key, and requests with no Upgrade or no Connection header.
  - An HTTP/1.0 upgrade gets no answer.
  - Pushes back on `ping_no_read` (it awaits each pong write) and stays bounded.
- **All three cap the upgrade header** (`header_flood` passes).

## Memory after drains: what it was, and the fix (2026-11-05)

**The extended run** (`soak.sh long`, 1000 slots, 10-minute cycles rotating hostile, attack and
storm, a 2000-connection burst per cycle):

- 13,257,490 runs over 1 h 59 m: 0 fails and 0 harness errors. The run was killed by the
  2-hour cap on background jobs, so it wrote no summary; next time detach it from the session.
- RSS after the drain climbed from 198 MB to 301 MB.

**Allocation snapshots** (`/mnt/nvme1tb/claude-tmp/allocshim`, 37-minute runs of the same mix,
data in `/mnt/nvme1tb/claude-tmp/soak/alloc-run*`) showed it was not a leak, but two kinds of
retention:

1. **Per-slot buffers:** each reused slot kept up to three buffers of 64 KiB, so after a burst
   memory followed the most connections ever open. Live heap after a drain was 54–121 MB.
2. **glibc keeping freed memory:** RSS was about 2.6 times the live heap.

**Fix, 0c899291:** only `max(open connections, 64)` free slots keep buffers; the rest are
stripped, oldest first. Test: `a_closed_burst_leaves_few_slots_with_buffers`. Same benchmark,
glibc:

| | Before | After |
|---|---|---|
| Live heap after a drain | 54–121 MB | 29–33 MB (flat) |
| Live heap when idle at the end | 121 MB | 37 MB |
| RSS after a drain | 256 → 316 MB | about 268 MB (flat; no trend violation) |
| Runs / fails | 3,671,421 / 0 | 3,665,570 / 0 |

- The remaining ~235 MB of RSS is glibc's own retention.
- jemalloc (`LD_PRELOAD`, `background_thread:true`) cut drained RSS to 86–162 MB before the fix,
  but raised the peaks under load 20–45% and its tail latency was worse. The user chose glibc.
- The typical per-second p99 is unchanged by the fix (cycles 0–3 within 3%). The after run's
  tail was worse in cycles 4–5, where harness lag rose with box load (load average 25 at the
  end), so it is not attributed to the fix. Re-run on a quiet box to confirm.
- Throughput (HttpArena A/B) has not been re-measured since the fix.

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
