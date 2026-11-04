# rimu-ws-soak design: prior art and harness (2026-11-04)

Research by a subagent; public repos shallow-cloned under `repos/` next to this file.

## What rimu-ws already has

- `wtx-fuzz/web_socket_differential.rs` -> `wtx/src/web_socket/differential.rs`: server read/echo
  loops (Plain, Drain, Queue) over chunked input, checked against an independent RFC 6455 model,
  plus a seeded generator. Better than anything the other Rust libraries ship.
- Gap: nothing fuzzes the handshake (`wtx/src/web_socket/handshake.rs`). `wtx-fuzz/web_socket.rs`
  is shallow.
- Executor stress tests in `uring_executor.rs` (seeded scripts: normal, slow reader, reset, flood,
  byte-exact echo, leak check) and, as of the robustness commit, tests for never-read peers,
  idle/handshake/close timeouts, a full direct-descriptor table and runtime drop.
- `~/src/httparena-wtx/wsload` (mio, 184 lines): well-behaved load only.

## Other Rust WebSocket libraries

None has a soak, load or chaos harness. Worth copying:

- tungstenite `fuzz/`: frame-header target, full read targets for client and server, 828
  minimised seeds (raw frame bytes, reusable as corpus). CI diffs Autobahn output against
  `expected-results.json`. CVE-2023-43669 (handshake re-parse, minutes of CPU) is the bug class a
  split-input handshake target with `-timeout` catches.
- fastwebsockets `fuzz/`: a stream that yields the input then returns Pending forever.
- yawc `fuzz/websocket_read.rs`: full handshake + frames over `tokio::io::duplex`; found an inflate
  hang. Template for a rimu-ws handshake target (fuzzer is the client).
- sockudo-ws: 4 fuzz targets (incl. UTF-8 differential vs std, `arbitrary` round trip), ~75
  edge-case test files (pong coalescing under backpressure, deadlines with paused time,
  partial frames across Pending), and a native Rust Autobahn port with `--concurrency`.
- soketto (small quickcheck), ratchet (duplex fixtures, 4 Autobahn binaries), axum
  (`handle_accept_error` sleeps on EMFILE), rust-websocket (RUSTSEC-2022-0035: allocation from
  the declared length).
- uWebSockets on OSS-Fuzz fuzzes whole servers through libEpollFuzzer (mocked syscalls). The
  rimu-ws analogue: a fault-injecting io_uring backend.

## External tools

| Tool | Many conns | Hostile behaviour | Notes |
|---|---|---|---|
| Autobahn | no | protocol violations | conformance gate only |
| sockudo autobahn-testsuite-rs | `--concurrency` | as Autobahn | could replace Docker Autobahn |
| k6, Artillery | yes | no | good reports, protocol-correct only |
| Gatling | tens of thousands per JVM (est.) | idle only | see below |
| tcpkali | 100k+ | rates, lifetimes, raw bytes | no never-read, no mid-frame RST |
| Toxiproxy | proxy | `slicer` splits, `reset_peer`, `limit_data` cut, latency | no code, under any load tool |
| slowhttptest | 1000+ | slowloris, slow read | add Upgrade headers |
| wsfuzz, boofuzz, radamsa | low | malformed frames | weaker than cargo-fuzz |

### Gatling

Good for realistic scripted soaks: `ws(..).connect/sendText/sendBytes/await(..).on(checks)`,
injection profiles for hours, HTML reports, CI assertions on percentiles. Built on Netty's client:
always masks, always reads, auto-pongs, whole messages only. It cannot send malformed or
fragmented frames, be a never-read client, do a slow handshake, RST mid-frame or split at chosen
bytes; idle clients after the upgrade are possible. Timings are in milliseconds (rimu-ws echoes in
~10 us). Throughput per box far below gcannon (estimate, not measured). Fit: the "realistic user"
lane, optionally behind Toxiproxy; not abuse or fuzzing.

## Recommended design: `rimu-ws-soak`

- Separate binary crate, no dependency on rimu-ws (independent client so shared bugs don't hide):
  tokio + socket2, its own ~300-line raw codec (any FIN/RSV/opcode/length encoding, masking,
  close-code parsing), hdrhistogram, JSONL output.
- Each client slot loops: pick a weighted scenario, run it to its oracle, reconnect (churn).
  Seed = splitmix(global, slot, generation); every failure prints `--replay SEED:SLOT:GEN` and a
  byte transcript.
- Scenarios and oracles:
  - `echo` probe at a fixed rate (avoids coordinated omission): byte-identical, in order, latency
    into the histogram.
  - `never_read` (small SO_RCVBUF, keeps sending): server RSS per conn bounded, server stops
    reading (client sees a zero window), probes unaffected.
  - `slowloris` (upgrade 1 byte every k ms): closed within the handshake timeout, no CPU spike.
  - `idle_pre` / `idle_post`: closed within the idle timeout.
  - `close_in_handshake`, `rst_midframe` (SO_LINGER 0), `half_close`: fd released, no CLOSE_WAIT.
  - `split_every_byte`: identical echo.
  - `invalid_*` (bad UTF-8 -> 1007; reserved opcode, RSV, unmasked, fragmented control,
    control > 125 bytes, bad close code, stray continuation -> 1002; oversized -> 1009): that
    close code, then TCP close.
  - `ctrl_in_fragments`, `huge_len` (2^63-1 etc.: no RSS jump), `ping_flood` (pongs bounded),
    `garbage`.
  - `fd_flood` phase under `prlimit --nofile`: no busy spin, accepts again after release.
- Monitor at 1 Hz on `--pid`: VmRSS/VmHWM, fd count, CPU from /proc/pid/stat, `ss` state counts
  (CLOSE_WAIT) and Recv-Q/Send-Q, io_uring fdinfo CQ overflow. Invariants: pid alive; fds and RSS
  back to baseline after drain; probe p99 within F x baseline; zero verification failures; a fresh
  connection accepted after each storm. Exit non-zero on violation.
- Phases: warmup -> hostile mix -> fd storm -> recovery -> drain -> leak check, repeated.
  Above ~28k conns bind several 127.0.0.x source addresses.

## In-process tests

1. `web_socket_handshake` fuzz target (new, highest value): fuzzer bytes as the client, split by
   input-chosen chunk sizes; oracle 101/400/error with a correct Sec-WebSocket-Accept. `-timeout=2`.
2. Run `web_socket_differential` with `-malloc_limit_mb=64 -rss_limit_mb=512`; seed from
   tungstenite's seeds and Autobahn payloads.
3. `utf8_incremental` differential vs std across splits; `mask` SIMD vs scalar.
4. proptest over a duplex stream with Pending reads and back-pressured writes (shrinking), plus an
   exhaustive 1- and 2-cut split test for small inputs.
5. Later: fault-injecting io_uring backend (CQE results chosen by fuzz input).

## Build order

1. Handshake fuzz target; limits on the differential target; tungstenite seeds.
2. Soak MVP: probes, never_read, slowloris, idle, rst_midframe, half_close + monitor.
3. invalid_*, huge_len, ctrl_in_fragments, ping_flood.
4. fd_flood phase.
5. proptest duplex + exhaustive splits.
6. sockudo's Autobahn port + expected-results diff.
7. Optional: k6/Gatling soak through Toxiproxy; slowhttptest.
