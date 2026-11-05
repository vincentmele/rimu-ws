# Soak tier 1: checking the common rules on the Rust servers (2026-11-05)

This is Task 6 of `docs/superpowers/plans/2026-11-05-soak-tier1.md`: the common rules (rules
version 1, `rimu-ws-soak/RULES.md`), run against the five Rust servers before the Docker work for the
other ten. Each server was set up as in its `competitors/<name>/CONFIG.md` and run through
`.scripts/competitor.sh run NAME -- --mode common --profile common --slots 100 --duration 60s
--cycles 2 --warmup 10s --drain 10s --records failures`.

Run output: `/mnt/nvme1tb/claude-tmp/soak/tier1-check/`.

| Server | Runs | MUST | SHOULD | Survival violations | Probe p50 / p99 / p99.9 |
|---|---|---|---|---|---|
| rimu-ws | 18,166 | 0 | 0 | **RSS 1, latency 6** | 38 / 541 / 1,727 µs |
| rimu-ws, rerun | 18,182 | 0 | 0 | **RSS 1, latency 3** | 40 / 509 / 1,679 µs |
| tokio-tungstenite | 17,724 | 0 | 1,399 | latency 123 | 1,093 / 5,431 / 7,203 µs |
| sockudo-ws | 11,979 | 537 | 1,039 | latency 123 | 1,056 / 11,895 / 16,591 µs |
| fastwebsockets | 18,187 | 268 | 1,245 | none | 38 / 224 / 677 µs |
| wtx (original) | 48,624 | 875 | 3,686 | RSS 18, latency 32 | 45 / 979 / 1,760 µs |

## rimu-ws

- **No failed scenario in either run.**
- **It fails survival, reproducibly, at the start of each cycle's load.** All 100 clients begin at
  once, and in that first second:
  - RSS reached 159 MB, then 171 MB on the rerun, against a limit of about 125 MB (cycle 0 only);
  - probe p99 reached 8.9 ms and 2.9 ms, then 6.0 ms and 4.1 ms on the rerun.
- **After the first second** RSS settles at 50–90 MB, and p99 at 0.1–1 ms with a few readings of
  1.1–1.2 ms.
- **The harness wasn't saturated:** its lag p99 stayed at about 950 µs, under the 1 ms cut-off.
- **fastwebsockets, on tokio under the same load, had no survival violation at all.** So these are
  rimu-ws findings, not rules too strict to meet. The same latency spikes were noted in strict-mode
  soaks of `main` on 5 Nov.
- **Not yet known:** whether the cause is the plain echo loop of the documented example (rimu-ws's
  own soak server uses the queue loop), or io_uring buffers being touched for the first time.

## tokio-tungstenite

- **SHOULD, 1,399:**
  - every protocol error ends in a bare TCP close with no close frame (1,357);
  - a frame pipelined behind the upgrade is refused (42).
- **MUST:** none.
- **Survival:** latency, with p99 of 2–8 ms through the run.
- Its slowloris and never-read runs no longer fail: the common rules judge those by survival, and
  its memory stayed within budget with the write-buffer limit set.

## sockudo-ws

- **MUST, 537:** in every `ctrl_in_fragments` run, the ping inside a fragmented message gets no pong
  at all. The transcript shows the echo and the close, and nothing else. RFC 6455 5.5.2 requires a
  pong for a ping received before the close. (On 5 Nov, with an idle timeout of 5 s, about 20 of
  some 700 runs showed the pong arriving late instead.)
- **SHOULD, 1,039:** bare TCP closes on protocol errors.
- **Survival:** latency, with p99 of 5–17 ms through the run.

## fastwebsockets

- **MUST, 268:**
  - it accepts unmasked client frames (160; RFC 6455 5.1);
  - it upgrades requests RFC 6455 4.2.1 says to refuse, such as POST (108). `is_upgrade_request`
    only checks the Upgrade and Connection headers.
- **SHOULD, 1,245:** bare TCP closes on protocol errors.
- **Survival:** clean, with the lowest latency of the five.

## wtx (original)

- **MUST, 875:**
  - it accepts RSV1 without an extension (386);
  - it upgrades a short key, a missing Upgrade or Connection header, and HTTP/1.0 (489).
- **SHOULD, 3,686:** bare TCP closes on protocol errors.
- **Survival:** RSS 18 times, latency 32 times.
- Every one of these MUST failures is a bug rimu-ws fixed after the fork.

## What this says about the rules

- **Every kind of check failed at least one server:** MUST, SHOULD, RSS and latency.
- **The rule changes behaved as intended.** The four version 1 changes are the never-read and
  ping-no-read rules, the pipelined frame, the late pong and the drain baseline. They removed
  failures that were artefacts, such as slowloris on servers with no handshake timeout, and kept
  the real ones.
- **No rule was loosened for rimu-ws:** it fails survival under the same rules as everyone.
