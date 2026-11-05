# rimu-ws-soak

A soak and abuse harness for WebSocket servers. Thousands of simulated clients mix echo traffic
that is checked byte for byte with hostile behaviour. A monitor watches the server from outside and
fails the run if the server answers wrongly or stops being bounded.

It speaks raw bytes through its own codec and does not depend on rimu-ws, so its clients can
misbehave freely, and a bug the two shared could not hide.

## Running it

`.scripts/soak.sh` builds `soak-server-uring` (from `wtx-internal`) and the harness. It starts the
server on CPUs 0-5,12-17 and runs the harness on 6-11,18-23:

```sh
.scripts/soak.sh --profile hostile --slots 2000 --duration 600s --cycles 3
.scripts/soak.sh fd-plain     # descriptor flood, ordinary descriptors, nofile 1024
.scripts/soak.sh fd-direct    # descriptor flood, 256-slot direct descriptor table per thread
```

Against another server: `rimu-ws-soak run --url ws://HOST:PORT/PATH --pid PID ...`. Without
`--pid`, the server is not monitored.

The server's limits must match the harness's `--handshake-timeout`, `--idle-timeout`,
`--close-timeout` and `--max-payload`, which default to `soak-server-uring`'s defaults: 2 s, 5 s,
2 s and 1 MiB. The server reads its limits from `WTX_HANDSHAKE_MS`, `WTX_IDLE_MS`, `WTX_CLOSE_MS`,
`WTX_RX_HIGH_WATER`, `WTX_DIRECT` and `WTX_MAX_PAYLOAD`.

## What a run does

Each cycle runs these phases in order:

1. **Warmup:** the latency probes run alone, which gives the latency and memory baselines.
2. **Mixed load:** every slot runs scenario after scenario for `--duration`. The server is sampled
   once a second for memory, descriptors, CPU, and socket states on its port.
3. **Drain:** everything is idle for `--drain`, then the harness checks for leaks.
4. **Recovery:** a fresh connection must upgrade and echo within 1 s.
5. **Descriptor flood** (with `--fd-flood N` only): N connections are held for 10 s. The server must
   stay under 20% of a core throughout, and serve again within 2 s once they close.

Each scenario has its own pass condition. They are weighted by `--profile` (`baseline`, `hostile`
or `storm`), or by `--weights echo=40,garbage=4`:

| Scenario | Client | Passes when |
|---|---|---|
| `echo` | 1-20 messages (some 70-200 KB, some fragmented), random write sizes | every echo is identical and in order, then close 1000 and EOF |
| `split_every_byte` | small messages, one byte per write | as `echo` |
| `ctrl_in_fragments` | a ping between fragments | the pong arrives before the echo |
| `never_read` | 4 KiB receive buffer, sends without reading | a send blocks 500 ms (the server stopped reading), or the server closes |
| `slowloris` | upgrade request at 1 byte per 100 ms | closed within the handshake timeout |
| `idle_pre` / `idle_post` | silent before or after the upgrade | closed within the timeout |
| `close_in_handshake` | part of the request, then FIN or RST | the server closes after a FIN |
| `rst_midframe` | a frame cut short by RST | (the monitor catches leaks) |
| `half_close` | messages, maybe a close, then FIN | every echo, then the close, then EOF |
| `ping_flood` | 10 000 pings while reading | every pong answers a ping; the text sent after the pings comes back |
| `garbage` | random bytes after the upgrade | closed within the idle timeout |
| `invalid` | one RFC 6455 violation | close 1002 (1007 for bad UTF-8, 1009 when too long), then EOF |
| `huge_len` | a declared length of up to 2^63 | close 1009 or 1002 within 1 s, with no memory jump |

A timeout oracle allows `limit * 5/4 + 250 ms`.

The monitor and probes judge the server against these limits:

| Check | Limit |
|---|---|
| Descriptors | baseline + live connections + 64 |
| RSS | baseline + 256 KiB per slot + 64 MiB |
| CLOSE_WAIT | at most 64, three samples running |
| After the drain | descriptors within 16 of baseline, RSS within 10% + 16 MiB, no CLOSE_WAIT |
| Probe p99 | 5x the warmup p99, at least 1 ms over it |

When the probes run more than 1 ms late, the harness is the bottleneck. Latency isn't judged for
that second, and the cycle counts as client-saturated.

## Output

Every run, sample and violation is one JSON line in `--out`, which defaults to
`/mnt/nvme1tb/claude-tmp/soak/soak-<seed>.jsonl`. Lines are tagged by `kind`: `warmup`, `record`,
`sample`, `violation` and, last, `summary`. Failures also print to stderr as
`FAIL <scenario> replay=<id> — <reason>`.

The exit code is:

- `0`: no failures or violations;
- `1`: any failure or violation;
- `2`: only harness errors (the client ran out of ports or descriptors);
- `3`: bad arguments.

## Replaying a failure

```sh
rimu-ws-soak replay SEED:SLOT:GEN --url ws://127.0.0.1:9080/
```

This reruns that one scenario with the same bytes and prints its outcome and transcript. Give it
the same `--profile` or `--weights` as the run, because they decide which scenario the id picks.

## License

Copyright 2026 Vincent Mele. Licensed under the [Apache License, version 2.0](LICENSE).

The rest of this repository is a fork of [wtx](https://github.com/c410-f3r/wtx) and is licensed
under the Mozilla Public License 2.0; see [NOTICE](../NOTICE). This crate contains no wtx code.
