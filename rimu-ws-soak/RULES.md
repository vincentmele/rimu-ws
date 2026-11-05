# rimu-ws-soak pass rules

**Rules version 1** (`src/rules.rs`). Every run's summary carries the version it was judged by.
Changing a rule needs the user's agreement and a new version.

The harness judges in one of two modes:

- **`--mode strict`** (the default) is the rimu-ws gate. Every limit and timeout is configured on the
  server and judged, and every failure counts.
- **`--mode common`** is the comparison between servers, run with `--profile common`. It holds
  every server to what RFC 6455 requires of any public WebSocket server. A check that only makes
  sense with a configured limit or timeout is judged by survival only, through the monitor.

## Kinds of failure

| Kind | What it means | Where it shows |
|---|---|---|
| Survival | The server died, grew without bound, leaked descriptors or sockets, stopped serving, or slowed the probes | monitor violations |
| MUST | RFC 6455 requires it | `fail` records with `kind: must` |
| SHOULD | RFC 6455 asks for it | `fail` records with `kind: should` |
| Limit mark | The server's own size limit is below the common 1 MiB, and it refused a message within it (RFC 6455 10.4 lets a server choose its limit) | `mark` records |

A server passes the common soak with no survival violations and no MUST or SHOULD failures. Marks
are reported, not failed.

## The common mode, scenario by scenario

| Scenario | Rule | RFC 6455 |
|---|---|---|
| `echo`, `split_every_byte`, `frag_flood`, `zero_flood`, `slow_reader` | Every echo arrives byte for byte and in order, then the close is answered (MUST). A close 1009 before every echo is a limit mark. | 5.4, 5.6, 7.1.2 |
| `frag_drip` | Never goes over the 1 MiB limit. The echo is as above. | 5.4, 10.4 |
| `ctrl_in_fragments` | A pong for the ping inside the fragmented message (MUST). It must come before that message's echo (SHOULD, in both modes). | 5.4, 5.5.2 |
| `half_close` | Every echo and the close (MUST). With no close frame sent, the server's EOF after the client's FIN isn't awaited; CLOSE_WAIT build-up shows in the monitor. | 7.1.2 |
| `ping_flood` | Every pong answers a ping, then the text after the flood comes back (MUST). | 5.5.2, 5.5.3 |
| `never_read`, `ping_no_read` | The client sends for 10 s without reading. Blocking, closing or neither all pass here, and memory is the monitor's to judge. Then the client reads for 500 ms, and every frame must be one it was owed: the echo of its text, or a pong carrying its ping, or a close (MUST). | 5.5.3 |
| `invalid`: bad UTF-8, reserved opcode, RSV without an extension, unmasked frame, fragmented control frame, control frame over 125 bytes, stray continuation, a new data frame inside a fragmented message | The connection is failed: TCP closed within 2 s (MUST). A close frame with the right code first (1007 for bad UTF-8, else 1002), not a bare TCP close (SHOULD). | 5.1, 5.2, 5.4, 5.5, 5.6, 7.1.7, 8.1 |
| `invalid`: close code 999 or 1005, one-byte close payload | The connection is failed within 2 s, with close 1002 (SHOULD). | 5.5.1, 7.4 |
| `invalid`: one byte over the size limit | Survival only. | 10.4 |
| `huge_len` | Survival only: the header is sent, then one byte every 100 ms for 1 s. Every declared length is legal. | 5.2, 10.4 |
| `garbage` | Survival only. | |
| `header_flood` | A 101 to an unterminated request (MUST). Otherwise survival only. | 4.2.1 |
| `bad_upgrade`: no key, a short key, a bad version, POST, HTTP/1.0, no Upgrade header, no Connection header | A 101 is a MUST failure. An answer that isn't 101, a close, or no answer within 1 s all pass. | 4.2.1, 4.2.2 |
| `bad_upgrade`: LF-only lines, no colon, a NUL in a value, a long path, many headers, a duplicate key, obs-fold | A 101 with a wrong `Sec-WebSocket-Accept`, or an upgrade that doesn't echo, is a MUST failure. A refusal or no answer passes. | 4.2.2 |
| `bad_upgrade`: a frame pipelined behind the request | It must be upgraded and echoed. Refusing it is a SHOULD failure, in both modes. | 4.1 |
| `slowloris` | The whole request is trickled. A 101 before it is complete is a MUST failure; otherwise survival only. | 4.2.1 |
| `close_in_handshake`, `rst_midframe` | As in strict mode. Leaks show in the monitor. | |
| `idle_pre`, `idle_post`, `close_linger` | Not in the common profile: they need configured timeouts. | |

## Survival (both modes)

These are the monitor's checks, unchanged from strict mode, except the drain baseline below.

| Check | Limit |
|---|---|
| Process | stays alive, under `--rss-ceiling` |
| Descriptors | baseline + live connections + 64 |
| RSS | baseline + 256 KiB per slot + 64 MiB, plus 3 × the size limit per large message in flight |
| CLOSE_WAIT | at most 64, three samples in a row |
| After the drain | descriptors within 16 of the warmup and no CLOSE_WAIT. RSS within 10% + 16 MiB of the first cycle's drain (cycle 0's RSS is not judged), and rising drained RSS across cycles is caught by `--trend`. |
| Probes | p99 within 5 × the warmup p99, and at least 1 ms over it |
| Recovery | a fresh connection upgrades and echoes within 1 s after each drain, and within 2 s after a descriptor flood |
| Burst | each of `--burst N` connections upgrades and echoes within 5 s |

## Changes from the rules before version 1

| Rule | Before | Now | Why |
|---|---|---|---|
| `never_read`, `ping_no_read` (common mode) | a send must block within 10 s | memory judged by the monitor, plus a read-back check | RFC 6455 5.5.3 lets a server answer only the latest ping and keep reading |
| A frame pipelined behind the upgrade | refused = failure | refused = SHOULD failure | RFC 6455 4.1 allows it; refusing breaks no requirement |
| The pong for a ping inside a fragmented message | after the echo = failure | after the echo = SHOULD failure | RFC 6455 5.5.2 says "as soon as is practical" |
| The drain leak check on RSS | against the warmup | against the first cycle's drain | io_uring receive buffers are only touched under load, so the first cycle's growth is not a leak; `--trend` catches growth across cycles |
