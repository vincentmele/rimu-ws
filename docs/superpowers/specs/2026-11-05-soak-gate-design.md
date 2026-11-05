# rimu-ws-soak as the production gate, and the competitor field (2026-11-05)

## Intent

rimu-ws is meant to compete with sockudo-ws, fastwebsockets and tokio-tungstenite as a WebSocket
server library. "Production" means production for its users: anyone who puts a rimu-ws server on
the public internet, in front of clients they do not control (buggy, abusive, hostile).

rimu-ws-soak already exists and has found real bugs. The user's doubt is that it may not be
thorough enough. This project makes it two things:

1. **The production gate.** A rimu-ws release ships only if the gate passes.
2. **A fair yardstick.** The same soak runs against the leading competitors, configured the way a
   careful production user would configure them. The point, in the user's words, is "proof that
   the soak is rough enough and that rimu-ws is held to the same standard as those other more
   mature ones."

The ambition of rimu-ws is larger than the competitors', so rimu-ws gets a harder test on top of
the common one.

## Goals

- **Tier 1, the common soak:** one fixed set of scenarios and pass rules, run unchanged against
  every competitor and against rimu-ws. rimu-ws must pass all of it.
- **Tier 2, the rimu-ws gate:** tier 1 plus everything a production library needs that the
  competitors do not all offer. One command runs it and gives one verdict.
- **A toughness audit:** every tier 1 check either fails at least one competitor, or has a written
  reason why none could fail it (for example, it guards a bug class rimu-ws had and fixed).
- **A report card:** one row per server and one column per check, showing pass, fail or not
  applicable, with failure counts and a replay id for an example failure. It is generated from the
  run output, not written by hand.

## Non-goals

- **Throughput benchmarking.** HttpArena already does that; this project measures robustness.
  Latency appears only as a pass rule ("probes stay within F x baseline").
- **Publishing.** The report card is evidence for the user and lives in the rimu-ws repo. It is
  not a marketing page and is not sent to HttpArena.
- **Fixing competitors.** Their failures are recorded, not patched.

## Anti-goals (would make this a failure even if it ran)

- **A home advantage for rimu-ws.** That means a pass rule shaped around rimu-ws's behaviour where
  RFC 6455 allows other behaviour, a scenario dropped because rimu-ws fails it, or a soak-specific
  rimu-ws tuning.
- **Competitors set up to fail.** Running with defaults when the library has a documented limit, a
  sloppy echo loop of our own around a good library, or an entry that silently falls back from
  io_uring to epoll.
- **Quietly loosening a rule.** Every pass rule is versioned, and changing one needs the user's
  agreement (an existing standing rule).
- **A gate that only passes on a quiet box.** It must also not hide real timing bugs behind
  slack.

## The competitor field (15 servers, plus rimu-ws)

The user chose:

- the top 10 echo-ws entries in HttpArena;
- the three Rust libraries;
- original wtx.

The top 10 is ranked by average rank over echo-ws-512, -4096 and -16384 in
`~/src/HttpArena/site/data/results`, with wtx left out:

| # | Competitor | Source | Kind |
|---|---|---|---|
| 1 | zix | HttpArena `frameworks/zix` | Zig framework, io_uring |
| 2 | tokio-ws | HttpArena `frameworks/tokio-ws` | hand-rolled echo loop, no library |
| 3 | ringzero-ws | HttpArena `frameworks/ringzero-ws` | hand-rolled echo loop on raw io_uring |
| 4 | viltrum | HttpArena `frameworks/viltrum` | V framework, epoll |
| 5 | aegon | HttpArena `frameworks/aegon` | C++ framework, io_uring |
| 6 | vanilla-epoll | HttpArena `frameworks/vanilla-epoll` | V HTTP server, epoll |
| 7 | minima-ws | HttpArena `frameworks/minima-ws` | hand-rolled echo on a C# io_uring engine |
| 8 | tokio-websockets | HttpArena `frameworks/tokio-websockets` | Rust library |
| 9 | uWebZockets | HttpArena `frameworks/uwebzockets` | Zig |
| 10 | plod | HttpArena `frameworks/plod` | Goose framework |
| 11 | wtx (original) | HttpArena `frameworks/wtx-ws` | the library rimu-ws forked |
| 12 | tokio-tungstenite | our server, `/mnt/nvme1tb/claude-tmp/tt-echo` | Rust library |
| 13 | sockudo-ws | our server, `/mnt/nvme1tb/claude-tmp/sk-echo` | Rust library |
| 14 | fastwebsockets | our server, `/mnt/nvme1tb/claude-tmp/fw-echo` | Rust library |

There are 14 rows. With rimu-ws, the report card has 15.

- **The hand-rolled loops stay in** (the user's decision). They have no settings, so they run as
  written, and the report card marks them "no settings available".
- **Ranking source:** the ranking above is from the local HttpArena checkout's site data as of
  5 Nov. The builder records the HttpArena commit used and does not re-rank later.

### "Configured as a careful production user would" (the user's decision)

For each competitor:

- **The settings:** use the library's own documented settings for:
  - maximum message and frame size;
  - write-buffer or backpressure limit;
  - handshake and idle timeouts;
  - connection limit;
  - upgrade request validation.
  
  Use them where they exist, with values matching rimu-ws's recommended production values.
- **No help from us.** Where a library has no setting for something, that gap counts against it.
  We do not add our own wrapper logic (deadlines, size checks) around the library. The echo loop
  itself must be the plain one the library's docs or examples show.
- **A `CONFIG.md` per competitor:** each setting, its value, and a link to the doc or source line
  it comes from. Also every setting looked for and not found. A reader can then check that nothing
  was set up to fail.
- **HttpArena entries:** these are benchmark code. Several turn limits off: tokio-websockets uses
  `Limits::unlimited()` and `frame_size(usize::MAX)`. The production setup is a patch on top of
  the entry at a pinned HttpArena commit.
- **rimu-ws:** gets the same treatment. Its tier 1 server uses the defaults rimu-ws documents for
  production, not the soak-server's `WTX_*` tuning. If the soak needs a non-default rimu-ws value
  to pass, that value becomes the documented default, or the soak fails.

### The common production values (the user's decision)

| Setting | Value |
|---|---|
| Maximum message (and frame) size | 1 MiB |
| Write buffer / backpressure limit | 256 KiB |
| Handshake timeout | 10 s |
| Idle timeout | 300 s |

- **rimu-ws documents these as its production values.** Where the library default differs, the
  docs say to set it: the default message limit is 64 MiB today, and there is no framework idle
  timeout.
- **Every competitor is set to the same values** where it has the setting.
- **The rimu-ws row** in tier 1 is a plain server built on rimu-ws's public API with these values,
  run in Docker like the others. It is not soak-server.
- **The common size** in "Message sizes in tier 1" below is the 1 MiB from this table.

## Tier 1: the common soak

### What "commonly supported" means

The user's direction: limit the comparison to what all competitors commonly support. This design
reads that as **features, not behaviour** (my call; the user did not object):

- **Features:** HttpArena's own check (`scripts/validate-ws.py`) only asks every entry for:
  - an upgrade;
  - text and binary echo;
  - ping/pong;
  - clean close;
  - refusing a bad upgrade.
  
  Scenarios whose pass rule needs a configured limit are out of tier 1:
  - handshake and idle timeouts;
  - 1009 for a size over the limit;
  - compression;
  - TLS;
  - connection limits;
  - `close_linger` (which needs a send-buffer setting).
- **Behaviour:** hostile behaviour stays in, because every public server meets it whether or not
  it was built for it.

### Scenarios

Starting point: the existing `untimed` profile, plus the attack scenarios that need no limit:

- `echo`, `split_every_byte`, `ctrl_in_fragments`, `half_close`
- `never_read`, `ping_no_read`, `slow_reader`, `ping_flood`
- `close_in_handshake`, `rst_midframe`, `garbage`
- `invalid`, `huge_len`, `bad_upgrade`, `header_flood`
- `frag_flood`, `zero_flood`
- `frag_drip`, but only up to the size limit, with no over-limit case
- `slowloris`, judged by survival only (below)
- `--burst`, and the descriptor flood phase

### Pass rules, in three kinds

Every check in tier 1 is labelled with one kind. The report card shows the kinds separately.

1. **Survival:** the same hard limits for everyone.
   - The process stays alive.
   - RSS stays under the monitor's budget and the RSS ceiling.
   - Descriptors stay bounded and return to baseline after the drain.
   - No CLOSE_WAIT build-up.
   - A fresh connection is accepted after every storm.
   - Probes stay within F x their baseline while hostile clients run.
   
   For scenarios that need a limit in tier 2, tier 1 judges only survival. For example, a
   slowloris connection held open forever is not a failure in tier 1, but the server running out
   of memory or descriptors because of it is.
2. **Protocol MUST:** what RFC 6455 requires.
   - Refuse a bad upgrade (the 7 must-refuse cases).
   - Fail the connection on unmasked frames, reserved opcodes or RSV bits, fragmented or oversized
     control frames, stray continuations and bad UTF-8.
   - Echo byte for byte, in order.
   - Answer pings.
   
   "Fail the connection" means closing TCP, with or without a close frame.
3. **Protocol SHOULD:** a close frame with the right code (1002, 1007) before the TCP close, as
   RFC 6455 7.1.7 asks. These are scored separately from MUST, so a competitor that just drops the
   TCP connection fails SHOULD but not MUST.

rimu-ws must pass all three kinds.

### Classifying the existing checks (my call, from the principle above)

The principle: a check that only makes sense with a configured limit or timeout is judged by
survival in tier 1, and strictly in tier 2. A check RFC 6455 states as MUST is MUST. Everything
else that RFC 6455 asks for is SHOULD.

| Existing check | Tier 1 kind | Tier 2 |
|---|---|---|
| `huge_len` "1009 or 1002 within 1 s, no memory jump" | survival: no memory jump, process alive | as today |
| `invalid::Oversized` (max_payload + 1) | survival only | 1009 |
| `garbage` "closed within the idle timeout" | survival only. Random bytes can form a valid frame with a large length, and waiting for it is legal. | as today |
| `header_flood` "refused before 1 MiB" | survival only | as today |
| `bad_upgrade`, the 7 must-refuse cases | MUST | as today |
| `bad_upgrade`, the 7 may-refuse cases ("answered within 1 s") | survival only | as today |
| `invalid`: unmasked frame, reserved opcode, RSV without an extension, fragmented control frame, control frame over 125 bytes, stray continuation, a new data frame inside a fragmented message, bad UTF-8 in a text message | MUST: the connection is failed (TCP closed, close frame optional) | as today |
| `invalid`: close code 999, 1005, 1006, 1015 or another invalid one, one-byte close payload, bad UTF-8 in the close reason | SHOULD | as today |
| close code 1002, 1007 or 1009 before the TCP close | SHOULD | as today |

The builder writes the final classification into the rules version file. Each line cites its RFC
6455 section, so the user can check it in one place.

### Message sizes in tier 1 (my call)

- **The common size:** tier 1 never sends a message larger than the common production maximum
  (below). The largest `echo` messages and `frag_drip` stay at or under it.
- **A smaller fixed limit:** some competitors have a hard-coded limit with no setting, such as the
  16 MiB `MAX_FRAME` in tokio-ws and ringzero-ws. If one has a limit below the common size, it may
  refuse a message under the common size with 1009 or a close. That scenario is then marked
  "limit below the common size" for that server, not failed. RFC 6455 lets a server choose its
  limit.
- **Silence is still a fail.** Truncating, corrupting or silently dropping a message is a MUST
  fail whatever the limit.

### Rule changes, agreed in principle

These are rules written around rimu-ws's behaviour, now widened to what the RFC requires:

- **`ping_no_read`:** pass when memory stays bounded (monitor) and every pong answers a ping. A
  server may answer only the most recent ping (RFC 6455 5.5.3), so a send no longer has to block.
  - Open question 2 in `docs/soak-handoff-2026-11-04.md`.
- **`never_read`:** the same, judged by memory, with blocking or closing accepted as before.
- **A frame pipelined behind the upgrade request:** RFC 6455 4.1 allows it. A server that refuses
  it fails a SHOULD-level check, not MUST.
  - Open question 1 in the handoff.
- **The drain leak check:** the baseline is the RSS after the first cycle's drain, not the warmup.
  Growth across cycles is caught by `--trend`.
  - Open question 3 in the handoff.

The builder lists each such change in the rules version file, with the before and after.

### Same conditions for everyone

- **Run settings:** same seeds, slot counts, durations, cycles, CPU pinning (server on 0-5,12-17,
  harness on 6-11,18-23) and RSS ceiling.
- **Run order:** interleaved, round-robin across competitors, so box load does not favour one.
- **Docker entries:** run the way HttpArena runs them:
  - `--network host`;
  - `--security-opt seccomp=unconfined`;
  - `--ulimit memlock=-1:-1 --ulimit nofile=1048576:1048576`;
  - `--cpuset-cpus` set to the server CPUs.
- **io_uring check:** an entry that claims io_uring must show io_uring descriptors
  (`anon_inode:[io_uring]` in `/proc/<pid>/fd`) during the run. Otherwise the run is invalid, not
  failed. Aegon fell back to epoll silently before.
- **Every server runs in a container** with the same flags. That includes rimu-ws, our three Rust
  echo servers and wtx, which get Dockerfiles next to their `CONFIG.md`. Memory and descriptors are
  then measured the same way for all.
- **Monitoring a container:** the monitor walks the container's cgroup.procs. It judges memory by
  the **sum of the processes' RSS**, the same metric the current budgets were tuned on. It also
  sums their descriptors. cgroup memory.current is recorded for information only and judges
  nothing, because it adds socket buffers and page cache and would amount to a different rule.
- **Ports and paths:** HttpArena entries serve `ws://127.0.0.1:8080/ws`. The harness takes the
  URL, so nothing changes in the entries.

## Tier 2: the rimu-ws gate

Tier 2 is everything in tier 1, plus the following. All of it is run by one script with one
verdict file.

1. **Strict versions of tier 1:**
   - `slowloris`, `idle_pre` and `idle_post` closed within the timeout;
   - `frag_drip` over the limit gets 1009;
   - `close_linger` with a small send buffer;
   - the existing timing rule: limit x 5/4 + 250 ms.
2. **The configuration matrix:**
   - io_uring server with the plain, drain and queue loops;
   - direct descriptors on and off;
   - the tokio server;
   - deflate on and off;
   - TLS through rustls, and kernel TLS;
   - one thread, and multi-threaded.
   
   That is the "rest of the matrix" left over in the handoff.

   **Shape (my call):**
   - One factor varied at a time around a base config (io_uring, queue loop, no compression,
     plaintext, multi-threaded), not a full cross product.
   - Two cross cells: deflate with TLS, and kernel TLS with direct descriptors off.
   - Each cell runs the scenarios that apply to it.
   - Timing cells configure short limits (2 s handshake, 5 s idle, 2 s close), as soak-server does
     today. That keeps runs short; the production values (below) are what tier 1 uses.
3. **New scenarios:**
   - **Compression abuse:**
     - a deflate bomb (a small frame that inflates past the size limit gets 1009, and memory
       stays bounded);
     - corrupt compressed data;
     - a bad `permessage-deflate` negotiation;
     - RSV1 set without negotiating it.
   - **TLS abuse:**
     - a slow ClientHello;
     - a garbage ClientHello;
     - RST mid-record;
     - no close_notify;
     - renegotiation or KeyUpdate attempts, where kernel TLS refuses KeyUpdate (it must fail
       cleanly, without a hang or leak);
     - a handshake flood.
   - **Graceful shutdown under load:** while the hostile mix runs, signal shutdown. Every open
     connection gets close 1001 or is dropped within the drain deadline, and the process exits
     cleanly with no descriptors left.
   - **Connection limit:** past the configured maximum, new connections are refused quickly, the
     existing ones are unaffected, and accepting resumes once the count drops.
4. **Scale:** tens of thousands of concurrent connections, using several 127.0.0.x source
   addresses. The number is the builder's call, bounded by the box (colossus has 24 CPUs, 62 GB
   and about 29 GB free, and runs live trading). It is set once and recorded in the rules file.
5. **Duration:** one 24-hour run of the rotating profiles. Hold the drained RSS trend flat
   (`--trend`) and keep 0 fails. Run it as a `systemd-run --user` unit, not a session background
   job, which got killed at 2 hours last time.
6. **In-process checks in the same gate:**
   - library tests;
   - the full Autobahn suite, all servers OK;
   - the handshake fuzz target and the differential fuzz target, each for a fixed time with no
     crash;
   - the soak crate's own tests.

**Missing rimu-ws features are out of scope (the user's decision).** This project builds the gate:
tier 1, tier 2 and the report card. Where tier 2 needs something rimu-ws lacks, the gate fails, and
the fix is follow-up work, done test-first. Known so far:

- the tokio server has no idle timeout;
- kernel TLS is not on the tokio path;
- connection limits exist only in the framework.

Cells that hit these are expected to fail at first. The builder lists every such gap in the
verdict.

**The verdict:** pass only if every item passes. A failed timing check stays a failure. The report
attaches a replay of it, so a person can see whether it was box load. But the gate does not pass
itself on a replay.

## Constraints

- **colossus only.** No AWS (standing rule) and no HttpArena `system_tune`. colossus is a shared
  trading box:
  - never run two soak or server processes at once;
  - kill by pid;
  - always pass `--rss-ceiling` against competitors.
- **Temp, build and run output** go under `/mnt/nvme1tb/claude-tmp`. `/tmp` is a small tmpfs.
- **HttpArena:** never push anything there. Competitor patches live in the rimu-ws repo.
- **rimu-ws repo:** never push to `origin` (upstream wtx). Push nowhere unless the user asks.
- **Licensing:** rimu-ws-soak is Apache-2.0. Competitor patches and our three Rust echo servers
  sit under `rimu-ws-soak/competitors/` with the same licence. Code copied from HttpArena entries
  keeps its own licence header.

## Decided by the user

- Purpose: a production gate for rimu-ws, and proof the soak is rough enough and fair.
- The field:
  - the top 10 HttpArena echo-ws performers, hand-rolled loops included;
  - tokio-tungstenite, sockudo-ws, fastwebsockets;
  - original wtx.
- Competitors configured as a careful production user would.
- Two tiers: what all competitors commonly support for the comparison, and a stricter test for
  rimu-ws.
- Production values: 1 MiB, 256 KiB, 10 s, 300 s, documented by rimu-ws and applied to every
  competitor.
- Docker with `--security-opt seccomp=unconfined` and HttpArena's other flags is allowed on
  colossus. The user approves the first such run when it is prompted.
- Gate first: missing rimu-ws features are follow-up work, not this project.

## My calls (the user can override)

- "Commonly support" means features, not hostile behaviour.
- The three kinds of pass rule (survival, MUST, SHOULD) and survival-only judging of
  limit-dependent scenarios in tier 1.
- The rule widenings listed above.
- Every server in a container, memory judged by the summed RSS of the container's processes, and
  the io_uring validity check.
- The classification table of existing checks, and the "limit below the common size" mark.
- The tier 2 matrix shape: one factor at a time, plus two cross cells.
- A 24-hour run, the scale target bounded by colossus, and a failed timing check never passing on
  a replay.
- Where things live: `rimu-ws-soak/competitors/<name>/` with `CONFIG.md`, and a patch or our own
  source.

## Left to the builder

- **Tooling:** the report card format, and how it is generated (a `rimu-ws-soak report`
  subcommand is the obvious home). The gate script's name and shape.
- **Run parameters:** tier 1 durations, slot counts and cycles per competitor. Keep a full round
  of 15 servers to a few hours.
- **Tier 2 scenarios:** the exact case lists for compression and TLS abuse, and how the harness
  speaks TLS. It must stay independent of rimu-ws, so use rustls in the harness or an
  established client.
- **Competitor setup:** how to find each competitor's production settings. That means docs first,
  then source.
- **Ordering:** the order of work, provided tier 1 against the three Rust libraries and rimu-ws
  comes first. Those servers already exist, so the rule changes can be validated before Docker
  work starts.
