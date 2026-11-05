# rimu-ws HTTP/2: batch-driven connection core (design)

Date: 2026-11-05. Branch `feat/http2-driver`, cut from `feat/hardening` (cc847160).
Background reports (colossus, not in the repo): `/mnt/nvme1tb/claude-tmp/httpwin/`:
`summary.md`, `rules.md` (HttpArena profile and scoring spec), `capabilities.md` (audit of the current
http2 module, with a bench in `cap-bench/`), `rivals.md` (how the leaders are built).

## 1. Intent

The user wants rimu-ws to win the HttpArena HTTP/1.1, HTTP/2 and HTTP/3 boards in the **experimental**
league (today: plod, viltrum, aegon, wastnet). The work goes in this order: HTTP/2 first (this document),
then HTTP/1.1, and HTTP/3 later (skipped for now). The new HTTP/2 is a real library feature for rimu-ws
users. It is held to the same production gate as the WebSocket work: conformance, fuzzing, soak. It is not
code made only for the benchmark.

Why HTTP/2 first: the protocol pieces already exist (HPACK, frames, flow control). The audit shows the
gap is how a connection is driven, not the protocol code. Upstream wtx scores 3.9M rps on baseline-h2;
the leaders score 14–15M.

## 2. What is wrong today (from the audit)

The `http2` module is shared by the HTTP/2 client, the client pool, gRPC client and server, the server
framework and WebSocket over HTTP/2. Per request on the server it costs:
- shared state behind an `Arc` and two async mutexes, with at least 5 lock operations;
- one spawned task per stream (a 1–2 KiB box);
- about 7 allocations;
- one write per response (strace: 4109 `writev` for about 4000 responses);
- a 50 ms linger timer per stream before cleanup;
- about 12k user instructions in the framework, against about 7k *total* cycles for the leaders.

Bugs found:
- A frame that arrives on a closed stream (likely WINDOW_UPDATE or RST_STREAM) gets GOAWAY(PROTOCOL_ERROR).
  RFC 9113 §5.1 says to tolerate it. The linger timer hides this; with linger off, curl breaks every
  2 requests. The error never reaches `error_cb`.
- The framework calls `peer_addr()` after accept. That is an extra syscall, and it fails with EOPNOTSUPP
  on io_uring direct descriptors.
- The 24-byte connection preface is checked from a single read.
- kTLS never switches on for HTTP/2, because the server splits the stream right after the handshake.

## 3. Goals, non-goals, anti-goals

Goals:
1. **Rewrite the `http2` module in place**: the user chose to rewrite the existing module, not to add a
   second HTTP/2 beside it. **The whole module moves to the new design, client included**: client, client
   pool, gRPC, server framework, WebSocket over HTTP/2.
2. **Server performance target:** on colossus, the rimu-ws entry ranks #1 on a local experimental-league
   HTTP/2 composite. The composite is the board formula (sum of 1000 × rps / best, over baseline-h2,
   static-h2, baseline-h2c and json-h2c). The field is plod, viltrum and aegon, run on the same box, with
   the same CPU split, under h2load with HttpArena's flags. Stretch goal: first on every profile.
3. **Production gate passes:** see §8.
4. **HTTP/1.1 can slot in next:** one listener picks the protocol by TLS ALPN (and, for cleartext, by
   the HTTP/2 preface). This design leaves that hook; HTTP/1.1 itself is out of scope.

Non-goals:
- HTTP/1.1 and HTTP/3 (later projects).
- **The server off io_uring.** The server, HTTP/2 and gRPC, runs only on `UringExecutor` (user
  decision). `Http2ServerFramework::tokio()`, the std-runtime server path and the server's `Send` bounds
  go on the breaking-change list. Existing server tests move to the uring runtime. The *client* (and
  client pool, gRPC client) keeps a small generic async loop over the same core and must still work on
  tokio; it is not tuned.
- Server push and priority (upstream has neither; RFC 9113 deprecates priority).
- Pushing anything to HttpArena or upstream wtx. Push only to the `rimu` remote, and only when the user
  asks.

Anti-goals (a failure even if the numbers win):
- Anything the HttpArena rules forbid, and grey-area tricks. The user chose **strict**:
  - Responses keep `content-type`, `server` and a correct `date` (RFC 9110 §6.6.1).
  - JSON is serialized per request.
  - No response caching.
  - Static files are served by the framework's own handler, and its cache follows the disk.
  - No pre-rendered bodies.
- Ignoring flow control for small bodies, or bending any other protocol rule (zix does both).
- Robustness lower than today: for example losing the hardening branch's limits, timeouts and
  panic isolation.
- A benchmark-only code path that library users don't get.

## 4. Constraints

- Licence: the fork is MPL-2.0; new files carry the fork's MPL-2.0 header (see `NOTICE`).
- Upstream merges get harder: the user accepted that by choosing an in-place rewrite. Keep HPACK,
  Huffman and frame types where they are, so merges in those files stay easy.
- Toolchain: nightly, as the crate is today. Tests without the `tokio` feature (upstream's tokio tests
  fail on `Sleep`). Never run two wtx test processes at once (SO_REUSEPORT splits connections).
- colossus:
  - memlock is now unlimited, but check `/proc/buddyinfo` if io_uring reports ENOMEM;
  - put temp, build and perf files under `/mnt/nvme1tb/claude-tmp`;
  - never run HttpArena's `system_tune` (it restarts docker);
  - no AWS.
- HttpArena entry: local branch `add-rimu-ws` in `~/src/HttpArena`, `frameworks/rimu-ws`, type
  experimental. HTTP/2 profiles are added to the same entry (one board row). Never push it.

## 5. Architecture

### 5.1 Protocol core with no I/O: one owned value per connection

A new per-connection state machine, called `Http2Conn` here (the name is the builder's call). It owns,
with no `Arc` and no locks:
- the HPACK decoder and encoder (existing code);
- connection and stream flow-control windows;
- SETTINGS, both local and peer;
- a stream table, slab-indexed, slots reused, holding each stream's state, windows, request
  buffers and pending response body;
- an output buffer of encoded frames.

Its interface is synchronous:
- `feed(&mut self, input: &[u8]) -> consumed`: parse **every complete frame** in the input. Update
  state and queue protocol replies (SETTINGS ACK, PING ACK, WINDOW_UPDATE) into the output buffer.
  Surface events: request headers complete, data, end of stream, reset, GOAWAY.
- `send_headers` / `send_data` / `send_trailers` / `reset` for a stream: encode into the output
  buffer under flow control. Data that the windows don't allow yet stays queued on the stream, and is
  written when WINDOW_UPDATE arrives.
- The output side lends the bytes to the I/O loop: `output() -> &[u8]` or vectored slices, then
  `consume(n)`.
- Body bytes from a static-file cache can be queued **by reference** (shared bytes, plus offset and
  length), so a large file is not copied into the output buffer; the I/O loop gathers them with a
  vectored send. On TLS, the record layer seals from those slices.

Protocol rules the core enforces (RFC 9113 and RFC 7541):
- the closed-stream rules of §5.1;
- the preface may arrive across several reads;
- all SETTINGS limits are honoured;
- CONTINUATION sequences are validated;
- errors are mapped to stream or connection errors with the right codes.

Abuse limits, configurable, each with a production default:
- max concurrent streams;
- header list size, and CONTINUATION frame count per header block;
- rapid reset (CVE-2023-44487): a budget of resets per window, then GOAWAY ENHANCE_YOUR_CALM;
- PING, SETTINGS and empty-frame floods;
- request body size;
- per-connection buffered bytes.

### 5.2 Server: one task per connection, batch in and batch out (io_uring)

The server driver is one task per connection on `UringExecutor`. Each turn:
1. Read all available bytes (`try_read` fast path, as in the WebSocket entry); `feed` them.
2. For each completed request, run the framework's router and handler **inline**: poll the handler
   future once, in place.
   - Ready: encode the response straight into the core's output buffer.
   - Pending: park the future in the connection's set of pending handlers (no separate task). It is
     polled again when its waker fires, and its response joins the next batch.
   - Handlers that take the stream for streaming (manual mode, gRPC streaming, WebSocket over HTTP/2)
     get their own task, which talks to the connection through a per-connection queue on the same
     thread (no locks).
3. Queue **one send** for everything produced in the turn (`try_write_all_vectored` / the uring
   write queue).
4. Wait for readiness, a handler wake or a timer.

Other server details:
- Stream slots are freed as soon as both sides are closed. **No linger timer.**
- Request buffers are pooled per connection.
- No `peer_addr()` call after accept; use the address accept already gave (or none with direct fds).
- With TLS, the connection is never split into reader and writer halves, so the existing kTLS switch can
  run once the handshake ends (AES-128-GCM, the benchmark's cipher).

### 5.3 Response headers

- HPACK encoding of repeated headers is cached: the `:status` / `content-type` / `server` combination
  for an endpoint is encoded once into dynamic-table references, and later responses copy those bytes.
- `content-length` is sent as a literal and not indexed, so it doesn't churn the dynamic table.
- `date` is formatted once a second, from a per-thread clock updated by the runtime timer. It is
  indexed, so it costs a few bytes per response and changes once a second.

### 5.4 SETTINGS and flow control (library defaults, tuned by measurement)

- Advertise max concurrent streams of at least 128 (h2load uses `-m 100` and `-m 32`).
- Use a large initial stream window, and open the connection window at start with a WINDOW_UPDATE.
- Keep max frame size at the peer's value for sending; DATA frames are filled to it.
- **The entry is standard mode (user decision), so the library's defaults must themselves be the fast
  values.** Standard mode allows no settings beyond the defaults, except ones the framework's own
  production guide recommends (`rules.md` §1.5). Pick defaults that are fast *and* safe for real
  deployments: window and stream values bounded by the per-connection memory limits of §5.1.
- Anything a production user might reasonably change goes in a short production-configuration guide in
  the rimu-ws docs, written as real advice. The entry may set only what that guide recommends.
- Under any setting, the behaviour must stay RFC-correct.

### 5.5 Client and gRPC on the same core

- The client and client pool drive `Http2Conn` from one connection task with a generic async read/write
  loop (works on tokio and on `UringExecutor`). Callers talk to it through stream handles.
- Handles may need to be `Send` for tokio users. Their synchronisation is the builder's call (a channel
  or one short lock around the core), but there must be **no lock on the server's hot path**.
- Public API: keep the current types and entry points source-compatible where it is practical:
  - `Http2ServerFramework`, `HttpRouter`, endpoints and extractors, middleware;
  - `ClientStream` / `ServerStream`, `Http2ClientPool`, gRPC client and server, `WebSocketOverStream`.
  
  List every breaking change in the plan, with the reason.

### 5.6 Static files (framework feature, needed for static-h2)

A static-file endpoint in the server framework. It serves a directory and:
- maps URL to path safely (no traversal);
- sets `content-type` from the file extension;
- negotiates `Accept-Encoding` and serves the precompressed `.br` / `.gz` sibling when one exists, with
  `vary: accept-encoding`;
- keeps an in-memory cache of the file bytes. The cache must **follow the disk within 2 s**: a cheap
  `stat` revalidation, at most about once a second per file, whose result is shared by all
  connections on the thread. Changed or deleted files are picked up.
- does conditional requests (ETag / Last-Modified) if cheap; that is the builder's call.

Rules to respect (`rules.md`): no preload map built by the entry, and no hand-mapped directory. The
handler must be the framework's own.

### 5.7 Protocol choice on one listener (hook for HTTP/1.1)

- The TLS acceptor offers ALPN `h2` (and later `http/1.1`) and gives the chosen protocol to the
  connection task.
- Cleartext h2c with prior knowledge is detected by the preface.
- For now any non-h2 choice is refused cleanly. HTTP/1.1 will plug in here.

## 6. HttpArena entry (local only)

Add `baseline-h2`, `static-h2`, `baseline-h2c` and `json-h2c` to `frameworks/rimu-ws` (same display
name, experimental). **Switch the entry from `tuned` to `standard`** (user decision): one board row has
one mode, and the rivals are standard. That affects the WebSocket profiles too:
- The WebSocket entry's knobs must become library defaults, or be recommended by the production guide.
  Those knobs are: spin 20 µs, rings 4096/16384, direct descriptors, TCP_DEFER_ACCEPT, the `WTX_*`
  environment variables and the hand-written drain loop.
- The entry must use the framework's documented high-level APIs (`rules.md` §1.5).
- If a knob can't honestly be either, drop it, measure what that costs on the WebSocket profiles, and
  report it to the user. Endpoints and request shapes are in `rules.md`:
- TLS on 8443 with the mounted certificate;
- h2c on 8082;
- `/baseline2` sums the query parameters;
- `/json/{count}?m=` serializes per request;
- static files are served from the mounted directory.

The entry should use real routing, middleware (at least one real middleware, for example the `server`
header or CORS), request extraction and response building. Missing completeness axes cost 2.5% each;
upstream's entry declares `middleware: false`.

## 7. Measurement

- Build h2load (nghttp2 with ngtcp2/nghttp3, the HttpArena versions in `rules.md`) under `~/.local`,
  the same way gcannon was built. The user approved this.
- Run the four profiles with HttpArena's h2load flags, scaled to colossus:
  - the server on one CPU set and h2load on the disjoint set, as in the WebSocket local runs (server
    0-5,12-17; load 6-11,18-23);
  - best of 3, rivals interleaved with us in the same session.
- Rivals: plod, viltrum and aegon, built from their HttpArena Dockerfiles. Docker with
  seccomp=unconfined is allowed on colossus; the user approves the first run. Aegon in docker without
  that falls back to epoll, so check each rival's log for its real engine.
- Watch the load side: on the official box h2load seems to cap at about 14–15M, and on colossus the
  generator may saturate first. Report generator CPU next to every number.
- Per-request cost is the steadier signal: `perf stat -e cycles:u,instructions:u -p <pid>` divided by
  requests. Use it for A/B work; throughput is the arbiter for the goal.
- Upstream's old server, on the same harness, is the baseline in every report.

## 8. Done means: the production gate below, plus the performance goal of §3

The performance goal (#1 on the local experimental composite) is an exit criterion. If plod, viltrum and
we all hit the generator's ceiling on a profile, that profile counts as a tie. Report the per-request
cycles (`perf stat`) beside it; they are informative only. The ranking is then decided by the remaining
profiles (my call).

The production gate:

1. h2spec (full server suite) passes against the server framework, plaintext and TLS.
2. Every existing test passes: http2, client pool, gRPC, server framework, WebSocket over HTTP/2.
   New unit tests cover each RFC rule and limit in §5.1.
3. A differential test plus a fuzz target for `Http2Conn`: random frame sequences, chunked at random
   byte offsets, checked against a simple model. This is the pattern of `web_socket::differential`.
4. Miri on the core's unsafe code (if any), and ASan on the server tests.
5. Soak: `rimu-ws-soak` gains HTTP/2 scenarios and passes:
   - steady load;
   - abusive clients: rapid reset, CONTINUATION flood, SETTINGS/PING flood, slow reader, never-read,
     window-starved streams, half-open, oversized headers and bodies;
   - each with bounded memory and no stalls.
6. Interop: curl, h2load, nghttp and a Go `net/http` client against the server; the client against
   nginx or h2o and our server.
7. The WebSocket and HTTP/2 entries show no regression on their benchmarks.

## 9. Calls made without the user (check these)

- **Panic isolation stays per stream.** Each inline or parked handler poll is wrapped so a panic answers
  that stream with 500 or RST_STREAM(INTERNAL_ERROR) and the connection lives on. Measure its cost. If it
  costs more than about 2% on any H/2 profile, bring it back to the user before weakening it. (Commit
  c9a319fb dropped a per-poll guard in the executor for a 5% WebSocket cost; this guard is per handler
  call, not per task poll.)
- **Robustness:** the HTTP/2 framework gets the same set as the hardened WebSocket framework:
  - connection cap (`set_max_connections`);
  - handshake and preface deadline;
  - idle timeout;
  - write-stall / close timeout;
  - graceful shutdown (`set_shutdown`);
  - error callback reporting.

  The soak scenarios of §8 need them.
- Generator-capped profiles are ties (§8).
- `date` is sent (RFC 9110 §6.6.1, strict posture); `server: rimu-ws`.

## 10. Left to the builder

- Type and module names, file layout inside `http2/`, and the order of the internal refactor.
- The client-handle synchronisation (§5.5) and how pending handlers are stored (§5.2).
- SETTINGS and window values for the entry, found by measurement.
- Whether the static cache does ETag / Last-Modified (§5.6).
- How to stage the work so the crate builds and its tests pass after each step.
