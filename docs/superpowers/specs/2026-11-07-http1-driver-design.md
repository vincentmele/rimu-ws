# rimu-ws HTTP/1.1: keep-alive server core (design)

**Status:** draft for approval, 7 Nov 2026.
**Author decisions captured:** tier = **tuned**; first plan = **MVP (4 profiles)**; parser = **hand-rolled SIMD from the start**.
**Related:** `2026-11-05-http2-driver-design.md` (sibling h2 core; §5.7 there is the protocol-choice hook this plugs into), the HttpArena investigation in `/mnt/nvme1tb/claude-tmp/httpwin/` (`rules.md` §2.1–2.4, §3; `capabilities.md` §1; `rivals.md`).

## 1. Intent

rimu-ws has no HTTP/1.1 server. HttpArena's h1 family is the largest prize on the board — **8 scored
framework profiles, 8000 points**, against h2's 4000 — and four of those profiles share a single
endpoint. This design builds the server that unlocks those four, correctly, as the foundation the other
four profiles (async, json-comp, json-tls, 8gbit) extend later.

The MVP is one plaintext keep-alive HTTP/1.1 server on port 8080 answering `GET|POST /baseline11`, built
to survive HttpArena's byte-by-byte fragmentation validator, and running on the existing io_uring
executor the way the WebSocket and HTTP/2 entries already do.

## 2. Why now, and what we are building on

- **h2 is done** (sibling spec); h1 is the next-highest return on effort. h3 needs a QUIC stack from
  scratch for a 2000-point ceiling, so it comes last.
- **There is nothing to fork from inside wtx.** No request/response framer, no keep-alive loop, no
  Content-Length body reader, no chunked decoder exist (`capabilities.md` §1). The only HTTP/1.1 code is
  the WebSocket upgrade handshake, which parses one request with `httparse` and then stops.
- **What genuinely helps** (`capabilities.md` §1 "Verdict"): the io_uring runtime (multishot accept,
  multishot recv into a provided-buffer ring, sends coalesced per turn — the model that measured level
  with ringzero on echo-ws); `web_socket_server_framework.rs` (+656 lines: per-thread accept loop,
  shutdown drain, admission control) as the server skeleton; `Router`/`EndpointNode`; `MsgBufferString`;
  `serde_json`. These are reused; the protocol core is new.

## 3. Goals, non-goals, anti-goals

### Goals (MVP — the four profiles that share `/baseline11`)

- **baseline** (`rules.md` §2.1): `GET|POST /baseline11?a=13&b=42` on 8080. GET → body `55` (a+b).
  POST → body `75` (a+b+request-body-as-int). `Content-Type: text/plain`. Keep-alive; the benchmark
  holds each connection for its whole life and pipeline depth is 1.
- **limited-conn** (§2.2): identical endpoint; the client closes each connection after 10 responses with
  `SO_LINGER{1,0}` (RST, no FIN). The server must tolerate ECONNRESET/EOF mid-stream and need not close
  first. This is an accept/close-churn test at 4096 connections.
- **latency-1m / latency-10k** (§2.4): `GET /baseline11?a=1&b=2` at a fixed rate (1,000,000 / 10,000
  rps), coordinated-omission corrected. Nothing new to implement — same endpoint. Scored on cgroup
  CPU/req, p99, mean (§3 of rules). **No busy-wait, no SQ polling, no fixed-cadence timers** — all are
  charged to this profile, so the runtime must not spin here.

### Non-goals (deferred to later phases, not this plan)

- async (`/delay/{ms}` + timer wheel), json-comp (`/json` + br/gzip), json-tls (TLS h1 on 8081),
  8gbit (`POST /echo` body echo over TLS). Designed-for but not built in the MVP.
- pipelined, async-db, fortunes, static-tls, latency-500k-8cpu: reference-only, not framework-scored.
- A GET fast-path (u32/u64 literal compares) is a later optimization, not MVP correctness.

### Anti-goals (never, any tier)

- No pre-computed, pre-serialized, or cached response bodies; no response lookup keyed on URL/params
  (`tuned.md:20-24`). The validator draws random `a,b` (100..999) and random POST bodies after startup,
  so a cache would pass validation but break the written rule.
- No answering POST from `Content-Length` without reading the body; the body is summed.
- No rule-bending of the kind catalogued in `rivals.md` (dropping flow control, fake timers, etc.).
  Dropping `Date`/`Server` headers is allowed (no rule requires them; rivals do it) and is in-scope.

## 4. Constraints

- **Tuned tier** (`rules.md` §1.5, `tuned.md`): custom buffer sizes, socket options, a custom parser and
  tuned libraries are allowed. Still required: the entry "must use the framework's HTTP server (not a raw
  socket replacement); the framework dependency must be a real, published framework." rimu-ws *is* the
  framework and io_uring is its I/O, exactly as the h2/WS entries already stand — this is satisfied by
  building the parser and framer *inside* an `Http1ServerFramework`, not in the arena binary.
- **Cross-entry tier note (integration, not MVP-blocking):** the h2/WS entry is `standard` (sibling spec
  §6). A board row has one mode, so a tuned h1 implies either a separate tuned row for rimu-ws or moving
  the whole entry to tuned. Flag to the user at entry-wiring time; it does not change the server code.
- **Correctness is the gate, not speed.** The baseline validator (`validate.sh:1236-1335`,
  `scripts/validate-frag.py`) is the hard bar: 9 request shapes split at **every byte offset**
  (~1000 connections, 200 ms pauses, batches of 384); chunked bodies split mid chunk-size and mid
  terminator; 5 hand-split fragmented requests with 30 ms pauses and `Connection: close` (server must
  close after the response and the client reads to EOF); lower-case header names; GET→55, POST-CL→75,
  POST-chunked→75; random `a,b`; two POSTs with random bodies (cache check).
- **Request shapes sent byte-exact** (`requests/*.raw`): `get.raw` (60 B), `post_cl.raw` (82 B,
  `Content-Length: 2`, body `20`), `post_chunked.raw` (101 B, `Transfer-Encoding: chunked`,
  `2\r\n20\r\n0\r\n\r\n`). No `Content-Type`, no `Connection` header in the benchmark requests.
- **No model identifiers** in any committed artifact. Commits end with the Co-Authored-By line the
  session's attribution reminder specifies. TDD throughout (watch each test fail first).
- Temp/build files under `/mnt/nvme1tb/claude-tmp`. Never run two wtx test processes at once. Do not
  build during a benchmark.

## 5. Architecture

### 5.1 Protocol core with no I/O: one owned value per connection

Mirror the h2 core's shape (sibling §5.1): a sans-I/O `Http1Conn` owned by one connection task, fed
bytes and producing responses, with no locks and no task-per-request. It holds:

- an **incremental, resumable request parser** (see §5.2) with its partial state across reads;
- a **body reader** for Content-Length and chunked transfer-encoding, also resumable;
- the keep-alive state machine: after a complete request is routed and its response written, reset for
  the next request in the same read buffer (pipelining falls out for free — parse the next request where
  the last one ended), until the buffer drains or `Connection: close` is seen.

The core takes `&[u8]` and appends response bytes to an output buffer; the driver owns the sockets.

### 5.2 Hand-rolled SIMD parser (user decision), resumable by construction

The parser is written from scratch, not `httparse`. Because the validator splits requests at every byte
offset, **resumability is the primary design property, not an afterthought**: the parser is a state
machine that consumes the read buffer as far as it can, records where it stopped (mid request-line, mid
header name/value, mid CRLF, mid chunk-size, mid chunk-terminator), and resumes from exactly there when
the next bytes arrive. It never requires a whole request in one read.

- Request line and header scanning use SWAR / SSE4.2 byte-set scans (find CR, LF, ':' , SP) over the
  available bytes, degrading to a scalar tail. Slices handed to the router are zero-copy into the read
  buffer.
- Header storage is a fixed stack array (as the WS handshake uses `MAX_HEADERS = 64`), no per-request
  allocation. A request exceeding the header cap or a byte budget is answered 431/400 and the connection
  closed.
- Smuggling hardening: reject a message with both `Content-Length` and `Transfer-Encoding`; reject a
  second `Content-Length`; chunked framing is authoritative when present. (The investigation notes
  `requests/noise-*.raw` exist but are unreferenced by the harness — hardening is for correctness, not a
  scored check.)
- The GET fast-path (compare `"GET "` as u32, `" HTTP/1.1\r\n"` as u64, like zix/viltrum) is explicitly
  **out of MVP scope** — added only after the state machine is green and measured.

### 5.3 Server: one task per connection on the io_uring executor

A new `Http1ServerFramework`, structured like `web_socket_server_framework.rs` and the h2 framework:

- per-thread `SO_REUSEPORT` listener, multishot accept, one `UringRuntime` per thread
  (`set_local_runtimes` default = one per core);
- multishot recv into the thread's provided-buffer ring; the connection task feeds received bytes to its
  `Http1Conn` and writes the coalesced response with one send per turn;
- admission control, handshake/idle timeouts and the shutdown drain reused from the WS skeleton;
- `Connection: close` (or HTTP/1.0 without keep-alive) → write the response, then close; the validator's
  fragmentation test depends on the server closing so the client's read-to-EOF completes;
- a peer RST mid-request (limited-conn) ends the task cleanly, counted as a normal close, not an error.

**Timeout, resolved (builder-check Q4 — my call):** the validator holds ~1000 connections open with
200 ms mid-request pauses (30 ms for the `Connection: close` cases), so any read/idle timeout **must be
measured from the last byte received and reset on every read of progress** — never a hard deadline from
accept, and never a per-request header-read deadline below ~1 s. The WS skeleton's idle timeout (300 s
default) and handshake timeout (10 s) both sit far above the validator's pauses, so reusing them is safe;
the constraint is only that the h1 loop resets the idle clock on each received chunk, which the MVP must
implement and a fragmentation test must prove.

### 5.4 Response writing

Status line + minimal headers (`Content-Type`, `Content-Length`) + body, appended to the output buffer.
No `Date`, no `Server` in the hot path (allowed; a 63 B baseline response is what the leading io_uring
entries emit). The baseline body is the decimal sum computed per request from the parsed `a`, `b` and
(for POST) the body integer — never cached.

### 5.5 Latency profiles: no spin

latency-1m/10k run on this same server with no code change, but the runtime must not busy-poll on these
profiles (spin, SQ-poll and fixed-cadence timers are charged to the score). The io_uring runtime's
`set_spin` stays 0 for the h1 server (the h2 spec already found h2 level without spin). This is a config
constraint on the arena entry, recorded here so the plan's entry task sets it.

### 5.6 Router / endpoints

**Resolved (builder-check Q3 — my call):** the h2 handler layer (`HttpRouter`, the `StreamDispatcher`
trait, `ServerStream`, the auto/manual `AutoOutput`/`SharedBytes` futures) is tightly h2-coupled. The MVP
does **not** generalize it across protocols — that would perturb the just-finished, still-in-review h2
code for no MVP gain. Instead the h1 server reuses only the **protocol-agnostic** pieces — the low-level
radix `Router`, `EndpointNode`, and `MsgBufferString` — behind a small **h1-local dispatcher**, so
`/baseline11` is a real routed endpoint with request extraction and response building (completeness axes;
sibling §6), and at least one real middleware (e.g. the `server`-header middleware the h2 entry defines)
keeps the `middleware` axis true. A single handler abstraction shared by h1 and h2 is a later refactor,
not MVP. serde_json is not needed until the json profiles.

## 6. HttpArena entry (local only)

Add `baseline`, `limited-conn`, `latency-1m`, `latency-10k` to `frameworks/rimu-ws`, experimental league,
**tuned** mode (per the tier decision; reconcile with the h2/WS row at wiring time — §4). The h1 server
listens on **8080**. Note the WebSocket echo entry also uses 8080 for `/ws`; an h1 server naturally
subsumes that (a WS upgrade is an h1 request), but the MVP need not serve `/ws` — keep the WS entry's
8080 role separate unless the user wants them merged. `local-src.sh` copies the worktree into the entry
before `docker build`, as for h2. **Never push to HttpArena or upstream.**

## 7. Done means

- The full baseline validator passes: GET→55, POST-CL→75, POST-chunked→75, `Content-Type: text/plain`,
  random `a,b`, random-body POST cache check, lower-case headers, the 5 fragmented + `Connection: close`
  cases, and `scripts/validate-frag.py`'s ~1000-connection byte-offset fragmentation gauntlet (including
  chunked split mid-size and mid-terminator).
- limited-conn's RST-after-10 behaviour is handled as a clean close (no error logged, no leak).
- The whole wtx suite is green and the server builds for the arena entry; h1 added to the entry locally.
- Performance is measured (cycles/req and rps on baseline at 4096 conns) and reported, but a number is
  not the gate — correctness is. **Measurement tool (builder-check Q5 — my call):** use the arena's own
  h1 generator, `gcannon`, locally (as the h2 work used `h2load`), for a single self-reported baseline
  rps + cycles/req figure. Standing up a full rival composite rig (plod/viltrum/aegon) is deferred until
  the MVP is correct — unless the done-bar decision below says otherwise. A GET fast-path is a follow-up
  if measurement warrants it.

## 8. Review focus (inputs the tests must exercise deliberately)

1. A request delivered one byte per read at every split point — parser resumes correctly at each.
2. Chunked body split mid chunk-size digits and mid `\r\n` terminator; zero-length final chunk.
3. Pipelined requests arriving in one read (two complete requests back-to-back in the buffer).
4. `Connection: close` → server writes response then closes; client read-to-EOF sees the full body.
5. Peer RST / EOF mid-request (limited-conn) → task ends clean, connection slot reused.

## 9. Calls left to the builder

- The exact `Http1Conn` API (method names, how the driver feeds bytes and drains output) — follow the h2
  core's naming where it transfers.
- Parser internal representation of partial state; SIMD intrinsic vs SWAR per scan (both allowed) —
  choose by what passes the gauntlet first, optimize after.
- Whether `/ws` is served by the same listener in a later phase (integration with the WS entry).
- Reconciling the tuned h1 row with the standard h2/WS row — the user decides at entry-wiring time.

## 10. Decisions resolved (from the builder-check, 7 Nov)

1. **Done-bar = lean MVP** (user). The gate is §7: the HttpArena baseline validator green (incl. the
   byte-offset fragmentation gauntlet), limited-conn clean close, wtx suite green, builds for the entry,
   one self-reported perf figure (gcannon). The full h2-style production gate (differential fuzzer +
   model, Miri/ASan, abusive-client soak, interop) does **not** carry over to this plan — revisit after
   the MVP ships and measures. A cargo-fuzz/differential target for the resumable parser was offered as
   a middle option and not taken; it remains the obvious first hardening step post-MVP.
2. **Port 8080 = separate h1 entry/row** (user). h1 is its own HttpArena entry (own container) binding
   8080 for the h1 benchmarks, independent of the live echo-ws entry — zero risk to the scored WS row,
   and no shared-listener dispatch needed for the MVP. The h1 server need not serve `/ws` at all.
3. **Base branch = main, after merging h2** (user). `feat/http2-driver` was fast-forward-merged into
   local `main` (now `73abd1f8`; not pushed) on 7 Nov after the full suite passed (394 lib + 160
   integration + doctests, 0 failed). The h1 worktree branches from `main`, which now carries the
   `Http2Conn` core and the shared framework module the h1 core builds on.
