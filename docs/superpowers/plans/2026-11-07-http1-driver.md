# HTTP/1.1 server (MVP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A tuned-tier HTTP/1.1 keep-alive server in rimu-ws that answers `GET|POST /baseline11?a=&b=` on port 8080 and passes HttpArena's full baseline validator, unlocking the baseline, limited-conn, latency-1m and latency-10k profiles.

**Architecture:** A sans-I/O `Http1Conn` core (hand-rolled resumable SIMD request parser + Content-Length/chunked body decoder + response writer + keep-alive state machine), owned one-per-connection and pumped by an `Http1ServerFramework` driver on the io_uring executor — the same shape as the HTTP/2 core/driver and the WebSocket framework it sits beside. A separate HttpArena entry/row binds 8080 and runs the four profiles.

**Tech Stack:** Rust, `no_std`+`alloc` wtx crate, io_uring (`UringExecutor`/`UringRuntime`), the protocol-agnostic radix `Router`, `MsgBufferString`. Hand-rolled SIMD/SWAR parsing (no `httparse`).

**Spec:** `docs/superpowers/specs/2026-11-07-http1-driver-design.md` (read it alongside this plan; §2.1–2.4 and §3 of `/mnt/nvme1tb/claude-tmp/httpwin/rules.md` carry the exact request/response bytes and the validator behaviour).

## Global Constraints

- **Base branch:** local `main` @ `73abd1f8` (now carries the merged h2 core + shared framework module). The execution worktree is cut from `main` via superpowers:using-git-worktrees at setup, under `/mnt/nvme1tb/claude-tmp`.
- **Tier = tuned:** custom parser, buffer sizes and socket options are allowed; the server is still a framework server on the io_uring runtime, not a per-request raw-socket hack. No pre-computed, pre-serialized, or cached response bodies; no response lookup keyed on URL/params — the baseline body is summed per request.
- **Correctness is the gate, not speed.** The deliverable is "the validator passes"; a perf figure is reported, not required.
- **No model identifiers** anywhere in code, comments, commit bodies, or the HttpArena entry. The only exception is the commit-message `Co-Authored-By:` trailer, which is the line from the executing session's attribution reminder.
- **Never push** to the HttpArena or upstream remotes. The HttpArena entry is local only.
- Never run two wtx test processes at once; do not build during a benchmark. Temp/build files under `/mnt/nvme1tb/claude-tmp`.
- New crate feature: `http1-server-framework` (gates the whole `http1` module and `http/http1_server_framework.rs`).

## Review Focus

1. **A request delivered a few bytes per read, split at any offset** (request line, header name/value, the blank line) — the parser must report "need more" without error and complete once the head arrives. → Task 2.
2. **Chunked body split mid chunk-size digits and mid `\r\n` terminator, and the zero-length final chunk** — the decoder must resume correctly and not over/under-read. → Task 3.
3. **Two complete requests back-to-back in one read (pipelining)** — the core must answer the first, then parse the second from where the first ended. → Task 5.
4. **`Connection: close` (and HTTP/1.0 without keep-alive)** — the server writes the response, then closes, so the client's read-to-EOF completes. → Task 6.
5. **Peer RST / EOF mid-request (limited-conn closes after 10 with `SO_LINGER{1,0}`)** — the connection task ends cleanly, counted as a normal close, not an error, and the slot is reused. → Task 6.

---

### Task 1: Scaffold the `http1` module, feature, and shared types

Creates the module, the feature flag, and the compiling stubs the parallel group (Tasks 2–4) builds against. This is the only task that touches the shared type file; afterwards Tasks 2, 3 and 4 are independent and may run in parallel.

**Files:**
- Modify: `wtx/Cargo.toml` (add `http1-server-framework` feature; it enables `io-uring` and the deps the module needs)
- Modify: `wtx/src/lib.rs` (gate `pub mod http1;`)
- Create: `wtx/src/http1.rs` (module root: re-exports + shared types)
- Create: `wtx/src/http1/parser.rs`, `wtx/src/http1/body.rs`, `wtx/src/http1/response.rs`, `wtx/src/http1/conn.rs` (stubs)

**Interfaces — Produces** (the exact shared types and stub signatures; stubs compile with `todo!()`):

```rust
pub const MAX_HEADERS: usize = 64;

pub enum BodyKind { None, ContentLength(usize), Chunked }

// Borrowed view into the read buffer; no allocation.
pub struct Http1Request<'b> {
  pub method: crate::http::Method,
  pub path: &'b str,          // percent-encoded path, no query
  pub query: &'b str,         // after '?', "" if none
  pub headers: &'b [(&'b str, &'b str)],
  pub body_kind: BodyKind,
  pub keep_alive: bool,       // false => respond then close
}

// Parser (Task 2)
pub enum ParseOutcome<'b> { Complete { request: Http1Request<'b>, head_len: usize }, Partial }
pub struct ParseScratch { /* fixed [(span,span); MAX_HEADERS] + counts */ }
impl ParseScratch { pub fn new() -> Self }
pub fn parse_request<'b>(buf: &'b [u8], scratch: &'b mut ParseScratch)
  -> crate::Result<ParseOutcome<'b>>;

// Body decoder (Task 3)
pub enum BodyStatus { NeedMore, Complete { consumed: usize } }
pub struct BodyDecoder { /* kind + resume state */ }
impl BodyDecoder {
  pub fn new(kind: BodyKind) -> Self;
  pub fn feed(&mut self, input: &[u8], out: &mut alloc::vec::Vec<u8>) -> crate::Result<BodyStatus>;
}

// Response writer (Task 4)
pub fn write_response(out: &mut alloc::vec::Vec<u8>, status: crate::http::StatusCode,
  content_type: &str, body: &[u8], keep_alive: bool);

// Keep-alive core (Task 5)
pub enum Http1Event { RequestReady, NeedMore, Closed }
pub struct Http1Conn { /* private */ }
impl Http1Conn {
  pub fn new(params: &crate::http::HttpRecvParams) -> Self;
  pub fn feed(&mut self, input: &[u8]) -> crate::Result<usize>;
  pub fn poll_event(&mut self) -> Http1Event;
  pub fn request(&self) -> Option<Http1Request<'_>>;   // valid only right after RequestReady
  pub fn respond(&mut self, status: crate::http::StatusCode, content_type: &str, body: &[u8]);
  pub fn take_output(&mut self, spare: alloc::vec::Vec<u8>) -> Result<alloc::vec::Vec<u8>, alloc::vec::Vec<u8>>;
  pub fn advance_output(&mut self, n: usize);
  pub fn wants_close(&self) -> bool;
}
```

- [ ] **Step 1: Write the failing test** `wtx/src/http1.rs` test module: `scaffold_types_exist` constructs `ParseScratch::new()`, `BodyDecoder::new(BodyKind::None)`, and a `Http1Conn::new(&HttpRecvParams::with_default_params())`, and asserts `BodyKind::ContentLength(2)` matches by value.
- [ ] **Step 2: Run it to verify it fails** — Run: `cargo test -q -p rimu-ws --features http1-server-framework --lib http1::` Expected: FAIL to compile (`http1` module / types not found).
- [ ] **Step 3: Add the `http1-server-framework` feature to `wtx/Cargo.toml` and `pub mod http1;` (feature-gated) to `wtx/src/lib.rs`.**
- [ ] **Step 4: Create `http1.rs` + the four submodule files with the types above and `todo!()` bodies for every fn.** Keep `parse_request`, `BodyDecoder::feed`, `write_response` and all `Http1Conn` methods as `todo!()`.
- [ ] **Step 5: Run the test to verify it passes** — Run: same command. Expected: PASS (the scaffold test touches only constructors, not `todo!()` paths).
- [ ] **Step 6: Commit** `feat: scaffold http1 module, feature and shared types`.

---

### Task 2: Hand-rolled SIMD request parser (resumable)  — PARALLEL with Tasks 3, 4

**Files:**
- Modify: `wtx/src/http1/parser.rs` (implement `parse_request` + `ParseScratch`)
- Test: in `wtx/src/http1/parser.rs` `#[cfg(test)]`

**Interfaces — Consumes:** the Task 1 types (`Http1Request`, `ParseOutcome`, `ParseScratch`, `BodyKind`, `MAX_HEADERS`). **Produces:** `parse_request` (signature from Task 1).

**Contract (what the body must satisfy, the implementer writes the SIMD/SWAR):** pure over the current `buf`; returns `Partial` (no error) whenever the head is not yet complete through the blank line `\r\n\r\n`; returns `Complete { head_len }` with `head_len` = bytes up to and including the blank line (body excluded); fills `scratch` with header name/value spans (lower-cased comparison for known names). `body_kind` derived from headers: `Transfer-Encoding: chunked` → `Chunked`; else `Content-Length: N` → `ContentLength(N)`; else `None`. `keep_alive` = not (`Connection: close` present or HTTP/1.0 without `Connection: keep-alive`). Errors (`crate::Error`): both `Content-Length` and `Transfer-Encoding` present; two `Content-Length`; header count > `MAX_HEADERS`; head bytes > a 16 KiB cap; malformed request line/version.

- [ ] **Step 1: Write the failing tests** (names + assertions):
  - `parses_get_baseline` — `GET /baseline11?a=13&b=42 HTTP/1.1\r\nHost: localhost:8080\r\n\r\n` → Complete, method GET, path `/baseline11`, query `a=13&b=42`, `body_kind` None, `keep_alive` true, `head_len == 60`.
  - `parses_post_content_length` — `post_cl.raw` bytes → Complete, method POST, `body_kind` ContentLength(2), `head_len == 80` (head only, body `20` excluded).
  - `parses_post_chunked` — `post_chunked.raw` head → Complete, `body_kind` Chunked.
  - `partial_returns_partial_at_every_split` — for each prefix length `1..full` of `get.raw`, `parse_request` returns `Partial` (not Err) until the full head is present, then `Complete`.
  - `lowercase_header_names_match` — `host:`/`content-length:` lower-case still classify.
  - `rejects_cl_and_te` and `rejects_double_cl` — both → Err.
  - `rejects_too_many_headers` — 65 headers → Err.
- [ ] **Step 2: Run to verify they fail** — Run: `cargo test -q -p rimu-ws --features http1-server-framework --lib http1::parser` Expected: FAIL (`todo!()` panics / assertion).
- [ ] **Step 3: Implement `parse_request` + `ParseScratch`** in `parser.rs` using SIMD/SWAR byte-set scans (CR, LF, ':', SP) with a scalar tail; zero-copy spans into `buf`.
- [ ] **Step 4: Run to verify they pass** — same command. Expected: PASS.
- [ ] **Step 5: Commit** `feat: http1 hand-rolled resumable request parser`.

---

### Task 3: Content-Length and chunked body decoder (resumable)  — PARALLEL with Tasks 2, 4

**Files:**
- Modify: `wtx/src/http1/body.rs` (implement `BodyDecoder`)
- Test: `wtx/src/http1/body.rs` `#[cfg(test)]`

**Interfaces — Consumes:** `BodyKind`, `BodyStatus` (Task 1). **Produces:** `BodyDecoder::{new, feed}` (Task 1 signatures).

**Contract:** `feed` appends decoded body bytes to `out`, returns `Complete { consumed }` when the body ends (`consumed` = input bytes used, so the caller can continue with a pipelined next request), or `NeedMore`. Resumable across calls: chunk-size digits split across feeds, the `\r\n` terminators split, and the `0\r\n\r\n` final chunk split. `ContentLength(0)` and `None` complete immediately with `consumed 0`. Errors on a malformed chunk size (non-hex) or a chunk-size overflow.

- [ ] **Step 1: Write the failing tests:**
  - `content_length_exact` — `BodyKind::ContentLength(2)`, feed `b"20"` → Complete{consumed:2}, out == `b"20"`.
  - `content_length_split` — feed `b"2"` then `b"0"` → NeedMore then Complete, out == `b"20"`.
  - `chunked_single` — feed `b"2\r\n20\r\n0\r\n\r\n"` → Complete, out == `b"20"`.
  - `chunked_split_mid_size` and `chunked_split_mid_terminator` — the same bytes delivered one byte per feed → Complete, out == `b"20"`, total consumed == input len.
  - `chunked_zero_only` — `b"0\r\n\r\n"` → Complete, out empty.
  - `rejects_bad_chunk_size` — `b"zz\r\n"` → Err.
- [ ] **Step 2: Run to verify they fail** — Run: `cargo test -q -p rimu-ws --features http1-server-framework --lib http1::body` Expected: FAIL.
- [ ] **Step 3: Implement `BodyDecoder`** as a small resumable state machine (`ContentLength{ remaining }`, `Chunked{ phase }`).
- [ ] **Step 4: Run to verify they pass** — same command. Expected: PASS.
- [ ] **Step 5: Commit** `feat: http1 resumable content-length and chunked body decoder`.

---

### Task 4: Response writer  — PARALLEL with Tasks 2, 3

**Files:**
- Modify: `wtx/src/http1/response.rs` (implement `write_response`)
- Test: `wtx/src/http1/response.rs` `#[cfg(test)]`

**Interfaces — Consumes:** `crate::http::StatusCode` (existing). **Produces:** `write_response` (Task 1 signature).

**Contract:** appends `HTTP/1.1 <code> <reason>\r\n`, `Content-Type: <content_type>\r\n`, `Content-Length: <body.len()>\r\n`, then `Connection: close\r\n` iff `!keep_alive`, then `\r\n`, then `body`. No `Date`, no `Server` header.

- [ ] **Step 1: Write the failing tests:**
  - `writes_keep_alive_200` — status 200, `text/plain`, body `b"55"`, keep_alive true → exact bytes `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n55` (assert no `Connection:`, no `Date`, no `Server`).
  - `writes_connection_close` — keep_alive false → includes `Connection: close\r\n`.
- [ ] **Step 2: Run to verify they fail** — Run: `cargo test -q -p rimu-ws --features http1-server-framework --lib http1::response` Expected: FAIL.
- [ ] **Step 3: Implement `write_response`** (reuse `StatusCode`'s reason text).
- [ ] **Step 4: Run to verify they pass** — same command. Expected: PASS.
- [ ] **Step 5: Commit** `feat: http1 response writer (no date/server headers)`.

---

### Task 5: `Http1Conn` keep-alive core (ties parser + body + writer)

Joins the parallel group. Depends on Tasks 2, 3, 4.

**Files:**
- Modify: `wtx/src/http1/conn.rs` (implement `Http1Conn`)
- Test: `wtx/src/http1/conn.rs` `#[cfg(test)]`

**Interfaces — Consumes:** `parse_request`, `BodyDecoder`, `write_response`, `Http1Request`, `Http1Event` (Tasks 1–4). **Produces:** `Http1Conn` methods (Task 1 signatures).

**Contract:** `feed(input)` accumulates into an internal buffer and advances the state machine; `poll_event()` returns `RequestReady` once a full request (head + body per `body_kind`) is available — the handler then reads `request()` (borrow), extracts what it needs, and calls `respond(...)`, which `write_response`s into the output buffer and advances the keep-alive state to parse the next request from the leftover bytes (pipelining). `NeedMore` when the buffer holds no complete request; `Closed` once `wants_close()` (a `Connection: close` request was answered) and the output is drained. `take_output`/`advance_output` mirror `Http2Conn` for the driver's send path. The decoded POST body is exposed to the handler via `request()` (a `&[u8]` field added to `Http1Request` for the body, or a `Http1Conn::body()` accessor — implementer's call, pin it in this task's Produces).

- [ ] **Step 1: Write the failing tests:**
  - `get_request_ready_then_needmore` — feed `get.raw`, `poll_event` → RequestReady, `request()` method GET; after `respond`, next `poll_event` → NeedMore.
  - `post_body_available` — feed `post_cl.raw` full → RequestReady, decoded body `b"20"` reachable; chunked variant same.
  - `pipelined_two_requests` — feed two `get.raw` concatenated in one `feed`; first RequestReady→respond, second RequestReady→respond; output holds two responses.
  - `request_split_across_feeds` — `get.raw` fed one byte at a time → NeedMore until complete, then one RequestReady.
  - `connection_close_sets_wants_close` — a request with `Connection: close` → after respond, `wants_close()` true.
- [ ] **Step 2: Run to verify they fail** — Run: `cargo test -q -p rimu-ws --features http1-server-framework --lib http1::conn` Expected: FAIL.
- [ ] **Step 3: Implement `Http1Conn`** — internal accumulation buffer, a `ParseScratch`, an optional `BodyDecoder` per in-flight request, the output `Vec<u8>`, and the keep-alive flag; reset per request, compact the buffer after consuming a request.
- [ ] **Step 4: Run to verify they pass** — same command. Expected: PASS.
- [ ] **Step 5: Commit** `feat: http1 keep-alive connection core`.

---

### Task 6: `Http1ServerFramework` and io_uring driver

Depends on Task 5. Mirrors `web_socket_server_framework.rs` (accept/shutdown/admission) and `http2_server_framework/conn_driver.rs` (per-connection task, recv→feed→send, buffer pools).

**Files:**
- Create: `wtx/src/http/http1_server_framework.rs` (builder + `run_in_threads`)
- Create: `wtx/src/http/http1_server_framework/conn_driver.rs` (the per-connection drive loop)
- Modify: `wtx/src/http.rs` (gate the new module)
- Test: `wtx/src/http/http1_server_framework.rs` `#[cfg(test)]` (loopback tests on `UringRuntime`, 1 thread, like the WS framework's own tests)

**Interfaces — Consumes:** `Http1Conn` (Task 5); `UringExecutor`/`UringRuntime`, `TcpParams`, `ShutdownSignal`, the radix `Router`/`RouterBuilder`/`RouterMatch` (existing). **Produces:** builder mirroring the WS one:
`Http1ServerFramework::{ new(executor, rng_or_unit, …), set_error_cb, set_local_runtime_cb, set_local_runtimes, set_max_connections, set_shutdown, set_tcp_params, set_http_recv_params, set_data, run_in_threads(addr, router) }`. The handler surface: an h1-local dispatcher that looks up the request path in the radix `Router` and invokes the matched endpoint with the request + a response sink; at least one real middleware hook (the `server`-header middleware the h2 entry defines, or an equivalent) so the `middleware` completeness axis is true.

**Driver behaviour to pin:** multishot accept + recv into the per-thread provided-buffer ring; feed received bytes to the connection's `Http1Conn`; on `RequestReady`, run the routed handler and write the coalesced response with one send per turn; on `wants_close()` write then close so the client reads to EOF; a peer RST/EOF mid-request ends the task as a normal close (no error logged); **the idle/read timeout resets on every received chunk and never applies a hard from-accept deadline** (so the validator's 200 ms mid-request pauses never trip it); idle buffers return to per-thread pools as in h2.

- [ ] **Step 1: Write the failing tests** (loopback on 127.0.0.1 : ephemeral port, `UringRuntime`, 1 runtime thread):
  - `serves_one_get` — a raw client writes `GET /ping HTTP/1.1\r\nHost: x\r\n\r\n` to a router with `/ping` → 200 body `pong`; client reads the full response.
  - `keep_alive_two_requests_one_connection` — two GETs on one socket → two responses.
  - `connection_close_then_eof` — a `Connection: close` request → response then the socket reaches EOF (read returns 0).
  - `peer_rst_midrequest_is_clean` — client writes a partial head then closes with SO_LINGER{1,0}; the server task ends without logging an error and the listener keeps serving (a following connection still gets 200).
  - `fragmented_request_with_pauses` — the request delivered in 3 writes with ~50 ms sleeps → still a single 200 (guards the no-hard-deadline rule).
- [ ] **Step 2: Run to verify they fail** — Run: `cargo test -q -p rimu-ws --features http1-server-framework,io-uring --lib http1_server_framework` Expected: FAIL (framework not implemented).
- [ ] **Step 3: Implement the framework + driver**, reusing the WS framework's accept/shutdown/admission skeleton and the h2 driver's pool/recv/send patterns.
- [ ] **Step 4: Run to verify they pass** — same command. Expected: PASS. Then run the whole lib suite once: `cargo test -q -p rimu-ws --features http1-server-framework,http2-server-framework,http2-client-pool,grpc-client,grpc-server,io-uring,crypto-ring,serde_json,_integration-tests,web-socket,json-writer --lib` Expected: all pass (no regression).
- [ ] **Step 5: Commit** `feat: http1 server framework on the io_uring executor`.

---

### Task 7: `arena-h1` binary, HttpArena entry, and the validator gauntlet

Depends on Task 6. This is the correctness gate and the only task that touches `~/src/HttpArena` (local only, never pushed). It also carries the latency-1m/10k profiles, which need no new server code — only the entry config (no-spin runtime) and the profile list.

**Files:**
- Create: `wtx-internal/src/bin/arena-h1.rs` (the `/baseline11` handler + `Http1ServerFramework` on `0.0.0.0:8080`, no-spin `UringParams`)
- Modify: `wtx-internal/Cargo.toml` (`arena-h1` bin + `arena-h1` feature)
- Create (local only, under `~/src/HttpArena/frameworks/rimu-ws-h1/`): the separate entry — `Dockerfile`, `meta.json` (experimental, **tuned**, profiles `baseline`, `limited-conn`, `latency-1m`, `latency-10k`), `README.md`, `local-src.sh` (copies the worktree into a git-excluded `rimu-ws/`), mirroring the existing `frameworks/rimu-ws` h2 entry.

**Interfaces — Consumes:** `Http1ServerFramework` (Task 6). **Produces:** the `/baseline11` handler: GET → body = `a + b`; POST → body = `a + b + <body-as-i64>`; `Content-Type: text/plain`; values parsed from the query each request (never cached).

- [ ] **Step 1: Write the failing test** — a unit test of the pure handler sum `baseline11_sum(a: i64, b: i64, body: Option<&[u8]>) -> i64` in `arena-h1.rs`: GET(13,42,None)→55; POST(13,42,Some(b"20"))→75; random a,b in 100..999 sum correctly.
- [ ] **Step 2: Run to verify it fails** — Run: `CARGO_TARGET_DIR=/mnt/nvme1tb/claude-tmp/target-h1 cargo test -q -p wtx-internal --features arena-h1 --bin arena-h1` Expected: FAIL (fn absent).
- [ ] **Step 3: Implement `baseline11_sum` and wire the handler + framework on 8080** with a no-spin `UringParams` (spin 0) and a router registering `/baseline11`.
- [ ] **Step 4: Run to verify it passes** — same command. Expected: PASS. Build the binary: `CARGO_TARGET_DIR=/mnt/nvme1tb/claude-tmp/target-h1 cargo build --release -p wtx-internal --features arena-h1 --bin arena-h1`.
- [ ] **Step 5: Run the HttpArena baseline validator against the running server** — start `arena-h1` on 8080 (pin cores, log errors), then run the local validator for the baseline profile (`~/src/HttpArena/scripts/validate.sh` + `scripts/validate-frag.py`, as the h2 work ran it from `/mnt/nvme1tb/claude-tmp/arena-main`); kill the server by PID afterwards. Expected: the baseline validation suite passes (GET 55 / POST-CL 75 / POST-chunked 75, Content-Type, random a,b, random-body cache check, lower-case headers, the 5 fragmented + `Connection: close` cases, and the ~1000-connection byte-offset fragmentation gauntlet including chunked split mid-size/mid-terminator), 0 failed.
- [ ] **Step 6: Report a baseline perf figure** — one `gcannon` run at 4096 conns (rps + cycles/req), recorded in `docs/perf/http1-bench.md`. Not a gate.
- [ ] **Step 7: Commit** `feat: arena-h1 entry serving /baseline11; baseline validator green` (the HttpArena entry files under `~/src/HttpArena` are committed in that local repo, never pushed).

---

## Self-Review

**1. Spec coverage.** baseline/limited-conn/latency (§3 goals) → Tasks 6 (RST tolerance, no-deadline) + 7 (endpoint, no-spin, profiles). Parser/body/writer/core (§5.1–5.4) → Tasks 2–5. Framework/driver + dispatcher/middleware (§5.3, §5.6) → Task 6. Entry (§6) → Task 7. Timeout resolution (§5.3) → Task 6 tests. No-spin (§5.5) → Task 7. Measurement (§7) → Task 7 Step 6. No gaps.

**2. Step scan.** The SIMD parser and body state machine are left as contracts + tests, not transcribed bodies (the implementer writes the craft). Signatures are pinned in Task 1 so the parallel group shares exact types. No empty "handle edge cases" lines.

**3. Type consistency.** `Http1Request`, `ParseOutcome`, `ParseScratch`, `BodyKind`, `BodyStatus`, `BodyDecoder`, `write_response`, `Http1Conn`, `Http1Event` are defined once in Task 1 and consumed by name in Tasks 2–7. The one open representation choice (how the handler reads the decoded POST body) is explicitly pinned in Task 5's Produces.

**4. Review Focus.** All five input classes map to a test: fragmentation → T2 `partial_returns_partial_at_every_split`; chunked splits → T3 `chunked_split_*`; pipelining → T5 `pipelined_two_requests`; `Connection: close` → T6 `connection_close_then_eof`; peer RST → T6 `peer_rst_midrequest_is_clean`.

**5. Proportion.** The plan pins interfaces and tests and defers all bodies; it is shorter than the code it describes. Good.

## Parallelism map (for subagent-driven execution)

- **Task 1** first (defines shared types; everything blocks on it).
- **Tasks 2, 3, 4** are mutually independent (separate files, shared types already fixed) → dispatch concurrently.
- **Task 5** after 2+3+4 (joins them).
- **Task 6** after 5. **Task 7** after 6.

Maximum concurrency is the 3-wide parser/body/writer group; the core→driver→entry tail is inherently sequential because each consumes the previous deliverable.
