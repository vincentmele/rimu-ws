# HTTP/2 batch-driven connection core: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite rimu-ws's `http2` module around a synchronous per-connection protocol core. The core
drives an io_uring server that reads in batches and writes in batches, and the client and gRPC run on the
same core. The work then passes the production gate and ranks #1 against plod, viltrum and aegon on a local
HttpArena HTTP/2 composite.

**Architecture:** A new `Http2Conn<IS_CLIENT>` owns all of a connection's protocol state: HPACK, windows,
SETTINGS, the stream slab and the output buffer. It parses every frame from a byte slice, and queues
encoded frames into its output. The server runs one task per connection on `UringExecutor`. That task feeds
everything it read, runs auto-mode handlers inline in reusable pinned slots, and queues one send per turn.
Manual-mode streams and the client talk to the core through same-thread handles (server) or one short lock
(client). The old `Arc`/`AsyncMutex` driver, the frame-reader task and the 50 ms linger are deleted.

**Tech stack:** Rust nightly, crate `rimu-ws` (directory `wtx/`), `UringExecutor` (`io-uring` feature),
the crate's own TLS 1.3 + kTLS, h2load (nghttp2 1.59 from Ubuntu 24.04, run in docker), h2spec 2.6.0
(docker), and the `rimu-ws-soak` crate.

**Spec:** `docs/superpowers/specs/2026-11-05-http2-driver-design.md`. Background reports, outside the repo,
are in `/mnt/nvme1tb/claude-tmp/httpwin/`. `rules.md` gives the HttpArena profiles, flags and rules, and
`capabilities.md` and `rivals.md` give our current state and the rivals' techniques.

## Global constraints

- Worktree `/mnt/nvme1tb/claude-tmp/rimu-h2`, branch `feat/http2-driver`. Never push. Never touch
  HttpArena's or upstream wtx's remotes.
- Build output goes outside `/tmp`:
  - `export CARGO_TARGET_DIR=/mnt/nvme1tb/claude-tmp/target-h2`
  - `export TMPDIR=/mnt/nvme1tb/claude-tmp`
- Test features (referred to as `$FEAT`):
  `export FEAT=http2-server-framework,http2-client-pool,grpc-client,grpc-server,io-uring,crypto-ring,serde_json,_integration-tests`
- Test command: `cargo test -p rimu-ws --features "$FEAT" --lib <filter>`.
  - Never enable `tokio` in these runs; upstream's tokio tests fail on `Sleep`.
  - Never run two test processes at once: `SO_REUSEPORT` splits their connections.
- Licence: no per-file headers. `NOTICE` covers the fork's files under MPL-2.0. `rimu-ws-soak/` is
  Apache-2.0 and must not depend on rimu-ws.
- Strict HttpArena posture:
  - every response carries `content-type` and a correct `date`;
  - JSON is serialized per request;
  - no response caches and no pre-rendered bodies;
  - static files come through the framework's handler, and its cache follows the disk within 2 s;
  - flow control is honoured for every body size.
- The server runs only on `UringExecutor`. The client must still work on any runtime the crate supports,
  tokio included.
- **Standard mode:** the HttpArena entry may set only the library's defaults, or settings the rimu-ws
  production guide (Task 13) recommends.
- Keep the HPACK, Huffman and `*_frame.rs` files in place and with the same names, so upstream merges stay
  easy.
- colossus CPU split for every measurement:
  - server on `0-5,12-17`;
  - load on `6-11,18-23`;
  - h2load `-t 12` (HttpArena's `-t 64` scaled to 12 load CPUs);
  - `-D 5s`, best of 3, in a fresh server process per (profile, conns).
- Commit after every task, with this trailer:

  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  ```

## Review focus

The inputs the spec implies but no task's main tests cover. Each one has a pinning test in the task named.

1. **The peer lowers SETTINGS_INITIAL_WINDOW_SIZE mid-stream**, so open streams' send windows go negative
   (RFC 9113 §6.9.2). Expected: no data is sent until WINDOW_UPDATE makes the window positive, and
   nothing is dropped. Test: `conn_settings_shrink_window_goes_negative` (Task 5).
2. **The peer sets SETTINGS_HEADER_TABLE_SIZE=0 after responses were cached** (or changes the table size).
   Expected: the header-block cache is invalidated, a size update is emitted, and later responses still
   decode. Test: `conn_header_cache_invalid_after_table_size_change` (Task 6).
3. **RST_STREAM, or the connection closing, on a stream whose handler is parked.** Expected: the parked
   future is dropped, no frame is sent for that stream, and no panic. Test:
   `server_reset_drops_parked_handler` (Task 8).
4. **A client posts a body larger than the initial stream window to an auto-mode endpoint.** Expected:
   the server replenishes the window as the body is buffered (up to `max_body_len`), and the request
   completes. Test: `server_auto_body_larger_than_window` (Task 8).
5. **On TLS, the client's preface and first HEADERS arrive in the same read as its Finished.** Expected:
   the request is answered, and kTLS is enabled once the buffered plaintext drains. Test:
   `server_tls_preface_with_finished_uses_ktls` (Task 9; skipped when `/proc/net/tls_stat` is absent).

---

## Phase A: measurement harness

### Task 1: Load, rival and baseline harness

**Files:**
- Create: `.scripts/h2-bench.sh`, `.scripts/h2-composite.py`, `wtx-internal/src/bin/arena-h2.rs`,
  `docs/perf/http2-bench.md`
- Modify: `wtx-internal/Cargo.toml` (add a feature `arena-h2` and a `[[bin]]` `arena-h2` with
  `required-features = ["arena-h2"]`)

**Interfaces:**
- Produces:
  - `.scripts/h2-bench.sh SERVER PROFILE CONNS`
    - `SERVER` is `rimu` (the native `arena-h2` binary) or `plod` / `viltrum` / `aegon` (docker images
      `httparena-<name>`).
    - `PROFILE` is one of `baseline-h2`, `static-h2`, `baseline-h2c`, `json-h2c`.
    - It prints one JSON line:
      `{"server","profile","conns","rps":[r1,r2,r3],"best","load_cpu_pct","server_ucyc_per_req"}`.
      `server_ucyc_per_req` is null for docker rivals.
  - `.scripts/h2-composite.py RESULTS.jsonl` prints the per-profile points and the composite, using the
    board formula: sum over profiles of 1000 × mean-over-scored-conns(best rps) / the field's best.
  - `arena-h2`:
    - serves `/baseline2` (sum of the `a`, `b` query values, `text/plain`) and `/json/{count}?m=` (the
      upstream wtx-http2 entry's handler and dataset types, read from `DATASET_PATH`, default
      `/data/dataset.json`);
    - h2c on `0.0.0.0:8082`;
    - TLS h2 on `0.0.0.0:8443`, with `/certs/server.crt` and `/certs/server.key`, overridable by the env
      vars `CERT_DIR` and `STATIC_DIR` (default `/data/static`);
    - the `Server` header comes from a middleware, not the handler.

- [ ] **Step 1:** Build the load generator image from HttpArena's own Dockerfile:
  `docker build -t httparena-h2load -f /mnt/nvme1tb/claude-tmp/arena-main/docker/h2load.Dockerfile /mnt/nvme1tb/claude-tmp/arena-main/docker`.
  Then run `docker run --rm httparena-h2load --version`. Expected: `h2load nghttp2/1.59.0` (the Ubuntu
  24.04 package).
- [ ] **Step 2:** Rival images.
  - Build `httparena-plod` from `/mnt/nvme1tb/claude-tmp/arena-main/frameworks/plod`.
  - Rebuild `httparena-viltrum` and `httparena-aegon` from arena-main, so they carry the h2 code that
    main publishes.
  - Use `docker build --no-cache -t httparena-<name> frameworks/<name>`.
  - The containers run as HttpArena does: `--network host --security-opt seccomp=unconfined --ulimit memlock=-1:-1 --cpuset-cpus 0-5,12-17`,
    with read-only mounts of `data/dataset.json`, `data/static` and `certs` at `/data/dataset.json`,
    `/data/static` and `/certs`.
  - The user has approved seccomp=unconfined on colossus. If the auto-mode classifier still blocks the
    first run, stop and ask the user.
- [ ] **Step 3:** Write `arena-h2.rs` on the current (old) `Http2ServerFramework` with
  `UringExecutor` (`set_local_runtime_cb` to `UringRuntime::with_params(UringParams::default())`). Static
  files answer 404 until Task 11.
  Check: `curl --http2-prior-knowledge 'http://127.0.0.1:8082/baseline2?a=13&b=42'` prints `55`.
- [ ] **Step 4:** Write `h2-bench.sh`.
  - It mirrors `arena-main/scripts/lib/tools/h2load.sh` for the four profiles, with the same URLs, `-m`,
    `-H`, `-p h2c`, and the URI files from `arena-main/requests/`.
  - h2load runs in `httparena-h2load` with `--network host --cpuset-cpus 6-11,18-23`, `-t 12 -D 5s`.
  - It does 3 runs and keeps the best.
  - It records `perf stat -e cycles:u -p <server pid>` divided by completed requests for native servers.
  - It records the load container's CPU% (`docker stats --no-stream` sampled mid-run).
  - It kills the server by the pid that `ss -ltnp 'sport = :8082'` reports, never with `pkill -f`.
  - Before each run it checks that ports 8082 and 8443 are free.
- [ ] **Step 5:** Write `h2-composite.py`. Check it with a hand-made file: rimu best 100 everywhere and plod
  200 everywhere gives rimu 2000 and plod 4000.
- [ ] **Step 6:** Baseline run. All four servers on every profile and conn count:
  - baseline-h2 256 and 1024;
  - static-h2 256 and 1024 (rivals only);
  - baseline-h2c 256, 1024 and 4096;
  - json-h2c 1024 and 4096.

  Put the table, the composite and the load CPU% in `docs/perf/http2-bench.md` under
  "Baseline (old driver)". Note which profiles show the load side above 90% CPU: those are
  generator-capped.
- [ ] **Step 7:** Commit with the message `bench: HTTP/2 load harness, rivals, baseline`.

### Task 2: Conformance and interop harness

**Files:**
- Create: `.scripts/h2-interop.sh`, `.scripts/h2-interop-go/main.go`, `.scripts/h2-interop-go/go.mod`
- Modify: `.scripts/h2spec.sh` (`CONTAINER=${CONTAINER:-podman}`, so `CONTAINER=docker` works; the
  output files go to `$TMPDIR`)

**Interfaces:**
- Produces:
  - `.scripts/h2spec.sh high|low [tls]`: runs the existing h2spec section list against `h2spec-high` /
    `h2spec-low`. `tls` adds `-t -k` and the server's TLS port.
  - `.scripts/h2-interop.sh URL_H2C URL_TLS`: runs `curl --http2-prior-knowledge`, `curl --http2 -k`,
    `nghttp -nv` (from `httparena-h2load`, entrypoint overridden), and the Go client. It exits non-zero
    on any wrong body or protocol error.
  - Go client: 200 requests over one connection, 50 concurrent, against `/baseline2?a=i&b=1`. It checks
    each body equals `i+1`.

- [ ] **Step 1:** Run `CONTAINER=docker .scripts/h2spec.sh high` on the current code. Record the pass and
  fail counts in `docs/perf/http2-bench.md` under "Conformance baseline".
- [ ] **Step 2:** Write `h2-interop.sh` and the Go client. Run them against `arena-h2`. Record which ones
  fail; curl is expected to fail with linger off.
- [ ] **Step 3:** Commit with the message `test: HTTP/2 conformance and interop harness`.

---

## Phase B: the protocol core (new files, not yet wired)

The new code goes in `wtx/src/http2/conn.rs` with submodules in `wtx/src/http2/conn/`. It is `pub(crate)`,
and compiled under the `http2` feature.

### Task 3: Frame scanning, preface, test helpers

**Files:**
- Create: `wtx/src/http2/conn.rs`, `wtx/src/http2/conn/scan.rs`, `wtx/src/http2/conn/test_frames.rs`
  (`#[cfg(test)]`)
- Modify: `wtx/src/http2.rs` (`mod conn;`)

**Interfaces:**
- Produces:
  - `scan::next_frame(input: &[u8], max_frame_len: u32) -> crate::Result<Option<(FrameInit, &[u8], usize)>>`
    - `None` means the input is incomplete.
    - On success it returns the header, the payload, and the total bytes consumed.
    - A length above `max_frame_len` is an error mapping to `Http2ErrorCode::FrameSizeError`.
    - An unknown frame type is returned with `FrameInit.ty = None`, so it is skipped and not an error.
      This means changing `FrameInit.ty` to `Option<FrameInitTy>`, or adding a `scan::Frame` struct;
      the implementer's choice.
  - `scan::strip_preface(input: &[u8]) -> Preface`, with `enum Preface { Incomplete, Done(usize), Invalid }`
    and `PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"`.
  - Test helpers (`test_frames`):
    - `frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8>`;
    - `settings(&[(u16, u32)]) -> Vec<u8>`;
    - `headers_req(stream: u32, method: &str, path: &str, extra: &[(&str, &str)], end_stream: bool) -> Vec<u8>`
      (HPACK literal without indexing, no Huffman);
    - `data(stream: u32, bytes: &[u8], end_stream: bool) -> Vec<u8>`;
    - `parse_all(bytes: &[u8]) -> Vec<(u8 /*ty*/, u8 /*flags*/, u32 /*stream*/, Vec<u8>)>`.

- [ ] **Step 1:** Write the tests in `scan.rs`:
  - `scan_every_split_offset`: concatenate a SETTINGS, a HEADERS and a DATA frame. For every split point
    `k`, feeding `input[..k]` then the rest yields the same three frames in order, and `None` while
    incomplete.
  - `scan_rejects_oversized`: a frame with length `max+1` gives `Err` with code FrameSizeError.
  - `scan_skips_unknown_type`: type `0x20` is returned as unknown with the right consumed length.
  - `preface_partial_reads`: every prefix shorter than 24 bytes gives `Incomplete`; 24 bytes gives
    `Done(24)`; one wrong byte gives `Invalid`.
- [ ] **Step 2:** Run `cargo test -p rimu-ws --features "$FEAT" --lib http2::conn::scan`. Expected: FAIL
  (functions missing).
- [ ] **Step 3:** Implement `next_frame` and `strip_preface` with `FrameInit::from_array`.
- [ ] **Step 4:** Run the tests again. Expected: PASS.
- [ ] **Step 5:** Commit with the message `http2: frame scanning over byte slices`.

### Task 4: `Http2Conn`: control frames, stream table, closed-stream rules

**Files:**
- Modify: `wtx/src/http2/conn.rs`
- Create: `wtx/src/http2/conn/stream_table.rs`, `wtx/src/http2/conn/output.rs`, `wtx/src/http2/conn/tests.rs`

**Interfaces:**
- Consumes: `scan::*` (Task 3); the existing `SettingsFrame`, `PingFrame`, `GoAwayFrame`,
  `ResetStreamFrame`, `WindowUpdateFrame`, `Windows` and `HttpRecvParams`.
- Produces:

  ```rust
  pub(crate) struct Http2Conn<const IS_CLIENT: bool> { /* owned, no Arc, no locks */ }
  impl<const IS_CLIENT: bool> Http2Conn<IS_CLIENT> {
    pub(crate) fn new(hp: HttpRecvParams, rng: &mut impl Rng) -> Self; // queues the client preface (client), local SETTINGS, and a connection WINDOW_UPDATE up to hp.initial_window_len()
    pub(crate) fn feed(&mut self, input: &[u8]) -> crate::Result<usize>; // parses every complete frame; returns bytes consumed; on a connection error queues GOAWAY and returns Err
    pub(crate) fn poll_event(&mut self) -> Option<ConnEvent>;
    pub(crate) fn output(&self, out: &mut ArrayVectorCopy<&[u8], 16>); // pending bytes as slices, in order
    pub(crate) fn advance_output(&mut self, n: usize);
    pub(crate) fn has_output(&self) -> bool;
    pub(crate) fn go_away(&mut self, code: Http2ErrorCode); // graceful: GOAWAY(last processed id), refuse new streams
    pub(crate) fn is_closed(&self) -> bool; // after GOAWAY both ways or a fatal error, once output is drained
    pub(crate) fn open_streams(&self) -> u32;
  }
  pub(crate) enum ConnEvent {
    Headers { stream_id: U31, end_stream: bool },
    Data { stream_id: U31, end_stream: bool },
    Trailers { stream_id: U31 },
    Reset { stream_id: U31, code: Http2ErrorCode },
    SendCapacity { stream_id: U31 }, // a WINDOW_UPDATE or SETTINGS let queued data of this stream move
    GoAway { last_stream_id: U31, code: Http2ErrorCode },
  }
  ```

  - The stream table is a slab: slot index → stream id, state, both windows, the `MsgBufferString`
    being received, and the pending send queue. Slots are reused.
  - Closed ids are remembered as "≤ highest id seen and not open" (no per-id set). A frame for a closed
    stream follows RFC 9113 §5.1:
    - WINDOW_UPDATE / RST_STREAM / PRIORITY are ignored;
    - DATA gets RST_STREAM(STREAM_CLOSED), with its length still charged to the connection window;
    - HEADERS on a closed stream is a connection error STREAM_CLOSED.
    
    Idle-state rules are as in the RFC.

- [ ] **Step 1:** Write the tests in `conn/tests.rs`, each feeding bytes from `test_frames` and checking
  `parse_all(output)`:
  - `conn_server_initial_output`: after `new`, the output is SETTINGS (values from `hp`) followed by a
    WINDOW_UPDATE on stream 0.
  - `conn_preface_split`: feeding the preface byte by byte, then SETTINGS, yields a SETTINGS ACK and no
    error.
  - `conn_settings_ack_and_ping_ack`: a PING with payload `[1..=8]` gives a PING ACK with the same
    payload.
  - `conn_window_update_on_closed_stream_ignored`: a full GET is answered (use `send_response` stubbed
    via a test-only `close_stream` until Task 5), then WINDOW_UPDATE and RST_STREAM for that id give no
    output and no error.
  - `conn_data_on_closed_stream_rst`: DATA on a closed id gives RST_STREAM(STREAM_CLOSED) for that id,
    and the connection stays up.
  - `conn_headers_on_closed_stream_goaway`: gives GOAWAY(STREAM_CLOSED) and `feed` returns `Err`.
  - `conn_even_stream_id_from_client_goaway`: gives GOAWAY(PROTOCOL_ERROR).
  - `conn_graceful_go_away`: `go_away(NoError)` gives GOAWAY with the last processed id, and a later
    HEADERS with a higher id is refused with RST_STREAM(REFUSED_STREAM).
- [ ] **Step 2:** Run `cargo test ... --lib http2::conn::tests`. Expected: FAIL.
- [ ] **Step 3:** Implement `Http2Conn::{new, feed, poll_event, output, advance_output, has_output, go_away, is_closed, open_streams}`
  and `stream_table.rs` / `output.rs`.
  - `output.rs` keeps one contiguous `VectorUsize<u8>` for encoded frames, plus a queue of
    by-reference body segments (Task 5) interleaved by position.
- [ ] **Step 4:** Run the tests again. Expected: PASS.
- [ ] **Step 5:** Commit with the message `http2: owned connection core with RFC 9113 closed-stream rules`.

### Task 5: Requests in, responses out, flow control

**Files:**
- Modify: `wtx/src/http2/conn.rs`, `wtx/src/http2/conn/stream_table.rs`, `wtx/src/http2/conn/output.rs`,
  `wtx/src/http2/conn/tests.rs`
- Create: `wtx/src/http2/conn/body.rs`

**Interfaces:**
- Consumes: `HeadersFrame::read`, the HPACK decoder and encoder, `encode_headers` (from
  `write_functions.rs`), `Windows`, and `check_content_length`.
- Produces:

  ```rust
  pub struct SharedBytes { /* crate::sync::Arc<[u8]> + start..end */ }   // public: static files hand bodies over by reference
  impl SharedBytes { pub fn new(bytes: Arc<[u8]>) -> Self; pub fn slice(&self, start: usize, end: usize) -> Self; pub fn as_slice(&self) -> &[u8]; }
  pub(crate) enum Body<'any> { Borrowed(&'any [u8]), Shared(SharedBytes) }
  impl<const IS_CLIENT: bool> Http2Conn<IS_CLIENT> {
    pub(crate) fn msg_mut(&mut self, stream_id: U31) -> Option<&mut MsgBufferString>; // the request (server) or response (client) being received
    pub(crate) fn method(&self, stream_id: U31) -> Option<Method>;
    pub(crate) fn release_capacity(&mut self, stream_id: U31, n: u32) -> crate::Result<()>; // queue WINDOW_UPDATEs (stream + connection), coalesced per feed
    pub(crate) fn send_headers(&mut self, stream_id: U31, status: Option<StatusCode>, headers: &Headers, end_stream: bool) -> crate::Result<()>;
    pub(crate) fn send_data(&mut self, stream_id: U31, body: Body<'_>, end_stream: bool) -> crate::Result<()>; // frames up to min(peer max frame size, windows); the rest stays queued on the stream
    pub(crate) fn send_trailers(&mut self, stream_id: U31, trailers: &Headers) -> crate::Result<()>;
    pub(crate) fn send_reset(&mut self, stream_id: U31, code: Http2ErrorCode);
    pub(crate) fn send_response(&mut self, stream_id: U31, status: StatusCode, msg: &mut MsgBufferString) -> crate::Result<()>; // HEADERS (+content-length) + DATA in one call; then the slot's buffers are cleared for reuse
    pub(crate) fn stream_send_pending(&self, stream_id: U31) -> u32; // bytes still queued
  }
  // client-only
  impl Http2Conn<true> {
    pub(crate) fn open_stream(&mut self) -> crate::Result<U31>; // Err when the peer's max concurrent streams would be exceeded
    pub(crate) fn send_request(&mut self, stream_id: U31, method: Method, msg: &MsgBuffer<impl Lease<str>>, end_stream: bool) -> crate::Result<()>;
  }
  ```

  - On the server, HEADERS decode straight into the slot's `MsgBufferString`, with uri and headers taken
    from a per-connection pool of cleared buffers. DATA appends to its body.
  - The connection window is replenished as soon as DATA lands in a stream buffer. The bytes still
    count against the per-connection buffered cap (Task 7).
  - The stream window is replenished only through `release_capacity`.
  - `send_response` encodes `:status`, then the user headers, then `content-length` as a literal
    *without indexing*. A body within both windows and one frame goes out as HEADERS+DATA(END_STREAM)
    in one pass (the existing `push_fast_path` logic).

- [ ] **Step 1:** Write the tests:
  - `conn_get_request_event_and_msg`: a HEADERS (GET /a?x=1, END_STREAM) gives
    `Headers{stream 1, end_stream: true}`, `msg_mut(1).uri.path() == "/a"` and
    `method(1) == Some(Method::Get)`.
  - `conn_post_body_across_feeds`: HEADERS without END_STREAM, then DATA "hel" and "lo" with END_STREAM,
    fed in 1-byte chunks, gives the events Headers, Data, Data(end); the body is `hello`.
  - `conn_response_one_pass`: `send_response(1, Ok, msg with body "2")` produces exactly HEADERS then
    DATA with END_STREAM. The HPACK-decoded headers contain `:status 200` and `content-length 1`.
  - `conn_response_waits_for_window`:
    - with the peer's initial window 10, a 25-byte body sends 10 bytes;
    - WINDOW_UPDATE(stream, 20) together with a connection update gives `SendCapacity{1}` and the
      remaining 15 bytes with END_STREAM;
    - `stream_send_pending(1) == 0`.
  - `conn_shared_body_by_reference`: `send_data(Body::Shared(..))` of 40 KiB with a peer frame size of
    16384 gives 3 DATA frames. `output()` returns at least one slice whose pointer lies inside the
    shared allocation, so it is not copied.
  - `conn_release_capacity_coalesced`: three `release_capacity(1, 100)` calls in one feed give one stream
    WINDOW_UPDATE(300).
  - `conn_settings_shrink_window_goes_negative` (Review focus 1):
    - 10 bytes of a 100-byte body sent with window 10;
    - SETTINGS INITIAL_WINDOW_SIZE=0 makes the window negative;
    - WINDOW_UPDATE(5) sends nothing, WINDOW_UPDATE(200) sends the remaining 90 bytes;
    - all bytes arrive in order.
  - `conn_client_request_response`: with a client `Http2Conn<true>`, `open_stream` gives id 1;
    `send_request` produces HEADERS. A fed response HEADERS+DATA gives events Headers and Data(end), and
    `msg_mut(1).body == b"ok"`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement. Reuse `encode_headers` / `push_*` from `write_functions.rs` by moving their
  synchronous parts into `conn/` helpers. Leave the async `send_msg` path untouched for now; the old
  driver still uses it.
- [ ] **Step 4:** Run the tests. Expected: PASS. Also run `cargo test ... --lib http2` to show the old
  module is unaffected.
- [ ] **Step 5:** Commit with the message `http2: request and response path with flow control in the core`.

### Task 6: Response header-block cache

**Files:**
- Modify: `wtx/src/http2/hpack_encoder.rs` (add `generation: u64`, bumped on every dynamic-table insert
  or eviction and on a size change), `wtx/src/http2/conn.rs`
- Create: `wtx/src/http2/conn/header_cache.rs`

**Interfaces:**
- Produces:
  - `HeaderCache` inside `Http2Conn`: a small map (at most 16 entries, evicted by age) from
    (status, hash of the user header names and values, excluding `content-length` and `date`) to the
    encoded bytes and the encoder generation.
  - A hit is valid only when the stored generation equals the current one.
  - `send_response` uses it automatically, so no new public method.

- [ ] **Step 1:** Write the tests:
  - `conn_header_cache_hit_same_bytes`: two identical responses on streams 1 and 3. The second HEADERS
    payload, minus the content-length literal, equals the first's encoding on its second use, and the
    table generation is unchanged after the second response.
  - `conn_header_cache_invalid_after_table_size_change` (Review focus 2):
    - two cached responses;
    - SETTINGS HEADER_TABLE_SIZE=0;
    - the next response's block starts with a dynamic-table size update (`0x20`);
    - a fresh `HpackDecoder` fed all blocks in order decodes every response correctly.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement `generation` and `HeaderCache`.
- [ ] **Step 4:** Run them, then run `cargo test ... --lib http2::tests::hpack` (the HPACK story tests).
  Expected: PASS.
- [ ] **Step 5:** Commit with the message `http2: cache encoded response header blocks per table generation`.

### Task 7: Abuse limits

**Files:**
- Modify: `wtx/src/http/http_recv_params.rs`, `wtx/src/http2/conn.rs`, `wtx/src/http2/conn/tests.rs`

**Interfaces:**
- Produces: new `HttpRecvParams` fields, each with a getter and a `const fn set_*`. Default values are
  given in brackets; `with_permissive_params` sets each to its maximum.
  - `max_resets_per_window: (u32, Duration)` [(200, 10 s)];
  - `max_continuations: u8` [4];
  - `max_control_frames_per_window: (u32, Duration)` [(1000, 10 s)], counting PING, SETTINGS and empty
    DATA/HEADERS;
  - `max_conn_buffered_len: u32` [4 MiB], the received body bytes buffered across the connection's
    streams;
  - `max_send_queue_len: u32` [4 MiB], the queued output and pending stream data before the peer must
    read.
  
  The existing `max_headers_len`, `max_body_len` and `max_concurrent_streams_num` are now enforced in
  the core.
  - Time comes from a `now: Instant` that the caller passes in `feed_at(&mut self, input, now)`. `feed`
    becomes `feed_at` with `Instant::now()`; tests pass fixed instants.

- [ ] **Step 1:** Write the tests:
  - `limit_rapid_reset_goaway`: 201 HEADERS+RST_STREAM pairs within 1 s give
    GOAWAY(ENHANCE_YOUR_CALM). 200 spread over 11 s do not.
  - `limit_continuation_flood`: HEADERS without END_HEADERS plus 5 CONTINUATIONs give
    GOAWAY(ENHANCE_YOUR_CALM). 4 are accepted.
  - `limit_ping_flood`: 1001 PINGs within 1 s give GOAWAY(ENHANCE_YOUR_CALM).
  - `limit_header_list_size`: a header block whose decoded size is above `max_headers_len` gives
    RST_STREAM(REFUSED_STREAM) or a 431 response (pick one and document it). The connection stays up.
  - `limit_body_len`: DATA beyond `max_body_len` gives RST_STREAM(CANCEL) for that stream only.
  - `limit_conn_buffered`: bodies across streams above `max_conn_buffered_len` give
    RST_STREAM(REFUSED_STREAM) for the stream that crossed it.
  - `limit_send_queue`: with the peer's window at 0 and responses queued past `max_send_queue_len`,
    `send_response` returns `Err`, and the driver closes (asserted in Task 8).
  - `limit_concurrent_streams`: stream number `max+1` while `max` are open gives
    RST_STREAM(REFUSED_STREAM).
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. Add counters and windows to `Http2Conn`; don't allocate per frame.
- [ ] **Step 4:** Run `cargo test ... --lib http2::conn`. Expected: PASS.
- [ ] **Step 5:** Commit with the message `http2: abuse limits in the core (rapid reset, floods, buffered bytes)`.

---

## Phase C: drivers

### Task 8: io_uring server connection driver

**Files:**
- Create: `wtx/src/http/http2_server_framework/conn_driver.rs`,
  `wtx/src/http/http2_server_framework/handler_slots.rs`, `wtx/src/http/date_header.rs`
- Test: `wtx/src/http/http2_server_framework/conn_driver/tests.rs`

**Interfaces:**
- Consumes: `Http2Conn<false>` (Tasks 4–7), `StreamReader::{try_read, readable}`,
  `StreamWriter::try_write_all_vectored` / `write_all_vectored`.
- Produces:

  ```rust
  pub(crate) trait StreamDispatcher {
    type AutoFut: Future<Output = Result<StatusCode, crate::Error>>; // owns its request; the response is written into the same MsgBufferString
    fn route(&self, method: Method, msg: &MsgBufferString) -> crate::Result<Route>; // Route { mode: OperationMode, matches: ArrayVectorCopy<RouteMatch, 4> }
    fn auto(&self, route: Route, req: Request<MsgBufferString>, peer: Option<IpAddr>) -> (Self::AutoFut, /* where the response lands */ ResponseCell);
    fn manual(&self, route: Route, stream: ServerStream, req: Request<MsgBufferString>, peer: Option<IpAddr>); // spawns a local task
  }
  pub(crate) async fn drive_conn<S, D>(stream: S, conn: Http2Conn<false>, dispatcher: &D, peer: Option<IpAddr>, date: &DateHeader) -> crate::Result<()>
  where S: StreamReader + StreamWriter, D: StreamDispatcher;
  pub(crate) struct DateHeader; // per thread: `fn get(&self) -> &str` (29-byte IMF-fixdate), refreshed when the coarse realtime clock's second changes
  pub(crate) fn format_imf_fixdate(unix_secs: u64, out: &mut [u8; 29]);
  ```

  - `ResponseCell` and the exact way the finished request buffer comes back to the driver are the
    builder's call. The constraint: the handler future owns its `Request<MsgBufferString>`, and the
    driver gets the buffer back to call `send_response`.
  - `handler_slots.rs` holds per-connection reusable heap slots that a handler future is **pinned into
    before its first poll**. Slots are reused when the future completes, so the steady state does no
    allocation, and a pending future never moves. The slot count is bounded by
    `max_concurrent_streams_num`.
  - Each turn of `drive_conn`:
    1. `try_read` into the read buffer until it would block, then `feed_at` everything;
    2. handle the events:
       - `Headers` → `route`;
       - auto mode with `end_stream` → start a handler;
       - auto mode without `end_stream` → collect the body, calling `release_capacity` as data arrives,
         up to `max_body_len`, and start the handler at the end of the stream;
       - manual mode → `dispatcher.manual(..)`;
    3. poll every newly started handler once, plus each parked one whose waker fired; each poll is
       wrapped in `catch_unwind(AssertUnwindSafe(..))`;
    4. a `Ready` handler → push `date` → `send_response`;
    5. a panic → if headers were not sent, a 500 with an empty body, else `send_reset(INTERNAL_ERROR)`;
       either way the slot is freed;
    6. queue **one** vectored write of `conn.output(..)` and `advance_output`;
    7. wait on `readable()`, a parked handler's wake, a manual-stream wake, or a timer (Task 10),
       whichever comes first.
  - `Reset` / `GoAway` for a stream with a parked handler drops its future in place.

- [ ] **Step 1:** Write the tests. They drive `drive_conn` on a `UringRuntime` over a loopback TCP pair,
  with a raw-frame client built from `test_frames`:
  - `server_inline_ready_one_write`: 100 pipelined GETs in one write give 100 responses, and the
    server's writes for them are ≤ 2 (count the writes through `UringStats`, or a counting test
    stream wrapper).
  - `server_parked_handler_answered_later`: a handler awaiting a 20 ms `UringSleep`, plus 10 immediate
    handlers. The 10 are answered before the slow one, and the slow one is still answered.
  - `server_reset_drops_parked_handler` (Review focus 3): park a handler whose future sets a flag in
    `Drop`, then send RST_STREAM. The flag is set, and no HEADERS for that stream appear.
  - `server_handler_panic_isolated`: one handler panics, the other 9 respond 200, the panicking stream
    gets 500, and the connection stays up for one more GET.
  - `server_auto_body_larger_than_window` (Review focus 4): a POST with a 200 KiB body and a peer
    initial window of 65535 completes, and the handler sees 200 KiB.
  - `server_slots_reused_no_alloc`: after warm-up, 1000 GETs cause 0 allocations in the driver, counted
    with a counting `#[global_allocator]` in a test binary under `wtx-internal/tests/`. If that is
    impractical, it is an allocation-histogram run of `arena-h2` documented in the commit message.
  - `date_known_values`: `format_imf_fixdate(0)` is `Thu, 01 Jan 1970 00:00:00 GMT`, and
    `format_imf_fixdate(1_700_000_000)` is `Tue, 14 Nov 2023 22:13:20 GMT`.
  - `limit_send_queue_closes` (from Task 7): a client that never reads gets disconnected once the queue
    cap is hit, and the server's RSS stays bounded.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement `drive_conn`, `handler_slots`, `DateHeader` and `format_imf_fixdate`.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit with the message `http2 server: batch-in, batch-out io_uring connection driver`.

### Task 9: Switch the server framework, manual streams, gRPC server and WebSocket over HTTP/2 to the driver

**Files:**
- Modify: `wtx/src/http/http2_server_framework.rs` (replace `http2()`, `stream_cb`, `stream_fut` and
  the accept loops), `wtx/src/http2/server_stream.rs` (a new handle type),
  `wtx/src/http2/web_socket_over_stream.rs`, `wtx/src/http/operation_mode.rs` (`ManualStream` holds the
  new `ServerStream`), `wtx/src/grpc/*` as needed, `wtx/src/http2/tests/connections.rs`,
  `wtx-internal/src/bin/h2spec-high.rs`, `wtx-internal/src/bin/arena-h2.rs`
- Create: `docs/http2-breaking-changes.md`

**Interfaces:**
- Consumes: `drive_conn`, `StreamDispatcher` (Task 8).
- Produces:
  - `ServerStream`: a non-`Send` handle (`Rc` to the connection's shared core cell, plus the stream id),
    with the same method names as today:
    - `recv_req`
    - `send_res`
    - `common().recv_data`
    - `send_data`
    - `send_trailers`
    - `send_reset`
    - `windows`
    - `release_capacity`

    Waiting is a per-stream waker that the driver wakes on `Data`, `Trailers`, `SendCapacity` or
    `Reset`. `Drop` before end-of-stream queues `RST_STREAM(CANCEL)`.
  - `Http2ServerFramework`:
    - generic only over `UringExecutor`;
    - `tokio()` and the std-runtime server path are removed;
    - `run`, `run_in_threads` and `run_local` keep their names, with only the `'static` bounds needed
      per thread;
    - no `peer_addr()` call (the address comes from `accept`, or `None` with direct descriptors);
    - the TLS stream stays unsplit, so the kTLS switch can run;
    - protocol choice by ALPN `h2`, or by the h2c preface for cleartext; any other ALPN result closes the
      connection with a TLS `no_application_protocol` alert (spec §5.7).
  - `docs/http2-breaking-changes.md` lists every public signature that changed, with the reason.

- [ ] **Step 1:** Port `http2/tests/connections.rs` (server side) and the framework tests in
  `http/http2_server_framework/tests.rs` to `UringRuntime`. Add these tests:
  - `framework_manual_stream_echo`: a manual endpoint echoes the request body back in 3 `send_data`
    calls.
  - `framework_web_socket_over_h2`: the existing extended-CONNECT test runs on the new driver.
  - `grpc_unary_roundtrip`: the gRPC example's unary call works, with the server on uring.
  - `server_tls_preface_with_finished_uses_ktls` (Review focus 5): the TLS client writes Finished,
    the preface and a GET in one buffer. The response arrives and `/proc/net/tls_stat`
    `TlsTxSw + TlsTxDevice` increased. The test is skipped if that file is absent.
- [ ] **Step 2:** Run `cargo test ... --lib http2 http2_server_framework grpc web_socket_over`. Expected:
  the new tests FAIL.
- [ ] **Step 3:** Implement. The old server-side code (`Http2::<_, _, false>::accept`, `stream`, the
  server half of `frame_reader`, and linger) is deleted. The client side of `Http2` still uses the old
  code until Task 10.
- [ ] **Step 4:** Run the same tests, then `.scripts/h2spec.sh high` and `.scripts/h2spec.sh high tls`,
  then `.scripts/h2-interop.sh` against `arena-h2`. Expected:
  - all tests PASS;
  - h2spec at least as many passes as the Task 2 baseline, with no new failures;
  - interop all green, curl included.
- [ ] **Step 5:** Run `h2-bench.sh rimu` on the three non-static profiles and add a row "after Task 9"
  to `docs/perf/http2-bench.md`.
  - Then measure the cost of panic isolation: an A/B build with the per-poll `catch_unwind` removed,
    comparing cycles per request and throughput on the same profiles.
  - If isolation costs more than 2% on any profile, stop and bring the numbers to the user before
    weakening it (spec §9).
- [ ] **Step 6:** Commit with the message `http2 server framework: run on the batch driver (io_uring only)`.

### Task 10: Client, client pool, client API transport and gRPC client on the core; delete the old driver

**Files:**
- Modify: `wtx/src/http2.rs`, `wtx/src/http2/client_stream.rs`, `wtx/src/http2/common_stream.rs`,
  `wtx/src/http/http_client.rs`, `wtx/src/http/http2_client_pool/*`,
  `wtx/src/client_api_framework/network/transport/wtx_http.rs`, `wtx/src/grpc/grpc_client.rs`,
  `docs/http2-breaking-changes.md`
- Delete: `wtx/src/http2/frame_reader.rs`, `wtx/src/http2/process_receipt_frame_ty.rs`, the async parts of
  `write_functions.rs` and `misc.rs`, `Http2Data`, `Http2Buffer`'s maps, and `AFTER_CLOSE_TIMEOUT_MS`.
  Also delete `HttpRecvParams::{linger, set_linger}` and list them in the breaking-changes doc.

**Interfaces:**
- Produces:
  - `Http2<SW, TCX, true>` keeps `connect(..) -> (impl Future<Output = ()>, Self)`: the future is the
    connection task, which the caller spawns, as today.
  - `stream() -> ClientStream`.
  - `ClientStream::{send_req, recv_res}` and `common()` keep their method names.
  - Internally there is one connection task that owns the socket and drives `Http2Conn<true>`.
    Handles share the core through `crate::sync::Arc<SyncMutex<..>>`, held only for synchronous core
    calls, never across an `.await`, plus per-stream wakers.
  - `Http2<SW, TCX, true>` stays `Send + Sync` when `SW: Send`, as today.

- [ ] **Step 1:** Port the client side of `http2/tests/connections.rs`, so the client runs against the
  new server on uring. Add these tests:
  - `client_many_concurrent_streams`: 50 concurrent `send_req` / `recv_res` pairs from 4 tasks on one
    connection all get the right bodies.
  - `client_pool_reuses_connection`: 10 requests through `Http2ClientPool` open 1 connection.
  - `client_on_tokio_smoke`: behind the `tokio` feature, run alone; a GET through `HttpClient` against
    the uring server succeeds. This test is excluded from `$FEAT` runs.
  - `client_server_reset_wakes_waiter`: when the server resets the stream, the pending `recv_res`
    returns `Http2RecvStatus::ClosedStream`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement, and delete the old driver code.
- [ ] **Step 4:** Run the full suite `cargo test -p rimu-ws --features "$FEAT"`, then the doctests and
  examples build (`cargo build -p rimu-ws-examples --all-targets`), then `client_on_tokio_smoke` alone
  with `--features "$FEAT,tokio" client_on_tokio_smoke`, then h2spec low. Expected: all PASS.
- [ ] **Step 5:** Commit with the message `http2 client: run on the shared core; remove the locked driver and linger`.

### Task 10A: Performance foundations, from the rivals' code (added 6 Nov)

**Why:** a line-level read of plod, cnetmod, zix and viltrum, against our own code, is in
`/mnt/nvme1tb/claude-tmp/httpwin/rivals-h2-code.md`. It found structural costs that are cheaper to
fix now than in Task 18. The rivals all write one coalesced buffer per read batch and run handlers
inline, and we already do both.

**Method:** each item is an A/B on `perf stat` user cycles per request (`h2-bench.sh`'s
`server_ucyc_per_req`), plus throughput on the four profiles. Keep an item only if it wins and
`cargo test --lib` and h2spec (plaintext and TLS) still pass.

- [ ] **Step 1: json-h2c costs about 72k user cycles per request.** Profile `arena-h2` on json-h2c
  (`perf record -g`) and fix what dominates before anything else. Expected: under 15k.
- [ ] **Step 2: send without copies.**
  - Hand the core's output buffer to the reactor's send queue by swapping, not by copying
    (`uring_executor.rs` around the `tx_pending` copy at ~2696).
  - Send by-reference (`Shared`) chunks with a vectored send (writev/SendMsg), holding the shared
    bytes until completion.
  - Drop the 8-slice cap in `write_output`.
- [ ] **Step 3: write the response straight into the output buffer.**
  - When the windows allow the whole body, write DATA straight into the output buffer, skipping
    `stream.owned`.
  - Encode the HPACK block straight into the output buffer, behind a reserved 9-byte header.
- [ ] **Step 4: one router lookup per request, and no per-request `Arc`, data or `error_cb`
  clones.** `StreamDispatcher::AutoFut` borrows the dispatcher (a GAT), and the route found in
  `is_manual` is passed on to `auto`.
- [ ] **Step 5: the stream table.** Remember the last stream looked up, or index by stream id.
  Look at cnetmod's no-node path for END_STREAM GETs.
- [ ] **Step 6: memo of the request HPACK block** (cnetmod: exact byte compare). Record a block
  only when decoding it left the table unchanged, and clear the memo on any insert or size change.
- [ ] **Step 7: header cache.**
  - Key it by a hash, with an exact compare on hit.
  - Include `date` in the cached block, and invalidate once a second, so a warm response block is
    a memcpy plus the `content-length` literal.
- [ ] **Step 8: record each kept item, with its numbers, in `docs/perf/http2-bench.md`.** Commit
  each item separately.

---

## Phase D: features, defaults, entry

### Task 11: Static files handler

**Files:**
- Create: `wtx/src/http/http2_server_framework/static_files.rs`
- Modify: `wtx/src/http/router.rs` (add a trailing catch-all segment `{*name}`), `wtx/src/http/mime.rs`
  (an extension → content-type table), `wtx-internal/src/bin/arena-h2.rs` (mount `/static`)

**Interfaces:**
- Produces:

  ```rust
  pub struct StaticFiles { /* root dir, per-thread cache */ }
  impl StaticFiles { pub fn new(root: impl Into<PathBuf>) -> crate::Result<Self>; }
  ```

  - `StaticFiles` is usable as an endpoint: `("/static/{*file}", get(StaticFiles::new(dir)?))`.
  - It serves `root/<file>` with path traversal rejected (`..`, absolute, NUL → 404).
  - `content-type` comes from the original extension.
  - For a request with `Accept-Encoding` it picks `.br`, then `.gz`, if the sibling exists, with q-values
    honoured. It adds `content-encoding` and `vary: accept-encoding`.
  - The cache is per thread: path+encoding → (`SharedBytes`, mtime, len, inode, last check). It
    re-`stat`s at most once a second per entry and reloads on any change; a deleted file gives 404. The
    body is sent with `Body::Shared`.
  - ETag / Last-Modified: the builder's call. If done, a conditional GET gets a 304.

- [ ] **Step 1:** Write the tests:
  - `static_serves_br_when_accepted`: with `Accept-Encoding: br;q=1, gzip;q=0.8` and `a.css` plus
    `a.css.br` present, the body equals the `.br` bytes, with `content-encoding: br` and
    `content-type: text/css`.
  - `static_falls_back_to_identity`: with no `.br`/`.gz` sibling, the raw bytes, and no
    `content-encoding`.
  - `static_follows_disk`: serve, then overwrite with same-length different bytes and wait 1.2 s. The
    next response has the new bytes.
  - `static_rejects_traversal`: `/static/../Cargo.toml`, `/static/%2e%2e/x` and `/static//etc/passwd`
    all give 404.
  - `static_missing_404`.
  - `router_catch_all_segment`: `/static/{*file}` matches `/static/a/b.css` with `file = "a/b.css"`;
    the existing router tests still pass.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them, then `h2-bench.sh rimu static-h2 256` and `1024`. Expected: tests PASS, and
  the bench gives non-zero rps with no non-2xx responses.
- [ ] **Step 5:** Commit with the message `server framework: static files with precompressed variants and a disk-following cache`.

### Task 12: Framework robustness parity

**Files:**
- Modify: `wtx/src/http/http2_server_framework.rs`, `conn_driver.rs`

**Interfaces:**
- Produces, on `Http2ServerFramework`, with the same names and meaning as `WebSocketServerFramework`:
  - `set_max_connections(Option<NonZeroUsize>)`: over the cap, accept and close at once.
  - `set_handshake_timeout(Option<Duration>)` (default 10 s): covers the TLS handshake **and** the
    preface plus the first SETTINGS.
  - `set_idle_timeout(Option<Duration>)` (default 300 s): no open streams and no bytes for this long
    → GOAWAY(NO_ERROR), then close.
  - `set_shutdown(ShutdownSignal, Duration)`: stop accepting, GOAWAY(NO_ERROR) to every connection, let
    open streams finish within the drain time, then close.
  - The send-stall close is the uring runtime's progress-based close timeout. It already exists; check
    that it applies to HTTP/2 connections.
  - `set_error_cb`: protocol errors that end a connection are reported (today they are swallowed).

- [ ] **Step 1:** Write the tests:
  - `fw_max_connections`: with cap 2, a third connection is closed without a response.
  - `fw_handshake_timeout_preface`: a TCP connect that sends nothing is closed after the timeout,
    tested with a 200 ms override.
  - `fw_idle_timeout_goaway`: after one GET and 300 ms idle (override), the client receives GOAWAY
    then EOF.
  - `fw_shutdown_drains`: a slow handler of 100 ms is in flight when shutdown is signalled. It
    completes, a new stream is refused, and `run` returns.
  - `fw_error_cb_reports_protocol_error`: a client sending HEADERS on stream 2 makes `error_cb`
    receive an `Http2Error`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the full suite. Expected: PASS.
- [ ] **Step 5:** Commit with the message `http2 server framework: connection cap, deadlines, idle, shutdown, error reporting`.

### Task 13: Fast-and-safe defaults and the production guide

**Files:**
- Modify: `wtx/src/http/http_recv_params.rs` (defaults), `wtx/src/executor/uring_executor.rs`
  (`UringParams::default`), `wtx/src/net/tcp_params.rs` (defaults) where the measurements justify it
- Create: `docs/production.md`

**Interfaces:**
- Produces:
  - `HttpRecvParams::default()` values, chosen by measurement within the memory bounds below:
    - `initial_window_len`;
    - `max_concurrent_streams_num` (≥ 128);
    - `max_frame_len`;
    - the HPACK table size.
  - `UringParams::default()` and `TcpParams::default()` changes, if any.
  - `docs/production.md`: a real production guide covering each setting a deployment may change, its
    default, when to change it, and its cost (memory per connection, CPU from spinning). The HttpArena
    entry may use only the defaults plus settings this guide recommends for the matching deployment
    shape (for example "dedicated server cores: spin 20 µs").

- [ ] **Step 1:** Measure, with `h2-bench.sh rimu` on the three non-static profiles plus static-h2 at
  256/1024 conns. Cover:
  - `initial_window_len` ∈ {64 KiB, 1 MiB, 4 MiB};
  - `max_concurrent_streams_num` ∈ {128, 256};
  - read buffer sizes.

  Record each run in `docs/perf/http2-bench.md`. Bound memory per connection: worst-case buffered per
  connection ≤ `max_conn_buffered_len` + `max_send_queue_len`.
- [ ] **Step 2:** Measure the WebSocket entry's knobs as candidates for defaults or guide items. Use the
  WebSocket A/B script from the memory notes (`/mnt/nvme1tb/claude-tmp/ab2.sh`) on echo-ws, pipeline and
  limited. The knobs are:
  - spin 20 µs;
  - rings 4096/16384;
  - direct descriptors;
  - `TCP_DEFER_ACCEPT`;
  - NODELAY.

  For each knob, decide default, guide item, or dropped. A dropped knob gets its measured cost written
  down.
- [ ] **Step 3:** Write the tests:
  - `defaults_are_documented`: every `HttpRecvParams` / `UringParams` getter appears in
    `docs/production.md`. The test reads the file and greps for each setter name.
  - The existing tests pass with the new defaults.
- [ ] **Step 4:** Set the defaults and write the guide. Run the full suite. Expected: PASS.
- [ ] **Step 5:** Commit with the message `defaults: fast and safe HTTP/2 and io_uring defaults; production guide`.

### Task 14: HttpArena entry: standard mode with the HTTP/2 profiles (local only)

**Files (in `~/src/HttpArena`, branch `add-rimu-ws`, never pushed):**
- Modify: `frameworks/rimu-ws/meta.json`, `frameworks/rimu-ws/Dockerfile`, `frameworks/rimu-ws/src/main.rs`,
  `frameworks/rimu-ws/Cargo.toml`

**Interfaces:**
- Produces:
  - `meta.json`:
    - `"mode": "standard"`;
    - `tests` += `baseline-h2`, `static-h2`, `baseline-h2c`, `json-h2c`;
    - a `completeness` block with all four axes true (routing via `HttpRouter`, middleware via the
      server-header middleware, request extraction, response building).
  - One binary serving WebSocket on 8080 and HTTP/2 on 8082/8443, with only defaults and production-guide
    settings. All `WTX_*` tuning env vars are removed from the entry.
  - The Dockerfile builds from a **local path context** of the rimu-ws worktree for local runs. Pinning
    to a pushed rimu-ws commit needs the user's go-ahead to push to the `rimu` remote; ask before doing
    it.

- [ ] **Step 1:** Port `arena-h2.rs` into the entry's `main.rs` beside the WebSocket server, through the
  framework's documented APIs only.
- [ ] **Step 2:** Run `./scripts/validate.sh rimu-ws` from `/mnt/nvme1tb/claude-tmp/arena-run`, a
  worktree updated to main + `add-rimu-ws`. It needs docker with seccomp=unconfined; ask the user if the
  classifier blocks it. Expected: every check passes for the WebSocket and HTTP/2 profiles.
- [ ] **Step 3:** Re-run the WebSocket profiles. Expected: within noise of the tuned entry, or the measured
  cost from Task 13 for any knob that was dropped.
- [ ] **Step 4:** Commit on `add-rimu-ws` with the message `rimu-ws: standard mode, HTTP/2 profiles`.

---

## Phase E: the gate and the goal

### Task 15: Differential test and fuzz target for the core

**Files:**
- Create: `wtx/src/http2/conn/differential.rs` (`#[cfg(test)]` plus a `_fuzz` entry point),
  `wtx-fuzz/fuzz_targets/http2_conn.rs`
- Modify: `wtx-fuzz/Cargo.toml`

**Interfaces:**
- Produces: `differential::run(seed_bytes: &[u8])`.
  - It builds a frame sequence from the bytes: valid requests, DATA, WINDOW_UPDATE, SETTINGS, PING,
    RST_STREAM, CONTINUATION, garbage.
  - It feeds them to `Http2Conn<false>` in chunks split at offsets taken from the bytes. It answers each
    request with a body of the stream id's decimal string.
  - It checks the output against a simple model:
    - every request completed with END_STREAM gets exactly one response with the right body, or an
      RST_STREAM;
    - no frame is sent on a stream after its END_STREAM or RST;
    - the windows never go below the RFC allowance;
    - on a GOAWAY, nothing is answered above its last stream id;
    - the core never panics.

- [ ] **Step 1:** Write `differential_fixed_seeds`: 2000 seeds from an `Xorshift64`, all passing.
- [ ] **Step 2:** Run it, fix the bugs it finds, and add each bug's input as a named regression test.
- [ ] **Step 3:** Fuzz for 30 minutes:
  `cargo +nightly fuzz run http2_conn -- -max_total_time=1800` (in `wtx-fuzz`, artefacts under
  `/mnt/nvme1tb/claude-tmp/fuzz-h2`). Expected: no crash. Record the exec count in the commit message.
- [ ] **Step 4:** Commit with the message `http2: differential test and fuzz target for the core`.

### Task 16: HTTP/2 soak scenarios

**Files:**
- Create: `rimu-ws-soak/src/h2codec.rs` (frame writer and reader; HPACK literal-only encoder; decoder
  for the static table plus literals, enough for `:status`), `rimu-ws-soak/src/scenario/h2.rs`,
  `wtx-internal/src/bin/soak-server-h2.rs`
- Modify: `rimu-ws-soak/src/scenario/mod.rs`, `rimu-ws-soak/src/main.rs` (a `--proto h2` flag),
  `.scripts/soak.sh` (`SOAK_PROTO=h2` builds and starts `soak-server-h2` on `127.0.0.1:9081`)

**Interfaces:**
- Produces these scenarios. Each reports pass/fail the way the WebSocket scenarios do, and the server's
  RSS is checked by the existing monitor.
  - `h2_steady`: N clients × 100 streams of GET and echo-POST, with bodies checked.
  - `h2_rapid_reset`: expects GOAWAY(ENHANCE_YOUR_CALM), and the server keeps serving the other
    clients.
  - `h2_continuation_flood`.
  - `h2_settings_flood` and `h2_ping_flood`.
  - `h2_slow_reader`: reads 1 KiB/s from a 10 MiB response. RSS stays bounded and other clients are
    unaffected.
  - `h2_never_read`: closed by the send-stall timeout.
  - `h2_window_starved`: the client's window is 0 forever; the connection closes at the idle or stall
    timeout.
  - `h2_half_open`: FIN after the preface.
  - `h2_oversized_headers`, `h2_oversized_body`.

- [ ] **Step 1:** Write the scenarios and the soak server, a `StaticFiles` + echo + `/baseline2`
  framework on uring with default settings.
- [ ] **Step 2:** Run `SOAK_PROTO=h2 .scripts/soak.sh soak --profile hostile` for 10 minutes. Expected:
  0 fails, and the drain RSS back within the WebSocket soak's tolerance.
- [ ] **Step 3:** Run `SOAK_PROTO=h2 SOAK_HOURS=1 .scripts/soak.sh long`. Expected: 0 fails and no RSS
  trend.
- [ ] **Step 4:** Commit with the message `soak: HTTP/2 scenarios and soak server`.

### Task 17: Full production gate

**Files:**
- Modify: `docs/perf/http2-bench.md` (a "Gate" section)

- [ ] **Step 1:** h2spec: run `.scripts/h2spec.sh high`, `high tls` and `low`. Expected: every listed
  section passes.
- [ ] **Step 2:** Full test suite, `$FEAT` plus `web-socket`, `web-socket-handshake` and `postgres`
  where they build. Run it 3 times. Expected: all pass every time.
- [ ] **Step 3:** ASan. Use
  `RUSTFLAGS=-Zsanitizer=address cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu -p rimu-ws --features "$FEAT" --lib http2`,
  with the target dir under `/mnt/nvme1tb/claude-tmp`. Expected: clean.
- [ ] **Step 4:** Miri. Run `cargo +nightly miri test -p rimu-ws --features http2 --lib http2::conn`,
  excluding io_uring tests. Expected: clean, or each exclusion listed with its reason.
- [ ] **Step 5:** Interop: run `.scripts/h2-interop.sh` against `arena-h2` and the soak server. Then
  run the client against nginx (`docker run --network host nginx` with an h2 config, from the
  `httparena-*` images or `nginx:stable`). Expected: all green.
- [ ] **Step 6:** WebSocket non-regression:
  - Autobahn on drain, uring and uring-direct (`.scripts/autobahn-fuzzingclient-fork.sh`,
    `CONTAINER=docker`);
  - the WebSocket A/B against `feat/hardening` cc847160.

  Expected: Autobahn 512 OK / 2 non-strict / 3 informational, and A/B within noise.
- [ ] **Step 7:** Record everything in the "Gate" section. Commit with the message
  `gate: HTTP/2 production gate results`.

### Task 18: Win the local composite

**Files:**
- Modify: whatever the measurements point at in `wtx/src/http2/conn*`, `conn_driver.rs` and
  `static_files.rs`; `docs/perf/http2-bench.md`

- [ ] **Step 1:** Run all four servers on all profiles, interleaved in one session, then run
  `h2-composite.py`. If rimu is #1 on the composite, go to Step 4.
- [ ] **Step 2:** Find the cost. Use `perf stat -e cycles:u,instructions:u` per request on the losing
  profile, then `perf record` on `arena-h2`. Candidates, ranked by `rivals.md`:
  1. memoise the last request header block per connection, so a byte-identical HPACK block becomes a
     memcmp plus a copy of the decoded headers (cnetmod);
  2. a larger read buffer and fewer `try_read` calls per turn;
  3. fill DATA frames to the peer's max frame size, and gather static bodies into fewer larger writes
     (static-h2);
  4. serialize JSON straight into the output buffer (json-h2c);
  5. TLS record sealing straight from body slices, or kTLS for baseline-h2.

  Each change gets an A/B on cycles per request plus throughput. Keep it only if it wins, and the gate
  tests (Task 17 Steps 1–2) still pass.
- [ ] **Step 3:** Repeat Steps 1–2. Stop after 5 rounds without progress and report to the user with the
  numbers.
- [ ] **Step 4:** A profile where every server's load side is above 90% CPU is generator-capped. It
  counts as a tie, and cycles per request are reported beside it. Write the final table and composite
  into `docs/perf/http2-bench.md`, then commit with the message
  `perf: HTTP/2 local composite results`.
