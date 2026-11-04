# rimu-ws-soak Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A soak and abuse harness, `rimu-ws-soak`, that drives thousands of simulated WebSocket clients against a rimu-ws server for hours. It mixes verified echo traffic with hostile client behaviour, and fails if the server misbehaves or stops being bounded (memory, fds, CLOSE_WAIT, latency, recovery).

**Architecture:**
- A library-plus-binary crate in the rimu-ws workspace.
- It has no dependency on rimu-ws: its own raw frame codec speaks bytes, so clients can misbehave freely, and a bug shared with the server can't hide itself.
- Client slots run scenarios picked by a seeded, weighted mix. Each scenario has an oracle.
- A separate thread runs fixed-rate latency probes, and a 1 Hz `/proc` monitor checks server-side invariants.
- Every failure prints a replay id and a byte transcript.
- The harness's own tests run its oracles against an in-test fake server with fault knobs. This proves each oracle fails when it should.
- A new `soak-server-uring` binary in `wtx-internal` is the real target.

**Tech Stack:**
- Rust 2024, toolchain `nightly-2026-10-12` (repo `rust-toolchain.toml`)
- tokio 1 (`rt-multi-thread`, `net`, `time`, `io-util`, `macros`, `sync`)
- socket2 0.5, rand 0.9 + rand_chacha 0.9, hdrhistogram 7
- serde 1 + serde_json 1, clap 4 (derive), sha1_smol 1, base64 0.22

**Spec:** `docs/superpowers/specs/2026-11-04-rimu-ws-soak-design.md`. Section "Recommended design" is what this plan implements. Sections 3.5 and 3.6, the in-process fuzz targets and proptest, are separate follow-on plans and are not in scope here.

## Global Constraints

- **Names:**
  - crate `rimu-ws-soak`, directory `rimu-ws-soak/`, a member of the root `Cargo.toml` `[workspace] members`;
  - library `rimu_ws_soak`;
  - binary `rimu-ws-soak`.
- **Dependencies:** `rimu-ws-soak` must not depend on `rimu-ws` or any workspace crate.
- **Formatting:** the repo `rustfmt.toml` (2-space indentation, `use_small_heuristics = "Max"`). Run `cargo fmt -p rimu-ws-soak`. Do not format other crates; the working tree has unrelated formatting changes that must stay out of commits.
- **Build and test:** `cargo +nightly-2026-10-12 test -p rimu-ws-soak`. Never run two rimu-ws or soak test processes, servers, or benchmarks at once (fixed ports, `SO_REUSEPORT`).
- **Ports:** `soak-server-uring` listens on `127.0.0.1:9080`. The fake server in tests binds `127.0.0.1:0`.
- **Where it runs:** colossus only. No AWS. Server CPUs `0-5,12-17`, harness CPUs `6-11,18-23` (`taskset`).
- **Files:** output and temp files go under `/mnt/nvme1tb/claude-tmp/soak/`, never `/tmp`.
- **Process handling:** stop servers by pid (`kill <pid>`, the pid from `ss -ltnp` or `$!`), never `pkill -f`.
- **Git:** work on branch `feat/rimu-ws-soak` from `perf/ws-write-queue`. Commit per task. Do not push until the user asks.
- **Oracle slack** for any server limit `L`: `slack(L) = L * 5 / 4 + 250 ms`. The server checks a few times per timeout from a coarse timer.
- **Expected close codes** follow RFC 6455 exactly (table in Task 5). If rimu-ws sends a different code, that is a finding to report to the user. Do not loosen an oracle without the user's agreement.

## Review Focus

- **Client-side resource exhaustion** must be reported as a harness error, never as a server failure. That covers EADDRNOTAVAIL from ephemeral ports, EMFILE in the harness, and a client CPU too saturated to keep up. Test in Task 2.
- **A server that dies or restarts mid-run** must give one loud "server pid gone" violation and a non-zero exit, not silent zeros or another process's numbers. Test in Task 6.
- **An echo scenario cut short by the server** (EOF or a close frame before every echo arrived) is a failure with the reason `server closed during echo`, not a pass. Test in Task 3.
- **Timeout oracles at the edge:** a server that closes at `limit * 1.2` passes, and one that never closes fails at `slack(limit)`. Test in Task 4.
- **Probe latency inflated by the harness itself:** the probe thread measures its own schedule lag. When that lag's p99 is over 1 ms, the cycle is marked `client_saturated` and the latency invariant is skipped for it, with a warning. Test in Task 7.

---

### Task 1: Crate skeleton and raw codec

**Files:**
- Modify: `Cargo.toml` (root): add `"rimu-ws-soak"` to `members`
- Create: `rimu-ws-soak/Cargo.toml`, `rimu-ws-soak/src/lib.rs`, `rimu-ws-soak/src/main.rs` (stub `fn main() {}`), `rimu-ws-soak/src/codec.rs`
- Test: unit tests in `rimu-ws-soak/src/codec.rs`

**Interfaces:**
- Produces, in `rimu_ws_soak::codec`:
  - `pub enum LenForm { Minimal, Ext16, Ext64 }`
  - `pub struct FrameSpec<'a> { pub fin: bool, pub rsv: u8, pub opcode: u8, pub mask: Option<[u8; 4]>, pub payload: &'a [u8], pub declared_len: Option<u64>, pub len_form: LenForm }`
    - `declared_len` overrides the length field and is used for the huge-length cases.
    - `LenForm::Ext16` and `LenForm::Ext64` force non-minimal encodings.
  - `pub fn encode(spec: &FrameSpec<'_>, out: &mut Vec<u8>)`
  - `pub fn client_frame(fin: bool, opcode: u8, payload: &[u8], mask: [u8; 4], out: &mut Vec<u8>)`: the common case.
  - `pub struct ServerFrame { pub fin: bool, pub rsv: u8, pub opcode: u8, pub payload: Vec<u8> }`
  - `pub enum ParseError { MaskedServerFrame, TooLong(u64), BadResponse(&'static str) }`
  - `pub struct Parser`, with `Parser::new(max_len: usize) -> Self`, `push(&mut self, bytes: &[u8])`, and `next_frame(&mut self) -> Result<Option<ServerFrame>, ParseError>`.
  - `pub fn close_code(frame: &ServerFrame) -> Option<u16>`
  - `pub fn upgrade_request(host: &str, path: &str, key: &str) -> Vec<u8>`
  - `pub fn accept_key(key: &str) -> String`
  - `pub struct UpgradeResponse { pub header_len: usize, pub status: u16, pub accept: Option<String> }`
  - `pub fn parse_upgrade_response(buf: &[u8]) -> Result<Option<UpgradeResponse>, ParseError>`: `Ok(None)` until `\r\n\r\n` arrives.

- [ ] **Step 1: Write the failing tests** in `codec.rs`:
  - `accept_key_matches_rfc_example`: `accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="`.
  - `encode_masks_and_picks_minimal_length`: payloads of 0, 125, 126, 65535 and 65536 bytes give header lengths 6, 6, 8, 8 and 14 (with mask). Payload bytes XORed with the mask come back to the original.
  - `encode_forced_forms_and_declared_len`: `Ext64` with 5 bytes gives byte 1 = `0x80 | 127` and length field 5. `declared_len: Some(u64::MAX >> 1)` writes that value and only the given payload bytes.
  - `parser_reassembles_byte_by_byte`: three server frames (text "abc"; binary 70 000 bytes; close 1000) pushed one byte at a time yield exactly those three frames, then `Ok(None)`.
  - `parser_rejects_masked_and_too_long`: a masked server frame gives `Err(MaskedServerFrame)`. A declared length of `max_len + 1` gives `Err(TooLong(max_len + 1))` before the payload arrives.
  - `close_code_reads_first_two_bytes`: a payload of `[0x03, 0xE8, b'x']` gives `Some(1000)`; an empty payload gives `None`.
  - `upgrade_response_partial_then_complete`: `"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: abc\r\n"` gives `Ok(None)`. Adding `"\r\n"` gives status 101, accept `Some("abc")`, and `header_len` equal to the total length.

- [ ] **Step 2: Run `cargo +nightly-2026-10-12 test -p rimu-ws-soak codec`.** Expected: compile errors or FAIL.

- [ ] **Step 3: Implement the `codec` items above.**
  - `accept_key` is SHA-1 of `key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"`, base64-encoded.
  - The `Parser` keeps a `Vec<u8>` buffer and a read offset, and compacts when the offset passes half the buffer.

- [ ] **Step 4: Run the tests from Step 2.** Expected: all PASS.

- [ ] **Step 5: Commit** with `git add Cargo.toml rimu-ws-soak` and message `rimu-ws-soak: crate and raw WebSocket codec`.

### Task 2: Seeds, transcript, connection helpers, fake server

**Files:**
- Create: `rimu-ws-soak/src/rng.rs`, `rimu-ws-soak/src/conn.rs`, `rimu-ws-soak/tests/support/mod.rs` (fake server), `rimu-ws-soak/tests/conn.rs`

**Interfaces:**
- Consumes: `codec::*` (Task 1).
- Produces:
  - In `rng`:
    - `pub type Rng = rand_chacha::ChaCha8Rng`
    - `pub fn seed_for(global: u64, slot: u32, generation: u32) -> u64`: splitmix64 over `global ^ (slot << 32 | generation)`.
    - `pub fn rng(seed: u64) -> Rng`
  - In `conn`:
    - `pub struct ConnOpts { pub rcvbuf: Option<u32>, pub nodelay: bool, pub source_ip: Option<std::net::IpAddr> }`
    - `pub enum Next { Frame(ServerFrame), Eof }`
    - `pub struct Failure(pub String)`
    - `pub enum ConnError { Harness(String), Server(Failure) }`. `Harness` is for client-side errors: EADDRNOTAVAIL, EMFILE, ENFILE or ENOBUFS on connect or socket creation.
    - `pub struct Transcript`: the last 64 events, each `(micros since connect, Sent | Received | Note, bytes)`. `pub fn dump(&self) -> String` gives one line per event, with hex limited to 64 bytes per event.
    - `pub struct Conn`, with:
      - `connect(addr: SocketAddr, opts: &ConnOpts) -> Result<Conn, ConnError>` (socket2 for the options, then tokio)
      - `send(&mut self, bytes: &[u8]) -> Result<(), ConnError>`
      - `upgrade(&mut self, host: &str, path: &str, rng: &mut Rng) -> Result<(), ConnError>`: checks status 101 and `accept_key`.
      - `next_frame(&mut self, deadline: tokio::time::Instant) -> Result<Next, ConnError>`
      - `expect_close(&mut self, codes: &[u16], deadline: Instant) -> Result<(), ConnError>`: skips data frames; a close frame with a code outside `codes`, or EOF first, is a `Server` failure.
      - `expect_eof(&mut self, deadline: Instant) -> Result<(), ConnError>`: discards bytes; a reset counts as EOF.
      - `reset(self)`: sets `SO_LINGER 0`, then drops.
      - `shutdown_write(&mut self)`
      - `transcript(&self) -> &Transcript`
      - `raw(&mut self) -> &mut tokio::net::TcpStream`
  - In `tests/support`:
    - `pub struct Faults { pub corrupt_echo: bool, pub close_mid_echo_after: Option<usize>, pub idle_timeout: Option<Duration>, pub handshake_timeout: Option<Duration>, pub close_code_for_protocol_errors: u16, pub close_code_for_bad_utf8: u16 }`, with `Default` set to a correct server: no corruption, timeouts `None`, codes 1002 and 1007.
    - `pub async fn spawn_fake(faults: Faults) -> SocketAddr`: a tokio echo server written with `codec`. It accepts masked frames, echoes data, answers pings, replies to close, and applies the faults.

- [ ] **Step 1: Write the failing tests** in `tests/conn.rs`:
  - `seed_for_is_stable_and_distinct`: `seed_for(1, 2, 3)` is equal across calls and differs from `seed_for(1, 2, 4)` and `seed_for(1, 3, 3)`.
  - `upgrade_and_echo_against_fake`: connect to `spawn_fake(Faults::default())`, upgrade, send a masked text "hi". `next_frame` gives text "hi"; a close 1000 then `expect_close(&[1000], +1s)` is Ok.
  - `expect_eof_times_out_as_server_failure`: against a fake server that never closes, `expect_eof(+200ms)` gives `Err(ConnError::Server(_))` after 200 to 400 ms.
  - `connect_refused_is_server_failure_but_addr_not_available_is_harness`:
    - Connecting to a closed port is `Server`.
    - Connecting with `source_ip: Some("192.0.2.1")` (not local) is `Harness`. It maps EADDRNOTAVAIL; this is a Review Focus line.
  - `transcript_keeps_last_64_events_and_limits_hex`: after 100 sends of 200 bytes, `dump()` has 64 lines, each with at most 128 hex chars.

- [ ] **Step 2: Run `cargo +nightly-2026-10-12 test -p rimu-ws-soak --test conn`.** Expected: FAIL (items missing).

- [ ] **Step 3: Implement `rng`, `conn` and `tests/support`.** Masks come from the caller's `Rng`. `upgrade` sends a random 16-byte base64 key.

- [ ] **Step 4: Run the tests from Step 2.** Expected: PASS.

- [ ] **Step 5: Commit** with message `rimu-ws-soak: seeds, transcripts, connection helpers, fake server`.

### Task 3: Scenario engine, runner, replay, echo scenarios, soak server

**Files:**
- Create:
  - `rimu-ws-soak/src/scenario/mod.rs`
  - `rimu-ws-soak/src/scenario/echo.rs`
  - `rimu-ws-soak/src/runner.rs`
  - `rimu-ws-soak/tests/echo.rs`
  - `wtx-internal/src/bin/soak-server-uring.rs`
  - `.scripts/soak.sh`
- Modify:
  - `rimu-ws-soak/src/main.rs`: the CLI, in the form `rimu-ws-soak run ...` and `rimu-ws-soak replay ID ...`
  - `wtx-internal/Cargo.toml`: a `[[bin]] soak-server-uring` with `required-features = ["soak-server-uring"]` and the feature `soak-server-uring = ["rimu-ws/crypto-ring", "rimu-ws/io-uring", "rimu-ws/web-socket-server-framework"]`

**Interfaces:**
- Consumes: `conn::*` and `rng::*` (Task 2).
- Produces:
  - In `scenario`:
    - `#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, clap::ValueEnum)] pub enum Scenario { Echo, SplitEveryByte, CtrlInFragments, NeverRead, Slowloris, IdlePre, IdlePost, CloseInHandshake, RstMidframe, HalfClose, PingFlood, Garbage, Invalid, HugeLen }`. Serde and clap names are snake_case.
    - `pub struct Weights(pub Vec<(Scenario, u32)>)`, with `pick(&self, rng: &mut Rng) -> Scenario`.
    - `pub fn profile(name: &str) -> Option<Weights>` covers three profiles:
      - `baseline`: `echo=100`
      - `hostile`: `echo=40, split_every_byte=5, ctrl_in_fragments=5, never_read=5, slowloris=5, idle_pre=3, idle_post=3, close_in_handshake=4, rst_midframe=6, half_close=4, ping_flood=4, garbage=4, invalid=10, huge_len=2`
      - `storm`: `rst_midframe=30, close_in_handshake=30, slowloris=20, never_read=20`
    - `pub fn parse_weights(s: &str) -> Result<Weights, String>`: `"echo=40,garbage=4"`.
    - `pub struct Limits { pub handshake: Duration, pub idle: Duration, pub close: Duration, pub max_payload: u64 }`
    - `pub fn slack(limit: Duration) -> Duration`
    - `pub struct Ctx { pub addr: SocketAddr, pub host: String, pub path: String, pub limits: Limits, pub opts: ConnOpts }`
    - `pub enum Outcome { Pass, Fail { reason: String, transcript: String }, HarnessError(String) }`
    - `pub async fn run(scenario: Scenario, ctx: &Ctx, rng: &mut Rng) -> Outcome`
  - In `runner`:
    - `pub struct RunConfig { pub global_seed: u64, pub slots: u32, pub duration: Duration, pub weights: Weights, pub ctx: Ctx, pub source_ips: Vec<IpAddr> }`. Slot `i` uses `source_ips[i % len]`.
    - `#[derive(serde::Serialize)] pub struct Record { pub slot: u32, pub generation: u32, pub seed: u64, pub replay: String, pub scenario: Scenario, pub outcome: &'static str, pub reason: Option<String>, pub transcript: Option<String>, pub elapsed_ms: u64 }`. The outcome is `"pass"`, `"fail"` or `"harness_error"`; a transcript is present only on fail.
    - `pub fn replay_id(global: u64, slot: u32, generation: u32) -> String`, formatted `"{global}:{slot}:{generation}"`.
    - `pub fn parse_replay(s: &str) -> Option<(u64, u32, u32)>`
    - `pub async fn run_slots(cfg: &RunConfig, stop: Arc<AtomicBool>, sink: tokio::sync::mpsc::Sender<Record>)`
      - Each slot loops through generation 0, 1, ... until `stop`.
      - Scenario and bytes come from `rng(seed_for(global, slot, gen))`.
    - `pub async fn replay(ctx: &Ctx, weights: &Weights, id: (u64, u32, u32)) -> Record`
- Scenario oracles in this task:
  - `echo`: 1 to 20 messages. Lengths: 0 to 125 for 60% of messages, up to 4096 for 30%, and 70 000 to 200 000 for 10%. Text (ASCII) or binary. 25% are fragmented into 2 to 4 frames. The batch is written in random chunks. Every echo must be byte-identical and in order, followed by close 1000 and EOF within 2 s. EOF or a close before all echoes arrive fails with the reason `server closed during echo`.
  - `split_every_byte`: like `echo` with at most 3 messages under 300 bytes, written one byte per write with `TCP_NODELAY`.
  - `ctrl_in_fragments`: a 3-fragment text with a ping between fragments 1 and 2. The pong (same payload) must arrive before the reassembled echo.
- Soak server (`soak-server-uring`):
  - It echoes like `autobahn-server-uring`, without compression, on `127.0.0.1:9080`, path `/`.
  - The handler sets `*ws.max_payload_len_mut()` from `WTX_MAX_PAYLOAD` (default `1048576`).
  - `UringParams` come from env: `WTX_HANDSHAKE_MS` (default 2000), `WTX_IDLE_MS` (5000), `WTX_CLOSE_MS` (2000), `WTX_RX_HIGH_WATER` (65536) and `WTX_DIRECT` (0). Spin stays at 0.
- `.scripts/soak.sh`:
  - Builds both release binaries.
  - Starts the server under `taskset -c 0-5,12-17` and waits for 9080 with `ss -ltn`.
  - Runs `taskset -c 6-11,18-23 target/release/rimu-ws-soak run --url ws://127.0.0.1:9080/ --pid $pid "$@"`.
  - Kills the server by pid and exits with the harness's code.

- [ ] **Step 1: Write the failing tests** in `tests/echo.rs`, all against `spawn_fake`:
  - `weights_pick_matches_profile`: over 100 000 picks from `profile("hostile")`, the `echo` share is between 0.38 and 0.42.
  - `parse_weights_rejects_unknown`: `parse_weights("echo=1,nope=2")` is `Err` naming `nope`.
  - `echo_scenarios_pass_on_good_server`: 200 runs each of `Echo`, `SplitEveryByte` and `CtrlInFragments` with distinct seeds all give `Outcome::Pass`.
  - `corrupted_echo_fails_with_transcript`: with `corrupt_echo: true`, some `Echo` run among 50 gives `Fail` whose transcript is non-empty.
  - `early_close_is_server_closed_during_echo`: with `close_mid_echo_after: Some(1)`, a run with at least 2 messages fails, and the reason contains `server closed during echo`.
  - `replay_reproduces_scenario_and_bytes`: run slot 7 generation 3 through `run_slots` with 1 slot for 1 s. `replay` with the same id gives the same scenario. With the fake server logging received bytes per connection, the bytes are identical.

- [ ] **Step 2: Run `cargo +nightly-2026-10-12 test -p rimu-ws-soak --test echo`.** Expected: FAIL.

- [ ] **Step 3: Implement `scenario` (the three echo scenarios; the others return `Outcome::HarnessError("not implemented")` until Tasks 4 and 5), `runner`, the CLI, `soak-server-uring` and `.scripts/soak.sh`.**
  - CLI flags for `run`:
    - `--url --pid --seed --slots --duration --profile --weights --handshake-timeout --idle-timeout --close-timeout --max-payload --out --source-ips --probes --probe-rate --cycles --fd-flood`
    - Durations parse `"2s"` / `"500ms"`.
    - `--source-ips 127.0.0.1-127.0.0.8` expands the range.
  - Records go as JSONL to `--out`, default `/mnt/nvme1tb/claude-tmp/soak/soak-<seed>.jsonl`. Every failure also goes to stderr as one line: `FAIL <scenario> replay=<id>: <reason>`.

- [ ] **Step 4: Run the tests from Step 2, then a smoke run.**
  - Tests: PASS.
  - Smoke run: `bash .scripts/soak.sh --profile baseline --slots 50 --duration 20s` exits 0 with 0 fail records (`grep -c '"fail"'` gives 0).

- [ ] **Step 5: Commit** with message `rimu-ws-soak: scenario engine, runner, replay, echo scenarios; soak-server-uring`. Add only `rimu-ws-soak`, `wtx-internal/Cargo.toml`, `wtx-internal/src/bin/soak-server-uring.rs` and `.scripts/soak.sh`.

### Task 4: Hostile connection scenarios

**Files:**
- Create: `rimu-ws-soak/src/scenario/abuse.rs`, `rimu-ws-soak/tests/abuse.rs`
- Modify: `rimu-ws-soak/src/scenario/mod.rs` (dispatch)

**Interfaces:**
- Consumes: `Ctx`, `Limits`, `slack`, `Conn` (Tasks 2 and 3).
- Produces: oracles for these scenarios:
  - **`never_read`:**
    - Setup: `rcvbuf: Some(4096)`, upgrade, then send 64-byte text frames as fast as possible without reading.
    - Pass: a single `send` blocks for at least 500 ms within 10 s, which shows the server stopped reading, or the server closes. Then `reset`.
    - Fail: 10 s of unblocked sending (`server buffered without bound`).
  - **`slowloris`:**
    - Setup: send the upgrade request one byte every 100 ms.
    - Pass: EOF or reset within `slack(limits.handshake)` of connect.
    - Fail: the whole request got through and was answered with 101 before the deadline (the server is too slow to cut it off), or the connection is still open at the deadline.
  - **`idle_pre`:** connect and send nothing. EOF within `slack(min(handshake, idle))`.
  - **`idle_post`:** upgrade and send nothing. EOF, or a close frame then EOF, within `slack(idle)`.
  - **`close_in_handshake`:** send a random prefix (1 to len-1 bytes) of the upgrade request, then either `shutdown_write` with the server's EOF expected within 2 s, or `reset` with no oracle.
  - **`rst_midframe`:** upgrade, send one valid frame header plus a random fraction of its payload, then `reset`. No oracle; leaks show up in the monitor.
  - **`half_close`:**
    - Variant A: 1 to 5 echo messages plus a close frame, then `shutdown_write`. All echoes, then close 1000, then EOF within 2 s.
    - Variant B: the same messages without the close frame, then `shutdown_write`. All echoes, then EOF (or close, then EOF) within `slack(limits.close) + 2s`.
  - **`ping_flood`:**
    - Upgrade, then send 10 000 pings with random payloads of up to 125 bytes while reading concurrently.
    - Every pong payload must equal one of the sent ping payloads. At least one pong must arrive.
    - Afterwards, an echo of "after" must come back within 1 s.
  - **`garbage`:** upgrade, send 1 to 4096 random bytes. A close frame (any code) or EOF within `slack(limits.idle)`.

- [ ] **Step 1: Write the failing tests** in `tests/abuse.rs`, with limits `handshake 300ms, idle 300ms, close 300ms`:
  - `abuse_scenarios_pass_on_fake_with_timeouts`: with the fake's timeouts set to 300 ms, 20 seeds of each abuse scenario all `Pass`.
  - `idle_post_fails_without_server_timeout`: with `idle_timeout: None`, `IdlePost` gives `Fail` after about `slack(300ms)` (between 600 and 900 ms).
  - `slowloris_fails_without_handshake_timeout`: with `handshake_timeout: None`, `Slowloris` gives `Fail`.
  - `timeout_edge`: with the fake's idle timeout at 360 ms (1.2x the limit), `IdlePost` passes. A fake that never closes fails no later than `slack(300ms) + 100ms`.
  - `never_read_fails_on_unbounded_server`: with the fake reading into an unbounded buffer (add `Faults::unbounded_reads: bool`) and the client's 10 s budget shortened to 1 s through a test-only `Limits` field `never_read_budget: Duration` (default 10 s), `NeverRead` gives `Fail` containing `without bound`.

- [ ] **Step 2: Run `cargo +nightly-2026-10-12 test -p rimu-ws-soak --test abuse`.** Expected: FAIL.

- [ ] **Step 3: Implement `abuse.rs`** with the oracles above. Add `never_read_budget: Duration` to `Limits`, default 10 s, with no CLI flag.

- [ ] **Step 4: Run all `rimu-ws-soak` tests.** Expected: PASS.

- [ ] **Step 5: Commit** with message `rimu-ws-soak: hostile connection scenarios`.

### Task 5: Invalid frames and huge lengths

**Files:**
- Create: `rimu-ws-soak/src/scenario/invalid.rs`, `rimu-ws-soak/tests/invalid.rs`
- Modify: `rimu-ws-soak/src/scenario/mod.rs`

**Interfaces:**
- Consumes: `encode`, `FrameSpec`, `Conn::expect_close`.
- Produces:
  - `pub enum InvalidCase { BadUtf8, ReservedOpcode, Rsv1NoExtension, Unmasked, FragmentedControl, ControlTooLong, BadCloseCode, OneByteClose, StrayContinuation, DataInsideFragmented, Oversized }`.
  - `pub fn expected_codes(case: InvalidCase) -> &'static [u16]`. Every case is `[1002]`, except `BadUtf8` (`[1007]`) and `Oversized` (`[1009]`).
  - The `Invalid` scenario picks a case uniformly. It upgrades, optionally sends 0 to 3 valid echoes first (verifying them), sends the case's bytes, then calls `expect_close(expected_codes(case), +2s)` followed by `expect_eof(+2s)`.
  - Case bytes:
    - `BadUtf8`: text `[0xC3, 0x28]`
    - `ReservedOpcode`: opcode 3
    - `Rsv1NoExtension`: rsv 4 on text
    - `Unmasked`: `mask: None`
    - `FragmentedControl`: ping with `fin: false`
    - `ControlTooLong`: ping with 126 bytes
    - `BadCloseCode`: close with 999 or 1005
    - `OneByteClose`: close payload `[0x03]`
    - `StrayContinuation`: opcode 0 with `fin: true` first
    - `DataInsideFragmented`: text `fin: false`, then text `fin: true`
    - `Oversized`: `declared_len: Some(max_payload + 1)` with no payload
  - `HugeLen` declares one of `u64::MAX >> 1`, `1 << 32` or `max_payload + 1`, then sends 1 payload byte every 100 ms. It expects a close in `[1009, 1002]` within 1 s, then EOF.

- [ ] **Step 1: Write the failing tests** in `tests/invalid.rs`:
  - `every_case_passes_on_fake`: each `InvalidCase` with 5 seeds `Pass`es.
  - `wrong_code_fails`: with `close_code_for_bad_utf8: 1002`, the `BadUtf8` case `Fail`s with a reason containing `1002` and `1007`.
  - `huge_len_passes_and_fails_by_code`: it passes on the default fake. With a fake that closes huge lengths with 1000 (add `Faults::huge_len_code: u16`, default 1009), it fails.

- [ ] **Step 2: Run `cargo +nightly-2026-10-12 test -p rimu-ws-soak --test invalid`.** Expected: FAIL.

- [ ] **Step 3: Implement `invalid.rs`.** The fake server's checks (protocol, UTF-8, length) must implement these cases so the default fake passes.

- [ ] **Step 4: Run all `rimu-ws-soak` tests.** Expected: PASS.

- [ ] **Step 5: Commit** with message `rimu-ws-soak: invalid-frame and huge-length scenarios`.

### Task 6: Server monitor and invariants

**Files:**
- Create: `rimu-ws-soak/src/monitor.rs`, `rimu-ws-soak/tests/monitor.rs`, fixtures `rimu-ws-soak/tests/fixtures/status.txt` and `rimu-ws-soak/tests/fixtures/tcp.txt`

**Interfaces:**
- Produces, in `monitor`:
  - `pub struct TcpStates { pub established: u32, pub close_wait: u32, pub time_wait: u32, pub other: u32, pub recv_q: u64, pub send_q: u64 }`. Counts cover sockets whose *local* port is the server port.
  - `pub struct Sample { pub rss_kib: u64, pub hwm_kib: u64, pub fds: u32, pub cpu_ticks: u64, pub tcp: TcpStates }`
  - `pub fn parse_status(text: &str) -> Option<(u64, u64)>`: `VmRSS` and `VmHWM` in KiB.
  - `pub fn parse_tcp_table(text: &str, port: u16) -> TcpStates`: the `/proc/net/tcp` format, where state `01` is established, `08` CLOSE_WAIT and `06` TIME_WAIT, and `tx_queue:rx_queue` is hex.
  - `pub fn sample(pid: u32, port: u16) -> Result<Sample, MonitorError>`. It reads `/proc/<pid>/status`, counts `/proc/<pid>/fd`, takes `utime + stime` from `/proc/<pid>/stat`, and reads `/proc/net/tcp` plus `tcp6`.
  - `pub enum MonitorError { PidGone, Io(std::io::Error) }`. `PidGone` is returned when `/proc/<pid>` is missing or its `starttime` changed since the first sample. The process start time is stored on the first call per pid, in a `Monitor` struct: `Monitor::new(pid, port) -> Result<Monitor, MonitorError>` and `Monitor::sample(&mut self) -> Result<Sample, MonitorError>`.
  - `pub struct Baseline { pub rss_kib: u64, pub fds: u32 }`
  - `pub struct Budgets { pub slots: u32 }`
  - `pub enum Violation { PidGone, Fds { fds: u32, limit: u32 }, Rss { rss_kib: u64, limit_kib: u64 }, CloseWait { count: u32 }, Busy { cpu_pct: f64 }, Latency { p99_us: u64, limit_us: u64 }, NoRecovery(String), Leak(String) }`, with `serde::Serialize`.
  - `pub fn check_running(base: &Baseline, s: &Sample, live_conns: u32, budgets: &Budgets, close_wait_streak: &mut u32) -> Vec<Violation>`:
    - fds must be at most `base.fds + live_conns + 64`;
    - RSS must be at most `base.rss_kib + 256 * budgets.slots + 65536` (KiB);
    - CLOSE_WAIT must be at most 64. It is reported only once exceeded in 3 consecutive samples, which the caller's `close_wait_streak` counts.
  - `pub fn check_drained(base: &Baseline, s: &Sample) -> Vec<Violation>`: fds at most `base.fds + 16`, RSS at most `base.rss_kib * 11 / 10 + 16384`, and CLOSE_WAIT equal to 0. Failures are `Leak`.

- [ ] **Step 1: Write the failing tests** in `tests/monitor.rs`:
  - `parses_status_fixture`: `VmRSS: 12345 kB` / `VmHWM: 23456 kB` gives `(12345, 23456)`.
  - `parses_tcp_fixture`: a fixture with 2 established, 3 CLOSE_WAIT and 1 TIME_WAIT on port 9080 (local `0100007F:2378`) and 4 sockets on other ports gives `established 2, close_wait 3, time_wait 1`, with queue sums equal to the fixture's.
  - `samples_own_process`: `Monitor::new(std::process::id(), 9)` then `sample()` is Ok with `fds > 0` and `rss_kib > 0`.
  - `dead_pid_is_pid_gone`: spawn `sleep 0.1`, sample, wait for it to exit and be reaped. `sample()` gives `Err(PidGone)`.
  - `close_wait_needs_three_samples`: four samples with CLOSE_WAIT 100 give no violation for the first two, then `CloseWait` on the third and fourth.
  - `drained_leak_detected`: `check_drained` with fds at `base + 17` gives one `Leak`.

- [ ] **Step 2: Run `cargo +nightly-2026-10-12 test -p rimu-ws-soak --test monitor`.** Expected: FAIL.

- [ ] **Step 3: Implement `monitor.rs`.** The process start time is field 22 of `/proc/<pid>/stat`, counted after the `)` of the command name.

- [ ] **Step 4: Run all `rimu-ws-soak` tests.** Expected: PASS.

- [ ] **Step 5: Commit** with message `rimu-ws-soak: /proc monitor and invariants`.

### Task 7: Latency probes and the cycle driver

**Files:**
- Create: `rimu-ws-soak/src/probe.rs`, `rimu-ws-soak/src/cycle.rs`, `rimu-ws-soak/tests/cycle.rs`
- Modify: `rimu-ws-soak/src/main.rs` (`run` calls `cycle::run`)

**Interfaces:**
- Consumes: `runner::run_slots`, `monitor::*`, `scenario::profile`.
- Produces:
  - In `probe`:
    - `pub struct ProbeStats { pub count: u64, pub p50_us: u64, pub p99_us: u64, pub max_us: u64, pub lag_p99_us: u64, pub failures: u64 }`
    - `pub struct Probes`
    - `Probes::spawn(ctx: Ctx, connections: u32, rate_hz: u32) -> Probes`: a dedicated OS thread with its own current-thread tokio runtime. Each probe connection sends one 32-byte text at a fixed schedule (`connections * rate_hz` total per second, spread evenly), verifies the echo, and records the round trip in an HDR histogram (1 µs to 10 s, 3 significant figures). `lag` is how late each send started against its schedule.
    - `snapshot(&self) -> ProbeStats`: resets the histograms.
    - `stop(self)`
  - In `cycle`:
    - `pub struct CycleConfig { pub run: RunConfig, pub pid: Option<u32>, pub port: u16, pub cycles: u32, pub warmup: Duration, pub drain: Duration, pub probes: u32, pub probe_rate: u32 }`
    - `pub struct Summary { pub cycles: u32, pub records: u64, pub fails: u64, pub harness_errors: u64, pub violations: Vec<Violation>, pub client_saturated_cycles: u32 }`
    - `pub async fn run(cfg: CycleConfig, out: &mut dyn std::io::Write) -> Summary`
  - Each cycle:
    1. Warmup: probes only, for `warmup` (default 30 s). Its p99 is the cycle's latency baseline, and its RSS and fds become `Baseline`. The first cycle's baseline is kept for leak checks.
    2. Mix: `run_slots` for `duration`, sampling once a second (`check_running`). Each second, probes run against `limit_us = max(5 * baseline_p99, baseline_p99 + 1000)`, unless `lag_p99_us > 1000` (`client_saturated`, warn and skip).
    3. Drain: stop the slots and wait `drain` (default 10 s).
    4. `check_drained` against the first baseline.
    5. Recovery: a fresh connection must upgrade and echo within 1 s, or `NoRecovery`.
  - Output and exit status:
    - Every sample, record and violation is written as one JSONL line tagged `"kind": "sample" | "record" | "violation"`. A final `"kind": "summary"` line closes the output.
    - `main` exits 0 only if `fails == 0 && violations.is_empty()`, 2 if only harness errors occurred, and 1 otherwise.
    - Without `--pid`, monitor checks are skipped with a warning.

- [ ] **Step 1: Write the failing tests** in `tests/cycle.rs`, against `spawn_fake` with `pid: Some(std::process::id())`, since the fake runs in-process:
  - `clean_cycle_summary`: 1 cycle with warmup 1 s, duration 2 s, drain 1 s, 20 slots and the baseline profile gives `fails == 0`, `violations.is_empty()`, `records > 0`, and a `summary` line as the last JSONL line.
  - `corrupt_server_counts_fails`: with `corrupt_echo`, `fails > 0`.
  - `saturated_probe_lag_skips_latency`: `probe::lag_exceeds(lag_p99_us: u64) -> bool` returns true for 1001 and false for 1000. Exercise it through a `cycle::latency_verdict(baseline_p99: u64, stats: &ProbeStats) -> Verdict { Ok, Violation(u64, u64), Saturated }` unit test: stats with lag 2000 µs give `Saturated`; stats with p99 6x the baseline and lag 0 give `Violation`.

- [ ] **Step 2: Run `cargo +nightly-2026-10-12 test -p rimu-ws-soak --test cycle`.** Expected: FAIL.

- [ ] **Step 3: Implement `probe.rs`, `cycle.rs` and the `run` wiring.**

- [ ] **Step 4: Run all `rimu-ws-soak` tests, then a live check.**
  - Tests: PASS.
  - Live check: `bash .scripts/soak.sh --profile hostile --slots 500 --duration 60s --cycles 1` exits 0, or prints `FAIL` lines with replay ids. Each `FAIL` is either a rimu-ws finding or an oracle bug: replay it with `rimu-ws-soak replay <id> --url ws://127.0.0.1:9080/` and fix oracle bugs here.

- [ ] **Step 5: Commit** with message `rimu-ws-soak: latency probes, cycles, invariants, exit status`.

### Task 8: fd-flood phase and the full soak

**Files:**
- Create: `rimu-ws-soak/src/fdflood.rs`
- Modify:
  - `rimu-ws-soak/src/cycle.rs`: when `--fd-flood N` is set, run the flood after the drain check.
  - `.scripts/soak.sh`: modes.
  - `rimu-ws-soak/README.md` (new): usage, profiles, exit codes, how to replay.

**Interfaces:**
- Consumes: `Conn`, `Monitor`.
- Produces: `pub async fn fd_flood(ctx: &Ctx, monitor: &mut Monitor, n: u32, hold: Duration) -> Vec<Violation>`.
  - It opens `n` upgraded connections from as many source IPs as configured, then holds them for `hold` (default 10 s).
  - Throughout the hold, server CPU (from `cpu_ticks` deltas, at `sysconf(_SC_CLK_TCK)`) must stay under 20% of one core. Otherwise it reports `Busy`: an accept retry loop.
  - Connections refused or reset while the server is at its limit are counted, not failed.
  - When the hold ends it closes them all. Within 2 s a fresh connection must upgrade and echo, or `NoRecovery`.
- `.scripts/soak.sh` modes, selected by the first argument:
  - `soak` (the default): the arguments above.
  - `fd-plain`: the server under `prlimit --nofile=1024:1024` with `WTX_DIRECT=0`, the harness with `--fd-flood 1500 --profile baseline --slots 20 --duration 10s --cycles 1`.
  - `fd-direct`: the server with `WTX_DIRECT=256` (no prlimit), the harness with `--fd-flood 600 ...` and the same tail.

- [ ] **Step 1: Write the failing test** `fd_flood_detects_busy_spin` (in `tests/cycle.rs`):
  - Pass `fdflood::busy_verdict(cpu_ticks_delta: u64, elapsed: Duration, clk_tck: u64) -> Option<Violation>`.
  - A delta of 50 ticks over 1 s at 100 Hz gives `Some(Busy { cpu_pct: 50.0 })`; 10 ticks gives `None`.

- [ ] **Step 2: Run `cargo +nightly-2026-10-12 test -p rimu-ws-soak --test cycle fd_flood`.** Expected: FAIL.

- [ ] **Step 3: Implement `fdflood.rs`, the cycle hook, the script modes and the README.**

- [ ] **Step 4: Run all tests, then the acceptance runs, one at a time, never two at once.**
  - Tests: PASS.
  - Acceptance runs:
    - `bash .scripts/soak.sh fd-plain` exits 0.
    - `bash .scripts/soak.sh fd-direct` exits 0.
    - `bash .scripts/soak.sh soak --profile hostile --slots 2000 --duration 600s --cycles 3 --source-ips 127.0.0.1-127.0.0.4` exits 0.
  - Expected: all three exit 0. Report any failure to the user with its replay id and transcript; do not change rimu-ws or loosen an oracle without asking.

- [ ] **Step 5: Commit** with message `rimu-ws-soak: fd-flood phase, script modes, README`.
