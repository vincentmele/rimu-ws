# rimu-ws HTTP/3: own QUIC transport, QPACK and server framework (design)

Date: 2026-11-08. Branch `feat/http3`, cut from main (85c9fe8d, the zero-allocation h1 work, pushed to the
rimu fork). Background (colossus, not in the repo):
- `/mnt/nvme1tb/claude-tmp/httpwin/` — the 5 Nov HttpArena investigation (`rules.md`, `rivals.md`, `capabilities.md`).
- `/mnt/nvme1tb/claude-tmp/h3win/reports/` — code reviews of the h3 leaders, read from their source at the
  versions the board ran: `zix.md`, `cnetmod.md`, `plod.md` (goose-http + goose-tls), `fib.md`,
  `aegon-anole-ngtcp2.md`, the scoring client `h2load-client.md`, and the home side `wtx.md`.
  Clones are in `h3win/rivals/` and `h3win/wtx-upstream/`.
Every factual claim below about a rival or the client is cited `path:line` in those reports.

Items marked **[Q1]**–**[Q4]** were decided by the user on 8 Nov (§10).

## 1. Intent

The user wants rimu-ws to win the HttpArena HTTP/3 family (baseline-h3 + static-h3, 2,000 points) in
the experimental league, where plod leads (1956: 6.82M / 923k) ahead of fib (1879: 6.00M / 966k) and
aegon (1689: 6.06M / 773k). The user asked for the design to come from the rivals' actual code, compared
with wtx, using the best patterns: zero allocation and SIMD.

Like the HTTP/2 and HTTP/1.1 work, this is a real library feature of rimu-ws (QUIC transport, HTTP/3,
a server framework), held to a production gate, not code made only for the benchmark. Neither upstream wtx
nor rimu-ws has any QUIC, HTTP/3 or QPACK code today (`wtx.md` §1). Rust entries on the board all use quinn
and score about 0.5M, 12–18× behind the leaders.

## 2. What the leaders do, from their code

### 2.1 The scoring client decides what "fast" means

The board's load is h2load (nghttp2 1.69) on ngtcp2 + nghttp3 + quictls: 64 connections, one per client
thread, 64 streams each (`h2load-client.md`). Facts that drive this design:
- **zix is first at 9.09M using 12.8 cores; the others use 27–40.** The client is the limiter. zix wins by
  giving h2load the fewest packets and bytes to process per request (`zix.md` §13–14).
- The client closes a stream, and only then issues the next request, after the response FIN has arrived
  **and** the server has ACKed the request packet (`h2load-client.md` §1, `ngtcp2_conn.c:13264-13276`).
  A late ACK is a stall, not just CPU.
- Client cost is a fixed amount per wake-up plus per received packet plus per request. Every request
  packet it sends is padded to the full MTU. An early ACK-only packet, or responses arriving one packet at a
  time, costs it a whole extra wake-up and an extra padded packet (§2, §6).
- h2load's own C++ is probably built at -O0 (the Dockerfile's `CXXFLAGS` replaces `-O2`; inferred).
  Each extra response header field costs it QPACK work, -O0 map lookups and, for literals, a malloc. Exact
  static-table entries cost nothing extra (§3–4).
- Fatal or stalling server behaviours: ACK_FREQUENCY/IMMEDIATE_ACK frames, PRIORITY_UPDATE, Version
  Negotiation, GOAWAY mid-run, STOP_SENDING/RESET on a request, GREASE/unknown frames on request
  streams beyond nghttp3's glitch limit (1,000 burst then 33/s), frames for already-closed streams
  (including spurious retransmits) beyond ngtcp2's limit (10,000 burst then 330/s), too little
  MAX_STREAMS headroom, replies from a different address or port (§7). The client never sends
  DATA_BLOCKED, so the server must top up MAX_DATA unasked. h2load never reconnects a QUIC connection.
- Client transport: AES-128-GCM preferred, X25519 key share, v1 only, no 0-RTT/resumption, 8-byte CIDs,
  active_connection_id_limit 2, ack_thresh 2, max_ack_delay 25 ms, QPACK decoder table 4096 / 100 blocked,
  initial_max_streams_uni 100, max_udp_payload 65527 (§2). Loopback MTU is forced to 1500, so datagrams top
  out at 1472 B (IPv4) / 1452 B (IPv6) (§4). `localhost` may resolve to `::1`: listen dual-stack.
- The client receives with UDP_GRO, so a GSO train from the server arrives in one recvmsg (§1). Its socket
  keeps the default receive buffer (about 208 KB, inferred): a burst much larger than that per connection
  risks drops (§6 static).

### 2.2 Comparison of the five stacks and wtx

| | zix (9.09M / 596k) | cnetmod (7.17M / 875k) | plod (6.82M / 923k) | fib (6.00M / 966k) | aegon (6.06M / 773k) | wtx / rimu-ws today | this design |
|---|---|---|---|---|---|---|---|
| QUIC | own, Zig std.crypto | own C++23, BoringSSL | own Goose, goose-tls + libcrypto EVP | own Go stdlib | ngtcp2 + nghttp3 + OpenSSL 3 | none; own TLS 1.3 | own, on wtx TLS 1.3 + ring |
| Workers / steering | 1 socket per pinned worker, 4-tuple hash | per worker, 4-tuple, unpinned | per worker, 4-tuple; ~1/3 idle | prefork 2-P children, 4-tuple | per pinned worker, 4-tuple (anole: CID CBPF, random placement) | thread-per-core TCP | per pinned worker; CID-encoded worker + CBPF; least-loaded placement (§5.11) |
| Receive | multishot recvmsg, 256 × 1552 B ring, no GRO | POLL_ADD + recvmmsg×16, GRO, 64 KiB global leases | POLL_ADD + 8×recvmmsg(32), no GRO | epoll + recvmmsg(32), GRO | recvmsg + recvmmsg×32 | RecvMulti (TCP), copy into conn Vec | multishot recvmsg on a provided-buffer ring; decrypt in place; GRO measured |
| Packing | 1 packet per received datagram: ACK + credits + all its responses; never across datagrams | 1 pack/seal pass per conn per batch, ~50 responses + ACK per 1472 B packet | per conn after each recv batch, ~20 per packet, ACK first | holds output while handlers run (≤1 ms), ~40 per packet | nghttp3 WRITE_MORE | — | 1 flush per dirty connection per receive turn, across all its datagrams; ACK + credits + all responses (§5.3) |
| Send | sendmsg SQE per GSO run, 2 × 32-slot batches, blocking flush on overflow | sendmmsg ≤16 + GSO, 2 getsockopt per send | sendmmsg ≤64 datagrams, GSO ≤65 KB | sendmmsg ≤32 + GSO | sendmmsg + GSO ≤65 KB | Send (TCP) | io_uring sendmsg SQE per GSO train (≤64 segments), packets built in place, one submit per turn, back-pressure never blocks |
| Datagram size | 1200 (1100 payload) | PMTUD 1200→1328→1472 | 1200, probe to 1452 | first probe straight to 1472 | 1452 | — | first probe straight to the ceiling after confirmation (§5.7) |
| AEAD | key re-expanded every packet | EVP_AEAD cached per key phase | EVP cached, 6 calls per packet; AEAD 42% of static instr. | Go asm AES-GCM | OpenSSL 3, 5–6 EVP calls | **key rebuilt every seal/open** (all 4 backends) | keyed objects built once per key phase (§5.6) |
| Allocation per request | 0 (all preallocated) | ~2.3 baseline, 6–8 static (coroutine frames) | 0 malloc; 3 pool ops | few, pooled; heap when >64 frames | nghttp3: 3 ring buffers per stream + 1 per literal; aegon +13–15 | h1: 0 after warm-up (tested) | 0 after warm-up, tested per path (§8) |
| Streams / sent records | linear find; 128-entry ring, small responses not recorded | unordered_map; vector per packet | linear scan of 545 B structs; ACK walks whole list | 64-slot arrays; PN-indexed ring | ngtcp2 pools | slot + generation tables (h1/h2) | id→slot direct index; PN-indexed ring, every frame recorded (§5.4) |
| ACK | ACK-only for ACK-only (RFC violation) | ranges dropped after one send (violation), no duplicate-PN check | every 2nd packet + piggyback | piggyback; 25 ms | ngtcp2 ack_thresh | — | every request-bearing packet ACKed in the same turn's flush; piggybacked; never ACK an ACK-only packet (§5.7) |
| CC / pacing | NewReno IW 32, cap 128 packets | CUBIC, no pacing on loopback | NewReno IW 12000 B, no pacing | CUBIC + HyStart++, pacing | CUBIC; pacing never engaged | — | NewReno (RFC 9002) + pacing with a GSO-train quantum; in-flight cap; measured (§5.7) |
| QPACK | static only; 5-byte HEADERS, no content-type | decoder table 4096/100; pre-encoded response block | static + memo of last response head | static + Huffman; decoder memo by position; re-encodes responses | dynamic 4096 both ways | HPACK + 4-bit-table Huffman | responses from exact static entries, pre-encoded per route/file; decoder capacity chosen by A/B (§5.9) |
| Handlers | inline | inline from accept loop | inline, but via HTTP/1.1 text and re-parse | goroutine pool + hold timer | aegon dispatch_sync | h1/h2: task per connection | inline in the receive turn; poll-once, park only if pending (§5.10) |
| Static | prewarmed cache, zero-copy slices, 1200 B packets, cwnd cap 128 | 1 MiB cache + twins, slices cut to fill packets, GSO +37–49% | 64 KB cache, 2–3 stat per request, 4 copies | FileCache (inotify), body by reference, 1 copy, GSO; 68 µs/req | stat + global rwlock + 2 copies | `StaticFiles`: per-thread cache that follows the disk (h2) | reuse `StaticFiles`; body by reference; slices fill packets; `.br` twin; one copy + seal in place (§5.10) |
| Correctness | many gaps (no retransmit of small responses, unverified client Finished, CRYPTO OOB write, no anti-amplification) | no duplicate-PN detection, Retry on every connection | range-set merge bug loses data, no key update | RFC-complete (interop runner in CI); no Date | path ignored on migration | — | RFC-complete core, production gate (§8) |

### 2.3 What we take, and what we refuse

Take (ranked by expected effect on the score):
1. **Answer each client batch in one burst** — process every datagram of the receive turn, run handlers
   inline, then one flush per dirty connection carrying the ACK, credit top-ups and every response
   (cnetmod's one pass per batch, plod's flush per batch, fib's hold, zix's packet per datagram).
2. **Dense packets, minimal bytes per response** — exact static QPACK entries pre-encoded; one STREAM frame
   per response carrying HEADERS + DATA + FIN; no dynamic table in responses (zix, cnetmod; client cost §2.1).
3. **Batched UDP I/O** — multishot recvmsg on a provided-buffer ring (zix), GSO trains of up to 64
   full-size segments (all), one ring submit per turn, never a blocking flush (avoid zix's overflow trap).
4. **Static from memory by reference**, `.br` twin, slices cut to exactly fill each packet, full-size
   datagrams reached by an immediate PMTU probe (fib, cnetmod).
5. **Zero allocation by construction** — fixed per-worker slabs sized at start, slot arrays, PN-indexed
   sent ring (zix, fib), plus rimu-ws's own pool discipline and alloc-counting tests.
6. **Cached crypto** — AEAD and header-protection keys expanded once per key phase (cnetmod), not per
   packet (zix, and wtx today).
7. **Balance connections over cores** — every leader leaves about a third of its workers idle at 64
   connections; we place each new connection on the least-loaded worker and steer by CID (§5.11).

Refuse: skipping retransmission of small responses (zix), dropping ACK ranges early or skipping
duplicate detection (cnetmod), ACKing ACK-only packets (zix), lossy range sets (plod), unverified
Finished and unchecked CRYPTO buffers (zix), statuses forced to 200 (zix rc1), the HTTP/1.1 text round
trip (plod), per-layer coroutine frames and shared refcounts (cnetmod), goroutine hops and mutexes (fib),
per-request file syscalls (anole, plod), 10 ms timer scans (aegon).

## 3. Goals, non-goals, anti-goals

Goals
- An own QUIC v1 transport (RFC 9000, 9001, 9002), HTTP/3 (RFC 9114) and QPACK (RFC 9204) in rimu-ws, as
  library features with a server framework. Server side first; the transport core is written role-generic
  (`IS_CLIENT` const generic, the house pattern) so a client can follow, but no client ships now.
- **Score (exit criterion, as for h2):** #1 on the local experimental h3 composite (the arena's normalised
  sum of baseline-h3 and static-h3) in head-to-head runs against plod, fib and aegon: rival images built from
  their HttpArena Dockerfiles, the same h2load-h3 generator, the same server and generator cores. If we and
  a rival both hit the generator's ceiling on a profile (generator cores saturated, within 1%), that profile
  is a tie and the other profile decides. Report cnetmod and zix too. The local result governs "done"; the
  one short EC2 batch (user's go-ahead) confirms it, and if EC2 ranks differently that is reported to the
  user as a finding, not silently re-tuned.
- **Zero heap allocations** per packet, per request and per connection on every h3 profile path once a
  worker is warm, including the QUIC handshake except ring's 9 RSA-sign allocations (the exception the user
  accepted for TLS on 8 Nov). Proved by counting-allocator tests like the h1 D1–D3 work.
- **SIMD where it pays:** AES-GCM and GHASH run on ring's assembly (AES-NI + PCLMULQDQ with AVX/MOVBE on
  the board's Zen 2; VAES + VPCLMULQDQ on Zen 3 and later); header-protection masks computed in batches
  with pipelined AES-NI; bitmap scans for ACK ranges; branch-light varint and frame parsing. Each SIMD path
  is kept only if an A/B shows it wins (per-request work is small; packing dominates, §2.1).
- Production quality: the gate in §8.

Non-goals (now)
- 0-RTT and session resumption (h2load never uses them; out by **[Q1]**), HelloRetryRequest beyond what the TLS
  stack already lacks (h2load sends an X25519 key share), server push, QPACK dynamic table on the encoder
  side, ECN, connection migration initiated by the server, DATAGRAM and WebTransport, an HTTP/3 client.
- Async handlers beyond the poll-once-then-park path of §5.10 (no h3 profile needs them).

Anti-goals (would be failure even if it scored)
- Any RFC MUST skipped for speed, any shortcut from the refuse list in §2.3, or tricks aimed at the
  validator (the h3 validator only counts 2xx; we behave as if it checked everything).
- Per-request or per-packet heap allocation, per-stream tasks, locks or atomics on the request path.
- A blocking syscall on a worker's hot path.
- Regressing h1, h2 or WebSocket (shared executor, TLS and crypto code): their suites stay green, and their
  perf is A/B'd like D3 (a >1% regression stops and is reported).

## 4. Constraints

- House style (`wtx.md` §2): sans-I/O protocol cores fed bytes and drained of bytes (like `Http1Conn`,
  `Http2Conn`), thin drivers on the io_uring executor, generics over dyn, one crate-wide `Error` ≤ 16 bytes
  with `QuicClose(TransportErrorCode, QuicError)` / `Http3Close(H3ErrorCode, Http3Error)` variants, fallible
  collections, `// SAFETY:` on every unsafe block with Miri tests, `crate::sync::Arc` and hashbrown only
  (clippy.toml), nightly-2026-10-12.
- Features: `quic = ["tls", ...]`, `http3 = ["http", "quic"]`, `http3-server-framework = ["http3", "io-uring"]`.
- Crypto: ring 0.17.14 (already used for TLS) is the backend for the fast path; the keyed-AEAD trait is
  implemented for every wired backend (ring, aws-lc-rs, graviola, RustCrypto) so the TLS stack gains the
  same fix. TLS posture unchanged: TLS 1.3 only; AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305.
- Server key parsed once (existing `DynSigningKey`); pooled handshake state zeroed with `zero_volatile`
  (existing D3 rule). No key material from one connection readable by the next.
- Colossus: never two wtx test processes at once; no builds during benchmarks; temp/build under
  `/mnt/nvme1tb/claude-tmp`; kill servers by PID from `ss -lunp`/`ss -ltnp`, never `pkill -f`; never
  `system_tune`. Never push to HttpArena or upstream; the rimu fork only when the user says.
- AWS: one short prepared batch at the end, with the user's go-ahead; no long soaks; tear down after.
- Colossus is a 12-core Zen 3 (VAES); the board is a 64-core Zen 2 3995WX (no VAES, no AVX-512). Local
  numbers may flatter VAES paths: the A/B for any crypto change also runs with VAES disabled (ring's
  runtime CPU detection can be steered, or measure the AES-NI path on EC2).

## 5. Architecture

### 5.1 Layers

```
arena-h3 entry (8443/udp, beside h2 on 8443/tcp)            wtx-internal/src/bin/
  Http3ServerFramework: Router, inline handlers, StaticFiles  wtx/src/http/http3_server_framework*
    H3 core (sans-I/O): control/QPACK streams, frames, QPACK  wtx/src/http3/, wtx/src/http3/qpack/
      QUIC core (sans-I/O): Endpoint + Conn                    wtx/src/quic/
        QUIC-TLS bridge on the wtx TLS 1.3 acceptor            wtx/src/tls/ (QUIC mode)
        keyed AEAD + header protection                         wtx/src/crypto/
  per-worker UDP driver on the io_uring executor               wtx/src/executor/ (UDP resource kind)
```

The QUIC core is pure: `Endpoint::recv(now, datagram, meta) -> RecvOutcome`, `Endpoint::flush(now, &mut
TxArena)`, `Endpoint::next_deadline()`, `Endpoint::on_timeout(now)`. It never does I/O or reads the clock.
The H3 core sits on stream events from the QUIC core. Both are testable without sockets, as h1/h2 are
(differential tests, fuzz targets).

### 5.2 Per-worker endpoint on io_uring

- One endpoint per executor thread, pinned, physical cores first. Each owns one dual-stack UDP socket
  (`[::]:8443`, `IPV6_V6ONLY=0`, `SO_REUSEPORT`) with large send/receive buffers (tuned values are library
  defaults chosen by measurement), joined to the reuseport group in worker order (§5.11).
- **Receive:** one multishot `IORING_OP_RECVMSG` on a per-worker provided-buffer ring (default 256 ×
  2 KiB; GRO mode needs 64 KiB buffers and is enabled only if the A/B shows a win). Each completion hands
  the core the datagram **in the ring buffer**: it is decrypted in place and parsed there, and the buffer goes
  back to the ring at the end of the turn. No copy into a connection buffer (the TCP path's `rx` copy is
  not reused). Control messages give the peer address, the local address (`IP_PKTINFO`/`IPV6_RECVPKTINFO`,
  so replies leave from the address the client used) and, with GRO, the segment size.
- **Turn structure:** the executor reaps all CQEs; the endpoint task processes every received datagram of
  the turn (per connection, in arrival order), runs handlers inline, then flushes each dirty connection
  once, then the ring is entered once for all sends and re-arms. This is the "answer each client batch in
  one burst" rule.
- **Send:** a per-worker TX arena of fixed segments (default 512 × 1500 B, contiguous so a train is one
  iovec). Packets are built in place in the arena; consecutive full-size packets to one peer form a GSO train
  (`UDP_SEGMENT`, ≤ 64 segments, ≤ 64 KiB); one `IORING_OP_SENDMSG` per train. If the arena is full the
  connection stays dirty and is flushed next turn: back-pressure, never a blocking send. Segments return to
  the arena on the send CQE.
- **Timers:** the core keeps one deadline per connection (loss/PTO, ACK delay, idle, pacing, drain) in a
  per-worker hashed timer wheel (sub-millisecond ticks); the driver arms one ring timeout for the earliest
  wheel slot. The clock is read once per turn.
- **Executor changes:** a UDP resource kind in the reactor (socket, buffer group, multishot recvmsg,
  sendmsg with cmsgs, completion routing to the endpoint task), plus a crate-internal hook so the endpoint
  sees all completions of a turn before flushing. io-uring 0.7.15 already has every opcode needed. The TCP
  paths are untouched; h1/h2/WS perf is A/B'd anyway (§3).

### 5.3 Packet path

Receive, per datagram: split coalesced long-header packets; read the DCID; look up the connection in the
worker's CID table (open addressing, inline values, generation-checked slot index; the worker byte of our
CIDs is checked first); remove header protection (masks for the whole turn's packets may be computed in one
pipelined batch, §5.6); decode the packet number; open the AEAD in place; walk the frames **once**,
dispatching each (ACK → recovery, STREAM → stream slot, CRYPTO → TLS bridge, credit frames → flow control).
Duplicate packet numbers are detected (RFC 9000 §12.3) with the received-PN bitmap. Undecryptable or
unknown-CID short packets may trigger a rate-limited stateless reset.

Flush, per dirty connection: build packets in place in the TX arena:
1. header with room for the packet number; 2. ACK frame (if any ack-eliciting packet arrived) and owed
control frames (MAX_DATA, MAX_STREAMS, MAX_STREAM_DATA, NEW_CONNECTION_ID, HANDSHAKE_DONE, ...); 3. stream
data from the connection's send queue, round-robin for small responses, one stream to completion at a time
for large bodies (in order, so the client never reassembles); 4. seal in place; 5. apply header protection.
Each small response is one STREAM frame with OFF=0, LEN and FIN, holding the pre-encoded HEADERS frame and
the DATA frame. Packets are filled to the current datagram ceiling; a GSO train ends at the first short
packet. Every packet is recorded for loss recovery (§5.4). Initial/Handshake/1-RTT packets are coalesced into
one datagram during the handshake.

### 5.4 Connection state and memory

Memory model (the same as the h1 D2/D3 pools): **worker-wide pools reached by index**, grown on demand up
to bounded caps (count and bytes), reused without allocation once warm, and trimmed at idle to a few entries
under a byte cap. Per-connection structures hold indices into the pools, not inline arrays, so an idle
connection is small and a busy one borrows what it uses. "Zero allocation after warm-up" means what it
meant for h1: once a worker has served the profile's load, serving more of it (including connection churn)
allocates nothing; growing past an idle trim is warm-up again. Optional prewarm sizes (default off) let a
deployment allocate the pools at start.
- **Connection slab** (cap per worker, default 4,096; generation counters). Steady-state connection core
  target ≤ 4 KiB (CID, keys, recovery and flow-control state, the stream-window index array of u32s);
  handshake-only state (CRYPTO reassembly per level, TLS acceptor state, transcript) comes from the
  existing per-thread TLS pools and returns there, zeroed, at handshake confirmation.
- **Budget:** at the benchmark (64 connections × 64 streams per process, at worst all on one worker) a
  worker's pools stay under 16 MiB; idle a worker keeps under 2 MiB; caps bound the worst case per worker
  and are reported with idle and peak figures. The budget counts everything a worker thread holds on the
  heap once started, measured as net live bytes (allocated minus freed, by layout, on the worker thread):
  pools, connection table, stream slots, executor tasks, HTTP/3 boxes, router-handler buffers, the transmit
  arena and the UDP receive ring. The one exception is the GRO receive ring (256 × 64 KiB = 16 MiB, off by
  default), reported apart: a deployment that turns GRO on adds it per worker (ruling T20-e). The idle
  budget of 2 MiB is on-demand state: the net live bytes over the floor a worker has at start, a fixed cost
  sized by configuration (transmit arena, receive ring, inbox, send slots, CID table, timer wheel). Measured
  floors: 1.86 MiB with GRO on (ring apart) and 2.41 MiB with the library's I/O defaults, pinned by test
  bounds of 2.0 and 2.5 MiB; measured on-demand state after the idle trim: 0.51 MiB (ruling T20-f).
- **Caps follow the connection cap** (task 23b): every per-worker pool that an idle connection holds a
  share of is capped at that share times `max_conns_per_worker` plus a budget for work in flight, so
  that idle HTTP/3 connections reach the connection cap (the next client's first Initial is dropped)
  before any pool runs out. The pools still grow on demand in bounded chunks and are never
  preallocated, so the benchmark and idle budgets above are unchanged. Sizing rule:
  - stream slots: 6 per connection (`SLOTS_PER_CONN`: our control, QPACK encoder and decoder streams
    and the client's three) plus 16,384 for requests (`REQUEST_SLOTS`, 64 connections × a window of
    256), 40,960 at the default cap;
  - frame-reference chunks: 2 per connection (`CONN_CHUNKS`) plus 32,768 for packets in flight
    (`FLIGHT_CHUNKS`), 40,960 at the default cap. An idle connection holds none (measured: 0 after
    the 4,096-connection fill, and 0 for 129 connections after 1,000 client PINGs each): the
    record of an ACK-only packet keeps no frame reference (task 23c, below), so a client that pings
    to keep a connection open and never acknowledges the ACK-only answers pins nothing. Nor does an
    idle connection that had losses: the record of a lost packet stays until its sent ring wraps,
    but gives its frame references back when the packet is declared lost (task 23c fix round 1),
    so after a download that a client acknowledged one datagram in four of (≈ 170 lost records
    kept per connection) it holds none (measured: 250 such connections, 1 chunk in the worker;
    before the fix the worker ran out at the 243rd). The 2 a connection are headroom, not a quota:
    what a connection holds beyond them, its packets in flight (at most a sent ring, 256 records)
    and the lost frames queued to go again, comes from the shared `FLIGHT_CHUNKS`. Task 23b had 256
    a connection (`SENT_RING_LEN`, one chunk for each ACK-only record until the ring wraps),
    1,081,344 at the default cap;
  - the CID table (one server CID per connection), the timer wheel and the dirty/fired lists were
    already sized by the connection cap; the free lists (≤ 1,024 entries each) and the H3 box pool
    (≤ 256 boxes, 4 MiB) bound what is kept for reuse, not what is live, so a connection past them
    allocates and is never refused.

  Measured idle connection (task 23, net live heap of a one-worker server): ≈ 21.6 KB QUIC-only
  (21,613 B), ≈ 27 KB with the client's three HTTP/3 unidirectional streams (+3 × 1,824 B, 27,085
  B). Task 23c adds 16 B to the connection core (4,032 → 4,048 B in the production build) and
  removes the two ACK-only chunks (2 × 200 B) that an idle connection held when that was
  measured; the figures here keep the measured ones plus 16 B, an upper bound (27,101 B). Worst
  case per worker at the default cap of 4,096: idle connections 4,096 × 27,101 B = 111,005,696 B
  ≈ 111 MB, pinged or not; with the request budgets full on top (16,384 slots × 1,632 B =
  26,738,688 B ≈ 27 MB) and every frame-reference chunk in use (40,960 × 200 B = 8,192,000 B ≈ 8
  MB), 145,936,384 B ≈ 146 MB (≈ 139.2 MiB), before the data blocks of requests in flight, which
  flow control bounds (task 23b, before task 23c: ≈ 354 MB, of which ≈ 210 MB were chunks pinned
  by pinging clients). Flow control bounds them per connection only: received stream data has no
  worker-wide cap, and a peer can pin up to `max_out_of_order_bytes_per_conn` (16 MiB) a
  connection of data that waits for earlier data (16 streams × `max_out_of_order_bytes_per_stream`,
  1 MiB, sent out of order with byte 0 withheld), up to 16 MiB × 4,096 = 64 GiB a worker at the
  default cap, on top of the 146 MB. The attacker uploads every byte it pins (1:1), so this is
  not cheap, but nothing below the connection limits bounds it (final review M7). Slot exhaustion
  can still happen when clients hold whole windows of requests on more than 64 connections. It
  does not stall the worker's loop, but it fails for every client of the worker, not only for
  the one that holds the slots: a request stream that finds no slot is refused with
  H3_REQUEST_REJECTED (ruling T10-c; past eight refused at once the connection closes with
  INTERNAL_ERROR), and a new connection whose own control or QPACK streams find no slot is
  closed with INTERNAL_ERROR. One client can cause this on purpose: see the second known limit
  of §5.12.
  Deferred reductions (future work, not done): the 1-RTT sent ring taken on demand (≈ −6 KB per
  idle connection); no QPACK encoder/decoder streams when both dynamic-table capacities are 0
  (RFC 9204 §4.2, ≈ −3.6 KB and −2 slots); the QPACK decode memo allocated lazily (≈ −1.7 KB).
- **CID table**: our CIDs are 8 bytes: byte 0 = worker index, bytes 1–7 random (CSPRNG), with a
  stateless-reset token derived from a per-process key (HMAC). While CID steering is on, each connection has
  **exactly one** server CID and we send no NEW_CONNECTION_ID: RFC 9000 §5.1 forbids CIDs of one connection
  carrying information that correlates them, and a shared worker byte would. With steering off it is the
  same: no NEW_CONNECTION_ID is ever sent (the frame is encoded only by the codec and its tests), so a
  client has no spare server CID to move to, which RFC 9000 §5.1.1 recommends (SHOULD) and does not
  require (final review M8). NAT rebinding works either way (same CID, path validation). The client's
  original DCID maps to the connection during the handshake only.
- **Streams**: a pooled stream slot per open stream; the connection maps client stream `id >> 2` modulo the
  window (default 256) to a slot index through its u32 index array, with generations; no maps. A slot holds
  a small inline receive buffer (default 256 B, enough for a QPACK-encoded request head); larger heads or
  bodies take bounded 4 KiB blocks from a per-worker pool. Out-of-order receive data is reassembled with an
  exact range set (no gap merging; overflow is a connection error, not data loss).
- **Send side**: small responses are written into a per-connection send queue (bytes plus FIN); large
  bodies are referenced (`Rc` into the per-thread static cache, offset, length) until acknowledged, never
  copied into a send buffer.
- **Sent-packet ring** per packet-number space, indexed by PN; each record holds time, size, flags and a
  range of entries in a worker-wide pool of frame references (stream slot + generation, offset, length, FIN;
  control frames as "owed" bits re-raised on loss), since a baseline packet carries ~64 STREAM frames.
  Every frame is recorded, small responses included, but for the ACK frame of an ACK-only packet
  (task 23c): such a packet is not ack-eliciting, nothing of it is sent again if it is lost, and
  its ACK frame only serves ACK-of-ACK (RFC 9000 §13.2.4), so its record holds no frame reference
  and the packet number space keeps the packet number and Largest Acknowledged of the newest
  ACK-only packet (two u64s). When the peer acknowledges that packet the receive floor rises as
  before; an older ACK-only packet acknowledged alone no longer raises it, which only keeps ACK
  frames a little larger for a little longer. A packet with an ACK frame and ack-eliciting frames
  keeps the ACK frame as a frame reference. This holds in all three spaces (Initial and Handshake
  are discarded at confirmation, so it matters there only for fewer chunk pushes). A packet
  declared lost keeps its record, so that a late acknowledgment is known as one, but not its frame
  references: they are owed again (data by range, control frames with their current values) and go
  back to the pool at once (task 23c fix round 1). A late acknowledgment of a lost packet then
  cancels nothing: what was owed again goes once more, a copy too many at worst (RFC 9000 §13.3),
  never data lost or a stream stuck.
- **Received PNs**: per space, a sliding window of u64 bitmaps; ACK frames are encoded from it with
  trailing/leading-zero scans; ranges are kept until an ACK of ours that carried them is acknowledged.
- All caps are bounded in count and bytes; idle trims keep a few entries per pool, like the D2/D3 pools.
  Idle and peak memory per worker are reported.

### 5.5 QUIC-TLS on the wtx TLS 1.3 stack

Reuse the acceptor's ClientHello decode, EncryptedExtensions/Certificate/CertificateVerify/Finished encoding,
signing with the parsed-once key, and the key schedule (which already keeps raw traffic secrets) (`wtx.md`
§3). Add a QUIC mode:
- no record layer and no ChangeCipherSpec; handshake bytes in and out per encryption level (Initial,
  Handshake, 1-RTT) through CRYPTO frames, with bounded, bounds-checked reassembly per level;
- the `quic_transport_parameters` extension (0x39) decoded from the ClientHello and encoded in
  EncryptedExtensions; ALPN `h3` mandatory (no ALPN → `no_application_protocol`);
- initial secrets from the client's DCID with the v1 salt; `quic key`/`quic iv`/`quic hp` per level; key
  update with `quic ku` (respond to the peer's; initiate before the AEAD confidentiality limit);
- the client Finished verified before 1-RTT keys are accepted for receiving (zix skips this; we do not);
- anti-amplification: at most 3× the bytes received before the client's address is validated;
- Retry with AEAD-sealed tokens (address, time, original DCID) off in normal operation and switched on automatically under handshake load (§5.12);
  NEW_TOKEN not sent (h2load does not reuse them).
Groups stay X25519, P-256, P-384 (h2load offers X25519 first).

### 5.6 Crypto and SIMD

- **Keyed AEAD objects:** a new trait whose keys are expanded once per key phase and held by the connection
  (ring `LessSafeKey` built once, not per seal/open). Seal and open in place. The TLS record path switches
  to it too (a free win for h1/h2 TLS; A/B'd).
- **Header protection:** ring's `aead::quic::HeaderProtectionKey` as the baseline (expanded once). An
  optional batched path computes all masks of a turn with an 8-wide pipelined AES-NI routine
  (`std::arch`, runtime-detected, ring fallback); kept only if the A/B wins. ChaCha20 HP uses ring.
- **AES-GCM speed** comes from ring's assembly: on the board (Zen 2) the AES-NI + PCLMULQDQ path, on
  Zen 3+ the VAES path. AES-128-GCM is negotiated first (the client's preference).
- **Parsing:** varints decoded branch-light (length from the top 2 bits, one big-endian load and mask);
  received-PN and ACK bookkeeping on u64 bitmaps; no SIMD where a profile does not show the cost.
- Own AES-GCM (to fuse the static-body copy into encryption) is a non-goal unless profiles show the copy
  matters.

### 5.7 Loss recovery, ACKs, congestion control, PMTU

- RFC 9002 in full: RTT estimator with ack-delay handling, packet threshold 3 and time threshold 9/8, PTO
  with backoff, persistent congestion, the three packet-number spaces, handshake-confirmed rules. Spurious
  retransmits are avoided (they count against ngtcp2's glitch limit, §2.1).
- **ACK policy:** every ack-eliciting packet received in a turn is acknowledged in that turn's flush,
  piggybacked on the response packet (so the client can close the stream and issue the next request at
  once). An ACK-only packet is sent only when ack-eliciting packets arrived and nothing else is going out;
  ACK-only packets are never acknowledged on their own (RFC 9000 §13.2.1). `max_ack_delay` advertised
  honestly. No ACK_FREQUENCY or IMMEDIATE_ACK (fatal for h2load, which does not advertise min_ack_delay).
- **Congestion control:** NewReno per RFC 9002 (initial window 10 × max datagram size, the RFC value) behind a
  trait so CUBIC can follow; **pacing** (an RFC SHOULD) with a burst quantum of one GSO train, so loopback is
  not gated; a per-connection in-flight cap (default chosen by measurement, ~the client's receive buffer) so
  static bursts do not overflow h2load's socket. Defaults are the library's, tuned by measurement, and the
  entry uses them unchanged.
- **PMTU:** start at 1200; right after handshake confirmation send one DF probe at the ceiling
  (min(peer `max_udp_payload_size`, local path limit: 1472 IPv4 / 1452 IPv6)); on ACK switch to it, with
  fallback steps on loss. Probes are not congestion signals.

### 5.8 Flow control and stream credit

Large initial credits (connection receive window 16 MiB, per-stream 1 MiB, `initial_max_streams_bidi` 256,
`initial_max_streams_uni` 16; at least 3 are required by h3). MAX_STREAMS is topped up as streams close,
once half the window is used, and **rides on the response packet** of the same flush, so the client always
has headroom (a late top-up is a silent stall, §2.1). MAX_DATA/MAX_STREAM_DATA are topped up unasked at half
window. Exact values are library defaults tuned by measurement.

### 5.9 HTTP/3 and QPACK

- Control stream with SETTINGS (QPACK_MAX_TABLE_CAPACITY, QPACK_BLOCKED_STREAMS, MAX_FIELD_SECTION_SIZE);
  QPACK encoder/decoder uni streams; GOAWAY only on graceful shutdown; PRIORITY_UPDATE and unknown frames
  received are ignored; nothing GREASE sent; push refused. H3 errors map to the RFC codes.
- **QPACK decoder:** full RFC 9204 decoder with a dynamic table up to the advertised capacity, required insert
  count, blocked streams, section acknowledgements batched into one decoder-stream write per flush. The
  **advertised capacity is chosen by measurement** with h2load: 0 (client sends static + literal, no Section
  Acks; reviewer's estimate: cheaper for the client) against 4096/100 (client indexes repeated fields;
  cnetmod's measured −25% CPU/req). A per-connection **decode memo** keyed by (absolute required insert
  count, field-section bytes) returns the decoded request without re-decoding repeated sections (h2load
  repeats them byte for byte). Huffman decode reuses the wtx table decoder (a wider table only if profiles
  ask). The shared prefix-integer and Huffman code is factored out of HPACK.
- **QPACK encoder (responses):** static table only, never the dynamic table. Response field sections are
  pre-encoded once per route and per (cached file, encoding) and copied; exact static entries are used where
  they exist (`:status 200`, `content-type` values, `content-encoding: br/gzip`, `vary: accept-encoding`).
  Which headers go out was chosen by measurement (**[Q2]**, §10), and decided by the user on 9 Nov 2026:
  the default (library, benchmark and HttpArena entry) is `content-type` only, like cnetmod and zix, which
  is not RFC 9110-compliant; `set_rfc9110_headers(true)` turns on full RFC 9110 compliance (`date`, spliced
  once a second, and `content-length`); the `server` header is the entry's middleware, off by default. The
  measurement (EC2, the RFC 9110 set costs 17 % on baseline-h3) is in `docs/benchmarks/2026-11-09-h3-ec2/`.
- Request validation per RFC 9114 §4.3 (pseudo-headers, no connection-specific headers, lowercase names);
  malformed requests get stream errors, not connection kills (except where the RFC says connection error).

### 5.10 Server framework

`Http3ServerFramework` mirrors the h2 framework's surface (Router, routes, `StaticFiles`, middlewares,
library defaults) so the h2 entry's routes run on h3 unchanged.
- **Inline handlers:** when a request head completes, the handler future is polled **once** inline in the
  receive turn with a no-op waker. If it completes (every h3 profile route does), the response is encoded
  into the connection's send queue in the same turn. If it is pending, the request is parked on a pooled
  per-request task slot and resumes later (bounded, counted). No task per stream or connection otherwise.
- **Middleware** runs the same way (the h2 entry's `server` header middleware, if the Q2 measurement keeps it).
- **Static files:** `StaticFiles` (today in `http2_server_framework/static_files.rs`, a per-thread cache
  that follows the disk, `.br`/`.gz` twins, `vary`) is lifted to a shared `http` module and used by both
  h2 and h3. h3 additionally keeps, per cached (file, encoding), a pre-encoded HEADERS block, and sends the
  body by reference (§5.4), copied once into the packet and sealed in place.

### 5.11 Balancing connections over cores

All leaders rely on the kernel's 4-tuple hash, which leaves about a third of 64 workers idle at 64
connections (plod's own note; `cnetmod.md`, `zix.md`). Design:
- **CID steering:** a classic-BPF reuseport program (`SO_ATTACH_REUSEPORT_CBPF`, unprivileged; anole ships
  one, `aegon-anole-ngtcp2.md`) returns `DCID[0] mod N` (short header: byte 1; long header: byte 6). Our CIDs
  carry the worker index in that byte, so every packet of a connection reaches its worker, also across NAT
  rebinding. A client's first Initial carries a random DCID, so it lands on a random worker.
- **Least-loaded placement without Retry:** a worker that receives a client's first Initial picks the
  least-loaded worker from per-worker connection counters (shared atomics, touched only on connection
  open/close, never per request). If that is another worker, it forwards the raw datagram (and its local
  address) to the target through a bounded per-worker inbox and wakes it with `IORING_OP_MSG_RING`; the
  target creates the connection with a CID carrying its own index. The forwarding worker remembers
  original DCID → target briefly, so a retransmitted first Initial follows. From the client's second flight on,
  the CBPF program routes by our CID. No extra round trip, no Retry.
- If the CBPF attach fails (or the socket set changes), fall back to the kernel hash and in-place accept;
  the program is rebuilt when the worker set changes.
This is a library default (`set_balance(...)`), useful in production, and A/B'd on the benchmark.

### 5.12 Abuse limits and robustness (same bar as the h2 gate)

Configurable limits, each with a production default, each with a unit test:
- **Handshake floods:** a cap on half-open handshakes per worker; above it, Retry switches on
  automatically (address validation before any signature or slot is spent), and above a hard cap new
  Initials are dropped. A handshake deadline (default 10 s, like h1/h2) and the 3× amplification limit.
- **Reassembly abuse:** bounded CRYPTO bytes per level, bounded out-of-order STREAM ranges and bytes per
  stream and per connection; exceeding them is a connection error (CRYPTO_BUFFER_EXCEEDED /
  PROTOCOL_VIOLATION), never unbounded memory.
- **Stream churn (QUIC's rapid reset):** a budget of RESET_STREAM / STOP_SENDING / abandoned requests per
  window, then CONNECTION_CLOSE with H3_EXCESSIVE_LOAD.
- **Frame floods:** budgets for ACK ranges per frame, PATH_CHALLENGE, NEW_CONNECTION_ID / RETIRE, PING and
  empty frames; QPACK encoder-stream inserts bounded by the advertised capacity and an instruction budget.
- **Header and body caps:** MAX_FIELD_SECTION_SIZE advertised and enforced; request body caps per route.
- **Panic isolation per stream:** every inline or parked handler poll is wrapped (as in h2) so a panic
  answers that stream with 500 / H3_INTERNAL_ERROR and the endpoint and its other connections keep going.
- **Graceful shutdown:** GOAWAY, drain in-flight requests within a deadline, CONNECTION_CLOSE.
- Connection cap per worker and per process; idle timeout; stateless reset rate limit.
- **Known limit (user's decision, 11 Nov): a non-acknowledging peer can pin the shared frame-reference pool.**
  A peer that acknowledges honestly, then stops acknowledging while keeping the connection alive with PINGs,
  pins its in-flight records (≤ 256 a connection, about 218 at the 256 KiB in-flight cap) and their
  frame-reference chunks; PTO backoff and persistent congestion give no relief, and the idle timer keeps
  restarting. If it also grants tiny stream windows, so that each packet carries many small STREAM frames
  (up to ≈ 37 chunks a record), about 4 such connections exhaust a worker's `FLIGHT_CHUNKS` (32,768). Other
  connections that then need a chunk are closed with INTERNAL_ERROR. Measured headroom on the benchmark path
  (Task 23d, 64 × 64 in-process, ACKs withheld included): peak 7,315 chunks a worker (22 %); theoretical
  ≤ 13,952 on static-h3 (43 %) and ≈ 4–5 k on baseline-h3, so the benchmark is unaffected. Not fixed; the
  candidate fixes are (d) closing a peer that acknowledges no newer packet for N PTOs, keyed on the newest
  ack-eliciting packet, and (b) making a connection wait instead of closing it when the pool is exhausted.
- **Known limit (user's decision, 11 Nov): one client can take a worker's request slots.** The 16,384
  request slots of a worker (`REQUEST_SLOTS`, §5.4) are one budget for all of its connections: a connection
  has no share of its own, and nothing bounds how long a request may take to send its head (the connection
  idle timeout is the only deadline, and PINGs keep restarting it). A client that opens 256 bidirectional
  streams (`max_streams_bidi`) on each of about 65 connections, sends one byte of a HEADERS frame on each and
  keeps the connections alive with PINGs holds them all, for a few hundred KB of traffic. Every other
  client's new requests on that worker are then refused with H3_REQUEST_REJECTED; at about 160 connections
  the stream-slot pool as a whole is gone and new connections are closed with INTERNAL_ERROR after a full
  handshake (task 23b M-2). With least-loaded placement the attack spreads over the workers: about 65
  connections a worker take the process. h2 in this fork has no request pool shared between connections, so
  this exposure is new with h3. Not fixed; the candidate fixes are a request-head deadline (as h1 and h2
  bound the first head), which frees the slot of a head that does not complete, and a fair share of
  `REQUEST_SLOTS` for each connection before it may borrow more (for example a lower MAX_STREAMS granted
  when the pool runs low) (final review I3).

## 6. HttpArena entry (local only, never pushed)

**[Q3]** (decided): h3 joins the existing `rimu-ws` entry (experimental, **standard** mode), on UDP 8443
beside its h2 on TCP 8443, same certificate and static directory, subscribing `baseline-h3` and `static-h3`.
In standard mode the entry uses the library defaults, so the defaults must be the fast ones (as decided for
h2). Dockerfile `EXPOSE 8443/udp`. Readiness and validation as the arena runs them (h2load-h3 `-n 4`).
The entry binary may be `arena-h2` extended or a separate `arena-h3` in the same image.

## 7. Measurement

- Generator: the h2load-h3 image built locally from `arena-main/docker/h2load-h3.Dockerfile`, with the
  ngtcp2/nghttp3 commits recorded (the recipe clones master).
- Rivals: plod, fib, aegon (experimental) and cnetmod, zix (engine) built from their HttpArena Dockerfiles.
  Same pinned server cores and generator cores for every run, interleaved passes, median of 3, rps plus
  server CPU per request and generator CPU per request (the client is the limiter, so both matter).
- Per-change A/B for every perf decision this document leaves to measurement (GRO, HP batch, QPACK
  capacity, in-flight cap, pacing quantum, balancing, PMTU ceiling).
- One short EC2 batch at the end on a board-like CPU (Zen 2, no VAES), with the user's go-ahead.

## 8. Done means

Production gate (all green):
- Unit and sans-I/O conformance tests per RFC section; differential tests where a reference exists;
  property tests for varints, ACK ranges, reassembly and the sent ring.
- **Interop:** h2load-h3 (the scorer), curl `--http3` (ngtcp2), the ngtcp2 example client and a quic-go
  client, all over dual-stack.
- **Loss and reordering:** a deterministic in-process UDP impairment proxy (drop, reorder, duplicate,
  delay; seeded) between those clients and the server; every request answered, no stall, no spurious
  connection close.
- **h3spec** (QUIC + HTTP/3 error-handling conformance) all passing, if it builds locally; otherwise the
  equivalent cases as tests.
- **Fuzz:** packet header, frame, transport parameters, QPACK decoder and the CRYPTO/TLS bridge (cargo-fuzz,
  time-boxed runs with corpora kept).
- **Soak:** `rimu-ws-soak` (a workspace member) gains QUIC/H3 scenarios: steady load, plus abusive clients
  for every limit in §5.12 (Initial flood, fragmented CRYPTO/STREAM, reset churn, frame floods, QPACK
  insert flood, slow reader, never-read, credit-starved streams, oversized heads), each with bounded memory
  and no stalls. The abusive clients are built on an existing QUIC client library (quinn) driven with raw
  frame control where it allows, plus a small raw-packet sender for what a library will not send.
- **Miri** (strict provenance) on every new unsafe pool, arena and in-place buffer path.
- **Allocation:** counting-allocator tests prove 0 per packet, request and connection after warm-up on
  baseline-h3 and static-h3 paths, with ring's 9 per handshake as the only budget.
- h1, h2 and WebSocket suites green; their A/B within 1%.
Plus the score goal in §3.

**Not measured (the user's decision, 11 Nov).** Task 24's EC2 batch was not run: neither the h1/h2/WebSocket
regression A/B against main `85c9fe8d` nor the final h3 composite of §3. So the "A/B within 1%" item above and
the score goal are unconfirmed after the last changes that affect speed (tasks 23b–23d). These shared-code
changes ship to every h1, h2 and WebSocket user without an A/B:
- the TLS record AEAD keyed once per traffic secret (`9c5732df`, `a23a2176`);
- `BUF_POOL_MAX` of the TLS buffer pool raised from 64 to 256 (ruling T10-q);
- StaticFiles reusing its path buffer on the once-a-second disk check (task 20).

The kit is ready at `/mnt/nvme1tb/claude-tmp/aws-final` (outside the repository; reviewed and fixed, never run).
If the A/B finds a regression above 1 % later, Ruling T18-f's revert plan applies: revert `a23a2176`'s AEAD
wrapping together with `9c5732df` by hand, keeping the `Drop` wipe of the raw fields. The per-task correctness
gates (suites, h2spec, h3spec, interop, validators) did run and passed (final review I4).

## 9. Calls made without the user (check these)

1. **Own QUIC stack**, not quinn-proto or quiche: zero allocation cannot be met on those (quinn's
   per-stream allocations, quiche's and nghttp3's per-stream buffers), and the board shows stock libraries
   with good plumbing top out near 6M (aegon) below the own stacks (6.8–9.1M).
2. **ring** as the fast crypto backend (already used; its AES-GCM assembly is OpenSSL's); keyed-object
   trait added for every backend; the TLS record path adopts it too.
3. **Least-loaded placement by forwarding the first Initial**, plus CID-steering CBPF (§5.11), on by default.
4. **Static-only QPACK encoding of responses**, pre-encoded; the decoder table capacity is left to an A/B.
5. **NewReno + pacing + in-flight cap** as library defaults, values by measurement, RFC initial window.
6. Retry only under handshake load (§5.12), never on every connection; NEW_TOKEN not sent; no ECN.
7. Dual-stack sockets with PKTINFO so replies leave from the address the client used.
8. Worker-wide pools grown on demand to bounded caps and trimmed at idle (the D2/D3 model), not
   preallocated at start; budget ≤ 16 MiB per worker at the benchmark, ≤ 2 MiB idle (§5.4).
9. One server CID per connection while CID steering is on (RFC 9000 §5.1; no correlatable spares).
10. The h2 gate's bar carried over: abuse limits, panic isolation, handshake deadline, graceful shutdown and
    a hostile-client soak (§5.12, §8), with the soak's attackers built on quinn plus a raw sender.
11. Score exit criterion and tie rule copied from h2 (§3); the local result governs, EC2 confirms.

## 10. User decisions (8 Nov)

- **[Q1] Scope: production core.** Every MUST of RFCs 9000/9001/9002/9114/9204, full loss recovery and CC,
  key update, Retry automatic under handshake load, stateless reset, path validation for NAT rebinding, the
  abuse limits of §5.12, and the full gate of §8 including the hostile soak. 0-RTT and session resumption
  are out.
- **[Q2] Response headers: measure, then decide.** Both header sets are built as options of the framework:
  (a) `content-type` only (one exact static entry), and (b) `content-type` + `date` + `server`, as the h2
  entry sends. Once baseline-h3 runs, A/B both against the rivals with h2load-h3 (rps, server and generator
  CPU per request) and bring the numbers to the user, who chooses. The run does not stop for this: work
  continues on static-h3 while the answer is pending, and only the entry's final header set waits on it.
- **[Q3] Entry: the existing `rimu-ws` entry, standard mode,** h3 on UDP 8443 beside h2 (§6). The entry uses
  library defaults, so the defaults are the fast ones.
- **[Q4] Phasing: one run, measured early.** UDP I/O + QUIC core + TLS, then H3/QPACK + baseline-h3
  (measured against the rivals as soon as it runs), then static-h3, then the perf passes and the gate,
  without stopping except for the Q2 numbers above and the EC2 go-ahead.

## 11. Left to the builder

Module boundaries inside `wtx/src/quic/`; timer-wheel tick size; TX arena and buffer-ring sizes; the exact
CBPF program; the per-request parked-task pool size; which RFC test vectors to use (RFC 9001 Appendix A
for initial secrets and HP; RFC 9204 examples); the impairment proxy's design; whether `arena-h2` is
extended or `arena-h3` added. Every perf default named "by measurement" is set from an A/B recorded in the
ledger.
