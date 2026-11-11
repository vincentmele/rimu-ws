# rimu-ws

rimu-ws is a fork of [wtx](https://github.com/c410-f3r/wtx), by Caio Fernandes and the wtx contributors, taken at
upstream commit `d22e17e0` (1 November 2026). rimu-ws is not affiliated with or endorsed by the wtx project; for wtx
itself — its protocol list, crypto backends and features — see the
[upstream README](https://github.com/c410-f3r/wtx#readme). This fork's changes were developed with AI assistance.

Like wtx, rimu-ws is licensed under the [Mozilla Public License 2.0](LICENSE), except [`rimu-ws-soak`](rimu-ws-soak),
which is licensed under [Apache-2.0](rimu-ws-soak/LICENSE). See [NOTICE](NOTICE) for the details.

## What the fork changed, by HttpArena contest

The fork was built to compete in [HttpArena](https://www.http-arena.com)'s experimental league. What follows is the
work behind each contest, at a glance, with where it stood in local head-to-heads against the league's leaders (plod,
viltrum, aegon, fib) and the engine entries (zix, cnetmod). Those runs were on a 12-core Ryzen 9 5900X ("colossus") and
on EC2; the official board's 64-core machine has not scored this fork. Write-ups with method and data are in
[`docs/benchmarks/`](docs/benchmarks).

### Foundations shared by every contest

- **A thread-per-core io_uring executor** (`UringExecutor`): one ring per thread with a single submitter and deferred
  task running, one kernel entry per turn, multishot accept, multishot receive into provided buffer rings, batched
  sends; an optional busy-spin for latency.
- **Zero allocation after warm-up** on every hot path — requests, connections, accept and TLS — with per-thread pools
  sized on demand and tests that count allocations on the server threads. The one accepted exception is ring's nine
  allocations per RSA handshake signature.
- **TLS**: user-space TLS 1.3 with kernel TLS offload where it helps; AEAD keys built once per connection instead of
  per record; the server key parsed once; pooled TLS state wiped when released.

### WebSocket (echo-ws, echo-ws-pipeline, echo-ws-limited)

- **Queued writes** flushed before a blocking read, so a pipeline of echoes leaves in one write instead of one write
  per frame.
- **Synchronous fast paths**: a one-pass frame header parse, masking specialised for small payloads, no allocation per
  frame read, and a drain API that reads buffered frames and queues their replies without awaiting.
- The io_uring executor underneath.

Result: pipelined echo 2.8–3.45× upstream wtx on EC2; on colossus level with or ahead of tokio-ws (6.98 M vs 6.83 M
frames/s pipelined, 480 K vs 434 K unpipelined).

### HTTP/2 (baseline-h2, static-h2, baseline-h2c, json-h2c)

- **A rewritten connection driver**: handlers run inline instead of a task per stream, the responses produced by one
  read leave in one coalesced write, 128 concurrent streams, response bodies sent straight from their buffers.
- **Send path**: owned io_uring sends from a per-thread pool, a mid-turn submit once enough bytes are queued, early
  completion reaping; per-thread pools for output and receive buffers.
- **Less header and event work**: a repeated content-length indexed in HPACK instead of re-encoded, several frames
  processed per wake-up.
- **A fast JSON writer** (`misc::JsonWriter`): fused literals, SIMD escaping while copying, integers formatted in place —
  json-h2c went from 0.54 M to about 1.6 M req/s.
- A static-file handler with its own cache that follows the disk; kernel TLS for h2 over TLS.

Result: the local four-way composite scored 4000 of 4000 — first on every profile against plod (3393), viltrum (2469)
and aegon (1854); hardened with h2spec (139/139 in six modes), a frame-level fuzzer and ASan/Miri.

### HTTP/1.1 (baseline, limited-conn, latency-10k, latency-1m, async, json-comp, json-tls, 8gbit)

- **A new server framework** (wtx had none): a hand-written, resumable SIMD request parser and body decoder that
  answer straight out of the receive buffer and survive requests split at any byte; a router; no `Server` header.
- **Timed responses on io_uring timers** for the async profile, so a delayed request holds no thread.
- **A TLS listener** for json-tls and 8gbit (body echo), on the shared TLS stack.
- **A one-shot gzip encoder for json-comp** (`codec::GzipEncoder`): a DEFLATE encoder for bodies of a few KB with
  hash-chain matching sized to the body, one step of lazy evaluation, and each block written stored, fixed or dynamic,
  whichever is fewest bits; tuned on the profile's own bodies for its score (throughput × size ratio²). It replaced
  zlib level 6 at 1.7× the throughput for 1.2 % more bytes.

Result: first on baseline (898 K req/s, +6.6 % over viltrum), ahead on json-tls (+10 %), level on latency-10k and
8gbit, competitive on async, and first on json-comp with 1.27× viltrum's score; latency-1m needs more cores than colossus has.

### HTTP/3 (baseline-h3, static-h3)

- **Its own QUIC and HTTP/3 stack** (RFCs 9000, 9001, 9002, 9114, 9204), on io_uring UDP: multishot receive with GRO,
  GSO send trains, pacing, NewReno congestion control, loss recovery and key update.
- **Spreading the load**: connection IDs carry the worker index and a classic-BPF reuseport program steers every
  packet to its worker; a connection's first packet is forwarded to the least-loaded worker.
- **Cheap responses**: static-only QPACK with pre-encoded response heads, a request decode memo, responses and their
  ACK packed into one flush, content-type-only responses by default (full RFC 9110 headers behind a flag).
- **Memory**: per-worker pools reached by index, a connection core of at most 4 KiB, no allocation per packet or
  request; acknowledgement-only packets keep no loss-recovery records.
- **Production hardening**: NAT rebinding with path validation, abuse limits (handshake floods, frame floods, reset
  churn, reassembly), Retry under load, stateless reset; checked with h3spec (86 passing, one case pending in h3spec itself),
  interop with curl, quic-go and ngtcp2 under packet loss, fuzzing and a hostile-client soak. Two resource limits a
  hostile client can still exhaust are documented in the [design](docs/superpowers/specs/2026-11-08-http3-quic-design.md)
  (§5.12).

Result: on EC2, first on static-h3 (1.035 M req/s, +24 % over fib) and 1.1 % behind zix on baseline-h3; on colossus,
the top composite (rimu 2000, cnetmod 1851, fib 1818, zix 1712, plod 1546, aegon 1506), first among the experimental
entries on both profiles.
