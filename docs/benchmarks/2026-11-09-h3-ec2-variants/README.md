# HTTP/3 perf-pass-1 variant batch on AWS EC2 — 9 Nov 2026

The second EC2 run: one batch that measured, one knob at a time against `base`, every perf setting of Tasks 16, 17
and 19 (Rulings T16-b, T16-d), plus the first part of Task 16's request-path work (`base` = `d73a785d` vs `prev` =
`e7eca138`). Method, box and harness are those of the first run — read
[`../2026-11-09-h3-ec2/README.md`](../2026-11-09-h3-ec2/README.md) first; only the differences are repeated here.

## 1. Why a batched variant run
The user moved all benchmarking to EC2 and asked not to waste EC2 time, so instead of one launch per perf change the
knobs became runtime switches of arena-h2 (`ARENA_H3_*`, table in `wtx-internal/src/bin/arena-h2.rs`) and one spot run
measured them all (`PHASES=V`). Each variant differs from `base` in exactly one setting; zix ran once per profile per pass
as a fixed reference; 3 passes with the order rotated; the verdict rule is the plan's: a WIN needs ≥ 1 % rps, or ≥ 2 %
less server CPU/req at rps within ±1 %.

## 2. Run
m6a.24xlarge spot, sa-east-1b (spot placement score was 1 for m6a/c6a.24xlarge; capacity was available anyway),
launched 16:13:53 UTC, kit (rimu part 6 MiB) uploaded in 15 s, setup done 16:14:40, three passes 16:14:40–16:47:12
(≈ 11 min each, 66 starts), profiles of `base` and `prev` until 16:50:07, terminated and cleaned up (SG, key; verified
no tagged resource left): **37 min wall, ≈ $0.48**. `base` ran with `ARENA_H3_HEADERS=min` (Q2 default) and
`ARENA_H3_DATA=reuse` (see §4).

## 3. Results (median of 3 passes)
### baseline-h3 — base 5,788k req/s, 2.10 µs server CPU/req (spread 0.1 %)
| variant | knob | req/s vs base | CPU/req vs base | verdict |
|---|---|---|---|---|
| prev | the build before Task 16 | −1.9 % (5,681k) | **+19.7 % (2.51 µs)** | the request-path work so far saves 16 % CPU/req |
| gro-on | UDP GRO, 64 KiB buffers | +0.8 % | −2.8 % | WIN |
| steer-kernel | kernel 4-tuple hash, no CID steering/balance | −0.0 % | −4.4 % | win within spread |
| balance-off | CID steering on, least-loaded placement off | +0.1 % | −8.2 % | win within spread |
| data-fresh | clone `State::data` per request (h2 semantics) | −0.9 % | +9.5 % | loss — the cost of the safe default (Ruling T16-e) |
| ring512 | 512 receive buffers | −0.6 % | +0.2 % | = |
| flush-slot | flush connections in slot order | −0.4 % | +0.7 % | = |
| pin-off | workers not pinned | −0.2 % | +0.4 % | = |
| zix (reference) | | +2.7 % (5,943k) | −34 % (1.39 µs) | |

Spec §2.1 properties, measured on every rimu variant: **62 responses per packet** (target ≥ 40), **0 % ACK-only**
packets, **100 %** of response flushes carry an ACK, **0** STREAMS_BLOCKED / DATA_BLOCKED / STREAM_DATA_BLOCKED
frames received, 0 losses, 0 PTOs.

### static-h3 — base 1,023k req/s, 30.12 µs server CPU/req (spread 1.8 %)
| variant | knob | req/s vs base | CPU/req vs base | verdict |
|---|---|---|---|---|
| prev | the build before Task 16 | −1.2 % | +3.9 % | within spread |
| gro-on | GRO | −1.3 % | +3.6 % | within spread |
| steer-kernel | kernel hash | −3.3 % | −6.6 % | within spread (spread 5.7 %) |
| arena-x2 | TX arena 1.5 MB | −0.3 % | −2.5 % | win within spread |
| **inflight128k** | max in flight 128 KiB | **−8.3 %** | −6.3 % | loss — but **0 packets lost** |
| inflight512k | 512 KiB | +0.7 % | +4.5 % | within spread |
| **pacing-off** | no pacing | **−5.8 %** | **−18.4 %** | loss on rps, large CPU saving |
| pmtu-rtt | first PMTU probe after 1 RTT | +0.2 % | +5.6 % | within spread |
| train32 | 32-segment GSO trains | −1.3 % | +1.3 % | within spread |
| bodies-rr | round-robin large bodies | −1.2 % | +4.3 % | within spread |
| zix (reference) | | −42.8 % | +59 % | |

**Losses on the loopback:** with the default 256 KiB in-flight bound, a static-h3 window lost ≈ 58,000 packets and
resent ≈ 112,000 frames; RcvbufErrors ≈ 2,000 per window — the generator's receive buffer (4 MiB rmem_max) is overrun.
At 128 KiB in flight there are no losses but 8 % less throughput; pacing off removes pacing work (−18 % CPU) but loses
6 %. Only 64 % of static-h3 response flushes carry an ACK (they are long trains).

## 4. Conclusions
1. The first part of the request-path work cut baseline-h3 server CPU by 16 % (2.51 → 2.10 µs/req) and raised
   throughput 1.9 %; rimu is now 2.7 % behind zix on baseline-h3 throughput (zix still uses 1.39 µs/req). The profile
   of `base` still shows RequestHead::push 4.8 %, RouterHandler 3.4 %+1.7 %, H3App 3.1 %, h2 PathParams 2.0 %,
   fill_ 1.9 %, memcpy 1.9 %: the remaining directives of Ruling T16-a (static-index header classification, single
   validation/copy of fields, single-copy responses, no AutoStream/path params where not needed) are in Task 16's fix
   round and will be measured by a short follow-up batch (new vs `d73a785d`).
2. **Data reuse vs fresh:** reusing `State::data` saves ≈ 9.5 % CPU/req, but it can carry one client's mutation into
   another client's request when the data type's `Clone` is a deep copy. Ruling T16-e: the library default is fresh
   (h2 semantics); arena-h2 and the HttpArena entry opt in to reuse explicitly (their data is shared, read-only).
3. Library-default candidates from this batch (to be set in Task 16 part 2 with the follow-up numbers): GRO on for
   baseline-type traffic (static neutral within spread); the steering/balance and pinning knobs show CPU savings within
   spread only — no change without a clearer result.
4. static-h3's next lever is loss avoidance, not more sending: the server overruns the client on loopback; a
   loss-free configuration (128 KiB) gives up throughput, so the answer is in pacing/in-flight tuning between 128 and
   256 KiB and in sending fewer, larger datagrams (Task 19).
5. Static-h3 profile unchanged by Task 16 so far: kernel page zeroing 15 %, AES-GCM ≈ 13 % (Task 18/19 territory).

## 5. Data
- `data/summary.txt` (the kit's full summary: both tables, rps by pass, knob lines of every variant, the profile
  windows of base/prev with top functions and tracepoints), `data/vbench.jsonl` (66 rows), `data/vprofile.jsonl`,
  `data/host.txt`, `data/uptime.log`, `data/perf-caps-variants.txt`, `data/launch.log` (redacted: colossus IP, account),
  `data/{setup,variants}.log`, `data/raw.tar.zst` (h2load outputs, server logs), `data/vprofile/` (text artifacts and
  folded stacks; regenerate flamegraphs with `zstd -dc stacks.folded.zst | inferno-flamegraph > f.svg`).
- The kit as run is the one in `../2026-11-09-h3-ec2/kit/` plus the variant phase (`remote/variants.txt`,
  `run.sh variants`, `launch.sh PHASES=V`) — committed copies in `kit/`.
- Full archive (perf.data, SVGs): `~/benchmarks-archive/rimu-h3/2026-11-09-h3-ec2-variants-run-20261109-161338.tar.zst`
  (sha256 in `ARCHIVE.sha256`).
