# Perf pass 1 (Task 16): request path, batching, knobs — measured on EC2

Task 16 of the HTTP/3 plan. All measurements ran on AWS EC2 (m6a.24xlarge spot, AMD EPYC 7R13 Zen 3, sa-east-1b),
with the harness of the first EC2 run. Nothing was benchmarked on colossus. The three write-ups:

- [`2026-11-09-h3-ec2/`](2026-11-09-h3-ec2/README.md): the first run (method, box, rivals, the profile that
  set Task 16's scope);
- [`2026-11-09-h3-ec2-variants/`](2026-11-09-h3-ec2-variants/README.md): the variant batch. It measured every knob of
  Tasks 16, 17 and 19 one at a time against `base` (d73a785d), plus the first request-path step against e7eca138;
- [`2026-11-09-h3-ec2-followup/`](2026-11-09-h3-ec2-followup/README.md): the follow-up A/B of the completed request path
  (a99e6332 vs d73a785d).

**Rule for defaults (the plan's).** A library default changes only for a WIN on at least one profile, with no loss
outside the spread on the other profile. A WIN is either ≥ 1 % more requests per second, or ≥ 2 % less server CPU per
request while requests per second stay within ±1 %. In both cases the change must exceed the larger of base's and the
variant's spread across the 3 passes, measured on the metric in question.

## 1. Spec §2.1 properties, measured (every rimu variant, baseline-h3)
| property | target | measured |
|---|---|---|
| responses per packet | ≥ 40 | **62** (64 with GRO) |
| ACK-only packets among packets sent | < 5 % | **0 %** |
| response flushes that carry the ACK of their requests | all | **100 %** (static-h3: 64 %, long trains) |
| STREAMS_BLOCKED / DATA_BLOCKED / STREAM_DATA_BLOCKED received | 0 | **0 / 0 / 0** |
| losses, PTOs (baseline-h3) | — | 0, 0 |

These are measured by the counters added in Task 16 (`Http3WorkerStats`: `fins_out`, `fin_flushes`,
`fin_flushes_acked`, `*_blocked_in`, `packets_lost`, `pto_probes`, `frames_resent`).
On static-h3 only 64 % of response flushes carry an ACK (target: all): its responses go out in long trains. That gap
is handed to Task 19.

## 2. The request path (Ruling T16-a)
| step | A/B | baseline-h3 req/s | server CPU µs/req | static-h3 req/s | CPU µs/req |
|---|---|---|---|---|---|
| e7eca138 → d73a785d: per-worker data reuse (opt-in since T16-e), byte-class checks, field view, URI from parts, keyed block lookup, length-switched known fields | variant batch, base vs prev | **+1.9 %** (5,681k → 5,788k) | **−16 %** (2.51 → 2.10) | +1.2 % (within spread) | −3.8 % (within spread) |
| d73a785d → a99e6332: QPACK static-index classification, one validation pass, gathered single-copy response write | follow-up | +0.3 % (within spread) | +2.2 % (within spread) | −0.3 % (within spread) | +4.4 % (within spread; host-dependent, see §5) |

- Reusing `State::data` saves 9.5 % CPU/req on baseline-h3 (variant `data-fresh`: 2.30 vs 2.10 µs/req, −0.9 %
  req/s). It is **opt-in** (Ruling T16-e). The library default is a fresh clone per request, which is HTTP/2's
  semantics. arena-h2 and the HttpArena entry turn reuse on; their data is read-only.
- Ruling T16-g reverted the gathered write. In the follow-up profile, `RequestHead::push` fell from 4.8 % to 2.8 % of
  server cycles, but `SendPart::append_bytes` rose to 3.4 %: appending each piece separately cost about what the
  removed copy saved. The static-index classification and the single validation pass were kept.
- On baseline-h3, rimu is now 2.7 % behind zix on throughput (5,788k vs 5,943k req/s). The server-CPU gap remains:
  2.1 vs 1.4 µs/req.

## 3. Every knob, with the decision
baseline-h3 base: 5,788k req/s, 2.10 µs/req (rps spread 0.1 %, CPU spread 1.3 %). static-h3 base: 1,023k req/s,
30.12 µs/req (rps spread 1.8 %, CPU spread 7.3 %). Percentages are the variant against base.

| knob (variant) | baseline-h3 rps / CPU (spreads) | static-h3 rps / CPU (spreads) | decision |
|---|---|---|---|
| GRO on, 64 KiB buffers (`gro-on`) | +0.8 % / **−2.8 %** (0.2 % / 0.3 %) | −1.3 % / +3.6 % (2.6 % / 8.9 %) | WIN on baseline, no loss outside spread on static — but **library default stays off** (ruling T16-h, memory budget); **on in arena-h2** (the benchmark path) |
| receive ring 512 (`ring512`) | −0.6 % / +0.2 % | not run | keep 256 |
| flush in slot order (`flush-slot`) | −0.4 % / +0.7 % | not run | keep arrival order |
| TX arena ×2, 1.5 MB (`arena-x2`) | not run | −0.3 % / −2.5 % (1.5 % / 24.5 %) | keep 768,000 B (within spread) |
| socket buffers | not measurable (the box's rmem/wmem_max is 4 MiB = the default request) | — | keep 4 MiB |
| kernel hash, no CID steering (`steer-kernel`) | −0.0 % / −4.4 % (0.4 % / 4.6 %) | −3.3 % / −6.6 % (5.7 % / 8.2 %) | keep CID steering (within spread) → Task 17 |
| balance off (`balance-off`) | +0.1 % / **−8.2 %** (1.2 % / 2.5 %) | not run | keep balance on: no static-h3 measurement, so the rule's second condition is not shown → Task 17 |
| workers not pinned (`pin-off`) | −0.2 % / +0.4 % | not run | keep pinning |
| max in flight 128 KiB (`inflight128k`) | not run | **−8.3 %** / −6.3 %, **0 losses** | keep 256 KiB → Task 19 |
| max in flight 512 KiB (`inflight512k`) | not run | +0.7 % / +4.5 % (2.5 % / 10.3 %) | keep 256 KiB |
| pacing off (`pacing-off`) | not run | **−5.8 %** / −18.4 % | keep pacing (a loss) → Task 19 lead |
| first PMTU probe after 1 RTT (`pmtu-rtt`) | not run | +0.2 % / +5.6 % (4.3 % / 30.3 %) | keep "now" |
| GSO trains of 32 (`train32`) | not run | −1.3 % / +1.3 % | keep 64 |
| round-robin bodies (`bodies-rr`) | not run | −1.2 % / +4.3 % | keep one body to completion |
| fresh data per request (`data-fresh`) | −0.9 % / +9.5 % | not run | semantics, not a perf default: fresh stays the library default (T16-e); reuse is opt-in |

**Library defaults changed: none.** GRO is the only WIN confirmed without a loss on the other profile, and the rule
would have made `UdpParams::gro` default on (`balance-off` was a baseline-h3 WIN too, held back because static-h3 was
not run: Task 17). **Ruling T16-h** keeps GRO off. With GRO, 256 receive buffers of 64 KiB make one socket's ring
256 × 65,536 B = exactly 16 MiB (16.8 MB), which equals spec §5.4's 16 MiB per-worker budget by itself (the budget counts the whole heap of a worker; the GRO ring is the one thing
reported apart, ruling T20-e; the 2 MiB idle budget is on-demand state over a fixed start floor of 1.86 MiB with GRO on and 2.41 MiB without, bounds 2.0 / 2.5 MiB, ruling T20-f), leaving nothing for the other pools (48 workers: 768 MiB), and the win is +0.8 % on one profile. arena-h2, the
benchmark path, turns GRO on by default: `ARENA_H3_GRO` is `1` unless set to `0`. The kit's `base` therefore runs
with GRO. Its old `gro-on` variant becomes `gro-off`, and a `gro-ring64` variant (GRO on with 64 receive buffers,
about 4 MiB) measures whether a ring that fits the budget keeps the win, so the library default can be revisited.
Every other knob keeps its library default.

## 4. Handed on to later tasks (settled here; do not re-measure)
- **Task 17 (steering, balance, pinning).** Settled: pinning stays on (neutral). Open:
  - `balance-off` saves 8.2 % CPU/req on baseline-h3, outside the spread, at equal rps. It was not run on static-h3.
    A likely cause is fewer, busier workers batching more per turn. Measure it on static-h3 and check the
    per-worker distribution before changing the default.
  - `steer-kernel` saves 4.4 % / 6.6 % CPU/req, within the spread, and halves the static-h3 losses (28k vs 58k
    packets lost per window).
- **Task 19 (in-flight, pacing, PMTU, trains, bodies).** Settled as neutral: PMTU probe timing, train length,
  round-robin bodies, TX arena size, in-flight 512 KiB. Open:
  - **Losses.** A static-h3 window loses about 58,000 packets and resends about 112,000 frames, and the host shows
    about 2,000 RcvbufErrors per window: the server overruns the generator's 4 MiB receive buffer on the loopback.
    128 KiB in flight is loss-free but costs 8.3 % throughput. Search the range between 128 and 256 KiB, or make
    the in-flight bound adapt.
  - **Pacing** costs about 18 % of static-h3 server CPU but buys 5.8 % throughput. Make the pacer cheaper rather
    than turning it off.
  - **Page zeroing.** `kernel_init_pages` (the kernel zeroing pages for outgoing skb data under `init_on_alloc`)
    takes 15 % of static-h3 server cycles on the variant-batch host and 31.5 % on the follow-up host; AES-GCM takes
    about 13 % (Task 18). Leads: fewer page allocations per byte sent (send-buffer reuse, zero-copy sends, smaller
    trains under memory pressure). Compare static-h3 results only within one run (one host).

## 5. Caveats
- static-h3 numbers move with the physical host's page-zeroing cost. In the follow-up, both rimu builds ran at
  43 µs/req against 30 µs/req in the variant batch, while zix moved only from 48 to 52.
- A variant run on one profile only cannot meet the rule's second condition, so it keeps its default.
- Spreads are the ranges of 3 passes of best-of-3 runs of 5 s each.
