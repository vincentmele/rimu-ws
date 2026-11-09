# HTTP/3 combined perf batch (Tasks 17–19) on AWS EC2 — 9 Nov 2026

The fourth EC2 run: one batch measuring the remaining knobs of Task 17 (steering/balance), Task 18 (batched header
protection, QPACK dynamic table) and Task 19 (zero-copy sends, in-flight bounds, pacing burst, repeated ACK) one at a
time against `base`, with zix (both profiles) and fib (static-h3) as fixed references. Method and box as in
[`../2026-11-09-h3-ec2/README.md`](../2026-11-09-h3-ec2/README.md); variant phase as in
[`../2026-11-09-h3-ec2-variants/README.md`](../2026-11-09-h3-ec2-variants/README.md).

## Why one combined batch
The user moved benchmarking to EC2 and asked not to waste EC2 time; Tasks 17–19 had no measurements of their own yet,
and each knob is a runtime switch, so one < 40-minute batch covers all three (Rulings T17-a, T18-d, T19-e). Builds:
`base` = `0e276984` (Task 19 part 1), `prev` = `7dd98337` (Task 18 part 1; differs from 767f5778 only off the h3 hot
path). Two later fixes are not in this batch: `b382ea5b`/`b5a18c17` (repeated ACK only in ack-eliciting packets; exact
counters) and `a23a2176`/`767f5778` (TLS key wipe; HP error path) — neither changes the steady-state send path measured
here, and the next batch re-measures `base` anyway.

## Run
m6a.24xlarge spot, sa-east-1b; launched 19:20:57 UTC, kit uploaded in 19 s, setup done 19:21:42, three passes of 23
starts 19:21:43–19:56:03 (≈ 11.5 min each), profiles of base, pacing-off and zc until 19:59:41, terminated and cleaned up
(verified): **39 min wall, ≈ $0.50**. Variant list:
`base prev gro-off steer-kernel balance-off hp-batched qpack4096 zc inflight160k inflight192k pace-burst16
repeat-ack-off`, refs `zix fib@static-h3`, profiles `base pacing-off zc`.

## Results (median of 3 passes)
### baseline-h3 — base 5,937k req/s, 2.04 µs server CPU/req (rps spread 0.3 %)
| variant | req/s vs base | CPU/req vs base | note |
|---|---|---|---|
| prev | −0.2 % | −1.0 % | Tasks 18–19 neutral on baseline |
| gro-off | −1.0 % | +1.6 % | GRO helps (arena-h2 keeps it on) |
| steer-kernel | −0.2 % | −6.8 % | CPU saving at equal rps |
| balance-off | +0.0 % | −7.4 % | CPU saving at equal rps |
| hp-batched | −0.4 % | −0.3 % | neutral |
| **qpack4096** | **−2.8 %** | +3.1 % | loss; generator +3 % CPU/req; memo hit rate 100 % |
| zc | −0.8 % | +2.4 % | loss |
| zix (ref) | **+1.2 % (6,010k)** | −33 % (1.37 µs) | the gap on baseline is now 1.2 % |

§2.1 properties on every rimu variant: 64 responses/packet, 0 % ACK-only, 100 % of flushes carry their owed ACK, 0
blocked frames, 0 losses.

### static-h3 — base 998k req/s, 38.4 µs server CPU/req (rps spread 5.1 % — noisy run)
| variant | req/s vs base | CPU/req vs base | lost / resent (window) | note |
|---|---|---|---|---|
| prev | −0.9 % | −3.2 % | 37k / 67k | |
| gro-off | −3.7 % | +5.1 % | 29k / 40k | |
| steer-kernel | −2.0 % | **−27.6 %** | 29k / 40k | |
| balance-off | −4.4 % | **−23.8 %** | 22k / 30k | |
| hp-batched | +0.9 % | −12.2 % | 50k / 69k | |
| qpack4096 | +0.6 % | −6.9 % | 36k / 50k | |
| zc | −4.2 % | +3.5 % | 36k / 60k | the kernel copied 100 % of zero-copy trains (loopback) |
| inflight160k | −3.4 % | −15.2 % | **0 / 0** | loss-free |
| inflight192k | −3.6 % | +3.3 % | **0 / 0** | loss-free |
| **pace-burst16** | **−63.9 %** | −16.6 % | 0.4k / 0.6k | disaster: spread 25 % |
| repeat-ack-off | +1.1 % | −16.0 % | 58k / 109k | only 67 % of owed ACKs carried |
| fib (ref) | −18.9 % (810k) | +16 % | | |
| zix (ref) | −40.7 % (591k) | +25 % | | |

Transfer (static-h3, base): 1,472-byte datagrams with 1,435 B of stream payload (target ≥ 1,420 ✓), 30.5 datagrams per
GSO train, 11.4 packets per response, **2 copies per stream byte** (target 1), 100 % owed ACKs carried, 0.15 pacer holds
per request.

## Profiles
| profile | variant | req/s | srv µs/req | user % | kernel_init_pages | AES-GCM |
|---|---|---|---|---|---|---|
| baseline-h3 | base | 5,894k | 2.16 | 83 | — | — |
| static-h3 | base | 902k | 44.6 | 44 | **30.0 %** | 7.0 % (+2.0 seal) |
| static-h3 | pacing-off | 942k | **25.0** | 62 | **13.6 %** | 10.9 % (+3.0 seal) |
| static-h3 | zc | 933k | 41.4 | 47 | (softirq 32 %) | |

baseline-h3 base top: RouterHandler 3.2 %, H3App 3.0 %, RequestHead::push 2.8 %, h2 PathParams 2.0 %, memcpy 1.9 %,
pseudo_value_ok 1.7 %, QuicConn 1.6 %, push_pseudo 1.6 %, Streams::deliver 1.6 %, fill_ 1.6 %.

## Conclusions
1. **baseline-h3:** rimu is 1.2 % behind zix on throughput (5.94M vs 6.01M); zix still spends 33 % less server CPU
   per request. Tasks 18–19 changed nothing on baseline (prev = base). The QPACK dynamic table loses (keep capacity 0 —
   Task 18 Step 3's question answered: the generator pays for it); zero-copy and batched HP do nothing here.
2. **static-h3:** rimu stays #1 (+23 % over fib). Page zeroing is the dominant cost and it is **tied to pacing**: with
   pacing off the kernel's `kernel_init_pages` share halves (30 → 13.6 %) and CPU/req falls 44.6 → 25 µs — paced flushes
   allocate fresh skb pages far more often than unpaced trains. That is the lead for Task 19 part 2 (pacing that keeps
   large trains / reuses send memory), not zero-copy: on loopback the kernel copies every zero-copy train anyway.
3. **Losses:** 160 and 192 KiB in flight are loss-free but cost 3.4–3.6 % rps; the repeated ACK (default) halves the
   resent frames vs `repeat-ack-off` (47k vs 109k) at a CPU cost within this run's spread. Pacing bursts of 16 are a
   disaster (−64 %).
4. Several static CPU savings (steer-kernel −28 %, balance-off −24 %, hp-batched −12 %, repeat-ack-off −16 %) sit at
   rps changes inside a 5 % spread: defaults must follow the plan's rule with CPU spreads (Task 18/19 part 2), and a
   quieter re-measure may be needed before any default flips.

## Data
`data/summary.txt` (all tables incl. transfer and knob lines), `data/vbench.jsonl`, `data/vprofile.jsonl`,
`data/host.txt`, `data/uptime.log`, `data/{setup,variants}.log`, `data/launch.log` (redacted), `data/raw.tar.zst`,
`data/vprofile/` (text + folded stacks). Full archive:
`~/benchmarks-archive/rimu-h3/2026-11-09-h3-ec2-combined-run-20261109-192041.tar.zst` (`ARCHIVE.sha256`).
