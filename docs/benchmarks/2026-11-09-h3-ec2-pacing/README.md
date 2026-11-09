# HTTP/3 pacing follow-up on AWS EC2 — 9 Nov 2026

The fifth EC2 run: Task 19's fixes (`base` = `44752fa8`, after the repeated-ACK exactness fix `b382ea5b` and the
counter fixes `b5a18c17`) against the build the combined batch measured (`prev` = `0e276984`), plus the test of the
page-zeroing hypothesis: pacing off at the in-flight bounds that were loss-free with pacing on. Method, box and kit as in
[`../2026-11-09-h3-ec2/README.md`](../2026-11-09-h3-ec2/README.md) and
[`../2026-11-09-h3-ec2-combined/README.md`](../2026-11-09-h3-ec2-combined/README.md).

## Why
The combined batch showed kernel page zeroing at 30 % of static-h3 server cycles with pacing and 13.6 % without, and
CPU/req 44.6 vs 25 µs. Task 19 part 2 inferred a cause (a worker's 32 KiB skb page fragment is reused only once the
client no longer holds the previous datagrams; paced flushes refill ≈ 3.2× more per byte) and proposed `pacing-off-160k`
/ `pacing-off-192k`: unpaced trains at in-flight bounds that are loss-free when paced. Ruling T19-f applied in advance:
the library keeps pacing on regardless (real networks), only the benchmark path could opt out.

## Run
m6a.24xlarge spot, sa-east-1b; launched 20:21:46 UTC, setup done 20:22:33, three passes of 13 starts 20:22:34–20:42:10,
profiles of base and pacing-off-160k until 20:44:26, terminated and cleaned up (verified): **23 min wall, ≈ $0.30**.
Variants: `base prev repeat-ack-off pacing-off inflight160k pacing-off-160k pacing-off-192k`; refs `zix fib@static-h3`.

## Results (median of 3 passes)
| profile | variant | req/s | vs base | CPU µs/req | vs base | lost / resent (window) |
|---|---|---|---|---|---|---|
| baseline-h3 | base | 5,938k | | 2.02 | | 0 / 0 |
| baseline-h3 | prev | 5,905k | −0.6 % | 2.03 | +0.7 % | 0 / 0 |
| baseline-h3 | repeat-ack-off | 5,900k | −0.6 % | 2.02 | +0.4 % | 0 / 0 |
| baseline-h3 | zix | 6,003k | +1.1 % | 1.40 | −31 % | |
| static-h3 | base | **1,035k** | (spread 1.3 %) | 27.35 | | 64k / 90k |
| static-h3 | prev | 1,032k | −0.4 % | 26.96 | −1.5 % | 68k / 94k |
| static-h3 | repeat-ack-off | 1,035k | −0.1 % | 27.00 | −1.3 % | 63k / **121k** |
| static-h3 | pacing-off | 974k | **−6.0 %** | 22.80 | −16.7 % | 95k / 193k |
| static-h3 | inflight160k | 989k | **−4.5 %** | 27.25 | −0.4 % | **0 / 0** |
| static-h3 | pacing-off-160k | 983k | **−5.1 %** | 22.24 | −18.7 % | **0 / 0** |
| static-h3 | pacing-off-192k | 1,001k | **−3.4 %** | 22.16 | −19.0 % | 0.05k / 0.1k |
| static-h3 | fib | 838k | −19.0 % | 40.23 | +47 % | |
| static-h3 | zix | 628k | −39.4 % | 45.06 | +65 % | |

Transfer (static-h3 base): 1,472 B datagrams, 1,435 B payload, 29.7 datagrams per train, 11.4 packets per response,
2 copies per byte, 100 % owed ACKs carried (prev: the old counter, not comparable), 0 ACK-only packets on both profiles.

Profiles (static-h3): `kernel_init_pages` 11.6 % of server cycles for base and 14.1 % for pacing-off-160k on this host —
the 30 % → 13.6 % split of the combined batch did not reproduce; AES-GCM ≈ 12.7 % / 13.7 %.

## Conclusions
1. **Pacing stays on — in the library and on the benchmark path.** Every unpaced variant saves 17–19 % CPU/req but
   loses 3.4–6.0 % throughput, outside the 1.3 % spread; HttpArena scores throughput. Loss-free bounds (160 KiB paced or
   unpaced) also lose throughput. No default changes (Ruling T19-f's opt-out is not taken).
2. **The page-zeroing hypothesis is not confirmed:** on this host base zeroes less (11.6 %) than pacing-off-160k (14.1 %).
   The earlier large split was host-dependent (see the follow-up run: 15 % vs 31.5 % between hosts for the same build).
3. **Task 19's fixes are neutral** (prev vs base within spread on both profiles); the repeated ACK keeps 100 % of owed
   ACKs carried at no measurable cost and with fewer resends than `repeat-ack-off` (90k vs 121k).
4. rimu: **#1 on static-h3** (+24 % over fib, +65 % over zix); **1.1 % behind zix on baseline-h3** (server CPU 2.02 vs
   1.40 µs/req — the remaining per-request framework gap).

## Data
`data/summary.txt`, `data/vbench.jsonl`, `data/vprofile.jsonl`, `data/host.txt`, `data/uptime.log`,
`data/{setup,variants}.log`, `data/launch.log` (redacted), `data/raw.tar.zst`, `data/vprofile/` (text + folded stacks).
Full archive: `~/benchmarks-archive/rimu-h3/2026-11-09-h3-ec2-pacing-run-20261109-202130.tar.zst` (`ARCHIVE.sha256`).
