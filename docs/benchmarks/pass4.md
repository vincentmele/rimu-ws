# Perf pass 4 (Task 19): static-h3 transfer, measured on EC2

This is Task 19 of the HTTP/3 plan, with the decisions of Task 17 (steering and balance), which Ruling T17-b
delegated here.

Measurements:
- Everything was measured in the combined EC2 batch of Tasks 17–19,
  [`2026-11-09-h3-ec2-combined/`](2026-11-09-h3-ec2-combined/README.md).
- The box was an m6a.24xlarge spot instance, AMD EPYC 7R13 (Zen 3).
- 3 passes; `base` = `0e276984`, with zix (both profiles) and fib (static-h3) in the same run.
- Nothing was benchmarked on colossus.

The rule for defaults is [pass1.md](pass1.md)'s.
- A WIN is ≥ 1 % more requests per second, or ≥ 2 % less server CPU per request at requests per second within ±1 %.
- In both cases the change must lie beyond the larger of base's and the variant's spread on that metric, on one
  profile, with no loss outside the spread on the other.
- Spreads are recomputed from `data/vbench.jsonl` (the range of the 3 passes over their median).
- static-h3 was noisy in this run:
  - base's rps spread is 5.1 % and its **CPU spread 19.8 %** (33.2, 40.8 and 38.4 µs/req over the passes).
  - baseline-h3 was quiet: 0.3 % rps and 0.9 % CPU.

## 1. What was built (commits 0e276984, b382ea5b, b5a18c17)
| ruling | change | switch |
|---|---|---|
| T19-a | transfer counters: datagram bytes, stream bytes written into packets and by copy, trains, pacer holds, owed and carried ACKs, zero-copy sends / copied / fallbacks; the kit derives the figures of section 2 | always on (`Http3WorkerStats`, arena-h2 `h3-stats`) |
| T19-b | io_uring zero-copy UDP sends (`IORING_OP_SENDMSG_ZC`): a train goes back to the arena only once its send and its notification have both completed; a fallback when the kernel refuses is counted | `UdpParams::zerocopy`, `ARENA_H3_ZC` |
| T19-c | pacer burst (datagrams per release, 1–64) | `QuicParams::pacing_burst`, `ARENA_H3_PACING_BURST` |
| T19-c | in-flight 160 / 192 KiB | `ARENA_H3_MAX_IN_FLIGHT` (existing) |
| T19-d | the first full-size packet of a flush with stream data repeats an acknowledgment the client may lack (no packet that carried it is acknowledged yet); it is kept only in a packet with an ack-eliciting frame | `QuicParams::repeat_ack`, `ARENA_H3_REPEAT_ACK` |

## 2. Counters against the targets (static-h3 `base`, median of the passes)
| figure | value | target | |
|---|---|---|---|
| datagram bytes | 1,472 | 1,472 (loopback MTU 1,500, IPv4) | ✓ |
| stream payload per datagram | **1,435 B** | ≥ 1,420 | ✓ |
| datagrams per GSO train | 30.5 | (64 at most) | |
| packets per response | 11.36 | | |
| copies per stream byte | **2.00** | 1 | ✗: user space copies once (the body goes by reference into the packet, which is then encrypted in place); the kernel copies each train into its own skb pages |
| flushes that carried the ACK they owed | 100 % | 100 % | ✓ (`repeat-ack-off`: 67 %) |
| pacer holds per request | 0.15 | | |
| packets lost / frames resent per 6 s profile window | 35,012 / 46,786 | 0 | ✗ (see in-flight) |
| ACK-only packets | 0 % | 0 % | ✓ |

The second copy cannot be removed on this path. Zero-copy hands the kernel the arena's pages, but the loopback copies
each zero-copy skb on delivery (`skb_copy_ubufs`) into pages that `init_on_alloc` zeroes. The notifications reported
100 % of zero-copy trains copied.

baseline-h3 kept its §2.1 properties on every variant: 64 responses per packet, 0 % ACK-only, 100 % of owed ACKs
carried, 0 blocked frames, 0 losses.

## 3. Results (median of 3 passes, against `base`; spreads are rps / CPU)
baseline-h3 base: 5,937k req/s, 2.04 µs/req. static-h3 base: 998k req/s, 38.4 µs/req.

| variant | baseline-h3 rps / CPU per req (spreads) | static-h3 rps / CPU per req (spreads) | static lost / resent | decision |
|---|---|---|---|---|
| `zc` | −0.8 % / **+2.4 %** (0.7 / 0.3) | −4.2 % / +3.5 % (0.2 / 5.9) | 36k / 60k | **loss: stays off** |
| `inflight160k` | — | −3.4 % / −15.2 % (2.3 / 7.7) | **0 / 0** | within spread, not a WIN: 256 KiB stays |
| `inflight192k` | — | −3.6 % / +3.3 % (0.8 / 2.8) | **0 / 0** | not a WIN: 256 KiB stays |
| `pace-burst16` | — | **−63.9 %** / −16.6 % (24.7 / 1.7) | 0.4k / 0.6k | **loss: 64 stays** |
| `repeat-ack-off` | (static only) | +1.1 % / −16.0 % (1.9 / 20.1) | 58k / **109k** | within spread, not a WIN: stays on; re-measured on both profiles next batch |
| `steer-kernel` (T17) | −0.2 % / **−6.8 %** (0.6 / 1.3) | −2.0 % / −27.6 % (2.6 / 8.9) | 29k / 40k | CPU win on baseline at equal rps; **kept on** (below) |
| `balance-off` (T17) | +0.0 % / **−7.4 %** (0.3 / 2.7) | −4.4 % / −23.8 % (3.8 / 16.2) | 22k / 30k | CPU win on baseline at equal rps; **kept on** (below) |
| `prev` (7dd98337) | −0.2 % / −1.0 % | −0.9 % / −3.2 % | 37k / 67k | Task 19 part 1's default path neutral |

Notes:
- **Zero-copy** loses on both profiles. On baseline-h3 the CPU cost is outside the spread (pinning, plus a
  notification completion for every train). On static-h3 the kernel zeroes and copies on delivery instead of on send:
  `kernel_init_pages` moves from `sk_page_frag_refill` (send) to `skb_copy_ubufs` (receive softirq, 32 % softirq),
  and nothing is saved.
- **In-flight bound.** 160 and 192 KiB end the loopback losses entirely (the generator's receive buffer is no longer
  overrun). Both cost about 3.5 % of rps, within the run's spread but in the same direction in every pass. HttpArena
  scores rps and not losses, so 256 KiB stays.
- **Pacing burst 16** is a disaster: trains halve (15.8 datagrams), pacer holds rise from 0.15 to 0.71 per request,
  and rps falls by 64 %.
- **Repeated ACK.**
  - Measured with the first cut, before b382ea5b: that version could also add an ACK-only packet, but the batch
    measured 0 % ACK-only on every variant.
  - Off: only 67 % of owed ACKs are carried and resends rise 2.3×.
  - The +1.1 % rps and −16 % CPU are inside the spreads (1.9 % / 20.1 %).
  - It stays on. Every pass of `repeat-ack-off` had higher rps than base's pass of the same order (1,008k / 1,020k /
    1,000k vs 1,007k / 956k / 998k), so the next batch re-measures it on both profiles with the fixed build.
- **Steering and balance (Task 17).**
  - By the letter of the rule both are WINs: about 7 % less CPU per request on baseline-h3 at equal rps, outside a CPU
    spread of 1.3–2.7 %. On static-h3 there is no loss outside the 5.1 % spread.
  - But both serve fewer static-h3 requests in every pass (balance-off 954k / 932k / 968k vs base 1,007k / 956k /
    998k), and HttpArena scores rps, not CPU.
  - The per-worker distribution was not recorded.
  - CID steering with least-loaded placement exists for the imbalance of the kernel's 4-tuple hash on the board (spec
    §5.11): 64 connections on HttpArena's server cores. A box where the generator is the limit (baseline-h3) hides an
    imbalance, and the CPU saving is the expected sign of fewer, busier workers.
  - **Both stay on.** A board-like run with per-worker counters would be needed to revisit them.

## 4. fib comparison (brief Step 3)
rimu is ahead on static-h3 in the same run: **998k vs 810k req/s (+23 %)**, at 38.4 vs 44.4 µs of server CPU per
request. Generator CPU per request is the same (37.9 vs 37.0 µs), so the difference is the server's.

The software profile of the first EC2 run (same host type, `2026-11-09-h3-ec2/data/profile/`) shows where fib spends
the extra time: rimu-min 30.4 µs/req, fib 44.5 µs/req.

| per request | fib | rimu |
|---|---|---|
| user-space CPU | ~28.5 µs (64 %; the binary is stripped, so no breakdown) | ~17.6 µs (58 %, AES-GCM 4.7 µs of it) |
| `udp_sendmsg` | 12.0 µs (sendmmsg 0.53/req, 0.554 GSO sends/req) | 8.7 µs (io_uring, 0.36 trains/req) |
| of which `kernel_init_pages` | 4.8 µs | 3.5 µs |
| epoll + futex | 1.0 µs (epoll_pwait 0.28/req, futex 0.08/req) | — (io_uring_enter 0.26/req) |
| context switches | 0.31/req | 0.20/req |

The gap is mostly fib's user space (about 11 µs/req more). The kernel part is its more numerous, smaller sends
(+54 % sends per request) and its epoll/futex wake-ups. rimu is not behind, so nothing changes on this account.

## 5. The pacing / page-zeroing finding
The batch profiled `base` and `pacing-off` on static-h3. Figures are per request, from the folded stacks
(`vprofile/v-{base,pacing-off}-static-h3`):

| | base (paced) | pacing-off |
|---|---|---|
| server CPU | 44.6 µs | 25.0 µs |
| `kernel_init_pages` (all under `sk_page_frag_refill`) | 13.2 µs (30 %) | 3.3 µs (13.6 %) |
| page allocator outside zeroing (`get_page_from_freelist`) | 0.65 µs | 0.20 µs |
| page freeing | 0.56 µs | 0.27 µs |
| `rep_movs` (the copy into the skb pages) | 1.15 µs | 0.68 µs |
| instructions | 75k | 74k |
| IPC | 0.64 | 0.87 |
| GSO sends | 0.36 | 0.31 |
| io_uring submissions | 0.60 | 0.31 |
| receive-buffer drops per window | 493 | 5,390 |

The bytes sent per request are the same, and so is the work in instructions. But the page allocator's own time per
request (outside zeroing) is 3.2× larger when paced, so paced sending takes several times more fresh pages per byte.
Each fresh page is zeroed while cold, hence the IPC.

Why, in the kernel's code:
- A UDP send copies its payload into the sending task's page fragment (`sk_page_frag` → `current->task_frag`, a
  32 KiB compound page, `SKB_FRAG_PAGE_ORDER`).
- `skb_page_frag_refill` reuses that page from offset 0 only if nobody else holds it (`page_ref_count == 1`).
  Otherwise, once it is full, it takes a fresh order-3 page, which `init_on_alloc` zeroes.
- The skbs of the datagrams sent hold the page until the client reads them: on the loopback, until h2load drains its
  socket.
- **A paced worker sends again while the client still holds its last datagrams** (timer-driven releases, 0.24 extra
  submissions per request). The page is never free, and almost every 32 KiB sent costs a fresh, zeroed page.
- An unpaced worker sends a whole window at once and then waits for the client's ACKs. The client ACKs after it has
  read, so by the next turn the page is free and is reused without zeroing.
- Its receive-buffer drops (11× more) free pages early too.

This is the lead for the next batch. The in-flight bound, not the pacer, is what bounds the bytes a client holds:
everything it holds is in flight. So **pacing off with the loss-free bound of section 3** should keep the losses
away and keep the unpaced CPU. The next batch's variants are `pacing-off-160k` and `pacing-off-192k`, with
`pacing-off` and `inflight160k` as same-host references.
- If they are loss-free at pacing-off's CPU and rps, the defaults follow by the rule (pacing is an RFC 9002 SHOULD;
  a pacer that only releases on ACK-clocked turns would be the conforming form).
- If the losses return, the CPU saving came from the drops, and the pacer stays.

No code change was made for it: the two switches exist, and the rule forbids changing a default without a
measurement.

## 6. Library defaults changed
**None.** No variant met the rule on rps, and the Task 17 CPU wins were overruled for the board's sake (section 3).

| setting | default | why |
|---|---|---|
| `UdpParams::zerocopy` | `false` | loss on both profiles (loopback copies anyway) |
| `QuicParams::max_in_flight` | 256 KiB | 160 / 192 KiB loss-free but −3.4 / −3.6 % rps (within spread) |
| `QuicParams::pacing_burst` | 64 | 16: −64 % |
| `QuicParams::repeat_ack` | `true` | off not a WIN (within spread); off carries 67 % of owed ACKs, 2.3× resends |
| `QuicParams::pacing` | `true` | pending the pacing-off + in-flight variants (section 5) |
| `QuicParams::cid_steering`, `QuicParams::balance` | `true` | CPU-only win at slightly lower static rps; kept for the board's 4-tuple imbalance |

`transfer_defaults_are_the_measured_ones` (quic/limits.rs) pins them.

## 7. What remains
- The next batch: `base prev repeat-ack-off pacing-off inflight160k pacing-off-160k pacing-off-192k`, refs
  `zix fib@static-h3`, where `prev` = 0e276984, the build measured here.
- A quieter static-h3 run. Its 20 % CPU spread hides every CPU-only effect, including hp-batched's (Task 18).
- Copies per byte stay at 2 on the loopback, the kernel's skb copy. Only a send path that hands the kernel pages it
  does not copy on local delivery would remove it, and the loopback copies zero-copy skbs by design.
- static-h3's QPACK decode memo hits 0 % (pass3.md's lead; not examined here).
