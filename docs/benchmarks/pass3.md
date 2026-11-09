# Perf pass 3 (Task 18): crypto and QPACK, measured on EC2

Task 18 of the HTTP/3 plan. Its two h3 switches were measured in the combined EC2 batch of Tasks 17–19
([`2026-11-09-h3-ec2-combined/`](2026-11-09-h3-ec2-combined/README.md); m6a.24xlarge spot, AMD EPYC 7R13 Zen 3,
3 passes, `base` = `0e276984`). Nothing was benchmarked on colossus. The rule for defaults is
[pass1.md](pass1.md)'s: a WIN is ≥ 1 % more requests per second, or ≥ 2 % less server CPU per request at requests per
second within ±1 %, in both cases beyond the larger of base's and the variant's spread on that metric, on one profile,
with no loss outside the spread on the other. The spreads below are recomputed from `data/vbench.jsonl` (range of the 3
passes over their median), CPU spreads included.

## 1. What was built
| step | change | switch | measured where |
|---|---|---|---|
| 1 | TLS records sealed and opened with the AEAD of their traffic key, expanded once per traffic secret (not once per record); the state wipes its secrets on drop | none (always on) | h1/h2 only: its A/B (h1 json-tls and 8gbit, h2 baseline-h2 and static-h2; revert if any regresses > 1 %) runs in Task 24's regression batch (Rulings T18-a, T18-f) |
| 2 | header-protection masks of the 1-RTT packets of a flush computed eight at a time with AES-NI, applied in the TX arena before the flush returns | `QuicParams::set_batched_header_protection`, arena-h2 `ARENA_H3_HP=ring\|batched` | `hp-batched`, both profiles |
| 3 | QPACK dynamic table offered to clients; decode memo hit rate counted (`Http3WorkerStats::qpack_sections`, `qpack_memo_hits`) | `H3Params::qpack_max_table_capacity` / `qpack_blocked_streams`, arena-h2 `ARENA_H3_QPACK=0\|4096` (4096 bytes, 100 blocked streams) | `qpack4096`, both profiles |

## 2. Results (median of 3 passes, against `base`)
baseline-h3 base: 5,937k req/s, 2.04 µs/req (rps spread 0.3 %, CPU spread 0.9 %). static-h3 base: 998k req/s,
38.4 µs/req (rps spread 5.1 %, **CPU spread 19.8 %** — a noisy static run).

| variant | baseline-h3 rps / CPU per req (spreads) | static-h3 rps / CPU per req (spreads) | generator CPU per req (baseline) | memo hit rate (baseline / static) | decision |
|---|---|---|---|---|---|
| `hp-batched` | −0.4 % / −0.3 % (0.6 % / 0.8 %) | +0.9 % / −12.2 % (3.9 % / **25.9 %**) | +0.3 % | 100 % / 0 % | **no WIN: stays off** |
| `qpack4096` | **−2.8 %** / +3.1 % (0.4 % / 1.7 %) | +0.6 % / −6.9 % (4.8 % / 19.1 %) | **+3.2 %** | 100 % / 0 % | **loss: capacity stays 0** |
| `prev` (7dd98337 vs base) | −0.2 % / −1.0 % | −0.9 % / −3.2 % | +0.3 % | — | Task 18's default path neutral |

- **QPACK (Step 3's question).** A 4096-byte dynamic table makes baseline-h3 lose 2.8 % of its requests per second,
  well outside the 0.4 % spread. The generator (h2load + nghttp3) pays for maintaining the table: +3.2 % of its
  CPU per request, and baseline-h3 is generator-bound. The server gains nothing: its decode memo already replays 100 %
  of baseline-h3's field sections with no table. **`qpack_max_table_capacity` stays 0** and `qpack_blocked_streams`
  stays 0. The memo hit rate exceeds 95 %, as expected, but only on baseline-h3.
- **Batched header protection.** Baseline-h3 is neutral within the spread, which is expected: a flush there is mostly
  one packet, so the batch has a single lane. On static-h3 the change is +0.9 % rps, below the 1 % rps threshold, and
  −12.2 % CPU per request, but base's CPU spread is 19.8 % and the variant's is 25.9 %, so the saving is inside the
  noise. The profile agrees: header protection takes **0.86 %** of static-h3 base's server cycles (ring's `new_mask`,
  `v-base-static-h3`; 0.17 % on baseline-h3), so batching cannot save 12 %. **Not a WIN; the switch stays off** by
  default (library and arena-h2). A quieter static-h3 run may revisit it, but its ceiling is below 1 % of CPU.
- **Memo on static-h3:** 0 % hits, with or without the table. static-h3's 20 URIs exceed the memo's 8 entries, or its
  sections exceed the memo's 128-byte limit; which one was not examined. The decode path is 3 % of static-h3 cycles
  (11 % on baseline-h3, where the memo hits). A lead, not a Task 18 change.

## 3. Hardware note (Ruling T18-b)
- The EC2 box is an EPYC 7R13 (Zen 3), with AES-NI and VAES.
  - ring's AES-GCM uses `aes_gcm_enc_update_vaes_avx2` there, and takes 7 % (+2 % seal) of static-h3 base's cycles in
    this run.
- HttpArena's board is a Threadripper 3995WX (Zen 2), with AES-NI but no VAES, so ring falls back to AES-NI/AVX AES-GCM.
  - Bulk AES-GCM therefore costs relatively more there.
- The batched header-protection path uses only 128-bit AES-NI, which both CPUs have, so its (null) result should carry
  over.
- ring's CPU steering cannot be set from outside, so the board's VAES-less AES-GCM was not emulated.

## 4. Library defaults changed
**None.**

| setting | default | why |
|---|---|---|
| `QuicParams::batched_header_protection` | `false` | no WIN |
| `H3Params::qpack_max_table_capacity` | 0 | 4096 is a loss on baseline-h3 |
| `H3Params::qpack_blocked_streams` | 0 | goes with no table |
| arena-h2 `ARENA_H3_HP` | `ring` | follows the library default |
| arena-h2 `ARENA_H3_QPACK` | `0` | follows the library default |

The keyed TLS record AEAD (Step 1) stays in; its h1/h2 A/B belongs to Task 24.
