# HTTP/3 response headers A/B (user decision Q2) — EC2, 9 Nov 2026

Box: m6a.24xlarge spot, sa-east-1b (AMD EPYC Milan, Zen 3, 48 cores / 96 threads, kernel 7.0.0-1016-aws). Server on
24 cores (48 threads), h2load-h3 generator on the other 24 (`-t 48`, `-c 64 -m 64`, `-D 5s`, best of 3 runs per start),
3 interleaved passes, all 7 servers in each pass. Run: `/mnt/nvme1tb/claude-tmp/aws-h3/results/run-20261109-140921`.
rimu = arena-h2 at bc19008d (same h3 server code as the HttpArena entry).

## The two variants
| variant | response fields | bytes per baseline2 response (QPACK) | RFC 9110 |
|---|---|---|---|
| `min` | `:status`, `content-type` | 4 B | violates §6.6.1 (an origin server with a clock MUST send Date) and §8.6 (Content-Length SHOULD be sent when the size is known) |
| `full` | `:status`, `content-type`, `content-length`, `date`, `server` | 48 B | compliant (`server` is optional) |

HttpArena's validator checks neither: for h3 it requires 4 × 2xx; the static-h3 docs require `content-type` and the
matching `content-encoding`, which both variants send. (Note: arena-h2 advertises a 4 KiB max field section, the entry
16 KiB — a 2-byte SETTINGS difference, no effect on these profiles.)

## Results (median of 3 passes; spread ≤ 2 %)
| profile | variant | req/s | server CPU µs/req | generator CPU µs/req | rank among 7 servers |
|---|---|---|---|---|---|
| baseline-h3 | min | **5,692k** | 2.48 | 6.89 | #2 (zix 5,970k) |
| baseline-h3 | full | 4,726k (−17 %) | 3.11 (+25 %) | 8.03 (+17 %) | #4 (cnetmod 5,584k, rimu-min, zix ahead) |
| static-h3 | min | 1,007k | 30.27 | 40.28 | #1 |
| static-h3 | full | 990k (−2 %, within noise) | 29.76 | 41.08 | #1 (min) / #2 |

Composite (reference = best of plod/fib/aegon/rimu per profile, 1000 pts each): rimu-min 2000, rimu-full 1814,
cnetmod 1789, zix 1631, fib 1623, plod 1544, aegon 1404.

## Where the cost of `full` comes from
- The generator is the limiter (it uses ~2.5× the server's CPU per request on baseline): the 44 extra header bytes
  cost it +1.14 µs/req (h2load's per-header work), which is most of the −17 %.
- On the server, `full` costs +0.63 µs/req; the profile shows `qpack::encoder::encode_static_line` at 7.3 % of server
  cycles in `full` (absent in `min`): `content-length`, `date` and `server` are encoded per response. Splicing a
  pre-encoded `date`/`server` block (date once a second) would recover most of the server-side part, not the
  generator-side part.
- static-h3 bodies (KB-sized) make the header bytes irrelevant.

## Decision needed
`min` keeps rimu #2 on baseline-h3 (and #1 composite) at the cost of RFC 9110's Date MUST; `full` is compliant and
drops rimu to #4 on baseline-h3 (still #1 on static-h3). A middle variant (`content-type` + `date`: satisfies the MUST,
skips the SHOULD and `server`) was not measured.
