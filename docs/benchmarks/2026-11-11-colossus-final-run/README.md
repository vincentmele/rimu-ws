# Final regression and HTTP/3 composite on colossus — 11 Nov 2026 (04:54–05:28 UTC)

The h1/h2/WebSocket regression A/B and the final HTTP/3 composite of the HTTP/3 plan's Task 24
(`docs/superpowers/plans/2026-11-08-http3-quic.md`), which were prepared as an EC2 kit and not run there (the user
declined the EC2 run on 11 Nov), run instead on colossus at the user's request. Kit: `/mnt/nvme1tb/claude-tmp/aws-final`
(not in the repo), started with `LOCAL=1`, a switch added for this run so the kit changes no sysctl or service and kills
nothing it did not start (`data/run.sh`).

## Machine and builds
colossus: AMD Ryzen 9 5900X, 12 cores / 24 threads (Zen 3, VAES), kernel 7.0.0-38 (`data/host.txt`). Servers on CPUs
0-5,12-17, generators on 6-10,18-22 (`h2load -t 10`); core 11/23 left to colossus's live services. No sysctl changes.
Builds (release, `-C target-cpu=znver2`, the kit's scratch clones):

- Phase R: A = `main` 85c9fe8d (before HTTP/3), B = 1a3c3b08 (HTTP/3 merged).
- Phase C+X: `base` = 1a3c3b08, `prev` = 44752fa8 (the last EC2-measured build); rivals plod (rebuilt `-march=znver2`),
  fib, aegon, cnetmod, zix (local images).

**Not a quiet machine.** From 05:23:57 a foreign job (`xauhft`, ~16 threads) ran alongside: the load average went from
about 11 (this run alone) to 33 (`data/uptime.log`). Pass 3 of phase C overlapped it — every server's static-h3 runs
roughly halved there — and phase R had finished before it. Medians are over the passes, each start keeping its best of 3
runs, so passes 1–2 carry the result; pass 3 is reported as it ran.

## Phase R — h1/h2/WebSocket regression, A (85c9fe8d) vs B (1a3c3b08), 4 interleaved passes

| profile | A req/s | B req/s | B vs A | A / B spread | A cpu µs/req | B cpu µs/req | cpu vs A | verdict |
|---|---|---|---|---|---|---|---|---|
| h1-baseline | 791,472 | 800,102 | +1.09 % | 4.1 / 0.5 % | 14.625 | 14.639 | +0.09 % | ok |
| h1-jsoncomp-4096 | 138,446 | 136,825 | −1.17 % | 0.6 / 3.7 % | 86.638 | 87.644 | +1.16 % | over 1 %, within B's spread |
| h1-json-tls | 352,570 | 353,886 | +0.37 % | 10.0 / 18.1 % | 27.065 | 26.953 | −0.41 % | ok |
| h1-8gbit (judged by cpu) | 47,162 | 47,135 | −0.06 % | 0.1 / 0.2 % | 34.847 | 36.100 | **+3.60 %** | over 1 %, inconclusive |
| baseline-h2-1024 | 4,509,487 | 4,536,250 | +0.59 % | 1.3 / 2.0 % | 1.046 | 1.053 | +0.72 % | ok |
| static-h2-1024 | 448,401 | 448,576 | +0.04 % | 14.7 / 11.9 % | 25.895 | 25.960 | +0.25 % | ok |
| baseline-h2c-1024 | 4,896,668 | 4,873,788 | −0.47 % | 4.4 / 2.0 % | 1.002 | 1.014 | +1.20 % | ok |
| json-h2c-1024 | 1,910,248 | 1,910,812 | +0.03 % | 3.3 / 5.8 % | 5.015 | 5.024 | +0.18 % | ok |
| ws-512:1:0 | 870,721 | 873,742 | +0.35 % | 1.6 / 2.6 % | 13.279 | 13.322 | +0.32 % | ok |

h1-8gbit's +3.6 % comes mostly from one pass of B (50.3 µs, p99 1,041 µs); without it B is +1–4 % against A's own 6 %
pass-to-pass range. It is the profile that runs the keyed TLS record AEAD (9c5732df / a23a2176, Ruling T18-f's revert
route). A later quiet A/B on the same box (`docs/benchmarks/2026-11-11-json-comp-colossus/`, `main` 1a3c3b08 vs the
gzip-encoder branch, both carrying that change) is not an A/B of it, so the question stays open: the evidence here is
inconclusive, not a confirmed > 1 % regression, and no revert was made.

## Phase C — final HTTP/3 composite (rimu = `base`, headers=min), 3 passes, both profiles

```
server     composite               baseline-h3                 static-h3
rimu-min        2000       1846k (1000) #2         264k (1000) #1
cnetmod         1851       1749k ( 948) #3         238k ( 903) #3
fib             1818       1531k ( 830) #4         261k ( 989) #2
zix             1712       1892k (1025) #1         181k ( 687) #6
plod            1546       1291k ( 699) #6         223k ( 847) #4
aegon           1506       1470k ( 796) #5         187k!( 709) #5
```

The composite normalises each profile to rimu (the kit's convention). The generator was saturated on both profiles
(about 102 % busy). rimu: #2 on baseline-h3, 2.43 % behind zix (server cpu 1.79 vs 1.35 µs/req); #1 on static-h3, 1.13 %
ahead of fib (27.3 µs/req, the lowest). Among the experimental league's entries (plod, fib, aegon) rimu is first on
both profiles. aegon had 143 request errors on static-h3; every rimu start had 0.

## Phase X — carried checks (rimu starts)
Request errors 0 on every start of `base` and `prev`; handler panics, UDP send errors, stateless resets and forwarding
drops 0; `frames_resent_acked` 0 (the counter of resending data the peer had acknowledged). `base` vs `prev`: baseline-h3
equal (1,845,806 vs 1,846,183 req/s), static-h3 +5.5 % for `base` (263,770 vs 249,955, inside the 56–60 % spreads that
pass 3 caused). Peak frame-reference chunks per worker are not in the server's stats line (measured in-process in Task
23d at 22 % of the pool).

## Data
`data/summary.txt` (the kit's tables), `data/phase-R.log`, `data/phase-C.log`, `data/regress/results.tsv`,
`data/vbench.jsonl`, `data/composite-input.jsonl`, `data/uptime.log`, `data/host.txt`, `data/raw/`, `data/run.sh` (the
kit's phase driver with the `LOCAL=1` switch).
