#!/usr/bin/env python3
"""Medians over the passes from ab-zrk.log (usage: summary_zrk.py ab-zrk.log). Paced runs are judged
by server cpu per request and latency: per start, 8gbit keeps its run with the least cpu per request
(the least disturbed of three), latency-10k has one run."""
import collections, re, statistics as st, sys

rows = collections.defaultdict(list)
non2xx = collections.Counter()
pat = re.compile(r"p(\d) (\w) (\S+) r\d rate ([\d.]+) ratio ([\d.]+) mean ([\d.]+) p99 ([\d.]+) "
                 r"p999 ([\d.]+) cpu_s [\d.]+ cpu_us_req ([\d.]+) 2xx \d+ non2xx (\d+)")
for line in open(sys.argv[1] if len(sys.argv) > 1 else "ab-zrk.log"):
    m = pat.match(line)
    if not m:
        continue
    p, v, prof, rate, ratio, mean, p99, p999, cpu, bad = m.groups()
    rows[(prof, v, int(p))].append(dict(rate=float(rate), ratio=float(ratio), mean=float(mean),
                                        p99=float(p99), p999=float(p999), cpu=float(cpu)))
    non2xx[v] += int(bad)
passes = sorted({k[2] for k in rows})
print("non-2xx:", dict(non2xx))
for prof in ["8gbit", "latency-10k"]:
    print(f"\n{prof}")
    print(f"  {'metric':14} {'A':>10} {'B':>10} {'B vs A':>8}  A spread / B spread   per-pass B vs A")
    best = {v: [min(rows[(prof, v, p)], key=lambda r: r["cpu"]) for p in passes] for v in "AB"}
    for metric in ["cpu", "rate", "ratio", "mean", "p99", "p999"]:
        vals = {v: [r[metric] for r in best[v]] for v in "AB"}
        med = {v: st.median(vals[v]) for v in "AB"}
        spread = {v: (max(vals[v]) - min(vals[v])) / med[v] * 100 if med[v] else 0 for v in "AB"}
        pp = " ".join(f"{(b / a - 1) * 100:+.1f}" for a, b in zip(vals["A"], vals["B"]))
        name = {"cpu": "cpu µs/req", "rate": "req/s", "ratio": "rate ratio", "mean": "mean µs",
                "p99": "p99 µs", "p999": "p99.9 µs"}[metric]
        print(f"  {name:14} {med['A']:10.3f} {med['B']:10.3f} {(med['B'] / med['A'] - 1) * 100:+7.2f}%  "
              f"{spread['A']:5.1f} / {spread['B']:5.1f} %        {pp}")
