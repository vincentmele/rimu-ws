#!/usr/bin/env python3
"""Medians over the passes of each build's best run per pass, from ab.log (usage: summary.py ab.log)."""
import collections, re, statistics as st, sys

rows = collections.defaultdict(list)
for line in open(sys.argv[1] if len(sys.argv) > 1 else "ab.log"):
    m = re.match(r"p(\d) (\w) (\S+) r\d\s+Throughput: ([\d.]+)K req/s\s+cpu_s ([\d.]+) "
                 r"2xx=(\d+), 3xx=(\d+), 4xx=(\d+), 5xx=(\d+)", line)
    if not m:
        continue
    p, v, prof, rps, cpu, ok, x3, x4, x5 = m.groups()
    rows[(prof, v, int(p))].append((float(rps) * 1000, float(cpu) * 1e6 / int(ok), int(x3) + int(x4) + int(x5)))
passes = sorted({k[2] for k in rows})
print("non-2xx total:", sum(r[2] for v in rows.values() for r in v))
print(f"{'profile':13} {'A rps':>9} {'B rps':>9} {'B/A':>7} {'A spread':>8} {'B spread':>8} "
      f"{'A us/req':>8} {'B us/req':>8} {'cpu B/A':>7}  per-pass B/A rps")
for prof in ["baseline", "limited-conn", "json-comp"]:
    res = {}
    for v in "AB":
        best = [max(rows[(prof, v, p)]) for p in passes]
        rps = [b[0] for b in best]
        cpu = [b[1] for b in best]
        res[v] = (st.median(rps), (max(rps) - min(rps)) / st.median(rps) * 100, st.median(cpu), rps)
    a, b = res["A"], res["B"]
    pp = " ".join(f"{(y / x - 1) * 100:+.1f}" for x, y in zip(a[3], b[3]))
    print(f"{prof:13} {a[0]:9.0f} {b[0]:9.0f} {(b[0] / a[0] - 1) * 100:+6.2f}% {a[1]:7.1f}% {b[1]:7.1f}% "
          f"{a[2]:8.3f} {b[2]:8.3f} {(b[2] / a[2] - 1) * 100:+6.2f}%  {pp}")
