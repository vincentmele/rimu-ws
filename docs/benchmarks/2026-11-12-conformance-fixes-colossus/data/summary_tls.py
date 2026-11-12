#!/usr/bin/env python3
"""Medians over the passes of each build's best run per pass, from ab-tls.log (usage: summary_tls.py ab-tls.log)."""
import collections, re, statistics as st, sys

rows = collections.defaultdict(list)
errors = collections.Counter()
for line in open(sys.argv[1] if len(sys.argv) > 1 else "ab-tls.log"):
    m = re.match(r"p(\d) (\w) (\S+) r\d rps ([\d.]+) reqs (\d+) cpu_s ([\d.]+) non2xx (\d+) sockerr ?(\S*)", line)
    if not m:
        continue
    p, v, prof, rps, reqs, cpu, non2xx, sockerr = m.groups()
    rows[(prof, v, int(p))].append((float(rps), float(cpu) * 1e6 / int(reqs)))
    errors[v] += int(non2xx)
    if sockerr not in ("", "none"):
        errors[f"{v} socket errors: {sockerr}"] += 1
passes = sorted({k[2] for k in rows})
print("non-2xx:", dict(errors))
print(f"{'profile':9} {'A rps':>9} {'B rps':>9} {'B/A':>7} {'A spread':>8} {'B spread':>8} "
      f"{'A us/req':>8} {'B us/req':>8} {'cpu B/A':>7}  per-pass B/A rps")
for prof in ["json-tls", "8gbit"]:
    res = {}
    for v in "AB":
        best = [max(rows[(prof, v, p)]) for p in passes]
        rps = [b[0] for b in best]
        cpu = [b[1] for b in best]
        res[v] = (st.median(rps), (max(rps) - min(rps)) / st.median(rps) * 100, st.median(cpu), rps)
    a, b = res["A"], res["B"]
    pp = " ".join(f"{(y / x - 1) * 100:+.1f}" for x, y in zip(a[3], b[3]))
    print(f"{prof:9} {a[0]:9.0f} {b[0]:9.0f} {(b[0] / a[0] - 1) * 100:+6.2f}% {a[1]:7.1f}% {b[1]:7.1f}% "
          f"{a[2]:8.3f} {b[2]:8.3f} {(b[2] / a[2] - 1) * 100:+6.2f}%  {pp}")
