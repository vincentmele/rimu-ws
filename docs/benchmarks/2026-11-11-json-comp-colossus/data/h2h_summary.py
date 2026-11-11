#!/usr/bin/env python3
"""Summarize h2h.sh: per server and pass, avgRps = mean over 4096/16384 of the best run's rps, bpr = mean bandwidth
(MiB/s x 2^20) / avgRps; eff = avgRps x (minBpr/bpr)^2 with minBpr over the league; medians over passes."""
import re, sys, statistics as st, pathlib
d = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/mnt/nvme1tb/claude-tmp/jsoncomp/h2h")
unit = {"": 1, "K": 1e3, "M": 1e6}
runs = {}
for f in d.glob("p*-c*-r*.txt"):
    m = re.match(r"p(\d+)-(.+)-c(\d+)-r(\d+)\.txt", f.name)
    p, s, c, r = int(m[1]), m[2], int(m[3]), int(m[4])
    t = f.read_text()
    rps = re.search(r"Throughput:\s+([\d.]+)([KM]?) req/s", t)
    bw = re.search(r"Bandwidth:\s+([\d.]+)([KMG]?)B/s", t)
    errs = re.search(r"2xx=(\d+), 3xx=(\d+), 4xx=(\d+), 5xx=(\d+)", t)
    if not rps or not bw:
        continue
    rps_v = float(rps[1]) * unit[rps[2]]
    bw_v = float(bw[1]) * {"K": 2**10, "M": 2**20, "G": 2**30, "": 1}[bw[2]]
    bad = sum(int(x) for x in errs.groups()[1:]) if errs else -1
    runs.setdefault((s, p, c), []).append((rps_v, bw_v, bad))
servers = sorted({k[0] for k in runs})
passes = sorted({k[1] for k in runs})
per = {}  # (server, pass) -> (avgRps, bpr)
for s in servers:
    for p in passes:
        best = [max(runs.get((s, p, c), [(0, 0, 0)])) for c in (4096, 16384)]
        if any(b[0] == 0 for b in best):
            continue
        avg_rps = st.mean(b[0] for b in best)
        avg_bw = st.mean(b[1] for b in best)
        per[(s, p)] = (avg_rps, avg_bw / avg_rps, [b[0] for b in best])
def table(league, title):
    print(f"\n## {title}")
    med = {s: (st.median(per[(s, p)][0] for p in passes if (s, p) in per),
               st.median(per[(s, p)][1] for p in passes if (s, p) in per)) for s in league if any((s, p) in per for p in passes)}
    min_bpr = min(v[1] for v in med.values())
    effs = {s: v[0] * (min_bpr / v[1]) ** 2 for s, v in med.items()}
    top = max(effs.values())
    print("| server | avgRps (median of passes) | per pass | bpr | eff | column |")
    print("|---|---|---|---|---|---|")
    for s in sorted(effs, key=effs.get, reverse=True):
        pp = ", ".join(f"{per[(s, p)][0]/1e3:.0f}K" for p in passes if (s, p) in per)
        print(f"| {s} | {med[s][0]/1e3:.1f} K | {pp} | {med[s][1]:.1f} | {effs[s]/1e3:.1f} K | {1000*effs[s]/top:.0f} |")
    print(f"league minBpr {min_bpr:.1f}")
    return effs
print("runs with non-2xx responses:", sum(1 for v in runs.values() for x in v if x[2] != 0))
e_new = table([s for s in servers if s != "rimu-main"], "League with the new encoder (rimu-new, viltrum, plod, aegon)")
e_old = table([s for s in servers if s != "rimu-new"], "League with main's zlib (rimu-main, viltrum, plod, aegon)")
if "rimu-new" in e_new and "viltrum" in e_new:
    print(f"\nrimu-new eff / viltrum eff = {e_new['rimu-new']/e_new['viltrum']:.3f} (goal >= 1.05)")
if "rimu-main" in e_old and "viltrum" in e_old:
    print(f"rimu-main eff / viltrum eff = {e_old['rimu-main']/e_old['viltrum']:.3f}")
