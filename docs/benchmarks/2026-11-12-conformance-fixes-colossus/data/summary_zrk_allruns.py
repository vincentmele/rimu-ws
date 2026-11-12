#!/usr/bin/env python3
"""Medians over every run (not one per start) from ab-zrk.log, for all passes and without the passes
given after the log (usage: summary_zrk_allruns.py ab-zrk.log [excluded pass ...])."""
import re, statistics as st, sys
pat = re.compile(r"p(\d) (\w) (\S+) r\d rate ([\d.]+) ratio [\d.]+ mean ([\d.]+) p99 ([\d.]+) "
                 r"p999 ([\d.]+) cpu_s [\d.]+ cpu_us_req ([\d.]+)")
runs = [m.groups() for m in map(pat.match, open(sys.argv[1])) if m]
excluded = set(sys.argv[2:])
for label, keep in [("all passes", lambda p: True), (f"without pass {','.join(sorted(excluded))}", lambda p: p not in excluded)]:
    if label.startswith("without") and not excluded:
        continue
    print(label)
    for prof in ["8gbit", "latency-10k"]:
        for i, name in [(7, "cpu µs/req"), (4, "mean µs"), (5, "p99 µs"), (6, "p99.9 µs")]:
            med = {v: st.median(float(r[i]) for r in runs if r[1] == v and r[2] == prof and keep(r[0])) for v in "AB"}
            n = sum(1 for r in runs if r[1] == "A" and r[2] == prof and keep(r[0]))
            print(f"  {prof:12} {name:11} A {med['A']:9.2f}  B {med['B']:9.2f}  {(med['B'] / med['A'] - 1) * 100:+6.1f}%  ({n} runs each)")
