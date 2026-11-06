#!/usr/bin/env python3
"""HttpArena HTTP/2 composite over local h2-bench.sh results.

    h2-composite.py RESULTS.jsonl

Each line is one h2-bench.sh output. Per profile, a server's number is the mean over the profile's
scored connection counts of its best rps (a later line for the same server, profile and conns
replaces an earlier one). Points are 1000 x number / the field's best, summed over the four
profiles, as gen_leaderboard_data.py's badge_composite does with the completeness factor at 1.
"""

import json
import sys

SCORED = {
    "baseline-h2": (256, 1024),
    "static-h2": (256, 1024),
    "baseline-h2c": (256, 1024, 4096),
    "json-h2c": (1024, 4096),
}


def main(path):
    best = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            best[(row["server"], row["profile"], row["conns"])] = row["best"]
    servers = sorted({key[0] for key in best})
    per = {}
    for server in servers:
        for profile, conns in SCORED.items():
            vals = [best[(server, profile, c)] for c in conns if (server, profile, c) in best]
            per[(server, profile)] = sum(vals) / len(conns) if vals else 0.0
    top = {p: max((per[(s, p)] for s in servers), default=0.0) for p in SCORED}
    rows = []
    for server in servers:
        points = {p: (1000 * per[(server, p)] / top[p] if top[p] > 0 else 0.0) for p in SCORED}
        rows.append((sum(points.values()), server, points))
    rows.sort(key=lambda r: (-r[0], r[1]))
    head = "".join(f"{p:>22}" for p in SCORED)
    print(f"{'server':10}{'composite':>10}{head}")
    for total, server, points in rows:
        cells = "".join(f"{per[(server, p)] / 1e3:>12.0f}k ({points[p]:4.0f})" for p in SCORED)
        print(f"{server:10}{total:>10.0f}{cells}")


if __name__ == "__main__":
    main(sys.argv[1])
