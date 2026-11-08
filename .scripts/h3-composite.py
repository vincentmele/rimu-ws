#!/usr/bin/env python3
"""Experimental HttpArena HTTP/3 composite over local h3-bench.sh results.

    h3-composite.py [--last] RESULTS.jsonl

Each line is one h3-bench.sh output. Per server and profile the number is the median rps over the
server's lines (the median of several server starts), or with --last the rps of its last line. Points
are 1000 x rps / the best rps of the profile among plod, fib, aegon and rimu, summed over baseline-h3
and static-h3. Servers outside that field (cnetmod, zix) are scored against the same best, so they can
exceed 1000 on a profile; they do not move the reference. Ranks are per profile, over every server
in the file. A number marked ! comes from lines with errors. Lines without an rps (a failed start)
are skipped.
"""

import json
import statistics
import sys

PROFILES = ("baseline-h3", "static-h3")
FIELD = ("plod", "fib", "aegon", "rimu")


def load(path, last):
    rows = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if "rps" not in row:
                continue  # a start that failed has no result
            rows.setdefault((row["server"], row["profile"]), []).append(row)
    rps = {}
    dirty = set()
    for key, lines in rows.items():
        if last:
            lines = lines[-1:]
        rps[key] = statistics.median(r["rps"] for r in lines)
        if any(r.get("errors", 0) for r in lines):
            dirty.add(key)
    return rps, dirty


def main(argv):
    last = "--last" in argv
    paths = [a for a in argv if a != "--last"]
    if len(paths) != 1:
        sys.exit(__doc__)
    rps, dirty = load(paths[0], last)
    servers = sorted({key[0] for key in rps})
    top = {p: max((rps.get((s, p), 0.0) for s in FIELD), default=0.0) for p in PROFILES}
    rank = {}
    for p in PROFILES:
        ordered = sorted((s for s in servers if (s, p) in rps), key=lambda s: -rps[(s, p)])
        for i, s in enumerate(ordered, 1):
            rank[(s, p)] = i
    rows = []
    for s in servers:
        points = {p: (1000 * rps.get((s, p), 0.0) / top[p] if top[p] > 0 else 0.0) for p in PROFILES}
        rows.append((sum(points.values()), s, points))
    rows.sort(key=lambda r: (-r[0], r[1]))
    head = "".join(f"{p:>26}" for p in PROFILES)
    print(f"{'server':10}{'composite':>10}{head}")
    for total, s, points in rows:
        cells = ""
        for p in PROFILES:
            if (s, p) in rps:
                mark = "!" if (s, p) in dirty else " "
                cells += f"{rps[(s, p)] / 1e3:>11.0f}k{mark}({points[p]:4.0f}) #{rank[(s, p)]:<2}"
            else:
                cells += f"{'-':>26}"
        print(f"{s:10}{total:>10.0f}{cells}")


if __name__ == "__main__":
    main(sys.argv[1:])
