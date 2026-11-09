#!/usr/bin/env python3
"""Experimental HttpArena HTTP/3 composite over local h3-bench.sh results.

    h3-composite.py [--last] RESULTS.jsonl
    h3-composite.py --cpu RESULTS.jsonl

Each line is one h3-bench.sh output. Per server and profile the number is the median rps over the
server's lines (the median of several server starts), or with --last the rps of its last line. Points
are 1000 x rps / the best rps of the profile among plod, fib, aegon and rimu, summed over baseline-h3
and static-h3. Servers outside that field (cnetmod, zix) are scored against the same best, so they can
exceed 1000 on a profile; they do not move the reference. Ranks are per profile, over every server
in the file. A number marked ! comes from lines with errors. Lines without an rps (a failed start)
are skipped.

A line of rimu that carries "headers" (the A/B of the response headers, ARENA_H3_HEADERS) counts as
the server "rimu-min" or "rimu-full"; in the composite those are rimu variants (the field has the
best of them).

--cpu prints, instead, a markdown table per server and profile: the median rps of the starts (and
each start's), the medians over the starts of the server's and the generator's CPU microseconds per
response, the errors summed, the range of the box's load, and for the servers that report them
(rimu) the medians of the datagrams received and sent and the packets sent per response and of the
share of ACK-only packets among the packets sent.
"""

import json
import statistics
import sys

PROFILES = ("baseline-h3", "static-h3")
FIELD = ("plod", "fib", "aegon", "rimu")


def name_of(row):
    """The name a line is listed under: rimu with its headers variant, if it has one."""
    if row.get("headers"):
        return f"{row['server']}-{row['headers']}"
    return row["server"]


def read(path):
    """The lines of the file that have a result, by (name, profile)."""
    rows = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if "rps" not in row:
                continue  # a start that failed has no result
            rows.setdefault((name_of(row), row["profile"]), []).append(row)
    return rows


def median_of(values):
    """The median of the values that are numbers, or None if there are none."""
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def cpu_table(path):
    rows = read(path)
    print("| profile | server | rps median of starts (per start) | srv us/req | gen us/req | errors | load1 range |"
          " dgrams in/req | dgrams out/req | pkts out/req | ACK-only share |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")

    def cell(value, fmt):
        return "-" if value is None else fmt.format(value)

    for profile in PROFILES:
        names = sorted({key[0] for key in rows if key[1] == profile})
        for name in names:
            lines = rows[(name, profile)]
            per = ", ".join(f"{r['rps'] / 1e3:.0f}k" for r in lines)
            rps = statistics.median(r["rps"] for r in lines)
            srv = median_of(r.get("server_cpu_us_per_req") for r in lines)
            gen = median_of(r.get("gen_cpu_us_per_req") for r in lines)
            errors = sum(r.get("errors", 0) for r in lines)
            lo = min(r["load1"] for r in lines)
            hi = max(r["load1"] for r in lines)
            din = median_of(r.get("dgrams_in_per_req") for r in lines)
            dout = median_of(r.get("dgrams_out_per_req") for r in lines)
            pout = median_of(r.get("pkts_out_per_req") for r in lines)
            ack = median_of(r.get("ack_only_share") for r in lines)
            print(
                f"| {profile} | {name} | {rps / 1e3:.0f}k ({per}) | {cell(srv, '{:.2f}')} | {cell(gen, '{:.2f}')}"
                f" | {errors} | {lo:.0f}-{hi:.0f} | {cell(din, '{:.2f}')} | {cell(dout, '{:.2f}')}"
                f" | {cell(pout, '{:.2f}')} | {cell(None if ack is None else 100 * ack, '{:.1f}%')} |"
            )


def load(path, last):
    rows = read(path)
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
    cpu = "--cpu" in argv
    paths = [a for a in argv if a not in ("--last", "--cpu")]
    if len(paths) != 1 or (last and cpu):
        sys.exit(__doc__)
    if cpu:
        cpu_table(paths[0])
        return
    rps, dirty = load(paths[0], last)
    servers = sorted({key[0] for key in rps})
    # The field is plod, fib, aegon and rimu, whichever headers variant of rimu a line has
    in_field = [s for s in servers if s.partition("-")[0] in FIELD]
    top = {p: max((rps.get((s, p), 0.0) for s in in_field), default=0.0) for p in PROFILES}
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
