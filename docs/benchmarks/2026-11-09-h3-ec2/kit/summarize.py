#!/usr/bin/env python3
"""summarize.py OUT_DIR: the tables of one aws-h3 phase (the box's kit/out, fetched by launch.sh into
results/run-*/A/out or B/out; or a smoke run's out/). Run with python3 -I.

  bench    bench.jsonl: the composite and the CPU table of h3-composite.py (median of the starts), then the rps of
           every start by pass (the server order was rotated each pass), failed starts marked
  profile  profile/<label>-<profile>/run<N>-<kind>/: per window the request rate (rimu: exact, from its h3 counters;
           rivals: the run's h2load rps, marked ~), the server's CPU per request and its user/system split, the server
           cores' softirq share, UDP datagrams and errors (host-wide: both ends of the loopback), the perf stat
           counts per request (context switches, syscalls, io_uring, net tracepoints) and the top symbols
  hw       the hardware counter windows (phase B, or phase A on a box with a PMU): cycles, instructions and IPC per
           request, miss ratios, the top-down metrics and the top cache-miss symbols
"""

import csv
import importlib.util
import json
import re
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def composite_module():
    spec = importlib.util.spec_from_file_location("h3composite", HERE / "remote" / "h3-composite.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read_jsonl(path):
    rows = []
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    rows.append({"bad_line": line})
    return rows


def name_of(r):
    return r.get("label") or (f"{r['server']}-{r['headers']}" if r.get("headers") else r.get("server", "?"))


def bench(out):
    path = out / "bench.jsonl"
    rows = read_jsonl(path)
    if not rows:
        return
    print("## bench\n")
    good = [r for r in rows if "rps" in r]
    if good:
        mod = composite_module()
        print("composite (median of the starts; reference = best of plod, fib, aegon, rimu):\n```")
        mod.main([str(path)])
        print("```\n")
        mod.cpu_table(str(path))
        print()
    print("rps of every start by pass (k = 1000; ! = errors; FAILED = no result after the retry):\n")
    passes = sorted({r.get("pass", 0) for r in rows})
    print("| profile | server | " + " | ".join(f"pass {p}" for p in passes) + " | spread |")
    print("|---|---|" + "---|" * len(passes) + "---|")
    for prof in ("baseline-h3", "static-h3"):
        for name in sorted({name_of(r) for r in rows if r.get("profile") == prof}):
            cells, vals = [], []
            for p in passes:
                rs = [r for r in rows if r.get("profile") == prof and name_of(r) == name and r.get("pass", 0) == p]
                if not rs:
                    cells.append("-")
                    continue
                r = rs[-1]
                if "rps" not in r:
                    cells.append("FAILED")
                    continue
                vals.append(r["rps"])
                cells.append(f"{r['rps'] / 1e3:.0f}k{'!' if r.get('errors') else ''}")
            spread = f"{100 * (max(vals) - min(vals)) / statistics.median(vals):.0f}%" if len(vals) > 1 else "-"
            print(f"| {prof} | {name} | " + " | ".join(cells) + f" | {spread} |")
    print()


def kv(path):
    d = {}
    if path.exists():
        for line in path.read_text().splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                try:
                    d[parts[0]] = float(parts[1])
                except ValueError:
                    d[parts[0]] = parts[1]
    return d


def perf_csv(path):
    """event -> value, and the metric lines (metric-value, metric-unit), of a perf stat -x, file."""
    events, metrics = {}, []
    if not path.exists():
        return events, metrics
    for row in csv.reader(l for l in path.read_text().splitlines() if l and not l.startswith("#")):
        if len(row) < 3:
            continue
        val, ev = row[0], row[2]
        try:
            events[ev] = float(val)
        except ValueError:
            pass
        if len(row) >= 7 and row[6].strip() and row[5].strip():
            metrics.append((row[6].strip(), row[5].strip()))
    return events, metrics


def top_symbols(path, n):
    out = []
    if path.exists():
        for line in path.read_text().splitlines():
            m = re.match(r"\s*([0-9.]+)%\s+(\S+)\s+\[.\]\s+(.*)", line)
            if m:
                out.append(f"{m.group(1)}% {m.group(3).strip()[:60]} ({Path(m.group(2)).name})")
            if len(out) >= n:
                break
    return out


def run_rps(out, kind, label, prof, run):
    """The h2load rps of run N of that start (rivals' request-rate estimate)."""
    for r in read_jsonl(out / f"{kind}.jsonl"):
        if r.get("label") == label and r.get("profile") == prof and "runs" in r:
            runs = r["runs"]
            if 0 < run <= len(runs) and runs[run - 1]:
                return float(runs[run - 1])
    return None


def windows(out, kind):
    base = out / kind
    if not base.is_dir():
        return []
    res = []
    for start in sorted(p for p in base.iterdir() if p.is_dir() and "-failed-" not in p.name):
        label, prof = start.name.rsplit("-", 2)[0], "-".join(start.name.rsplit("-", 2)[1:])
        for w in sorted(start.glob("run*-*")):
            m = re.match(r"run(\d+)-(\w+)", w.name)
            if not m:
                continue
            win = kv(w / "window.txt")
            secs = win.get("t_ns", 0) / 1e9
            exact = "h3_requests" in win and secs > 0
            if exact:
                rate = win["h3_requests"] / secs
            else:
                rate = run_rps(out, kind, label, prof, int(m.group(1)))
            ev, metrics = perf_csv(w / "stat.csv")
            res.append(dict(label=label, prof=prof, run=int(m.group(1)), kind=m.group(2), dir=w, win=win, secs=secs,
                            rate=rate, exact=exact, ev=ev, metrics=metrics))
    return res


def per_req(w, count):
    """A perf stat count over its own duration -> per request."""
    dur = w["ev"].get("duration_time", 0) / 1e9 or w["secs"]
    if not w["rate"] or not dur:
        return None
    return count / (w["rate"] * dur)


def fmt(v, f="{:.2f}"):
    return "-" if v is None else f.format(v)


def profile(out, kind):
    ws = [w for w in windows(out, kind) if w["kind"] == "sw"]
    if not ws:
        return
    print(f"## {kind}: software profile windows\n")
    print("| profile | server | req/s | srv us/req | user % | softirq % cores | UDP in/req | UDP out/req | rcvbuf/sndbuf/in err | ctx-sw/req | syscalls/req (top) |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for w in ws:
        win, rate, secs = w["win"], w["rate"], w["secs"]
        n = rate * secs if rate else None
        u, s = win.get("srv_user_usec"), win.get("srv_system_usec")
        srv = (u + s) / n if n and u is not None and s is not None else None
        user = 100 * u / (u + s) if u is not None and s and (u + s) > 0 else None
        tot = sum(win.get(k, 0) for k in ("cores_user", "cores_nice", "cores_system", "cores_idle", "cores_iowait",
                                         "cores_irq", "cores_softirq", "cores_steal"))
        sirq = 100 * win.get("cores_softirq", 0) / tot if tot else None
        uin = win.get("udp_InDatagrams", 0) + win.get("udp6_InDatagrams", 0)
        uout = win.get("udp_OutDatagrams", 0) + win.get("udp6_OutDatagrams", 0)
        err = "/".join(str(int(win.get(f"udp_{k}", 0) + win.get(f"udp6_{k}", 0))) for k in ("RcvbufErrors", "SndbufErrors", "InErrors"))
        sc = sorted(((k.split(":")[1].replace("sys_enter_", ""), per_req(w, v)) for k, v in w["ev"].items()
                     if k.startswith("syscalls:")), key=lambda x: -(x[1] or 0))
        scs = ", ".join(f"{k} {v:.2f}" for k, v in sc[:4] if v)
        ctx = per_req(w, w["ev"]["context-switches"]) if "context-switches" in w["ev"] else None
        print(f"| {w['prof']} | {w['label']} | {'' if w['exact'] else '~'}{fmt(rate, '{:,.0f}')} | {fmt(srv)} | {fmt(user, '{:.0f}')} |"
              f" {fmt(sirq, '{:.1f}')} | {fmt(uin / n if n else None, '{:.3f}')} | {fmt(uout / n if n else None, '{:.3f}')} | {err} |"
              f" {fmt(ctx, '{:.3f}')} | {scs} |")
    print("\n~ = request rate from the run's h2load rps (rivals); rimu's comes from its own counters over the window.")
    print("UDP counters are host-wide: both the server's and the generator's datagrams on the loopback.\n")
    for w in ws:
        other = {k: v for k, v in w["ev"].items() if k.startswith(("io_uring:", "net:", "skb:", "udp:"))}
        extra = ", ".join(f"{k} {per_req(w, v):.3f}/req" for k, v in sorted(other.items()) if per_req(w, v) is not None)
        print(f"### {w['prof']} {w['label']}  ({w['dir'].relative_to(out)})")
        if extra:
            print(f"tracepoints: {extra}")
        for line in top_symbols(w["dir"] / "top.txt", 10):
            print(f"  {line}")
        print()


def hw(out, kind):
    ws = [w for w in windows(out, kind) if w["kind"] in ("hwstat", "topdown", "cachemiss", "lbr")]
    if not ws:
        return
    print(f"## {kind}: hardware counter windows\n")
    print("| profile | server | req/s | cycles/req | instr/req | IPC | branch-miss % | L1d miss % | LLC miss % | dTLB miss/req | iTLB miss/req |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for w in (w for w in ws if w["kind"] == "hwstat"):
        e = w["ev"]

        def ratio(a, b):
            return 100 * e[a] / e[b] if a in e and e.get(b) else None
        cyc = per_req(w, e["cycles"]) if "cycles" in e else None
        ins = per_req(w, e["instructions"]) if "instructions" in e else None
        ipc = e["instructions"] / e["cycles"] if e.get("cycles") and "instructions" in e else None
        dtlb = per_req(w, e["dTLB-load-misses"]) if "dTLB-load-misses" in e else None
        itlb = per_req(w, e["iTLB-load-misses"]) if "iTLB-load-misses" in e else None
        print(f"| {w['prof']} | {w['label']} | {fmt(w['rate'], '{:,.0f}')} | {fmt(cyc, '{:,.0f}')} | {fmt(ins, '{:,.0f}')} | {fmt(ipc)} |"
              f" {fmt(ratio('branch-misses', 'branches'))} | {fmt(ratio('L1-dcache-load-misses', 'L1-dcache-loads'))} |"
              f" {fmt(ratio('LLC-load-misses', 'LLC-loads'))} | {fmt(dtlb)} | {fmt(itlb)} |")
    print()
    for w in (w for w in ws if w["kind"] == "topdown"):
        print(f"### top-down {w['prof']} {w['label']}")
        if (w["dir"] / "skipped.txt").exists():
            print(f"  skipped: {(w['dir'] / 'skipped.txt').read_text().strip()}")
        for unit, val in w["metrics"]:
            print(f"  {val} {unit}")
        print()
    for w in (w for w in ws if w["kind"] in ("cachemiss", "lbr")):
        print(f"### {w['kind']} {w['prof']} {w['label']} ({w['dir'].relative_to(out)})")
        for line in top_symbols(w["dir"] / "top.txt", 10):
            print(f"  {line}")
        print()


def main(argv):
    if len(argv) != 1:
        sys.exit(__doc__)
    out = Path(argv[0])
    host = out / "host.txt"
    if host.exists():
        for line in host.read_text().splitlines():
            if line.startswith(("imds instance-type", "imds placement", "pmu=", "server cpus", "uname -r")):
                print(line)
        print()
    bench(out)
    profile(out, "profile")
    hw(out, "profile")
    hw(out, "hw")


if __name__ == "__main__":
    main(sys.argv[1:])
