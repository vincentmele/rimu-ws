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
  variants phase V (vbench.jsonl, vprofile/): per profile and variant the median over the passes of rps and of the
           server's CPU per request, their change against `base`, the spread of the passes, the verdict of the
           brief of task 16 (a win is >= +1 % rps, or <= -2 % server CPU/req at equal rps: |rps change| < 1 %),
           the counters of spec section 2.1 (responses per packet, ACK-only share, share of response flushes
           with an ACK, BLOCKED frames received, losses, PTOs, STREAM frames sent again) and the knobs line
           each start printed; then the profile windows of the variants profiled
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


VERDICT_RPS = 1.0  # % of rps that makes a win (brief of task 16, step 2)
VERDICT_CPU = 2.0  # % of server CPU per request at equal rps


def med(rows, key):
    vals = [r[key] for r in rows if isinstance(r.get(key), (int, float))]
    return statistics.median(vals) if vals else None


def variants(out):
    rows = [r for r in read_jsonl(out / "vbench.jsonl") if "profile" in r]
    if not rows:
        return
    print("## variants (phase V)\n")
    passes = sorted({r.get("pass", 0) for r in rows})
    for prof in ("baseline-h3", "static-h3"):
        prows = [r for r in rows if r.get("profile") == prof]
        if not prows:
            continue
        names = []
        for r in prows:
            n = r.get("variant") or r.get("server", "?")
            if n not in names:
                names.append(n)
        good = lambda n: [r for r in prows if (r.get("variant") or r.get("server")) == n and "rps" in r]
        base = good("base")
        b_rps, b_cpu = med(base, "rps"), med(base, "server_cpu_us_per_req")
        print(f"### {prof} (median of {len(passes)} passes; base {fmt(b_rps, '{:,.0f}')} req/s, {fmt(b_cpu)} us/req)\n")
        print("| variant | req/s | vs base | srv us/req | vs base | spread | verdict | resp/pkt | ACK-only | flushes w/ ACK"
              " | blocked in (streams/data/stream) | lost | PTO | resent | starts |")
        print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
        for n in names:
            rs = good(n)
            failed = len([r for r in prows if (r.get("variant") or r.get("server")) == n and "rps" not in r])
            rps, cpu = med(rs, "rps"), med(rs, "server_cpu_us_per_req")
            d_rps = 100 * (rps / b_rps - 1) if rps and b_rps else None
            d_cpu = 100 * (cpu / b_cpu - 1) if cpu and b_cpu else None
            vals = [r["rps"] for r in rs]
            spread = 100 * (max(vals) - min(vals)) / statistics.median(vals) if len(vals) > 1 else None
            verdict = "-"
            b_vals = [r["rps"] for r in base]
            b_spread = 100 * (max(b_vals) - min(b_vals)) / statistics.median(b_vals) if len(b_vals) > 1 else None
            if n not in ("base", "zix") and d_rps is not None and d_cpu is not None:
                if d_rps >= VERDICT_RPS or (abs(d_rps) < VERDICT_RPS and d_cpu <= -VERDICT_CPU):
                    verdict = "WIN"
                elif d_rps <= -VERDICT_RPS or (abs(d_rps) < VERDICT_RPS and d_cpu >= VERDICT_CPU):
                    verdict = "loss"
                else:
                    verdict = "="
                # A change smaller than the spread of base's passes or of the variant's is not one
                noise = max(s for s in (spread, b_spread, 0.0) if s is not None)
                if noise > abs(d_rps) and verdict != "=":
                    verdict += " (within spread)"
                if rs and rs[0].get("binary") == "prev":
                    # `prev` is the older build: its "loss" is the newer build's win
                    verdict += " [prev: read inverted]"
            blocked = "/".join(fmt(med(rs, k), "{:.0f}") for k in ("streams_blocked", "data_blocked", "stream_data_blocked"))
            ack = med(rs, "ack_only_share")
            fas = med(rs, "fin_ack_share")
            print(f"| {n} | {fmt(rps, '{:,.0f}')} | {fmt(d_rps, '{:+.1f}%')} | {fmt(cpu)} | {fmt(d_cpu, '{:+.1f}%')} |"
                  f" {fmt(spread, '{:.1f}%')} | {verdict} | {fmt(med(rs, 'resp_per_pkt'), '{:.1f}')} |"
                  f" {fmt(100 * ack if ack is not None else None, '{:.1f}%')} | {fmt(100 * fas if fas is not None else None, '{:.1f}%')} |"
                  f" {blocked} | {fmt(med(rs, 'packets_lost'), '{:.0f}')} | {fmt(med(rs, 'pto_probes'), '{:.0f}')} |"
                  f" {fmt(med(rs, 'frames_resent'), '{:.0f}')} | {len(rs)}{f' ({failed} failed)' if failed else ''} |")
        print()
        print("The verdict of `prev` (the build before the one measured) reads inverted: its loss is the newer"
              " build's win. \"within spread\": the change is smaller than the spread of the passes of base or of"
              " the variant.\n")
        print("rps by pass (k = 1000; ! = errors):\n")
        print("| variant | " + " | ".join(f"pass {p}" for p in passes) + " |")
        print("|---|" + "---|" * len(passes))
        for n in names:
            cells = []
            for p in passes:
                rs = [r for r in prows if (r.get("variant") or r.get("server")) == n and r.get("pass", 0) == p]
                if not rs:
                    cells.append("-")
                elif "rps" not in rs[-1]:
                    cells.append("FAILED")
                else:
                    cells.append(f"{rs[-1]['rps'] / 1e3:.0f}k{'!' if rs[-1].get('errors') else ''}")
            print(f"| {n} | " + " | ".join(cells) + " |")
        print()
    print("knobs each variant ran with (first start; the server's own line):\n")
    seen = set()
    for r in rows:
        n = r.get("variant")
        if n and n not in seen and r.get("knobs") is not None:
            seen.add(n)
            print(f"- {n}: {r['knobs']}")
        elif n and n not in seen and r.get("binary") == "prev":
            seen.add(n)
            print(f"- {n}: (build before task 16: prints no knobs line)")
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
    variants(out)
    profile(out, "vprofile")
    hw(out, "vprofile")


if __name__ == "__main__":
    main(sys.argv[1:])
