# HTTP/3 benchmark and profile on AWS EC2 — 9 Nov 2026

The first quiet-hardware measurement of rimu-ws's HTTP/3 server (feat/http3 at `bc19008d`) against the five strongest
HttpArena h3 entries, plus the response-header A/B behind user decision Q2, plus a full CPU profile (software sampling
with kernel stacks, tracepoint counts, and hardware counters). Everything needed to read, check or repeat it is in this
directory; the full run (with `perf.data` files and flamegraph SVGs) is archived outside the repo (see "Data").

## 1. Why EC2, and the constraints
- colossus (Ryzen 9 5900X, shared with other work) had load averages of 30–112 during every earlier h3 measurement;
  individual starts of one server differed by up to 4× (`/mnt/nvme1tb/claude-tmp/h3bench/RESULTS.md`). The user then
  directed: *"instead of running the benchmarks on colossus, use aws ec2 instance. Prepare the script and programs before
  spinning up the instance so as to not waste EC2 time. Use spot instance on the cheapest appropriate configuration in
  regions we're already approved in"*, *"do full profiling on the ec2 instance also"*, and *"no need for a S3 bucket;
  just transfer via ssh or console"*.
- **Region.** Spot quotas checked in 15 regions: sa-east-1 is the only one with a raised spot quota (96 standard
  vCPUs); every other region is at the default 32 (us-east-1's raise, 1,280, is on-demand only). eu-west-2 was excluded
  outright: the same AWS account runs a live production trading system there. → **sa-east-1**.
- **Why 96 vCPUs matter.** The h3 load generator (h2load + ngtcp2 + nghttp3) is the bottleneck — it spends 2–3× the
  server's CPU per request — so a 32-vCPU box would be generator-bound for every server and hide their differences.
- **Why AMD Zen 3.** HttpArena builds each entry's image on the benchmark machine, and the rival images (plod, aegon,
  cnetmod) and our own entry were built on colossus with `-march=native` / `target-cpu=native`, i.e. for Zen 3. On an
  Intel box they could fault on an unsupported instruction (wasting the run) or run unrepresentatively. A Zen 3 box runs
  them exactly as built.
- **Why the hardware-counter plan had two phases.** AWS's virtual AMD instances were expected to expose no PMU (the
  c6a.8xlarge of the earlier h1 run had none; AWS's Graviton perf runbook lists AMD 5a/6a/7a as unsupported — 
  https://aws.github.io/graviton/perfrunbook/debug_hw_perf.html; background: https://brendangregg.com/blog/2017-05-04/the-pmcs-of-ec2.html),
  AMD bare metal is 192 vCPUs (over the quota), so the kit planned phase A (Zen 3: benchmarks + software profiling) and,
  only if A's PMU probe failed, phase B on Intel bare metal (c7i.metal-24xl, rimu only, rebuilt for x86-64-v3) for
  counters. **In the event the m6a.24xlarge exposed a PMU** (`pmu=yes`), so phase A collected rimu's counters itself
  and phase B was skipped.

## 2. Instance choice and what happened at launch
| attempt | what | outcome |
|---|---|---|
| 1, 2 | `launch.sh` | exited at once, nothing created: a `RUN=…$([ "$DRY" = 1 ] && echo -dry)` assignment returns the test's failure status when DRY=0 and `set -e` aborted silently (dry runs passed, which hid it). Fixed with `|| true`; verified with a stand-in `aws` command; AWS checked for leftovers (none). |
| 3 | c6a.24xlarge (planned, Zen 3, 96 vCPU, ≈ $0.57/h), fallback c6a.16xlarge, AZs a/b/c | `InsufficientInstanceCapacity` for both sizes in all three AZs (spot placement score 1/10). Cleaned up; nothing billed. |
| 4 | **m6a.24xlarge** (same EPYC 7R13 Milan, Zen 3, 96 vCPU, more RAM; placement score 3 in 1b/1c; spot $0.7706/h) | launched sa-east-1b 14:09:36 UTC, ssh 14:09:59, kit (233 MiB, zstd -19 --long) uploaded over ssh in 41 s while apt ran, setup done 14:10:47; bench 14:10:49–14:31:12; profile 14:31:21–14:41:18; terminated; security group + key deleted; **32 min wall, ≈ $0.41**. |

Safety model (as the h1 kit): temporary key pair and security group open only on tcp/22 to colossus' IP; one-time spot
request, `InstanceInterruptionBehavior=terminate`, `--instance-initiated-shutdown-behavior terminate`; a halt from boot
(user-data `shutdown -h +70`) and `shutdown -h +55` as soon as ssh answered; ssh phases capped at 40 min; an EXIT trap
that cancels the spot request, terminates the instance and waits, then deletes the SG, the key and the local .pem; every
AWS call goes through a wrapper that refuses calls without `--region sa-east-1` or naming eu-west-2. After the run:
no instance, SG or key tagged `project=rimu-h3-bench` remained.

## 3. Box and method
- m6a.24xlarge, AMD EPYC 7R13 (Zen 3), 1 socket, 48 cores / 96 threads, 2 NUMA nodes, 192 MiB L3; Ubuntu 26.04,
  kernel 7.0.0-1016-aws; network sysctls copied from colossus (rmem/wmem_max 4 MiB, defaults 212,992,
  netdev_max_backlog 1000, udp_mem as colossus), perf_event_paranoid −1, kptr_restrict 0, nmi_watchdog 0.
- **Split:** server on cores 0–23 with their SMT siblings (48 CPUs); generator (h2load-h3 image, `--network host`) on
  cores 24–47 + siblings, `-t 48` — HttpArena's half/half split (its `-t 64` on 64 generator CPUs) scaled to this box.
- **Profiles** (HttpArena's): baseline-h3 `GET /baseline2?a=1&b=1`, static-h3 (20 files, `Accept-Encoding: br;q=1,
  gzip;q=0.8`); `-c 64 -m 64 -D 5s`; generator `/etc/hosts` = `127.0.0.1 localhost` only.
- **Harness:** `.scripts/h3-bench.sh` (kit copy, diff in `kit/h3-bench.sh.diff`): per start a fresh server, 3 runs of
  5 s, best kept (as HttpArena); server CPU = cgroup (docker) or /proc (native) time from h2load start to end ÷ 2xx;
  generator CPU from its own cgroup. 7 servers × 2 profiles × 3 passes, server order rotated each pass.
- **Servers:** rimu-min (arena-h2, `ARENA_H3_HEADERS=min`: content-type only), rimu-full (content-type +
  content-length + date + server), and the HttpArena images of plod, fib, aegon, cnetmod, zix (built on colossus).
- **Profiling** (one start per server × profile, h2load `-D 12s`, window +3 s for 6 s): `perf record -F 499 -g
  --call-graph fp -C <server CPUs>` (system-wide on the server cores, so softirq and the UDP stack are included; rimu
  ran a frame-pointer + line-tables build of the same commit), `perf stat` software events and tracepoints (syscalls,
  io_uring, net, skb, udp), `/proc/net/snmp{,6}` and softnet deltas; for rimu also a hardware-counter `perf stat`, an
  LBR-attempted (fell back to fp on AMD) cycles profile and a cache-miss profile.

## 4. Results — benchmark (median of 3 passes; every spread ≤ 2 %, fib static 4 %)
| profile | server | req/s | server CPU µs/req | generator CPU µs/req | errors |
|---|---|---|---|---|---|
| baseline-h3 | zix | **5,970k** | **1.39** | 7.06 | 0 |
| baseline-h3 | rimu-min | 5,692k | 2.48 | 6.89 | 0 |
| baseline-h3 | cnetmod | 5,584k | 2.74 | 7.07 | 0 |
| baseline-h3 | rimu-full | 4,726k | 3.11 | 8.03 | 0 |
| baseline-h3 | fib | 4,561k | 5.50 | 7.11 | 0 |
| baseline-h3 | plod | 4,464k | 5.21 | 8.66 | 0 |
| baseline-h3 | aegon | 4,445k | 4.14 | 7.08 | 0 |
| static-h3 | rimu-min | **1,007k** | 30.27 | 40.28 | 0 |
| static-h3 | rimu-full | 990k | **29.76** | 41.08 | 0 |
| static-h3 | fib | 827k | 44.35 | 38.27 | 0 |
| static-h3 | cnetmod | 814k | 37.68 | 41.56 | 0 |
| static-h3 | plod | 765k | 46.34 | 42.41 | 0 |
| static-h3 | aegon | 627k | 51.34 | 34.80 | 39 (pass 2) |
| static-h3 | zix | 586k | 46.80 | 56.20 | 0 |

Composite (each profile scored against the best of plod/fib/aegon/rimu = 1000): rimu-min **2000** (#2 baseline, #1
static), rimu-full 1814, cnetmod 1789, zix 1631, fib 1623, plod 1544, aegon 1404.
rimu's transport counters: baseline 0.05 datagrams in and 0.02 (min) / 0.05 (full) packets out per request — about 50 /
20 responses per packet — ACK-only share 0 %; static 0.12 in / 11.4 out per request.

## 5. Results — profile
Software windows (UDP counters are host-wide: server + generator on the loopback):

| profile | server | srv µs/req | user % | UDP out/req | rcvbuf err (window) | ctx-sw/req | top syscalls/req |
|---|---|---|---|---|---|---|---|
| baseline-h3 | rimu-min | 2.69 | 85 | 0.032 | 0 | 0.028 | io_uring_enter 0.03 |
| baseline-h3 | zix | 1.52 | 74 | 0.046 | 0 | 0.030 | io_uring_enter 0.03 |
| baseline-h3 | cnetmod | 3.00 | 80 | 0.032 | 0 | 0.038 | io_uring_enter 0.11 |
| baseline-h3 | plod | 6.32 | 69 | 0.045 | 0 | 0.651 | io_uring_enter 0.33 |
| static-h3 | rimu-min | 30.37 | 58 | 0.503 | 1,960 | 0.197 | io_uring_enter 0.26 |
| static-h3 | cnetmod | 43.42 | 63 | 0.928 | 7,317 | 0.049 | sendmmsg 0.74 |
| static-h3 | zix | 53.75 | 49 | 3.358 | 596 | 0.069 | sendmsg 2.75 |

(all 14 rows in `data/summary.txt`)

rimu hot spots (share of server-core cycles):
- **baseline-h3, min:** RouterHandler 6.5 %, H3App 6.4 %, RequestHead::push 4.9 %, router_handler::fill_ 2.1 %,
  Uri::process 1.9 %, ResponseEncoder 1.8 %, check_field 1.8 %, memcpy 1.8 %, h2 PathParams 1.7 %, known-header lookup
  1.7 %. **full** adds qpack `encode_static_line` 7.3 % (content-length/date/server encoded per response).
- **static-h3:** kernel `kernel_init_pages` 12–13 % (pages zeroed when the kernel allocates skb memory for sends —
  every server pays it: cnetmod 10 %, aegon 6 %, zix 4 %), AES-GCM ≈ 13 % (ring vaes enc 9–10 %, seal 2.5 %, ghash
  1.2 %), `rep_movs_alternative` 2.3 %, QuicConn send path 3.5 %, write_stream_frame 1.8 %.
- **Hardware counters:**

| profile | variant | cycles/req | instructions/req | IPC | branch miss % | L1d miss % | dTLB miss/req | iTLB miss/req |
|---|---|---|---|---|---|---|---|---|
| baseline-h3 | min | 8,179 | 10,244 | 1.25 | 1.22 | 2.94 | 0.69 | 0.53 |
| baseline-h3 | full | 9,571 | 13,341 | 1.39 | 1.05 | 2.85 | 0.65 | 0.56 |
| static-h3 | min | 89,636 | 77,171 | 0.86 | 2.36 | 6.91 | 5.46 | 3.98 |
| static-h3 | full | 104,296 | 79,682 | 0.76 | 2.20 | 7.01 | 5.56 | 3.90 |

  Top-down metrics are not available on this AMD box's perf; LBR fell back to frame pointers; LLC-load-misses
  unavailable (cache-misses used).

## 6. Conclusions
1. rimu is **#1 on static-h3** (+22 % over fib, 30 µs vs 44 µs of server CPU per request) and **#2 on baseline-h3**
   with content-type-only responses, 5 % behind zix; #1 composite. All numbers repeat within 2 % across passes.
2. **Q2 (response headers):** the RFC-compliant set costs 17 % on baseline-h3 — mostly in the generator (+1.14 µs/req
   of h2load work for 44 extra header bytes), partly on the server (+0.63 µs/req, `encode_static_line`). static-h3 is
   unaffected. **User decision (9 Nov):** headers configurable; the default (library, benchmark and HttpArena) is
   content-type only, like cnetmod and zix; `set_rfc9110_headers(true)` turns on full RFC 9110 compliance (date +
   content-length). Implemented in `2e4ced7f`; write-up: `headers-ab.md` (copied here).
3. **The gap to zix is per-request framework work, not transport:** zix spends 1.39 µs of server CPU per request,
   rimu 2.48; rimu's transport is already lean (≈ 50 responses per packet, 0 % ACK-only, 0.03 io_uring_enter per
   request, same as zix), and its cycles go to the HTTP/3 request path (router, request assembly, URI/path parsing,
   field checks, response encoding). → Task 16 (perf pass 1) takes this as its first target (Ruling T16-a).
4. **static-h3 costs are kernel page zeroing and AES-GCM** — both paid by every server; rimu sends the fewest datagrams
   per request (0.50 vs cnetmod 0.93, zix 3.36: GSO trains). Candidates: fewer/larger skb allocations, MSG_ZEROCOPY
   for large bodies, AES-GCM batching (Task 18), iTLB pressure (huge pages for text). → Tasks 18/19.
5. The m6a (Zen 3) **does** expose a PMU on AWS — so future hardware-counter work can stay on the Zen 3 box with the
   benchmarks (no Intel metal phase needed).
6. RcvbufErrors appear on static-h3 for every server (host-wide counter; most likely the generator's socket at the
   4 MiB rmem_max); they did not produce h2load errors except aegon's 39.

## 7. Data in this directory
- `data/summary.txt` (the full summary the kit printed), `data/bench.jsonl` (42 rows), `data/profile.jsonl`,
  `data/host.txt` (lscpu, kernel, cmdline, sysctls, PMU probe), `data/uptime.log`, `data/perf-caps-profile.txt`,
  `data/launch.log`, `data/{setup,bench,profile}.log`, `data/raw.tar.zst` (every h2load output and server log),
  `data/profile/<server>-<profile>/<run>/` (top.txt, comm-dso.txt, stat.csv, window.txt, snapshots,
  `stacks.folded.zst` — regenerate a flamegraph with `zstd -dc stacks.folded.zst | inferno-flamegraph > f.svg`).
- `kit/`: the scripts exactly as run (launch.sh, build.sh, summarize.py, README.md, BRIEF.md, remote/run.sh,
  remote/prof-hook.sh, remote/h3-bench.sh, remote/h3-composite.py, h3-bench.sh.diff). Binaries and images are not
  committed: `kit/build.sh` rebuilds them (rimu from `bc19008d`; images from the local HttpArena builds).
- `headers-ab.md`: the Q2 write-up shown to the user.
- **Full archive** (with perf.data and SVG flamegraphs, 72 MB raw):
  `~/benchmarks-archive/rimu-h3/2026-11-09-h3-ec2-run-20261109-140921.tar.zst` (sha256 in `ARCHIVE.sha256`).

## 8. Repeat it
`cd kit && ./build.sh all && DRY=1 ./launch.sh` (prints every AWS call), then
`TYPES_A="m6a.24xlarge m6a.16xlarge c6a.24xlarge" AZS="sa-east-1b sa-east-1c sa-east-1a" ./launch.sh`. Check spot
placement scores first (`aws ec2 get-spot-placement-scores --region sa-east-1 --instance-types … --single-availability-zone`).
