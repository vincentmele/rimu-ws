# aws-h3: HTTP/3 benchmark and full profile of rimu-ws on EC2 spot (sa-east-1)

Runs rimu's `arena-h2` (rimu-ws bc19008d, QUIC/HTTP/3 on UDP 8443) against five HttpArena rivals (plod, fib,
aegon, cnetmod, zix) with the h3 harness of rimu-h3 (`h3-bench.sh`: h2load-h3, `-c 64 -m 64`, 3 runs of 5 s
per server start, best kept, CPU per request from h2load's start to its end), then profiles every server.
Everything is built here; the box only installs packages, takes the kit over ssh and runs.
The controller's decisions are in `BRIEF.md`. Change from the user (9 Nov): **no S3** - the kit goes over ssh.

- **Phase A, `c6a.24xlarge`** (AMD Zen 3, 48 cores / 96 vCPU; fallback `c6a.16xlarge`): the benchmark, then a
  software profile of every server. Zen 3 is colossus' microarchitecture: the rival images and our build use
  `-march=native` / `target-cpu=znver3`, so only Zen 3 runs them safely and comparably.
- **Phase B, `c7i.metal-24xl`** (Intel Sapphire Rapids bare metal, 96 vCPU; fallbacks `m7i.metal-24xl`,
  `c5.metal`): rimu's hardware counters. AWS virtual AMD boxes expose no PMU; bare metal does. **B runs only if
  A's PMU probe found no counters** (if it found them, A's rimu starts already ran the counter set).
- Phases run one after the other (the 96-vCPU spot quota holds one box). Region **sa-east-1 only** (the only
  raised spot quota); `launch.sh` refuses any AWS call without `--region sa-east-1` or naming eu-west-2
  (production runs there).

## Phase V: the variant batch of task 16 (9 Nov, rulings T16-b, T16-d)

One launch measures every perf knob of tasks 16, 17 and 19 one at a time against `base`, on the build of the
task-16 commit (`d73a785d`: request-path fast path, `ARENA_H3_*` switches, spec 2.1 counters), plus the build
before it (`prev`, `e7eca138`) for the request-path A/B, plus zix as the reference, 3 interleaved passes, with
the same harness as phase A; then the software profile (and, with a PMU, the hardware counters) of `base` and
`prev`. Box: phase A's type (`TYPES_V`, default `m6a.24xlarge c6a.24xlarge`; the first run found no c6a spot
capacity), same split, halt (+55) and 40-minute budget.

```bash
./build.sh rimu && ./build.sh prev && ./build.sh harness && ./build.sh pack   # done 9 Nov (d73a785d)
DRY=1 PHASES=V ./launch.sh
PHASES=V AZS="sa-east-1b sa-east-1c sa-east-1a" ./launch.sh
```

- **Variants** (`remote/variants.txt`; each = binary + `ARENA_H3_*` settings, table in
  `rimu-h3/wtx-internal/src/bin/arena-h2.rs`): both profiles `base`, `prev`, `gro-on`, `steer-kernel`;
  baseline-h3 only `data-fresh`, `ring512`, `flush-slot`, `balance-off`, `pin-off`; static-h3 only `arena-x2`,
  `inflight128k`, `inflight512k`, `pacing-off`, `pmtu-rtt`, `train32`, `bodies-rr` (a knob runs on the profile it
  can move). `sockbuf1m` is defined but not in the default list (the box keeps colossus' 4 MiB rmem_max /
  wmem_max, which the default already asks for). `VARIANTS="..."` picks others; `VREF=` (empty) drops zix.
- **Runtime estimate** (from the first run: one start = 3 runs of 5 s = 29 s): 22 starts per pass (16 variants
  over their profiles + zix twice) x 3 passes = 66 starts = 32 min, + the 4 profile starts (2 runs each, about
  40 s) = 3 min, + setup about 1 min: **about 36 min** of the 40-minute budget. If the budget cuts it, what is
  lost is the last profile starts (prev's): every bench row is written as it is made.
- **Output**: `results/run-*/V/out/vbench.jsonl` (one row per start, with `variant`, `binary`, `headers`,
  `knobs` - the line of settings the server printed, which proves the variant applied - and the spec 2.1
  counters: `resp_per_pkt`, `ack_only_share`, `fin_ack_share`, `streams_blocked`, `data_blocked`,
  `stream_data_blocked`, `packets_lost`, `pto_probes`, `frames_resent`), `vprofile/` and `V/summary.txt`
  (`summarize.py`: per profile and variant the median rps and server CPU/req over the passes, their change
  against base, the spread, the brief's verdict - a win is >= +1 % rps or <= -2 % CPU/req at equal rps - and
  the counters).
- Local smoke (`remote/run.sh vsmoke`: base and gro-on, one pass, -D 2s, base's profile on baseline-h3):
  plumbing passed on colossus in 70 s, nothing left behind (no numbers taken from it).

## Phase V follow-up (task 16 fix round 1, Z5)

The A/B of the completed request path (a99e6332: static-index fields, fields validated once, single-copy responses,
data reuse opt-in) against the commit the first batch measured (d73a785d): `base` = the new build, `prev` = the
build of `PREV`, both profiles, 3 passes, zix once per profile and pass: 6 starts per pass, 18 starts, about 9 min of
starts + about 1 min of setup (`VPROF=base` adds about 1.5 min of profiles; `VPROF="base prev"` about 3).

```bash
REV=a99e6332 ./build.sh rimu && PREV=d73a785d ./build.sh prev && REV=a99e6332 ./build.sh harness && ./build.sh pack
DRY=1 PHASES=V VARIANTS="base prev" VPROF=base ./launch.sh
PHASES=V VARIANTS="base prev" VPROF=base AZS="sa-east-1b sa-east-1c sa-east-1a" ./launch.sh
```

Since the fix round: `run.sh` rotates each pass by n / PASSES places (every variant moves across the whole order);
`summarize.py` marks the `prev` row "read inverted" (its loss is the newer build's win) and calls a change "within
spread" against the larger of base's and the variant's spread; `build.sh` takes `PREV=<sha>`.

## Launch

```bash
cd /mnt/nvme1tb/claude-tmp/aws-h3
DRY=1 ./launch.sh          # prints every AWS call / ssh / rsync in order, makes none (build/dry-run.txt)
./launch.sh                # PHASES=AB: A, then B if A's box had no PMU
```

The log goes to `results/run-<UTC time>/launch.log` (and the terminal). Overrides:

| variable | default | meaning |
|---|---|---|
| `PHASES` | `AB` | `A`, `B` (B alone, unconditionally), `AB` or `V` (the variant batch, alone) |
| `FORCE_B` | `0` | `1`: run B after A even if A had counters |
| `TYPES_A` | `c6a.24xlarge c6a.16xlarge` | tried in order, each in every AZ |
| `TYPES_B` | `c7i.metal-24xl m7i.metal-24xl c5.metal` | same |
| `TYPES_V` | `m6a.24xlarge c6a.24xlarge` | same, for phase V |
| `VARIANTS` | the default list of `remote/variants.txt` | phase V's rimu variants |
| `VREF` | `zix` | phase V's reference server (empty: none) |
| `VPROF` | `base prev` | phase V's variants profiled after the bench |
| `AZS` | `sa-east-1a sa-east-1b sa-east-1c` | tried in order on a capacity, price, quota or "unsupported" error |
| `PASSES` | `3` | bench passes |
| `SERVERS` | `rimu-full rimu-min plod fib aegon cnetmod zix` | bench / profile servers (`rimu-*` = `ARENA_H3_HEADERS`) |
| `PROFILES` | `baseline-h3 static-h3` | |
| `PROF_RESERVE` | `8` | minutes of A's 40-minute budget kept for the profile when the bench starts |

Before launching: `aws sts get-caller-identity` must work (the script checks it first and stops before creating
anything). The credentials must outlive the run (about 1.5 h for AB): the EXIT trap needs them to terminate.

## Safety (as the h1 kit, `/mnt/nvme1tb/claude-tmp/aws-d3/launch.sh`)

- `aws sts get-caller-identity` first; read-only preflight: default VPC, spot quota (L-34B43A08), spot prices.
- A temporary ed25519 key pair and a security group open only on tcp/22 to this machine's IP.
- A one-time spot request (`InstanceInterruptionBehavior=terminate`), `--instance-initiated-shutdown-behavior
  terminate`, root volume 40 GB gp3 (3000 IOPS, 250 MB/s, deleted on termination), IMDSv2 only.
- The box halts (= terminates) itself: user-data `shutdown -h +70` (A) / `+50` (B) at boot, in case ssh never
  answers; replaced by `shutdown -h +55` (A) / `+35` (B) as soon as ssh answers.
- ssh phases are cut 40 min (A) / 20 min (B) after ssh answers: each remote phase runs under `systemd-run` with
  `RuntimeMaxSec` = the time left (so an ssh drop does not stop it; launch.sh re-attaches to its log), and is
  stopped at the limit.
- EXIT trap (success, failure, Ctrl-C): cancel the spot request, terminate the instance and wait until it is
  terminated, delete the security group (retried while the ENI detaches), the key pair, the local `.pem` and the
  ssh control socket. Between A and B the instance is terminated and waited for; the SG and key are reused.
- Everything is named and tagged `Name=rimuh3-<epoch>`, `project=rimu-h3-bench` (instance also `phase=A|B`;
  volume and spot request tagged too).

## The kit and its transfer (`build.sh`, parts in `parts/`)

`./build.sh all` (or one step: `rimu`, `inferno`, `images`, `data`, `harness`, `pack`) builds:

| part | contents | phase |
|---|---|---|
| `kit-common.tgz` (1.9 MiB, gzip so the box can open it before zstd is sure to be there) | `run.sh`, `h3-bench.sh`, `h3-composite.py`, `prof-hook.sh`, inferno (`inferno-collapse-perf`, `inferno-flamegraph`), arena certs, `dataset.json`, `static/`, `requests/`, `hosts-v4` | A, B |
| `kit-rimu-a.tar.zst` (4.2 MiB) | `bin/znver3/arena-h2` (release, `-C target-cpu=znver3`) and `bin/znver3-prof/arena-h2` (profile `profiling` = release + line tables, `-C force-frame-pointers=yes`, znver3) | A |
| `kit-rimu-b.tar.zst` (3.6 MiB) | `bin/v3-prof/arena-h2` (the same profiling build for `-C target-cpu=x86-64-v3`) | B |
| `kit-img-h2load-h3.tar.zst` (39.4 MiB) | `httparena-h2load-h3:latest` (the generator) | A, B |
| `kit-img-{zix,fib,plod,cnetmod,aegon}.tar.zst` (3.1, 5.2, 27.5, 36.2, 115.6 MiB) | `httparena-<name>:latest` (the tags `h3-bench.sh` runs; zix = `frameworks/zix-http3`) | A |

All rimu builds are from `/mnt/nvme1tb/claude-tmp/rimu-h3` at bc19008d (read-only, `--locked`, toolchain
nightly-2026-10-12, own target dirs `/mnt/nvme1tb/claude-tmp/target-aws-h3/*`). Shipped binaries need only glibc
(>= 2.34) and libgcc_s (`build/ldd.txt`); the AMI is Ubuntu 26.04 like colossus. Image IDs: `images.txt`;
sha256 of every part: `parts/kit.sha256`; sizes and upload times: `parts/SIZES`. Images and rimu parts are
`zstd -19 --long=27` (measured on the generator image: 169 MB -> 41.3 MB in 49 s; `-12` gave 49.4 MB, `-22` 40.5 MB
in 150 s). The harness diff against bc19008d is `build/h3-bench.sh.diff` (CPU lists, `-t`, hosts file and a
per-run hook made overridable; nothing else changed).

**Upload** (over ssh from colossus; the real rate was not measured, no AWS resource was used for it):

| phase | bytes | at 50 Mbit/s | at 200 Mbit/s |
|---|---|---|---|
| A | 233.0 MiB | 39 s | 10 s |
| B | 44.8 MiB | 8 s | 2 s |

How the box overlaps it: as soon as ssh answers, one ssh command sets the halt, stops the apt timers and starts
`apt-get install docker.io zstd rsync linux-tools-common linux-tools-$(uname -r)` under `systemd-run` (falling back
to `linux-tools-aws`). `kit-common.tgz` goes first; it is unpacked and `run.sh setup` starts (also under
systemd-run). The other parts follow with `rsync --partial-dir=.rsync-partial --timeout=60` (a dropped connection
resumes from the partial file; up to 5 tries per part; a part only appears under its name when complete; if the
AMI had no rsync, scp to a temporary name instead, restarting a part on a drop), in the order rimu, generator,
zix, fib, plod, cnetmod, aegon. After each part launch.sh touches `dl/<part>.done`; `run.sh
setup` waits for apt, applies the tuning, writes `host.txt`, then takes each part as its marker appears: sha256
check, then unpack or `zstd -dc --long=27 | docker load`. `setup.ok` ends it.

## What runs on the box (`remote/run.sh`, as root)

Host tuning (`tune`): colossus' network sysctls (`net.core.rmem_max = wmem_max = 4194304`, `rmem_default =
wmem_default = 212992`, `netdev_max_backlog = 1000`, `net.ipv4.udp_mem = 1534386 2045850 3068772`),
`kernel.perf_event_paranoid=-1`, `kernel.kptr_restrict=0`, `kernel.io_uring_disabled=0` if it is not already
(colossus: 0), `kernel.nmi_watchdog=0` (frees a PMU counter), apt/snap/motd timers stopped, `ulimit -n 1048576
-l unlimited`. CPU split from `lscpu -p`: whole cores with their SMT siblings sorted by node/socket/core, the first
half to the server, the second to the generator, `h2load -t` = generator CPU count (c6a.24xlarge: 48 + 48, `-t 48`;
HttpArena runs `-t 64` on 64 CPUs). Override with `SCPU` / `LCPU` / `LOAD_THREADS` in run.sh's environment.

`host.txt`: IMDS instance type / AZ / lifecycle, `uptime`, `uname -r`, the PMU probe (`perf stat -e
cycles,instructions -- true`) and `pmu=yes|no`, perf version, sysctls, ulimits, docker and image IDs, binary
revisions, `free`, `lscpu`, `lscpu -e`.

**Phase A, bench** (`run.sh bench`): 7 servers (`rimu-full` = `ARENA_H3_HEADERS=full`, `rimu-min`, plod, fib,
aegon, cnetmod, zix) x baseline-h3, static-h3 x 3 passes; per pass and profile the server order is rotated by the
pass (as `run-t15-first.sh`). Each start is `h3-bench.sh` unchanged in method: fresh server (rimu native, rivals in
docker, host network, `--cpuset-cpus`), readiness by the generator itself, 3 runs of 5 s, best kept, server CPU
from its cgroup / `/proc/PID/stat` over h2load's own span, IPv4-only hosts for the generator, rimu's datagram
counters by SIGUSR1. A start that fails or serves nothing (rps 0) is retried once, then recorded
`"failed":true`. Rows stream to `out/bench.jsonl` (the harness line plus `label`, `pass`, `try`, `ts`); every
start's h2load outputs and server log go to `out/raw/bench/<label>-<profile>-p<pass>/`; `uptime` before every
start to `out/uptime.log`. Fetched as soon as the bench ends, before profiling (a spot reclaim then loses only
the profiles).

**Phase A, profile** (`run.sh profile`, rimu first, then the rivals): one start per server and profile, rimu
on the profiling build, h2load with the profile's arguments and `-D 12s`; at the run's go `prof-hook.sh` sleeps
3 s and records a 6 s window:

- `perf record -F 499 -e <cycles, or cpu-clock without PMU> -g --call-graph fp -C <server CPUs>` (system-wide on the
  server CPUs: softirq / UDP stack work included; rivals in their containers; the reports run while the container
  is still up so perf resolves their binaries);
- `perf stat -x, -C <server CPUs> -e task-clock,context-switches,cpu-migrations,page-faults,duration_time` plus every
  tracepoint of this list that the box has (probed first, `out/perf-caps-profile.txt`): `syscalls:sys_enter_` +
  io_uring_enter, sendmsg, recvmsg, sendmmsg, recvmmsg, sendto, recvfrom, epoll_wait, epoll_pwait, epoll_pwait2,
  futex, read, write, writev; `io_uring:io_uring_submit_req` (or `_submit_sqe`), `io_uring_complete`,
  `io_uring_task_add`; `net:net_dev_xmit`, `netif_receive_skb`, `netif_rx`; `skb:kfree_skb`;
  `udp:udp_fail_queue_rcv_skb`;
- before/after snapshots (`snap-a.txt`, `snap-b.txt`, difference `window.txt`): rimu's h3 counters by SIGUSR1
  (exact requests in the window), the server's user/system CPU (`/proc/PID/stat` or cgroup `cpu.stat`), `/proc/net/snmp`
  and `snmp6` UDP counters (InDatagrams, OutDatagrams, RcvbufErrors, SndbufErrors, InErrors, ...), `softnet_stat`
  (processed, dropped, time_squeeze), the server CPUs' `/proc/stat` split;
- then `perf report --stdio --no-children -g none --sort dso,sym --percent-limit 0.3` -> `top.txt`, `--sort comm,dso`
  -> `comm-dso.txt`, `perf script | inferno-collapse-perf` -> `stacks.folded.zst`, `inferno-flamegraph` ->
  `flame.svg`. rimu's `perf.data` is kept (`perf record -z`) with `buildids.txt`; rivals' is deleted.
  `out/kallsyms.zst` holds the box's kernel symbols for re-analysis (`perf report --kallsyms=...`; rimu's binaries
  are in `remote/bin/`).

If the PMU probe found counters, rimu's profile starts run 5 h2load runs instead of 1 (`sw` then phase B's four
windows below) and phase B is skipped.

**Phase B, hw** (`run.sh hw`, `bin/v3-prof`): rimu-full and rimu-min x both profiles, one start each with four
12 s runs, each with its own 6 s window from +3 s (separate runs, so the PMU is not shared between the sets):

1. `hwstat`: `perf stat -x, -C <server CPUs> -e cycles,instructions,branches,branch-misses,cache-references,
   cache-misses,L1-dcache-loads,L1-dcache-load-misses,LLC-loads,LLC-load-misses,dTLB-load-misses,iTLB-load-misses,duration_time`
   (events the box lacks are dropped; multiplexing is scaled by perf);
2. `topdown`: the first of `-M TopdownL1,TopdownL2`, `--topdown --td-level 2`, `--topdown`, `-M TopdownL1`,
   `-M PipelineL1,PipelineL2`, `-M PipelineL1` that works here;
3. `lbr`: `perf record -e cycles -F 999 --call-graph lbr -C <server CPUs>` (fp if LBR is refused) -> flamegraph by
   cycles, top symbols;
4. `cachemiss`: `perf record -e LLC-load-misses` (or `cache-misses`) `-F 999` -> top symbols.

Per-request figures divide each count by (requests/s over the window x the counter's own `duration_time`); the
request rate is rimu's exact counter delta (rivals in phase A: the run's h2load rps, marked `~`).

## Runtime and cost

Per-start overhead measured in the local smoke (2.5 s per start plus about 0.5 s per generator container start;
profile post-processing grows with the samples):

| | phase A (c6a.24xlarge) | phase B (c7i.metal-24xl) |
|---|---|---|
| launch until ssh | 1.5-3 min | 5-10 min (bare metal boots slowly) |
| setup (apt, upload, docker load, overlapped) | 2-3 min | about 2 min |
| bench: 42 starts x ~25 s | 18-22 min | - |
| profile: 14 starts x ~30 s (+ ~6 min if the box has a PMU) | 7 min | - |
| hw: 4 starts x 4 windows, ~2 min a start | - | about 8 min |
| fetches, terminate and wait | 2-3 min | 3-6 min |
| **billed, expected** | **32-38 min** | **20-28 min** |
| hard limits | ssh phases 40 min; self-halt 55 min after ssh (70 after boot) | 20 min; 35 (50) |
| spot (brief: ~$0.57/h, ~$0.66/h) | **~$0.35** | **~$0.30** |
| worst case: on-demand cap for the whole self-halt window | $5.66/h x ~1.0 h = **~$5.7** (if ssh never answers: 1.2 h, ~$6.8) | $6.60/h x ~0.8 h = **~$5.5** (m7i.metal-24xl $7.71/h: ~$6.4) |

On-demand prices are sa-east-1 Linux from the AWS price list (c6a.16xlarge $3.77/h, c5.metal $6.29/h). EBS
(40 GB gp3 for under an hour per box) and the fetch egress (a few hundred MB at ~$0.15/GB) add about $0.05-0.10.
Expected total for AB: about $0.65-0.75.

## Output

```
results/run-<UTC time>/launch.log
results/run-<UTC time>/A/{setup,bench,profile}.log  summary.txt
results/run-<UTC time>/A/out/host.txt  bench.jsonl  profile.jsonl  uptime.log  perf-caps-profile.txt  kallsyms.zst
                       out/raw/{bench,profile}/<label>-<profile>-p<pass>/   (h2load outputs per try and run, server log)
                       out/profile/<label>-<profile>/run<N>-<kind>/         (window.txt, snap-*.txt, stat.csv, top.txt,
                                                                             comm-dso.txt, stacks.folded.zst, flame.svg,
                                                                             rimu: perf.data, buildids.txt)
results/run-<UTC time>/B/{setup,hw}.log  summary.txt  out/{host.txt,hw.jsonl,perf-caps-hw.txt,raw/hw/...,hw/...}
```

`python3 -I summarize.py results/run-*/A/out` (run by launch.sh into `summary.txt`) prints the composite and the
CPU table of `h3-composite.py` (median of the starts), the rps of every start by pass, the profile windows (request
rate, CPU per request and user share, softirq share of the server cores, UDP datagrams per request and errors,
context switches and syscalls per request, tracepoints per request, top symbols) and the hardware windows (cycles,
instructions and IPC per request, miss ratios, top-down metrics, top cycle and cache-miss symbols).
`python3 -I remote/h3-composite.py [--cpu] results/run-*/A/out/bench.jsonl` works directly too.

## Manual cleanup (if colossus dies mid-run)

The instance terminates itself (self-halt; root volume deleted with it). The security group and key pair
(`rimuh3-<epoch>`, free) stay. Everything carries `project=rimu-h3-bench`, all in **sa-east-1**:

```bash
R=sa-east-1; F=Name=tag:project,Values=rimu-h3-bench
aws ec2 describe-instances --region $R --filters $F Name=instance-state-name,Values=pending,running,stopping \
  --query 'Reservations[].Instances[].[InstanceId,State.Name,Tags[?Key==`Name`]|[0].Value]' --output text
aws ec2 terminate-instances --region $R --instance-ids i-...        # only if one is still running
aws ec2 describe-spot-instance-requests --region $R --filters $F Name=state,Values=open,active \
  --query 'SpotInstanceRequests[].SpotInstanceRequestId' --output text   # cancel-spot-instance-requests if any
aws ec2 describe-security-groups --region $R --filters $F --query 'SecurityGroups[].[GroupId,GroupName]' --output text
aws ec2 delete-security-group --region $R --group-id sg-...
aws ec2 describe-key-pairs --region $R --filters $F --query 'KeyPairs[].KeyName' --output text
aws ec2 delete-key-pair --region $R --key-name rimuh3-<epoch>
rm -f /mnt/nvme1tb/claude-tmp/aws-h3/rimuh3-*.pem /mnt/nvme1tb/claude-tmp/aws-h3/.cm-*
```

## Local validation (9 Nov)

- `bash -n` and shellcheck (koalaman/shellcheck:stable, `-x`) clean on build.sh, launch.sh, remote/run.sh,
  remote/prof-hook.sh, remote/h3-bench.sh; `python3 -I` runs summarize.py and h3-composite.py.
- `./build.sh all` completes; `parts/SIZES`, `parts/kit.sha256`, `build/ldd.txt`.
- Transfer pieces checked locally: the per-phase sha256 subset, `rsync --partial-dir` resuming after a dropped
  remote shell (only the missing bytes sent, sha256 equal), `zstd -dc --long=27 | tar -x`, `| docker load`.
- Smoke: `OUT=... WORK=... remote/run.sh smoke` (SMOKE=1: one pass, rimu-full and fib, `-D 2s`, one run per start,
  4 s profile runs with a 2 s window at -F 99, colossus' own split 0-5,12-17 / 6-11,18-23) in `results/smoke-*`:
  bench rows, perf record/stat, the counter windows (colossus has a PMU: hwstat ran, top-down was skipped as Zen 3
  has no top-down metrics, LBR fell back to fp, cache-misses replaced LLC-load-misses), inferno, the summary and
  the fetch layout all worked, and no listener or container was left. Its numbers are not results (shared box,
  2 s runs); fib's symbols are unresolved locally only because perf ran as a user (root on the box).
- `DRY=1 ./launch.sh` -> `build/dry-run.txt`.

## Caveats

- UDP counters in `window.txt` are host-wide (loopback: server and generator both count).
- Rivals' per-request figures in the profile use the run's h2load rps, not an exact count over the window.
- Phase B runs on Intel with an x86-64-v3 build: its cycle counts are not Zen 3's; use it for where the cycles go
  (IPC, misses, top-down, hot symbols), and phase A for the comparison with the rivals.
- The generator shares the box with the server (as on HttpArena), on its own half of the cores.
- `httparena-cnetmod` and `httparena-h2load-h3` share one Ubuntu base layer, uploaded twice (~28 MB).
