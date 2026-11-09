# aws-h3 kit brief (from the controller)

Build, and validate locally, a kit that runs the HTTP/3 benchmarks and a full profile on AWS EC2 spot instances,
so that no EC2 time is spent on building, uploading or debugging. **Do not launch any EC2 instance** — the controller
launches after reviewing the kit. Everything lives in `/mnt/nvme1tb/claude-tmp/aws-h3/`.

## Why EC2, and the user's instructions
The user: "instead of running the benchmarks on colossus, use aws ec2 instance. Prepare the script and programs before
spinning up the instance so as to not waste EC2 time. Use spot instance on the cheapest appropriate configuration in
regions we're already approved in." and "do full profiling on the ec2 instance also".

## Decided by the controller (binding)
- **Region sa-east-1 only.** It is the only region with a raised spot quota (96 standard vCPUs; every other region is
  at 32; us-east-1's raise is on-demand only). Never use eu-west-2: the same AWS account runs a live production
  trading system there (xtrader). Never touch, list-and-modify, or delete any resource you did not create in this run.
- **Phase A — benchmarks + software profiling: `c6a.24xlarge`** (AMD Zen 3 Milan, 48 cores / 96 vCPU, spot ≈ $0.57/h).
  Zen 3 is colossus' microarchitecture, and the rival images (plod, aegon, cnetmod…) and our entry were built on
  colossus with `-march=native` / `target-cpu=native`, so only a Zen 3 box runs them safely and representatively
  (HttpArena builds its images on the benchmark machine). Fallback type: `c6a.16xlarge` (32 cores / 64 vCPU). AZ order:
  sa-east-1a, then b, then c, on a capacity/price error.
- **Phase B — hardware-counter profiling of rimu only: `c7i.metal-24xl`** (Intel Sapphire Rapids, bare metal, 96 vCPU,
  spot ≈ $0.66/h). AWS virtual AMD instances expose no PMU (the c6a.8xlarge of the earlier h1 run had none; AWS's
  Graviton perf runbook lists AMD 5a/6a/7a as unsupported); bare metal always has it, and AMD bare metal is 192 vCPU,
  over the quota. Phase B runs only rimu (built for x86-64-v3, portable to Intel) and the h2load-h3 generator image
  (built without CPU-specific flags). Fallback types: `m7i.metal-24xl`, then `c5.metal`. **Phase B runs only if phase
  A's PMU probe found no hardware counters** (if the c6a has them, phase A also does the hardware-counter work).
- Phases run one after the other (the quota cannot hold both boxes).
- AMI: Ubuntu 26.04 via SSM (`/aws/service/canonical/ubuntu/server/26.04/stable/current/amd64/hvm/ebs-gp3/ami-id`),
  like the h1 kit — colossus is Ubuntu 26.04 / glibc 2.43, so native binaries built here run there (check with `ldd`
  and ship any non-glibc library, as the h1 kit shipped liburing). Root volume 40 GB gp3 (3000 IOPS, 250 MB/s).
- **SUPERSEDED (user, 9 Nov): no S3 — transfer the kit over ssh (scp/rsync), overlapped with box setup.** The rest of this bullet is void.
  `rimuh3-kit-<epoch>` in sa-east-1 with public access blocked, the kit parts uploaded with `aws s3 cp`, presigned GET
  URLs (`aws s3 presign --expires-in 10800`) passed to the box over ssh; the box downloads with `curl -fsS` (same-region
  transfer, no IAM role needed). The bucket and its objects are deleted in the EXIT trap.
- Safety exactly like `/mnt/nvme1tb/claude-tmp/aws-d3/launch.sh` (read it and reuse it): `aws sts get-caller-identity`
  first, a temporary key pair and a security group open only on tcp/22 to this machine's IP, a one-time spot request
  with `InstanceInterruptionBehavior=terminate`, `--instance-initiated-shutdown-behavior terminate`,
  `sudo shutdown -h +N` as soon as ssh answers (A: +55, B: +35), ssh phases cut by `timeout` (A: 40 min, B: 20 min),
  and an EXIT trap that terminates the instance and waits, deletes the SG, the key pair, the local .pem and the S3
  bucket — on success, failure and Ctrl-C. Tag everything `Name=rimuh3-<epoch>` and `project=rimu-h3-bench`.
- Host tuning on the box: replicate colossus' network sysctls so EC2 numbers are comparable with colossus runs
  (net.core.rmem_max = wmem_max = 4194304, rmem_default = wmem_default = 212992, netdev_max_backlog = 1000,
  net.ipv4.udp_mem = 1534386 2045850 3068772), raise ulimit -n / -l, stop apt/snap timers (as the h1 kit's run.sh), and
  for profiling `kernel.perf_event_paranoid=-1`, `kernel.kptr_restrict=0`. Install `docker.io`, `zstd`,
  `linux-tools-common linux-tools-$(uname -r)` with apt (regional mirrors are fast).

## What to build (build.sh, on colossus, before launch)
1. rimu `arena-h2`, release, from `/mnt/nvme1tb/claude-tmp/rimu-h3` at `bc19008d`, `RUSTFLAGS="-C target-cpu=znver3"`
   (the recipe: `cargo build --release -p rimu-ws-internal --bin arena-h2 --features arena-h2`, toolchain
   nightly-2026-10-12; use your own `CARGO_TARGET_DIR` under /mnt/nvme1tb/claude-tmp, e.g. `target-aws-h3`).
2. rimu `arena-h2` **profiling** builds: same, with frame pointers and debug line tables (`-C force-frame-pointers=yes`
   plus the repo's `profiling` profile or `CARGO_PROFILE_RELEASE_DEBUG=line-tables-only`): one `target-cpu=znver3`
   (phase A) and one `target-cpu=x86-64-v3` (phase B).
3. Docker images, saved and zstd-compressed: `httparena-h2load-h3`, `httparena-plod`, `httparena-fib`,
   `httparena-aegon`, `httparena-cnetmod`, `httparena-zix` (check which tag `.scripts/h3-bench.sh` runs for each). Phase B
   needs only the generator image — split the kit so phase B downloads only what it needs.
4. Flamegraph tools: `inferno` (`cargo install inferno --root /mnt/nvme1tb/claude-tmp/aws-bin/inferno`), shipped as
   binaries.
5. The arena data: `/mnt/nvme1tb/claude-tmp/arena-main/{certs,data,requests}` (read-only source; copy) and the
   generator's IPv4-only hosts file the bench script uses.
6. The bench harness: copy `/mnt/nvme1tb/claude-tmp/rimu-h3/.scripts/h3-bench.sh` and `.scripts/h3-composite.py` (at
   bc19008d) into the kit and make the CPU split, generator threads, arena path and binary path overridable by
   environment (today: server 0-5,12-17, generator 6-11,18-23, `-t 12`). On the box derive them from `lscpu -p`: whole
   cores with their SMT siblings, server on the first half, generator on the second half, `-t` = generator CPU count
   (HttpArena runs -t 64 on its 64 generator CPUs). Keep everything else the harness does (3 runs of 5 s per start, best
   kept; cgroup/proc CPU accounting from h2load start to end; IPv4 hosts for the generator; EndpointStats via SIGUSR1 for
   rimu).

## What runs on the box (remote/run.sh)
- **Phase A, bench:** servers `rimu-full` (ARENA_H3_HEADERS=full), `rimu-min` (ARENA_H3_HEADERS=min), plod, fib, aegon,
  cnetmod, zix × profiles baseline-h3, static-h3 × 3 passes, interleaved (rotate the server order each pass, as
  `/mnt/nvme1tb/claude-tmp/h3bench/run-t15-first.sh` / `run-t15-ab.sh` do — read them). Stream JSONL rows; fetch after the
  bench phase before profiling starts (a spot reclaim later loses only the profiles). Record `uptime`, `lscpu`,
  `uname -r` and the PMU probe (`perf stat -e cycles,instructions -- true`) in host.txt.
- **Phase A, software profile** (each server, each profile, one start): h2load-h3 with the profile's arguments but
  `-D 12s`; from +3 s to +9 s, concurrently:
  - `perf record -F 499 -g --call-graph fp -C <server CPUs> -o …` (system-wide on the server CPUs so softirq/UDP stack
    work is included; rimu runs the profiling build natively; rivals run in their containers — let perf record finish
    while the container is alive so the build-id cache gets their binaries);
  - `perf stat -C <server CPUs>` with task-clock, context-switches, cpu-migrations, page-faults and tracepoints: syscalls
    (io_uring_enter, sendmsg, recvmsg, sendmmsg, recvmmsg, epoll_wait, …), io_uring:io_uring_submit_req /
    io_uring_complete, net:net_dev_xmit, net:netif_receive_skb — list what exists on the box first and degrade
    gracefully;
  - `/proc/net/snmp` and `/proc/net/snmp6` UDP counters (InDatagrams, OutDatagrams, RcvbufErrors, SndbufErrors,
    InErrors) and `/proc/net/softnet_stat` deltas; the server's user vs system CPU split; for rimu the EndpointStats
    delta (exact requests in the window).
  - Then: `perf script | inferno-collapse-perf` → `.folded` and `inferno-flamegraph` → `.svg`; `perf report --stdio
    --no-children --sort dso,sym --percent-limit 0.3` → top.txt; a comm/dso split. Keep rimu's perf.data compressed
    (`perf record -z` or zstd afterwards) for local re-analysis; do not keep rivals' perf.data (size).
  - If the PMU probe found hardware counters, also run phase B's counter set here (and phase B is skipped).
- **Phase B (Intel metal), hardware counters, rimu-full and rimu-min × both profiles**, same window method:
  `perf stat -C <server CPUs> -e cycles,instructions,branches,branch-misses,cache-references,cache-misses,
  L1-dcache-loads,L1-dcache-load-misses,LLC-loads,LLC-load-misses,dTLB-load-misses,iTLB-load-misses`; top-down
  (`perf stat -M TopdownL1` and `TopdownL2`, or `--topdown --td-level 2`, whichever the box's perf supports);
  `perf record -e cycles -F 999 --call-graph lbr -C <server CPUs>` → flamegraph by cycles; a cache-miss sampling run
  (`-e cache-misses` or `LLC-load-misses`) → top symbols. Per-request figures (cycles/req, instructions/req, IPC) use the
  EndpointStats request delta of the window.
- Every run checks h2load's 2xx > 0 and errors; a failed start is retried once and then recorded as failed (never loop).

## Local validation before handing back (required)
1. `bash -n` and `shellcheck` on every script; `python3 -I` on the summarizers.
2. `build.sh all` completes; `kit-*.tgz` sizes and sha256 recorded; `ldd` of every shipped native binary.
3. **Smoke run of remote/run.sh on colossus** in a `SMOKE=1` mode: one pass, `rimu-full` and `fib`, `-D 2s`, one run per
   start, a 2 s profile window at `-F 99` — this validates the plumbing (bench rows, perf record/stat, inferno, the
   fetch layout), it is not a benchmark: report no numbers from it. It must take under 5 minutes, start nothing else
   heavy, and leave no server, container or listener behind (kill by PID from `ss -lunp`/`ss -ltnp`, never `pkill -f`;
   stop only containers you started). Do not run it while any other benchmark or test process runs on colossus.
4. **S3 round trip** (the only AWS resources you may create): make a test bucket in sa-east-1 with public access
   blocked, upload a small file, presign it, `curl` it back and compare sha256, delete the object and the bucket.
   Record the measured upload rate for one real kit part (time `aws s3 cp` of the generator image archive, then delete).
5. `launch.sh` with `DRY=1`: prints every AWS call it would make, in order, without making any.
6. A README.md: how to launch (`PHASES=A|B|AB`, overrides), what runs, expected runtime per phase, cost estimate
   (spot prices above, worst case = on-demand cap for the full self-halt window), what is fetched where, and how to clean
   up by hand if colossus dies mid-run (tags, names).

## Constraints
- Never launch EC2. Never push anything. Never `git stash` / `git worktree add`; do not modify `/mnt/nvme1tb/claude-tmp/rimu-h3`
  (copy files out of it; build from it read-only — `cargo build` with your own target dir is fine).
- Never run system_tune or change colossus' sysctls. Builds use `nice`. Temp files under /mnt/nvme1tb/claude-tmp.
- Rival images are untrusted: run them only in docker (as h3-bench.sh does), locally and on the box.
- Report back with: status, kit files and sizes, smoke result (plumbing ok/not, no numbers), S3 round-trip result and
  upload rate, DRY=1 output summary, estimated runtime and cost per phase, and any concern.
