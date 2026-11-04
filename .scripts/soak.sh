#!/usr/bin/env bash

# Builds a soak server and rimu-ws-soak, starts the server on CPUs 0-5,12-17 and runs the harness
# on 6-11,18-23. Exits with the harness's code.
#
#   soak.sh [soak] ARGS...  the harness with ARGS (the default mode)
#   soak.sh long ARGS...    a long run: profiles hostile, attack and storm by turns, 10-minute
#                           cycles, for SOAK_HOURS (default 2) hours; failures only, a heartbeat
#                           a minute, the trend check, a connection burst after each cycle and
#                           a 4 GiB RSS ceiling. ARGS add to or override these.
#   soak.sh fd-plain        a descriptor flood against ordinary descriptors (nofile 1024)
#   soak.sh fd-direct       a descriptor flood against a 256-slot direct descriptor table
#
# Environment:
#   SOAK_SERVER=uring|tokio  the server (default uring). tokio has no server timeouts: run it with
#                            --profile untimed.
#   SOAK_SNDBUF=BYTES        the server's SO_SNDBUF, passed to the harness too so close_linger runs
#                            (at most 32768; the long mode defaults to 16384).
#   SOAK_MALLOC=0            leaves glibc's malloc alone. By default the server runs with
#                            MALLOC_MMAP_THRESHOLD_=262144: otherwise glibc keeps hundreds of MB
#                            the server freed, which the drain's leak check reads as a leak.
# Other WTX_* variables (WTX_LOOP, WTX_DEFLATE, WTX_IDLE_MS, ...) reach the server as they are.

set -euo pipefail
cd "$(dirname "$0")/.."

mode=soak
case "${1:-}" in
soak | long | fd-plain | fd-direct)
	mode=$1
	shift
	;;
esac

server_name=${SOAK_SERVER:-uring}
case $server_name in
uring | tokio) ;;
*)
	echo "SOAK_SERVER must be uring or tokio" >&2
	exit 3
	;;
esac
cargo build -q --release -p rimu-ws-internal --bin "soak-server-$server_name" --features "soak-server-$server_name"
cargo build -q --release -p rimu-ws-soak
mkdir -p /mnt/nvme1tb/claude-tmp/soak
if ss -ltn | grep -q ':9080 '; then
	echo "port 9080 is busy" >&2
	exit 1
fi

server_env=()
if [[ ${SOAK_MALLOC:-1} != 0 ]]; then
	server_env+=(MALLOC_MMAP_THRESHOLD_=262144)
fi
harness_args=()
sndbuf=${SOAK_SNDBUF:-}
if [[ $mode == long && -z $sndbuf ]]; then
	sndbuf=16384
fi
if [[ -n $sndbuf ]]; then
	server_env+=(WTX_SNDBUF="$sndbuf")
	harness_args+=(--server-sndbuf "$sndbuf")
fi

# Flood connections are held idle, so the idle timeout is lifted for the flood modes.
flood_args=(--profile baseline --slots 20 --duration 10s --cycles 1 --warmup 5s --drain 5s)
server=(env "${server_env[@]}" "./target/release/soak-server-$server_name")
case $mode in
long)
	stamp=$(date -u +%Y%m%dT%H%M%SZ)
	set -- --profile hostile,attack,storm --slots 1000 --cycles 100000 --duration 10m \
		--warmup 30s --drain 30s --max-time "${SOAK_HOURS:-2}h" --records failures --heartbeat 60s \
		--trend 4 --rss-ceiling 4096 --burst 2000 --out "/mnt/nvme1tb/claude-tmp/soak/long-$stamp.jsonl" "$@"
	;;
fd-plain)
	server=(env WTX_DIRECT=0 WTX_IDLE_MS=60000 "${server_env[@]}" prlimit --nofile=1024:1024 "./target/release/soak-server-$server_name")
	set -- --fd-flood 1500 "${flood_args[@]}" "$@"
	;;
fd-direct)
	server=(env WTX_DIRECT=256 WTX_IDLE_MS=60000 "${server_env[@]}" "./target/release/soak-server-$server_name")
	# The table is per runtime thread: 12 threads x 256 slots, so 3500 overflows it.
	set -- --fd-flood 3500 "${flood_args[@]}" "$@"
	;;
esac

taskset -c 0-5,12-17 "${server[@]}" &
pid=$!
# The server must not outlive the script: Ctrl-C would otherwise leave it on port 9080 (a
# background job ignores SIGINT).
trap 'kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for _ in $(seq 100); do
	ss -ltn | grep -q ':9080 ' && break
	sleep 0.1
done
set +e
taskset -c 6-11,18-23 ./target/release/rimu-ws-soak run --url ws://127.0.0.1:9080/ --pid "$pid" "${harness_args[@]}" "$@"
rc=$?
exit $rc
