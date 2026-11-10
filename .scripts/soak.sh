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
#   SOAK_PROTO=ws|h2         the protocol (default ws). h2 runs soak-server-h2 (the HTTP/2 server
#                            framework) on 127.0.0.1:9081 and the harness with --proto h2, whose
#                            profiles are HTTP/2 mixes; SOAK_SERVER and SOAK_SNDBUF don't apply.
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
soak | long | fd-plain | fd-direct | h3)
	mode=$1
	shift
	;;
esac

# The HTTP/3 soak (task 23): a steady client plus the abusive QUIC/HTTP/3 clients, about ten
# minutes total. Two servers of its own (not the ws/h2 soak-server): a four-worker one for the
# steady client and most abusers, and a one-worker one for the per-worker caps (idle x 4,096,
# ruling T23-f). Each is `soak-server-h3` on UDP, dual-stack, with the library's default QUIC/H3
# limits. Environment: CERT_DIR (default arena-main's certs), DURATION (default 600s),
# SOAK_H3_CPUS (default 0-3), SOAK_H3_IDLE_CPU (default 4).
if [[ $mode == h3 ]]; then
	cert_dir=${CERT_DIR:-/mnt/nvme1tb/claude-tmp/arena-main/certs}
	duration=${DURATION:-600s}
	cpus=${SOAK_H3_CPUS:-0-3}
	idle_cpu=${SOAK_H3_IDLE_CPU:-4}
	main_port=8443
	idle_port=8444
	if [[ ! -r $cert_dir/server.crt || ! -r $cert_dir/server.key ]]; then
		echo "no server.crt/server.key in $cert_dir (set CERT_DIR)" >&2
		exit 3
	fi
	for p in $main_port $idle_port; do
		if ss -lun "sport = :$p" | grep -q ":$p"; then
			echo "UDP port $p is busy" >&2
			exit 1
		fi
	done
	cargo build -q --release -p rimu-ws-internal --bin soak-server-h3 --features soak-server-h3
	cargo build -q --release -p rimu-ws-soak
	mkdir -p /mnt/nvme1tb/claude-tmp/soak
	rel=${CARGO_TARGET_DIR:-./target}/release
	srv=$rel/soak-server-h3
	# MALLOC_MMAP_THRESHOLD_ stops glibc from keeping memory it freed (which would read as RSS
	# growth), as the ws/h2 soak server runs; SOAK_MALLOC=0 leaves malloc alone.
	malloc_env=()
	if [[ ${SOAK_MALLOC:-1} != 0 ]]; then
		malloc_env+=(MALLOC_MMAP_THRESHOLD_=262144)
	fi
	env "${malloc_env[@]}" SOAK_H3_ADDR="[::]:$main_port" SOAK_STATIC_DIR=/mnt/nvme1tb/claude-tmp/soak/h3-static \
		CERT_DIR="$cert_dir" taskset -c "$cpus" "$srv" &
	main_pid=$!
	env "${malloc_env[@]}" SOAK_H3_ADDR="[::]:$idle_port" SOAK_STATIC_DIR=/mnt/nvme1tb/claude-tmp/soak/h3-static-idle \
		CERT_DIR="$cert_dir" taskset -c "$idle_cpu" "$srv" &
	idle_pid=$!
	# The servers must not outlive the script.
	trap 'kill "$main_pid" "$idle_pid" 2>/dev/null; wait 2>/dev/null' EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	for p in $main_port $idle_port; do
		for _ in $(seq 100); do
			ss -lun "sport = :$p" | grep -q ":$p" && break
			kill -0 "$main_pid" 2>/dev/null || { echo "a server exited early" >&2; exit 5; }
			sleep 0.1
		done
	done
	sleep 0.5
	set +e
	"$rel/rimu-ws-soak" h3 \
		--url "https://127.0.0.1:$main_port" --pid "$main_pid" \
		--idle-url "https://127.0.0.1:$idle_port" --idle-pid "$idle_pid" \
		--duration "$duration" "$@"
	rc=$?
	exit $rc
fi

server_name=${SOAK_SERVER:-uring}
case $server_name in
uring | tokio) ;;
*)
	echo "SOAK_SERVER must be uring or tokio" >&2
	exit 3
	;;
esac
port=9080
url=ws://127.0.0.1:9080/
proto_args=()
case ${SOAK_PROTO:-ws} in
ws) ;;
h2)
	server_name=h2
	port=9081
	url=http://127.0.0.1:9081/
	proto_args=(--proto h2)
	;;
*)
	echo "SOAK_PROTO must be ws or h2" >&2
	exit 3
	;;
esac
cargo build -q --release -p rimu-ws-internal --bin "soak-server-$server_name" --features "soak-server-$server_name"
cargo build -q --release -p rimu-ws-soak
mkdir -p /mnt/nvme1tb/claude-tmp/soak
if ss -ltn | grep -q ":$port "; then
	echo "port $port is busy" >&2
	exit 1
fi

server_env=()
if [[ ${SOAK_MALLOC:-1} != 0 ]]; then
	server_env+=(MALLOC_MMAP_THRESHOLD_=262144)
fi
harness_args=()
sndbuf=${SOAK_SNDBUF:-}
if [[ $server_name == h2 ]]; then
	sndbuf=
elif [[ $mode == long && -z $sndbuf ]]; then
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
	ss -ltn | grep -q ":$port " && break
	sleep 0.1
done
set +e
taskset -c 6-11,18-23 ./target/release/rimu-ws-soak run --url "$url" "${proto_args[@]}" --pid "$pid" "${harness_args[@]}" "$@"
rc=$?
exit $rc
