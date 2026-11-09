#!/usr/bin/env bash

# HTTP/3 interop and impairment matrix: independent clients against arena-h2's h3 server, direct and
# through a lossy UDP proxy, on 127.0.0.1 and ::1. Correctness only: no throughput is measured.
#
#   h3-interop.sh [-b] [-c CLIENTS] [-p PATHS] [-f FAMILIES]
#
#   -b          build the client images first (needs network; otherwise they must exist)
#   -c CLIENTS  comma list of curl, ngtcp2, quic-go (default: all three)
#   -p PATHS    comma list of direct, loss1, loss5 (default: all three)
#   -f FAMILIES comma list of v4, v6 (default: both)
#
# Clients (built from pinned sources by .scripts/h3-interop/Dockerfile.*; the versions below are the
# ones in those files, ruling T21-b):
#   curl      curl 8.23.0 (tag curl-8_23_0) on ngtcp2 v1.26.0, nghttp3 v1.19.0, quictls
#             openssl-3.3.0-quic1; --http3-only        image rimu-h3-interop-curl
#   ngtcp2    the example client of ngtcp2 v1.26.0     image rimu-h3-interop-curl
#   quic-go   github.com/quic-go/quic-go v0.65.0 (http3 package), Go from golang:1.27.3-trixie
#                                                      image rimu-h3-interop-quic-go
#
# Paths between a client and the server (UDP 8443, arena-h2 with ARENA_TEST_ROUTES=1 for /echo):
#   direct    no proxy
#   loss1     udp-impair: 1% of the datagrams dropped, 0.5 ms each way
#   loss5     udp-impair: 5% dropped, 5% reordered (held 1 to 5 ms more), 5% duplicated, 0.5 ms
#
# Scenarios per cell: GET /baseline2; GET of every file under /static with Accept-Encoding br, gzip
# and identity (bytes and content-encoding checked against the file or its twin); POST of 1 MiB to
# /echo (echoed back unchanged); 1,000 sequential requests on one connection; 64 parallel
# connections of five requests each. Every request has a limit of 5 s (a stall longer than that
# fails the cell), and the cell fails on any wrong answer or connection error.
#
# Server counters (arena-h2's h3-stats on SIGUSR1) are read before and after each cell: the cell also
# fails if the server sent a STREAM frame of bytes that the client had acknowledged
# (frames_resent_acked, ruling T21-d). Losses and resends are expected under impairment and are
# only reported. The server is started once and runs on every cell; a crash fails the cell.
#
# Output: one line per cell, `cell CLIENT FAMILY PATH PASS|FAIL <seconds>s ...counters`, with the
# failing scenarios' lines under a FAIL, and a summary. Exit status 1 if any cell failed.
#
# Environment:
#   ARENA      HttpArena checkout with data/ and certs/ (default /mnt/nvme1tb/claude-tmp/arena-main)
#   ARENA_BIN  the arena-h2 binary (default $CARGO_TARGET_DIR/release/arena-h2), built with
#              `cargo build --release -p rimu-ws-internal --features arena-h2,udp-impair`
#   IMPAIR_BIN the udp-impair binary (default $CARGO_TARGET_DIR/release/udp-impair)
#   SEED       seed of the proxy (default 1)
#   PING_BUDGET  ARENA_H3_PING_BUDGET of the server (unset: the library's base of 64 PING frames a
#              second, plus 2 per smoothed RTT, ruling T21-g). Before T21-g the ngtcp2 example client
#              was closed with H3_EXCESSIVE_LOAD under loss5 at the flat 64
#   SEQ, PAR   sequential requests (1000) and parallel connections (64)
#   CELL_LIMIT seconds a cell may take before it is stopped and failed (default 240)

set -euo pipefail

arena=${ARENA:-/mnt/nvme1tb/claude-tmp/arena-main}
target=${CARGO_TARGET_DIR:-/mnt/nvme1tb/claude-tmp/target-h3}
bin=${ARENA_BIN:-$target/release/arena-h2}
impair_bin=${IMPAIR_BIN:-$target/release/udp-impair}
seed=${SEED:-1}
seq_n=${SEQ:-1000}
par_n=${PAR:-64}
cell_limit=${CELL_LIMIT:-240}
port=8443
dir=$(cd "$(dirname "$0")" && pwd)
work=${TMPDIR:-/mnt/nvme1tb/claude-tmp}/h3-interop
mkdir -p "$work"

build=0
clients=curl,ngtcp2,quic-go
paths=direct,loss1,loss5
families=v4,v6
while getopts "bc:p:f:" opt; do
	case $opt in
	b) build=1 ;;
	c) clients=$OPTARG ;;
	p) paths=$OPTARG ;;
	f) families=$OPTARG ;;
	*) exit 2 ;;
	esac
done

image_curl=rimu-h3-interop-curl
image_go=rimu-h3-interop-quic-go

if [ "$build" = 1 ]; then
	docker build -f "$dir/h3-interop/Dockerfile.curl-ngtcp2" -t "$image_curl" "$dir/h3-interop"
	docker build -f "$dir/h3-interop/Dockerfile.quic-go" -t "$image_go" "$dir/h3-interop"
fi
for image in $image_curl $image_go; do
	docker image inspect "$image" >/dev/null 2>&1 || { echo "no image $image (use -b)" >&2; exit 2; }
done
[ -x "$bin" ] || { echo "no $bin" >&2; exit 2; }
[ -x "$impair_bin" ] || { echo "no $impair_bin" >&2; exit 2; }

port_pids() {
	{
		ss -lunp "sport = :$port"
		ss -ltnp "sport = :$port"
	} | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u
}
port_busy() {
	local listeners
	listeners=$(ss -lun "sport = :$port"; ss -ltn "sport = :$port")
	[[ $listeners == *":$port"* ]]
}
if port_busy || [[ $(ss -ltn 'sport = :8082') == *":8082"* ]]; then
	echo "ports $port or 8082 are busy" >&2
	exit 3
fi

server_pid=""
impair_pid=""
log=$work/server.log
stop_impair() {
	if [ -n "$impair_pid" ]; then
		kill "$impair_pid" 2>/dev/null || true
		wait "$impair_pid" 2>/dev/null || true
		impair_pid=""
	fi
}
cleanup() {
	stop_impair
	docker rm -f h3-interop-cell >/dev/null 2>&1 || true
	if [ -n "$server_pid" ]; then
		kill "$server_pid" 2>/dev/null || true
		for _ in $(seq 1 20); do
			kill -0 "$server_pid" 2>/dev/null || break
			sleep 0.25
		done
		kill -9 "$server_pid" 2>/dev/null || true
	fi
}
trap cleanup EXIT

ping_env=()
[ -z "${PING_BUDGET:-}" ] || ping_env=(ARENA_H3_PING_BUDGET="$PING_BUDGET")
env "${ping_env[@]}" ARENA_LOG_ERRORS=1 ARENA_TEST_ROUTES=1 ARENA_H3_PIN=0 CERT_DIR=$arena/certs DATASET_PATH=$arena/data/dataset.json \
	STATIC_DIR=$arena/data/static "$bin" >"$log" 2>&1 &
server_pid=$!
for _ in $(seq 1 40); do
	port_busy && break
	kill -0 "$server_pid" 2>/dev/null || { echo "arena-h2 exited; log in $log" >&2; exit 5; }
	sleep 0.25
done
# The listener's pid, as the kernel sees it
listener=$(port_pids | head -1) || true
[ -n "$listener" ] || { echo "nothing listens on $port" >&2; exit 6; }
server_pid=$listener
sleep 0.5

# One "name=value ..." line: the sums of the h3 workers' counters, printed on SIGUSR1.
stats_line() {
	local seen now
	seen=$(grep -c '^h3-stats ' "$log" || true)
	kill -USR1 "$server_pid"
	for _ in $(seq 1 40); do
		now=$(grep -c '^h3-stats ' "$log" || true)
		if [ "$now" -gt "$seen" ]; then
			grep '^h3-stats ' "$log" | tail -1
			return
		fi
		sleep 0.05
	done
	return 1
}
# The value of counter $2 in stats line $1.
counter() {
	grep -o " $2=[0-9]*" <<<"$1" | cut -d= -f2
}

# Starts the proxy for path $1; sets target_port (the port a client uses).
start_path() {
	local params
	case $1 in
	direct)
		target_port=$port
		return
		;;
	loss1) params=(--drop 0.01 --delay-us 500) ;;
	loss5) params=(--drop 0.05 --reorder 0.05 --dup 0.05 --delay-us 500) ;;
	*) echo "unknown path $1" >&2; exit 2 ;;
	esac
	: >"$work/impair.out"
	"$impair_bin" --server-port "$port" --seed "$seed" "${params[@]}" >"$work/impair.out" 2>"$work/impair.err" &
	impair_pid=$!
	for _ in $(seq 1 40); do
		target_port=$(sed -n 's/^listening //p' "$work/impair.out")
		[ -n "$target_port" ] && return
		kill -0 "$impair_pid" 2>/dev/null || { cat "$work/impair.err" >&2; exit 7; }
		sleep 0.1
	done
	echo "udp-impair did not start" >&2
	exit 7
}

# Runs client $1 against address $2 in a container; its lines go to $work/cell.out.
run_client() {
	local client=$1 addr=$2
	local mounts=(-v "$arena/certs:/certs:ro" -v "$arena/data/static:/data/static:ro" -v "$dir/h3-interop:/driver:ro")
	local env=(-e "ADDR=$addr" -e CA=/certs/server.crt -e STATIC=/data/static -e "SEQ=$seq_n" -e "PAR=$par_n")
	docker rm -f h3-interop-cell >/dev/null 2>&1 || true
	case $client in
	curl)
		timeout "$cell_limit" docker run --rm --name h3-interop-cell --network host "${mounts[@]}" "${env[@]}" \
			"$image_curl" bash /driver/client-curl.sh >"$work/cell.out" 2>&1
		;;
	ngtcp2)
		timeout "$cell_limit" docker run --rm --name h3-interop-cell --network host "${mounts[@]}" "${env[@]}" \
			"$image_curl" bash /driver/client-ngtcp2.sh >"$work/cell.out" 2>&1
		;;
	quic-go)
		timeout "$cell_limit" docker run --rm --name h3-interop-cell --network host "${mounts[@]}" \
			"$image_go" -addr "$addr" -ca /certs/server.crt -static /data/static -seq "$seq_n" -par "$par_n" \
			>"$work/cell.out" 2>&1
		;;
	*) echo "unknown client $client" >&2; exit 2 ;;
	esac
}

cells=0
failed=0
IFS=, read -ra client_list <<<"$clients"
IFS=, read -ra path_list <<<"$paths"
IFS=, read -ra family_list <<<"$families"
for client in "${client_list[@]}"; do
	for family in "${family_list[@]}"; do
		for path in "${path_list[@]}"; do
			cells=$((cells + 1))
			case $family in
			v4) host=127.0.0.1 ;;
			v6) host='[::1]' ;;
			*) echo "unknown family $family" >&2; exit 2 ;;
			esac
			start_path "$path"
			before=$(stats_line) || before=""
			log_lines=$(wc -l <"$log")
			start=$SECONDS
			status=PASS
			if ! run_client "$client" "$host:$target_port"; then
				status=FAIL
			fi
			elapsed=$((SECONDS - start))
			stop_impair
			if ! kill -0 "$server_pid" 2>/dev/null; then
				echo "cell $client $family $path FAIL ${elapsed}s the server died; log in $log"
				exit 1
			fi
			after=$(stats_line) || after=""
			detail=""
			if [ -n "$before" ] && [ -n "$after" ]; then
				for name in requests datagrams_in packets_lost pto_probes frames_resent frames_resent_acked \
					handler_panics udp_send_errors; do
					delta=$(($(counter "$after" $name) - $(counter "$before" $name)))
					detail="$detail $name=$delta"
					if [ "$name" = frames_resent_acked ] && [ "$delta" -ne 0 ]; then
						status=FAIL
						echo "FAIL server: $delta STREAM frames carried bytes that were already acknowledged" >>"$work/cell.out"
					fi
					if [ "$name" = handler_panics ] && [ "$delta" -ne 0 ]; then
						status=FAIL
						echo "FAIL server: $delta handler panics" >>"$work/cell.out"
					fi
				done
				# Errors the server logged (ARENA_LOG_ERRORS): reported, not judged; a connection that a
				# client closed or let time out is one
				errors=$(tail -n +$((log_lines + 1)) "$log" | grep -c '^arena-h2: ' || true)
				detail="$detail server_errors=$errors"
			else
				status=FAIL
				echo "FAIL server: no h3-stats line" >>"$work/cell.out"
			fi
			echo "cell $client $family $path $status ${elapsed}s$detail"
			if [ "$status" = FAIL ]; then
				failed=$((failed + 1))
				grep -v '^ok ' "$work/cell.out" | head -20 | sed 's/^/    /'
				tail -n +$((log_lines + 1)) "$log" | grep '^arena-h2: ' | sort | uniq -c | sort -rn | head -5 | sed 's/^/    server: /' || true
			fi
			cp "$work/cell.out" "$work/last-$client-$family-$path.out"
		done
	done
done
echo "summary: $cells cells, $failed failed"
[ "$failed" -eq 0 ]
