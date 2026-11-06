#!/usr/bin/env bash

# One HttpArena HTTP/2 profile against one server, the way HttpArena runs it, scaled to colossus.
#
#   h2-bench.sh SERVER PROFILE CONNS
#
#   SERVER   rimu (the native arena-h2 binary) or plod | viltrum | aegon (docker images
#            httparena-<name>, built from HttpArena's frameworks/<name>)
#   PROFILE  baseline-h2 | static-h2 | baseline-h2c | json-h2c
#   CONNS    h2load -c
#
# The server runs on CPUs 0-5,12-17 and h2load (image httparena-h2load, nghttp2 1.59 as on the
# official box) on 6-11,18-23 with -t 12. A fresh server serves 3 runs of 5 s; the best is kept, as
# HttpArena does. Prints one JSON line.
#
# Environment:
#   ARENA      HttpArena checkout with data/, certs/ and requests/
#              (default /mnt/nvme1tb/claude-tmp/arena-main)
#   ARENA_BIN  the arena-h2 binary (default $CARGO_TARGET_DIR/release/arena-h2)
#   RUNS       runs per server start (default 3)
#   DURATION   h2load -D (default 5s)
#   ARENA_PARAMS  passed to arena-h2 (permissive = upstream wtx-http2's settings)

set -euo pipefail

server=${1:?SERVER}
profile=${2:?PROFILE}
conns=${3:?CONNS}
arena=${ARENA:-/mnt/nvme1tb/claude-tmp/arena-main}
target=${CARGO_TARGET_DIR:-/mnt/nvme1tb/claude-tmp/target-h2}
bin=${ARENA_BIN:-$target/release/arena-h2}
runs=${RUNS:-3}
duration=${DURATION:-5s}
server_cpus=0-5,12-17
load_cpus=6-11,18-23
load_threads=12
work=${TMPDIR:-/mnt/nvme1tb/claude-tmp}/h2bench
mkdir -p "$work"

case $profile in
baseline-h2)
	port=8443
	args=("https://localhost:8443/baseline2?a=1&b=1" -m 100)
	;;
static-h2)
	port=8443
	args=(-i /requests/static-h2-uris.txt -H "Accept-Encoding: br;q=1, gzip;q=0.8" -m 32)
	;;
baseline-h2c)
	port=8082
	args=("http://localhost:8082/baseline2?a=1&b=1" -p h2c -m 100)
	;;
json-h2c)
	port=8082
	args=(-i /requests/json-h2c-uris.txt -p h2c -m 32)
	;;
*)
	echo "unknown profile $profile" >&2
	exit 2
	;;
esac

port_pids() {
	ss -ltnp "sport = :$1" | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u
}

# A server from an earlier run may still be closing (a graceful drain keeps the listeners open):
# give it 10 s before calling the port busy.
for p in 8082 8443; do
	for _ in $(seq 1 20); do
		ss -ltn | grep -q ":$p " || break
		sleep 0.5
	done
	if ss -ltn | grep -q ":$p "; then
		echo "port $p is busy" >&2
		exit 3
	fi
done

server_pid=""
container=""
cleanup() {
	if [ -n "$container" ]; then
		docker rm -f "$container" >/dev/null 2>&1 || true
	fi
	if [ -n "$server_pid" ]; then
		kill "$server_pid" 2>/dev/null || true
		# SIGTERM starts a graceful drain; don't wait for it longer than 5 s.
		for _ in $(seq 1 10); do
			kill -0 "$server_pid" 2>/dev/null || break
			sleep 0.5
		done
		kill -9 "$server_pid" 2>/dev/null || true
	fi
	for _ in $(seq 1 20); do
		ss -ltn | grep -qE ":(8082|8443) " || break
		sleep 0.5
	done
}
trap cleanup EXIT

# As HttpArena does: thousands of connections need more than the default 1024 descriptors.
ulimit -n "$(ulimit -Hn)"

if [ "$server" = rimu ]; then
	CERT_DIR=$arena/certs DATASET_PATH=$arena/data/dataset.json STATIC_DIR=$arena/data/static \
		taskset -c $server_cpus "$bin" >"$work/server-$server.log" 2>&1 &
	server_pid=$!
else
	container=h2bench-$server
	docker rm -f "$container" >/dev/null 2>&1 || true
	docker run -d --name "$container" --network host --security-opt seccomp=unconfined \
		--ulimit memlock=-1:-1 --ulimit nofile=1048576:1048576 --cpuset-cpus $server_cpus \
		-v "$arena/data/dataset.json:/data/dataset.json:ro" -v "$arena/data/static:/data/static:ro" \
		-v "$arena/certs:/certs:ro" "httparena-$server" >/dev/null
fi

scheme=http
curl_flag=--http2-prior-knowledge
if [ $port = 8443 ]; then
	scheme=https
	curl_flag="--http2 -k"
fi
for _ in $(seq 1 60); do
	# shellcheck disable=SC2086
	if curl -s $curl_flag -o /dev/null "$scheme://localhost:$port/baseline2?a=1&b=1"; then
		break
	fi
	sleep 0.5
done

if [ -z "$server_pid" ]; then
	pid=""
else
	pid=$(port_pids $port | head -1)
fi

# "busy total" jiffies summed over the load CPUs.
cpu_busy() {
	awk '$1 ~ /^cpu(6|7|8|9|10|11|18|19|20|21|22|23)$/ { t = 0; for (i = 2; i <= NF; i++) t += $i; b += t - $5 - $6; all += t } END { print b, all }' /proc/stat
}

rps=()
load_cpu=()
ucyc=()
for run in $(seq 1 "$runs"); do
	name=h2load-$$-$run
	out=$work/h2load-$server-$profile-$conns-$run.txt
	docker run --rm --name "$name" --network host --cpuset-cpus $load_cpus \
		--ulimit nofile=1048576:1048576 \
		-v "$arena/requests:/requests:ro" httparena-h2load "${args[@]}" \
		-c "$conns" -t $load_threads -D "$duration" >"$out" 2>&1 &
	h2load=$!
	sleep 2
	before=$(cpu_busy)
	if [ -n "$pid" ]; then
		cyc=$(perf stat -x, -e cycles:u -p "$pid" -- sleep 2 2>&1 | awk -F, '/cycles/ {print $1}')
	else
		sleep 2
		cyc=""
	fi
	cpu=$(awk -v a="$before" -v b="$(cpu_busy)" 'BEGIN { split(a, x, " "); split(b, y, " "); if (y[2] > x[2]) printf "%.1f", 100 * (y[1] - x[1]) / (y[2] - x[2]); else print "null" }')
	# A server that stalls streams can keep h2load waiting long past -D: stop it after 30 s and
	# count the run as failed.
	for _ in $(seq 1 50); do
		kill -0 $h2load 2>/dev/null || break
		sleep 0.5
	done
	if kill -0 $h2load 2>/dev/null; then
		docker rm -f "$name" >/dev/null 2>&1 || true
		wait $h2load 2>/dev/null || true
		echo "stalled: h2load still running after 30 s" >>"$out"
	fi
	wait $h2load 2>/dev/null || true
	ok=$(awk '/status codes:/ {gsub(",", "", $3); print $3}' "$out")
	secs=$(awk '/finished in/ {gsub("s,", "", $3); print $3}' "$out")
	r=$(awk -v ok="${ok:-0}" -v s="${secs:-0}" 'BEGIN { if (s > 0 && s < 20) printf "%.0f", ok / s; else print 0 }')
	rps+=("$r")
	load_cpu+=("${cpu:-null}")
	if [[ "$cyc" =~ ^[0-9]+$ ]] && [ "$r" -gt 0 ]; then
		ucyc+=("$(awk -v c="$cyc" -v r="$r" 'BEGIN { printf "%.0f", c / (r * 2) }')")
	else
		ucyc+=(null)
	fi
	sleep 2
done

best=0
best_idx=0
for i in "${!rps[@]}"; do
	if [ "${rps[$i]}" -gt "$best" ]; then
		best=${rps[$i]}
		best_idx=$i
	fi
done
join() {
	local IFS=,
	echo "$*"
}
printf '{"server":"%s","profile":"%s","conns":%s,"rps":[%s],"best":%s,"load_cpu_pct":%s,"server_ucyc_per_req":%s}\n' \
	"$server" "$profile" "$conns" "$(join "${rps[@]}")" "$best" "${load_cpu[$best_idx]}" "${ucyc[$best_idx]}"
