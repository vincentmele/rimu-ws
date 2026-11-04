#!/usr/bin/env bash

# Builds soak-server-uring and rimu-ws-soak, starts the server on CPUs 0-5,12-17 and runs the
# harness on 6-11,18-23. Exits with the harness's code.
#
#   soak.sh [soak] ARGS...  the harness with ARGS (the default mode)
#   soak.sh fd-plain        a descriptor flood against ordinary descriptors (nofile 1024)
#   soak.sh fd-direct       a descriptor flood against a 256-slot direct descriptor table

set -euo pipefail
cd "$(dirname "$0")/.."

mode=soak
case "${1:-}" in
soak | fd-plain | fd-direct)
	mode=$1
	shift
	;;
esac

cargo build -q --release -p rimu-ws-internal --bin soak-server-uring --features soak-server-uring
cargo build -q --release -p rimu-ws-soak
mkdir -p /mnt/nvme1tb/claude-tmp/soak
if ss -ltn | grep -q ':9080 '; then
	echo "port 9080 is busy" >&2
	exit 1
fi

# Flood connections are held idle, so the idle timeout is lifted for the flood modes.
flood_args=(--profile baseline --slots 20 --duration 10s --cycles 1 --warmup 5s --drain 5s)
server=(./target/release/soak-server-uring)
case $mode in
fd-plain)
	server=(env WTX_DIRECT=0 WTX_IDLE_MS=60000 prlimit --nofile=1024:1024 "${server[@]}")
	set -- --fd-flood 1500 "${flood_args[@]}" "$@"
	;;
fd-direct)
	server=(env WTX_DIRECT=256 WTX_IDLE_MS=60000 "${server[@]}")
	# The table is per runtime thread: 12 threads x 256 slots, so 3500 overflows it.
	set -- --fd-flood 3500 "${flood_args[@]}" "$@"
	;;
esac

taskset -c 0-5,12-17 "${server[@]}" &
pid=$!
for _ in $(seq 100); do
	ss -ltn | grep -q ':9080 ' && break
	sleep 0.1
done
set +e
taskset -c 6-11,18-23 ./target/release/rimu-ws-soak run --url ws://127.0.0.1:9080/ --pid "$pid" "$@"
rc=$?
kill "$pid"
wait "$pid" 2>/dev/null
exit $rc
