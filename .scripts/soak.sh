#!/usr/bin/env bash

# Builds soak-server-uring and rimu-ws-soak, starts the server on CPUs 0-5,12-17 and runs the
# harness on 6-11,18-23 with the given arguments. Exits with the harness's code.

set -euo pipefail
cd "$(dirname "$0")/.."

cargo build -q --release -p rimu-ws-internal --bin soak-server-uring --features soak-server-uring
cargo build -q --release -p rimu-ws-soak
mkdir -p /mnt/nvme1tb/claude-tmp/soak
if ss -ltn | grep -q ':9080 '; then
	echo "port 9080 is busy" >&2
	exit 1
fi
taskset -c 0-5,12-17 ./target/release/soak-server-uring &
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
