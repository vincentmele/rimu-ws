#!/usr/bin/env bash

# h3spec (https://github.com/kazu-yamamoto/h3spec) against arena-h2's HTTP/3 server on UDP 127.0.0.1:8443.
#
#   h3spec.sh [H3SPEC_ARGS...]     extra arguments go to h3spec, e.g. -m "FRAME_ENCODING_ERROR"
#
# h3spec is a third-party binary: it is never run on the host, only in a pinned Debian container
# (--network host, the binary bind-mounted read-only), after its sha256 is checked. Pinned:
#   h3spec v0.1.15, asset h3spec-linux-x86_64
#     https://github.com/kazu-yamamoto/h3spec/releases/download/v0.1.15/h3spec-linux-x86_64
#     sha256 c3c5f497153f4ba81f82023791ba7f9a4bc46d4141211e614196f141c5996830
#   image debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
#
# The release asset is fetched with `h3spec.sh --fetch` (needs network) into $H3SPEC_DIR.
#
# Environment:
#   H3SPEC_DIR  directory of the binary (default /mnt/nvme1tb/claude-tmp/h3spec)
#   ARENA       HttpArena checkout with data/ and certs/ (default /mnt/nvme1tb/claude-tmp/arena-main)
#   ARENA_BIN   the arena-h2 binary (default $CARGO_TARGET_DIR/release/arena-h2), built with
#               `cargo build --release -p rimu-ws-internal --features arena-h2`
#   TIMEOUT_MS  h3spec's timeout for each case (default 2000, its own default)
#
# Output: h3spec's own, and `h3spec: N examples, N failures` last; exit status 0 only if every case
# passed (the 0-RTT case is pending in h3spec itself: 0-RTT is not possible, ruling T22-a).

set -euo pipefail

version=v0.1.15
sha256=c3c5f497153f4ba81f82023791ba7f9a4bc46d4141211e614196f141c5996830
image=debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
dir=${H3SPEC_DIR:-/mnt/nvme1tb/claude-tmp/h3spec}
arena=${ARENA:-/mnt/nvme1tb/claude-tmp/arena-main}
target=${CARGO_TARGET_DIR:-/mnt/nvme1tb/claude-tmp/target-h3}
bin=${ARENA_BIN:-$target/release/arena-h2}
timeout_ms=${TIMEOUT_MS:-2000}
port=8443

if [ "${1:-}" = "--fetch" ]; then
	mkdir -p "$dir"
	curl -fsSL -o "$dir/h3spec" "https://github.com/kazu-yamamoto/h3spec/releases/download/$version/h3spec-linux-x86_64"
	chmod 755 "$dir/h3spec"
	shift
fi
[ -f "$dir/h3spec" ] || { echo "no $dir/h3spec (use --fetch)" >&2; exit 2; }
echo "$sha256  $dir/h3spec" | sha256sum --check --quiet || { echo "h3spec: wrong sha256" >&2; exit 2; }
[ -x "$bin" ] || { echo "no $bin" >&2; exit 2; }

listeners=$(ss -lun "sport = :$port"; ss -ltn "sport = :$port"; ss -ltn 'sport = :8082')
if [[ $listeners == *":$port"* || $listeners == *":8082"* ]]; then
	echo "ports $port or 8082 are busy" >&2
	exit 3
fi

log=${TMPDIR:-/mnt/nvme1tb/claude-tmp}/h3spec-server.log
server_pid=""
cleanup() {
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

ARENA_LOG_ERRORS=1 ARENA_TEST_ROUTES=1 ARENA_H3_PIN=0 CERT_DIR=$arena/certs DATASET_PATH=$arena/data/dataset.json \
	STATIC_DIR=$arena/data/static "$bin" >"$log" 2>&1 &
server_pid=$!
for _ in $(seq 1 40); do
	[[ $(ss -lun "sport = :$port") == *":$port"* ]] && break
	kill -0 "$server_pid" 2>/dev/null || { echo "arena-h2 exited; log in $log" >&2; exit 5; }
	sleep 0.25
done
sleep 0.5

# -n: the certificate of the arena is self-signed and h3spec has no option for a CA
status=0
out=$(docker run --rm --network host -v "$dir/h3spec:/h3spec:ro" "$image" \
	/h3spec -n -t "$timeout_ms" "$@" 127.0.0.1 "$port" 2>&1) || status=$?
echo "$out"
echo "h3spec: $(grep -E '^[0-9]+ examples?,' <<<"$out" || echo 'no summary')"
exit "$status"
