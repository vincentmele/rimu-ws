#!/usr/bin/env bash

# The fuzz runs of the QUIC and HTTP/3 stack (task 22): each target alone, for SECONDS (default 1800),
# in FORK worker processes (default 12) of one libFuzzer, with a timeout of 10 s per input and 2 GiB of
# RSS. Corpora live in wtx-fuzz/corpus/<target>, crashes in wtx-fuzz/artifacts/<target>.
#
#   fuzz-h3.sh [SECONDS [TARGET...]]
#
# Targets (default: all): quic_packet quic_frame quic_transport_params qpack_decoder quic_conn h3_conn quic_endpoint.
# quic_conn and h3_conn also cap the heap of an input at 128 MiB (wtx-fuzz/lib/cap_alloc.rs).
#
# Only one cargo process may run at a time: this script runs the targets one after the other.

set -euo pipefail

seconds=${1:-1800}
shift || true
targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(quic_packet quic_frame quic_transport_params qpack_decoder quic_conn h3_conn quic_endpoint)
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/mnt/nvme1tb/claude-tmp/target-fuzz}

for target in "${targets[@]}"; do
	echo "== $target $(date -u +%FT%TZ)"
	cargo fuzz run --fuzz-dir wtx-fuzz "$target" -- -max_total_time="$seconds" -timeout=10 \
		-rss_limit_mb=2048 -fork="${FORK:-12}" -max_len=4096
done
