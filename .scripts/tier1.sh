#!/usr/bin/env bash

# The tier 1 runs: the common soak (rimu-ws-soak/RULES.md) against every competitor in
# rimu-ws-soak/competitors/, round-robin, then the report card.
#
#   tier1.sh [--rounds N] [--out DIR] [NAMES...]
#
# Each round runs every competitor, in alphabetical order rotated by the round, with seed
# 1000 + round, through two jobs of .scripts/competitor.sh:
#   1. the soak: --mode common --profile common, 300 slots, 3 cycles of 180 s, a 500-connection
#      burst after each cycle;
#   2. the descriptor flood: a fresh container with nofile 1024, 1500 connections held.
# Output: DIR/r<round>/<name>.jsonl and <name>-fd.jsonl, then DIR/card.md.
#
# Environment: TIER1_ARGS and TIER1_FD_ARGS are appended to the two jobs' harness arguments (a
# later option overrides an earlier one), for shorter dry runs.
#
# A full run takes hours: start it detached, e.g.
#   systemd-run --user --unit soak-tier1 --working-directory="$PWD" .scripts/tier1.sh

set -uo pipefail
cd "$(dirname "$0")/.."

rounds=2
out=/mnt/nvme1tb/claude-tmp/soak/tier1-$(date +%F)
while [[ $# -gt 0 ]]; do
	case $1 in
	--rounds)
		rounds=$2
		shift 2
		;;
	--out)
		out=$2
		shift 2
		;;
	*) break ;;
	esac
done
names=("$@")
if [[ ${#names[@]} -eq 0 ]]; then
	mapfile -t names < <(ls rimu-ws-soak/competitors)
fi
mkdir -p "$out"
target=${CARGO_TARGET_DIR:-/mnt/nvme1tb/claude-tmp/target-rimu-gate}

for name in "${names[@]}"; do
	.scripts/competitor.sh build "$name" || echo "tier1: $name did not build" >&2
done

read -ra extra <<<"${TIER1_ARGS:-}"
read -ra fd_extra <<<"${TIER1_FD_ARGS:-}"
for ((round = 1; round <= rounds; round++)); do
	dir=$out/r$round
	mkdir -p "$dir"
	count=${#names[@]}
	for ((i = 0; i < count; i++)); do
		name=${names[$(((i + round - 1) % count))]}
		echo "tier1: round $round, $name ($(date +%T))"
		.scripts/competitor.sh run "$name" -- --mode common --profile common --seed $((1000 + round)) \
			--slots 300 --duration 180s --cycles 3 --warmup 10s --drain 10s --burst 500 \
			--records failures --heartbeat 60s --out "$dir/$name.jsonl" "${extra[@]}" 2>&1 |
			grep -E '^cycles|INVALID' || true
		FD_NOFILE=1024 .scripts/competitor.sh run "$name" -- --mode common --profile baseline \
			--seed $((1000 + round)) --slots 20 --duration 20s --cycles 1 --warmup 5s --drain 5s \
			--fd-flood 1500 --records failures --out "$dir/$name-fd.jsonl" "${fd_extra[@]}" 2>&1 |
			grep -E '^cycles|INVALID' || true
	done
done

"$target/release/rimu-ws-soak" report --gated rimu-ws --out "$out/card.md" "$out"/r*/*.jsonl
echo "tier1: card at $out/card.md"
