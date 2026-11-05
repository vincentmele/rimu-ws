#!/usr/bin/env bash

# Builds and runs the soak's competitors, each described in rimu-ws-soak/competitors/NAME/
# (competitor.env, CONFIG.md, and a Dockerfile or a patch to an HttpArena entry).
#
#   competitor.sh build NAME             builds the image soak-NAME
#   competitor.sh run NAME [--] ARGS...  starts soak-NAME and runs the harness against it with ARGS
#   competitor.sh smoke NAME             builds, then HttpArena's validate-ws and a 10 s baseline run
#
# Every container runs with the same flags (rimu-ws-soak/RULES.md, docs/superpowers/plans/
# 2026-11-05-soak-tier1.md): host network, seccomp unconfined, memlock unlimited, the server CPUs,
# a 3 GiB memory cap, this user's uid, and MALLOC_MMAP_THRESHOLD_=262144. The harness runs on the
# other CPUs with --cgroup, --label NAME and --rss-ceiling 2048.
#
# Environment:
#   FD_NOFILE=N   the container's descriptor limit (default 1048576; the flood job uses 1024)
#   HTTPARENA     the HttpArena checkout (default ~/src/HttpArena), read at commit fdb4aae
#
# A server that never listens on 8080 within 60 s gets a summary line {"invalid":"did not start"}
# in the harness's --out file, and exit code 4.

set -euo pipefail
cd "$(dirname "$0")/.."
repo=$PWD

httparena=${HTTPARENA:-$HOME/src/HttpArena}
httparena_commit=fdb4aae
build_dir=/mnt/nvme1tb/claude-tmp/soak-build
target=${CARGO_TARGET_DIR:-/mnt/nvme1tb/claude-tmp/target-rimu-gate}
harness=$target/release/rimu-ws-soak
nofile=${FD_NOFILE:-1048576}

usage() {
	sed -n '3,10p' "$0" >&2
	exit 3
}

[[ $# -ge 2 ]] || usage
cmd=$1
name=$2
shift 2
[[ ${1:-} == -- ]] && shift
dir=rimu-ws-soak/competitors/$name
if [[ ! -f $dir/competitor.env ]]; then
	echo "no competitor $name ($dir/competitor.env)" >&2
	exit 3
fi
# shellcheck source=/dev/null
source "$dir/competitor.env"
container=soak-$name

build() {
	mkdir -p "$build_dir"
	case $BUILD_CONTEXT in
	repo)
		# -h: wtx's README.md and NOTICE are symlinks into the repository root.
		tar -chf - --exclude=target wtx wtx-macros "$dir" |
			docker build -q -t "$container" -f "$dir/Dockerfile" - >/dev/null
		;;
	self)
		docker build -q -t "$container" "$dir" >/dev/null
		;;
	httparena)
		local out=$build_dir/$name
		rm -rf "$out"
		mkdir -p "$out"
		git -C "$httparena" archive "$httparena_commit" "frameworks/$HTTPARENA_DIR" |
			tar -x -C "$out" --strip-components=2
		if [[ -s $dir/production.patch ]]; then
			(cd "$out" && git apply "$repo/$dir/production.patch")
		fi
		docker build -q -t "$container" "$out" >/dev/null
		;;
	*)
		echo "$name: unknown BUILD_CONTEXT $BUILD_CONTEXT" >&2
		exit 3
		;;
	esac
	echo "built $container"
}

# Nothing else may run on the box's soak CPUs or port.
check_idle() {
	if pgrep -f 'rimu-ws-soak run|soak-server-' >/dev/null; then
		echo "another soak is running" >&2
		exit 1
	fi
	if [[ -n $(docker ps -q --filter name='^soak-') ]]; then
		echo "a soak container is running: $(docker ps --format '{{.Names}}' --filter name='^soak-')" >&2
		exit 1
	fi
	if ss -ltn | grep -q ':8080 '; then
		echo "port 8080 is busy" >&2
		exit 1
	fi
}

cleanup() {
	docker rm -f "$container" >/dev/null 2>&1 || true
}

# Starts the container; false if it never listens on 8080.
start() {
	check_idle
	trap cleanup EXIT
	docker run -d --name "$container" --network host --security-opt seccomp=unconfined \
		--ulimit memlock=-1:-1 --ulimit "nofile=$nofile:$nofile" --cpuset-cpus 0-5,12-17 \
		--memory 3g --user "$(id -u):$(id -g)" -e MALLOC_MMAP_THRESHOLD_=262144 \
		"$container" >/dev/null
	for _ in $(seq 300); do
		ss -ltn | grep -q ':8080 ' && return 0
		[[ $(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null) == true ]] || break
		sleep 0.2
	done
	echo "$name did not start; its log:" >&2
	docker logs "$container" 2>&1 | tail -20 >&2
	return 1
}

# The container's cgroup directory.
cgroup_dir() {
	local id pid rel
	id=$(docker inspect -f '{{.Id}}' "$container")
	if [[ -d /sys/fs/cgroup/system.slice/docker-$id.scope ]]; then
		echo "/sys/fs/cgroup/system.slice/docker-$id.scope"
		return
	fi
	pid=$(docker inspect -f '{{.State.Pid}}' "$container")
	rel=$(sed -n 's/^0:://p' "/proc/$pid/cgroup")
	echo "/sys/fs/cgroup$rel"
}

build_harness() {
	CARGO_TARGET_DIR=$target cargo build -q --release -p rimu-ws-soak
}

# The value of --out among the harness's arguments.
out_arg() {
	local prev=
	for arg in "$@"; do
		if [[ $prev == --out ]]; then
			echo "$arg"
			return
		fi
		case $arg in --out=*) echo "${arg#--out=}" && return ;; esac
		prev=$arg
	done
}

harness_run() {
	local uring=()
	[[ ${IO_URING:-0} == 1 ]] && uring=(--expect-io-uring)
	local code=0
	taskset -c 6-11,18-23 "$harness" run --url "ws://127.0.0.1:8080$URL_PATH" \
		--cgroup "$(cgroup_dir)" --label "$name" --rss-ceiling 2048 "${uring[@]}" "$@" || code=$?
	return "$code"
}

case $cmd in
build)
	build
	;;
run)
	build_harness
	if ! start; then
		out=$(out_arg "$@")
		if [[ -n $out ]]; then
			mkdir -p "$(dirname "$out")"
			printf '{"kind":"summary","label":"%s","invalid":"did not start"}\n' "$name" >"$out"
		fi
		exit 4
	fi
	code=0
	harness_run "$@" || code=$?
	exit "$code"
	;;
smoke)
	build
	build_harness
	start || exit 4
	python3 -I "$httparena/scripts/validate-ws.py" 127.0.0.1 8080 "$URL_PATH" | grep -E "FAIL|Results" || true
	# No probes: the smoke checks the server works, not its latency.
	harness_run --mode common --profile baseline --slots 20 --duration 10s --warmup 3s \
		--drain 3s --probes 0 --out "$build_dir/$name-smoke.jsonl"
	;;
*)
	usage
	;;
esac
