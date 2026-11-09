#!/usr/bin/env bash

# One HttpArena HTTP/3 profile against one server, the way HttpArena runs it, scaled to colossus.
#
#   h3-bench.sh SERVER PROFILE
#
#   SERVER   rimu (the native arena-h2 binary, UDP 8443) or plod | fib | aegon | cnetmod | zix
#            (docker images httparena-<name>, built from HttpArena's frameworks/<name>; for zix
#            from frameworks/zix-http3, the only zix entry that serves h3)
#   PROFILE  baseline-h3 | static-h3
#
# The server runs on CPUs 0-5,12-17 and the generator (image httparena-h2load-h3: h2load 1.69.0 with
# ngtcp2 and nghttp3, built from HttpArena's docker/h2load-h3.Dockerfile) on 6-11,18-23, both on the
# host network as in HttpArena's benchmark.sh. The invocation is scripts/lib/tools/h2load-h3.sh's:
# --alpn-list=h3, -c 64 -m 64, -D 5s, and for static-h3 the URI file and the Accept-Encoding header.
# HttpArena's -t 64 on 64 CPUs becomes -t 12 on these 12. A fresh server serves 3 runs of 5 s; the
# best is kept, as HttpArena does (rps = 2xx responses / "finished in", also as HttpArena does).
#
# Prints one JSON line:
#   {"server","profile","rps","server_cpu_us_per_req","gen_cpu_us_per_req","errors","runs":[rps..],"load1",
#    "dgrams_in_per_req","dgrams_out_per_req","pkts_out_per_req","ack_only_share",
#    "resp_per_pkt","fin_ack_share","streams_blocked","data_blocked","stream_data_blocked",
#    "packets_lost","pto_probes","frames_resent"}
# and, for rimu, "headers" (ARENA_H3_HEADERS, `min` when unset: arena-h2's default since decision
# Q2, so that runs before and after it are never mixed unlabelled) and "knobs" (the line of h3
# settings that arena-h2 prints at start, if it prints one).
# rps and the per-request figures are those of the best run. A CPU figure is the CPU time (user +
# system) the server, or the generator, used during the run, divided by the 2xx responses of that
# run. The run is the span of h2load itself: the generator container waits for the script's go
# (a file in a directory they share) before it starts h2load and signals when h2load has exited, and
# the server's time is read at both, so neither the start nor the stop of the container counts. A
# docker server's time comes from its cgroup (the entrypoints of some rivals fork), the native
# server's from /proc/PID/stat, the generator's from its own container's cgroup, read just before it
# exits. The datagram figures exist for rimu only (null for the others): the datagrams it received
# and sent per 2xx response and the share of the packets it sent that were ACK-only
# (Http3WorkerStats, which arena-h2 prints on SIGUSR1, read at the same two moments). errors sums,
# over the runs, h2load's failed + errored + timeout requests and the non-2xx responses; a run
# without a summary line counts as 1. load1 is the box's 1-minute load average when the server
# started: this box is shared, so read the numbers together with it.
#
# The URL says localhost, and h2load tries only the first address getaddrinfo returns. colossus has
# a global IPv6 address, so there localhost is ::1 first, and a server that listens on IPv4 only
# (cnetmod) never gets a packet. HttpArena's board has results for such servers, so its generator
# reaches 127.0.0.1: the generator gets an /etc/hosts with only `127.0.0.1 localhost`.
#
# Environment:
#   ARENA         HttpArena checkout with data/, certs/ and requests/
#                 (default /mnt/nvme1tb/claude-tmp/arena-main)
#   ARENA_BIN     the arena-h2 binary (default $CARGO_TARGET_DIR/release/arena-h2; the HttpArena entry
#                 builds with -C target-cpu=native, so the default target dir is the one built so)
#   ARENA_H3_HEADERS  min or full, passed on to arena-h2 (the response headers A/B); recorded in
#                 every rimu output line, `min` when unset
#   RUNS          runs per server start (default 3)
#   DURATION      h2load -D (default 5s)
#   GEN_LOCALHOST v4 (default: the generator resolves localhost to 127.0.0.1 only) or auto (the
#                 host's /etc/hosts: ::1 first on colossus)
# Added for the aws-h3 kit (defaults keep colossus' behaviour above):
#   SERVER_CPUS   CPU list of the server (default 0-5,12-17)
#   LOAD_CPUS     CPU list of the generator (default 6-11,18-23)
#   LOAD_THREADS  h2load -t (default 12)
#   GEN_HOSTS     a ready hosts file to mount for GEN_LOCALHOST=v4 (default: written into the work dir)
#   RUN_HOOK      a command started in the background at each run's go, waited for before the run's
#                 `sleep 2` (the server is still up). It gets HOOK_RUN (1..RUNS), HOOK_SERVER, HOOK_PROFILE,
#                 HOOK_PID (the native server's pid, empty for docker), HOOK_CGROUP (docker: its cgroup dir),
#                 HOOK_LOG (the server's log), HOOK_SERVER_CPUS, HOOK_LOAD_CPUS and HOOK_OUT (this run's
#                 h2load output). The run's numbers are taken exactly as without it.

set -euo pipefail

server=${1:?SERVER}
profile=${2:?PROFILE}
arena=${ARENA:-/mnt/nvme1tb/claude-tmp/arena-main}
target=${CARGO_TARGET_DIR:-/mnt/nvme1tb/claude-tmp/target-h3-native}
bin=${ARENA_BIN:-$target/release/arena-h2}
runs=${RUNS:-3}
duration=${DURATION:-5s}
server_cpus=${SERVER_CPUS:-0-5,12-17}
load_cpus=${LOAD_CPUS:-6-11,18-23}
load_threads=${LOAD_THREADS:-12}
conns=64
streams=64
port=8443
generator=httparena-h2load-h3
work=${TMPDIR:-/mnt/nvme1tb/claude-tmp}/h3bench
mkdir -p "$work"
# Shared with the generator container: it creates ready, the script go, the container done.
sync_dir=$work/sync-$$
mkdir -p "$sync_dir"

# Mounted over the generator's /etc/hosts (the host network shares the host's own otherwise).
gen_hosts=()
case ${GEN_LOCALHOST:-v4} in
v4)
	hosts_file=${GEN_HOSTS:-$work/hosts-v4}
	[ -n "${GEN_HOSTS:-}" ] || printf '127.0.0.1 localhost\n' >"$hosts_file"
	gen_hosts=(-v "$hosts_file:/etc/hosts:ro")
	;;
auto) ;;
*)
	echo "GEN_LOCALHOST must be v4 or auto" >&2
	exit 2
	;;
esac

case $server in
rimu | plod | fib | aegon | cnetmod | zix) ;;
*)
	echo "unknown server $server" >&2
	exit 2
	;;
esac

case $profile in
baseline-h3)
	args=("https://localhost:$port/baseline2?a=1&b=1")
	;;
static-h3)
	args=(-i /requests/static-h2-uris.txt -H "Accept-Encoding: br;q=1, gzip;q=0.8")
	;;
*)
	echo "unknown profile $profile" >&2
	exit 2
	;;
esac
args=(--alpn-list=h3 "${args[@]}" -c "$conns" -m "$streams" -t "$load_threads" -D "$duration")
probe_url="https://localhost:$port/baseline2?a=1&b=1"

# Pids listening on the port (UDP and TCP; the rivals also serve h2 on TCP 8443).
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

# A server from an earlier run may still be closing: give it 10 s before calling the port busy.
for _ in $(seq 1 20); do
	port_busy || break
	sleep 0.5
done
if port_busy; then
	echo "port $port is busy" >&2
	exit 3
fi

server_pid=""
container=""
cgroup=""
gen_name=h3load-$$
log=$work/server-$server-$profile.log
hook=""
cleanup() {
	if [ -n "$hook" ]; then
		kill "$hook" 2>/dev/null || true
	fi
	docker rm -f "$gen_name" >/dev/null 2>&1 || true
	rm -rf "$sync_dir"
	if [ -n "$container" ]; then
		docker logs "$container" >"$log" 2>&1 || true
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
		port_busy || break
		sleep 0.5
	done
}
trap cleanup EXIT

# As HttpArena does: thousands of connections need more than the default 1024 descriptors.
ulimit -n "$(ulimit -Hn)"

load1=$(cut -d' ' -f1 /proc/loadavg)

if [ "$server" = rimu ]; then
	CERT_DIR=$arena/certs DATASET_PATH=$arena/data/dataset.json STATIC_DIR=$arena/data/static \
		taskset -c "$server_cpus" "$bin" >"$log" 2>&1 &
	server_pid=$!
else
	image=httparena-$server
	container=h3bench-$server
	docker rm -f "$container" >/dev/null 2>&1 || true
	# HttpArena's framework_start: host network, unconfined seccomp, certs, data and static mounted.
	docker run -d --name "$container" --network host --security-opt seccomp=unconfined \
		--ulimit memlock=-1:-1 --ulimit nofile=1048576:1048576 --cpuset-cpus "$server_cpus" \
		-v "$arena/data/dataset.json:/data/dataset.json:ro" -v "$arena/data/static:/data/static:ro" \
		-v "$arena/certs:/certs:ro" "$image" >/dev/null
	id=$(docker inspect -f '{{.Id}}' "$container")
	for c in "/sys/fs/cgroup/system.slice/docker-$id.scope" "/sys/fs/cgroup/docker/$id"; do
		if [ -r "$c/cpu.stat" ]; then
			cgroup=$c
			break
		fi
	done
	if [ -z "$cgroup" ]; then
		echo "no cgroup for container $container" >&2
		exit 4
	fi
fi

# Readiness as validate.sh does it: the generator itself, one request, until it sees a 2xx.
ready=0
# 60 s in all, whatever the probes take
deadline=$((SECONDS + 60))
while [ "$SECONDS" -lt "$deadline" ]; do
	if [ -n "$container" ] && [ "$(docker inspect -f '{{.State.Running}}' "$container")" != true ]; then
		echo "$server exited before it answered; log in $log" >&2
		exit 5
	fi
	if [ -n "$server_pid" ] && ! kill -0 "$server_pid" 2>/dev/null; then
		echo "$server exited before it answered; log in $log" >&2
		exit 5
	fi
	# A server that does not answer leaves h2load waiting for its 30 s idle timeout: give it 10 s
	# (less, if the deadline comes sooner).
	left=$((deadline - SECONDS))
	answer=$(timeout $((left < 10 ? left : 10)) docker run --rm --name "$gen_name" --network host --cpuset-cpus "$load_cpus" \
		"${gen_hosts[@]}" "$generator" --alpn-list=h3 -n 1 -c 1 -t 1 "$probe_url" 2>/dev/null || true)
	docker rm -f "$gen_name" >/dev/null 2>&1 || true
	if [[ $answer == *" 1 2xx"* ]]; then
		ready=1
		break
	fi
	sleep 0.5
done
if [ $ready != 1 ]; then
	echo "$server did not answer over HTTP/3 within 60 s; log in $log" >&2
	exit 5
fi

# The native server's pid as the kernel sees the listener (taskset execs, so it is the same). The
# pipeline fails when nothing listens (grep finds no pid), which pipefail would turn into a silent
# exit of the script.
if [ -n "$server_pid" ]; then
	listener=$(port_pids | head -1) || true
	if [ -z "$listener" ]; then
		echo "$server answered, yet no process of this user listens on port $port (ss -lunp / -ltnp)" >&2
		exit 6
	fi
	server_pid=$listener
fi

clk_tck=$(getconf CLK_TCK)
# CPU time (user + system) the server has used so far, in microseconds.
server_cpu_usec() {
	if [ -n "$cgroup" ]; then
		awk '/^usage_usec/ { print $2 }' "$cgroup/cpu.stat"
	else
		# Drop "pid (comm) ": the comm may hold spaces. Then utime and stime are fields 12 and 13.
		sed 's/^.*) //' "/proc/$server_pid/stat" | awk -v hz="$clk_tck" '{ printf "%.0f\n", ($12 + $13) * 1000000 / hz }'
	fi
}

# One "name=value ..." line with the sums of the counters of arena-h2's h3 workers, which it prints
# to its log on SIGUSR1. Fails (and prints nothing) if the server does not answer within 2 s.
h3_stats_line() {
	local seen now
	seen=$(grep -c '^h3-stats ' "$log" || true)
	kill -USR1 "$server_pid" 2>/dev/null || return 1
	for _ in $(seq 1 200); do
		now=$(grep -c '^h3-stats ' "$log" || true)
		if [ "$now" -gt "$seen" ]; then
			grep '^h3-stats ' "$log" | tail -1
			return 0
		fi
		sleep 0.01
	done
	return 1
}
# The value of NAME in a line of h3_stats_line.
stat_of() {
	local name=$1 line=$2 value
	value=$(sed -n "s/.* $name=\([0-9][0-9]*\).*/\1/p" <<<"$line")
	echo "${value:-0}"
}
# Waits up to $2 * 10 ms for the file $1; stops early if the generator ($3) has exited.
wait_for_file() {
	for _ in $(seq 1 "$2"); do
		[ -e "$1" ] && return 0
		kill -0 "$3" 2>/dev/null || return 1
		sleep 0.01
	done
	return 1
}

rps=()
srv_cpu=()
gen_cpu=()
dgrams_in=()
dgrams_out=()
pkts_out=()
ack_share=()
# The counters of spec section 2.1 (ruling T16-c), one JSON fragment per run
sec21=()
sec21_null=',"resp_per_pkt":null,"fin_ack_share":null,"streams_blocked":null,"data_blocked":null,"stream_data_blocked":null,"packets_lost":null,"pto_probes":null,"frames_resent":null'
total_errors=0
for run in $(seq 1 "$runs"); do
	name=$gen_name
	out=$work/h3load-$server-$profile-$run.txt
	rm -f "$sync_dir/ready" "$sync_dir/go" "$sync_dir/done"
	# The generator prints its container's CPU time as its last line (the cgroup file of its own
	# cgroup namespace); the container is gone as soon as it exits. It starts h2load when the
	# script creates `go` and creates `done` when h2load has exited.
	docker run --rm --name "$name" --network host --cpuset-cpus "$load_cpus" "${gen_hosts[@]}" \
		--ulimit nofile=1048576:1048576 -v "$arena/requests:/requests:ro" -v "$sync_dir:/sync" \
		--entrypoint sh "$generator" -c ': >/sync/ready
while [ ! -e /sync/go ]; do sleep 0.005; done
h2load "$@"; rc=$?
echo "gen cpu usec: $(awk "/^usage_usec/ { print \$2 }" /sys/fs/cgroup/cpu.stat)"
: >/sync/done
exit $rc' \
		sh "${args[@]}" >"$out" 2>&1 &
	gen=$!
	before=""
	after=""
	stats_before=""
	stats_after=""
	if wait_for_file "$sync_dir/ready" 3000 $gen; then
		before=$(server_cpu_usec)
		if [ -n "$server_pid" ] && [ "$server" = rimu ]; then
			stats_before=$(h3_stats_line || true)
			before=$(server_cpu_usec)
		fi
		: >"$sync_dir/go"
		if [ -n "${RUN_HOOK:-}" ]; then
			HOOK_RUN=$run HOOK_SERVER=$server HOOK_PROFILE=$profile HOOK_PID=$server_pid HOOK_CGROUP=$cgroup \
				HOOK_LOG=$log HOOK_SERVER_CPUS=$server_cpus HOOK_LOAD_CPUS=$load_cpus HOOK_OUT=$out \
				"$RUN_HOOK" </dev/null >>"$work/hook.log" 2>&1 &
			hook=$!
		fi
		# A server that stalls streams can keep h2load waiting long past -D: stop it after 30 s
		# and count the run as failed.
		if ! wait_for_file "$sync_dir/done" 3000 $gen; then
			docker rm -f "$name" >/dev/null 2>&1 || true
			echo "stalled: h2load still running after 30 s" >>"$out"
		fi
		after=$(server_cpu_usec)
		if [ -n "$stats_before" ]; then
			stats_after=$(h3_stats_line || true)
		fi
	else
		docker rm -f "$name" >/dev/null 2>&1 || true
		echo "the generator container did not start within 30 s" >>"$out"
	fi
	wait $gen 2>/dev/null || true
	# The hook (a profile window) finishes while the server is still up.
	if [ -n "$hook" ]; then
		wait "$hook" 2>/dev/null || true
		hook=""
	fi

	ok=$(awk '/status codes:/ { print $3 }' "$out")
	secs=$(awk '/^finished in/ { sub("s,", "", $3); print $3 }' "$out")
	bad=$(awk '/^requests:/ { f = $10 + $12 + $14 } /status codes:/ { n = $5 + $7 + $9 } END { print f + n }' "$out")
	g=$(awk '/^gen cpu usec:/ { print $4 }' "$out")
	if [ -z "$ok" ] || [ -z "$secs" ] || [ -z "$before" ] || [ -z "$after" ]; then
		bad=1
		ok=0
		secs=0
	fi
	r=$(awk -v ok="$ok" -v s="$secs" 'BEGIN { if (s > 0 && s < 20) printf "%.0f", ok / s; else print 0 }')
	rps+=("$r")
	total_errors=$((total_errors + ${bad:-0}))
	if [ "$ok" -gt 0 ] && [ "$r" -gt 0 ]; then
		srv_cpu+=("$(awk -v a="$before" -v b="$after" -v n="$ok" 'BEGIN { printf "%.3f", (b - a) / n }')")
		if [[ "$g" =~ ^[0-9]+$ ]]; then
			gen_cpu+=("$(awk -v g="$g" -v n="$ok" 'BEGIN { printf "%.3f", g / n }')")
		else
			gen_cpu+=(null)
		fi
	else
		srv_cpu+=(null)
		gen_cpu+=(null)
	fi
	if [ -n "$stats_before" ] && [ -n "$stats_after" ] && [ "$ok" -gt 0 ]; then
		d() { echo $(($(stat_of "$1" "$stats_after") - $(stat_of "$1" "$stats_before"))); }
		din=$(d datagrams_in)
		dout=$(d datagrams_out)
		pout=$(d packets_out)
		aout=$(d ack_only_out)
		dgrams_in+=("$(awk -v a="$din" -v n="$ok" 'BEGIN { printf "%.3f", a / n }')")
		dgrams_out+=("$(awk -v a="$dout" -v n="$ok" 'BEGIN { printf "%.3f", a / n }')")
		pkts_out+=("$(awk -v a="$pout" -v n="$ok" 'BEGIN { printf "%.3f", a / n }')")
		ack_share+=("$(awk -v a="$aout" -v p="$pout" 'BEGIN { if (p > 0) printf "%.4f", a / p; else print "null" }')")
		if [[ $stats_after == *" fins_out="* ]]; then
			fins=$(d fins_out)
			ff=$(d fin_flushes)
			ffa=$(d fin_flushes_acked)
			sec21+=("$(printf ',"resp_per_pkt":%s,"fin_ack_share":%s,"streams_blocked":%s,"data_blocked":%s,"stream_data_blocked":%s,"packets_lost":%s,"pto_probes":%s,"frames_resent":%s' \
				"$(awk -v a="$fins" -v p="$pout" 'BEGIN { if (p > 0) printf "%.2f", a / p; else print "null" }')" \
				"$(awk -v a="$ffa" -v f="$ff" 'BEGIN { if (f > 0) printf "%.4f", a / f; else print "null" }')" \
				"$(d streams_blocked_in)" "$(d data_blocked_in)" "$(d stream_data_blocked_in)" "$(d packets_lost)" \
				"$(d pto_probes)" "$(d frames_resent)")")
		else
			sec21+=("$sec21_null")
		fi
	else
		dgrams_in+=(null)
		dgrams_out+=(null)
		pkts_out+=(null)
		ack_share+=(null)
		sec21+=("$sec21_null")
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
headers=""
if [ "$server" = rimu ]; then
	headers=$(printf ',"headers":"%s"' "${ARENA_H3_HEADERS:-min}")
	knobs=$(grep -m1 '^arena-h2: h3 knobs ' "$log" | sed 's/^arena-h2: h3 knobs //' | tr -cd 'a-z0-9_=. -' || true)
	[ -n "$knobs" ] && headers="$headers$(printf ',"knobs":"%s"' "$knobs")"
fi
printf '{"server":"%s","profile":"%s"%s,"rps":%s,"server_cpu_us_per_req":%s,"gen_cpu_us_per_req":%s,"errors":%s,"runs":[%s],"load1":%s,"dgrams_in_per_req":%s,"dgrams_out_per_req":%s,"pkts_out_per_req":%s,"ack_only_share":%s%s}\n' \
	"$server" "$profile" "$headers" "$best" "${srv_cpu[$best_idx]}" "${gen_cpu[$best_idx]}" "$total_errors" "$(join "${rps[@]}")" "$load1" \
	"${dgrams_in[$best_idx]}" "${dgrams_out[$best_idx]}" "${pkts_out[$best_idx]}" "${ack_share[$best_idx]}" "${sec21[$best_idx]}"
