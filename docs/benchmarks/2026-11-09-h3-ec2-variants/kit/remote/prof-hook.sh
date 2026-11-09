#!/usr/bin/env bash
# shellcheck disable=SC2153 # PERF, SW_EVENT, TRACEPOINTS, ... come from run.sh's environment
# prof-hook.sh: one profile window inside one h2load run, started by h3-bench.sh (RUN_HOOK) at the run's go.
# h3-bench.sh passes HOOK_RUN, HOOK_SERVER, HOOK_PROFILE, HOOK_PID (native server), HOOK_CGROUP (docker server),
# HOOK_LOG, HOOK_SERVER_CPUS, HOOK_LOAD_CPUS, HOOK_OUT; run.sh exports the rest:
#   PERF, TOOLS, PROF_DIR, PROF_KINDS (the kind of window of each run: word HOOK_RUN of the list),
#   WIN_DELAY, WIN_LEN (s), FREQ_SW, FREQ_HW, SW_EVENT, RECORD_Z, TRACEPOINTS, HW_EVENTS, TOPDOWN_ARGS,
#   LBR_CG, CM_EVENT, KEEP_DATA (1: keep perf.data (compressed by perf record -z, else zstd); 0: delete it)
# Kinds: sw (perf record -g fp on the server CPUs + perf stat of software events and tracepoints),
#   hwstat (perf stat of the hardware counter set), topdown (perf stat top-down metrics), lbr (perf record of
#   cycles with LBR call stacks), cachemiss (perf record of LLC-load-misses / cache-misses, top symbols).
# Every kind also writes snap-a.txt / snap-b.txt / window.txt: the server's CPU (user/system), rimu's h3
# counters (SIGUSR1: exact requests in the window), UDP counters (/proc/net/snmp, snmp6), softnet_stat
# and the server CPUs' /proc/stat, at the window's start and end, and their differences.
set -u
read -r -a kinds <<<"${PROF_KINDS:-sw}"
kind=${kinds[$((HOOK_RUN - 1))]:-none}
[ "$kind" = none ] && exit 0
d=$PROF_DIR/run$HOOK_RUN-$kind
mkdir -p "$d"
cpus=$HOOK_SERVER_CPUS
hz=$(getconf CLK_TCK)
cpu_set=" $(tr ',' '\n' <<<"$cpus" | awk -F- '{ if ($2 == "") print $1; else for (i = $1; i <= $2; i++) print i }' | tr '\n' ' ')"

# The h3-stats line rimu prints on SIGUSR1 (fails if none arrives within 2 s).
stats_line() {
	local seen now
	seen=$(grep -c '^h3-stats ' "$HOOK_LOG" || true)
	kill -USR1 "$HOOK_PID" 2>/dev/null || return 1
	for _ in $(seq 1 200); do
		now=$(grep -c '^h3-stats ' "$HOOK_LOG" || true)
		if [ "$now" -gt "$seen" ]; then
			grep '^h3-stats ' "$HOOK_LOG" | tail -1
			return 0
		fi
		sleep 0.01
	done
	return 1
}

# "key value" lines; window.txt is the difference of two of them.
snap() {
	local line kv p=0 dr=0 sq=0 a b c rest
	echo "t_ns $(date +%s%N)"
	if [ -n "${HOOK_PID:-}" ]; then
		if [ "$HOOK_SERVER" = rimu ] && line=$(stats_line); then
			for kv in ${line#h3-stats }; do echo "h3_${kv%%=*} ${kv#*=}"; done
		fi
		sed 's/^.*) //' "/proc/$HOOK_PID/stat" 2>/dev/null |
			awk -v hz="$hz" '{ printf "srv_user_usec %.0f\nsrv_system_usec %.0f\n", $12 * 1e6 / hz, $13 * 1e6 / hz }'
	elif [ -n "${HOOK_CGROUP:-}" ]; then
		awk '$1 ~ /^(usage|user|system)_usec$/ { print "srv_" $1, $2 }' "$HOOK_CGROUP/cpu.stat"
	fi
	awk '$1 == "Udp:" { if (!h) { for (i = 2; i <= NF; i++) n[i] = $i; h = 1 } else for (i = 2; i <= NF; i++) print "udp_" n[i], $i }' /proc/net/snmp
	awk '$1 ~ /^Udp6/ { print "udp6_" substr($1, 5), $2 }' /proc/net/snmp6 2>/dev/null
	while read -r a b c rest; do
		p=$((p + 0x$a)); dr=$((dr + 0x$b)); sq=$((sq + 0x$c))
	done </proc/net/softnet_stat
	echo "softnet_processed $p"; echo "softnet_dropped $dr"; echo "softnet_time_squeeze $sq"
	awk -v want="$cpu_set" 'BEGIN { n = split(want, w, " "); for (i = 1; i <= n; i++) ok["cpu" w[i]] = 1 }
		($1 in ok) { u += $2; ni += $3; s += $4; id += $5; io += $6; irq += $7; si += $8; st += $9 }
		END { printf "cores_user %d\ncores_nice %d\ncores_system %d\ncores_idle %d\ncores_iowait %d\ncores_irq %d\ncores_softirq %d\ncores_steal %d\n", u, ni, s, id, io, irq, si, st }' /proc/stat
}

run_bg() { # name cmd...: a perf command in the background, its stderr kept
	local n=$1
	shift
	"$@" 2>"$d/$n.err" &
	pids+=($!)
}

# A kind this box cannot count is noted and skipped (the window's other numbers are still taken).
skip=""
case $kind in
hwstat) [ -n "${HW_EVENTS:-}" ] || skip="no hardware events on this box" ;;
topdown) [ -n "${TOPDOWN_ARGS:-}" ] || skip="no top-down metrics in this box's perf" ;;
cachemiss) [ -n "${CM_EVENT:-}" ] || skip="no cache-miss event on this box" ;;
esac
[ -n "$skip" ] && { echo "$skip" >"$d/skipped.txt"; kind=skip; }

pids=()
sleep "$WIN_DELAY"
snap >"$d/snap-a.txt"
case $kind in
sw)
	run_bg record "$PERF" record -q -F "$FREQ_SW" -e "$SW_EVENT" -g --call-graph fp -C "$cpus" ${RECORD_Z:+-z} \
		-o "$d/perf.data" -- sleep "$WIN_LEN"
	run_bg stat "$PERF" stat -x, -o "$d/stat.csv" -C "$cpus" \
		-e "task-clock,context-switches,cpu-migrations,page-faults,duration_time${TRACEPOINTS:+,$TRACEPOINTS}" -- sleep "$WIN_LEN"
	;;
hwstat)
	run_bg stat "$PERF" stat -x, -o "$d/stat.csv" -C "$cpus" -e "${HW_EVENTS},duration_time" -- sleep "$WIN_LEN"
	;;
topdown)
	# shellcheck disable=SC2086 # TOPDOWN_ARGS is a word list (e.g. "-M TopdownL1,TopdownL2")
	run_bg stat "$PERF" stat -x, -o "$d/stat.csv" -C "$cpus" $TOPDOWN_ARGS -- sleep "$WIN_LEN"
	;;
lbr)
	run_bg record "$PERF" record -q -e cycles -F "$FREQ_HW" --call-graph "$LBR_CG" -C "$cpus" ${RECORD_Z:+-z} \
		-o "$d/perf.data" -- sleep "$WIN_LEN"
	;;
cachemiss)
	run_bg record "$PERF" record -q -e "$CM_EVENT" -F "$FREQ_HW" -C "$cpus" ${RECORD_Z:+-z} \
		-o "$d/perf.data" -- sleep "$WIN_LEN"
	;;
esac
sleep "$WIN_LEN"
snap >"$d/snap-b.txt"
wait "${pids[@]}" 2>/dev/null
awk 'NR == FNR { a[$1] = $2; next } ($1 in a) { print $1, $2 - a[$1] }' "$d/snap-a.txt" "$d/snap-b.txt" >"$d/window.txt"
printf 'kind %s\nwin_len_s %s\nserver %s\nprofile %s\ncpus %s\n' "$kind" "$WIN_LEN" "$HOOK_SERVER" "$HOOK_PROFILE" "$cpus" >>"$d/window.txt"

# Reports, while the server (and a container's mount namespace, for perf's symbol lookup) is still up.
if [ -s "$d/perf.data" ]; then
	"$PERF" report -i "$d/perf.data" --stdio --no-children -g none --sort dso,sym --percent-limit 0.3 >"$d/top.txt" 2>"$d/report.err"
	"$PERF" report -i "$d/perf.data" --stdio --no-children -g none --sort comm,dso --percent-limit 0.3 >"$d/comm-dso.txt" 2>>"$d/report.err"
	if [ "$kind" != cachemiss ]; then
		"$PERF" script -i "$d/perf.data" 2>"$d/script.err" | "$TOOLS/inferno-collapse-perf" >"$d/stacks.folded" 2>>"$d/script.err"
		"$TOOLS/inferno-flamegraph" --title "$HOOK_SERVER ${ARENA_H3_HEADERS:-} $HOOK_PROFILE $kind ($SW_EVENT/cycles, CPUs $cpus)" \
			<"$d/stacks.folded" >"$d/flame.svg" 2>>"$d/script.err"
		# Rust's generic names make the folded stacks large (KBs a line): zstd keeps them at a few MB.
		zstd -q -T0 --rm -f "$d/stacks.folded"
	fi
	if [ "${KEEP_DATA:-0}" = 1 ]; then
		"$PERF" buildid-list -i "$d/perf.data" >"$d/buildids.txt" 2>/dev/null
		# perf record -z already compressed the records; otherwise zstd the file
		[ -n "${RECORD_Z:-}" ] || zstd -q -T0 --rm -f "$d/perf.data" -o "$d/perf.data.zst"
	else
		rm -f "$d/perf.data"
	fi
fi
exit 0
