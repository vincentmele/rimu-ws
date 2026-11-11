#!/usr/bin/env bash
# run.sh PHASE: the aws-final run on the box (as root, started by launch.sh under systemd-run), or the local smoke.
#   setup F    (box) wait for the boot apt job launch.sh started, apply the host tuning, write host.txt (with the
#              CPU's model, flags and vaes=yes|no), then take each kit part as launch.sh's rsync finishes it (marker
#              dl/<part>.done, order dl/parts.txt): check its sha256, unpack it or `docker load` it. Ends with
#              setup.ok (or setup.failed) in the kit dir.
#   regress    phase R (Task 24 step 2): the h1 / h2 / WebSocket A/B of regress.sh (A = main 85c9fe8d, B = feat/http3),
#              PASSES passes (launch.sh passes 4), rows to out/regress/results.tsv
#   h3final    phase C + X (Task 24 steps 3 and carried checks): variants `base` (the final build) and `prev` (44752fa8,
#              the last EC2-measured build) with the five rivals (VREF), PASSES passes (3) with the order rotated,
#              both h3 profiles, h3-bench.sh (3 runs of 5 s per start, best kept); rows to out/vbench.jsonl. X reads
#              the request errors of each start (a close with 0x0107 / InternalError / PoolExhausted shows as failed or
#              errored requests), the server's own totals (last h3-stats line of out/raw/vbench/*/server-try*.log) and
#              `frames_resent_acked`; rimu starts run with ARENA_LOG_ERRORS=1 (worker-level errors only). An optional
#              software profile (VPROF, default none) follows.
#   smoke      the local plumbing check: regress.sh smoke, then the h3final phase with SMOKE=1 (variants base and prev,
#              reference fib, one pass, -D 2s, one run per start, no profile), then the leftovers check. No numbers.
#   Phases of the earlier kits still work (bench, profile, hw, variants, vsmoke) for the same harness.
# Env overrides: SCPU / LCPU (server / generator CPU lists; default: whole cores with their SMT siblings from
# lscpu -p, the first half to the server), LOAD_THREADS (default: the generator's CPU count), SERVERS, PROFILES,
# PASSES, OUT (default <kit>/out), WORK (default <kit>/work), PERF (the perf binary), VARIANTS, VREF (empty: no
# reference), VPROF, VPROF_PROFILES (default PROFILES), VARIANT_FILE, BIN_BENCH, BIN_PREV, BIN_PROF, BIN_PREV_PROF.
set -u
K=$(cd "$(dirname "$0")" && pwd)
KIT=$(dirname "$K")
PHASE=${1:-}
case $PHASE in smoke | vsmoke) export SMOKE=1 ;; esac
SMOKE=${SMOKE:-0}
# LOCAL=1: a full run on colossus at the user's request (11 Nov): no sysctl / systemctl change, no killing of anything
# the kit did not start (reset_box refuses instead of killing).
LOCAL=${LOCAL:-0}
O=${OUT:-$KIT/out}
WORK=${WORK:-$KIT/work}
mkdir -p "$O" "$WORK"
ARENA=$K/arena
export PERF_BUILDID_DIR=$WORK/.debug # perf's build-id cache: not in $HOME
export TOOLS=$K/tools

# --- the CPU split: whole cores (with all their SMT siblings) sorted by NUMA node, socket and core; the first
# half to the server, the rest to the generator (POSIX awk: mawk on Ubuntu)
split_cpus() {
	lscpu -p=CPU,CORE,SOCKET,NODE | grep -v '^#' | awk -F, '{ printf "%05d %05d %05d %d\n", $4, $3, $2, $1 }' |
		sort -k1,1 -k2,2 -k3,3 -k4,4n | awk '{ k = $1 " " $2 " " $3; if (k != last) { n++; last = k }
      if (m[n]++) c[n] = c[n] "," $4; else c[n] = $4 }
    END { h = int(n / 2); s = ""; l = ""
          for (i = 1; i <= n; i++) if (i <= h) s = s (s == "" ? "" : ",") c[i]; else l = l (l == "" ? "" : ",") c[i]
          print s, l }'
}
expand() { tr ',' '\n' <<<"$1" | awk -F- '{ if ($2 == "") print $1; else for (i = $1; i <= $2; i++) print i }'; }
count() { expand "$1" | wc -l; }
read -r DS DL <<<"$(split_cpus)"
SCPU=${SCPU:-$DS}
LCPU=${LCPU:-$DL}
LT=${LOAD_THREADS:-$(count "$LCPU")}

if [ "$SMOKE" = 1 ]; then
	PASSES=${PASSES:-1}; SERVERS=${SERVERS:-"rimu-full fib"}; BENCH_RUNS=1; BENCH_D=2s
	PROF_D=4s; WIN_DELAY=1; WIN_LEN=2; FREQ_SW=99; FREQ_HW=99; VREF=${VREF-fib}
else
	PASSES=${PASSES:-3}; SERVERS=${SERVERS:-"rimu-full rimu-min plod fib aegon cnetmod zix"}; BENCH_RUNS=3; BENCH_D=5s
	PROF_D=12s; WIN_DELAY=3; WIN_LEN=6; FREQ_SW=499; FREQ_HW=999
fi
PROFILES=${PROFILES:-"baseline-h3 static-h3"}
BIN_BENCH=${BIN_BENCH:-$K/bin/znver2/arena-h2}
BIN_PROF=${BIN_PROF:-$K/bin/znver2-prof/arena-h2}
BIN_HW=${BIN_HW:-$K/bin/znver2-prof/arena-h2}
BIN_PREV=${BIN_PREV:-$K/bin/prev-znver2/arena-h2}
BIN_PREV_PROF=${BIN_PREV_PROF:-$K/bin/prev-znver2-prof/arena-h2}
VARIANT_FILE=${VARIANT_FILE:-$K/variants.txt}
VREF=${VREF-"plod fib aegon cnetmod zix"}
export WIN_DELAY WIN_LEN FREQ_SW FREQ_HW

find_perf() {
	if [ -n "${PERF:-}" ]; then echo "$PERF"; return; fi
	if perf --version >/dev/null 2>&1; then command -v perf; return; fi
	# The linux-tools wrapper wants the package of the running kernel; any installed perf will do.
	# shellcheck disable=SC2012 # plain paths
	ls /usr/lib/linux-tools/*/perf /usr/lib/linux-tools-*/perf 2>/dev/null | tail -1
}

pmu_probe() { # prints yes if the box counts cycles
	local p
	p=$(find_perf)
	"$p" stat -x, -e cycles,instructions -- true 2>&1 | awk -F, '$3 ~ /^cycles/ && $1 ~ /^[0-9]+$/ && $1 > 0 { y = 1 } END { print (y ? "yes" : "no") }'
}

hostinfo() {
	local p
	p=$(find_perf)
	echo "== $(date -u +%FT%TZ) $(hostname) phase=$PHASE smoke=$SMOKE"
	if [ "$SMOKE" != 1 ]; then
		local tok
		tok=$(curl -fsS -m 2 -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null)
		for k in instance-type placement/availability-zone instance-id ami-id instance-life-cycle; do
			echo "imds $k: $(curl -fsS -m 2 -H "X-aws-ec2-metadata-token: $tok" "http://169.254.169.254/latest/meta-data/$k" 2>/dev/null)"
		done
	fi
	echo "uptime: $(uptime)"
	echo "uname -r: $(uname -r)"
	echo "cmdline: $(cat /proc/cmdline)"
	echo "server cpus $SCPU | generator cpus $LCPU | h2load -t $LT"
	echo "cpu model: $(lscpu | sed -n 's/^Model name: *//p')"
	echo "cpu flags of note: $(grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -E '^(aes|avx2|vaes|vpclmulqdq|avx512f|sha_ni)$' | sort -u | tr '\n' ' ')"
	echo "vaes=$(grep -m1 '^flags' /proc/cpuinfo | grep -qw vaes && echo yes || echo no)"
	echo "== PMU probe: perf stat -e cycles,instructions -- true"
	"$p" stat -e cycles,instructions -- true 2>&1
	echo "pmu=$(pmu_probe)"
	echo "== perf: $p $("$p" --version 2>&1)"
	echo "== sysctl"
	sysctl net.core.rmem_max net.core.wmem_max net.core.rmem_default net.core.wmem_default net.core.netdev_max_backlog \
		net.ipv4.udp_mem kernel.perf_event_paranoid kernel.kptr_restrict kernel.io_uring_disabled kernel.nmi_watchdog 2>&1
	echo "ulimit -n $(ulimit -n) -l $(ulimit -l)"
	echo "== docker: $(docker version --format '{{.Server.Version}}' 2>&1)"
	docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.Size}}' 2>&1 | grep -E 'httparena-' || true
	for b in "$K"/bin/*/REVISION "$K"/bin/regress/*/REVISION; do [ -e "$b" ] && echo "$b: $(tr '\n' ' ' <"$b")"; done
	echo "arena: $(cat "$ARENA/REVISION" 2>/dev/null)"
	echo "== free -g"; free -g
	echo "== lscpu"; lscpu
	echo "== lscpu -e"; lscpu -e
}

tune() { # box only: colossus' network sysctls, profiling access, a quiet box
	[ "$LOCAL" = 1 ] && { echo "local: no sysctl or service changes"; return 0; }
	sysctl -qw net.core.rmem_max=4194304 net.core.wmem_max=4194304 net.core.rmem_default=212992 \
		net.core.wmem_default=212992 net.core.netdev_max_backlog=1000 "net.ipv4.udp_mem=1534386 2045850 3068772" \
		kernel.perf_event_paranoid=-1 kernel.kptr_restrict=0
	# The servers use io_uring (colossus: 0). The NMI watchdog holds a PMU counter (perf asks for it to be off).
	if [ -e /proc/sys/kernel/io_uring_disabled ] && [ "$(cat /proc/sys/kernel/io_uring_disabled)" != 0 ]; then
		sysctl -qw kernel.io_uring_disabled=0
	fi
	[ -e /proc/sys/kernel/nmi_watchdog ] && sysctl -qw kernel.nmi_watchdog=0
	systemctl stop unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer apt-daily.service \
		apt-daily-upgrade.service snapd.service snapd.socket fwupd-refresh.timer motd-news.timer 2>/dev/null || true
}

limits() {
	ulimit -n 1048576 2>/dev/null || ulimit -n "$(ulimit -Hn)" 2>/dev/null
	ulimit -l unlimited 2>/dev/null || true
}

# What an interrupted earlier phase may have left (box only: our container names, our ports).
reset_box() {
	[ "$SMOKE" = 1 ] && return 0
	if [ "$LOCAL" = 1 ]; then
		if docker ps -aq --filter name=^h3bench- --filter name=^h3load- | grep -q . ||
			{ ss -Hlunp 'sport = :8443'; ss -Hltnp '( sport = :8443 or sport = :8082 )'; } | grep -q .; then
			echo "local: ports 8443/8082 or h3bench/h3load containers in use: refusing (nothing is killed locally)"; exit 1
		fi
		return 0
	fi
	local c p
	c=$(docker ps -aq --filter name=^h3bench- --filter name=^h3load- 2>/dev/null)
	# shellcheck disable=SC2086 # id / pid lists
	[ -n "$c" ] && { echo "reset: removing containers $c"; docker rm -f $c >/dev/null; }
	p=$({ ss -Hlunp 'sport = :8443'; ss -Hltnp '( sport = :8443 or sport = :8082 )'; } | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u)
	# shellcheck disable=SC2086
	[ -n "$p" ] && { echo "reset: killing listeners $p"; kill -9 $p 2>/dev/null; sleep 1; }
	return 0
}

setup() {
	local phase=$1 dl=$KIT/dl part deadline
	trap '[ -e "$KIT/setup.ok" ] || touch "$KIT/setup.failed"' EXIT
	echo "== setup $phase $(date -u +%T)"
	deadline=$((SECONDS + 1200))
	until [ -e /var/tmp/rimufin-apt.ok ]; do
		[ -e /var/tmp/rimufin-apt.failed ] && { echo "apt install failed (journalctl -u rimufin-apt)"; exit 1; }
		[ $SECONDS -lt $deadline ] || { echo "apt install not done after 20 min"; exit 1; }
		sleep 1
	done
	echo "apt done $(date -u +%T)"
	systemctl start docker
	tune
	limits
	hostinfo >"$O/host.txt" 2>&1
	grep '^pmu=' "$O/host.txt"
	while read -r part; do
		until [ -e "$dl/$part.done" ]; do
			[ $SECONDS -lt $deadline ] || { echo "$part did not arrive"; exit 1; }
			sleep 0.5
		done
		(cd "$dl" && grep " $part\$" kit.sha256 | sha256sum -c --quiet) || { echo "$part: sha256 mismatch"; exit 1; }
		case $part in
		kit-common.tgz) ;; # unpacked by launch.sh before this script could run
		kit-img-*) zstd -dc --long=27 "$dl/$part" | docker load -q || { echo "docker load $part failed"; exit 1; }; rm -f "$dl/$part" ;;
		*.tar.zst) zstd -dc --long=27 "$dl/$part" | tar -C "$KIT" -x || { echo "unpack $part failed"; exit 1; } ;;
		esac
		echo "took $part $(date -u +%T)"
	done <"$dl/parts.txt"
	# host.txt again, now with the images and binaries
	hostinfo >"$O/host.txt" 2>&1
	touch "$KIT/setup.ok"
	echo "== setup done $(date -u +%T)"
}

# --- perf capabilities (profile and hw phases), exported for prof-hook.sh
caps() {
	local c0 ev ok=() hw=() a
	PERF=$(find_perf); export PERF
	c0=$(expand "$SCPU" | head -1)
	PMU=$(pmu_probe)
	SW_EVENT=cpu-clock; [ "$PMU" = yes ] && SW_EVENT=cycles
	RECORD_Z=""
	"$PERF" record -q -z -e cpu-clock -C "$c0" -o "$WORK/probe.data" -- sleep 0.05 >/dev/null 2>&1 && RECORD_Z=1
	for ev in syscalls:sys_enter_io_uring_enter syscalls:sys_enter_sendmsg syscalls:sys_enter_recvmsg \
		syscalls:sys_enter_sendmmsg syscalls:sys_enter_recvmmsg syscalls:sys_enter_sendto syscalls:sys_enter_recvfrom \
		syscalls:sys_enter_epoll_wait syscalls:sys_enter_epoll_pwait syscalls:sys_enter_epoll_pwait2 \
		syscalls:sys_enter_futex syscalls:sys_enter_read syscalls:sys_enter_write syscalls:sys_enter_writev \
		io_uring:io_uring_submit_req io_uring:io_uring_submit_sqe io_uring:io_uring_complete io_uring:io_uring_task_add \
		net:net_dev_xmit net:netif_receive_skb net:netif_rx skb:kfree_skb udp:udp_fail_queue_rcv_skb; do
		a=$("$PERF" stat -x, -e "$ev" -C "$c0" -- sleep 0.01 2>&1) && [[ $a != *"not supported"* ]] && ok+=("$ev")
	done
	TRACEPOINTS=$(IFS=,; echo "${ok[*]}")
	for ev in cycles instructions branches branch-misses cache-references cache-misses L1-dcache-loads \
		L1-dcache-load-misses LLC-loads LLC-load-misses dTLB-load-misses iTLB-load-misses; do
		a=$("$PERF" stat -x, -e "$ev" -C "$c0" -- sleep 0.01 2>&1) && [[ $a =~ (^|$'\n')[0-9]+, ]] && hw+=("$ev")
	done
	HW_EVENTS=$(IFS=,; echo "${hw[*]}")
	TOPDOWN_ARGS=""
	for a in "-M TopdownL1,TopdownL2" "--topdown --td-level 2" "--topdown" "-M TopdownL1" "-M PipelineL1,PipelineL2" "-M PipelineL1"; do
		# shellcheck disable=SC2086 # a is a word list
		if "$PERF" stat -x, $a -C "$SCPU" -- sleep 0.05 >"$WORK/probe.td" 2>&1 && ! grep -qiE 'not supported|cannot|invalid|unknown' "$WORK/probe.td"; then
			TOPDOWN_ARGS=$a
			break
		fi
	done
	LBR_CG=fp
	"$PERF" record -q -e cycles -F 99 --call-graph lbr -C "$c0" -o "$WORK/probe.data" -- sleep 0.05 >/dev/null 2>&1 && LBR_CG=lbr
	CM_EVENT=""
	for ev in LLC-load-misses cache-misses; do
		if "$PERF" record -q -e "$ev" -F 99 -C "$c0" -o "$WORK/probe.data" -- sleep 0.05 >/dev/null 2>&1; then CM_EVENT=$ev; break; fi
	done
	rm -f "$WORK/probe.data" "$WORK/probe.data.old" "$WORK/probe.td"
	export PMU SW_EVENT RECORD_Z TRACEPOINTS HW_EVENTS TOPDOWN_ARGS LBR_CG CM_EVENT
	{
		echo "perf=$PERF ($("$PERF" --version 2>&1))"
		echo "pmu=$PMU sw_event=$SW_EVENT record_z=${RECORD_Z:-no} lbr_cg=$LBR_CG cm_event=${CM_EVENT:-none}"
		echo "topdown_args=${TOPDOWN_ARGS:-none}"
		echo "hw_events=${HW_EVENTS:-none}"
		echo "tracepoints=${TRACEPOINTS:-none}"
	} | tee "$O/perf-caps-$PHASE.txt"
	# kernel symbols for re-analysing rimu's perf.data elsewhere (perf report --kallsyms=...)
	[ -s "$O/kallsyms.zst" ] || zstd -q -c /proc/kallsyms >"$O/kallsyms.zst" 2>/dev/null || true
}

# --- one server start: h3-bench.sh SERVER PROFILE, retried once if it fails or serves nothing; one JSON line
# to out/<kind>.jsonl, h2load outputs and the server log to out/raw/<kind>/<label>-<profile>-p<pass>/
one_start() { # kind pass profile label
	local kind=$1 pass=$2 prof=$3 label=$4 server=$4 hdr="" bin runs dur hook="" kinds="sw" keep=0 raw line rc try rps okstart=0
	local variant="" vbin=new venv=() def
	case $label in
	rimu-*) server=rimu; hdr=${label#rimu-}; keep=1 ;;
	v-*)
		# a variant of variants.txt: rimu with its ARENA_H3_* settings, on the new build or the one before task 16
		variant=${label#v-}; server=rimu; hdr=min; keep=1
		def=$(variant_def "$variant") || { echo "  unknown variant $variant"; return 1; }
		read -r _ _ vbin venv_s <<<"$def"
		read -r -a venv <<<"${venv_s:-}"
		;;
	esac
	case $kind in
	bench) bin=$BIN_BENCH; runs=$BENCH_RUNS; dur=$BENCH_D ;;
	vbench) bin=$BIN_BENCH; [ "$vbin" = prev ] && bin=$BIN_PREV; runs=$BENCH_RUNS; dur=$BENCH_D ;;
	profile)
		bin=$BIN_PROF; dur=$PROF_D; hook=$K/prof-hook.sh
		[ "$server" = rimu ] && [ "$PMU" = yes ] && kinds="sw hwstat topdown lbr cachemiss"
		;;
	vprofile)
		bin=$BIN_PROF; [ "$vbin" = prev ] && bin=$BIN_PREV_PROF; dur=$PROF_D; hook=$K/prof-hook.sh
		[ "$PMU" = yes ] && kinds="sw hwstat"
		;;
	hw) bin=$BIN_HW; dur=$PROF_D; hook=$K/prof-hook.sh; kinds="hwstat topdown lbr cachemiss" ;;
	esac
	[ -n "$hook" ] && runs=$(wc -w <<<"$kinds")
	raw=$O/raw/$kind/$label-$prof-p$pass
	mkdir -p "$raw"
	for try in 1 2; do
		echo "$(date -u +%FT%TZ) $kind p$pass $prof $label try $try $(uptime)" >>"$O/uptime.log"
		rm -f "$WORK"/h3bench/h3load-"$server"-"$prof"-*.txt "$WORK/h3bench/server-$server-$prof.log"
		if [ -n "$hook" ] && [ -d "$O/$kind/$label-$prof" ]; then mv "$O/$kind/$label-$prof" "$O/$kind/$label-$prof-failed-$(date +%s)"; fi
		line=$(env SERVER_CPUS="$SCPU" LOAD_CPUS="$LCPU" LOAD_THREADS="$LT" ARENA="$ARENA" ARENA_BIN="$bin" \
			GEN_HOSTS="$ARENA/hosts-v4" TMPDIR="$WORK" RUNS="$runs" DURATION="$dur" ${hdr:+ARENA_H3_HEADERS=$hdr} \
			${hook:+RUN_HOOK=$hook} PROF_DIR="$O/$kind/$label-$prof" PROF_KINDS="$kinds" KEEP_DATA=$keep \
			"${venv[@]}" "$K/h3-bench.sh" "$server" "$prof" 2>>"$raw/stderr.txt")
		rc=$?
		for f in "$WORK"/h3bench/h3load-"$server"-"$prof"-*.txt; do [ -e "$f" ] && cp "$f" "$raw/try$try-${f##*/}"; done
		cp "$WORK/h3bench/server-$server-$prof.log" "$raw/server-try$try.log" 2>/dev/null
		rps=$(sed -n 's/.*"rps":\([0-9]*\).*/\1/p' <<<"$line")
		if [ $rc = 0 ] && [ "${rps:-0}" -gt 0 ]; then okstart=1; break; fi
		echo "  FAILED start: $kind p$pass $prof $label try $try (exit $rc, rps ${rps:-none}): $(tail -2 "$raw/stderr.txt" | tr '\n' ' ')"
		sleep 3
	done
	local vfield=""
	[ -n "$variant" ] && vfield=",\"variant\":\"$variant\",\"binary\":\"$vbin\""
	if [ $okstart = 1 ]; then
		line="${line%\}}$vfield,\"label\":\"$label\",\"pass\":$pass,\"try\":$try,\"ts\":\"$(date -u +%FT%TZ)\"}"
	else
		line="{\"server\":\"$server\",\"profile\":\"$prof\"${hdr:+,\"headers\":\"$hdr\"}$vfield,\"label\":\"$label\",\"pass\":$pass,\"failed\":true,\"ts\":\"$(date -u +%FT%TZ)\"}"
	fi
	echo "$line" >>"$O/$kind.jsonl"
	sed -E 's/.*"rps":([0-9]+),"server_cpu_us_per_req":([^,]*),"gen_cpu_us_per_req":([^,]*),"errors":([0-9]+),"runs":\[([^]]*)\].*/\1 \2 \3 \4 \5/' <<<"$line" |
		awk -v k="$kind" -v p="$pass" -v pr="$prof" -v l="$label" -v ok=$okstart '{ if (!ok) { printf "%s p%s %-11s %-9s FAILED\n", k, p, pr, l; exit }
			printf "%s p%s %-11s %-9s rps %8d | srv %s us/req gen %s | errors %s | runs %s\n", k, p, pr, l, $1, $2, $3, $4, $5 }'
	[ $okstart = 1 ]
}

# --- phase V: the variants of variants.txt
variant_def() { # name: its line of variants.txt (name profiles binary settings...), or fails
	awk -v n="$1" '!/^#/ && $1 == n { print; f = 1; exit } END { exit !f }' "$VARIANT_FILE"
}
default_variants() { # the names above the "Not in the default list" line, in their order
	awk '/^# Not in the default list/ { exit } !/^#/ && NF { printf "%s ", $1 }' "$VARIANT_FILE"
}
variant_runs_on() { # name profile: if the variant runs on that profile
	local def p
	def=$(variant_def "$1") || return 1
	read -r _ p _ <<<"$def"
	[ "$p" = both ] || [ "$p" = "$2" ]
}
ref_runs_on() { # ref profile: if the reference (VREF: a server, or server@profile for one profile only) runs on it
	case $1 in
	*@*) [ "${1#*@}" = "$2" ] ;;
	*) return 0 ;;
	esac
}
rotated() { # pass words...: the words rotated by (pass - 1) x n / PASSES, so that each word takes a different
	# place in each pass, spread over the order (a rotation by one would move every word by one place only)
	local pass=$1 n i stride
	shift
	n=$#
	local -a w=("$@")
	stride=$((n / ${PASSES:-1}))
	[ "$stride" -ge 1 ] || stride=1
	for ((i = 0; i < n; i++)); do echo "${w[$(((i + (pass - 1) * stride) % n))]}"; done
}
variants() {
	reset_box
	limits
	[ -s "$O/host.txt" ] || hostinfo >"$O/host.txt" 2>&1
	local list=${VARIANTS:-$(default_variants)} prof_list=${VPROF-"base prev"} v s r pass prof t0=$SECONDS starts=0
	for v in $list $prof_list; do
		variant_def "$v" >/dev/null || { echo "unknown variant $v (VARIANT_FILE=$VARIANT_FILE)"; return 2; }
	done
	for pass in $(seq 1 "$PASSES"); do
		for prof in $PROFILES; do
			for v in $list; do variant_runs_on "$v" "$prof" && starts=$((starts + 1)); done
			for v in $VREF; do ref_runs_on "$v" "$prof" && starts=$((starts + 1)); done
		done
	done
	echo "== variants: $list (reference: ${VREF:-none}) x $PROFILES x $PASSES passes = $starts starts, $BENCH_RUNS x $BENCH_D per start; then profiles of $prof_list; server $SCPU, generator $LCPU (-t $LT); $(date -u +%T)"
	for pass in $(seq 1 "$PASSES"); do
		for prof in $PROFILES; do
			# shellcheck disable=SC2046 # one word per reference
			for s in $(rotated "$pass" $list $(for v in $VREF; do echo "ref:$v"; done)); do
				case $s in
				ref:*)
					r=${s#ref:}
					ref_runs_on "$r" "$prof" && { one_start vbench "$pass" "$prof" "${r%@*}" || true; }
					;;
				*) variant_runs_on "$s" "$prof" && { one_start vbench "$pass" "$prof" "v-$s" || true; } ;;
				esac
			done
		done
		echo "== pass $pass done $(date -u +%T) ($((SECONDS - t0)) s)"
	done
	if [ -n "$prof_list" ]; then
		caps
		echo "== variant profiles: $prof_list x ${VPROF_PROFILES:-$PROFILES}, $PROF_D runs, window +${WIN_DELAY}s for ${WIN_LEN}s, -F $FREQ_SW; pmu=$PMU; $(date -u +%T)"
		for v in $prof_list; do
			for prof in ${VPROF_PROFILES:-$PROFILES}; do
				# A variant of one profile is profiled on that one only
				variant_runs_on "$v" "$prof" || continue
				one_start vprofile 1 "$prof" "v-$v" || true
			done
		done
	fi
	echo "== variants done $(date -u +%T) ($((SECONDS - t0)) s)"
}

servers_rotated() { # pass: SERVERS rotated by the pass, as run-t15-first.sh rotates by the round
	local -a s
	read -r -a s <<<"$SERVERS"
	local n=${#s[@]} i
	for ((i = 0; i < n; i++)); do echo "${s[$(((i + $1 - 1) % n))]}"; done
}

bench() {
	reset_box
	limits
	[ -s "$O/host.txt" ] || hostinfo >"$O/host.txt" 2>&1
	echo "== bench: $(wc -w <<<"$SERVERS") servers x $(wc -w <<<"$PROFILES") profiles x $PASSES passes, $BENCH_RUNS x $BENCH_D per start; server $SCPU, generator $LCPU (-t $LT); $(date -u +%T)"
	local t0=$SECONDS pass prof s
	for pass in $(seq 1 "$PASSES"); do
		for prof in $PROFILES; do
			for s in $(servers_rotated "$pass"); do
				one_start bench "$pass" "$prof" "$s"
			done
		done
		echo "== pass $pass done $(date -u +%T) ($((SECONDS - t0)) s)"
	done
}

profile() {
	reset_box
	limits
	caps
	echo "== profile: $SERVERS x $PROFILES, $PROF_D runs, window +${WIN_DELAY}s for ${WIN_LEN}s, -F $FREQ_SW ($SW_EVENT); pmu=$PMU; $(date -u +%T)"
	local t0=$SECONDS prof s
	# rimu first: if the time budget cuts the phase, the rivals' profiles are what is lost
	for s in $(tr ' ' '\n' <<<"$SERVERS" | grep '^rimu-'; tr ' ' '\n' <<<"$SERVERS" | grep -v '^rimu-'); do
		for prof in $PROFILES; do
			one_start profile 1 "$prof" "$s"
		done
	done
	echo "== profile done $(date -u +%T) ($((SECONDS - t0)) s)"
}

hw() {
	reset_box
	limits
	[ -s "$O/host.txt" ] || hostinfo >"$O/host.txt" 2>&1
	caps
	if [ "$PMU" != yes ]; then echo "== hw: no hardware counters on this box: nothing to do"; return 1; fi
	SERVERS=${HW_SERVERS:-"rimu-full rimu-min"}
	echo "== hw: $SERVERS x $PROFILES, $PROF_D runs, window +${WIN_DELAY}s for ${WIN_LEN}s, -F $FREQ_HW; $(date -u +%T)"
	local t0=$SECONDS prof s
	for s in $SERVERS; do
		for prof in $PROFILES; do
			one_start hw 1 "$prof" "$s"
		done
	done
	echo "== hw done $(date -u +%T) ($((SECONDS - t0)) s)"
}

h3final() { # phases C and X
	reset_box
	[ "$SMOKE" = 1 ] || tune # phase R set its own TCP sysctls; the h3 harness wants colossus' UDP ones again (never on colossus)
	limits
	[ -s "$O/host.txt" ] || hostinfo >"$O/host.txt" 2>&1
	export VPROF=${VPROF-}
	VARIANTS=${VARIANTS:-"base prev"} variants
}

leftovers() { # smoke: nothing of ours may stay
	local l c
	l=$({ ss -Hlunp 'sport = :8443'; ss -Hltnp '( sport = :8443 or sport = :8082 )'; })
	c=$(docker ps -a --format '{{.Names}}' | grep -E '^(h3bench|h3load)-' || true)
	echo "leftover listeners: ${l:-none}"
	echo "leftover containers: ${c:-none}"
	[ -z "$l" ] && [ -z "$c" ]
}

case $PHASE in
regress)
	exec env OUT="$O" bash "$K/regress.sh" full
	;;
h3final) h3final ;;
setup) setup "${2:?F}" ;;
bench) bench ;;
profile) profile ;;
hw) hw ;;
variants) variants ;;
smoke | vsmoke)
	t0=$SECONDS
	hostinfo >"$O/host.txt" 2>&1
	bash "$K/regress.sh" smoke
	echo "== regress smoke done in $((SECONDS - t0)) s"
	h3final
	echo "== smoke done in $((SECONDS - t0)) s"
	leftovers
	;;
*)
	echo "usage: $0 setup F | regress | h3final | smoke | bench | profile | hw | variants | vsmoke"
	exit 2
	;;
esac
