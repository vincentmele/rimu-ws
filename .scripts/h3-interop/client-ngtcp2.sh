#!/usr/bin/env bash

# The scenarios of h3-interop.sh for the example client of ngtcp2 (qtlsclient, installed as
# `client`), run inside the rimu-h3-interop-curl image. Prints "ok NAME" or "FAIL NAME: why" per
# scenario; exits non-zero if any failed.
#
#   ADDR=127.0.0.1:8443 STATIC=/data/static [SEQ=1000] [PAR=64] client-ngtcp2.sh
#
# What this client cannot do (ruling T21-e: noted, not worked around):
#   * it sends no Accept-Encoding and has no option to: `static` asks for the identity coding only
#     (br and gzip are covered by curl and quic-go);
#   * it does not verify the server's certificate (no option for it);
#   * it opens all the streams of its URIs as soon as the server's stream limit allows, so the
#     1,000 requests of `sequential` share one connection but are not strictly one at a time.
# The 5 s limit of ruling T21-d is the longest gap between two finished streams (the first from the
# start of the client), measured here from the lines that the client prints.
#
# In addition: `key-update` sends the 1 MiB POST of a client that changes its keys (--key-update)
# while the server holds the stream, to follow the key phase flip of RFC 9001 section 6.

set -uo pipefail

addr=${ADDR:?ADDR}
static=${STATIC:?STATIC}
seq=${SEQ:-1000}
par=${PAR:-64}
post_bytes=${POST_BYTES:-1048576}
host=${addr%:*}
host=${host#[}
host=${host%]}
port=${addr##*:}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0
stall_us=5000000

report() {
	local name=$1 why=${2:-}
	if [ -z "$why" ]; then
		echo "ok $name"
	else
		echo "FAIL $name: $why"
		fails=$((fails + 1))
	fi
}

# ng DIR [client options] -- URI...: one connection that requests the URIs and saves the answers in
# DIR (a file per URI, named after its last path component). Writes DIR.events: the time in
# microseconds and each line that tells of a status or of a closed stream. Returns the status of
# the client, 124 if it ran for more than 60 s.
ng() {
	local out=$1
	shift
	local opts=()
	while [ "$1" != -- ]; do
		opts+=("$1")
		shift
	done
	shift
	mkdir -p "$out"
	start_us=${EPOCHREALTIME/./}
	(
		cd "$out" || exit 1
		timeout 60 stdbuf -oL -eL client --no-quic-dump --no-http-dump --exit-on-all-streams-close \
			--timeout=5s --download="$out" "${opts[@]}" "$host" "$port" "$@" 2>&1
		echo "exit $?" >"$out.exit"
	) | grep --line-buffered -E '\[:status: |closed with error codes|handshake' |
		while IFS= read -r line; do
			printf '%s %s\n' "${EPOCHREALTIME/./}" "$line"
		done >"$out.events"
	return "$(sed -n 's/^exit //p' "$out.exit" 2>/dev/null || echo 1)"
}

# check DIR N: what the events say about N requests that were all answered with 200.
check() {
	local out=$1 n=$2
	local ok bad got
	got=$(grep -c '\[:status: 200\]' "$out.events")
	[ "$got" -eq "$n" ] || { echo "$got of $n answers with status 200 ($(grep -c ':status:' "$out.events") with a status)"; return; }
	ok=$(grep -c 'closed with error codes (RX:(no error), TX:(no error))' "$out.events")
	bad=$(grep -c 'closed with error codes' "$out.events")
	[ "$ok" -eq "$n" ] && [ "$bad" -eq "$n" ] || { echo "$ok of $n streams closed without error ($bad closed)"; return; }
	awk -v start="$start_us" -v limit="$stall_us" '
		/closed with error codes/ { if ($1 - last > limit) { printf "stall of %.1f s\n", ($1 - last) / 1e6; exit } last = $1 }
		BEGIN { last = start }' "$out.events"
}

baseline() {
	local out=$work/baseline
	ng "$out" -- "https://$addr/baseline2?a=1&b=2" || { echo "client status $?"; return; }
	local why
	why=$(check "$out" 1)
	[ -z "$why" ] || { echo "$why"; return; }
	[ "$(cat "$out/baseline2?a=1&b=2")" = 3 ] || echo "body '$(cat "$out/baseline2?a=1&b=2")'"
}

static_files() {
	local out=$work/static f uris=()
	for f in $(cd "$static" && ls | grep -v -E '\.(br|gz)$' | sort); do
		uris+=("https://$addr/static/$f")
	done
	ng "$out" -- "${uris[@]}" || { echo "client status $?"; return; }
	local why
	why=$(check "$out" "${#uris[@]}")
	[ -z "$why" ] || { echo "$why"; return; }
	for f in $(cd "$static" && ls | grep -v -E '\.(br|gz)$'); do
		cmp -s "$out/$f" "$static/$f" || { echo "$f (identity): body differs"; return; }
	done
}

post_echo() {
	local out=$work/echo
	head -c "$post_bytes" /dev/urandom >"$work/up"
	ng "$out" -m POST --data="$work/up" -- "https://$addr/echo" || { echo "client status $?"; return; }
	local why
	why=$(check "$out" 1)
	[ -z "$why" ] || { echo "$why"; return; }
	cmp -s "$out/echo" "$work/up" || echo "echoed body differs ($(stat -c %s "$out/echo") bytes of $post_bytes)"
}

key_update() {
	local out=$work/keyupdate
	head -c "$post_bytes" /dev/urandom >"$work/up"
	# The request goes 100 ms after the handshake, the key update 30 ms after it
	ng "$out" --key-update=30ms --delay-stream=100ms -m POST --data="$work/up" -- "https://$addr/echo" ||
		{ echo "client status $?"; return; }
	local why
	why=$(check "$out" 1)
	[ -z "$why" ] || { echo "$why"; return; }
	cmp -s "$out/echo" "$work/up" || echo "echoed body differs ($(stat -c %s "$out/echo") bytes of $post_bytes)"
}

sequential() {
	local out=$work/seq i uris=()
	for i in $(seq 1 "$seq"); do
		uris+=("https://$addr/baseline2?a=$i&b=1")
	done
	ng "$out" -- "${uris[@]}" || { echo "client status $?"; return; }
	local why
	why=$(check "$out" "$seq")
	[ -z "$why" ] || { echo "$why"; return; }
	for i in $(seq 1 "$seq"); do
		[ "$(cat "$out/baseline2?a=$i&b=1")" = "$((i + 1))" ] || { echo "request $i: body '$(cat "$out/baseline2?a=$i&b=1")'"; return; }
	done
}

parallel() {
	local pids=() i b uris
	for i in $(seq 1 "$par"); do
		uris=()
		for b in 1 2 3 4 5; do
			uris+=("https://$addr/baseline2?a=$i&b=$b")
		done
		ng "$work/par$i" -- "${uris[@]}" &
		pids+=($!)
	done
	for i in $(seq 1 "$par"); do
		wait "${pids[$((i - 1))]}" || { echo "connection $i: client status $?"; return; }
	done
	for i in $(seq 1 "$par"); do
		# `start_us` is shared by the subshells' parent, so the stall is checked against the first
		# event of the connection instead of the start of the scenario
		local n ok
		n=$(grep -c '\[:status: 200\]' "$work/par$i.events")
		ok=$(grep -c 'closed with error codes (RX:(no error), TX:(no error))' "$work/par$i.events")
		[ "$n" -eq 5 ] && [ "$ok" -eq 5 ] || { echo "connection $i: $n answers, $ok streams closed cleanly"; return; }
		for b in 1 2 3 4 5; do
			[ "$(cat "$work/par$i/baseline2?a=$i&b=$b")" = "$((i + b))" ] || { echo "connection $i request $b: wrong body"; return; }
		done
		awk -v limit="$stall_us" '
			/closed with error codes/ { if (last && $1 - last > limit) { printf "connection stalled %.1f s\n", ($1 - last) / 1e6; exit } last = $1 }' \
			"$work/par$i.events" | grep . && return
	done
}

for scenario in baseline static_files post_echo key_update sequential parallel; do
	name=${scenario//_files/}
	case $scenario in
	post_echo) name=post-1mib ;;
	key_update) name=key-update ;;
	esac
	report "$name" "$($scenario)"
done
[ "$fails" -eq 0 ]
