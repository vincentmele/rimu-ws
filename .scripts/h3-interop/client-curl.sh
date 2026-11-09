#!/usr/bin/env bash

# The curl scenarios of h3-interop.sh, run inside the rimu-h3-interop-curl image (curl on ngtcp2,
# nghttp3 and quictls). Prints "ok NAME" or "FAIL NAME: why" per scenario; exits non-zero if any
# failed. Every request has a 5 s limit (ruling T21-d).
#
#   ADDR=127.0.0.1:8443 CA=/certs/server.crt STATIC=/data/static [SEQ=1000] [PAR=64] client-curl.sh

set -uo pipefail

addr=${ADDR:?ADDR}
ca=${CA:?CA}
static=${STATIC:?STATIC}
seq=${SEQ:-1000}
par=${PAR:-64}
post_bytes=${POST_BYTES:-1048576}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0

# curl with the options of every request
c() {
	curl --http3-only -sS --max-time 5 --cacert "$ca" "$@"
}

report() {
	local name=$1 why=${2:-}
	if [ -z "$why" ]; then
		echo "ok $name"
	else
		echo "FAIL $name: $why"
		fails=$((fails + 1))
	fi
}

baseline() {
	local got
	got=$(c -w ' %{http_code}' "https://$addr/baseline2?a=1&b=2" 2>&1)
	[ "$got" = "3 200" ] || { echo "got '$got'"; return; }
}

static_files() {
	local f enc want coding
	for f in $(cd "$static" && ls | grep -v -E '\.(br|gz)$' | sort); do
		for enc in br gzip identity; do
			want=$f coding=
			case $enc in
			br) [ -e "$static/$f.br" ] && want=$f.br coding=br ;;
			gzip) [ -e "$static/$f.gz" ] && want=$f.gz coding=gzip ;;
			esac
			if ! c -H "Accept-Encoding: $enc" -D "$work/h" -o "$work/b" -w '%{http_code}' \
				"https://$addr/static/$f" >"$work/code" 2>"$work/err"; then
				echo "$f ($enc): $(cat "$work/err")"
				return
			fi
			[ "$(cat "$work/code")" = 200 ] || { echo "$f ($enc): status $(cat "$work/code")"; return; }
			got=$(tr -d '\r' <"$work/h" | grep -i '^content-encoding:' | awk '{print tolower($2)}')
			[ "$got" = "$coding" ] || { echo "$f ($enc): content-encoding '$got', want '$coding'"; return; }
			cmp -s "$work/b" "$static/$want" || { echo "$f ($enc): body differs from $want"; return; }
		done
	done
}

post_echo() {
	head -c "$post_bytes" /dev/urandom >"$work/up"
	if ! c --data-binary @"$work/up" -H 'Content-Type: application/octet-stream' -o "$work/down" \
		-w '%{http_code}' "https://$addr/echo" >"$work/code" 2>"$work/err"; then
		echo "$(cat "$work/err")"
		return
	fi
	[ "$(cat "$work/code")" = 200 ] || { echo "status $(cat "$work/code")"; return; }
	cmp -s "$work/up" "$work/down" || echo "echoed body differs ($(stat -c %s "$work/down") bytes of $post_bytes)"
}

# One curl, N URLs: curl sends them one after the other on one connection, and says in
# `num_connects` (1 for the request that connected, 0 after) whether it reused it.
sequential() {
	if ! c -w ' %{http_code} %{num_connects}\n' "https://$addr/baseline2?a=[1-$seq]&b=1" \
		>"$work/seq" 2>"$work/err"; then
		echo "$(cat "$work/err")"
		return
	fi
	local want
	want=$(awk -v n="$seq" 'BEGIN { for (i = 1; i <= n; i++) printf "%d 200 %d\n", i + 1, (i == 1 ? 1 : 0) }')
	if [ "$(cat "$work/seq")" != "$want" ]; then
		echo "answers differ: $(diff <(cat "$work/seq") <(echo "$want") | head -3 | tr '\n' ' ')"
	fi
}

parallel() {
	local pids=() i
	for i in $(seq 1 "$par"); do
		c "https://$addr/baseline2?a=$i&b=[1-5]" -w '\n' >"$work/p$i" 2>"$work/pe$i" &
		pids+=($!)
	done
	for i in $(seq 1 "$par"); do
		if ! wait "${pids[$((i - 1))]}"; then
			echo "connection $i: $(cat "$work/pe$i")"
			return
		fi
		local want
		want=$(for b in 1 2 3 4 5; do printf '%d\n' $((i + b)); done | tr -d '\n')
		[ "$(tr -d '\n' <"$work/p$i")" = "$want" ] || { echo "connection $i: got '$(tr -d '\n' <"$work/p$i")' want '$want'"; return; }
	done
}

for scenario in baseline static_files post_echo sequential parallel; do
	name=${scenario//_files/}
	[ "$scenario" = post_echo ] && name=post-1mib
	report "$name" "$($scenario)"
done
[ "$fails" -eq 0 ]
