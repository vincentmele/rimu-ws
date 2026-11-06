#!/usr/bin/env bash

# HTTP/2 interop against a server that serves /baseline2 (sum of a and b).
#
#   h2-interop.sh URL_H2C URL_TLS
#
# e.g. h2-interop.sh http://127.0.0.1:8082 https://127.0.0.1:8443. Runs curl (prior knowledge and
# TLS), nghttp (from the httparena-h2load image) and the Go client in .scripts/h2-interop-go.
# Exits non-zero if any client gets a wrong body or a protocol error. Pass "-" to skip a URL.

set -uo pipefail

h2c=${1:?URL_H2C}
tls=${2:?URL_TLS}
dir=$(cd "$(dirname "$0")" && pwd)
go=${GO:-$(command -v go || echo /usr/local/go/bin/go)}
fails=0

check() {
	local name=$1 want=$2 got=$3
	if [ "$got" = "$want" ]; then
		echo "ok   $name"
	else
		echo "FAIL $name: got '$got', want '$want'"
		fails=$((fails + 1))
	fi
}

curl_series() {
	local name=$1
	shift
	# 20 requests over one connection: curl reuses it for every URL on the command line.
	local urls=() i
	for i in $(seq 1 20); do
		urls+=("$base/baseline2?a=$i&b=1")
	done
	local got
	got=$(curl -s --fail-with-body "$@" -w '%{http_version} ' "${urls[@]}" 2>&1 | tr -d '\n')
	local want="" i2
	for i2 in $(seq 1 20); do
		want+="$((i2 + 1))2 "
	done
	check "$name" "$want" "$got"
}

nghttp_series() {
	local name=$1 url=$2
	# Three requests over one connection. nghttp's exit code does not reflect a refused connection,
	# so count the 200 responses in its verbose output.
	local got
	got=$(docker run --rm --network host --entrypoint nghttp httparena-h2load -nv \
		"$url/baseline2?a=1&b=1" "$url/baseline2?a=2&b=2" "$url/baseline2?a=3&b=3" 2>&1 |
		grep -c ':status: 200')
	check "$name" 3 "$got"
}

go_client() {
	local name=$1 url=$2
	(cd "$dir/h2-interop-go" && "$go" run . "$url" >/dev/null 2>&1)
	check "$name" 0 $?
}

if [ "$h2c" != - ]; then
	base=$h2c
	curl_series "curl h2c" --http2-prior-knowledge
	nghttp_series "nghttp h2c" "$h2c"
	go_client "go h2c" "$h2c"
fi
if [ "$tls" != - ]; then
	base=$tls
	curl_series "curl h2 tls" --http2 -k
	nghttp_series "nghttp h2 tls" "$tls"
	go_client "go h2 tls" "$tls"
fi
if [ $fails -gt 0 ]; then
	echo "$fails interop check(s) failed"
	exit 1
fi
echo "all interop checks passed"
