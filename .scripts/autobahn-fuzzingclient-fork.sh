#!/usr/bin/env bash

# The full fuzzingclient suite against the drain-API server and the io_uring server (with and
# without direct descriptors). Fails if any case fails.

set -euxo pipefail

CONTAINER=${CONTAINER:-podman}

run() {
	local name=$1 feature=$2
	shift 2
	cargo build --bin "$feature" --features "$feature" --release
	env "$@" ./target/release/"$feature" & server_pid=$!
	sleep 1
	mkdir -p .scripts/autobahn/reports/"$name"
	sed "s|/autobahn/reports/fuzzingclient|/autobahn/reports/$name|; s|\"wtx\"|\"$name\"|" \
		.scripts/autobahn/fuzzingclient.json > .scripts/autobahn/"$name".json
	$CONTAINER run \
		-v .scripts/autobahn/"$name".json:/fuzzingclient.json:z \
		-v .scripts/autobahn:/autobahn:z \
		--name fuzzingclient \
		--network host \
		--rm \
		docker.io/crossbario/autobahn-testsuite:25.10.1 wstest -m fuzzingclient -s fuzzingclient.json
	kill -9 $server_pid
	rm .scripts/autobahn/"$name".json
	if [ $(grep -ci "failed" .scripts/autobahn/reports/"$name"/index.json) -gt 0 ]
	then
		exit 1
	fi
}

run drain autobahn-server-drain
run uring autobahn-server-uring
run uring-direct autobahn-server-uring WTX_DIRECT=1024
