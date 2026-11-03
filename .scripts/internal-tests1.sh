#!/usr/bin/env bash

. "$(dirname "$0")/common.sh" --source-only

# WTX

$rt check-generic rimu-ws
$rt test-with-features rimu-ws _bench
$rt test-with-features rimu-ws _hack
$rt test-with-features rimu-ws _integration-tests
$rt test-with-features rimu-ws _tracing-tree
$rt test-with-features rimu-ws 32-tuple-impls
$rt test-with-features rimu-ws arbitrary
$rt test-with-features rimu-ws argon2
$rt test-with-features rimu-ws asn1
$rt test-with-features rimu-ws client-api-framework
$rt test-with-features rimu-ws crossbeam-channel
$rt test-with-features rimu-ws crypto
$rt test-with-features rimu-ws crypto-alr,_hack
$rt test-with-features rimu-ws crypto-graviola
$rt test-with-features rimu-ws crypto-ring
$rt test-with-features rimu-ws database
$rt test-with-features rimu-ws database-tests
$rt test-with-features rimu-ws default
$rt test-with-features rimu-ws embassy-net,_hack
$rt test-with-features rimu-ws embassy-time,_hack
$rt test-with-features rimu-ws executor
$rt test-with-features rimu-ws foldhash
$rt test-with-features rimu-ws getrandom
$rt test-with-features rimu-ws grpc
$rt test-with-features rimu-ws grpc-client,crypto-ring