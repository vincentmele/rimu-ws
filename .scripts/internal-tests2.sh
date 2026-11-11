#!/usr/bin/env bash

. "$(dirname "$0")/common.sh" --source-only

# WTX

$rt test-with-features rimu-ws grpc-server,crypto-ring
$rt test-with-features rimu-ws hashbrown
$rt test-with-features rimu-ws http
$rt test-with-features rimu-ws http2-client-pool,crypto-ring
$rt test-with-features rimu-ws http-cookie
$rt test-with-features rimu-ws http-cookie-secure
$rt test-with-features rimu-ws http-session,crypto-ring
$rt test-with-features rimu-ws http2,crypto-ring
$rt test-with-features rimu-ws http2-server-framework,crypto-ring
$rt test-with-features rimu-ws http3,web-socket,crypto-ring
$rt test-with-features rimu-ws http3-server-framework,web-socket,crypto-ring
$rt test-with-features rimu-ws httparse
$rt test-with-features rimu-ws libc
$rt test-with-features rimu-ws macros
$rt test-with-features rimu-ws memchr
$rt test-with-features rimu-ws optimizations
$rt test-with-features rimu-ws parking_lot
$rt test-with-features rimu-ws portable-atomic
$rt test-with-features rimu-ws portable-atomic-util
$rt test-with-features rimu-ws postgres
$rt test-with-features rimu-ws quick-protobuf
$rt test-with-features rimu-ws rand_core
$rt test-with-features rimu-ws rust_decimal
$rt test-with-features rimu-ws schema-manager
$rt test-with-features rimu-ws schema-manager-dev
$rt test-with-features rimu-ws secret,crypto-ring