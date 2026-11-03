#!/usr/bin/env bash

. "$(dirname "$0")/common.sh" --source-only

# WTX

$rt test-with-features rimu-ws serde
$rt test-with-features rimu-ws serde_json
$rt test-with-features rimu-ws sha3
$rt test-with-features rimu-ws simdutf8
$rt test-with-features rimu-ws std
$rt test-with-features rimu-ws tokio
$rt test-with-features rimu-ws tracing
$rt test-with-features rimu-ws tracing-subscriber
$rt test-with-features rimu-ws tracing-tree
$rt test-with-features rimu-ws uuid
$rt test-with-features rimu-ws web-socket,crypto-ring
$rt test-with-features rimu-ws rimu-ws-macros
$rt test-with-features rimu-ws x509

# WTX Macros

$rt test-generic wtx-macros

# WTX UI

$rt check-generic rimu-ws-ui
$rt test-with-features rimu-ws-ui embed-migrations
$rt test-with-features rimu-ws-ui schema-manager
$rt test-with-features rimu-ws-ui schema-manager-dev
$rt test-with-features rimu-ws-ui http-client
$rt test-with-features rimu-ws-ui web-socket
