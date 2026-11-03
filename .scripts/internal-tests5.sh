#!/usr/bin/env bash

set -euxo pipefail

MIRIFLAGS="-Zmiri-disable-isolation" cargo miri test --features http2,postgres,web-socket -p rimu-ws

pushd wtx-macros-tests
cargo run