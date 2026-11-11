#!/usr/bin/env bash

set -euxo pipefail

# WTX

cargo check --all-features --all-targets

# QUIC and HTTP/3 with each crypto backend. A library check, without the dev-dependencies, which
# turn `crypto-ring` on and with it the size budget of a connection
cargo check -p rimu-ws --lib --no-default-features --features quic,std,crypto-ring
cargo check -p rimu-ws --lib --no-default-features --features quic,std,crypto-ruco
cargo check -p rimu-ws --lib --no-default-features --features quic,std,crypto-alr,_hack
cargo check -p rimu-ws --lib --no-default-features --features quic,std,crypto-graviola,crypto-ruco
cargo check -p rimu-ws --lib --no-default-features --features http3,std,crypto-ruco
cargo check -p rimu-ws --lib --no-default-features --features http3-server-framework,crypto-ring
cargo check -p rimu-ws --lib --no-default-features --features http3-server-framework,crypto-ruco
# The one-shot gzip encoder, with and without std
cargo check -p rimu-ws --lib --no-default-features --features gzip-encoder
cargo check -p rimu-ws --lib --no-default-features --features std,gzip-encoder

RUSTDOCFLAGS="-Dwarnings" cargo doc --all-features
