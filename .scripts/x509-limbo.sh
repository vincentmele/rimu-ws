#!/usr/bin/env bash

set -euxo pipefail

BACKENDS=("rimu-ws/crypto-alr rimu-ws/_hack" "rimu-ws/crypto-graviola" "rimu-ws/crypto-ring" "rimu-ws/crypto-ruco")

if [ ! -e "limbo.json" ]; then
    curl -L -o limbo.json https://raw.githubusercontent.com/C2SP/x509-limbo/3e000feb51285a8153509129a62248a6b4883181/limbo.json
fi

for backend in "${BACKENDS[@]}"; do
    echo -e "\e[0;33m***** Testing with '$backend' *****\e[0m"
    cargo run --bin x509-limbo --features "$backend x509-limbo" -p rimu-ws-internal --release
done;