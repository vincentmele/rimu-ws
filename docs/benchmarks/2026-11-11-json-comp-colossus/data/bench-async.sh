#!/usr/bin/env bash
# bench-async.sh LABEL (BIN=path | IMG=image): GET /delay/10 over 32000 conns, server 0-5,12-17, gcannon 6-11,18-23.
set -uo pipefail
label=$1; A=/mnt/nvme1tb/claude-tmp/arena-main; W=/mnt/nvme1tb/claude-tmp/jsoncomp/async
SVC=0-5,12-17; CLI=6-10,18-22
cid=""; sp=""
if [ -n "${IMG:-}" ]; then
  cid=$(docker run -d --rm --network host --cpuset-cpus $SVC -v "$A/data:/data:ro" --ulimit nofile=1048576:1048576 "$IMG")
  stop() { [ -n "$cid" ] && docker stop -t1 "$cid" >/dev/null 2>&1 || true; }
else
  
  DATASET_PATH=$A/data/dataset.json STATIC_DIR=$A/data/static taskset -c $SVC "${BIN:?}" > $W/server-async-$label.log 2>&1 &
  sp=$!; stop() { kill $sp 2>/dev/null; sleep 1; kill -9 $sp 2>/dev/null || true; }
fi
trap stop EXIT
for _ in $(seq 1 80); do curl -s -o /dev/null "http://localhost:8080/delay/10" && break; sleep 0.25; done
curl -s "http://localhost:8080/delay/10" || { echo "$label never answered"; exit 1; }; echo
( cd "$A/requests" && taskset -c $CLI gcannon http://localhost:8080 --raw async-delay.raw -c ${CONNS:-24000} -t 10 -d 10s -p 1 -r 0 ) > $W/load-async-$label.txt 2>&1
cat $W/load-async-$label.txt | tail -25
