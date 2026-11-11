#!/usr/bin/env bash
set -u
A=/mnt/nvme1tb/claude-tmp/arena-main; O=/mnt/nvme1tb/claude-tmp/jsoncomp/profile; mkdir -p $O
BIN=${BIN:-/mnt/nvme1tb/claude-tmp/aws-final/remote/bin/regress/B/h1}
for _ in $(seq 1 40); do ss -Hltn "sport = :8080" | grep -q . || break; sleep 0.25; done
DATASET_PATH=$A/data/dataset.json taskset -c 0-5,12-17 "$BIN" > $O/server.log 2>&1 & sp=$!
for _ in $(seq 1 120); do curl -s -o /dev/null -H "Accept-Encoding: gzip" "http://localhost:8080/json/50?m=6" && break; sleep 0.25; done
( cd $A/requests && taskset -c 6-10,18-22 gcannon http://localhost:8080 --raw json-gzip-25.raw,json-gzip-40.raw,json-gzip-50.raw -c 4096 -t 10 -d 12s -p 1 -r 25 ) > $O/load.txt 2>&1 & lp=$!
sleep 4
perf record -F 999 -g -p $sp -o $O/perf.data -- sleep 5 > $O/perf-record.log 2>&1
wait $lp
kill $sp; wait $sp 2>/dev/null
perf report -i $O/perf.data --no-children --sort dso,symbol --stdio 2>/dev/null | grep -v '^#' | grep -v '^$' | head -60 > $O/top.txt
perf report -i $O/perf.data --no-children --sort symbol --stdio 2>/dev/null | grep -E '^ +[0-9.]+%' > $O/symbols.txt
