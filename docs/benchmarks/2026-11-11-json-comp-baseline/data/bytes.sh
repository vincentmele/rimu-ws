#!/usr/bin/env bash
# bytes.sh: header and body bytes of the three json-comp requests for rimu (BIN) and the rival images. No load.
set -u
A=/mnt/nvme1tb/claude-tmp/arena-main; O=${O:-/mnt/nvme1tb/claude-tmp/jsoncomp/bytes}; mkdir -p $O
BIN=${BIN:-/mnt/nvme1tb/claude-tmp/aws-final/remote/bin/regress/B/h1}
measure() { # label
  for q in "25?m=4" "40?m=8" "50?m=6"; do
    curl -s -D $O/$1-h-${q%%\?*}.txt -o $O/$1-b-${q%%\?*}.bin -H "Accept-Encoding: gzip, br" "http://localhost:8080/json/$q"
    printf '%s %s header %d body %d enc %s\n' "$1" "$q" "$(wc -c <$O/$1-h-${q%%\?*}.txt)" "$(wc -c <$O/$1-b-${q%%\?*}.bin)" "$(grep -i '^content-encoding' $O/$1-h-${q%%\?*}.txt | tr -d '\r' | cut -d' ' -f2)"
  done
}
wait_up() { for _ in $(seq 1 120); do curl -s -o /dev/null -H "Accept-Encoding: gzip" "http://localhost:8080/json/50?m=6" && return 0; sleep 0.25; done; return 1; }
ss -Hltn 'sport = :8080' | grep -q . && { echo "port 8080 busy"; exit 1; }
[ "${SKIP_RIMU:-0}" = 1 ] || { DATASET_PATH=$A/data/dataset.json taskset -c 0-5,12-17 "$BIN" > $O/rimu.log 2>&1 & sp=$!
wait_up && measure rimu; kill $sp; wait $sp 2>/dev/null; }
for img in viltrum plod aegon; do
  for _ in $(seq 1 40); do ss -Hltn "sport = :8080" | grep -q . || break; sleep 0.25; done; ss -Hltn "sport = :8080" | grep -q . && { echo "port 8080 busy"; exit 1; }
  cid=$(docker run -d --rm --network host --cpuset-cpus 0-5,12-17 -v "$A/data:/data:ro" --ulimit nofile=1048576:1048576 httparena-$img)
  wait_up && measure $img; docker stop -t1 $cid >/dev/null
done
