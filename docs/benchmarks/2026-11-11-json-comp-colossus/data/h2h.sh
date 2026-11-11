#!/usr/bin/env bash
# h2h.sh: json-comp head-to-head on colossus. Servers on 0-5,12-17, gcannon on 6-10,18-22 (core 11/23 left free),
# no sysctl changes. Per pass (order rotated), per server: 4096 and 16384 connections, RUNS x 5 s, best kept.
set -u
A=/mnt/nvme1tb/claude-tmp/arena-main; O=${O:-/mnt/nvme1tb/claude-tmp/jsoncomp/h2h}; mkdir -p $O
BINS=/mnt/nvme1tb/claude-tmp/aws-final/remote/bin/regress
SERVERS=(${SERVERS:-rimu-new rimu-main viltrum plod aegon}); PASSES=${PASSES:-3}; RUNS=${RUNS:-3}
ulimit -n "$(ulimit -Hn)"
quiet() { # wait until no process outside the run uses > 50 % of a CPU (max 10 min)
  for _ in $(seq 1 60); do
    busy=$(ps -eo pcpu=,comm= --sort=-pcpu | awk '$1 > 50 && $2 !~ /^(rtk|bash|ps|awk|sleep|gcannon|arena-h1|h1|docker.*|containerd.*)$/ {print $2" "$1}' | head -3)
    [ -z "$busy" ] && return 0; echo "waiting: $busy"; sleep 10
  done; echo "machine never went quiet: $busy"; return 1
}
port_free() { for _ in $(seq 1 60); do ss -Hltn "sport = :8080" | grep -q . || return 0; sleep 0.25; done; return 1; }
start() { # server -> sets KILL
  port_free || { echo "port 8080 busy"; exit 1; }
  case $1 in
  rimu-new|rimu-main)
    bin=$BINS/B/h1; [ $1 = rimu-main ] && bin=$BINS/A/h1
    DATASET_PATH=$A/data/dataset.json taskset -c 0-5,12-17 "$bin" > $O/server-$1.log 2>&1 & sp=$!; KILL="kill $sp; wait $sp 2>/dev/null" ;;
  *)
    cid=$(docker run -d --rm --network host --cpuset-cpus 0-5,12-17 -v "$A/data:/data:ro" --ulimit nofile=1048576:1048576 httparena-$1); KILL="docker stop -t1 $cid >/dev/null" ;;
  esac
  for _ in $(seq 1 120); do curl -s -o /dev/null -H "Accept-Encoding: gzip" "http://localhost:8080/json/50?m=6" && return 0; sleep 0.25; done
  echo "$1 never answered"; eval "$KILL"; return 1
}
for pass in $(seq 1 $PASSES); do
  n=${#SERVERS[@]}; off=$(( (pass - 1) % n ))
  order=("${SERVERS[@]:$off}" "${SERVERS[@]:0:$off}")
  quiet || exit 1
  echo "== pass $pass $(date -u +%T) order ${order[*]} load $(cut -d' ' -f1-3 /proc/loadavg)"
  for s in "${order[@]}"; do
    start $s || continue
    for c in 4096 16384; do
      for r in $(seq 1 $RUNS); do
        f=$O/p$pass-$s-c$c-r$r.txt
        ( cd $A/requests && taskset -c 6-10,18-22 gcannon http://localhost:8080 --raw json-gzip-25.raw,json-gzip-40.raw,json-gzip-50.raw -c $c -t 10 -d 5s -p 1 -r 25 ) > $f 2>&1
        echo "p$pass $s c$c r$r $(grep -E 'Throughput|Bandwidth' $f | tr -s ' ' | tr '\n' ' ') $(grep -oE '2xx=[0-9]+, 3xx=[0-9]+, 4xx=[0-9]+, 5xx=[0-9]+' $f)"
        sleep 2
      done
    done
    eval "$KILL"
  done
done
echo "== done $(date -u +%T)"
