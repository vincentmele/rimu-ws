#!/usr/bin/env bash
# ab.sh: h1 A/B of rimu-ws-h1, A = rimu-ws HEAD ef0f7abb, B = working tree (conformance fixes).
# Servers on 0-5,12-17, gcannon on 6-10,18-22 (core 11/23 left free), no sysctl changes.
# Per pass (order A,B then B,A), per build, per profile: RUNS x 5 s, best kept; server cpu from /proc.
set -u
R=/mnt/nvme1tb/claude-tmp/rimu-review/ab; A=/mnt/nvme1tb/claude-tmp/rimu-review/arena
O=${O:-$R/out}; mkdir -p $O; PASSES=${PASSES:-4}; RUNS=${RUNS:-3}
ulimit -n "$(ulimit -Hn)"
TICK=$(getconf CLK_TCK)
quiet() { # until no process outside the run uses > 50 % of a CPU (max 45 min)
  for _ in $(seq 1 270); do
    busy=$(ps -eo pcpu=,comm= --sort=-pcpu | awk '$1 > 50 && $2 !~ /^(rtk|bash|ps|awk|sleep|gcannon|httparena-rimu-w.*)$/ {print $2" "$1}' | head -3)
    [ -z "$busy" ] && return 0; echo "waiting: $(echo $busy | tr '\n' ' ') load $(cut -d' ' -f1-3 /proc/loadavg)"; sleep 10
  done; echo "machine never went quiet: $busy"; return 1
}
port_free() { for _ in $(seq 1 60); do ss -Hltn "sport = :8080" | grep -q . || return 0; sleep 0.25; done; return 1; }
cpu_ticks() { awk '{print $14 + $15}' /proc/$1/stat; }
declare -A PROF=(
  [baseline]="--raw get.raw,post_cl.raw,post_chunked.raw -c 4096 -t 10 -d 5s -p 1"
  [limited-conn]="--raw get.raw,post_cl.raw,post_chunked.raw -c 4096 -t 10 -d 5s -p 1 -r 10"
  [json-comp]="--raw json-gzip-25.raw,json-gzip-40.raw,json-gzip-50.raw -c 4096 -t 10 -d 5s -p 1 -r 25"
)
for pass in $(seq 1 $PASSES); do
  if [ $((pass % 2)) = 1 ]; then order="A B"; else order="B A"; fi
  quiet || exit 1
  echo "== pass $pass $(date -u +%T) order $order load $(cut -d' ' -f1-3 /proc/loadavg)"
  for v in $order; do
    port_free || { echo "port 8080 busy"; exit 1; }
    DATASET_PATH=$A/data/dataset.json taskset -c 0-5,12-17 $R/target-$v/release/httparena-rimu-ws-h1 > $O/server-$v-p$pass.log 2>&1 & sp=$!
    for _ in $(seq 1 120); do curl -s -o /dev/null "http://localhost:8080/baseline11?a=1&b=2" && break; sleep 0.25; done
    for p in baseline limited-conn json-comp; do
      for r in $(seq 1 $RUNS); do
        f=$O/p$pass-$v-$p-r$r.txt
        c0=$(cpu_ticks $sp)
        ( cd $A/requests && taskset -c 6-10,18-22 gcannon http://localhost:8080 ${PROF[$p]} ) > $f 2>&1
        c1=$(cpu_ticks $sp)
        echo "cpu_ticks $((c1 - c0)) tick $TICK" >> $f
        echo "p$pass $v $p r$r $(grep -E 'Throughput' $f | tr -s ' ' | tr '\n' ' ') cpu_s $(awk -v d=$((c1 - c0)) -v t=$TICK 'BEGIN{printf "%.2f", d/t}') $(grep -oE '2xx=[0-9]+, 3xx=[0-9]+, 4xx=[0-9]+, 5xx=[0-9]+' $f)"
        sleep 2
      done
    done
    kill $sp; wait $sp 2>/dev/null
  done
done
echo "== done $(date -u +%T) load $(cut -d' ' -f1-3 /proc/loadavg)"
