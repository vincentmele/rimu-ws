#!/usr/bin/env bash
# ab-tls.sh: TLS h1 A/B of rimu-ws-h1 with wrk, A = rimu-ws ef0f7abb (before the conformance work),
# B = main 37e36643. Servers on 0-5,12-17, wrk on 6-10,18-22 (core 11/23 left free), no sysctl
# changes. Per pass (order A,B then B,A), per build, per profile: RUNS x 5 s, best kept; server cpu
# from /proc.
set -u
R=/mnt/nvme1tb/claude-tmp/rimu-review/ab; HA=${HA:-$HOME/src/HttpArena}
O=${O:-$R/out-tls}; mkdir -p $O; PASSES=${PASSES:-4}; RUNS=${RUNS:-3}
ulimit -n "$(ulimit -Hn)"
TICK=$(getconf CLK_TCK)
quiet() { # until no process outside the run uses > 50 % of a CPU (max 45 min)
  for _ in $(seq 1 270); do
    busy=$(ps -eo pcpu=,comm= --sort=-pcpu | awk '$1 > 50 && $2 !~ /^(rtk|bash|ps|awk|sleep|wrk|httparena-rimu-w.*)$/ {print $2" "$1}' | head -3)
    [ -z "$busy" ] && return 0; echo "waiting: $(echo $busy | tr '\n' ' ') load $(cut -d' ' -f1-3 /proc/loadavg)"; sleep 10
  done; echo "machine never went quiet: $busy"; return 1
}
port_free() { for _ in $(seq 1 60); do ss -Hltn "sport = :8081" | grep -q . || return 0; sleep 0.25; done; return 1; }
cpu_ticks() { awk '{print $14 + $15}' /proc/$1/stat; }
declare -A PROF=(
  [json-tls]="-t 10 -c 4096 -d 5s -s $HA/requests/json-tls-rotate.lua https://localhost:8081"
  [8gbit]="-t 10 -c 512 -d 5s -s $HA/requests/8gbit-rotate.lua https://localhost:8081"
)
for pass in $(seq 1 $PASSES); do
  if [ $((pass % 2)) = 1 ]; then order="A B"; else order="B A"; fi
  quiet || exit 1
  echo "== pass $pass $(date -u +%T) order $order load $(cut -d' ' -f1-3 /proc/loadavg)"
  for v in $order; do
    port_free || { echo "port 8081 busy"; exit 1; }
    CERT_DIR=$HA/certs DATASET_PATH=$HA/data/dataset.json taskset -c 0-5,12-17 $R/target-$v/release/httparena-rimu-ws-h1 > $O/server-$v-p$pass.log 2>&1 & sp=$!
    for _ in $(seq 1 120); do curl -sk -o /dev/null "https://localhost:8081/baseline11?a=1&b=2" && break; sleep 0.25; done
    for p in json-tls 8gbit; do
      for r in $(seq 1 $RUNS); do
        f=$O/p$pass-$v-$p-r$r.txt
        c0=$(cpu_ticks $sp)
        ( cd $HA/requests && taskset -c 6-10,18-22 wrk ${PROF[$p]} ) > $f 2>&1
        c1=$(cpu_ticks $sp)
        echo "cpu_ticks $((c1 - c0)) tick $TICK" >> $f
        reqs=$(grep -oP '(\d+) requests in' $f | grep -oP '^\d+')
        echo "p$pass $v $p r$r rps $(grep -oP 'Requests/sec:\s+\K[\d.]+' $f) reqs $reqs cpu_s $(awk -v d=$((c1 - c0)) -v t=$TICK 'BEGIN{printf "%.2f", d/t}') non2xx $(grep -oP 'Non-2xx or 3xx responses: \K\d+' $f || echo 0) sockerr $(grep -oP 'Socket errors: \K.*' $f | tr -d ' ' || echo none)"
        sleep 2
      done
    done
    kill $sp; wait $sp 2>/dev/null
  done
done
echo "== done $(date -u +%T) load $(cut -d' ' -f1-3 /proc/loadavg)"
