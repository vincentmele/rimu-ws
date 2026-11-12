#!/usr/bin/env bash
# ab-zrk.sh: paced h1 A/B of rimu-ws-h1 with zrk, HttpArena's shapes: 8gbit (POST /echo over TLS,
# 10 KiB body, 512 connections, 50,000 req/s, 5 s) and latency-10k (GET /baseline11, 1,024
# connections, 10,000 req/s, 20 s). A = rimu-ws ef0f7abb, B = main 37e36643. Servers on 0-5,12-17,
# zrk on 6-10,18-22, no sysctl changes. 4 passes (order A,B then B,A); 8gbit 3 runs per start,
# latency-10k 1; server cpu from /proc.
set -u
R=/mnt/nvme1tb/claude-tmp/rimu-review/ab; HA=${HA:-$HOME/src/HttpArena}
O=${O:-$R/out-zrk}; mkdir -p $O; PASSES=${PASSES:-4}
ulimit -n "$(ulimit -Hn)"
TICK=$(getconf CLK_TCK)
BODY=$R/echo-body.bin
python3 -c "import sys; n=10240; u=b'echo-body:'; sys.stdout.buffer.write((u*(n//len(u)+1))[:n])" > $BODY
quiet() {
  for _ in $(seq 1 270); do
    busy=$(ps -eo pcpu=,comm= --sort=-pcpu | awk '$1 > 50 && $2 !~ /^(rtk|bash|ps|awk|sleep|zrk|httparena-rimu-w.*)$/ {print $2" "$1}' | head -3)
    [ -z "$busy" ] && return 0; echo "waiting: $(echo $busy | tr '\n' ' ') load $(cut -d' ' -f1-3 /proc/loadavg)"; sleep 10
  done; echo "machine never went quiet: $busy"; return 1
}
port_free() { for _ in $(seq 1 60); do ss -Hltn "( sport = :8080 or sport = :8081 )" | grep -q . || return 0; sleep 0.25; done; return 1; }
cpu_ticks() { awk '{print $14 + $15}' /proc/$1/stat; }
run() { # pass build profile run args...
  local pass=$1 v=$2 p=$3 r=$4; shift 4
  local f=$O/p$pass-$v-$p-r$r.json c0 c1
  c0=$(cpu_ticks $sp)
  taskset -c 6-10,18-22 zrk "$@" > $f 2>$O/p$pass-$v-$p-r$r.err
  c1=$(cpu_ticks $sp)
  python3 - "$f" "$((c1 - c0))" "$TICK" "p$pass $v $p r$r" <<'PY'
import json, sys
raw = open(sys.argv[1]).read(); d = json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
lat = d.get("latency_us") or {}; codes = d.get("status_codes") or {}
done = sum(codes.get(k) or 0 for k in ("2xx", "3xx", "4xx", "5xx"))
cpu = int(sys.argv[2]) / int(sys.argv[3])
print(f"{sys.argv[4]} rate {d.get('achieved_rate', 0):.0f} ratio {d.get('rate_ratio', 0):.4f} "
      f"mean {lat.get('mean', 0):.1f} p99 {lat.get('p99', 0):.1f} p999 {lat.get('p99_9', 0):.1f} "
      f"cpu_s {cpu:.2f} cpu_us_req {cpu * 1e6 / max(done, 1):.3f} 2xx {codes.get('2xx', 0)} "
      f"non2xx {done - (codes.get('2xx') or 0)} lag_us {d.get('max_schedule_lag_us', 0)}")
PY
}
for pass in $(seq 1 $PASSES); do
  if [ $((pass % 2)) = 1 ]; then order="A B"; else order="B A"; fi
  quiet || exit 1
  echo "== pass $pass $(date -u +%T) order $order load $(cut -d' ' -f1-3 /proc/loadavg)"
  for v in $order; do
    port_free || { echo "ports busy"; exit 1; }
    CERT_DIR=$HA/certs DATASET_PATH=$HA/data/dataset.json taskset -c 0-5,12-17 $R/target-$v/release/httparena-rimu-ws-h1 > $O/server-$v-p$pass.log 2>&1 & sp=$!
    for _ in $(seq 1 120); do curl -sk -o /dev/null "https://localhost:8081/baseline11?a=1&b=2" && break; sleep 0.25; done
    for r in 1 2 3; do
      run $pass $v 8gbit $r -t 10 -c 512 -d 5s -R 50000 -m POST -b "@$BODY" \
        -H "Content-Type: application/octet-stream" -k --format json --plain "https://localhost:8081/echo"
      sleep 2
    done
    run $pass $v latency-10k 1 -t 10 -c 1024 -d 20s -R 10000 --format json --plain \
      "http://localhost:8080/baseline11?a=1&b=2"
    kill $sp; wait $sp 2>/dev/null
  done
done
echo "== done $(date -u +%T) load $(cut -d' ' -f1-3 /proc/loadavg)"
