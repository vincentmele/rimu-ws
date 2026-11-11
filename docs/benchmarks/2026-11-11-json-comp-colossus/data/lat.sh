#!/usr/bin/env bash
# lat.sh LABEL RATE  (BIN=path | IMG=image): fixed-rate zrk against one server (cores 0-5,12-17),
# zrk on 6-11,18-23. Reports server cyc/req + rate_ratio + mean/p50/p99 + connect-error rate.
set -uo pipefail
label=$1; rate=$2
A=/mnt/nvme1tb/claude-tmp/arena-main; W=/mnt/nvme1tb/claude-tmp/jsoncomp/lat
SVC=0-5,12-17; CLI=6-10,18-22
cid=""; sp=""
if [ -n "${IMG:-}" ]; then
  cid=$(docker run -d --rm --network host --cpuset-cpus $SVC -v "$A/data:/data:ro" --ulimit nofile=1048576:1048576 "$IMG")
  stop(){ docker stop -t1 "$cid" >/dev/null 2>&1 || true; }
else
  ARENA_LOG_ERRORS=1 DATASET_PATH=$A/data/dataset.json taskset -c $SVC "${BIN:?}" >$W/lsrv-$label.log 2>&1 & sp=$!
  stop(){ kill $sp 2>/dev/null; sleep 1; kill -9 $sp 2>/dev/null||true; }
fi
trap stop EXIT
for _ in $(seq 1 80); do curl -s -o /dev/null "http://localhost:8080/baseline11?a=1&b=2" && break; sleep 0.25; done
docker run --rm --network host --cpuset-cpus $CLI zrk:local -t 10 -c 1024 -d 14s -R $rate --format json --plain "http://localhost:8080/baseline11?a=1&b=2" >$W/zrk-$label.json 2>/dev/null &
zp=$!; sleep 4
perf stat -x, -e cycles:u,cycles:k -C $SVC -o $W/lstat-$label.csv -- sleep 6 2>/dev/null
wait $zp || true
python3 - "$W/zrk-$label.json" "$W/lstat-$label.csv" "$label" "$rate" <<'PY'
import json,sys
j=json.load(open(sys.argv[1])); st=open(sys.argv[2]).read()
lat=j["latency_us"]; req=j["requests"]; dur=j["duration_s"]
import re
def cyc(n):
  m=re.search(rf'^([0-9]+),[^\n]*{n}',st,re.M); return int(m.group(1)) if m else 0
u=cyc('cycles:u'); k=cyc('cycles:k')
# requests answered during the 6s perf window ~ achieved_rate*6
rate=j["achieved_rate"]; n=rate*6
ucyc=int(u/n) if n else 0; kcyc=int(k/n) if n else 0
print(f'{sys.argv[3]:<12} R={sys.argv[4]:<8} ratio={j["rate_ratio"]:.3f}  mean={lat["mean"]:>7.0f}us p50={lat["p50"]:>5}us p99={lat["p99"]:>6}us  cyc/req u={ucyc} k={kcyc} tot={ucyc+kcyc}  conn_err={j["errors"]["connect"]} 2xx={j["status_codes"]["2xx"]}')
PY
