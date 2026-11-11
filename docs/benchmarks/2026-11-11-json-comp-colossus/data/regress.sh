#!/usr/bin/env bash
set -u
O=/mnt/nvme1tb/claude-tmp/jsoncomp/regress; mkdir -p $O
for _ in $(seq 1 60); do
  busy=$(ps -eo pcpu=,comm= --sort=-pcpu | awk '$1 > 50 && $2 !~ /^(rtk|bash|ps|awk|sleep)$/ {print $2" "$1}' | head -3)
  [ -z "$busy" ] && break; echo "waiting: $busy"; sleep 10
done
echo "start $(date -u +%T) load $(cut -d' ' -f1-3 /proc/loadavg)"
cd /mnt/nvme1tb/claude-tmp/aws-final && env LOCAL=1 OUT=$O SCPU=0-5,12-17 LCPU=6-10,18-22 TMPDIR=/mnt/nvme1tb/claude-tmp/tmp \
  PROFILES="h1-baseline h1-jsoncomp-4096 h1-json-tls h1-8gbit" bash remote/regress.sh full > $O/regress.log 2>&1
echo "regress rc=$? $(date -u +%T)"
