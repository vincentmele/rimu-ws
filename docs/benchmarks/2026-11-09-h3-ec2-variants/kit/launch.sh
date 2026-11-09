#!/usr/bin/env bash
# launch.sh: the aws-h3 run on EC2 spot in sa-east-1: phase A (c6a.24xlarge, Zen 3: benchmark + software profile)
# and, if A's box has no PMU, phase B (c7i.metal-24xl, Intel bare metal: rimu's hardware counters), one box after
# the other. The kit goes over ssh (rsync --partial-dir, so a dropped connection resumes); the box installs its
# packages while the kit uploads and `docker load`s each image as soon as its part has arrived.
#
# usage: [PHASES=A|B|AB|V] [DRY=1] [TYPES_A="c6a.24xlarge c6a.16xlarge"] [TYPES_B="c7i.metal-24xl m7i.metal-24xl c5.metal"]
#        [TYPES_V="m6a.24xlarge c6a.24xlarge"] [AZS="sa-east-1a sa-east-1b sa-east-1c"] [PASSES=3] [SERVERS="..."]
#        [PROFILES="..."] [VARIANTS="..."] [VREF=zix] [VPROF="base prev"] [PROF_RESERVE=8] [FORCE_B=1] ./launch.sh
# Phase V (task 16, ruling T16-d) runs alone (PHASES=V): rimu's variants (remote/variants.txt) and the zix
# reference on a Zen 3 box like phase A's, then the profiles of VPROF; its kit is kit-common, kit-rimu-v (the
# task-16 build and the build before it) and the h2load-h3 and zix images; same safety, halt (+55) and budget
# (40 min from the moment ssh answers) as phase A.
# DRY=1 prints every AWS call (and every ssh/rsync) in order and makes none.
# Safety: aws sts get-caller-identity first; a temporary key pair and a security group open only on tcp/22 to this
# machine's IP; a one-time spot request (InstanceInterruptionBehavior=terminate); shutdown = terminate; the box halts
# itself (user-data at boot, then `shutdown -h +55` (A) / `+35` (B) as soon as ssh answers); ssh phases cut at 40 (A)
# / 20 (B) minutes from the moment ssh answers; an EXIT trap (success, failure, Ctrl-C) cancels the spot request,
# terminates the instance and waits, then deletes the security group, the key pair and the local .pem.
# Every resource is named/tagged Name=rimuh3-<epoch>, project=rimu-h3-bench (README: manual cleanup).
set -euo pipefail
S=$(cd "$(dirname "$0")" && pwd)
P=$S/parts
readonly R=sa-east-1 # the only region with the raised spot quota; never eu-west-2 (production lives there)
PHASES=${PHASES:-AB}
DRY=${DRY:-0}
TYPES_A=${TYPES_A:-"c6a.24xlarge c6a.16xlarge"}
TYPES_B=${TYPES_B:-"c7i.metal-24xl m7i.metal-24xl c5.metal"}
TYPES_V=${TYPES_V:-"m6a.24xlarge c6a.24xlarge"}
AZS=${AZS:-"sa-east-1a sa-east-1b sa-east-1c"}
PROF_RESERVE=${PROF_RESERVE:-8}
HALT_A=55; HALT_B=35; HALT_V=55; BUDGET_A=40; BUDGET_B=20; BUDGET_V=40
PARTS_A="kit-common.tgz kit-rimu-a.tar.zst kit-img-h2load-h3.tar.zst kit-img-zix.tar.zst kit-img-fib.tar.zst kit-img-plod.tar.zst kit-img-cnetmod.tar.zst kit-img-aegon.tar.zst"
PARTS_B="kit-common.tgz kit-rimu-b.tar.zst kit-img-h2load-h3.tar.zst"
PARTS_V="kit-common.tgz kit-rimu-v.tar.zst kit-img-h2load-h3.tar.zst kit-img-zix.tar.zst"
EPOCH=$(date +%s)
TAG=rimuh3-$EPOCH
TAGS="{Key=Name,Value=$TAG},{Key=project,Value=rimu-h3-bench}"
RUN=$S/results/run-$(date -u +%Y%m%d-%H%M%S)$([ "$DRY" = 1 ] && echo -dry || true)
mkdir -p "$RUN"
# tee ignores Ctrl-C, so the cleanup after a Ctrl-C still has somewhere to write (and is not killed by SIGPIPE)
exec > >(trap '' INT TERM; exec tee -a "$RUN/launch.log") 2>&1
exec 3>&2 # the trace of AWS / ssh / rsync calls: not caught by a call's own 2> redirection
case $PHASES in A | B | AB | V) ;; *) echo "PHASES must be A, B, AB or V"; exit 2 ;; esac

# --- every AWS call goes through aws_: printed, region-checked, and in DRY mode not made (a stand-in answer instead)
aws_() {
	[[ " $* " == *" --region $R "* ]] || { echo "refusing an AWS call without --region $R: $*"; exit 1; }
	[[ "$*" != *eu-west-2* ]] || { echo "refusing an AWS call that names eu-west-2: $*"; exit 1; }
	echo "+ aws $*" >&3
	if [ "$DRY" = 1 ]; then
		case "$*" in
		*"sts get-caller-identity"*) echo "arn:aws:iam::000000000000:user/dry-run" ;;
		*"describe-vpcs"*) echo "vpc-0dry" ;;
		*"get-service-quota"*) echo "96.0" ;;
		*"describe-spot-price-history"*) printf 'sa-east-1a\tc6a.24xlarge\t0.57\n' ;;
		*"ssm get-parameter"*) echo "ami-0dry00000000000000" ;;
		*"describe-images"*) echo "/dev/sda1" ;;
		*"create-security-group"*) echo "sg-0dry00000000000000" ;;
		*"run-instances"*) echo "i-0dry00000000000000" ;;
		*"SpotInstanceRequestId"*) printf 'sir-dry00000\tsa-east-1a\n' ;;
		*"PublicIpAddress"*) echo "192.0.2.10" ;;
		esac
		return 0
	fi
	aws "$@"
}
SSHO=()
SSHT=""
ssh_() { # a command on the box (DRY: printed); stdin passes through
	echo "+ ssh ubuntu@$IP $*" >&3
	[ "$DRY" = 1 ] && { case "$*" in *"command -v rsync"*) echo /usr/bin/rsync ;; *"cat kit/out/host.txt"*) echo "pmu=no" ;; esac; return 0; }
	# shellcheck disable=SC2029 # the command is meant to expand here
	ssh "${SSHO[@]}" "ubuntu@$IP" "$@"
}
left() { echo $((DEADLINE - SECONDS)); }

[ -s "$P/kit.sha256" ] || { echo "no parts/kit.sha256: run ./build.sh all first"; exit 1; }
(cd "$P" && sha256sum -c --quiet kit.sha256) || { echo "a kit part does not match parts/kit.sha256: rebuild"; exit 1; }
for ph in A B V; do
	l=PARTS_$ph; t=0
	for f in ${!l}; do t=$((t + $(stat -c %s "$P/$f"))); done
	awk -v ph=$ph -v t=$t 'BEGIN { printf "phase %s kit: %.1f MiB over ssh: %.0f s at 50 Mbit/s, %.0f s at 200 Mbit/s\n", ph, t / 1048576, t * 8 / 50e6, t * 8 / 200e6 }'
done
echo "run $TAG, phases $PHASES, results in $RUN$([ "$DRY" = 1 ] && echo ' (DRY: no AWS call is made)')"

aws_ sts get-caller-identity --region "$R" --query Arn --output text || { echo "AWS session not valid: log in first"; exit 1; }
if [ "$DRY" = 1 ]; then MYIP=192.0.2.1; else MYIP=$(curl -fsS -m 10 https://checkip.amazonaws.com); fi
[[ $MYIP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "could not learn this machine's IP ($MYIP)"; exit 1; }
# Read-only preflight: a default VPC (run-instances picks its subnet per AZ), the spot quota, the spot prices.
VPC=$(aws_ ec2 describe-vpcs --region "$R" --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
[[ $VPC == vpc-* ]] || { echo "no default VPC in $R"; exit 1; }
echo "spot vCPU quota (standard): $(aws_ service-quotas get-service-quota --region "$R" --service-code ec2 --quota-code L-34B43A08 --query Quota.Value --output text || echo '?')"
# shellcheck disable=SC2086 # the type lists are word lists
aws_ ec2 describe-spot-price-history --region "$R" --product-descriptions Linux/UNIX --start-time "$(date -u +%FT%TZ)" \
	--instance-types $TYPES_A $TYPES_B $TYPES_V --query 'SpotPriceHistory[].[AvailabilityZone,InstanceType,SpotPrice]' --output text | sort || true

T0=$SECONDS
IID=""; SIR=""; SG=""; KEY=""; IP=""
stop_box() { # cancel the spot request, terminate the instance, wait until it is gone
	[ -n "$SIR" ] && aws_ ec2 cancel-spot-instance-requests --region "$R" --spot-instance-request-ids "$SIR" >/dev/null
	if [ -n "$IID" ]; then
		aws_ ec2 terminate-instances --region "$R" --instance-ids "$IID" >/dev/null &&
			aws_ ec2 wait instance-terminated --region "$R" --instance-ids "$IID" && echo "terminated $IID"
	fi
	[ "$DRY" = 1 ] || [ -z "$IP" ] || ssh -O exit -o ControlPath="$S/.cm-%C" "ubuntu@$IP" 2>/dev/null || true
	IID=""; SIR=""; IP=""
}
# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
	set +e
	trap '' INT TERM PIPE # a second Ctrl-C must not stop the termination
	stop_box
	if [ -n "$SG" ]; then
		for _ in 1 2 3 4 5 6 7 8 9 10; do
			aws_ ec2 delete-security-group --region "$R" --group-id "$SG" && break
			[ "$DRY" = 1 ] && break
			sleep 10
		done
	fi
	[ -n "$KEY" ] && aws_ ec2 delete-key-pair --region "$R" --key-name "$KEY" >/dev/null
	rm -f "$S/$TAG.pem"
	echo "cleaned up $TAG (sg ${SG:-none}, key ${KEY:-none}) after $(((SECONDS - T0) / 60)) min; results in $RUN"
}
trap cleanup EXIT
trap 'echo interrupted; exit 130' INT TERM

KEY=$TAG # set first: a failed create leaves nothing, and the delete in cleanup is then a harmless no-op
aws_ ec2 create-key-pair --region "$R" --key-name "$TAG" --key-type ed25519 \
	--tag-specifications "ResourceType=key-pair,Tags=[$TAGS]" --query KeyMaterial --output text >"$S/$TAG.pem"
chmod 600 "$S/$TAG.pem"
SG=$(aws_ ec2 create-security-group --region "$R" --group-name "$TAG" --description "rimu-h3 bench: ssh from one IP" \
	--tag-specifications "ResourceType=security-group,Tags=[$TAGS]" --query GroupId --output text)
aws_ ec2 authorize-security-group-ingress --region "$R" --group-id "$SG" --protocol tcp --port 22 --cidr "$MYIP/32" >/dev/null
AMI=$(aws_ ssm get-parameter --region "$R" --name /aws/service/canonical/ubuntu/server/26.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
	--query Parameter.Value --output text)
ROOTDEV=$(aws_ ec2 describe-images --region "$R" --image-ids "$AMI" --query 'Images[0].RootDeviceName' --output text)
SSHO=(-i "$S/$TAG.pem" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10
	-o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o ControlMaster=auto -o ControlPath="$S/.cm-%C" -o ControlPersist=20m)
SSHT="ssh ${SSHO[*]}"

launch_box() { # phase types halt -> IID, SIR, IP
	local ph=$1 types=$2 halt=$3 type az err out
	err=$RUN/run-instances-$ph.err
	for type in $types; do
		for az in $AZS; do
			# user-data: a halt from boot, so the box ends even if ssh never answers (ssh's own halt replaces it)
			if out=$(aws_ ec2 run-instances --region "$R" --image-id "$AMI" --instance-type "$type" --count 1 \
				--key-name "$TAG" --security-group-ids "$SG" --placement "AvailabilityZone=$az" \
				--instance-market-options 'MarketType=spot,SpotOptions={SpotInstanceType=one-time,InstanceInterruptionBehavior=terminate}' \
				--instance-initiated-shutdown-behavior terminate --metadata-options HttpTokens=required,HttpEndpoint=enabled \
				--block-device-mappings "DeviceName=$ROOTDEV,Ebs={VolumeSize=40,VolumeType=gp3,Iops=3000,Throughput=250,DeleteOnTermination=true}" \
				--user-data "$(printf '#!/bin/sh\nshutdown -h +%d\n' $((halt + 15)))" \
				--tag-specifications "ResourceType=instance,Tags=[$TAGS,{Key=phase,Value=$ph}]" "ResourceType=volume,Tags=[$TAGS]" \
				"ResourceType=spot-instances-request,Tags=[$TAGS]" \
				--query 'Instances[0].InstanceId' --output text 2>"$err") && [[ $out == i-* ]]; then
				IID=$out
				echo "launched $IID ($type, $az, $AMI) for phase $ph at $(date -u +%T)"
				read -r SIR AZ_GOT <<<"$(aws_ ec2 describe-instances --region "$R" --instance-ids "$IID" \
					--query 'Reservations[0].Instances[0].[SpotInstanceRequestId,Placement.AvailabilityZone]' --output text)"
				aws_ ec2 wait instance-running --region "$R" --instance-ids "$IID"
				IP=$(aws_ ec2 describe-instances --region "$R" --instance-ids "$IID" \
					--query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
				echo "running: $IP ($AZ_GOT, spot request $SIR)"
				return 0
			fi
			if grep -qE 'InsufficientInstanceCapacity|InsufficientCapacity|SpotMaxPriceTooLow|MaxSpotInstanceCountExceeded|Unsupported|capacity-not-available|VcpuLimitExceeded|InstanceLimitExceeded|No subnets found|default subnet' "$err"; then
				echo "no $type in $az: $(tr '\n' ' ' <"$err" | cut -c1-200)"
				continue
			fi
			echo "run-instances failed: $(cat "$err")"
			return 1
		done
	done
	echo "no capacity for phase $ph in any of: $types x $AZS"
	return 1
}

xfer() { # part: rsync into kit/dl (resumes from .rsync-partial after a drop), then the box may take it
	local part=$1 try
	for try in 1 2 3 4 5; do
		if [ "${XFER:-rsync}" = scp ]; then # no rsync on the box: scp to a temporary name (a drop restarts the part)
			echo "+ scp $P/$part ubuntu@$IP:kit/dl/$part.tmp (try $try)" >&3
			if [ "$DRY" = 1 ] || { scp -q "${SSHO[@]}" "$P/$part" "ubuntu@$IP:kit/dl/$part.tmp" && ssh_ "mv kit/dl/$part.tmp kit/dl/$part"; }; then
				ssh_ "touch kit/dl/$part.done"
				return 0
			fi
			sleep 3
			continue
		fi
		echo "+ rsync -a --partial-dir=.rsync-partial --timeout=60 -e ssh $P/$part ubuntu@$IP:kit/dl/ (try $try)" >&3
		if [ "$DRY" = 1 ] || rsync -a --partial-dir=.rsync-partial --timeout=60 -e "$SSHT" "$P/$part" "ubuntu@$IP:kit/dl/"; then
			ssh_ "touch kit/dl/$part.done"
			return 0
		fi
		sleep 3
	done
	return 1
}

# A detached phase on the box (systemd-run: an ssh drop does not stop it), followed live; stopped at the budget.
remote_phase() { # name cap_seconds
	local name=$1 cap=$2 l until seen
	l=$(left); [ "$l" -gt "$cap" ] && l=$cap
	[ "$l" -ge 60 ] || { echo "no time left for $name ($l s)"; return 1; }
	echo "== $name: up to $((l / 60)) min ($(date -u +%T))"
	ssh_ "sudo PASSES='${PASSES:-}' SERVERS='${SERVERS:-}' PROFILES='${PROFILES:-}' VARIANTS='${VARIANTS:-}' VREF='${VREF-zix}' \
		VPROF='${VPROF:-}' systemd-run --quiet --unit=rimuh3-$name --collect \
		-p RuntimeMaxSec=$l --setenv=PASSES --setenv=SERVERS --setenv=PROFILES --setenv=VARIANTS --setenv=VREF --setenv=VPROF \
		bash -c 'exec /home/ubuntu/kit/remote/run.sh $name >/home/ubuntu/kit/$name.log 2>&1'"
	[ "$DRY" = 1 ] && return 0
	until=$((SECONDS + l + 20))
	while [ $SECONDS -lt $until ]; do
		seen=$(wc -l 2>/dev/null <"$RUN/$PH/$name.log" || echo 0)
		timeout $((until - SECONDS)) ssh "${SSHO[@]}" "ubuntu@$IP" "p=\$(systemctl show -p MainPID --value rimuh3-$name 2>/dev/null)
			if [ \"\${p:-0}\" = 0 ]; then tail -n +$((seen + 1)) kit/$name.log; else tail -n +$((seen + 1)) -F --pid=\$p kit/$name.log 2>/dev/null; fi" |
			tee -a "$RUN/$PH/$name.log" || true
		ssh_ "systemctl is-active -q rimuh3-$name" 2>/dev/null || return 0
		echo "(log stream dropped; reconnecting)"
		sleep 5
	done
	echo "$name hit its time limit: stopping it"
	ssh_ "sudo systemctl stop rimuh3-$name" || true
}

fetch() { # what: copy the box's kit/out and logs into $RUN/$PH
	echo "== fetch $1"
	if [ "$DRY" = 1 ]; then ssh_ "sudo tar -C kit -czf - out setup.log bench.log profile.log hw.log variants.log" >/dev/null; return 0; fi
	timeout 600 ssh "${SSHO[@]}" "ubuntu@$IP" "cd kit && sudo tar -czf - out \$(ls setup.log bench.log profile.log hw.log variants.log 2>/dev/null)" |
		tar -C "$RUN/$PH" -xzf - && echo "fetched $1 into $RUN/$PH ($(du -sh "$RUN/$PH" | cut -f1))"
}

run_phase() { # A|B
	PH=$1
	local types halt budget parts part
	case $PH in
	A) types=$TYPES_A; halt=$HALT_A; budget=$BUDGET_A; parts=$PARTS_A ;;
	B) types=$TYPES_B; halt=$HALT_B; budget=$BUDGET_B; parts=$PARTS_B ;;
	V) types=$TYPES_V; halt=$HALT_V; budget=$BUDGET_V; parts=$PARTS_V ;;
	esac
	mkdir -p "$RUN/$PH"
	launch_box "$PH" "$types" "$halt" || return 1
	if [ "$DRY" != 1 ]; then
		for _ in $(seq 180); do ssh "${SSHO[@]}" -o ControlMaster=no "ubuntu@$IP" true 2>/dev/null && break; sleep 5; done
	fi
	DEADLINE=$((SECONDS + budget * 60))
	# As soon as ssh answers: the halt, a quiet box, and the packages installing in the background while the kit uploads.
	ssh_ "sudo shutdown -h +$halt && mkdir -p kit/dl && sudo systemctl stop unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer \
apt-daily.service apt-daily-upgrade.service 2>/dev/null; sudo systemd-run --quiet --unit=rimuh3-apt --collect bash -c 'timeout 120 cloud-init status --wait >/dev/null 2>&1
export DEBIAN_FRONTEND=noninteractive; o=\"-q -o DPkg::Lock::Timeout=300\"
for i in 1 2 3; do apt-get \$o update && { apt-get \$o install -y docker.io zstd rsync linux-tools-common linux-tools-\$(uname -r) ||
apt-get \$o install -y docker.io zstd rsync linux-tools-common linux-tools-aws; } && touch /var/tmp/rimuh3-apt.ok && exit 0; sleep 10; done
touch /var/tmp/rimuh3-apt.failed'" || { echo "the box does not answer"; return 1; }
	echo "box answered at $(date -u +%T): halts itself at +$halt min; ssh phases end by $(date -u -d "+$budget min" +%T)"
	XFER=rsync
	ssh_ "command -v rsync" >/dev/null || { XFER=scp; echo "no rsync on the box: the parts go by scp"; }
	tr ' ' '\n' <<<"$parts" | ssh_ "cat > kit/dl/parts.txt"
	awk -v want=" $parts " 'index(want, " " $2 " ")' "$P/kit.sha256" | ssh_ "cat > kit/dl/kit.sha256"
	local t1=$SECONDS
	xfer kit-common.tgz || return 1
	ssh_ "cd kit && tar -xzf dl/kit-common.tgz && sudo systemd-run --quiet --unit=rimuh3-setup --collect \
		bash -c 'exec /home/ubuntu/kit/remote/run.sh setup $PH >/home/ubuntu/kit/setup.log 2>&1'"
	for part in $parts; do
		[ "$part" = kit-common.tgz ] && continue
		xfer "$part" || { echo "upload of $part failed"; return 1; }
	done
	echo "kit uploaded in $((SECONDS - t1)) s"
	local wl; wl=$(left); [ "$wl" -gt 60 ] || wl=60
	ssh_ "timeout $wl sh -c 'until [ -e kit/setup.ok ] || [ -e kit/setup.failed ]; do sleep 2; done'; cat kit/setup.log; [ -e kit/setup.ok ]" ||
		{ echo "setup failed"; fetch setup || true; return 1; }
	echo "setup done at $(date -u +%T) ($(($(left) / 60)) min of the budget left)"
	if [ "$PH" = A ]; then
		# Bench first and fetched at once: a spot reclaim later loses only the profiles.
		remote_phase bench $(($(left) - PROF_RESERVE * 60)) || true
		fetch bench || true
		remote_phase profile "$(left)" || true
		fetch profile || true
		[ "$DRY" = 1 ] || python3 -I "$S/summarize.py" "$RUN/A/out" | tee "$RUN/A/summary.txt" || true
	elif [ "$PH" = V ]; then
		# Bench and profiles in one phase: what the budget cuts is the last profiles (prev's)
		remote_phase variants "$(left)" || true
		fetch variants || true
		[ "$DRY" = 1 ] || python3 -I "$S/summarize.py" "$RUN/V/out" | tee "$RUN/V/summary.txt" || true
	else
		remote_phase hw "$(left)" || true
		fetch hw || true
		[ "$DRY" = 1 ] || python3 -I "$S/summarize.py" "$RUN/B/out" | tee "$RUN/B/summary.txt" || true
	fi
	stop_box
}

rc=0
if [ "$PHASES" = V ]; then run_phase V || { rc=1; stop_box; }; fi
if [[ $PHASES == *A* ]]; then run_phase A || { rc=1; stop_box; }; fi
if [[ $PHASES == *B* ]]; then
	if [ "$PHASES" = B ] || [ "${FORCE_B:-0}" = 1 ]; then
		run_phase B || { rc=1; stop_box; }
	elif [ "$DRY" = 1 ] || grep -q '^pmu=no' "$RUN/A/out/host.txt" 2>/dev/null; then
		echo "phase A's box has no PMU: phase B (hardware counters on Intel metal)"
		run_phase B || { rc=1; stop_box; }
	elif grep -q '^pmu=yes' "$RUN/A/out/host.txt" 2>/dev/null; then
		echo "phase A's box had hardware counters and ran rimu's counter set: phase B skipped"
	else
		echo "phase A left no host.txt: phase B skipped (FORCE_B=1 PHASES=B to run it alone)"
		rc=1
	fi
fi
exit $rc
