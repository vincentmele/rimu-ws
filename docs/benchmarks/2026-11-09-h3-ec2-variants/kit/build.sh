#!/usr/bin/env bash
# build.sh [rimu|prev|inferno|images|data|harness|pack|all]: builds everything the aws-h3 run ships, on colossus,
# before any instance exists, and packs it into the kit parts in parts/ (launch.sh sends them over ssh with rsync).
#
#   rimu     arena-h2 from /mnt/nvme1tb/claude-tmp/rimu-h3 at $REV (read-only; own target dirs), three builds:
#              bin/znver3       release, -C target-cpu=znver3                          (phase A bench, phase V)
#              bin/znver3-prof  profile `profiling` (release + line tables), frame pointers, znver3   (phase A/V profile)
#              bin/v3-prof      the same for -C target-cpu=x86-64-v3                   (phase B, Intel metal)
#   prev     arena-h2 at $PREV_REV (PREV=<sha>; default e7eca138, before task 16), from a scratch `git clone --local`
#            (deleted after), for phase V's `prev` variant: bin/prev-znver3 and bin/prev-znver3-prof, built as above
#   inferno  inferno-collapse-perf and inferno-flamegraph (cargo install into aws-bin/inferno)
#   images   the docker images h3-bench.sh runs, saved and compressed (zstd -19 --long=27), one part each
#   data     arena certs, dataset.json, static/, requests/ and the generator's IPv4-only hosts file
#   harness  checks the kit's h3-bench.sh / h3-composite.py against bc19008d and writes the diff
#   pack     kit-common.tgz (gzip: the box unpacks it before zstd is sure to exist), kit-rimu-a.tar.zst,
#            kit-rimu-b.tar.zst (+ the image parts), kit.sha256, SIZES (with the upload time per phase), ldd
# Phase A uploads kit-common, kit-rimu-a and every kit-img-*; phase B only kit-common, kit-rimu-b and
# kit-img-h2load-h3; phase V kit-common, kit-rimu-v (the task-16 build and the one before it), kit-img-h2load-h3 and
# kit-img-zix (launch.sh picks the parts; PARTS_A / PARTS_B / PARTS_V below are the upload order).
set -euo pipefail
K=/mnt/nvme1tb/claude-tmp/aws-h3; R=$K/remote; P=$K/parts
SRC=/mnt/nvme1tb/claude-tmp/rimu-h3; REV=${REV:-a99e6332}; PREV_REV=${PREV:-e7eca138}
T=/mnt/nvme1tb/claude-tmp/target-aws-h3
ARENA=/mnt/nvme1tb/claude-tmp/arena-main
INF=/mnt/nvme1tb/claude-tmp/aws-bin/inferno
IMAGES="h2load-h3 plod fib aegon cnetmod zix" # h3-bench.sh: generator=httparena-h2load-h3, image=httparena-<server>
TOOLCHAIN=nightly-2026-10-12
ZSTD=(zstd -q -T0 -19 --long=27) # measured on the generator image: 169 MB -> 41.3 MB in 49 s (-12: 49.4 MB in 2.5 s)
# shellcheck disable=SC2034 # read through ${!list} in pack
PARTS_A="kit-common.tgz kit-rimu-a.tar.zst kit-img-h2load-h3.tar.zst kit-img-zix.tar.zst kit-img-fib.tar.zst kit-img-plod.tar.zst kit-img-cnetmod.tar.zst kit-img-aegon.tar.zst"
# shellcheck disable=SC2034
PARTS_B="kit-common.tgz kit-rimu-b.tar.zst kit-img-h2load-h3.tar.zst"
# shellcheck disable=SC2034
PARTS_V="kit-common.tgz kit-rimu-v.tar.zst kit-img-h2load-h3.tar.zst kit-img-zix.tar.zst"

rimu_one() { # dir rustflags profile [source tree]
  local d=$1 flags=$2 prof=$3 src=${4:-$SRC} out
  # The source tree is only read: cargo writes into its own target dir, --locked keeps Cargo.lock as it is.
  (cd "$src" && CARGO_TARGET_DIR=$T/$d RUSTFLAGS="$flags" nice -n 10 cargo +$TOOLCHAIN build -q --locked \
    --profile "$prof" -p rimu-ws-internal --bin arena-h2 --features arena-h2)
  out=$T/$d/$prof/arena-h2 # cargo's dir is named after the profile (release/, profiling/)
  mkdir -p "$R/bin/$d"
  cp "$out" "$R/bin/$d/arena-h2"
  printf '%s %s\nRUSTFLAGS=%s profile=%s toolchain=%s\n' "$(git -C "$src" rev-parse HEAD)" "$(git -C "$src" log -1 --format=%s)" \
    "$flags" "$prof" "$TOOLCHAIN" >"$R/bin/$d/REVISION"
  ls -la "$R/bin/$d/arena-h2"
}
rimu() {
  [ "$(git -C "$SRC" rev-parse HEAD | cut -c1-8)" = $REV ] || { echo "rimu-h3 is not at $REV"; exit 1; }
  [ -z "$(git -C "$SRC" status --porcelain --untracked-files=no)" ] || { echo "rimu-h3 has local changes"; exit 1; }
  rimu_one znver3 "-C target-cpu=znver3" release
  rimu_one znver3-prof "-C target-cpu=znver3 -C force-frame-pointers=yes" profiling
  rimu_one v3-prof "-C target-cpu=x86-64-v3 -C force-frame-pointers=yes" profiling
}
prev() {
  local clone=/mnt/nvme1tb/claude-tmp/aws-h3-prev-src
  rm -rf "$clone"
  git clone -q --local --no-hardlinks --no-checkout "$SRC" "$clone" # the shared .git is on another device
  git -C "$clone" checkout -q "$PREV_REV"
  rimu_one prev-znver3 "-C target-cpu=znver3" release "$clone"
  rimu_one prev-znver3-prof "-C target-cpu=znver3 -C force-frame-pointers=yes" profiling "$clone"
  rm -rf "$clone"
}
inferno() {
  [ -x "$INF/bin/inferno-flamegraph" ] ||
    (cd /mnt/nvme1tb/claude-tmp && CARGO_TARGET_DIR=$T/inferno RUSTFLAGS='' nice -n 10 cargo install -q --locked inferno --root "$INF")
  mkdir -p "$R/tools"
  cp "$INF/bin/inferno-collapse-perf" "$INF/bin/inferno-flamegraph" "$R/tools/"
  printf "a;b 1\n" | "$R/tools/inferno-flamegraph" >/dev/null && echo "inferno ok"
}
images() {
  mkdir -p "$P"
  : >"$K/images.txt"
  for n in $IMAGES; do
    docker image inspect "httparena-$n:latest" >/dev/null
    printf 'httparena-%s:latest %s %s\n' "$n" "$(docker image inspect -f '{{.Id}}' "httparena-$n:latest")" \
      "$(docker image inspect -f '{{.Size}}' "httparena-$n:latest")" >>"$K/images.txt"
    docker save "httparena-$n:latest" | nice -n 10 "${ZSTD[@]}" -o "$P/kit-img-$n.tar.zst.tmp" -f
    mv "$P/kit-img-$n.tar.zst.tmp" "$P/kit-img-$n.tar.zst"
  done
  cat "$K/images.txt"
}
data() {
  rm -rf "$R/arena"; mkdir -p "$R/arena/data"
  cp -r "$ARENA/certs" "$R/arena/certs"
  cp -r "$ARENA/requests" "$R/arena/requests"
  # Only what the servers are given (h3-bench.sh mounts dataset.json, static/ and certs/); the rest of data/
  # (benchmark.db, pgdb-seed.sql, upload.bin: 35 MB) belongs to other HttpArena profiles.
  cp "$ARENA/data/dataset.json" "$R/arena/data/"; cp -r "$ARENA/data/static" "$R/arena/data/static"
  printf '127.0.0.1 localhost\n' >"$R/arena/hosts-v4"
  git -C "$ARENA" rev-parse HEAD >"$R/arena/REVISION" 2>/dev/null || echo unknown >"$R/arena/REVISION"
  du -sh "$R/arena"
}
harness() {
  for f in h3-bench.sh h3-composite.py; do
    git -C "$SRC" show "$REV:.scripts/$f" >"$K/build/$f.$REV"
  done
  diff -u "$K/build/h3-bench.sh.$REV" "$R/h3-bench.sh" >"$K/build/h3-bench.sh.diff" || true
  cmp -s "$K/build/h3-composite.py.$REV" "$R/h3-composite.py" || { echo "remote/h3-composite.py differs from $REV"; exit 1; }
  echo "h3-bench.sh: $(grep -c '^[+-][^+-]' "$K/build/h3-bench.sh.diff") changed lines against $REV (build/h3-bench.sh.diff)"
}
pack() {
  local need="run.sh h3-bench.sh h3-composite.py prof-hook.sh variants.txt tools/inferno-collapse-perf tools/inferno-flamegraph
    arena/certs/server.crt arena/data/dataset.json arena/requests/static-h2-uris.txt arena/hosts-v4
    bin/znver3/arena-h2 bin/znver3-prof/arena-h2 bin/v3-prof/arena-h2 bin/prev-znver3/arena-h2 bin/prev-znver3-prof/arena-h2"
  for f in $need; do [ -e "$R/$f" ] || { echo "missing remote/$f"; exit 1; }; done
  for n in $IMAGES; do [ -s "$P/kit-img-$n.tar.zst" ] || { echo "missing parts/kit-img-$n.tar.zst"; exit 1; }; done
  chmod +x "$R"/*.sh "$R"/tools/* "$R"/bin/*/arena-h2
  tar -C "$K" -cf - remote/run.sh remote/h3-bench.sh remote/h3-composite.py remote/prof-hook.sh remote/variants.txt \
    remote/tools remote/arena | gzip -9 >"$P/kit-common.tgz"
  tar -C "$K" -cf - remote/bin/znver3 remote/bin/znver3-prof | nice -n 10 "${ZSTD[@]}" -o "$P/kit-rimu-a.tar.zst" -f
  tar -C "$K" -cf - remote/bin/v3-prof | nice -n 10 "${ZSTD[@]}" -o "$P/kit-rimu-b.tar.zst" -f
  tar -C "$K" -cf - remote/bin/znver3 remote/bin/znver3-prof remote/bin/prev-znver3 remote/bin/prev-znver3-prof |
    nice -n 10 "${ZSTD[@]}" -o "$P/kit-rimu-v.tar.zst" -f
  (cd "$P" && sha256sum kit-common.tgz kit-rimu-*.tar.zst kit-img-*.tar.zst >kit.sha256)
  {
    (cd "$P" && ls -l kit-common.tgz kit-rimu-*.tar.zst kit-img-*.tar.zst) | awk '{ printf "%-28s %12d bytes %8.1f MiB\n", $9, $5, $5 / 1048576 }'
    for ph in A B V; do
      local list total=0 f
      list=PARTS_$ph
      for f in ${!list}; do total=$((total + $(stat -c %s "$P/$f"))); done
      awk -v ph=$ph -v t=$total 'BEGIN { printf "phase %s upload: %.1f MiB = %.0f s at 50 Mbit/s, %.0f s at 200 Mbit/s\n", ph, t / 1048576, t * 8 / 50e6, t * 8 / 200e6 }'
    done
  } | tee "$P/SIZES"
  {
    for b in bin/znver3/arena-h2 bin/znver3-prof/arena-h2 bin/v3-prof/arena-h2 bin/prev-znver3/arena-h2 \
      bin/prev-znver3-prof/arena-h2 tools/inferno-collapse-perf tools/inferno-flamegraph; do
      echo "== $b"; ldd "$R/$b"
    done
  } | tee "$K/build/ldd.txt"
  if grep -v -E '^==|linux-vdso|libc\.so|libm\.so|libgcc_s|ld-linux|libpthread|libdl|librt|libutil' "$K/build/ldd.txt" | grep -q .; then
    echo "WARNING: a shipped binary needs a library beyond glibc/libgcc (see build/ldd.txt)"
  fi
}
mkdir -p "$K/build"
case ${1:-all} in
rimu) rimu ;;
prev) prev ;;
inferno) inferno ;;
images) images ;;
data) data ;;
harness) harness ;;
pack) pack ;;
all) rimu; prev; inferno; images; data; harness; pack ;;
*) echo "usage: $0 [rimu|prev|inferno|images|data|harness|pack|all]"; exit 2 ;;
esac
