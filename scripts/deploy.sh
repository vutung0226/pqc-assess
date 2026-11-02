#!/usr/bin/env bash
# Install pqc-assess on another machine over SSH, such as a Raspberry Pi.
#
#   scripts/deploy.sh HOST [DIR]      DIR defaults to ~/pqc-assess on HOST
#
# The scanners are built here, for HOST's architecture: Go cross-compiles, so
# HOST needs only Docker and Python 3.10+, and no Go toolchain or build image
# (golang is close to 1 GB, too much for a small SD card). HOST then wraps each
# binary in a distroless image under the tag tools.lock.json names, pulls
# CBOMkit, and scans the test fixtures to check the install.
set -euo pipefail

host=${1:?usage: scripts/deploy.sh HOST [DIR]}
dir=${2:-pqc-assess}
root=$(cd "$(dirname "$0")/.." && pwd)

lock() { python3 -c "import json; print(json.load(open('$root/tools.lock.json'))$1)"; }

case $(ssh "$host" uname -m) in
  aarch64 | arm64) goarch=arm64 ;;
  x86_64) goarch=amd64 ;;
  *) echo "deploy.sh: unsupported architecture on $host" >&2; exit 1 ;;
esac

work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT
mkdir -p "$work/bin"

echo "== building scanners for linux/$goarch"
git clone -q "$(lock "['cryptoscan']['repo']")" "$work/cryptoscan"
git -C "$work/cryptoscan" checkout -q "$(lock "['cryptoscan']['commit']")"
git -C "$work/cryptoscan" apply "$root"/patches/cryptoscan/*.patch
docker run --rm --user "$(id -u):$(id -g)" -v "$work:/w" \
  -e HOME=/tmp -e GOPATH=/tmp/go -e GOCACHE=/tmp/cache -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH="$goarch" \
  -e QRYX="$(lock "['qryx']['module']")@$(lock "['qryx']['version']")" \
  golang:1.22 sh -ec '
    cd /w/cryptoscan && go build -trimpath -buildvcs=false -o /w/bin/cryptoscan ./cmd/cryptoscan
    GOTOOLCHAIN=go1.27.3 go install -trimpath "$QRYX"
    cp /tmp/go/bin/linux_$GOARCH/qryx /w/bin/qryx 2>/dev/null || cp /tmp/go/bin/qryx /w/bin/qryx'

echo "== copying pqc-assess to $host:$dir"
ssh "$host" "mkdir -p '$dir/.prebuilt'"
git -C "$root" archive HEAD | ssh "$host" "tar -x -C '$dir'"
scp -q "$work/bin/cryptoscan" "$work/bin/qryx" "$host:$dir/.prebuilt/"

echo "== building images on $host"
ssh "$host" "cd '$dir' && \
  docker build -q -f docker/prebuilt.Dockerfile --build-arg BIN=cryptoscan -t '$(lock "['cryptoscan']['image']")' .prebuilt && \
  docker build -q -f docker/prebuilt.Dockerfile --build-arg BIN=qryx -t '$(lock "['qryx']['image']")' .prebuilt && \
  docker pull -q '$(lock "['cbomkit']['image']")'"

echo "== checking the install on $host"
ssh "$host" "cd '$dir' && python3 -m unittest discover -s tests -t . 2>&1 | tail -1 && \
  python3 -m pqc_assess scan tests/fixtures -o /tmp/pqc-assess-selftest | tail -2"
