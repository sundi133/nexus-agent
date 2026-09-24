#!/bin/sh
# Cross-compile votal-agent for every supported target into dist/.
# One repository, one shared core, per-OS binaries:
#
#   scripts/build.sh            # version from git describe
#   VERSION=0.1.0 scripts/build.sh
set -eu
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PKG=github.com/sundi133/nexus-agent/internal/version
LDFLAGS="-s -w -X $PKG.Version=$VERSION -X $PKG.Commit=$COMMIT -X $PKG.BuildDate=$DATE"

TARGETS="darwin/arm64 darwin/amd64 windows/amd64 windows/arm64 linux/amd64 linux/arm64"
mkdir -p dist
for t in $TARGETS; do
  os="${t%/*}"; arch="${t#*/}"
  ext=""; [ "$os" = windows ] && ext=".exe"
  out="dist/votal-agent_${os}_${arch}${ext}"
  echo "building $out"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$out" ./cmd/votal-agent
done
( cd dist && sha256sum votal-agent_* > SHA256SUMS 2>/dev/null || shasum -a 256 votal-agent_* > SHA256SUMS )
echo "version $VERSION"
