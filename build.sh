#!/usr/bin/env bash
#
# Cross-compile the Sally Print Agent for every shipped target.
#
# Pure Go with no cgo, so one machine builds all of them — that is the reason
# the status page exists instead of a native tray icon (a tray needs cgo, and
# cgo means building each platform on that platform).
#
#   ./build.sh              # current version from main.go
#   VERSION=1.2.0 ./build.sh
#
# Output lands in dist/. These binaries are UNSIGNED: see README.md — macOS
# refuses to run an unnotarised binary without the user overriding Gatekeeper,
# and Windows endpoint security tends to flag an unsigned process that opens a
# listening port. Signing and notarisation happen in the release pipeline.
set -euo pipefail

cd "$(dirname "$0")"

VERSION="${VERSION:-}"
OUT=dist
mkdir -p "$OUT"
rm -f "$OUT"/sally-print-agent-*

# -s -w strips the symbol table and DWARF: ~12 MB becomes ~8 MB, and this is a
# binary end users download.
LDFLAGS="-s -w"
if [ -n "$VERSION" ]; then
  LDFLAGS="$LDFLAGS -X main.version=$VERSION"
fi

build() {
  local goos="$1" goarch="$2" ext="${3:-}"
  local name="$OUT/sally-print-agent-$goos-$goarch$ext"
  echo "  $goos/$goarch"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -trimpath -ldflags "$LDFLAGS" -o "$name" .
}

echo "Building sally-print-agent ${VERSION:-(dev)}"
build windows amd64 .exe
build windows arm64 .exe
build darwin amd64
build darwin arm64

# A universal binary spares the download page from asking users which Mac they
# have. lipo only exists on macOS, so elsewhere the two slices ship as they are.
if command -v lipo >/dev/null 2>&1; then
  echo "  darwin/universal"
  lipo -create -output "$OUT/sally-print-agent-darwin-universal" \
    "$OUT/sally-print-agent-darwin-amd64" "$OUT/sally-print-agent-darwin-arm64"
else
  echo "  darwin/universal — skipped (lipo is macOS only)"
fi

echo
ls -la "$OUT"
