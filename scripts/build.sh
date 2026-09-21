#!/usr/bin/env bash
# KingMoat release build script (Linux / CI)
# Usage: ./scripts/build.sh [version]   (default: dev)
# Targets: windows/amd64, linux/amd64, linux/arm64 (CGO disabled, static)
set -euo pipefail

VERSION="${1:-dev}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTROOT="$ROOT/dist/kingmoat_${VERSION}"

rm -rf "$OUTROOT"
mkdir -p "$OUTROOT"
cd "$ROOT"

# Third-party license bundle for the release packages (ARCHITECTURE.md 搂12).
go run ./scripts/gen-licenses -out "$OUTROOT/THIRD-PARTY-LICENSES"

export CGO_ENABLED=0
LDFLAGS="-s -w -X main.version=${VERSION} -X github.com/kingmoat/kingmoat/internal/api.engineCorazaVersion=$(go list -m -f '{{.Version}}' github.com/corazawaf/coraza/v3) -X github.com/kingmoat/kingmoat/internal/api.engineCRSVersion=$(go list -m -f '{{.Version}}' github.com/corazawaf/coraza-coreruleset/v4)"

build_pkg() {
    local os="$1" arch="$2" ext=""
    [ "$os" = "windows" ] && ext=".exe"
    local pkgName="kingmoat_${VERSION}_${os}_${arch}"
    local pkgDir="$OUTROOT/$pkgName"
    mkdir -p "$pkgDir"

    echo "==> building $pkgName"
    GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" -o "$pkgDir/kingmoat$ext" ./cmd/kingmoat
    GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" -o "$pkgDir/kingmoat-cli$ext" ./cmd/kingmoat-cli

    cp LICENSE NOTICE README.md config.example.json "$pkgDir/"
    cp "$OUTROOT/THIRD-PARTY-LICENSES" "$pkgDir/"
    go version -m "$pkgDir/kingmoat$ext" > "$pkgDir/SBOM.txt"
    cp deploy/kingmoat.service "$pkgDir/"
    [ "$os" = "windows" ] && cp deploy/windows.md "$pkgDir/"

    if [ "$os" = "windows" ]; then
        (cd "$OUTROOT" && zip -qr "$pkgName.zip" "$pkgName")
    else
        tar -czf "$OUTROOT/$pkgName.tar.gz" -C "$OUTROOT" "$pkgName"
    fi
    rm -rf "$pkgDir"
}

build_pkg windows amd64
build_pkg linux amd64
build_pkg linux arm64

# checksums
cd "$OUTROOT"
: > checksums.txt
for f in *.zip *.tar.gz; do
    [ -e "$f" ] || continue
    sha256sum "$f" >> checksums.txt
done

echo
echo "== artifacts =="
ls -l
echo
echo "done: $OUTROOT"
