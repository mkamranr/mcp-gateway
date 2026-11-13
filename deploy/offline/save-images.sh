#!/usr/bin/env sh
# Run on a CONNECTED build host. Builds the gateway images, pulls the pinned third-party images and
# writes them plus a SHA-256 manifest to ./release for transfer into the air-gapped environment.
#
#   ./deploy/offline/save-images.sh [version]
set -eu

VERSION="${1:-0.1.0}"
OUT="release/mcp-gateway-${VERSION}"
BACKEND="mcp-gateway/backend:${VERSION}"
WEB="mcp-gateway/web-ui:${VERSION}"
THIRD_PARTY="mongo:7.0.14 redis:7.4.1-alpine"

mkdir -p "$OUT"
docker build -t "$BACKEND" backend
docker build -t "$WEB" frontend
for img in $THIRD_PARTY; do docker pull "$img"; done

# Record digests so the target can verify exactly what was shipped.
: > "$OUT/images.txt"
for img in "$BACKEND" "$WEB" $THIRD_PARTY; do
  echo "$img $(docker image inspect --format '{{.Id}}' "$img")" >> "$OUT/images.txt"
done

docker save "$BACKEND" "$WEB" $THIRD_PARTY | gzip -9 > "$OUT/images.tar.gz"
cp docker-compose.yml .env.example "$OUT/"
mkdir -p "$OUT/deploy" && cp -r deploy/scripts deploy/offline "$OUT/deploy/"
[ -d sbom ] && cp -r sbom "$OUT/" || echo "note: run deploy/scripts/sbom.sh first to include SBOMs"

(cd "$OUT" && find . -type f ! -name SHA256SUMS -exec sha256sum {} + | sort -k2 > SHA256SUMS)
tar -C release -czf "release/mcp-gateway-${VERSION}.tar.gz" "mcp-gateway-${VERSION}"
sha256sum "release/mcp-gateway-${VERSION}.tar.gz" > "release/mcp-gateway-${VERSION}.tar.gz.sha256"
echo "Bundle: release/mcp-gateway-${VERSION}.tar.gz (verify with the .sha256 file after transfer)"
