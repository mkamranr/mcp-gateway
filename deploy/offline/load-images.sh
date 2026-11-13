#!/usr/bin/env sh
# Run on the AIR-GAPPED host inside the extracted bundle directory. Verifies checksums, loads the
# images and checks their IDs against images.txt. Nothing is downloaded.
#
#   sha256sum -c mcp-gateway-<version>.tar.gz.sha256 && tar xzf mcp-gateway-<version>.tar.gz
#   cd mcp-gateway-<version> && ./deploy/offline/load-images.sh
set -eu

sha256sum -c SHA256SUMS
gunzip -c images.tar.gz | docker load

status=0
while read -r img id; do
  actual="$(docker image inspect --format '{{.Id}}' "$img" 2>/dev/null || echo missing)"
  if [ "$actual" = "$id" ]; then echo "ok       $img"; else echo "MISMATCH $img (expected $id, got $actual)"; status=1; fi
done < images.txt
[ "$status" -eq 0 ] || { echo "Image verification failed. Do not deploy." >&2; exit 1; }

echo
echo "Next: ./deploy/scripts/generate-secrets.sh && cp .env.example .env && docker compose up -d --no-build --pull never"
