#!/usr/bin/env sh
# Online MongoDB backup of the gateway database (docs/operations.md, "Backup and restore").
#
# Writes <dir>/mcp-gateway-<UTC timestamp>.archive.gz and a matching .sha256 (bare file name, so
# `sha256sum -c` works from that directory). Run from the install directory (where docker-compose.yml is).
# The archive holds every tenant's configuration and audit log: store it encrypted and access-controlled.
# Keys are NOT in the archive. Back up secrets/data_encryption_key and secrets/api_key_hash_pepper
# separately; a restore needs the same ones.
#
#   ./deploy/scripts/backup.sh [output-dir]          (default ./backups)
set -eu

OUT="${1:-./backups}"
DB="${MONGODB_DATABASE:-$(sed -n 's/^MONGODB_DATABASE=\([A-Za-z0-9_-]*\).*/\1/p' .env 2>/dev/null | tail -n 1)}"
DB="${DB:-mcp_gateway}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="mcp-gateway-$STAMP.archive.gz"

umask 077
mkdir -p "$OUT"
docker compose exec -T mongodb sh -c \
  'mongodump --quiet --archive --gzip -u mgw_root -p "$(cat /run/secrets/mongo_root_password)" --authenticationDatabase admin --db "$1"' \
  sh "$DB" > "$OUT/$NAME.partial"

if [ ! -s "$OUT/$NAME.partial" ]; then
  rm -f "$OUT/$NAME.partial"
  echo "backup failed: empty archive" >&2
  exit 1
fi
mv "$OUT/$NAME.partial" "$OUT/$NAME"
(cd "$OUT" && sha256sum "$NAME" > "$NAME.sha256")
echo "backup   $OUT/$NAME ($(wc -c < "$OUT/$NAME") bytes, database $DB)"
