#!/usr/bin/env sh
# Restore the gateway database from an archive made by backup.sh (docs/operations.md, "Backup and restore").
#
# Works on a running stack and on a fresh one (new host or empty volumes). It:
#   1. checks the archive against its .sha256;
#   2. stops gateway-api, worker and web-ui so nothing writes during the restore;
#   3. starts MongoDB alone and restores with --drop (collections in the archive replace the current ones);
#   4. runs `python -m app.tools.verify_data` with the configured DATA_ENCRYPTION_KEY: every stored secret
#      must decrypt, otherwise the services are left stopped;
#   5. starts the whole stack and waits until it is healthy.
#
# The secrets/ directory must hold the SAME data_encryption_key and api_key_hash_pepper that were in use
# when the backup was taken. Run from the install directory.
#
#   ./deploy/scripts/restore.sh <archive.gz> [--yes]
set -eu

ARCHIVE="${1:-}"
CONFIRM="${2:-}"
if [ -z "$ARCHIVE" ] || [ ! -s "$ARCHIVE" ]; then
  echo "usage: $0 <archive.gz> [--yes]" >&2
  exit 2
fi
DB="${MONGODB_DATABASE:-$(sed -n 's/^MONGODB_DATABASE=\([A-Za-z0-9_-]*\).*/\1/p' .env 2>/dev/null | tail -n 1)}"
DB="${DB:-mcp_gateway}"

if [ -f "$ARCHIVE.sha256" ]; then
  (cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "$ARCHIVE").sha256" >/dev/null) || {
    echo "checksum mismatch: $ARCHIVE is damaged or was modified" >&2
    exit 1
  }
  echo "checksum OK"
else
  echo "warning: no $ARCHIVE.sha256; the archive cannot be checked" >&2
fi

if [ "$CONFIRM" != "--yes" ]; then
  printf 'This REPLACES database "%s" with %s. Type "restore" to continue: ' "$DB" "$ARCHIVE"
  read -r answer
  [ "$answer" = "restore" ] || { echo "aborted"; exit 1; }
fi

docker compose stop web-ui gateway-api worker
docker compose up -d --wait --wait-timeout 180 mongodb
docker compose exec -T mongodb sh -c \
  'umask 077; f="$(mktemp)"; printf "password: \"%s\"\n" "$(cat /run/secrets/mongo_root_password)" > "$f"
   mongorestore --quiet --archive --gzip --drop --nsInclude "$1.*" -u mgw_root --config "$f" --authenticationDatabase admin; rc=$?
   rm -f "$f"; exit $rc' \
  sh "$DB" < "$ARCHIVE"
echo "restored database $DB"

if ! docker compose run --rm --no-deps -T gateway-api python -m app.tools.verify_data; then
  echo "verification FAILED: services left stopped. Check that secrets/data_encryption_key is the key" >&2
  echo "that was active when the backup was taken, then run this script again." >&2
  exit 1
fi

docker compose up -d --wait --wait-timeout 300
echo "restore complete"
