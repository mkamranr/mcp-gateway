#!/usr/bin/env sh
# Creates the Kubernetes Secret for the Helm chart (secrets.existingSecret), from the same generator as Docker
# Compose. Existing files in the secrets directory are kept, so running it again reuses the same keys.
#
#   ./deploy/helm/create-secret.sh <namespace> <release> [secret-name] [secrets-dir]
#
# With the bundled MongoDB and Redis, mongodb_uri and redis_url point at <release>-mcp-gateway-mongodb and
# -redis (or <release>-mongodb when the release name contains "mcp-gateway"). For external databases, edit
# mongodb_uri and redis_url in the secrets directory first (see docs/high-availability.md), then run this.
#
# Keep the secrets directory (or the Secret) in your secret store: data_encryption_key and
# api_key_hash_pepper can't be recovered.
set -eu

NS="${1:?namespace}"
RELEASE="${2:?release name}"
NAME="${3:-mcp-gateway-secrets}"
DIR="${4:-./secrets-k8s-$NS-$RELEASE}"

case "$RELEASE" in
  *mcp-gateway*) FULL="$RELEASE" ;;
  *) FULL="$RELEASE-mcp-gateway" ;;
esac
FULL="$(printf '%s' "$FULL" | cut -c1-50 | sed 's/-*$//')"

HERE="$(cd "$(dirname "$0")" && pwd)"
sh "$HERE/../scripts/generate-secrets.sh" "$DIR" >/dev/null

# generate-secrets.sh writes Compose host names; point them at the chart's Services (only if still unchanged).
if grep -q '@mongodb:27017/' "$DIR/mongodb_uri"; then
  sed -i.bak "s#@mongodb:27017/#@$FULL-mongodb:27017/#" "$DIR/mongodb_uri" && rm -f "$DIR/mongodb_uri.bak"
fi
if grep -q '@redis:6379/' "$DIR/redis_url"; then
  sed -i.bak "s#@redis:6379/#@$FULL-redis:6379/#" "$DIR/redis_url" && rm -f "$DIR/redis_url.bak"
fi

set --
for key in session_secret data_encryption_key api_key_hash_pepper bootstrap_admin_password mongodb_uri redis_url \
           mongo_root_password redis_password; do
  set -- "$@" "--from-file=$key=$DIR/$key"
done
kubectl -n "$NS" create secret generic "$NAME" "$@" --dry-run=client -o yaml | kubectl -n "$NS" apply -f -

echo "Secret $NS/$NAME is ready. Install with: --set secrets.existingSecret=$NAME"
echo "The files are in $DIR: move them to your secret store, then delete the directory."
