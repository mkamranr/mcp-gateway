#!/usr/bin/env sh
# Generates the secret files used by docker-compose.yml into ./secrets (mode 600).
# Existing files are never overwritten. Delete one deliberately to rotate it (see docs/operations.md).
#
#   ./deploy/scripts/generate-secrets.sh [secrets-dir]
set -eu

DIR="${1:-./secrets}"
umask 077
mkdir -p "$DIR"

rand() { # $1 = number of random bytes, urlsafe base64 without padding
  head -c "$1" /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'
}

write() { # $1 = name, $2 = value
  if [ -s "$DIR/$1" ]; then
    echo "keep     $DIR/$1"
  else
    printf '%s' "$2" > "$DIR/$1"
    chmod 600 "$DIR/$1"
    echo "created  $DIR/$1"
  fi
}

write session_secret "$(rand 48)"
# AES-256 key: exactly 32 bytes, urlsafe base64 (padding is restored by the application).
write data_encryption_key "$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '\n')"
write api_key_hash_pepper "$(rand 48)"
write bootstrap_admin_password "$(rand 18)"
write mongo_root_password "$(rand 24)"
write redis_password "$(rand 24)"

MONGO_PW="$(cat "$DIR/mongo_root_password")"
REDIS_PW="$(cat "$DIR/redis_password")"
write mongodb_uri "mongodb://mgw_root:${MONGO_PW}@mongodb:27017/?authSource=admin"
write redis_url "redis://:${REDIS_PW}@redis:6379/0"

echo
echo "Secrets are in $DIR. Back up data_encryption_key and api_key_hash_pepper securely:"
echo "losing them makes stored upstream secrets unreadable and invalidates every agent key."
echo "The initial admin password is in $DIR/bootstrap_admin_password. Change it after first login."
