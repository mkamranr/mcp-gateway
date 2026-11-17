#!/bin/sh
# Example KMS command for Google Cloud KMS (KMS_PROVIDER=command). See docs/key-management.md.
#
#   KMS_WRAP_COMMAND=/opt/mgw/gcp-kms.sh wrap
#   KMS_UNWRAP_COMMAND=/opt/mgw/gcp-kms.sh unwrap
#   GCP_KMS_KEY=projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>
#
# Needs the gcloud CLI in the image (build a derived image) and credentials (Workload Identity, or a service
# account key mounted as a secret). Grant roles/cloudkms.cryptoKeyDecrypter (and ...Encrypter for wrapping) on
# this key only. Cloud HSM keys (protection level HSM) work the same way.
#
# stdin: the plain value (wrap) or the base64 ciphertext (unwrap). stdout: the result. Nothing is logged.
# An example: test it with `python -m app.tools.kms check` before relying on it.
set -eu
: "${GCP_KMS_KEY:?GCP_KMS_KEY is required}"
case "${1:-}" in
  wrap)
    gcloud kms encrypt --key "$GCP_KMS_KEY" --plaintext-file=- --ciphertext-file=- | base64 | tr -d '\n' ;;
  unwrap)
    base64 -d | gcloud kms decrypt --key "$GCP_KMS_KEY" --ciphertext-file=- --plaintext-file=- ;;
  *) echo "usage: $0 wrap|unwrap" >&2; exit 64 ;;
esac
