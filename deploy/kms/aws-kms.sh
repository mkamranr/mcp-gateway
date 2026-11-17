#!/bin/sh
# Example KMS command for AWS KMS (KMS_PROVIDER=command). See docs/key-management.md.
#
#   KMS_WRAP_COMMAND=/opt/mgw/aws-kms.sh wrap
#   KMS_UNWRAP_COMMAND=/opt/mgw/aws-kms.sh unwrap
#   AWS_KMS_KEY_ID=arn:aws:kms:<region>:<account>:key/<key-id>     (a symmetric encryption key)
#
# Needs the AWS CLI v2 in the image (build a derived image) and credentials from the environment: an instance
# profile, IRSA / EKS Pod Identity, or AWS_* variables. Grant kms:Decrypt (and kms:Encrypt for wrapping) on
# this key only.
#
# stdin: the plain value (wrap) or the base64 ciphertext (unwrap). stdout: the result. Nothing is logged.
# An example: test it with `python -m app.tools.kms check` before relying on it.
set -eu
: "${AWS_KMS_KEY_ID:?AWS_KMS_KEY_ID is required}"
case "${1:-}" in
  wrap)
    aws kms encrypt --key-id "$AWS_KMS_KEY_ID" --plaintext fileb:///dev/stdin \
      --encryption-context purpose=mcp-gateway --query CiphertextBlob --output text ;;
  unwrap)
    base64 -d | aws kms decrypt --key-id "$AWS_KMS_KEY_ID" --ciphertext-blob fileb:///dev/stdin \
      --encryption-context purpose=mcp-gateway --query Plaintext --output text | base64 -d ;;
  *) echo "usage: $0 wrap|unwrap" >&2; exit 64 ;;
esac
