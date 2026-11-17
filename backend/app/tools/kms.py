"""Wrap the gateway's secrets with the key service (docs/key-management.md).

    python -m app.tools.kms generate data_encryption_key > secrets/data_encryption_key   # new, wrapped
    python -m app.tools.kms wrap < plain-file > wrapped-file                              # existing value
    python -m app.tools.kms rewrap < wrapped-file > new-file      # after rotating the key-encryption key
    python -m app.tools.kms check secrets/data_encryption_key secrets/api_key_hash_pepper
    python -m app.tools.kms unwrap --out plain-file < wrapped-file  # moving off the key service

The key service is configured with the same environment variables as the gateway (KMS_PROVIDER, VAULT_* or
KMS_*_COMMAND). Plain values are never printed: ``generate`` prints only the wrapped value, and ``unwrap`` writes
to a file created with mode 0600. ``check`` prints a fingerprint (first 12 hex digits of SHA-256) to compare values.
"""

from __future__ import annotations

import argparse
import base64
import os
import secrets
import sys
from pathlib import Path

from app.config import _read_secret_files
from app.core import kms

GENERATED = {
    # AES-256 key: 32 random bytes, urlsafe base64 (as deploy/scripts/generate-secrets.sh)
    "data_encryption_key": lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
    "api_key_hash_pepper": lambda: secrets.token_urlsafe(48),
    "session_secret": lambda: secrets.token_urlsafe(48),
}


def _stdin() -> str:
    value = sys.stdin.read().strip()
    if not value:
        raise SystemExit("nothing on stdin")
    return value


def _valid_dek(value: str) -> bool:
    try:
        return len(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))) == 32
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.tools.kms", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="generate a new secret and print it wrapped")
    g.add_argument("kind", choices=sorted(GENERATED))
    sub.add_parser("wrap", help="wrap the plain value on stdin")
    sub.add_parser("rewrap", help="re-encrypt the wrapped value on stdin under the current key version")
    c = sub.add_parser("check", help="unwrap files and report fingerprints, never values")
    c.add_argument("files", nargs="+")
    u = sub.add_parser("unwrap", help="unwrap the value on stdin into a new file (mode 0600)")
    u.add_argument("--out", required=True)
    ns = parser.parse_args(argv)

    _read_secret_files()
    cfg = kms.KmsConfig.from_env()
    try:
        provider = kms.provider_for(cfg)
        if ns.cmd == "generate":
            print(kms.wrap(provider, GENERATED[ns.kind]()))
        elif ns.cmd == "wrap":
            value = _stdin()
            if kms.is_wrapped(value):
                raise SystemExit("already wrapped")
            print(kms.wrap(provider, value))
        elif ns.cmd == "rewrap":
            value = _stdin()
            if not kms.is_wrapped(value):
                raise SystemExit("not a wrapped value")
            print(kms.rewrap(provider, value))
        elif ns.cmd == "check":
            failed = 0
            for f in ns.files:
                value = Path(f).read_text(encoding="utf-8").strip()
                if not kms.is_wrapped(value):
                    print(f"plain     {f}  fingerprint {kms.fingerprint(value)}")
                    continue
                try:
                    plain = kms.unwrap(provider, value)
                except kms.KmsError as exc:
                    failed += 1
                    print(f"FAILED    {f}: {exc}")
                    continue
                note = "" if "encryption_key" not in Path(f).name or _valid_dek(plain) else "  NOT A 32-BYTE KEY"
                print(f"unwrapped {f}  fingerprint {kms.fingerprint(plain)}{note}")
                failed += bool(note)
            print(cfg.describe())
            return 1 if failed else 0
        elif ns.cmd == "unwrap":
            value = _stdin()
            if not kms.is_wrapped(value):
                raise SystemExit("not a wrapped value")
            if Path(ns.out).exists():
                print(f"error: {ns.out} exists; refusing to overwrite", file=sys.stderr)
                return 1
            plain = kms.unwrap(provider, value)
            fd = os.open(ns.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(plain)
            print(f"wrote {ns.out} (fingerprint {kms.fingerprint(plain)})", file=sys.stderr)
    except kms.KmsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
