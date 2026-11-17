"""Offline rotation of DATA_ENCRYPTION_KEY (spec §27 "Encryption key rotation").

Re-encrypts every AES-GCM ciphertext the gateway stores from the old key to the new key:

* ``secrets.ciphertext``                upstream credentials      AD = "<tenant>:<secret id>"
* ``approval_requests.arguments_encrypted`` approval arguments   AD = "<tenant>:<approval id>"
* ``approval_requests.result_encrypted``    approved-call results AD = "<tenant>:<approval id>:result"
* ``system_settings[oidc].value.client_secret_enc`` SSO client secret AD = "system:oidc:client_secret"
* ``system_settings[siem].value.http_auth_value_enc`` SIEM collector credential AD = "system:siem:http_auth_value"

Procedure (see docs/operations.md): stop gateway-api and worker, back up MongoDB and the old key, run this
tool, switch DATA_ENCRYPTION_KEY to the new key, start the services. The tool is idempotent: values that
already decrypt with the new key are skipped, so an interrupted run can be repeated. It never prints keys
or plaintext.

    python -m app.tools.rotate_encryption_key --old-key-file old.key --new-key-file new.key [--dry-run]

Either key file may be wrapped by the key service (docs/key-management.md).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pymongo import AsyncMongoClient

from app.core.crypto import Encryptor

TARGETS: list[tuple[str, str, str]] = [
    # (collection, field, associated-data suffix)
    ("secrets", "ciphertext", ""),
    ("approval_requests", "arguments_encrypted", ""),
    ("approval_requests", "result_encrypted", ":result"),
]


def load_key(path: str) -> bytes:
    """A plain key file, or a wrapped one (docs/key-management.md), unwrapped through the key service."""
    from app.core import kms

    value = Path(path).read_text(encoding="utf-8").strip()
    if kms.is_wrapped(value):
        try:
            value = kms.unwrap(kms.provider_for(kms.KmsConfig.from_env()), value)
        except kms.KmsError as exc:
            raise SystemExit(f"{path}: {exc}") from None
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != 32:
        raise SystemExit(f"{path}: key must decode to exactly 32 bytes")
    return raw


@dataclass
class Report:
    rotated: int = 0
    already_new: int = 0
    failed: list[str] = field(default_factory=list)


@dataclass
class Ciphertext:
    """One stored AES-GCM value: where it lives and the associated data it was sealed with."""

    label: str
    collection: str
    doc_id: Any
    field: str  # dotted path, used for the compare-and-set update
    token: str
    ad: str


async def iter_ciphertexts(db: Any) -> AsyncIterator[Ciphertext]:
    """Every ciphertext the gateway stores. Shared by rotation and by ``app.tools.verify_data``."""
    from app.services import siem_service, sso_service

    for collection, fld, suffix in TARGETS:
        async for doc in db[collection].find({fld: {"$nin": [None, ""]}}, {fld: 1, "tenant_id": 1}):
            yield Ciphertext(f"{collection}/{doc['_id']}.{fld}", collection, doc["_id"], fld, doc[fld],
                             f"{doc['tenant_id']}:{doc['_id']}{suffix}")
    for key, name, aad in ((sso_service.CONFIG_KEY, "client_secret_enc", sso_service.SECRET_AAD),
                           (siem_service.CONFIG_KEY, "http_auth_value_enc", siem_service.SECRET_AAD)):
        fld = f"value.{name}"
        doc = await db["system_settings"].find_one({"key": key, fld: {"$nin": [None, ""]}})
        if doc is not None:
            yield Ciphertext(f"system_settings/{key}.{name}", "system_settings", doc["_id"], fld,
                             doc["value"][name], aad)


async def rotate(db: Any, old: Encryptor, new: Encryptor, *, dry_run: bool = False) -> Report:
    report = Report()
    async for c in iter_ciphertexts(db):
        try:
            new.decrypt(c.token, c.ad)
            report.already_new += 1
            continue
        except Exception:  # noqa: BLE001,S110 - not yet rotated
            pass
        try:
            plaintext = old.decrypt(c.token, c.ad)
        except Exception:  # noqa: BLE001
            report.failed.append(c.label)
            continue
        if not dry_run:
            # Compare-and-set on the old ciphertext so a concurrent writer is never overwritten.
            res = await db[c.collection].update_one({"_id": c.doc_id, c.field: c.token},
                                                    {"$set": {c.field: new.encrypt(plaintext, c.ad)}})
            if res.modified_count != 1:
                report.failed.append(f"{c.label} (changed during rotation)")
                continue
        report.rotated += 1
    return report


async def _main(ns: argparse.Namespace) -> int:
    from app.config import get_settings

    settings = get_settings()
    old, new = Encryptor(load_key(ns.old_key_file)), Encryptor(load_key(ns.new_key_file))
    client: AsyncMongoClient[Any] = AsyncMongoClient(settings.mongodb_uri, tz_aware=True)
    try:
        report = await rotate(client[settings.mongodb_database], old, new, dry_run=ns.dry_run)
    finally:
        await client.close()
    mode = "DRY RUN: " if ns.dry_run else ""
    print(f"{mode}rotated={report.rotated} already_on_new_key={report.already_new} failed={len(report.failed)}")
    for item in report.failed[:50]:
        print(f"  could not rotate {item}")
    return 1 if report.failed else 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--old-key-file", required=True)
    parser.add_argument("--new-key-file", required=True)
    parser.add_argument("--dry-run", action="store_true")
    sys.exit(asyncio.run(_main(parser.parse_args())))


if __name__ == "__main__":
    main()
