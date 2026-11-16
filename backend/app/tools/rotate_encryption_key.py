"""Offline rotation of DATA_ENCRYPTION_KEY (spec §27 "Encryption key rotation").

Re-encrypts every AES-GCM ciphertext the gateway stores from the old key to the new key:

* ``secrets.ciphertext``                upstream credentials      AD = "<tenant>:<secret id>"
* ``approval_requests.arguments_encrypted`` approval arguments   AD = "<tenant>:<approval id>"
* ``approval_requests.result_encrypted``    approved-call results AD = "<tenant>:<approval id>:result"
* ``system_settings[oidc].value.client_secret_enc`` SSO client secret AD = "system:oidc:client_secret"

Procedure (see docs/operations.md): stop gateway-api and worker, back up MongoDB and the old key, run this
tool, switch DATA_ENCRYPTION_KEY to the new key, start the services. The tool is idempotent: values that
already decrypt with the new key are skipped, so an interrupted run can be repeated. It never prints keys
or plaintext.

    python -m app.tools.rotate_encryption_key --old-key-file old.key --new-key-file new.key [--dry-run]
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import sys
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
    value = Path(path).read_text(encoding="utf-8").strip()
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != 32:
        raise SystemExit(f"{path}: key must decode to exactly 32 bytes")
    return raw


@dataclass
class Report:
    rotated: int = 0
    already_new: int = 0
    failed: list[str] = field(default_factory=list)


async def rotate(db: Any, old: Encryptor, new: Encryptor, *, dry_run: bool = False) -> Report:
    report = Report()
    for collection, fld, suffix in TARGETS:
        async for doc in db[collection].find({fld: {"$nin": [None, ""]}}, {fld: 1, "tenant_id": 1}):
            ad = f"{doc['tenant_id']}:{doc['_id']}{suffix}"
            token = doc[fld]
            try:
                new.decrypt(token, ad)
                report.already_new += 1
                continue
            except Exception:  # noqa: BLE001,S110 - not yet rotated
                pass
            try:
                plaintext = old.decrypt(token, ad)
            except Exception:  # noqa: BLE001
                report.failed.append(f"{collection}/{doc['_id']}.{fld}")
                continue
            if not dry_run:
                # Compare-and-set on the old ciphertext so a concurrent writer is never overwritten.
                res = await db[collection].update_one({"_id": doc["_id"], fld: token},
                                                      {"$set": {fld: new.encrypt(plaintext, ad)}})
                if res.modified_count != 1:
                    report.failed.append(f"{collection}/{doc['_id']}.{fld} (changed during rotation)")
                    continue
            report.rotated += 1
    await _rotate_oidc_secret(db, old, new, report, dry_run)
    return report


async def _rotate_oidc_secret(db: Any, old: Encryptor, new: Encryptor, report: Report, dry_run: bool) -> None:
    from app.services.sso_service import CONFIG_KEY, SECRET_AAD

    fld = "value.client_secret_enc"
    doc = await db["system_settings"].find_one({"key": CONFIG_KEY, fld: {"$nin": [None, ""]}})
    if doc is None:
        return
    token = doc["value"]["client_secret_enc"]
    try:
        new.decrypt(token, SECRET_AAD)
        report.already_new += 1
        return
    except Exception:  # noqa: BLE001,S110 - not yet rotated
        pass
    try:
        plaintext = old.decrypt(token, SECRET_AAD)
    except Exception:  # noqa: BLE001
        report.failed.append(f"system_settings/{CONFIG_KEY}.client_secret_enc")
        return
    if not dry_run:
        res = await db["system_settings"].update_one({"_id": doc["_id"], fld: token},
                                                     {"$set": {fld: new.encrypt(plaintext, SECRET_AAD)}})
        if res.modified_count != 1:
            report.failed.append(f"system_settings/{CONFIG_KEY}.client_secret_enc (changed during rotation)")
            return
    report.rotated += 1


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
