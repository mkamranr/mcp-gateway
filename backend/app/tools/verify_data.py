"""Post-restore integrity check (docs/operations.md, "Backup and restore").

Reports document counts per collection and decrypts every stored ciphertext with the *current*
DATA_ENCRYPTION_KEY, so a restore made with the wrong key, or a damaged archive, is caught before the gateway
serves traffic. It prints counts and the labels of failures only: never keys, plaintext or ciphertext.
Read-only.

    python -m app.tools.verify_data            # human-readable
    python -m app.tools.verify_data --json     # machine-readable (used by the CI restore drill)

Exit status: 0 = every ciphertext decrypts, 1 = at least one does not, 2 = the database is empty or
unreachable.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

from pymongo import AsyncMongoClient

from app.core.crypto import Encryptor
from app.tools.rotate_encryption_key import iter_ciphertexts


async def verify(db: Any, encryptor: Encryptor) -> dict[str, Any]:
    names = sorted(n for n in await db.list_collection_names() if not n.startswith("system."))
    counts = {n: await db[n].count_documents({}) for n in names}
    checked, failed = 0, []
    async for c in iter_ciphertexts(db):
        checked += 1
        try:
            encryptor.decrypt(c.token, c.ad)
        except Exception:  # noqa: BLE001 - any failure means unreadable with this key
            failed.append(c.label)
    return {"collections": counts, "ciphertexts": {"checked": checked, "failed": failed}}


async def _main(as_json: bool) -> int:
    from app.config import get_settings

    settings = get_settings()
    client: AsyncMongoClient[Any] = AsyncMongoClient(settings.mongodb_uri, tz_aware=True,
                                                     serverSelectionTimeoutMS=15000)
    try:
        report = await verify(client[settings.mongodb_database], Encryptor(settings.encryption_key_bytes()))
    except Exception as exc:  # noqa: BLE001
        print(f"cannot read the database: {type(exc).__name__}", file=sys.stderr)
        return 2
    finally:
        await client.close()
    if as_json:
        print(json.dumps(report, sort_keys=True))
    else:
        for name, n in report["collections"].items():
            print(f"{name:28} {n:>10}")
        ct = report["ciphertexts"]
        print(f"ciphertexts checked={ct['checked']} unreadable={len(ct['failed'])}")
        for label in ct["failed"][:50]:
            print(f"  cannot decrypt {label}")
    if not report["collections"].get("users"):
        return 2
    return 1 if report["ciphertexts"]["failed"] else 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="print one JSON object")
    sys.exit(asyncio.run(_main(parser.parse_args().json)))


if __name__ == "__main__":
    main()
