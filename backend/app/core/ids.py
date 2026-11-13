"""Identifier, time and canonical-hash helpers."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime
from typing import Any


def new_id(prefix: str) -> str:
    """Opaque, URL-safe, globally unique identifier with a type prefix (e.g. ``srv_...``)."""
    return f"{prefix}_{secrets.token_hex(12)}"


def utcnow() -> datetime:
    # Mongo stores millisecond precision; truncate so round-trips compare equal.
    now = datetime.now(UTC)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


def canonical_json(value: Any) -> str:
    """Deterministic JSON used for hashing arguments and schemas."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_hex(value: Any) -> str:
    data = value if isinstance(value, bytes) else canonical_json(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def ensure_aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
