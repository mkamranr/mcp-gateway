"""Container healthcheck for the worker: healthy when its Redis heartbeat is recent.

    python -m app.workers.healthcheck   (exit 0 = healthy)
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime

from app.config import get_settings
from app.core.ids import utcnow
from app.db import create_redis

MAX_AGE_SECONDS = 90


async def _check() -> bool:
    redis = create_redis(get_settings())
    try:
        beat = await redis.get("worker:heartbeat")
        if not beat:
            return False
        return (utcnow() - datetime.fromisoformat(str(beat))).total_seconds() < MAX_AGE_SECONDS
    finally:
        await redis.aclose()


if __name__ == "__main__":
    try:
        sys.exit(0 if asyncio.run(_check()) else 1)
    except Exception:  # noqa: BLE001
        sys.exit(1)
