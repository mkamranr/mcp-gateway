"""Container healthcheck for the worker: healthy when *this host's* worker has a recent heartbeat.

    python -m app.workers.healthcheck   (exit 0 = healthy)

Each worker beats under its own host name, so with several workers a hung one is reported unhealthy even while
the others are fine.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import time

from app.config import get_settings
from app.db import create_redis
from app.workers.heartbeat import HEARTBEAT_KEY

MAX_AGE_SECONDS = 90


async def _check() -> bool:
    redis = create_redis(get_settings())
    try:
        beat = await redis.zscore(HEARTBEAT_KEY, socket.gethostname())
        return beat is not None and time.time() - float(beat) < MAX_AGE_SECONDS
    finally:
        await redis.aclose()


if __name__ == "__main__":
    try:
        sys.exit(0 if asyncio.run(_check()) else 1)
    except Exception:  # noqa: BLE001
        sys.exit(1)
