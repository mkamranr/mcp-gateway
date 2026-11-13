"""MongoDB and Redis connection holders."""

from __future__ import annotations

from typing import Any

from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase
from redis.asyncio import Redis

from app.config import Settings


class Database:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client: AsyncMongoClient[dict[str, Any]] = AsyncMongoClient(
            settings.mongodb_uri, tz_aware=True, serverSelectionTimeoutMS=5000, uuidRepresentation="standard"
        )
        self.db: AsyncDatabase[dict[str, Any]] = self.client[settings.mongodb_database]

    def __getitem__(self, name: str) -> Any:
        return self.db[name]

    async def ping(self) -> bool:
        try:
            await self.client.admin.command("ping")
            return True
        except Exception:  # noqa: BLE001
            return False

    async def close(self) -> None:
        await self.client.close()


def create_redis(settings: Settings) -> Redis:
    return Redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=5, socket_connect_timeout=5)


async def redis_ping(redis: Redis) -> bool:
    try:
        return bool(await redis.ping())
    except Exception:  # noqa: BLE001
        return False
