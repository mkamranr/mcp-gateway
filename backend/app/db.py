"""MongoDB and Redis connection holders."""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote, urlsplit

from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase
from redis.asyncio import Redis
from redis.asyncio.sentinel import Sentinel

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


TIMEOUTS: dict[str, Any] = {"socket_timeout": 5, "socket_connect_timeout": 5}


def create_redis(settings: Settings) -> Redis:
    if not settings.redis_sentinels:
        return Redis.from_url(settings.redis_url, decode_responses=True, **TIMEOUTS)
    return _sentinel_master(settings)


def _sentinel_master(settings: Settings) -> Redis:
    """A client that always talks to the current master; after a failover it reconnects to the promoted replica."""
    url = urlsplit(settings.redis_url)
    master_kwargs: dict[str, Any] = {"decode_responses": True, **TIMEOUTS}
    if url.username:
        master_kwargs["username"] = unquote(url.username)
    if url.password:
        master_kwargs["password"] = unquote(url.password)
    db = url.path.lstrip("/")
    master_kwargs["db"] = int(db) if db.isdigit() else 0
    if url.scheme == "rediss":
        master_kwargs["ssl"] = True
    nodes = [(h, int(p)) for h, _, p in (s.rpartition(":") for s in settings.redis_sentinels)]
    sentinel_kwargs: dict[str, Any] = dict(TIMEOUTS)
    if settings.redis_sentinel_password:
        sentinel_kwargs["password"] = settings.redis_sentinel_password
    sentinel = Sentinel(nodes, sentinel_kwargs=sentinel_kwargs, **TIMEOUTS)
    return sentinel.master_for(settings.redis_sentinel_master, redis_class=Redis, **master_kwargs)


async def redis_ping(redis: Redis) -> bool:
    try:
        return bool(await redis.ping())
    except Exception:  # noqa: BLE001
        return False
