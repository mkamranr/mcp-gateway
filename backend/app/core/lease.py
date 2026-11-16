"""Redis leases for work that must run on one replica at a time (SIEM forwarding, health checks, bootstrap).

Acquire, renew and release are atomic and owner-checked (Lua), so a replica whose lease expired can never extend
or delete a lease another replica has taken over since.
"""

from __future__ import annotations

from redis.asyncio import Redis

# KEYS[1] lease key. ARGV: owner, ttl_ms. 1 = held by owner (now with a fresh ttl), 0 = held by someone else.
_ACQUIRE = """
if redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2]) then return 1 end
if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('PEXPIRE', KEYS[1], ARGV[2]) return 1 end
return 0
"""
_RENEW = """
if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('PEXPIRE', KEYS[1], ARGV[2]) return 1 end
return 0
"""
_RELEASE = """
if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end
return 0
"""


class Lease:
    def __init__(self, redis: Redis, key: str, owner: str, ttl_seconds: float) -> None:
        self.redis = redis
        self.key = key
        self.owner = owner
        self.ttl_ms = int(ttl_seconds * 1000)

    async def _run(self, script: str, *args: str | int) -> int:
        return int(await self.redis.eval(script, 1, self.key, *args))  # type: ignore[misc]

    async def acquire(self) -> bool:
        """Take the lease, or refresh it if this owner already holds it."""
        return bool(await self._run(_ACQUIRE, self.owner, self.ttl_ms))

    async def renew(self) -> bool:
        """Extend the lease. False means it expired and may now belong to another replica: stop working."""
        return bool(await self._run(_RENEW, self.owner, self.ttl_ms))

    async def release(self) -> None:
        await self._run(_RELEASE, self.owner)

    async def holder(self) -> str | None:
        value = await self.redis.get(self.key)
        return str(value) if value is not None else None
