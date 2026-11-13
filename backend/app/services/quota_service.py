"""Rate limits, quotas and concurrency (spec §13), enforced atomically in Redis.

Semantics (documented in docs/security-model.md):
* All limits for one call are checked and consumed in a single Lua script. A call is either
  admitted against every limit or rejected without consuming any of them, so there is no
  partial consumption and no race between concurrent callers.
* Quota is consumed at admission, after policy and input validation pass. Denied or invalid
  calls do not consume quota. Admitted calls whose upstream later fails do consume it.
* Approval-pending calls do not reserve quota. Quota is re-checked when the approved call executes.
* Rate windows (minute/hour) are sliding. Daily and monthly quotas are fixed UTC calendar windows.
* If Redis is unavailable, hard limits fail closed. The development fail-open mode must be
  enabled explicitly and is refused in production.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis

from app.config import Settings
from app.core.errors import ErrorCode, GatewayError
from app.core.identity import Principal
from app.core.ids import utcnow
from app.core.logging import get_logger

log = get_logger(__name__)

# KEYS: limit keys. ARGV: now_ms, member, then (kind, window_ms, limit) triples.
# kind 'z' = sliding window sorted set; kind 'c' = fixed window counter.
# Returns {0} if admitted, else {1-based index of the failing limit, retry_after_ms}.
CHECK_AND_CONSUME = """
local now = tonumber(ARGV[1])
local member = ARGV[2]
local n = #KEYS
for i = 1, n do
  local kind = ARGV[3 + (i-1)*3]
  local window = tonumber(ARGV[4 + (i-1)*3])
  local limit = tonumber(ARGV[5 + (i-1)*3])
  if kind == 'z' then
    redis.call('ZREMRANGEBYSCORE', KEYS[i], 0, now - window)
    local count = redis.call('ZCARD', KEYS[i])
    if count >= limit then
      local oldest = redis.call('ZRANGE', KEYS[i], 0, 0, 'WITHSCORES')
      local retry = window
      if oldest[2] then retry = tonumber(oldest[2]) + window - now end
      return {i, retry}
    end
  else
    local count = tonumber(redis.call('GET', KEYS[i]) or '0')
    if count >= limit then
      return {i, redis.call('PTTL', KEYS[i])}
    end
  end
end
for i = 1, n do
  local kind = ARGV[3 + (i-1)*3]
  local window = tonumber(ARGV[4 + (i-1)*3])
  if kind == 'z' then
    redis.call('ZADD', KEYS[i], now, member)
    redis.call('PEXPIRE', KEYS[i], window)
  else
    local v = redis.call('INCR', KEYS[i])
    if v == 1 then redis.call('PEXPIRE', KEYS[i], window) end
  end
end
return {0, 0}
"""

# KEYS: concurrency keys. ARGV: limits. Acquire all slots or none.
ACQUIRE = """
for i = 1, #KEYS do
  local v = tonumber(redis.call('GET', KEYS[i]) or '0')
  if v >= tonumber(ARGV[i]) then return i end
end
for i = 1, #KEYS do
  redis.call('INCR', KEYS[i])
  redis.call('EXPIRE', KEYS[i], 900)
end
return 0
"""

RELEASE = """
for i = 1, #KEYS do
  local v = redis.call('DECR', KEYS[i])
  if v < 0 then redis.call('SET', KEYS[i], 0) end
end
return 0
"""

WINDOWS_MS = {"per_minute": 60_000, "per_hour": 3_600_000}


@dataclass
class Limit:
    scope: str
    key: str
    kind: str  # 'z' or 'c'
    window_ms: int
    limit: int
    label: str


@dataclass
class Admission:
    concurrency_keys: list[str]
    warnings: list[dict[str, Any]]


class QuotaService:
    def __init__(self, settings: Settings, redis: Redis) -> None:
        self.settings = settings
        self.redis = redis
        self._check = redis.register_script(CHECK_AND_CONSUME)
        self._acquire = redis.register_script(ACQUIRE)
        self._release = redis.register_script(RELEASE)

    def _fail_open(self) -> bool:
        return self.settings.redis_fail_open_dev and self.settings.app_env == "development"

    @staticmethod
    def _period_keys() -> dict[str, tuple[str, int]]:
        now = utcnow()
        day = now.strftime("%Y%m%d")
        month = now.strftime("%Y%m")
        end_of_day = 86_400_000 - ((now.hour * 3600 + now.minute * 60 + now.second) * 1000)
        # month window: approximate remaining ms in month (safe upper bound of 31 days)
        days_left = 31 - now.day + 1
        return {"per_day": (day, end_of_day), "per_month": (month, days_left * 86_400_000)}

    def build_limits(
        self,
        principal: Principal,
        tool: dict[str, Any],
        tenant_settings: dict[str, Any],
        obligations: dict[str, Any],
        global_limits: dict[str, Any] | None = None,
    ) -> list[Limit]:
        t = principal.tenant_id
        tool_id = tool["_id"]
        periods = self._period_keys()
        limits: list[Limit] = []

        def add(scope: str, base: str, spec: dict[str, Any] | None) -> None:
            for name, value in (spec or {}).items():
                if not value or name not in ("per_minute", "per_hour", "per_day", "per_month"):
                    continue
                if name in WINDOWS_MS:
                    limits.append(Limit(scope, f"{base}:{name}", "z", WINDOWS_MS[name], int(value), name))
                else:
                    pid, ttl = periods[name]
                    limits.append(Limit(scope, f"{base}:{name}:{pid}", "c", ttl, int(value), name))

        add("global", "q:global", global_limits)
        add("tenant", f"q:t:{t}", tenant_settings.get("quotas"))
        add("tool", f"q:t:{t}:tool:{tool_id}", tool.get("limits"))
        add("policy", f"q:t:{t}:p:{principal.principal_id}:tool:{tool_id}", obligations.get("limits"))
        return limits

    async def check_and_consume(self, limits: list[Limit]) -> list[dict[str, Any]]:
        if not limits:
            return []
        keys = [lim.key for lim in limits]
        args: list[Any] = [int(time.time() * 1000), uuid.uuid4().hex]
        for lim in limits:
            args += [lim.kind, lim.window_ms, lim.limit]
        try:
            idx, retry_ms = await self._check(keys=keys, args=args)
        except Exception as exc:  # noqa: BLE001
            log.error("quota.redis_unavailable", error=type(exc).__name__)
            if self._fail_open():
                return [{"scope": "redis", "warning": "quota enforcement bypassed (development fail-open)"}]
            raise GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE, "Quota enforcement is unavailable.") from exc
        if int(idx) > 0:
            lim = limits[int(idx) - 1]
            retry = max(1, int((int(retry_ms) if int(retry_ms) > 0 else lim.window_ms) / 1000 + 0.999))
            code = ErrorCode.QUOTA_EXCEEDED if lim.kind == "c" else ErrorCode.RATE_LIMIT_EXCEEDED
            raise GatewayError(code, f"{'Quota' if lim.kind == 'c' else 'Rate limit'} exceeded ({lim.scope} {lim.label}).",
                               headers={"Retry-After": str(retry)},
                               extra={"scope": lim.scope, "limit": lim.limit, "window": lim.label,
                                      "retry_after_seconds": retry})
        return await self._soft_warnings(limits)

    async def _soft_warnings(self, limits: list[Limit]) -> list[dict[str, Any]]:
        warnings = []
        try:
            for lim in limits:
                used = await (self.redis.zcard(lim.key) if lim.kind == "z" else self.redis.get(lim.key))
                used_n = int(used or 0)
                if used_n >= 0.8 * lim.limit:
                    flag = f"{lim.key}:warned"
                    if await self.redis.set(flag, "1", nx=True, px=lim.window_ms):
                        warnings.append({"scope": lim.scope, "window": lim.label, "used": used_n, "limit": lim.limit})
        except Exception:  # noqa: BLE001,S110 - warnings are best effort
            pass
        return warnings

    async def acquire_concurrency(self, principal: Principal, tool: dict[str, Any]) -> list[str]:
        t = principal.tenant_id
        keys = [f"c:t:{t}:p:{principal.principal_id}"]
        limits = [self.settings.max_concurrent_calls_per_agent]
        tool_conc = (tool.get("limits") or {}).get("concurrency")
        if tool_conc:
            keys.append(f"c:t:{t}:tool:{tool['_id']}")
            limits.append(int(tool_conc))
        try:
            failed = int(await self._acquire(keys=keys, args=limits))
        except Exception as exc:  # noqa: BLE001
            if self._fail_open():
                return []
            raise GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE, "Quota enforcement is unavailable.") from exc
        if failed:
            raise GatewayError(ErrorCode.CONCURRENCY_LIMIT_EXCEEDED, "Too many concurrent calls.",
                               headers={"Retry-After": "1"})
        return keys

    async def release_concurrency(self, keys: list[str]) -> None:
        if not keys:
            return
        try:
            await self._release(keys=keys, args=[])
        except Exception:  # noqa: BLE001
            log.warning("quota.release_failed")

    async def in_flight(self, tenant_id: str) -> int:
        total = 0
        try:
            async for key in self.redis.scan_iter(match=f"c:t:{tenant_id}:p:*", count=200):
                total += int(await self.redis.get(key) or 0)
        except Exception:  # noqa: BLE001
            return -1
        return total

    async def usage_snapshot(self, tenant_id: str, tenant_settings: dict[str, Any]) -> list[dict[str, Any]]:
        """Current utilisation of tenant-level limits, for the Usage & Quotas page."""
        periods = self._period_keys()
        out = []
        for name, value in (tenant_settings.get("quotas") or {}).items():
            if not value:
                continue
            try:
                if name in WINDOWS_MS:
                    key = f"q:t:{tenant_id}:{name}"
                    await self.redis.zremrangebyscore(key, 0, int(time.time() * 1000) - WINDOWS_MS[name])
                    used = await self.redis.zcard(key)
                elif name in periods:
                    used = int(await self.redis.get(f"q:t:{tenant_id}:{name}:{periods[name][0]}") or 0)
                else:
                    continue
            except Exception:  # noqa: BLE001
                used = None
            out.append({"scope": "tenant", "window": name, "limit": int(value), "used": used})
        return out
