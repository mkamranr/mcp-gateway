"""Authentication: local users with server-side sessions, and agent API keys (spec §7)."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Any

from redis.asyncio import Redis

from app.config import Settings
from app.core.crypto import (
    constant_time_equals,
    hash_api_key,
    hash_password,
    password_needs_rehash,
    random_token,
    split_api_key,
    verify_password,
)
from app.core.errors import ErrorCode, GatewayError
from app.core.identity import Principal, Role
from app.core.ids import ensure_aware, utcnow
from app.core.logging import get_logger
from app.repositories.collections import Repos
from app.services.audit_service import AuditService

log = get_logger(__name__)
SYSTEM_TENANT = "_system"  # audit bucket for events before a tenant is known


class AuthService:
    def __init__(self, settings: Settings, repos: Repos, redis: Redis, audit: AuditService) -> None:
        self.settings = settings
        self.repos = repos
        self.redis = redis
        self.audit = audit

    # ------------------------------------------------------------------ rate limiting
    async def _throttle(self, key: str, limit: int, window: int) -> None:
        try:
            k = f"authrl:{hashlib.sha256(key.encode()).hexdigest()[:32]}"
            count = await self.redis.incr(k)
            if count == 1:
                await self.redis.expire(k, window)
        except Exception as exc:  # noqa: BLE001
            raise GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE, "Authentication is temporarily unavailable.") from exc
        if count > limit:
            raise GatewayError(
                ErrorCode.RATE_LIMIT_EXCEEDED, "Too many authentication attempts. Try again later.",
                headers={"Retry-After": str(window)},
            )

    # ------------------------------------------------------------------ users
    async def login(self, username: str, password: str, source_ip: str, tenant_id: str | None) -> dict[str, Any]:
        uname = username.strip().lower()
        await self._throttle(
            f"login:{uname}:{source_ip}", self.settings.login_max_attempts_per_window,
            self.settings.login_window_seconds,
        )
        user = await self.repos.users.by_username(uname)
        ok = verify_password(password, user.get("password_hash") if user else None)
        if not ok or not user or user.get("status") != "active":
            await self.audit.record(
                SYSTEM_TENANT, "auth.login.failed",
                principal={"type": "user", "id": user["_id"] if user else None, "name": uname[:64]},
                status="failure", metadata={"source_ip": source_ip},
            )
            raise GatewayError(ErrorCode.INVALID_CREDENTIAL, "Invalid username or password.")
        assert user is not None
        if password_needs_rehash(user["password_hash"]):
            await self.repos.users.update(user["_id"], {"password_hash": hash_password(password)})

        tenants = await self._user_tenants(user)
        if not tenants:
            raise GatewayError(ErrorCode.ACCESS_DENIED, "This account has no active tenant membership.")
        active: str = tenant_id if tenant_id and tenant_id in tenants else (
            user["last_tenant_id"] if user.get("last_tenant_id") in tenants else tenants[0])
        sid = random_token(32)
        csrf = random_token(24)
        now = utcnow()
        session = {
            "user_id": user["_id"], "tenant_id": active, "csrf": csrf,
            "created_at": now.isoformat(),
            "absolute_expiry": (now + timedelta(minutes=self.settings.session_ttl_minutes)).isoformat(),
            "source_ip": source_ip,
        }
        try:
            await self.redis.set(self._skey(sid), json.dumps(session), ex=self.settings.session_idle_minutes * 60)
            await self.redis.sadd(f"usess:{user['_id']}", sid)
        except Exception as exc:  # noqa: BLE001
            raise GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE, "Authentication is temporarily unavailable.") from exc
        await self.repos.users.update(user["_id"], {"last_login_at": now, "last_tenant_id": active})
        await self.audit.record(
            active, "auth.login.succeeded", principal={"type": "user", "id": user["_id"], "name": user["username"]},
            status="success", metadata={"source_ip": source_ip},
        )
        return {"session_id": sid, "csrf": csrf, "tenant_id": active}

    async def _user_tenants(self, user: dict[str, Any]) -> list[str]:
        if user.get("is_platform_admin"):
            page = await self.repos.tenants.list({"status": "active"}, sort=[("name", 1)], limit=200)
            return [t["_id"] for t in page["items"]]
        memberships = await self.repos.memberships.for_user_global(user["_id"])
        ids = [m["tenant_id"] for m in memberships]
        active = await self.repos.tenants.col.find({"_id": {"$in": ids}, "status": "active"}, {"_id": 1}).to_list()
        return [t["_id"] for t in active]

    @staticmethod
    def _skey(sid: str) -> str:
        return f"sess:{hashlib.sha256(sid.encode()).hexdigest()}"

    async def resolve_session(self, sid: str) -> tuple[Principal, dict[str, Any]]:
        try:
            raw = await self.redis.get(self._skey(sid))
        except Exception as exc:  # noqa: BLE001
            raise GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE, "Authentication is temporarily unavailable.") from exc
        if not raw:
            raise GatewayError(ErrorCode.AUTHENTICATION_REQUIRED, "Session expired. Please sign in again.")
        session = json.loads(raw)
        from datetime import datetime

        if datetime.fromisoformat(session["absolute_expiry"]) <= utcnow():
            await self.redis.delete(self._skey(sid))
            raise GatewayError(ErrorCode.AUTHENTICATION_REQUIRED, "Session expired. Please sign in again.")
        user = await self.repos.users.get(session["user_id"])
        if not user or user.get("status") != "active":
            await self.redis.delete(self._skey(sid))
            raise GatewayError(ErrorCode.AUTHENTICATION_REQUIRED, "Session is no longer valid.")
        principal = await self.user_principal(user, session["tenant_id"], session_id=sid)
        await self.redis.expire(self._skey(sid), self.settings.session_idle_minutes * 60)  # sliding idle timeout
        return principal, session

    async def user_principal(self, user: dict[str, Any], tenant_id: str, session_id: str | None = None) -> Principal:
        tenant = await self.repos.tenants.get(tenant_id)
        if not tenant:
            raise GatewayError(ErrorCode.AUTHENTICATION_REQUIRED, "Tenant no longer exists.")
        is_global = bool(user.get("is_platform_admin"))
        roles: list[str] = []
        membership = await self.repos.memberships.find_one(tenant_id, {"user_id": user["_id"], "status": "active"})
        if membership:
            roles = list(membership.get("roles", []))
        if is_global:
            roles.append(Role.PLATFORM_ADMIN.value)
        if not roles:
            raise GatewayError(ErrorCode.ACCESS_DENIED, "No active membership in this tenant.")
        if tenant.get("status") != "active" and not is_global:
            raise GatewayError(ErrorCode.TENANT_SUSPENDED, "This tenant is suspended.")
        return Principal(
            principal_type="user", principal_id=user["_id"], tenant_id=tenant_id, roles=tuple(sorted(set(roles))),
            display_name=user.get("display_name") or user["username"], session_id=session_id,
            is_global_admin=is_global, tenant_ids=tuple(await self._user_tenants(user)),
        )

    async def switch_tenant(self, sid: str, principal: Principal, tenant_id: str) -> Principal:
        if tenant_id not in principal.tenant_ids:
            raise GatewayError(ErrorCode.NOT_FOUND, "Tenant not found.")
        raw = await self.redis.get(self._skey(sid))
        if not raw:
            raise GatewayError(ErrorCode.AUTHENTICATION_REQUIRED)
        session = json.loads(raw)
        session["tenant_id"] = tenant_id
        ttl = await self.redis.ttl(self._skey(sid))
        await self.redis.set(self._skey(sid), json.dumps(session), ex=max(ttl, 60))
        await self.repos.users.update(principal.principal_id, {"last_tenant_id": tenant_id})
        user = await self.repos.users.get(principal.principal_id)
        assert user is not None
        return await self.user_principal(user, tenant_id, session_id=sid)

    async def logout(self, sid: str, principal: Principal | None) -> None:
        try:
            await self.redis.delete(self._skey(sid))
            if principal:
                await self.redis.srem(f"usess:{principal.principal_id}", sid)
        except Exception:  # noqa: BLE001,S110
            pass
        if principal:
            await self.audit.record(principal.tenant_id, "auth.logout", principal=principal)

    async def revoke_user_sessions(self, user_id: str) -> None:
        sids = await self.redis.smembers(f"usess:{user_id}")
        for sid in sids:
            await self.redis.delete(self._skey(str(sid)))
        await self.redis.delete(f"usess:{user_id}")

    async def change_password(self, principal: Principal, current: str, new: str) -> None:
        user = await self.repos.users.get(principal.principal_id)
        if not user or not verify_password(current, user.get("password_hash")):
            raise GatewayError(ErrorCode.INVALID_CREDENTIAL, "Current password is incorrect.")
        await self.repos.users.update(user["_id"], {"password_hash": hash_password(new), "must_change_password": False})
        await self.revoke_user_sessions(user["_id"])
        await self.audit.record(principal.tenant_id, "auth.password.changed", principal=principal)

    # ------------------------------------------------------------------ agents
    async def authenticate_api_key(self, raw_key: str, source: str | None = None) -> Principal:
        """Resolve an agent API key to a Principal. Every failure path is indistinguishable to the caller."""
        prefix = split_api_key(raw_key.strip())
        if not prefix:
            raise GatewayError(ErrorCode.INVALID_CREDENTIAL)
        await self._throttle(f"apikey:{prefix}", 6000, 60)
        cred = await self.repos.credentials.by_prefix_global(prefix)
        expected = cred["secret_hash"] if cred else hash_api_key("x" * 40, self.settings.api_key_hash_pepper)
        presented = hash_api_key(raw_key.strip(), self.settings.api_key_hash_pepper)
        if not cred or not constant_time_equals(presented, expected):
            raise GatewayError(ErrorCode.INVALID_CREDENTIAL)
        tenant_id = cred["tenant_id"]
        if cred.get("revoked_at"):
            raise GatewayError(ErrorCode.CREDENTIAL_REVOKED, "The credential has been revoked.")
        exp = ensure_aware(cred.get("expires_at"))
        if exp and exp <= utcnow():
            raise GatewayError(ErrorCode.CREDENTIAL_EXPIRED, "The credential has expired.")
        tenant = await self.repos.tenants.get(tenant_id)
        if not tenant or tenant.get("status") != "active":
            raise GatewayError(ErrorCode.TENANT_SUSPENDED, "The tenant is suspended.")
        agent = await self.repos.agents.get(tenant_id, cred["principal_id"])
        if not agent or agent.get("status") != "active":
            raise GatewayError(ErrorCode.CREDENTIAL_REVOKED, "The agent is disabled.")
        last = ensure_aware(cred.get("last_used_at"))
        if not last or (utcnow() - last).total_seconds() > 30:
            await self.repos.credentials.touch(tenant_id, cred["_id"], source)
            await self.repos.agents.col.update_one(
                {"_id": agent["_id"], "tenant_id": tenant_id}, {"$set": {"last_activity_at": utcnow()}}
            )
        return Principal(
            principal_type="agent", principal_id=agent["_id"], tenant_id=tenant_id, roles=(),
            scopes=tuple(cred.get("scopes", [])), credential_id=cred["_id"], agent_id=agent["_id"],
            display_name=agent["name"],
        )

    async def revalidate_agent(self, tenant_id: str, agent_id: str, credential_id: str | None) -> None:
        """Used before approved execution: credential/agent/tenant must still be valid (spec §14.4)."""
        tenant = await self.repos.tenants.get(tenant_id)
        if not tenant or tenant.get("status") != "active":
            raise GatewayError(ErrorCode.TENANT_SUSPENDED)
        agent = await self.repos.agents.get(tenant_id, agent_id)
        if not agent or agent.get("status") != "active":
            raise GatewayError(ErrorCode.CREDENTIAL_REVOKED, "The agent is disabled.")
        if credential_id:
            cred = await self.repos.credentials.get(tenant_id, credential_id)
            if not cred or cred.get("revoked_at"):
                raise GatewayError(ErrorCode.CREDENTIAL_REVOKED)
            exp = ensure_aware(cred.get("expires_at"))
            if exp and exp <= utcnow():
                raise GatewayError(ErrorCode.CREDENTIAL_EXPIRED)
