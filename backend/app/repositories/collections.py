"""Concrete repositories, one per collection (spec §17.1)."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pymongo import ReturnDocument

from app.core.ids import new_id, utcnow
from app.repositories.base import GlobalRepository, Page, TenantScopedRepository


# ---------- global collections ----------
class TenantRepository(GlobalRepository):
    collection_name = "tenants"
    id_prefix = "ten"


class UserRepository(GlobalRepository):
    collection_name = "users"
    id_prefix = "usr"

    async def by_username(self, username: str) -> dict[str, Any] | None:
        return await self.col.find_one({"username": username.strip().lower()})


class SystemSettingsRepository(GlobalRepository):
    collection_name = "system_settings"

    async def get_value(self, key: str, default: Any = None) -> Any:
        doc = await self.col.find_one({"key": key})
        return doc["value"] if doc else default

    async def all(self) -> dict[str, Any]:
        return {d["key"]: d["value"] async for d in self.col.find({})}

    async def set_value(self, key: str, value: Any, updated_by: str) -> None:
        await self.col.update_one(
            {"key": key},
            {
                "$set": {"value": value, "updated_at": utcnow(), "updated_by": updated_by},
                "$setOnInsert": {"_id": new_id("set")},
            },
            upsert=True,
        )


# ---------- tenant-scoped collections ----------
class MembershipRepository(TenantScopedRepository):
    collection_name = "tenant_memberships"
    id_prefix = "mem"

    async def for_user_global(self, user_id: str) -> list[dict[str, Any]]:
        """Privileged: list a user's memberships across tenants (used only during login/session)."""
        return [d async for d in self.col.find({"user_id": user_id, "status": "active"})]


class AgentRepository(TenantScopedRepository):
    collection_name = "agents"
    id_prefix = "agt"
    versioned = True


class CredentialRepository(TenantScopedRepository):
    collection_name = "credentials"
    id_prefix = "cred"

    async def by_prefix_global(self, key_prefix: str) -> dict[str, Any] | None:
        """Privileged: resolve an API key prefix before the tenant is known (authentication)."""
        return await self.col.find_one({"key_prefix": key_prefix})

    async def by_cert_match_global(self, keys: list[str]) -> list[dict[str, Any]]:
        """Privileged: active certificate credentials matching a presented certificate (authentication)."""
        return [d async for d in self.col.find({"cert_match": {"$in": keys}, "revoked_at": None}).limit(10)]

    async def touch(self, tenant_id: str, cred_id: str, source: str | None) -> None:
        await self.col.update_one(
            {"_id": cred_id, "tenant_id": tenant_id},
            {"$set": {"last_used_at": utcnow(), "last_used_source": source}},
        )


class SecretRepository(TenantScopedRepository):
    collection_name = "secrets"
    id_prefix = "sec"


class ServerRepository(TenantScopedRepository):
    collection_name = "mcp_servers"
    id_prefix = "srv"
    versioned = True


class ToolRepository(TenantScopedRepository):
    collection_name = "tools"
    id_prefix = "tool"
    versioned = True

    async def by_gateway_name(self, tenant_id: str, gateway_name: str) -> dict[str, Any] | None:
        return await self.find_one(tenant_id, {"gateway_name": gateway_name, "archived": {"$ne": True}})


class ToolVersionRepository(TenantScopedRepository):
    collection_name = "tool_schema_versions"
    id_prefix = "tsv"


class PolicyRepository(TenantScopedRepository):
    collection_name = "policies"
    id_prefix = "pol"
    versioned = True

    async def enabled_for_tenant(self, tenant_id: str) -> list[dict[str, Any]]:
        """Tenant policies plus explicitly global policies (tenant_id == '*')."""
        q = {"tenant_id": {"$in": [tenant_id, "*"]}, "enabled": True}
        return [d async for d in self.col.find(q).sort([("priority", 1)])]


class ApprovalRepository(TenantScopedRepository):
    collection_name = "approval_requests"
    id_prefix = "apr"

    async def transition(
        self,
        tenant_id: str,
        approval_id: str,
        from_status: str | list[str],
        to_status: str,
        changes: Mapping[str, Any] | None = None,
        push: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Atomic compare-and-set state transition. Returns None if the state did not match."""
        statuses = [from_status] if isinstance(from_status, str) else from_status
        update: dict[str, Any] = {"$set": {"status": to_status, "updated_at": utcnow(), **(changes or {})}}
        if push:
            update["$push"] = dict(push)
        return await self.col.find_one_and_update(
            {"_id": approval_id, "tenant_id": tenant_id, "status": {"$in": statuses}},
            update,
            return_document=ReturnDocument.AFTER,
        )

    async def expired_pending_global(self, now: datetime, limit: int = 200) -> list[dict[str, Any]]:
        """Privileged: used by the expiry sweeper; each result is then handled tenant-scoped."""
        q = {"status": "PENDING", "expires_at": {"$lte": now}}
        return [d async for d in self.col.find(q, {"_id": 1, "tenant_id": 1}).limit(limit)]

    async def stuck_approved_global(self, older_than: datetime, limit: int = 100) -> list[dict[str, Any]]:
        q = {"status": "APPROVED", "approved_at": {"$lte": older_than}}
        return [d async for d in self.col.find(q, {"_id": 1, "tenant_id": 1}).limit(limit)]

    async def stale_claims_global(self, older_than: datetime, limit: int = 100) -> list[dict[str, Any]]:
        """Privileged: claims whose worker went quiet (used by the stale-claim sweep)."""
        q = {"status": {"$in": ["REVALIDATING", "EXECUTING"]}, "updated_at": {"$lte": older_than}}
        return [d async for d in self.col.find(q, {"_id": 1, "tenant_id": 1, "status": 1, "updated_at": 1}).limit(limit)]

    async def due_global(self, at_field: str, done_field: str, now: datetime, limit: int = 200) -> list[dict[str, Any]]:
        """Privileged: pending requests whose escalation or reminder point has passed and not yet been handled."""
        q = {"status": "PENDING", at_field: {"$lte": now}, done_field: None}
        return [d async for d in self.col.find(q, {"_id": 1, "tenant_id": 1}).limit(limit)]


class ApprovalDelegationRepository(TenantScopedRepository):
    collection_name = "approval_delegations"
    id_prefix = "dlg"


class InvocationRepository(TenantScopedRepository):
    collection_name = "invocations"
    id_prefix = "inv"


class AuditRepository(TenantScopedRepository):
    """Append-only. Deliberately exposes no update or delete operations."""

    collection_name = "audit_events"
    id_prefix = "evt"

    async def update(self, *a: Any, **k: Any) -> Any:  # type: ignore[override]
        raise PermissionError("Audit events are append-only")

    async def delete(self, *a: Any, **k: Any) -> Any:  # type: ignore[override]
        raise PermissionError("Audit events are append-only")

    async def append(self, tenant_id: str, event: dict[str, Any]) -> dict[str, Any]:
        event = {**event, "_id": event["event_id"]}
        return await super().insert(tenant_id, event)

    async def search(self, tenant_id: str, query: Mapping[str, Any], **kw: Any) -> Page:
        return await self.list(tenant_id, query, sort=[("timestamp", -1)], **kw)

    async def search_global(self, query: Mapping[str, Any], **kw: Any) -> Page:
        """Privileged: platform-admin cross-tenant audit search (itself audited by the caller)."""
        return await self._paginate(query, sort=[("timestamp", -1)], **kw)

    async def purge_expired(self, tenant_id: str, cutoff: datetime) -> int:
        """Retention enforcement: the ONLY deletion path for audit events. Removes one tenant's events
        older than ``cutoff``. Called by the worker; each purge is itself recorded as an audit event."""
        if not tenant_id:
            raise ValueError("tenant_id is required")
        res = await self.col.delete_many({"tenant_id": tenant_id, "timestamp": {"$lt": cutoff}})
        return int(res.deleted_count)


class UsageRepository(TenantScopedRepository):
    collection_name = "usage_counters"
    id_prefix = "use"

    async def increment(
        self, tenant_id: str, period: str, principal_id: str, tool_id: str, outcome: str, units: int = 1
    ) -> None:
        await self.col.update_one(
            {"tenant_id": tenant_id, "period": period, "principal_id": principal_id, "tool_id": tool_id},
            {
                "$inc": {"count": 1, "weighted_units": units, f"outcomes.{outcome}": 1},
                "$set": {"updated_at": utcnow()},
                "$setOnInsert": {"_id": new_id("use"), "created_at": utcnow()},
            },
            upsert=True,
        )


class Repos:
    """Container so services receive one object instead of a dozen repositories."""

    def __init__(self, db: Any) -> None:
        self.tenants = TenantRepository(db)
        self.users = UserRepository(db)
        self.settings = SystemSettingsRepository(db)
        self.memberships = MembershipRepository(db)
        self.agents = AgentRepository(db)
        self.credentials = CredentialRepository(db)
        self.secrets = SecretRepository(db)
        self.servers = ServerRepository(db)
        self.tools = ToolRepository(db)
        self.tool_versions = ToolVersionRepository(db)
        self.policies = PolicyRepository(db)
        self.approvals = ApprovalRepository(db)
        self.delegations = ApprovalDelegationRepository(db)
        self.invocations = InvocationRepository(db)
        self.audit = AuditRepository(db)
        self.usage = UsageRepository(db)
