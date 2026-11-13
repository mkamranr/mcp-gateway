"""Index initialisation (spec §17.2). Idempotent; runs at API and worker startup."""

from __future__ import annotations

from pymongo import ASCENDING as A
from pymongo import DESCENDING as D
from pymongo import IndexModel

from app.db import Database

INDEXES: dict[str, list[IndexModel]] = {
    "tenants": [IndexModel([("slug", A)], unique=True)],
    "users": [
        IndexModel([("username", A)], unique=True),
        IndexModel([("email", A)], unique=True, partialFilterExpression={"email": {"$type": "string"}}),
    ],
    "tenant_memberships": [
        IndexModel([("tenant_id", A), ("user_id", A)], unique=True),
        IndexModel([("user_id", A), ("status", A)]),
    ],
    "agents": [IndexModel([("tenant_id", A), ("status", A)]), IndexModel([("tenant_id", A), ("name", A)], unique=True)],
    "credentials": [
        IndexModel([("key_prefix", A)], unique=True),
        IndexModel([("tenant_id", A), ("principal_id", A), ("revoked_at", A)]),
    ],
    "secrets": [IndexModel([("tenant_id", A), ("owner_id", A)])],
    "mcp_servers": [
        IndexModel([("tenant_id", A), ("name", A)], unique=True),
        IndexModel([("tenant_id", A), ("alias", A)], unique=True),
    ],
    "tools": [
        IndexModel([("tenant_id", A), ("server_id", A), ("upstream_name", A)], unique=True),
        IndexModel([("tenant_id", A), ("gateway_name", A)], unique=True),
    ],
    "tool_schema_versions": [IndexModel([("tenant_id", A), ("tool_id", A), ("discovered_at", D)])],
    "policies": [IndexModel([("tenant_id", A), ("enabled", A), ("priority", A)])],
    "approval_requests": [
        IndexModel([("tenant_id", A), ("status", A), ("created_at", D)]),
        IndexModel([("tenant_id", A), ("expires_at", A)]),
        IndexModel([("status", A), ("expires_at", A)]),
        IndexModel([("tenant_id", A), ("invocation_id", A)]),
    ],
    "invocations": [
        IndexModel([("tenant_id", A), ("created_at", D)]),
        IndexModel([("tenant_id", A), ("principal.id", A), ("created_at", D)]),
        IndexModel([("tenant_id", A), ("tool_id", A), ("created_at", D)]),
        IndexModel([("tenant_id", A), ("idempotency_key", A)], unique=True,
                   partialFilterExpression={"idempotency_key": {"$type": "string"}}),
    ],
    "audit_events": [
        IndexModel([("tenant_id", A), ("timestamp", D)]),
        IndexModel([("tenant_id", A), ("event_type", A), ("timestamp", D)]),
        IndexModel([("tenant_id", A), ("request_id", A)]),
        IndexModel([("tenant_id", A), ("invocation_id", A)]),
        IndexModel([("timestamp", D)]),
    ],
    "usage_counters": [
        IndexModel([("tenant_id", A), ("period", A), ("principal_id", A), ("tool_id", A)], unique=True),
    ],
    "system_settings": [IndexModel([("key", A)], unique=True)],
}


async def ensure_indexes(db: Database) -> None:
    for collection, models in INDEXES.items():
        await db[collection].create_indexes(models)
