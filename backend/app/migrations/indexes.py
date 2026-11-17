"""Index initialisation (spec §17.2). Idempotent; runs at API and worker startup."""

from __future__ import annotations

from pymongo import ASCENDING as A
from pymongo import DESCENDING as D
from pymongo import IndexModel
from pymongo.errors import OperationFailure

from app.db import Database

INDEXES: dict[str, list[IndexModel]] = {
    "tenants": [IndexModel([("slug", A)], unique=True)],
    "users": [
        IndexModel([("username", A)], unique=True),
        IndexModel([("email", A)], unique=True, partialFilterExpression={"email": {"$type": "string"}}),
        # One account per IdP identity (issuer + subject); never matched by username.
        IndexModel([("oidc.issuer", A), ("oidc.subject", A)], unique=True,
                   partialFilterExpression={"oidc.subject": {"$type": "string"}}),
        # One account per directory entry (its unique ID attribute, e.g. entryUUID or objectGUID).
        IndexModel([("ldap.id", A)], unique=True, partialFilterExpression={"ldap.id": {"$type": "string"}}),
    ],
    "tenant_memberships": [
        IndexModel([("tenant_id", A), ("user_id", A)], unique=True),
        IndexModel([("user_id", A), ("status", A)]),
    ],
    "agents": [IndexModel([("tenant_id", A), ("status", A)]), IndexModel([("tenant_id", A), ("name", A)], unique=True)],
    "credentials": [
        # API keys only: certificate credentials have no key prefix.
        IndexModel([("key_prefix", A)], unique=True, name="key_prefix_unique_v2",
                   partialFilterExpression={"key_prefix": {"$type": "string"}}),
        # Certificate credentials: "fp:<sha256>" (a pinned certificate) or "san:<name>" (any trusted certificate
        # with that subject alternative name).
        IndexModel([("cert_match", A), ("revoked_at", A)], partialFilterExpression={"cert_match": {"$type": "string"}}),
        # OAuth credentials: "<issuer>\n<client>" (docs/agent-oauth.md).
        IndexModel([("oauth_match", A), ("revoked_at", A)],
                   partialFilterExpression={"oauth_match": {"$type": "string"}}),
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
        IndexModel([("status", A), ("escalate_at", A)]),
        IndexModel([("status", A), ("remind_at", A)]),
    ],
    "approval_delegations": [
        IndexModel([("tenant_id", A), ("delegate_user_id", A), ("ends_at", A)]),
        IndexModel([("tenant_id", A), ("delegator_user_id", A), ("ends_at", A)]),
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


# Indexes replaced by a differently defined one. Dropped before INDEXES are created (idempotent, and safe when
# several replicas start at once).
LEGACY_INDEXES: dict[str, list[str]] = {
    "credentials": ["key_prefix_1"],  # unique on every document; now partial, so certificates need no prefix
}


async def ensure_indexes(db: Database) -> None:
    for collection, names in LEGACY_INDEXES.items():
        existing = {ix["name"] async for ix in await db[collection].list_indexes()}
        for name in names:
            if name in existing:
                try:
                    await db[collection].drop_index(name)
                except OperationFailure:
                    pass  # another replica dropped it first
    for collection, models in INDEXES.items():
        await db[collection].create_indexes(models)
