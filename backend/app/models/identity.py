"""Request/response models for authentication, tenants, users, agents and credentials."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, field_validator

from app.core.identity import TENANT_ROLES
from app.models.registry import Strict

SLUG = r"^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$"
USERNAME = r"^[a-zA-Z0-9][a-zA-Z0-9._@-]{1,62}[a-zA-Z0-9]$"
TENANT_ROLE_VALUES = {r.value for r in TENANT_ROLES}


def _check_roles(v: list[str]) -> list[str]:
    bad = [r for r in v if r not in TENANT_ROLE_VALUES]
    if bad:
        raise ValueError(f"Unknown roles: {', '.join(bad)}")
    return sorted(set(v))


class LoginRequest(Strict):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)
    tenant_id: str | None = None


class SwitchTenantRequest(Strict):
    tenant_id: str


class ChangePasswordRequest(Strict):
    current_password: str = Field(max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


class TenantSettings(Strict):
    audit_retention_days: int = Field(default=365, ge=30, le=3650)
    default_environment: Literal["development", "test", "production"] = "production"
    quotas: dict[str, int] = Field(default_factory=lambda: {"per_minute": 600, "per_day": 100_000})
    critical_requires_approval: bool = True


class TenantCreate(Strict):
    name: str = Field(min_length=2, max_length=100)
    slug: str = Field(pattern=SLUG)
    admin_username: str = Field(pattern=USERNAME)
    admin_email: str | None = Field(default=None, max_length=254)
    admin_password: str | None = Field(default=None, min_length=12, max_length=1024)
    settings: TenantSettings = Field(default_factory=TenantSettings)


class TenantUpdate(Strict):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    status: Literal["active", "suspended"] | None = None
    settings: TenantSettings | None = None


class UserCreate(Strict):
    username: str = Field(pattern=USERNAME)
    email: str | None = Field(default=None, max_length=254)
    display_name: str | None = Field(default=None, max_length=120)
    password: str | None = Field(default=None, min_length=12, max_length=1024)
    roles: list[str] = Field(min_length=1)

    _roles = field_validator("roles")(_check_roles)


class MembershipUpdate(Strict):
    roles: list[str] | None = None
    status: Literal["active", "disabled"] | None = None
    display_name: str | None = Field(default=None, max_length=120)

    @field_validator("roles")
    @classmethod
    def _r(cls, v: list[str] | None) -> list[str] | None:
        return _check_roles(v) if v is not None else v


class AgentCreate(Strict):
    name: str = Field(min_length=2, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]+$")
    description: str = Field(default="", max_length=2000)
    tags: list[str] = Field(default_factory=list, max_length=20)
    owner_user_id: str | None = None
    environment: Literal["development", "test", "production"] = "production"


class AgentUpdate(Strict):
    version: int
    description: str | None = Field(default=None, max_length=2000)
    tags: list[str] | None = None
    owner_user_id: str | None = None
    environment: Literal["development", "test", "production"] | None = None
    status: Literal["active", "disabled"] | None = None


class AgentKeyCreate(Strict):
    agent_id: str
    name: str = Field(default="default", min_length=1, max_length=100)
    scopes: list[Literal["tools:list", "tools:invoke", "approvals:read"]] = Field(
        default_factory=lambda: ["tools:list", "tools:invoke", "approvals:read"]  # type: ignore[arg-type]
    )
    expires_at: datetime | None = None


class RevokeRequest(Strict):
    reason: str = Field(default="", max_length=500)


def tenant_to_api(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": doc["_id"], "name": doc["name"], "slug": doc["slug"], "status": doc.get("status", "active"),
        "settings": doc.get("settings", {}), "created_at": doc.get("created_at"), "updated_at": doc.get("updated_at"),
    }


def credential_to_api(doc: dict[str, Any]) -> dict[str, Any]:
    """Never includes secret_hash."""
    return {
        "id": doc["_id"], "tenant_id": doc["tenant_id"], "name": doc.get("name"),
        "principal_type": doc["principal_type"], "principal_id": doc["principal_id"],
        "key_prefix": doc["key_prefix"], "scopes": doc.get("scopes", []), "expires_at": doc.get("expires_at"),
        "revoked_at": doc.get("revoked_at"), "revoked_by": doc.get("revoked_by"),
        "last_used_at": doc.get("last_used_at"), "last_used_source": doc.get("last_used_source"),
        "created_at": doc.get("created_at"), "created_by": doc.get("created_by"),
        "rotated_from": doc.get("rotated_from"),
        "status": credential_status(doc),
    }


def credential_status(doc: dict[str, Any]) -> str:
    from app.core.ids import ensure_aware, utcnow

    if doc.get("revoked_at"):
        return "revoked"
    exp = ensure_aware(doc.get("expires_at"))
    if exp and exp <= utcnow():
        return "expired"
    return "active"


def agent_to_api(doc: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "id": doc["_id"], "tenant_id": doc["tenant_id"], "name": doc["name"],
        "description": doc.get("description", ""), "status": doc.get("status", "active"),
        "owner_user_id": doc.get("owner_user_id"), "tags": doc.get("tags", []),
        "environment": doc.get("environment", "production"), "last_activity_at": doc.get("last_activity_at"),
        "version": doc.get("version", 1), "created_at": doc.get("created_at"), "created_by": doc.get("created_by"),
        **extra,
    }
