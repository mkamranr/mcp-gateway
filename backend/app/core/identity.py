"""Authenticated principal and role model (spec §7.3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal


class Role(StrEnum):
    PLATFORM_ADMIN = "platform_admin"  # global: tenants, system settings
    SECURITY_ADMIN = "security_admin"  # policies, audit, approvals, credentials within tenant
    TENANT_ADMIN = "tenant_admin"  # users, agents, servers, tools, policies within tenant
    APPROVER = "approver"  # approve / reject approval requests
    AUDITOR = "auditor"  # read-only audit and usage
    DEVELOPER = "developer"  # register servers, inspect tools, simulate policies


TENANT_ROLES = [r for r in Role if r is not Role.PLATFORM_ADMIN]

# Role groups used by route dependencies.
ADMINS = (Role.PLATFORM_ADMIN, Role.TENANT_ADMIN)
SECURITY = (Role.PLATFORM_ADMIN, Role.SECURITY_ADMIN, Role.TENANT_ADMIN)
REGISTRY_WRITE = (Role.PLATFORM_ADMIN, Role.TENANT_ADMIN, Role.DEVELOPER)
READERS = tuple(Role)
AUDIT_READ = (Role.PLATFORM_ADMIN, Role.SECURITY_ADMIN, Role.TENANT_ADMIN, Role.AUDITOR)
APPROVERS = (Role.PLATFORM_ADMIN, Role.SECURITY_ADMIN, Role.TENANT_ADMIN, Role.APPROVER)


@dataclass(frozen=True, slots=True)
class Principal:
    principal_type: Literal["user", "agent", "service"]
    principal_id: str
    tenant_id: str
    roles: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    credential_id: str | None = None
    delegated_by_user_id: str | None = None
    agent_id: str | None = None
    display_name: str = ""
    session_id: str | None = None
    is_global_admin: bool = False
    tenant_ids: tuple[str, ...] = field(default=())  # tenants this user may switch to

    def has_any_role(self, *roles: str) -> bool:
        if self.is_global_admin and Role.PLATFORM_ADMIN in roles:
            return True
        return any(r in self.roles for r in roles)

    def audit_ref(self) -> dict[str, str | None]:
        return {
            "type": self.principal_type,
            "id": self.principal_id,
            "credential_id": self.credential_id,
            "name": self.display_name or self.principal_id,
        }
