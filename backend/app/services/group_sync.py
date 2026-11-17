"""Group-driven tenant memberships, shared by OIDC single sign-on and LDAP sign-in.

At every external sign-in the user's groups are mapped to tenant roles through the group rules, and the
memberships that source created are re-synchronised: a group removed at the IdP or in the directory removes
the access here. Memberships created by hand, or by another source, are never touched.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from app.repositories.collections import Repos
from app.services.audit_service import AuditService

LABELS = {"oidc": "SSO group sync", "ldap": "Directory group sync"}


def desired_memberships(rules: Iterable[dict[str, Any]], groups: set[str],
                        key: Callable[[str], str] = lambda g: g) -> dict[str, set[str]]:
    """tenant_id -> roles from every rule whose group (compared through ``key``) the user belongs to."""
    desired: dict[str, set[str]] = {}
    for rule in rules:
        try:
            g = key(rule["group"])
        except ValueError:
            continue
        if g in groups:
            desired.setdefault(rule["tenant_id"], set()).update(rule["roles"])
    return desired


async def sync_memberships(repos: Repos, audit: AuditService, user: dict[str, Any], desired: dict[str, set[str]],
                           source: str) -> None:
    existing = [m async for m in repos.memberships.col.find({"user_id": user["_id"]})]
    by_tenant = {m["tenant_id"]: m for m in existing}
    actor = {"type": "system", "id": f"{source}-sync", "name": LABELS.get(source, "Group sync")}
    who = {"user_id": user["_id"], "username": user["username"]}
    for tenant_id, roles in desired.items():
        m = by_tenant.get(tenant_id)
        role_list = sorted(roles)
        if m is None:
            await repos.memberships.insert(tenant_id, {"user_id": user["_id"], "roles": role_list,
                                                       "status": "active", "managed_by": source})
            await audit.record(tenant_id, "user.membership.created", principal=actor, resource=who,
                               metadata={"roles": role_list, "source": source})
        elif m.get("managed_by") == source and (m.get("roles") != role_list or m.get("status") != "active"):
            await repos.memberships.update(tenant_id, m["_id"], {"roles": role_list, "status": "active"})
            await audit.record(tenant_id, "user.membership.changed", principal=actor, resource=who,
                               metadata={"roles": role_list, "status": "active", "source": source})
    for tenant_id, m in by_tenant.items():
        if tenant_id not in desired and m.get("managed_by") == source and m.get("status") == "active":
            await repos.memberships.update(tenant_id, m["_id"], {"status": "disabled"})
            await audit.record(tenant_id, "user.membership.changed", principal=actor, resource=who,
                               metadata={"status": "disabled", "source": source,
                                         "reason": "group no longer maps to this tenant"})
