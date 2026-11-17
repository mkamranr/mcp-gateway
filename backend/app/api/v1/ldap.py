"""LDAP / Active Directory sign-in: public login-page hint (/auth/ldap/config) and platform-admin configuration."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.api.deps import get_container, require_user
from app.container import Container
from app.core.identity import Principal, Role
from app.models.ldap import LdapConfigUpdate, LdapTestRequest

router = APIRouter(tags=["ldap"])


@router.get("/auth/ldap/config")
async def ldap_public_config(c: Container = Depends(get_container)) -> dict[str, Any]:
    cfg = await c.ldap.admin_view()
    return {"enabled": cfg["enabled"], "display_name": cfg["display_name"]}


@router.get("/ldap/config")
async def get_ldap_config(p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                          c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.ldap.admin_view()


@router.put("/ldap/config")
async def put_ldap_config(body: LdapConfigUpdate, p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                          c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.ldap.update_config(p, body)


@router.post("/ldap/test")
async def test_ldap(body: LdapTestRequest | None = None, p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                    c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.ldap.test_connection(p, (body.username or "").strip() or None if body else None)
