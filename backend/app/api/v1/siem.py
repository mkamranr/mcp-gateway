"""SIEM forwarding configuration and status (platform administrators)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.api.deps import get_container, require_user
from app.container import Container
from app.core.identity import Principal, Role
from app.models.siem import SiemConfigUpdate

router = APIRouter(prefix="/siem", tags=["siem"])


@router.get("/config")
async def get_siem_config(p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                          c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.siem.admin_view()


@router.put("/config")
async def put_siem_config(body: SiemConfigUpdate, p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                          c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.siem.update_config(p, body)


@router.get("/status")
async def siem_status(p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                      c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.siem.status()


@router.post("/test")
async def test_siem(p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                    c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.siem.test(p)
