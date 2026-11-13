"""Liveness and readiness probes (spec §15.4). Unauthenticated; reveal no tenant data."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.api.deps import get_container
from app.container import Container
from app.db import redis_ping

router = APIRouter(tags=["health"])


@router.get("/health/live")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready")
async def ready(c: Container = Depends(get_container)) -> JSONResponse:
    checks = {"mongodb": await c.db.ping(), "redis": await redis_ping(c.redis)}
    ok = all(checks.values())
    return JSONResponse(status_code=200 if ok else 503,
                        content={"status": "ready" if ok else "not_ready",
                                 "checks": {k: "ok" if v else "unavailable" for k, v in checks.items()}})
