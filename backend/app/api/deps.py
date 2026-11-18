"""FastAPI dependencies: container access, authentication, CSRF and role checks."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Depends, Request

from app.api.proxy import peer_address
from app.container import Container
from app.core.crypto import constant_time_equals
from app.core.errors import ErrorCode, GatewayError
from app.core.identity import Principal

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_HEADER = "X-CSRF-Token"


def session_cookie_name(secure: bool) -> str:
    # The __Host- prefix requires the Secure attribute; plain-HTTP development uses a fallback name.
    return "__Host-mgw_session" if secure else "mgw_session"


CSRF_COOKIE = "mgw_csrf"


def get_container(request: Request) -> Container:
    return request.app.state.container  # type: ignore[no-any-return]


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def get_principal(request: Request, c: Container = Depends(get_container)) -> Principal:
    cached = getattr(request.state, "principal", None)
    if cached is not None:
        return cached  # type: ignore[no-any-return]
    agent = await c.auth.authenticate_agent(request.headers, source=client_ip(request),
                                            peer=peer_address(request.scope))
    if agent is not None:
        principal = agent
    else:
        sid = request.cookies.get(session_cookie_name(c.settings.cookie_secure))
        if not sid:
            raise GatewayError(ErrorCode.AUTHENTICATION_REQUIRED)
        principal, session = await c.auth.resolve_session(sid)
        if request.method not in SAFE_METHODS:
            token = request.headers.get(CSRF_HEADER, "")
            if not token or not constant_time_equals(token, session["csrf"]):
                raise GatewayError(ErrorCode.CSRF_FAILED, "Missing or invalid CSRF token.")
    request.state.principal = principal
    return principal


def require_user(*roles: str) -> Callable[..., Awaitable[Principal]]:
    """Human user with at least one of ``roles`` (any role if none given)."""

    async def dep(p: Principal = Depends(get_principal)) -> Principal:
        if p.principal_type != "user":
            raise GatewayError(ErrorCode.ACCESS_DENIED, "This endpoint requires a user session.")
        if roles and not p.has_any_role(*roles):
            raise GatewayError(ErrorCode.ACCESS_DENIED, "Your role does not permit this action.")
        return p

    return dep


def require_agent(scope: str) -> Callable[..., Awaitable[Principal]]:
    async def dep(p: Principal = Depends(get_principal)) -> Principal:
        if p.principal_type != "agent" or scope not in p.scopes:
            raise GatewayError(ErrorCode.ACCESS_DENIED, f"An agent credential with scope {scope} is required.")
        return p

    return dep


def page_params(limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
    return {"limit": max(1, min(limit, 200)), "cursor": cursor}
