"""OIDC single sign-on: public browser endpoints (/auth/oidc/*) and platform-admin configuration (/sso/*)."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from app.api.deps import client_ip, get_container, require_user
from app.api.v1.auth import _set_cookies
from app.container import Container
from app.core.errors import GatewayError
from app.core.identity import Principal, Role
from app.core.logging import get_logger
from app.models.sso import OidcConfigUpdate
from app.services.auth_service import SYSTEM_TENANT
from app.services.oidc_client import OidcError

log = get_logger(__name__)
router = APIRouter(tags=["sso"])

STATE_COOKIE = "mgw_oidc"
STATE_COOKIE_PATH = "/api/v1/auth/oidc"


def _login_error(code: str) -> RedirectResponse:
    resp = RedirectResponse(f"/?sso_error={quote(code)}", status_code=303)
    resp.delete_cookie(STATE_COOKIE, path=STATE_COOKIE_PATH)
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------- public (browser) endpoints
@router.get("/auth/oidc/config")
async def oidc_public_config(c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.sso.public_view()


@router.get("/auth/oidc/login")
async def oidc_login(request: Request, return_to: str | None = None,
                     c: Container = Depends(get_container)) -> RedirectResponse:
    try:
        url, binding = await c.sso.start_login(return_to, client_ip(request))
    except OidcError as exc:
        log.warning("oidc.login.failed", code=exc.code, detail=exc.detail)
        return _login_error(exc.code)
    except GatewayError as exc:
        return _login_error("rate_limited" if exc.code.value == "RATE_LIMIT_EXCEEDED" else "unavailable")
    resp = RedirectResponse(url, status_code=303)
    # SameSite=Lax (not Strict): the IdP sends the browser back with a cross-site top-level GET, and the
    # cookie must come along so the callback can prove the flow started in this browser.
    resp.set_cookie(STATE_COOKIE, binding, httponly=True, secure=c.settings.cookie_secure, samesite="lax",
                    path=STATE_COOKIE_PATH, max_age=600)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@router.get("/auth/oidc/callback")
async def oidc_callback(request: Request, code: str | None = None, state: str | None = None,
                        error: str | None = None, c: Container = Depends(get_container)) -> RedirectResponse:
    ip = client_ip(request)
    try:
        session, return_to = await c.sso.complete_login(
            code=code, state=state, error=error, binding=request.cookies.get(STATE_COOKIE), source_ip=ip)
    except OidcError as exc:
        log.warning("oidc.callback.failed", code=exc.code, detail=exc.detail)
        if exc.code not in ("no_access", "account_conflict"):  # those are audited with full context already
            await c.audit.record(SYSTEM_TENANT, "auth.oidc.failed", status="failure",
                                 metadata={"source_ip": ip, "error": exc.code, "detail": exc.detail})
        return _login_error(exc.code)
    except GatewayError as exc:
        return _login_error("rate_limited" if exc.code.value == "RATE_LIMIT_EXCEEDED" else "unavailable")
    resp = RedirectResponse(return_to, status_code=303)
    _set_cookies(resp, c, session["session_id"], session["csrf"])
    resp.delete_cookie(STATE_COOKIE, path=STATE_COOKIE_PATH)
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------- platform-admin configuration
@router.get("/sso/config")
async def get_sso_config(p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                         c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.sso.admin_view()


@router.put("/sso/config")
async def put_sso_config(body: OidcConfigUpdate, p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                         c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.sso.update_config(p, body)


@router.post("/sso/test")
async def test_sso(p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                   c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.sso.test_connection(p)
