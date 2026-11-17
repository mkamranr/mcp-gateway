"""/api/v1/auth: login, logout, session principal and agent keys."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request, Response

from app.api.deps import (
    CSRF_COOKIE,
    CSRF_HEADER,
    client_ip,
    get_container,
    get_principal,
    page_params,
    require_user,
    session_cookie_name,
)
from app.container import Container
from app.core.crypto import constant_time_equals
from app.core.errors import ErrorCode, GatewayError
from app.core.identity import SECURITY, Principal
from app.models.identity import (
    AgentCertificateCreate,
    AgentKeyCreate,
    AgentOAuthClientCreate,
    ChangePasswordRequest,
    LoginRequest,
    RevokeRequest,
    SwitchTenantRequest,
    credential_to_api,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _principal_payload(p: Principal, c: Container, tenants: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "principal_type": p.principal_type, "principal_id": p.principal_id, "tenant_id": p.tenant_id,
        "display_name": p.display_name, "roles": list(p.roles), "scopes": list(p.scopes),
        "is_platform_admin": p.is_global_admin, "agent_id": p.agent_id, "credential_id": p.credential_id,
        "tenants": tenants, "environment": c.settings.app_env, "version": c.settings.app_version,
    }


async def _tenants_for(c: Container, p: Principal) -> list[dict[str, Any]]:
    if not p.tenant_ids:
        return []
    docs = await c.repos.tenants.col.find({"_id": {"$in": list(p.tenant_ids)}}).sort("name", 1).to_list()
    return [{"id": d["_id"], "name": d["name"], "slug": d["slug"], "status": d.get("status")} for d in docs]


def _set_cookies(response: Response, c: Container, sid: str, csrf: str) -> None:
    secure = c.settings.cookie_secure
    max_age = c.settings.session_ttl_minutes * 60
    response.set_cookie(session_cookie_name(secure), sid, httponly=True, secure=secure, samesite="strict",
                        path="/", max_age=max_age)
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=secure, samesite="strict", path="/",
                        max_age=max_age)


@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response,
                c: Container = Depends(get_container)) -> dict[str, Any]:
    result = await c.auth.login(body.username, body.password, client_ip(request), body.tenant_id)
    _set_cookies(response, c, result["session_id"], result["csrf"])
    principal, _ = await c.auth.resolve_session(result["session_id"])
    user = await c.repos.users.get(principal.principal_id)
    payload = _principal_payload(principal, c, await _tenants_for(c, principal))
    payload["csrf_token"] = result["csrf"]
    payload["must_change_password"] = bool((user or {}).get("must_change_password"))
    payload["auth_source"] = (user or {}).get("auth_source", "local")
    return payload


@router.post("/logout", status_code=204)
async def logout(request: Request, response: Response, c: Container = Depends(get_container)) -> Response:
    sid = request.cookies.get(session_cookie_name(c.settings.cookie_secure))
    principal = None
    if sid:
        try:
            principal, session = await c.auth.resolve_session(sid)
        except Exception:  # noqa: BLE001  (expired or unknown session: nothing to protect, just clear cookies)
            principal = None
        if principal is not None:
            # A live session may only be ended by the console itself, not by a cross-site request.
            token = request.headers.get(CSRF_HEADER, "")
            if not token or not constant_time_equals(token, session["csrf"]):
                raise GatewayError(ErrorCode.CSRF_FAILED, "Missing or invalid CSRF token.")
        await c.auth.logout(sid, principal)
    response = Response(status_code=204)
    response.delete_cookie(session_cookie_name(c.settings.cookie_secure), path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return response


@router.get("/me")
async def me(request: Request, p: Principal = Depends(get_principal),
             c: Container = Depends(get_container)) -> dict[str, Any]:
    payload = _principal_payload(p, c, await _tenants_for(c, p))
    if p.principal_type == "user":
        payload["csrf_token"] = request.cookies.get(CSRF_COOKIE)
        user = await c.repos.users.get(p.principal_id) or {}
        payload["auth_source"] = user.get("auth_source", "local")
        payload["must_change_password"] = bool(user.get("must_change_password"))
    return payload


@router.post("/switch-tenant")
async def switch_tenant(body: SwitchTenantRequest, request: Request, p: Principal = Depends(require_user()),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    sid = request.cookies.get(session_cookie_name(c.settings.cookie_secure)) or ""
    new_p = await c.auth.switch_tenant(sid, p, body.tenant_id)
    return _principal_payload(new_p, c, await _tenants_for(c, new_p))


@router.post("/change-password", status_code=204)
async def change_password(body: ChangePasswordRequest, p: Principal = Depends(require_user()),
                          c: Container = Depends(get_container)) -> Response:
    await c.auth.change_password(p, body.current_password, body.new_password)
    return Response(status_code=204)


# ---- agent client certificates (docs/mtls.md) ----
@router.get("/agent-certificates/status")
async def agent_certificate_status(_: Principal = Depends(require_user()),
                                   c: Container = Depends(get_container)) -> dict[str, Any]:
    return c.identity.certificate_status()


@router.post("/agent-certificates", status_code=201)
async def create_agent_certificate(body: AgentCertificateCreate, p: Principal = Depends(require_user(*SECURITY)),
                                   c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.identity.create_certificate(p, body)


@router.get("/agent-oauth/status")
async def agent_oauth_status(_: Principal = Depends(require_user()),
                             c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.agent_oauth.public_view()


@router.post("/agent-oauth-clients", status_code=201)
async def create_agent_oauth_client(body: AgentOAuthClientCreate, p: Principal = Depends(require_user(*SECURITY)),
                                    c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.identity.create_oauth_client(p, body)


# ---- agent keys (spec §16.1) ----
@router.post("/agent-keys", status_code=201)
async def create_agent_key(body: AgentKeyCreate, p: Principal = Depends(require_user(*SECURITY)),
                           c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.identity.create_key(p, body)


@router.get("/agent-keys")
async def list_agent_keys(agent_id: str | None = None, page: dict[str, Any] = Depends(page_params),
                          p: Principal = Depends(require_user()), c: Container = Depends(get_container)) -> dict[str, Any]:
    res = await c.identity.list_keys(p, agent_id, **page)
    return {**res, "items": [credential_to_api(d) for d in res["items"]]}


@router.post("/agent-keys/{cred_id}/rotate")
async def rotate_agent_key(cred_id: str, p: Principal = Depends(require_user(*SECURITY)),
                           c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.identity.rotate_key(p, cred_id)


@router.post("/agent-keys/{cred_id}/revoke")
async def revoke_agent_key(cred_id: str, body: RevokeRequest | None = None,
                           p: Principal = Depends(require_user(*SECURITY)),
                           c: Container = Depends(get_container)) -> dict[str, Any]:
    return credential_to_api(await c.identity.revoke_key(p, cred_id, body.reason if body else ""))
