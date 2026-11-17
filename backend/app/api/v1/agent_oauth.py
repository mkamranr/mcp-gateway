"""OAuth 2.0 for agents: trusted token issuers (platform-admin configuration). docs/agent-oauth.md"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.api.deps import get_container, require_user
from app.container import Container
from app.core.identity import Principal, Role
from app.models.agent_oauth import AgentOAuthConfig, AgentOAuthTest

router = APIRouter(tags=["agent-oauth"])
wellknown = APIRouter(tags=["agent-oauth"])  # mounted at the root, not under /api/v1


async def _metadata(c: Container) -> JSONResponse:
    doc = await c.agent_oauth.resource_metadata()
    if doc is None:
        return JSONResponse({"error": {"code": "NOT_FOUND", "message": "OAuth for agents is not enabled."}},
                            status_code=404)
    # Public, credential-free metadata: any origin may read it (browser-based MCP clients).
    return JSONResponse(doc, headers={"Cache-Control": "public, max-age=300", "Access-Control-Allow-Origin": "*"})


# RFC 9728 §3.1: the metadata for https://host/mcp lives at /.well-known/oauth-protected-resource/mcp. The root form
# is served too, for clients that look there first.
@wellknown.get("/.well-known/oauth-protected-resource", include_in_schema=False)
async def protected_resource_metadata_root(c: Container = Depends(get_container)) -> JSONResponse:
    return await _metadata(c)


@wellknown.get("/.well-known/oauth-protected-resource/{path:path}", include_in_schema=False)
async def protected_resource_metadata(path: str, c: Container = Depends(get_container)) -> JSONResponse:
    if "/" + path.strip("/") != c.settings.mcp_endpoint_path.rstrip("/"):
        return JSONResponse({"error": {"code": "NOT_FOUND", "message": "Not found."}}, status_code=404)
    return await _metadata(c)


@router.get("/agent-oauth/config")
async def get_agent_oauth_config(p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                                 c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.agent_oauth.config(fresh=True)


@router.put("/agent-oauth/config")
async def put_agent_oauth_config(body: AgentOAuthConfig, p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                                 c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.agent_oauth.update_config(p, body)


@router.post("/agent-oauth/test")
async def test_agent_oauth_issuer(body: AgentOAuthTest, p: Principal = Depends(require_user(Role.PLATFORM_ADMIN)),
                                  c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.agent_oauth.test_issuer(p, body.issuer)
