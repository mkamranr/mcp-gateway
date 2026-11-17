"""OAuth 2.0 for agents: trusted token issuers (platform-admin configuration). docs/agent-oauth.md"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.api.deps import get_container, require_user
from app.container import Container
from app.core.identity import Principal, Role
from app.models.agent_oauth import AgentOAuthConfig, AgentOAuthTest

router = APIRouter(tags=["agent-oauth"])


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
