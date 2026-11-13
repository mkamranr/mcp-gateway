"""/api/v1/tenants and /api/v1/agents (spec §16.2)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.api.deps import get_container, page_params, require_user
from app.container import Container
from app.core.identity import ADMINS, SECURITY, Principal
from app.models.identity import (
    AgentCreate,
    AgentUpdate,
    MembershipUpdate,
    RevokeRequest,
    TenantCreate,
    TenantUpdate,
    UserCreate,
    agent_to_api,
    credential_to_api,
    tenant_to_api,
)

router = APIRouter(tags=["tenants & identities"])


@router.get("/tenants")
async def list_tenants(page: dict[str, Any] = Depends(page_params), p: Principal = Depends(require_user()),
                       c: Container = Depends(get_container)) -> dict[str, Any]:
    res = await c.identity.list_tenants(p, **page)
    return {**res, "items": [tenant_to_api(t) for t in res["items"]]}


@router.post("/tenants", status_code=201)
async def create_tenant(body: TenantCreate, p: Principal = Depends(require_user("platform_admin")),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    t = await c.identity.create_tenant(p, body)
    out = tenant_to_api(t)
    if "initial_admin_password" in t:
        out["initial_admin_password"] = t["initial_admin_password"]
    return out


@router.get("/tenants/{tenant_id}")
async def get_tenant(tenant_id: str, p: Principal = Depends(require_user()),
                     c: Container = Depends(get_container)) -> dict[str, Any]:
    return tenant_to_api(await c.identity.get_tenant(p, tenant_id))


@router.patch("/tenants/{tenant_id}")
async def update_tenant(tenant_id: str, body: TenantUpdate, p: Principal = Depends(require_user(*ADMINS)),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    return tenant_to_api(await c.identity.update_tenant(p, tenant_id, body))


@router.get("/tenants/{tenant_id}/users")
async def list_users(tenant_id: str, page: dict[str, Any] = Depends(page_params),
                     p: Principal = Depends(require_user(*SECURITY, "auditor")),
                     c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.identity.list_users(p, tenant_id, **page)


@router.post("/tenants/{tenant_id}/users", status_code=201)
async def add_user(tenant_id: str, body: UserCreate, p: Principal = Depends(require_user(*ADMINS)),
                   c: Container = Depends(get_container)) -> dict[str, Any]:
    return await c.identity.add_user(p, tenant_id, body)


@router.patch("/tenants/{tenant_id}/users/{user_id}")
async def update_user(tenant_id: str, user_id: str, body: MembershipUpdate,
                      p: Principal = Depends(require_user(*ADMINS)),
                      c: Container = Depends(get_container)) -> dict[str, Any]:
    m = await c.identity.update_membership(p, tenant_id, user_id, body)
    return {"membership_id": m["_id"], "user_id": m["user_id"], "roles": m["roles"], "status": m["status"]}


@router.get("/tenants/{tenant_id}/agents")
async def list_agents(tenant_id: str, page: dict[str, Any] = Depends(page_params),
                      p: Principal = Depends(require_user()), c: Container = Depends(get_container)) -> dict[str, Any]:
    res = await c.identity.list_agents(p, tenant_id, **page)
    counts: dict[str, int] = {}
    async for row in await c.repos.credentials.col.aggregate([
        {"$match": {"tenant_id": tenant_id, "revoked_at": None}},
        {"$group": {"_id": "$principal_id", "n": {"$sum": 1}}}]):
        counts[row["_id"]] = row["n"]
    return {**res, "items": [agent_to_api(a, active_credentials=counts.get(a["_id"], 0)) for a in res["items"]]}


@router.post("/tenants/{tenant_id}/agents", status_code=201)
async def create_agent(tenant_id: str, body: AgentCreate, p: Principal = Depends(require_user(*SECURITY, "developer")),
                       c: Container = Depends(get_container)) -> dict[str, Any]:
    return agent_to_api(await c.identity.create_agent(p, tenant_id, body))


@router.get("/agents/{agent_id}")
async def get_agent(agent_id: str, p: Principal = Depends(require_user()),
                    c: Container = Depends(get_container)) -> dict[str, Any]:
    agent = await c.identity.get_agent(p, agent_id)
    creds = await c.identity.list_keys(p, agent_id, limit=100)
    invocations = await c.repos.invocations.list(p.tenant_id, {"principal.id": agent_id}, limit=20)
    policies = await c.repos.policies._paginate({
        "tenant_id": {"$in": [p.tenant_id, "*"]}, "kind": {"$ne": "default_deny"},
        "$or": [{"principals.ids": agent_id}, {"principals.ids": "*"}, {"principals.types": "*"},
                {"principals.ids": {"$size": 0}, "principals.roles": {"$size": 0}}]}, limit=100,
        sort=[("priority", 1)])
    visible = await c.invocations.discover(_as_agent(agent, p.tenant_id))
    return agent_to_api(
        agent,
        credentials=[credential_to_api(x) for x in creds["items"]],
        recent_invocations=[{**{k: v for k, v in i.items() if k != "_id"}, "id": i["_id"]}
                            for i in invocations["items"]],
        policies=[{"id": x["_id"], "name": x["name"], "effect": x["effect"], "enabled": x.get("enabled"),
                   "priority": x.get("priority")} for x in policies["items"]],
        permitted_tools=[{"id": t["_id"], "gateway_name": t["gateway_name"], "risk_level": t.get("risk_level")}
                         for t in visible],
    )


def _as_agent(agent: dict[str, Any], tenant_id: str) -> Principal:
    return Principal(principal_type="agent", principal_id=agent["_id"], tenant_id=tenant_id,
                     scopes=("tools:list",), agent_id=agent["_id"], display_name=agent["name"])


@router.patch("/agents/{agent_id}")
async def update_agent(agent_id: str, body: AgentUpdate, p: Principal = Depends(require_user(*SECURITY)),
                       c: Container = Depends(get_container)) -> dict[str, Any]:
    return agent_to_api(await c.identity.update_agent(p, agent_id, body))


@router.post("/agents/{agent_id}/revoke")
async def revoke_agent(agent_id: str, body: RevokeRequest | None = None, p: Principal = Depends(require_user(*SECURITY)),
                       c: Container = Depends(get_container)) -> dict[str, Any]:
    return agent_to_api(await c.identity.revoke_agent(p, agent_id, body.reason if body else ""))


@router.post("/emergency/revoke-all-credentials")
async def emergency_revoke(body: RevokeRequest, p: Principal = Depends(require_user(*SECURITY)),
                           c: Container = Depends(get_container)) -> dict[str, Any]:
    return {"revoked": await c.identity.emergency_revoke_all(p, body.reason)}
