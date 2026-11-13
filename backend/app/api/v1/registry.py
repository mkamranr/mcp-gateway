"""/api/v1/servers and /api/v1/tools (spec §16.3)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Response

from app.api.deps import get_container, page_params, require_user
from app.container import Container
from app.core.identity import ADMINS, REGISTRY_WRITE, Principal
from app.models.registry import ServerCreate, ServerUpdate, ToolUpdate, server_to_api, tool_to_api

router = APIRouter(tags=["registry"])


@router.get("/servers")
async def list_servers(search: str | None = None, page: dict[str, Any] = Depends(page_params),
                       p: Principal = Depends(require_user()), c: Container = Depends(get_container)) -> dict[str, Any]:
    res = await c.registry.list_servers(p, search=search, **page)
    return {**res, "items": [server_to_api(s) for s in res["items"]]}


@router.post("/servers", status_code=201)
async def create_server(body: ServerCreate, p: Principal = Depends(require_user(*REGISTRY_WRITE)),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    return server_to_api(await c.registry.create_server(p, body))


@router.get("/servers/{server_id}")
async def get_server(server_id: str, p: Principal = Depends(require_user()),
                     c: Container = Depends(get_container)) -> dict[str, Any]:
    return server_to_api(await c.registry.get_server(p, server_id))


@router.patch("/servers/{server_id}")
async def update_server(server_id: str, body: ServerUpdate, p: Principal = Depends(require_user(*REGISTRY_WRITE)),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    if body.enabled is not None and not p.has_any_role(*ADMINS, "security_admin"):
        from app.core.errors import denied

        raise denied("Only administrators can enable or disable servers.")
    return server_to_api(await c.registry.update_server(p, server_id, body))


@router.post("/servers/{server_id}/enable")
async def enable_server(server_id: str, p: Principal = Depends(require_user(*ADMINS, "security_admin")),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    return server_to_api(await c.registry.set_server_enabled(p, server_id, True))


@router.post("/servers/{server_id}/disable")
async def disable_server(server_id: str, p: Principal = Depends(require_user(*ADMINS, "security_admin")),
                         c: Container = Depends(get_container)) -> dict[str, Any]:
    return server_to_api(await c.registry.set_server_enabled(p, server_id, False))


@router.delete("/servers/{server_id}", status_code=204)
async def delete_server(server_id: str, p: Principal = Depends(require_user(*ADMINS)),
                        c: Container = Depends(get_container)) -> Response:
    await c.registry.archive_server(p, server_id)
    return Response(status_code=204)


@router.post("/servers/{server_id}/test")
async def test_server(server_id: str, p: Principal = Depends(require_user(*REGISTRY_WRITE, "security_admin")),
                      c: Container = Depends(get_container)) -> dict[str, Any]:
    server = await c.registry.get_server(p, server_id)
    return await c.registry.test_connection(p, server)


@router.post("/servers/{server_id}/refresh-tools")
async def refresh_tools(server_id: str, p: Principal = Depends(require_user(*REGISTRY_WRITE)),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    server = await c.registry.get_server(p, server_id)
    return await c.registry.refresh_tools(p, server)


@router.get("/servers/{server_id}/tools")
async def server_tools(server_id: str, p: Principal = Depends(require_user()),
                       c: Container = Depends(get_container)) -> dict[str, Any]:
    server = await c.registry.get_server(p, server_id)
    res = await c.registry.list_tools(p, server_id=server_id, limit=200)
    return {**res, "items": [tool_to_api(t, server) for t in res["items"]]}


@router.get("/servers/{server_id}/history")
async def server_history(server_id: str, p: Principal = Depends(require_user()),
                         c: Container = Depends(get_container)) -> dict[str, Any]:
    await c.registry.get_server(p, server_id)
    res = await c.repos.audit.search(p.tenant_id, {"resource.server_id": server_id,
                                                   "event_type": {"$not": {"$regex": "^tool\\.invocation"}}}, limit=100)
    return {"items": [{**{k: v for k, v in e.items() if k != "_id"}} for e in res["items"]]}


@router.get("/tools")
async def list_tools(server_id: str | None = None, risk: str | None = None, enabled: bool | None = None,
                     approval_required: bool | None = None, review_status: str | None = None,
                     environment: str | None = None, search: str | None = None,
                     page: dict[str, Any] = Depends(page_params), p: Principal = Depends(require_user()),
                     c: Container = Depends(get_container)) -> dict[str, Any]:
    if environment:
        env_servers = await c.repos.servers.find_all(p.tenant_id, {"environment": environment})
        ids = [s["_id"] for s in env_servers]
        if server_id and server_id not in ids:
            return {"items": [], "next_cursor": None, "total": 0}
    res = await c.registry.list_tools(p, server_id=server_id, risk=risk, enabled=enabled,
                                      approval_required=approval_required, review_status=review_status,
                                      search=search, **page)
    items = res["items"]
    if environment:
        items = [t for t in items if t["server_id"] in ids]
    counts = await c.usage.tool_call_counts(p.tenant_id, 7)
    return {**res, "items": [{**tool_to_api(t), "calls_7d": counts.get(t["_id"], 0)} for t in items]}


@router.get("/tools/{tool_id}")
async def get_tool(tool_id: str, p: Principal = Depends(require_user()),
                   c: Container = Depends(get_container)) -> dict[str, Any]:
    tool = await c.registry.get_tool(p, tool_id)
    server = await c.repos.servers.get(p.tenant_id, tool["server_id"])
    policies = await c.repos.policies._paginate({
        "tenant_id": {"$in": [p.tenant_id, "*"]}, "kind": {"$ne": "default_deny"},
        "$or": [{"resources.tools": {"$in": [tool["upstream_name"], tool["gateway_name"], tool_id, "*"]}},
                {"resources.tools": {"$regex": "\\*"}}]}, limit=100, sort=[("priority", 1)])
    return {**tool_to_api(tool, server),
            "policies": [{"id": x["_id"], "name": x["name"], "effect": x["effect"], "enabled": x.get("enabled"),
                          "principals": x.get("principals"), "priority": x.get("priority")}
                         for x in policies["items"]]}


@router.patch("/tools/{tool_id}")
async def update_tool(tool_id: str, body: ToolUpdate, p: Principal = Depends(require_user(*ADMINS, "security_admin")),
                      c: Container = Depends(get_container)) -> dict[str, Any]:
    return tool_to_api(await c.registry.update_tool(p, tool_id, body))


@router.get("/tools/{tool_id}/versions")
async def tool_versions(tool_id: str, p: Principal = Depends(require_user()),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    return {"items": await c.registry.tool_versions(p, tool_id)}
