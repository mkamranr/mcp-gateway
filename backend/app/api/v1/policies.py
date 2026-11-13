"""/api/v1/policies (spec §16.4)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Response

from app.api.deps import get_container, page_params, require_user
from app.container import Container
from app.core.errors import GatewayError, not_found
from app.core.identity import SECURITY, Principal
from app.models.policy import PolicyCreate, PolicyUpdate, SimulateRequest, policy_to_api
from app.services.policy_service import RequestContext

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("")
async def list_policies(page: dict[str, Any] = Depends(page_params), p: Principal = Depends(require_user()),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    res = await c.policy.list_policies(p, **page)
    return {**res, "items": [policy_to_api(x) for x in res["items"]]}


@router.post("", status_code=201)
async def create_policy(body: PolicyCreate, p: Principal = Depends(require_user(*SECURITY)),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    return policy_to_api(await c.policy.create(p, body))


@router.post("/simulate")
async def simulate(body: SimulateRequest, p: Principal = Depends(require_user(*SECURITY, "developer", "auditor")),
                   c: Container = Depends(get_container)) -> dict[str, Any]:
    """Evaluate a sample request. Never dispatches to the upstream tool."""
    tool = (await c.repos.tools.get(p.tenant_id, body.tool_id) if body.tool_id
            else await c.repos.tools.by_gateway_name(p.tenant_id, body.gateway_name or ""))
    if not tool or tool.get("archived"):
        raise not_found("Tool")
    server = await c.repos.servers.get(p.tenant_id, tool["server_id"])
    if not server:
        raise not_found("Server")
    roles: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ("tools:list", "tools:invoke")
    if body.principal_type == "agent":
        agent = await c.repos.agents.get(p.tenant_id, body.principal_id)
        if not agent:
            raise not_found("Agent")
    else:
        m = await c.repos.memberships.find_one(p.tenant_id, {"user_id": body.principal_id})
        roles = tuple(m.get("roles", [])) if m else ()
    sample = Principal(principal_type=body.principal_type, principal_id=body.principal_id, tenant_id=p.tenant_id,
                       roles=roles, scopes=scopes, agent_id=body.principal_id if body.principal_type == "agent" else None)
    tenant = await c.repos.tenants.get(p.tenant_id) or {}
    decision = await c.policy.decide(RequestContext(
        principal=sample, action=body.action, server=server, tool=tool, source_ip=body.source_ip,
        critical_requires_approval=bool(tenant.get("settings", {}).get("critical_requires_approval", True))))
    state_issues = []
    if not server.get("enabled"):
        state_issues.append("SERVER_DISABLED")
    if not tool.get("enabled"):
        state_issues.append("TOOL_DISABLED")
    if tool.get("review_status") != "approved":
        state_issues.append("TOOL_NOT_REVIEWED" if tool.get("review_status") != "schema_changed"
                            else "TOOL_SCHEMA_CHANGED")
    validation: dict[str, Any] | None = None
    if body.arguments is not None:
        try:
            c.validation.validate_input(tool, body.arguments)
            validation = {"valid": True, "errors": []}
        except GatewayError as exc:
            validation = {"valid": False, "code": exc.code.value, "errors": exc.details}
    effective = decision.decision if not state_issues else "DENY"
    await c.audit.record(p.tenant_id, "policy.simulated", principal=p,
                         resource={"tool_id": tool["_id"], "tool_name": tool["upstream_name"]},
                         decision=effective, metadata={"sample_principal": body.principal_id, "action": body.action})
    return {**decision.admin(), "effective_decision": effective, "state_issues": state_issues,
            "validation": validation, "tool": {"id": tool["_id"], "gateway_name": tool["gateway_name"]},
            "dispatched": False}


@router.get("/{policy_id}")
async def get_policy(policy_id: str, p: Principal = Depends(require_user()),
                     c: Container = Depends(get_container)) -> dict[str, Any]:
    return policy_to_api(await c.policy.get(p, policy_id))


@router.get("/{policy_id}/history")
async def policy_history(policy_id: str, p: Principal = Depends(require_user()),
                         c: Container = Depends(get_container)) -> dict[str, Any]:
    return {"items": await c.policy.history(p, policy_id)}


@router.patch("/{policy_id}")
async def update_policy(policy_id: str, body: PolicyUpdate, p: Principal = Depends(require_user(*SECURITY)),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    return policy_to_api(await c.policy.update(p, policy_id, body))


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(policy_id: str, p: Principal = Depends(require_user(*SECURITY)),
                        c: Container = Depends(get_container)) -> Response:
    await c.policy.delete(p, policy_id)
    return Response(status_code=204)


@router.post("/{policy_id}/enable")
async def enable_policy(policy_id: str, p: Principal = Depends(require_user(*SECURITY)),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    return policy_to_api(await c.policy.set_enabled(p, policy_id, True))


@router.post("/{policy_id}/disable")
async def disable_policy(policy_id: str, p: Principal = Depends(require_user(*SECURITY)),
                         c: Container = Depends(get_container)) -> dict[str, Any]:
    return policy_to_api(await c.policy.set_enabled(p, policy_id, False))


@router.post("/{policy_id}/clone", status_code=201)
async def clone_policy(policy_id: str, p: Principal = Depends(require_user(*SECURITY)),
                       c: Container = Depends(get_container)) -> dict[str, Any]:
    return policy_to_api(await c.policy.clone(p, policy_id))
