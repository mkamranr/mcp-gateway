"""/api/v1/approvals (spec §16.5). Agents may read their own requests' status and result."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.api.deps import get_container, get_principal, page_params, require_user
from app.container import Container
from app.core.errors import denied
from app.core.identity import Principal
from app.core.ids import utcnow
from app.models.approval import (
    ApproveRequest,
    CancelRequest,
    DelegationCreate,
    RejectRequest,
    approval_to_api,
    delegation_to_api,
)

router = APIRouter(prefix="/approvals", tags=["approvals"])


def _readable(p: Principal) -> None:
    if p.principal_type == "agent" and "approvals:read" not in p.scopes:
        raise denied("The credential lacks the approvals:read scope.")


@router.get("")
async def list_approvals(status: str | None = None, risk: str | None = None, requester: str | None = None,
                         tool: str | None = None, page: dict[str, Any] = Depends(page_params),
                         p: Principal = Depends(get_principal), c: Container = Depends(get_container)) -> dict[str, Any]:
    _readable(p)
    res = await c.approvals.list(p, status=status, risk=risk, requester=requester, tool=tool, **page)
    return {**res, "items": [approval_to_api(d) for d in res["items"]], "counts": await c.approvals.counts(p.tenant_id)}


# Delegations are declared before /{approval_id} so that "delegations" is not read as an approval id.
@router.get("/delegations")
async def list_delegations(scope: str = "mine", include_past: bool = False, p: Principal = Depends(require_user()),
                           c: Container = Depends(get_container)) -> dict[str, Any]:
    docs = await c.approvals.list_delegations(p, everyone=scope == "all", include_past=include_past)
    now = utcnow()
    return {"items": [delegation_to_api(d, now) for d in docs]}


@router.get("/delegations/candidates")
async def delegate_candidates(p: Principal = Depends(require_user()),
                              c: Container = Depends(get_container)) -> dict[str, Any]:
    return {"items": await c.approvals.delegate_candidates(p)}


@router.post("/delegations", status_code=201)
async def create_delegation(body: DelegationCreate, p: Principal = Depends(require_user()),
                            c: Container = Depends(get_container)) -> dict[str, Any]:
    return delegation_to_api(await c.approvals.create_delegation(p, body), utcnow())


@router.delete("/delegations/{delegation_id}")
async def revoke_delegation(delegation_id: str, p: Principal = Depends(require_user()),
                            c: Container = Depends(get_container)) -> dict[str, Any]:
    return delegation_to_api(await c.approvals.revoke_delegation(p, delegation_id), utcnow())


@router.get("/{approval_id}")
async def get_approval(approval_id: str, p: Principal = Depends(get_principal),
                       c: Container = Depends(get_container)) -> dict[str, Any]:
    _readable(p)
    if p.principal_type == "agent":
        doc = await c.approvals.get(p, approval_id)
        return approval_to_api(doc)
    d = await c.approvals.detail(p, approval_id)
    await c.audit.record(p.tenant_id, "approval.viewed", principal=p, approval_id=approval_id)
    return {**approval_to_api(d["approval"], include_args=d["arguments"]), "integrity": d["integrity"],
            "preview_gaps": d["preview_gaps"], "changes_since_request": d["changes_since_request"],
            "related_invocations": [{**{k: v for k, v in i.items() if k != "_id"}, "id": i["_id"]}
                                    for i in d["related_invocations"]],
            "separation_of_duties_warning": d["separation_of_duties_warning"], "can_decide": d["can_decide"],
            "cannot_decide_reason": d["cannot_decide_reason"], "decide_as": d["decide_as"],
            "agent_owner_user_id": d["agent_owner_user_id"]}


@router.get("/{approval_id}/status")
async def approval_status(approval_id: str, p: Principal = Depends(get_principal),
                          c: Container = Depends(get_container)) -> dict[str, Any]:
    """Polling endpoint for the requesting agent. Includes the result once COMPLETED (24h retention)."""
    _readable(p)
    doc = await c.approvals.get(p, approval_id)
    out = {"approval_id": doc["_id"], "status": doc["status"], "expires_at": doc.get("expires_at"),
           "approvals": len(doc.get("approvals", [])), "required_approvals": doc.get("required_approvals")}
    if doc["status"] == "COMPLETED" and p.principal_type == "agent":
        out["result"] = c.invocations.approval_result(doc)
    if doc["status"] in ("EXECUTION_ABORTED", "FAILED"):
        out["error_code"] = (doc.get("execution") or {}).get("error_code")
    return out


@router.post("/{approval_id}/approve")
async def approve(approval_id: str, body: ApproveRequest, p: Principal = Depends(require_user()),
                  c: Container = Depends(get_container)) -> dict[str, Any]:
    return approval_to_api(await c.approvals.approve(p, approval_id, body.comment, body.confirm_critical))


@router.post("/{approval_id}/reject")
async def reject(approval_id: str, body: RejectRequest, p: Principal = Depends(require_user()),
                 c: Container = Depends(get_container)) -> dict[str, Any]:
    return approval_to_api(await c.approvals.reject(p, approval_id, body.comment))


@router.post("/{approval_id}/cancel")
async def cancel(approval_id: str, body: CancelRequest | None = None, p: Principal = Depends(get_principal),
                 c: Container = Depends(get_container)) -> dict[str, Any]:
    return approval_to_api(await c.approvals.cancel(p, approval_id, body.reason if body else ""))
