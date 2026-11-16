"""Approval request API models (spec §14)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.core.ids import ensure_aware
from app.models.registry import Strict

TERMINAL = {"REJECTED", "CANCELLED", "EXPIRED", "COMPLETED", "FAILED", "EXECUTION_ABORTED", "CANCELLED_BY_ADMIN"}


class ApproveRequest(Strict):
    comment: str = Field(default="", max_length=2000)
    confirm_critical: bool = False


class RejectRequest(Strict):
    comment: str = Field(default="", max_length=2000)


class CancelRequest(Strict):
    reason: str = Field(default="", max_length=500)


class DelegationCreate(Strict):
    delegate_user_id: str = Field(min_length=1, max_length=64)
    # Administrators may create a delegation on behalf of an approver; everyone else delegates their own authority.
    delegator_user_id: str | None = Field(default=None, max_length=64)
    starts_at: datetime | None = None  # default: now
    ends_at: datetime
    reason: str = Field(default="", max_length=500)


def delegation_to_api(doc: dict[str, Any], now: datetime) -> dict[str, Any]:
    starts, ends = ensure_aware(doc["starts_at"]) or now, ensure_aware(doc["ends_at"]) or now
    if doc.get("revoked_at"):
        status = "revoked"
    elif ends <= now:
        status = "expired"
    elif starts > now:
        status = "scheduled"
    else:
        status = "active"
    return {
        "id": doc["_id"], "tenant_id": doc["tenant_id"], "status": status,
        "delegator_user_id": doc["delegator_user_id"], "delegator_name": doc.get("delegator_name"),
        "delegate_user_id": doc["delegate_user_id"], "delegate_name": doc.get("delegate_name"),
        "starts_at": doc["starts_at"], "ends_at": doc["ends_at"], "reason": doc.get("reason", ""),
        "created_by": doc.get("created_by"), "created_at": doc.get("created_at"),
        "revoked_at": doc.get("revoked_at"), "revoked_by": doc.get("revoked_by"),
    }


def approval_to_api(doc: dict[str, Any], *, include_args: dict[str, Any] | None = None) -> dict[str, Any]:
    out = {
        "id": doc["_id"], "tenant_id": doc["tenant_id"], "invocation_id": doc.get("invocation_id"),
        "status": doc["status"], "requester": doc.get("requester"), "agent_id": doc.get("agent_id"),
        "delegated_by_user_id": doc.get("delegated_by_user_id"),
        "tool_id": doc.get("tool_id"), "tool_name": doc.get("tool_name"), "gateway_name": doc.get("gateway_name"),
        "server_id": doc.get("server_id"), "server_name": doc.get("server_name"), "risk_level": doc.get("risk_level"),
        "purpose": doc.get("purpose"), "arguments_hash": doc.get("arguments_hash"),
        "arguments_preview": doc.get("arguments_preview"), "policy_ids": doc.get("policy_ids", []),
        "approval_policy": doc.get("approval_policy", {}), "required_approvals": doc.get("required_approvals", 1),
        "approvals": doc.get("approvals", []), "rejection": doc.get("rejection"),
        "cancellation": doc.get("cancellation"), "expires_at": doc.get("expires_at"),
        "escalate_at": doc.get("escalate_at"), "escalated_at": doc.get("escalated_at"),
        "approved_at": doc.get("approved_at"), "executed_at": doc.get("executed_at"),
        "completed_at": doc.get("completed_at"), "execution": doc.get("execution"),
        "created_at": doc.get("created_at"), "updated_at": doc.get("updated_at"),
    }
    if include_args is not None:
        out["arguments"] = include_args
    return out
