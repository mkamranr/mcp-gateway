"""Approval request API models (spec §14)."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from app.models.registry import Strict

TERMINAL = {"REJECTED", "CANCELLED", "EXPIRED", "COMPLETED", "FAILED", "EXECUTION_ABORTED", "CANCELLED_BY_ADMIN"}


class ApproveRequest(Strict):
    comment: str = Field(default="", max_length=2000)
    confirm_critical: bool = False


class RejectRequest(Strict):
    comment: str = Field(default="", max_length=2000)


class CancelRequest(Strict):
    reason: str = Field(default="", max_length=500)


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
        "approved_at": doc.get("approved_at"), "executed_at": doc.get("executed_at"),
        "completed_at": doc.get("completed_at"), "execution": doc.get("execution"),
        "created_at": doc.get("created_at"), "updated_at": doc.get("updated_at"),
    }
    if include_args is not None:
        out["arguments"] = include_args
    return out
