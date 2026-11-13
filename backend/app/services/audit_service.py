"""Audit event creation (spec §15). Append-only; never stores raw payloads or secrets."""

from __future__ import annotations

from typing import Any

from app.core.errors import ErrorCode, GatewayError
from app.core.identity import Principal
from app.core.ids import new_id, utcnow
from app.core.logging import get_logger, request_id_var, scrub
from app.repositories.collections import Repos

log = get_logger(__name__)

HIGH_SEVERITY_EVENTS = {
    "credential.revoked",
    "agent.revoked",
    "tenant.suspended",
    "server.disabled",
    "tool.disabled",
    "emergency.action",
    "auth.login.failed",
    "tool.schema.changed",
    "policy.deleted",
}


class AuditService:
    def __init__(self, repos: Repos) -> None:
        self.repos = repos

    async def record(
        self,
        tenant_id: str,
        event_type: str,
        *,
        principal: Principal | dict[str, Any] | None = None,
        resource: dict[str, Any] | None = None,
        decision: str | None = None,
        policy_ids: list[str] | None = None,
        status: str | None = None,
        severity: str | None = None,
        invocation_id: str | None = None,
        approval_id: str | None = None,
        duration_ms: int | None = None,
        input_hash: str | None = None,
        output_hash: str | None = None,
        reason_code: str | None = None,
        metadata: dict[str, Any] | None = None,
        required: bool = False,
    ) -> dict[str, Any] | None:
        """Persist one audit event.

        ``required=True`` means the caller's action must not proceed if the event cannot be
        written (fail closed): an ``AUDIT_UNAVAILABLE`` error is raised.
        """
        if isinstance(principal, Principal):
            pref: dict[str, Any] | None = principal.audit_ref()
            delegated = principal.delegated_by_user_id
        else:
            pref = principal
            delegated = None
        event = {
            "event_id": new_id("evt"),
            "timestamp": utcnow(),
            "event_type": event_type,
            "severity": severity or ("high" if event_type in HIGH_SEVERITY_EVENTS else "info"),
            "request_id": request_id_var.get(),
            "invocation_id": invocation_id,
            "approval_id": approval_id,
            "principal": pref,
            "delegated_by_user_id": delegated,
            "resource": resource or {},
            "decision": decision,
            "reason_code": reason_code,
            "policy_ids": policy_ids or [],
            "status": status,
            "duration_ms": duration_ms,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "metadata": scrub(metadata or {}),
        }
        try:
            return await self.repos.audit.append(tenant_id, event)
        except Exception as exc:  # noqa: BLE001
            log.error("audit.write_failed", event_type=event_type, error=type(exc).__name__)
            if required:
                raise GatewayError(ErrorCode.AUDIT_UNAVAILABLE, "Audit persistence is unavailable.") from exc
            return None
