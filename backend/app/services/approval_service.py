"""Approval workflow (spec §14).

Lifecycle: PENDING -> APPROVED -> REVALIDATING -> EXECUTING -> COMPLETED | FAILED,
or PENDING -> REJECTED | CANCELLED | EXPIRED. Revalidation can also end in
EXECUTION_ABORTED. Every transition is an atomic compare-and-set on the current status, so
two workers or two approvers can never move the same request forward twice.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from redis.asyncio import Redis

from app.config import Settings
from app.core.crypto import Encryptor
from app.core.errors import ErrorCode, GatewayError, denied, not_found
from app.core.identity import Principal, Role
from app.core.ids import ensure_aware, sha256_hex, utcnow
from app.core.logging import get_logger
from app.models.approval import TERMINAL
from app.repositories.collections import Repos
from app.services.audit_service import AuditService

log = get_logger(__name__)
JOB_STREAM = "jobs:approved"
JOB_GROUP = "workers"
MASK = "••••••"


def mask_arguments(args: Any, redact_fields: list[str], depth: int = 0) -> Any:
    """Masked view for approvers: configured sensitive fields hidden, long strings truncated."""
    fields = {f.lower() for f in redact_fields}
    if depth > 16:
        return "…"
    if isinstance(args, dict):
        return {k: (MASK if k.lower() in fields else mask_arguments(v, redact_fields, depth + 1)) for k, v in args.items()}
    if isinstance(args, list):
        return [mask_arguments(v, redact_fields, depth + 1) for v in args[:100]]
    if isinstance(args, str) and len(args) > 2000:
        return args[:2000] + f"… ({len(args)} chars)"
    return args


class ApprovalService:
    def __init__(self, settings: Settings, repos: Repos, redis: Redis, encryptor: Encryptor,
                 audit: AuditService) -> None:
        self.settings = settings
        self.repos = repos
        self.redis = redis
        self.encryptor = encryptor
        self.audit = audit

    # ------------------------------------------------------------------ creation
    async def create(
        self,
        principal: Principal,
        *,
        invocation_id: str,
        tool: dict[str, Any],
        server: dict[str, Any],
        arguments: dict[str, Any],
        arguments_hash: str,
        decision_policy_ids: list[str],
        approval_obligation: dict[str, Any],
        purpose: str | None,
    ) -> dict[str, Any]:
        ttl = int(approval_obligation.get("ttl_minutes") or self.settings.approval_default_ttl_minutes)
        policies = await self.repos.policies.enabled_for_tenant(principal.tenant_id)
        doc = await self.repos.approvals.insert(principal.tenant_id, {
            "invocation_id": invocation_id,
            "requester": principal.audit_ref(),
            "agent_id": principal.agent_id,
            "credential_id": principal.credential_id,
            "delegated_by_user_id": principal.delegated_by_user_id,
            "tool_id": tool["_id"], "tool_name": tool["upstream_name"], "gateway_name": tool["gateway_name"],
            "server_id": server["_id"], "server_name": server["name"], "risk_level": tool.get("risk_level"),
            "purpose": (purpose or "")[:1000] or None,
            "arguments_encrypted": "",
            "arguments_hash": arguments_hash,
            "arguments_preview": mask_arguments(arguments, (tool.get("output") or {}).get("redact_fields", [])),
            "policy_ids": decision_policy_ids,
            "approval_policy": approval_obligation,
            "required_approvals": int(approval_obligation.get("required_approvals", 1)),
            "approvals": [],
            "status": "PENDING",
            "expires_at": utcnow() + timedelta(minutes=ttl),
            "tool_schema_hash": tool.get("schema_hash"),
            "tool_version": tool.get("version"),
            "policy_versions": {p["_id"]: p.get("version", 1) for p in policies},
        })
        # Encrypt with associated data bound to tenant + approval id: the ciphertext cannot be
        # moved to another approval request or tenant.
        ct = self.encryptor.encrypt(json.dumps(arguments).encode(), f"{principal.tenant_id}:{doc['_id']}")
        await self.repos.approvals.col.update_one(
            {"_id": doc["_id"], "tenant_id": principal.tenant_id}, {"$set": {"arguments_encrypted": ct}}
        )
        doc["arguments_encrypted"] = ct
        await self.audit.record(
            principal.tenant_id, "approval.created", principal=principal, approval_id=doc["_id"],
            invocation_id=invocation_id, decision="REQUIRE_APPROVAL", policy_ids=decision_policy_ids,
            resource={"server_id": server["_id"], "tool_id": tool["_id"], "tool_name": tool["upstream_name"]},
            input_hash=arguments_hash, status="pending",
            metadata={"required_approvals": doc["required_approvals"], "expires_at": doc["expires_at"].isoformat(),
                      "reasons": approval_obligation.get("reasons")},
            required=True,
        )
        return doc

    def decrypt_arguments(self, doc: dict[str, Any]) -> dict[str, Any]:
        """Decrypt and verify integrity against the stored hash (spec §14.4)."""
        try:
            raw = self.encryptor.decrypt(doc["arguments_encrypted"], f"{doc['tenant_id']}:{doc['_id']}")
            args = json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            raise GatewayError(ErrorCode.APPROVAL_INVALIDATED, "Approved arguments failed integrity checks.") from exc
        if sha256_hex(args) != doc["arguments_hash"]:
            raise GatewayError(ErrorCode.APPROVAL_INVALIDATED, "Approved arguments failed integrity checks.")
        return args  # type: ignore[no-any-return]

    # ------------------------------------------------------------------ queries
    async def get(self, p: Principal, approval_id: str) -> dict[str, Any]:
        doc = await self.repos.approvals.get(p.tenant_id, approval_id)
        if not doc:
            raise not_found("Approval request")
        if p.principal_type == "agent" and doc.get("agent_id") != p.agent_id:
            raise not_found("Approval request")
        return doc

    async def detail(self, p: Principal, approval_id: str) -> dict[str, Any]:
        doc = await self.get(p, approval_id)
        tool = await self.repos.tools.get(p.tenant_id, doc["tool_id"])
        redact = (tool or {}).get("output", {}).get("redact_fields", [])
        try:
            args = mask_arguments(self.decrypt_arguments(doc), redact)
            integrity = "verified"
        except GatewayError:
            args, integrity = None, "failed"
        changes = await self._changes_since_request(doc, tool)
        related = await self.repos.invocations.list(
            p.tenant_id, {"principal.id": doc["requester"]["id"], "tool_id": doc["tool_id"],
                          "_id": {"$ne": doc.get("invocation_id")}}, limit=5)
        agent = await self.repos.agents.get(p.tenant_id, doc["agent_id"]) if doc.get("agent_id") else None
        sod = self._separation_issue(p, doc, agent)
        return {"approval": doc, "arguments": args, "integrity": integrity, "changes_since_request": changes,
                "related_invocations": related["items"], "separation_of_duties_warning": sod,
                "can_decide": self._can_decide(p, doc, agent)[0], "agent_owner_user_id": (agent or {}).get("owner_user_id")}

    async def _changes_since_request(self, doc: dict[str, Any], tool: dict[str, Any] | None) -> list[str]:
        changes = []
        if not tool:
            return ["tool_removed"]
        if tool.get("schema_hash") != doc.get("tool_schema_hash"):
            changes.append("tool_schema_changed")
        if tool.get("version") != doc.get("tool_version"):
            changes.append("tool_configuration_changed")
        if not tool.get("enabled"):
            changes.append("tool_disabled")
        current = {p["_id"]: p.get("version", 1)
                   for p in await self.repos.policies.enabled_for_tenant(doc["tenant_id"])}
        if current != doc.get("policy_versions", {}):
            changes.append("policies_changed")
        return changes

    async def list(self, p: Principal, *, status: str | None = None, risk: str | None = None,
                   requester: str | None = None, tool: str | None = None, **kw: Any) -> Any:
        q: dict[str, Any] = {}
        if status:
            groups = {"approved": ["APPROVED", "REVALIDATING", "EXECUTING", "COMPLETED", "FAILED",
                                   "EXECUTION_ABORTED"],
                      "rejected": ["REJECTED"], "expired": ["EXPIRED"], "pending": ["PENDING"],
                      "cancelled": ["CANCELLED", "CANCELLED_BY_ADMIN"]}
            q["status"] = {"$in": groups.get(status.lower(), [status.upper()])}
        if risk:
            q["risk_level"] = risk
        if requester:
            q["$or"] = [{"requester.id": requester}, {"requester.name": requester}]
        if tool:
            q["$or"] = [{"tool_name": tool}, {"gateway_name": tool}, {"tool_id": tool}]
        if p.principal_type == "agent":
            q["agent_id"] = p.agent_id
        return await self.repos.approvals.list(p.tenant_id, q, **kw)

    async def counts(self, tenant_id: str) -> dict[str, Any]:
        pending = await self.repos.approvals.count(tenant_id, {"status": "PENDING"})
        oldest = await self.repos.approvals.col.find_one(
            {"tenant_id": tenant_id, "status": "PENDING"}, sort=[("created_at", 1)])
        created = ensure_aware(oldest["created_at"]) if oldest else None
        age = int((utcnow() - created).total_seconds()) if created else 0
        return {"pending": pending, "oldest_pending_age_seconds": age}

    # ------------------------------------------------------------------ decisions
    def _can_decide(self, p: Principal, doc: dict[str, Any], agent: dict[str, Any] | None) -> tuple[bool, str | None]:
        if p.principal_type != "user":
            return False, "Only human users can approve requests."
        roles = doc.get("approval_policy", {}).get("approver_roles") or [Role.APPROVER.value]
        if not (p.has_any_role(*roles) or p.is_global_admin):
            return False, "You do not hold an approver role for this request."
        if self._separation_issue(p, doc, agent) and not doc.get("approval_policy", {}).get("allow_self_approval"):
            return False, "Separation of duties: requesters cannot approve their own requests."
        if any(a["approver_id"] == p.principal_id for a in doc.get("approvals", [])):
            return False, "You have already approved this request."
        return True, None

    @staticmethod
    def _separation_issue(p: Principal, doc: dict[str, Any], agent: dict[str, Any] | None) -> bool:
        requester_ids = {doc.get("requester", {}).get("id"), doc.get("delegated_by_user_id")}
        if agent:
            requester_ids.add(agent.get("owner_user_id"))
        return p.principal_id in requester_ids

    async def _expire_if_due(self, doc: dict[str, Any]) -> None:
        exp = ensure_aware(doc.get("expires_at"))
        if doc["status"] == "PENDING" and exp and exp <= utcnow():
            await self.expire(doc["tenant_id"], doc["_id"])
            raise GatewayError(ErrorCode.APPROVAL_EXPIRED, "This approval request has expired.")

    async def approve(self, p: Principal, approval_id: str, comment: str, confirm_critical: bool) -> dict[str, Any]:
        doc = await self.get(p, approval_id)
        if doc["status"] != "PENDING":
            raise GatewayError(ErrorCode.APPROVAL_STATE_CONFLICT, f"Request is {doc['status']}, not PENDING.")
        await self._expire_if_due(doc)
        agent = await self.repos.agents.get(p.tenant_id, doc["agent_id"]) if doc.get("agent_id") else None
        ok, why = self._can_decide(p, doc, agent)
        if not ok:
            code = ErrorCode.SEPARATION_OF_DUTIES if why and "Separation" in why else ErrorCode.ACCESS_DENIED
            raise GatewayError(code, why)
        if doc.get("risk_level") == "critical" and not confirm_critical:
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "Critical actions require explicit confirmation.",
                               details=[{"field": "confirm_critical", "code": "required"}])
        if doc.get("approval_policy", {}).get("require_comment_on_approve") and not comment.strip():
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "A comment is required to approve.",
                               details=[{"field": "comment", "code": "required"}])
        entry = {"approver_id": p.principal_id, "approver_name": p.display_name, "at": utcnow(),
                 "comment": comment.strip()[:2000]}
        # Atomic: append only while still PENDING and this user has not already approved.
        updated = await self.repos.approvals.col.find_one_and_update(
            {"_id": approval_id, "tenant_id": p.tenant_id, "status": "PENDING",
             "approvals.approver_id": {"$ne": p.principal_id}},
            {"$push": {"approvals": entry}, "$set": {"updated_at": utcnow()}},
            return_document=True,
        )
        if not updated:
            raise GatewayError(ErrorCode.APPROVAL_STATE_CONFLICT, "The request changed; reload and try again.")
        await self.audit.record(p.tenant_id, "approval.approved", principal=p, approval_id=approval_id,
                                invocation_id=doc.get("invocation_id"),
                                resource={"tool_id": doc["tool_id"], "tool_name": doc["tool_name"]},
                                metadata={"comment": entry["comment"], "approvals": len(updated["approvals"]),
                                          "required": updated["required_approvals"]})
        if len(updated["approvals"]) >= int(updated["required_approvals"]):
            final = await self.repos.approvals.transition(p.tenant_id, approval_id, "PENDING", "APPROVED",
                                                          {"approved_at": utcnow()})
            if final:
                await self.enqueue(p.tenant_id, approval_id)
                return final
        return updated

    async def reject(self, p: Principal, approval_id: str, comment: str) -> dict[str, Any]:
        doc = await self.get(p, approval_id)
        agent = await self.repos.agents.get(p.tenant_id, doc["agent_id"]) if doc.get("agent_id") else None
        ok, why = self._can_decide(p, doc, agent)
        if not ok and "already approved" not in (why or ""):
            raise GatewayError(ErrorCode.ACCESS_DENIED, why)
        if doc.get("approval_policy", {}).get("require_comment_on_reject", True) and not comment.strip():
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "A comment is required to reject.",
                               details=[{"field": "comment", "code": "required"}])
        updated = await self.repos.approvals.transition(
            p.tenant_id, approval_id, "PENDING", "REJECTED",
            {"rejection": {"by": p.principal_id, "by_name": p.display_name, "at": utcnow(),
                           "comment": comment.strip()[:2000]}})
        if not updated:
            raise GatewayError(ErrorCode.APPROVAL_STATE_CONFLICT, "Only pending requests can be rejected.")
        await self.repos.invocations.update(p.tenant_id, doc["invocation_id"], {"status": "rejected"})
        await self.audit.record(p.tenant_id, "approval.rejected", principal=p, approval_id=approval_id,
                                invocation_id=doc.get("invocation_id"), decision="DENY",
                                resource={"tool_id": doc["tool_id"], "tool_name": doc["tool_name"]},
                                metadata={"comment": comment.strip()[:2000]})
        return updated

    async def cancel(self, p: Principal, approval_id: str, reason: str) -> dict[str, Any]:
        doc = await self.get(p, approval_id)
        is_requester = p.principal_type == "agent" and doc.get("agent_id") == p.agent_id
        is_admin = p.has_any_role(Role.PLATFORM_ADMIN, Role.TENANT_ADMIN, Role.SECURITY_ADMIN)
        if not (is_requester or is_admin):
            raise denied("Only the requester or an administrator can cancel.")
        to = "CANCELLED" if is_requester else "CANCELLED_BY_ADMIN"
        updated = await self.repos.approvals.transition(
            p.tenant_id, approval_id, ["PENDING", "APPROVED"], to,
            {"cancellation": {"by": p.principal_id, "at": utcnow(), "reason": reason[:500]}})
        if not updated:
            raise GatewayError(ErrorCode.APPROVAL_STATE_CONFLICT, "The request can no longer be cancelled.")
        await self.repos.invocations.update(p.tenant_id, doc["invocation_id"], {"status": "cancelled"})
        await self.audit.record(p.tenant_id, "approval.cancelled", principal=p, approval_id=approval_id,
                                invocation_id=doc.get("invocation_id"), metadata={"reason": reason[:500]})
        return updated

    async def expire(self, tenant_id: str, approval_id: str) -> bool:
        doc = await self.repos.approvals.transition(tenant_id, approval_id, "PENDING", "EXPIRED")
        if not doc:
            return False
        await self.repos.invocations.update(tenant_id, doc["invocation_id"], {"status": "expired"})
        await self.audit.record(tenant_id, "approval.expired", principal={"type": "service", "id": "worker"},
                                approval_id=approval_id, invocation_id=doc.get("invocation_id"),
                                resource={"tool_id": doc["tool_id"], "tool_name": doc["tool_name"]})
        return True

    async def expire_due(self) -> int:
        n = 0
        for d in await self.repos.approvals.expired_pending_global(utcnow()):
            if await self.expire(d["tenant_id"], d["_id"]):
                n += 1
        return n

    # ------------------------------------------------------------------ job queue
    async def enqueue(self, tenant_id: str, approval_id: str) -> None:
        try:
            await self.redis.xadd(JOB_STREAM, {"tenant_id": tenant_id, "approval_id": approval_id},
                                  maxlen=100_000, approximate=True)
        except Exception:  # noqa: BLE001
            # Not fatal: the worker's recovery sweep re-enqueues APPROVED requests.
            log.warning("approval.enqueue_failed", approval_id=approval_id)

    async def requeue_stuck(self) -> int:
        stuck = await self.repos.approvals.stuck_approved_global(utcnow() - timedelta(seconds=30))
        for d in stuck:
            await self.enqueue(d["tenant_id"], d["_id"])
        return len(stuck)

    def is_terminal(self, status: str) -> bool:
        return status in TERMINAL
