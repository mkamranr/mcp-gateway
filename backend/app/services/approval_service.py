"""Approval workflow (spec §14).

Lifecycle: PENDING -> APPROVED -> REVALIDATING -> EXECUTING -> COMPLETED | FAILED,
or PENDING -> REJECTED | CANCELLED | EXPIRED. Revalidation can also end in
EXECUTION_ABORTED. Every transition is an atomic compare-and-set on the current status, so
two workers or two approvers can never move the same request forward twice.
"""

from __future__ import annotations

import builtins
import json
from datetime import timedelta
from typing import Any

from redis.asyncio import Redis

from app.config import Settings
from app.core.crypto import Encryptor
from app.core.errors import ErrorCode, GatewayError, denied, not_found
from app.core.identity import APPROVERS, SECURITY, Principal, Role
from app.core.ids import ensure_aware, sha256_hex, utcnow
from app.core.logging import get_logger
from app.models.approval import TERMINAL, DelegationCreate
from app.repositories.collections import Repos
from app.services.audit_service import AuditService
from app.services.registry_service import server_config_fingerprint

log = get_logger(__name__)
JOB_STREAM = "jobs:approved"
JOB_GROUP = "workers"
MASK = "••••••"
DELEGATION_MAX_DAYS = 90
MAX_ACTIVE_DELEGATIONS = 10
WORKER = {"type": "service", "id": "worker"}
APPROVER_ROLES = {r.value for r in APPROVERS}


PREVIEW_DEPTH, PREVIEW_ITEMS, PREVIEW_CHARS = 16, 100, 2000


def mask_arguments(args: Any, redact_fields: list[str], depth: int = 0) -> Any:
    """Masked view for approvers: configured sensitive fields hidden, long strings and lists shortened, every
    omission marked. ``preview_gaps`` says whether anything was left out."""
    fields = {f.lower() for f in redact_fields}
    if depth > PREVIEW_DEPTH:
        return "… (nested too deeply to show)"
    if isinstance(args, dict):
        return {k: (MASK if k.lower() in fields else mask_arguments(v, redact_fields, depth + 1)) for k, v in args.items()}
    if isinstance(args, list):
        shown = [mask_arguments(v, redact_fields, depth + 1) for v in args[:PREVIEW_ITEMS]]
        if len(args) > PREVIEW_ITEMS:
            shown.append(f"… ({len(args) - PREVIEW_ITEMS} more items not shown)")
        return shown
    if isinstance(args, str) and len(args) > PREVIEW_CHARS:
        return args[:PREVIEW_CHARS] + f"… ({len(args)} chars)"
    return args


def preview_gaps(args: Any, redact_fields: list[str]) -> list[str]:
    """What ``mask_arguments`` leaves out of the approver's view: ``items_omitted``, ``text_truncated``,
    ``nesting_truncated``, ``fields_masked``. Empty when the preview shows the arguments in full."""
    fields = {f.lower() for f in redact_fields}
    gaps: set[str] = set()

    def walk(v: Any, depth: int) -> None:
        if depth > PREVIEW_DEPTH:
            gaps.add("nesting_truncated")
        elif isinstance(v, dict):
            for k, item in v.items():
                if k.lower() in fields:
                    gaps.add("fields_masked")
                else:
                    walk(item, depth + 1)
        elif isinstance(v, list):
            if len(v) > PREVIEW_ITEMS:
                gaps.add("items_omitted")
            for item in v[:PREVIEW_ITEMS]:
                walk(item, depth + 1)
        elif isinstance(v, str) and len(v) > PREVIEW_CHARS:
            gaps.add("text_truncated")

    walk(args, 0)
    return sorted(gaps)


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
        now = utcnow()
        expires_at = now + timedelta(minutes=ttl)
        esc = approval_obligation.get("escalate_after_minutes")
        escalate_at = now + timedelta(minutes=int(esc)) if esc and int(esc) < ttl else None
        rem = approval_obligation.get("remind_before_expiry_minutes")
        remind_at = expires_at - timedelta(minutes=int(rem)) if rem and int(rem) < ttl else None
        policies = await self.repos.policies.enabled_for_tenant(principal.tenant_id)
        cred = (await self.repos.credentials.get(principal.tenant_id, principal.credential_id)
                if principal.credential_id else None)
        doc = await self.repos.approvals.insert(principal.tenant_id, {
            "invocation_id": invocation_id,
            "requester": principal.audit_ref(),
            "agent_id": principal.agent_id,
            "credential_id": principal.credential_id,
            # Whoever issued the calling credential is a requester too, for separation of duties.
            "credential_issued_by": (cred or {}).get("created_by"),
            "delegated_by_user_id": principal.delegated_by_user_id,
            "server_config_hash": server_config_fingerprint(server),
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
            "expires_at": expires_at,
            "escalate_at": escalate_at,
            "escalated_at": None,
            "remind_at": remind_at,
            "reminded_at": None,
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
            plain = self.decrypt_arguments(doc)
            args, gaps = mask_arguments(plain, redact), preview_gaps(plain, redact)
            integrity = "verified"
        except GatewayError:
            args, gaps, integrity = None, [], "failed"
        changes = await self._changes_since_request(doc, tool)
        related = await self.repos.invocations.list(
            p.tenant_id, {"principal.id": doc["requester"]["id"], "tool_id": doc["tool_id"],
                          "_id": {"$ne": doc.get("invocation_id")}}, limit=5)
        agent = await self.repos.agents.get(p.tenant_id, doc["agent_id"]) if doc.get("agent_id") else None
        sod = self._separation_issue(p, doc, agent)
        capacity, why = await self._decide_as(p, doc, agent)
        decide_as = ({"on_behalf_of": capacity["id"], "on_behalf_of_name": capacity["name"],
                      "delegation_id": capacity["delegation_id"]}
                     if capacity and capacity["delegation_id"] else None)
        return {"approval": doc, "arguments": args, "integrity": integrity, "preview_gaps": gaps,
                "changes_since_request": changes,
                "related_invocations": related["items"], "separation_of_duties_warning": sod,
                "can_decide": capacity is not None, "cannot_decide_reason": why, "decide_as": decide_as,
                "agent_owner_user_id": (agent or {}).get("owner_user_id")}

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
    async def _identity(self, tenant_id: str, user_id: str | None) -> dict[str, Any] | None:
        """Current roles and SSO groups of an active tenant member, or None."""
        if not user_id:
            return None
        user = await self.repos.users.get(user_id)
        if not user or user.get("status") != "active":
            return None
        membership = await self.repos.memberships.find_one(tenant_id, {"user_id": user_id, "status": "active"})
        roles = set((membership or {}).get("roles", []))
        is_global = bool(user.get("is_platform_admin"))
        if is_global:
            roles.add(Role.PLATFORM_ADMIN.value)
        if not roles:
            return None
        return {"id": user_id, "name": user.get("display_name") or user["username"], "roles": roles,
                "groups": set(user.get("last_oidc_groups") or []), "is_global": is_global}

    @staticmethod
    def _requester_ids(doc: dict[str, Any], agent: dict[str, Any] | None) -> set[str]:
        # The caller, the user who delegated to it, the user who issued its credential, and the agent's owner and
        # creator: none of them may approve the agent's own request (unless the policy allows self-approval).
        ids = {doc.get("requester", {}).get("id"), doc.get("delegated_by_user_id"), doc.get("credential_issued_by")}
        if agent:
            ids.update((agent.get("owner_user_id"), agent.get("created_by")))
        return {i for i in ids if i}

    def _authority_issue(self, actor_id: str, ident: dict[str, Any], doc: dict[str, Any],
                         agent: dict[str, Any] | None) -> str | None:
        """Why ``actor_id`` may not decide with ``ident``'s authority (their own or a delegator's); None if they may."""
        pol = doc.get("approval_policy", {})
        roles = set(pol.get("approver_roles") or [Role.APPROVER.value])
        groups = set(pol.get("approver_groups") or [])
        has_role = ident["is_global"] or bool(ident["roles"] & roles)
        in_group = not groups or bool(ident["groups"] & groups)
        escalated = bool(doc.get("escalated_at")) and bool(ident["roles"] & set(pol.get("escalation_roles") or []))
        if not ((has_role and in_group) or escalated):
            if has_role:
                return "This request must be approved by a member of: " + ", ".join(sorted(groups)) + "."
            return "You do not hold an approver role for this request."
        both = {actor_id, ident["id"]}
        if self._requester_ids(doc, agent) & both and not pol.get("allow_self_approval"):
            return "Separation of duties: requesters cannot approve their own requests."
        approvals = doc.get("approvals", [])
        done = {a.get("approver_id") for a in approvals} | {a.get("on_behalf_of") for a in approvals}
        if both & done:
            if actor_id in done:
                return "You have already approved this request."
            return f"{ident['name']} has already approved this request."
        return None

    async def _decide_as(self, p: Principal, doc: dict[str, Any],
                         agent: dict[str, Any] | None) -> tuple[dict[str, Any] | None, str | None]:
        """The authority a user decides with: their own if sufficient, else an active delegation to them.

        Delegations do not chain: only authority delegated directly to this user counts. The delegator's
        current roles and groups are used, so a delegator who loses the approver role passes nothing on.
        """
        if p.principal_type != "user":
            return None, "Only human users can approve requests."
        reasons: builtins.list[str] = []
        me = await self._identity(p.tenant_id, p.principal_id)
        if me:
            why = self._authority_issue(p.principal_id, me, doc, agent)
            if why is None:
                return {**me, "delegation_id": None}, None
            reasons.append(why)
        for d in await self._active_delegations_to(p.tenant_id, p.principal_id):
            ident = await self._identity(p.tenant_id, d["delegator_user_id"])
            if not ident:
                continue
            why = self._authority_issue(p.principal_id, ident, doc, agent)
            if why is None:
                return {**ident, "delegation_id": d["_id"]}, None
            reasons.append(why)
        # Most specific explanation first: separation of duties or "already approved" beat a missing role.
        for r in reasons:
            if not r.startswith("You do not hold"):
                return None, r
        return None, reasons[0] if reasons else "You do not hold an approver role for this request."

    @staticmethod
    def _separation_issue(p: Principal, doc: dict[str, Any], agent: dict[str, Any] | None) -> bool:
        return p.principal_id in ApprovalService._requester_ids(doc, agent)

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
        capacity, why = await self._decide_as(p, doc, agent)
        if capacity is None:
            code = ErrorCode.SEPARATION_OF_DUTIES if why and "Separation" in why else ErrorCode.ACCESS_DENIED
            raise GatewayError(code, why)
        on_behalf = capacity["id"] if capacity["delegation_id"] else None
        if doc.get("risk_level") == "critical" and not confirm_critical:
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "Critical actions require explicit confirmation.",
                               details=[{"field": "confirm_critical", "code": "required"}])
        if doc.get("approval_policy", {}).get("require_comment_on_approve") and not comment.strip():
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "A comment is required to approve.",
                               details=[{"field": "comment", "code": "required"}])
        entry = {"approver_id": p.principal_id, "approver_name": p.display_name, "at": utcnow(),
                 "comment": comment.strip()[:2000], "on_behalf_of": on_behalf,
                 "on_behalf_of_name": capacity["name"] if on_behalf else None,
                 "delegation_id": capacity["delegation_id"]}
        # Atomic: append only while still PENDING and neither this user nor the person they act for has
        # approved yet, so one person's authority can never count twice towards a two-person rule.
        ids = sorted({p.principal_id, capacity["id"]})
        updated = await self.repos.approvals.col.find_one_and_update(
            {"_id": approval_id, "tenant_id": p.tenant_id, "status": "PENDING",
             "approvals.approver_id": {"$nin": ids}, "approvals.on_behalf_of": {"$nin": ids}},
            {"$push": {"approvals": entry}, "$set": {"updated_at": utcnow()}},
            return_document=True,
        )
        if not updated:
            raise GatewayError(ErrorCode.APPROVAL_STATE_CONFLICT, "The request changed; reload and try again.")
        await self.audit.record(p.tenant_id, "approval.approved", principal=p, approval_id=approval_id,
                                invocation_id=doc.get("invocation_id"),
                                resource={"tool_id": doc["tool_id"], "tool_name": doc["tool_name"]},
                                metadata={"comment": entry["comment"], "approvals": len(updated["approvals"]),
                                          "required": updated["required_approvals"], "on_behalf_of": on_behalf,
                                          "delegation_id": capacity["delegation_id"]})
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
        capacity, why = await self._decide_as(p, doc, agent)
        if capacity is None and "already approved" not in (why or ""):
            code = ErrorCode.SEPARATION_OF_DUTIES if why and "Separation" in why else ErrorCode.ACCESS_DENIED
            raise GatewayError(code, why)
        on_behalf = capacity["id"] if capacity and capacity["delegation_id"] else None
        if doc.get("approval_policy", {}).get("require_comment_on_reject", True) and not comment.strip():
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "A comment is required to reject.",
                               details=[{"field": "comment", "code": "required"}])
        updated = await self.repos.approvals.transition(
            p.tenant_id, approval_id, "PENDING", "REJECTED",
            {"rejection": {"by": p.principal_id, "by_name": p.display_name, "at": utcnow(),
                           "comment": comment.strip()[:2000], "on_behalf_of": on_behalf,
                           "on_behalf_of_name": capacity["name"] if capacity and on_behalf else None}})
        if not updated:
            raise GatewayError(ErrorCode.APPROVAL_STATE_CONFLICT, "Only pending requests can be rejected.")
        await self.repos.invocations.update(p.tenant_id, doc["invocation_id"], {"status": "rejected"})
        await self.audit.record(p.tenant_id, "approval.rejected", principal=p, approval_id=approval_id,
                                invocation_id=doc.get("invocation_id"), decision="DENY",
                                resource={"tool_id": doc["tool_id"], "tool_name": doc["tool_name"]},
                                metadata={"comment": comment.strip()[:2000], "on_behalf_of": on_behalf})
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

    async def escalate_due(self) -> int:
        """Open requests that waited past their escalation point to the escalation roles."""
        now, n = utcnow(), 0
        for d in await self.repos.approvals.due_global("escalate_at", "escalated_at", now):
            doc = await self.repos.approvals.col.find_one_and_update(
                {"_id": d["_id"], "tenant_id": d["tenant_id"], "status": "PENDING", "escalated_at": None},
                {"$set": {"escalated_at": now, "updated_at": now}}, return_document=True)
            if doc:
                n += 1
                await self.audit.record(
                    doc["tenant_id"], "approval.escalated", principal=WORKER, approval_id=doc["_id"],
                    invocation_id=doc.get("invocation_id"), status="pending",
                    resource={"tool_id": doc["tool_id"], "tool_name": doc["tool_name"]},
                    metadata={"escalation_roles": doc.get("approval_policy", {}).get("escalation_roles", []),
                              "approvals": len(doc.get("approvals", [])), "required": doc.get("required_approvals")})
        return n

    async def remind_due(self) -> int:
        """Raise one approval.expiring event per request nearing expiry (SIEM forwarding turns it into an alert)."""
        now, n = utcnow(), 0
        for d in await self.repos.approvals.due_global("remind_at", "reminded_at", now):
            doc = await self.repos.approvals.col.find_one_and_update(
                {"_id": d["_id"], "tenant_id": d["tenant_id"], "status": "PENDING", "reminded_at": None},
                {"$set": {"reminded_at": now}}, return_document=True)
            if doc:
                n += 1
                exp = ensure_aware(doc.get("expires_at"))
                await self.audit.record(
                    doc["tenant_id"], "approval.expiring", principal=WORKER, approval_id=doc["_id"],
                    invocation_id=doc.get("invocation_id"), status="pending",
                    resource={"tool_id": doc["tool_id"], "tool_name": doc["tool_name"]},
                    metadata={"expires_at": exp.isoformat() if exp else None,
                              "approvals": len(doc.get("approvals", [])), "required": doc.get("required_approvals"),
                              "approver_roles": doc.get("approval_policy", {}).get("approver_roles", [])})
        return n

    # ------------------------------------------------------------------ delegations
    async def _active_delegations_to(self, tenant_id: str, user_id: str) -> builtins.list[dict[str, Any]]:
        now = utcnow()
        return await self.repos.delegations.find_all(tenant_id, {
            "delegate_user_id": user_id, "revoked_at": None,
            "starts_at": {"$lte": now}, "ends_at": {"$gt": now}}, limit=50)

    async def create_delegation(self, p: Principal, data: DelegationCreate) -> dict[str, Any]:
        delegator_id = data.delegator_user_id or p.principal_id
        if delegator_id != p.principal_id and not p.has_any_role(*SECURITY):
            raise denied("Only administrators can delegate another user's approval authority.")
        if delegator_id != p.principal_id and data.delegate_user_id == p.principal_id:
            # Otherwise an administrator could collect any approver's authority (and roles or groups they lack).
            raise denied("You can't delegate another user's approval authority to yourself.")
        delegator = await self._identity(p.tenant_id, delegator_id)
        if not delegator or not (delegator["roles"] & APPROVER_ROLES):
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "Only users who can approve requests can delegate.",
                               details=[{"field": "delegator_user_id", "code": "not_an_approver"}])
        if data.delegate_user_id == delegator_id:
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "Choose someone other than the delegator.",
                               details=[{"field": "delegate_user_id", "code": "self"}])
        delegate = await self._identity(p.tenant_id, data.delegate_user_id)
        if not delegate:
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "The delegate must be an active member of this tenant.",
                               details=[{"field": "delegate_user_id", "code": "not_a_member"}])
        now = utcnow()
        starts = max(ensure_aware(data.starts_at) or now, now)
        ends = ensure_aware(data.ends_at) or now
        problems = []
        if ends <= starts:
            problems.append({"field": "ends_at", "code": "not_after_start",
                             "message": "Must be in the future and after the start."})
        if ends - starts > timedelta(days=DELEGATION_MAX_DAYS):
            problems.append({"field": "ends_at", "code": "too_long",
                             "message": f"A delegation can last at most {DELEGATION_MAX_DAYS} days."})
        if starts > now + timedelta(days=365):
            problems.append({"field": "starts_at", "code": "too_far", "message": "Must start within a year."})
        if problems:
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "The delegation period is invalid.", details=problems)
        live = await self.repos.delegations.count(p.tenant_id, {
            "delegator_user_id": delegator_id, "revoked_at": None, "ends_at": {"$gt": now}})
        if live >= MAX_ACTIVE_DELEGATIONS:
            raise GatewayError(ErrorCode.VALIDATION_FAILED,
                               f"At most {MAX_ACTIVE_DELEGATIONS} current delegations per approver. Revoke one first.")
        doc = await self.repos.delegations.insert(p.tenant_id, {
            "delegator_user_id": delegator_id, "delegator_name": delegator["name"],
            "delegate_user_id": delegate["id"], "delegate_name": delegate["name"],
            "starts_at": starts, "ends_at": ends, "reason": data.reason.strip(),
            "created_by": p.principal_id, "revoked_at": None,
        })
        await self.audit.record(p.tenant_id, "approval.delegation.created", principal=p,
                                resource={"delegation_id": doc["_id"]},
                                metadata={"delegator_user_id": delegator_id, "delegate_user_id": delegate["id"],
                                          "starts_at": starts.isoformat(), "ends_at": ends.isoformat(),
                                          "reason": doc["reason"]})
        return doc

    async def revoke_delegation(self, p: Principal, delegation_id: str) -> dict[str, Any]:
        doc = await self.repos.delegations.get(p.tenant_id, delegation_id)
        involved = doc is not None and p.principal_id in (
            doc["delegator_user_id"], doc["delegate_user_id"], doc.get("created_by"))
        if not doc or not (involved or p.has_any_role(*SECURITY)):
            raise not_found("Delegation")
        now = utcnow()
        updated = await self.repos.delegations.col.find_one_and_update(
            {"_id": delegation_id, "tenant_id": p.tenant_id, "revoked_at": None},
            {"$set": {"revoked_at": now, "revoked_by": p.principal_id, "updated_at": now}}, return_document=True)
        if not updated:
            raise GatewayError(ErrorCode.CONFLICT, "The delegation is already revoked.")
        await self.audit.record(p.tenant_id, "approval.delegation.revoked", principal=p,
                                resource={"delegation_id": delegation_id},
                                metadata={"delegator_user_id": doc["delegator_user_id"],
                                          "delegate_user_id": doc["delegate_user_id"]})
        return updated  # type: ignore[no-any-return]

    async def list_delegations(self, p: Principal, *, everyone: bool, include_past: bool) -> builtins.list[dict[str, Any]]:
        if everyone and not p.has_any_role(*SECURITY):
            raise denied("Only administrators can list every delegation.")
        q: dict[str, Any] = {} if everyone else {
            "$or": [{"delegator_user_id": p.principal_id}, {"delegate_user_id": p.principal_id}]}
        if not include_past:
            q.update({"revoked_at": None, "ends_at": {"$gt": utcnow()}})
        docs = await self.repos.delegations.find_all(p.tenant_id, q, limit=500)
        return sorted(docs, key=lambda d: ensure_aware(d["starts_at"]) or utcnow(), reverse=True)

    async def delegate_candidates(self, p: Principal) -> builtins.list[dict[str, Any]]:
        """Active members of the tenant, for the delegate picker (names only)."""
        out = []
        for m in await self.repos.memberships.find_all(p.tenant_id, {"status": "active"}, limit=2000):
            u = await self.repos.users.get(m["user_id"])
            if u and u.get("status") == "active" and u["_id"] != p.principal_id:
                out.append({"id": u["_id"], "username": u["username"],
                            "display_name": u.get("display_name") or u["username"],
                            "can_approve": bool(set(m.get("roles", [])) & APPROVER_ROLES)})
        return sorted(out, key=lambda x: str(x["display_name"]).lower())

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
