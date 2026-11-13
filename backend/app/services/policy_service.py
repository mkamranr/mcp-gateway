"""Policy Decision Point and policy administration (spec §8).

Evaluation is default-deny, and an explicit deny always overrides an allow. If anything goes
wrong during evaluation, the result is DENY: the engine fails closed.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from app.core.errors import ErrorCode, GatewayError, denied, not_found
from app.core.identity import Principal, Role
from app.core.ids import utcnow
from app.core.logging import get_logger
from app.models.policy import PolicyCreate, PolicyUpdate, Principals, Resources, is_broad
from app.repositories.collections import Repos
from app.services.audit_service import AuditService

log = get_logger(__name__)
Decision = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]


@dataclass
class PolicyDecision:
    decision: Decision
    reason_code: str
    policy_ids: list[str] = field(default_factory=list)
    obligations: dict[str, Any] = field(default_factory=dict)
    explanation: list[dict[str, Any]] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        """Safe for agents: no policy internals."""
        return {"decision": self.decision, "reason_code": self.reason_code}

    def admin(self) -> dict[str, Any]:
        return {"decision": self.decision, "reason_code": self.reason_code, "policy_ids": self.policy_ids,
                "obligations": self.obligations, "explanation": self.explanation}


@dataclass
class RequestContext:
    principal: Principal
    action: str
    server: dict[str, Any]
    tool: dict[str, Any]
    environment: str | None = None
    source_ip: str | None = None
    now: datetime | None = None
    critical_requires_approval: bool = True


def _match_any(patterns: list[str], *values: str | None) -> bool:
    vals = [v for v in values if v]
    for p in patterns:
        if p == "*":
            return True
        for v in vals:
            if ("*" in p and fnmatch.fnmatchcase(v, p)) or p == v:
                return True
    return False


def _match_reason(policy: dict[str, Any], ctx: RequestContext) -> str | None:
    """Return None if the policy applies to the request, otherwise the reason it does not."""
    p = ctx.principal
    pr = policy.get("principals", {})
    types = pr.get("types", [])
    if "*" not in types and p.principal_type not in types:
        return "principal_type"
    ids, roles = pr.get("ids", []), pr.get("roles", [])
    if ids or roles:
        id_ok = bool(ids) and _match_any(ids, p.principal_id, p.agent_id)
        role_ok = bool(roles) and any(r in p.roles for r in roles)
        if not (id_ok or role_ok):
            return "principal"
    if ctx.action not in policy.get("actions", []):
        return "action"
    res = policy.get("resources", {})
    srv, tool = ctx.server, ctx.tool
    if not _match_any(res.get("servers", []), srv.get("alias"), srv.get("_id"), srv.get("name")):
        return "server"
    if not _match_any(res.get("tools", []), tool.get("upstream_name"), tool.get("gateway_name"), tool.get("_id")):
        return "tool"
    risks = res.get("risk_levels") or []
    if risks and tool.get("risk_level") not in risks:
        return "risk_level"
    c = policy.get("constraints", {}) or {}
    envs = c.get("environments") or []
    if envs and (ctx.environment or srv.get("environment")) not in envs:
        return "environment"
    if c.get("source_cidrs"):
        if not ctx.source_ip:
            return "source_network"
        try:
            ip = ipaddress.ip_address(ctx.source_ip)
        except ValueError:
            return "source_network"
        if not any(ip in ipaddress.ip_network(n, strict=False) for n in c["source_cidrs"]):
            return "source_network"
    if c.get("time_windows"):
        now = ctx.now or utcnow()
        hhmm = now.strftime("%H:%M")
        if not any(now.weekday() in w["days"] and w["start"] <= hhmm <= w["end"] for w in c["time_windows"]):
            return "time_window"
    return None


def evaluate(policies: list[dict[str, Any]], ctx: RequestContext) -> PolicyDecision:
    """Pure policy evaluation. Never raises: any error results in DENY."""
    try:
        return _evaluate(policies, ctx)
    except Exception as exc:  # noqa: BLE001
        log.error("policy.evaluation_error", error=type(exc).__name__)
        return PolicyDecision("DENY", "POLICY_ENGINE_ERROR")


def _evaluate(policies: list[dict[str, Any]], ctx: RequestContext) -> PolicyDecision:
    explanation: list[dict[str, Any]] = []
    denies: list[dict[str, Any]] = []
    allows: list[dict[str, Any]] = []
    default = None
    for pol in sorted(policies, key=lambda x: (x.get("priority", 100), x["_id"])):
        if not pol.get("enabled"):
            continue
        if pol.get("kind") == "default_deny":
            default = pol
            continue
        reason = _match_reason(pol, ctx)
        explanation.append({"policy_id": pol["_id"], "name": pol["name"], "effect": pol["effect"],
                            "matched": reason is None, "not_matched_on": reason})
        if reason is None:
            (denies if pol["effect"] == "deny" else allows).append(pol)

    if denies:
        return PolicyDecision("DENY", "EXPLICIT_DENY", [d["_id"] for d in denies], {}, explanation)
    if not allows:
        ids = [default["_id"]] if default else []
        return PolicyDecision("DENY", "NO_MATCHING_ALLOW", ids, {}, explanation)

    obligations: dict[str, Any] = {}
    for key, name in (("per_minute", "max_calls_per_minute"), ("per_hour", "max_calls_per_hour"),
                      ("per_day", "max_calls_per_day")):
        values = [a["constraints"][name] for a in allows if (a.get("constraints") or {}).get(name)]
        if values:
            obligations.setdefault("limits", {})[key] = min(values)

    if ctx.action == "discover":
        return PolicyDecision("ALLOW", "ALLOWED", [a["_id"] for a in allows], obligations, explanation)

    tool = ctx.tool
    tool_approval = tool.get("approval") or {}
    approval_reasons = []
    if tool_approval.get("required"):
        approval_reasons.append("tool")
    if ctx.critical_requires_approval and tool.get("risk_level") == "critical":
        approval_reasons.append("critical_risk")
    requiring = [a for a in allows if (a.get("constraints") or {}).get("require_approval")]
    if requiring:
        approval_reasons.append("policy")
    if approval_reasons:
        base = dict(tool_approval.get("policy") or {})
        required = max([int(base.get("required_approvals", 1))] + [
            int(a["constraints"].get("required_approvals") or 1) for a in requiring])
        roles = base.get("approver_roles") or [Role.APPROVER.value, Role.SECURITY_ADMIN.value, Role.TENANT_ADMIN.value]
        for a in requiring:
            if a["constraints"].get("approver_roles"):
                roles = [r for r in roles if r in a["constraints"]["approver_roles"]] or a["constraints"]["approver_roles"]
        obligations["approval"] = {
            "required_approvals": required,
            "approver_roles": roles,
            "allow_self_approval": bool(base.get("allow_self_approval", False)) and not requiring,
            "ttl_minutes": int(base.get("ttl_minutes", 60)),
            "require_comment_on_reject": bool(base.get("require_comment_on_reject", True)),
            "require_comment_on_approve": bool(base.get("require_comment_on_approve", False)),
            "approval_policy_id": next((a["constraints"].get("approval_policy_id") for a in requiring
                                        if a["constraints"].get("approval_policy_id")), None),
            "reasons": approval_reasons,
        }
        policy_ids = [a["_id"] for a in (requiring or allows)]
        return PolicyDecision("REQUIRE_APPROVAL", "SENSITIVE_TOOL_REQUIRES_APPROVAL", policy_ids, obligations,
                              explanation)
    return PolicyDecision("ALLOW", "ALLOWED", [a["_id"] for a in allows], obligations, explanation)


class PolicyService:
    def __init__(self, repos: Repos, audit: AuditService) -> None:
        self.repos = repos
        self.audit = audit

    async def decide(self, ctx: RequestContext) -> PolicyDecision:
        try:
            policies = await self.repos.policies.enabled_for_tenant(ctx.principal.tenant_id)
        except Exception as exc:  # noqa: BLE001
            log.error("policy.load_failed", error=type(exc).__name__)
            return PolicyDecision("DENY", "POLICY_ENGINE_UNAVAILABLE")
        return evaluate(policies, ctx)

    # ------------------------------------------------------------------ administration
    def _scope_tenant(self, p: Principal, scope: str) -> str:
        if scope == "global":
            if not p.is_global_admin:
                raise denied("Only platform administrators can manage global policies.")
            return "*"
        return p.tenant_id

    async def _get_editable(self, p: Principal, policy_id: str) -> dict[str, Any]:
        doc = await self.repos.policies.get(p.tenant_id, policy_id)
        if doc is None:
            doc = await self.repos.policies.get("*", policy_id)
            if doc is None:
                raise not_found("Policy")
            if not p.is_global_admin:
                raise denied("Tenant administrators cannot edit global policies.")
        if doc.get("system"):
            raise GatewayError(ErrorCode.CONFLICT, "System policies cannot be modified.")
        return doc

    async def get(self, p: Principal, policy_id: str) -> dict[str, Any]:
        doc = await self.repos.policies.get(p.tenant_id, policy_id) or await self.repos.policies.get("*", policy_id)
        if not doc:
            raise not_found("Policy")
        return doc

    async def list_policies(self, p: Principal, **kw: Any) -> Any:
        return await self.repos.policies._paginate(
            {"tenant_id": {"$in": [p.tenant_id, "*"]}}, sort=[("priority", 1), ("name", 1)], **kw
        )

    @staticmethod
    def _check_broad(principals: Principals, resources: Resources, effect: str, confirmed: bool) -> list[str]:
        reasons = is_broad(principals, resources)
        if effect == "allow" and reasons and not confirmed:
            raise GatewayError(
                ErrorCode.BROAD_GRANT_CONFIRMATION_REQUIRED,
                "This policy grants broad or wildcard access. Set confirm_broad_grant to proceed.",
                details=[{"field": r, "code": "wildcard"} for r in reasons],
            )
        return reasons

    async def create(self, p: Principal, data: PolicyCreate) -> dict[str, Any]:
        tenant_id = self._scope_tenant(p, data.scope)
        broad = self._check_broad(data.principals, data.resources, data.effect, data.confirm_broad_grant)
        body = data.model_dump(exclude={"scope", "confirm_broad_grant"})
        doc = await self.repos.policies.insert(tenant_id, {**body, "kind": "standard", "broad": broad,
                                                          "created_by": p.principal_id, "updated_by": p.principal_id})
        await self.audit.record(p.tenant_id, "policy.created", principal=p,
                                resource={"policy_id": doc["_id"], "policy_name": data.name},
                                metadata={"snapshot": _snapshot(doc), "broad": broad, "scope": data.scope})
        return doc

    async def update(self, p: Principal, policy_id: str, data: PolicyUpdate) -> dict[str, Any]:
        current = await self._get_editable(p, policy_id)
        changes = data.model_dump(exclude_unset=True, exclude={"version", "confirm_broad_grant"})
        principals = data.principals or Principals(**current["principals"])
        resources = data.resources or Resources(**current["resources"])
        effect = changes.get("effect", current["effect"])
        if data.constraints is not None:
            changes["constraints"] = data.constraints.model_dump()
            if effect == "deny" and data.constraints.require_approval:
                raise GatewayError(ErrorCode.VALIDATION_FAILED, "Deny policies cannot require approval.")
        if data.principals is not None:
            changes["principals"] = data.principals.model_dump()
        if data.resources is not None:
            changes["resources"] = data.resources.model_dump()
        widening = data.principals is not None or data.resources is not None or "effect" in changes
        broad = is_broad(principals, resources)
        if widening:
            broad = self._check_broad(principals, resources, effect, data.confirm_broad_grant)
        changes["broad"] = broad
        changes["updated_by"] = p.principal_id
        doc = await self.repos.policies.update(current["tenant_id"], policy_id, changes, expected_version=data.version)
        await self.audit.record(p.tenant_id, "policy.changed", principal=p,
                                resource={"policy_id": policy_id, "policy_name": doc["name"]},
                                metadata={"changed_fields": sorted(set(changes) - {"updated_by", "broad"}),
                                          "snapshot": _snapshot(doc), "previous": _snapshot(current)})
        return doc

    async def set_enabled(self, p: Principal, policy_id: str, enabled: bool) -> dict[str, Any]:
        current = await self._get_editable(p, policy_id)
        doc = await self.repos.policies.update(current["tenant_id"], policy_id,
                                               {"enabled": enabled, "updated_by": p.principal_id})
        await self.audit.record(p.tenant_id, "policy.enabled" if enabled else "policy.disabled", principal=p,
                                resource={"policy_id": policy_id, "policy_name": doc["name"]},
                                metadata={"snapshot": _snapshot(doc)})
        return doc

    async def clone(self, p: Principal, policy_id: str) -> dict[str, Any]:
        src = await self.get(p, policy_id)
        if src.get("system"):
            raise GatewayError(ErrorCode.CONFLICT, "System policies cannot be cloned.")
        base_name = f"{src['name']} copy"[:90]
        name = base_name
        n = 2
        while await self.repos.policies.find_one(p.tenant_id, {"name": name}):
            name = f"{base_name} {n}"
            n += 1
        body = {k: src[k] for k in ("description", "effect", "principals", "resources", "actions", "constraints",
                                    "priority", "broad")}
        doc = await self.repos.policies.insert(p.tenant_id, {**body, "name": name, "enabled": False,
                                                            "kind": "standard", "created_by": p.principal_id,
                                                            "updated_by": p.principal_id, "cloned_from": policy_id})
        await self.audit.record(p.tenant_id, "policy.created", principal=p,
                                resource={"policy_id": doc["_id"], "policy_name": name},
                                metadata={"cloned_from": policy_id, "snapshot": _snapshot(doc)})
        return doc

    async def delete(self, p: Principal, policy_id: str) -> None:
        current = await self._get_editable(p, policy_id)
        await self.repos.policies.delete(current["tenant_id"], policy_id)
        await self.audit.record(p.tenant_id, "policy.deleted", principal=p,
                                resource={"policy_id": policy_id, "policy_name": current["name"]},
                                metadata={"snapshot": _snapshot(current)})

    async def history(self, p: Principal, policy_id: str) -> list[dict[str, Any]]:
        page = await self.repos.audit.search(p.tenant_id, {"resource.policy_id": policy_id}, limit=100)
        return [{"event_id": e["event_id"], "event_type": e["event_type"], "timestamp": e["timestamp"],
                 "principal": e.get("principal"), "snapshot": (e.get("metadata") or {}).get("snapshot"),
                 "changed_fields": (e.get("metadata") or {}).get("changed_fields")} for e in page["items"]]


def _snapshot(doc: dict[str, Any]) -> dict[str, Any]:
    return {k: doc.get(k) for k in ("name", "description", "effect", "principals", "resources", "actions",
                                    "constraints", "priority", "enabled", "version")}
