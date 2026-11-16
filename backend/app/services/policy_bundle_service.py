"""Policy-as-code: export, plan (validate + diff) and apply of policy bundles (Phase 6).

* Policies are matched to bundle entries by name, within the bundle's scope (tenant or global).
* A policy applied from a bundle is *owned* by it (``managed_by = {"kind": "bundle", "bundle": <name>}``).
  ``prune`` deletes only policies owned by the same bundle and absent from the file; hand-made policies and
  policies of other bundles are never pruned.
* An unowned policy whose name appears in the bundle is *adopted* (shown as such in the plan).
* ``plan`` returns a fingerprint of the exact changes it computed. ``apply`` recomputes the plan and refuses
  with 409 if the fingerprint differs: no surprise changes from drift or a concurrent edit since review.
* Apply is all-or-nothing: if any write fails, the writes already made are reverted from their snapshots.
  Every change is audited individually (``source: bundle``) plus one ``policy.bundle.applied`` event.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import yaml
from pydantic import ValidationError

from app.core.errors import ErrorCode, GatewayError, denied
from app.core.identity import Principal
from app.core.ids import utcnow
from app.core.logging import get_logger
from app.models.policy import Principals, Resources, is_broad
from app.models.policy_bundle import BundlePolicy, PolicyBundle
from app.repositories.collections import Repos
from app.services.audit_service import AuditService

log = get_logger(__name__)
FIELDS = ("description", "effect", "principals", "resources", "actions", "constraints", "priority", "enabled")


def parse_bundle(content: str) -> PolicyBundle:
    """YAML (a superset of JSON). Errors are reported as VALIDATION_FAILED with field paths."""
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise GatewayError(ErrorCode.VALIDATION_FAILED, f"The bundle is not valid YAML{where}.") from exc
    if not isinstance(data, dict):
        raise GatewayError(ErrorCode.VALIDATION_FAILED, "The bundle must be a mapping with apiVersion, kind, "
                                                        "metadata and policies.")
    try:
        return PolicyBundle.model_validate(data)
    except ValidationError as exc:
        details = [{"field": ".".join(str(x) for x in e["loc"]), "code": e["type"], "message": e["msg"]}
                   for e in exc.errors()[:50]]
        raise GatewayError(ErrorCode.VALIDATION_FAILED, "The bundle is invalid.", details=details) from exc


def _desired(p: BundlePolicy) -> dict[str, Any]:
    return p.model_dump(include=set(FIELDS))


def _current(doc: dict[str, Any]) -> dict[str, Any]:
    """Normalise a stored policy through the same models so that defaults don't show up as differences."""
    try:
        bp = BundlePolicy.model_validate({**{k: doc.get(k) for k in FIELDS if doc.get(k) is not None},
                                          "name": doc["name"]})
        return _desired(bp)
    except ValidationError:
        return {k: doc.get(k) for k in FIELDS}


def _diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    return {k: {"from": before.get(k), "to": after.get(k)} for k in FIELDS if before.get(k) != after.get(k)}


class PolicyBundleService:
    def __init__(self, repos: Repos, audit: AuditService) -> None:
        self.repos = repos
        self.audit = audit

    def _scope_tenant(self, p: Principal, scope: str) -> str:
        if scope == "global":
            if not p.is_global_admin:
                raise denied("Only platform administrators can manage global policies.")
            return "*"
        return p.tenant_id

    # ------------------------------------------------------------------ export
    async def export(self, p: Principal, *, scope: str, bundle: str, include: str) -> str:
        tenant_id = self._scope_tenant(p, scope)
        query: dict[str, Any] = {"system": {"$ne": True}, "kind": {"$ne": "default_deny"}}
        if include == "bundle":
            query["managed_by.bundle"] = bundle
        docs = sorted(await self.repos.policies.find_all(tenant_id, query), key=lambda d: (d.get("priority", 100),
                                                                                          d["name"]))
        policies = []
        for d in docs:
            entry: dict[str, Any] = {"name": d["name"], **_current(d)}
            if d.get("broad"):
                entry["confirm_broad_grant"] = True
            policies.append(entry)
        doc = {"apiVersion": "mcp-gateway/v1", "kind": "PolicyBundle",
               "metadata": {"name": bundle, "scope": scope}, "policies": policies}
        await self.audit.record(p.tenant_id, "policy.bundle.exported", principal=p,
                                metadata={"bundle": bundle, "scope": scope, "policies": len(policies)})
        return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False)

    # ------------------------------------------------------------------ plan
    async def plan(self, p: Principal, content: str, *, prune: bool = False) -> dict[str, Any]:
        bundle = parse_bundle(content)
        tenant_id = self._scope_tenant(p, bundle.metadata.scope)
        name = bundle.metadata.name
        existing = await self.repos.policies.find_all(tenant_id, {"kind": {"$ne": "default_deny"}})
        by_name: dict[str, list[dict[str, Any]]] = {}
        for d in existing:
            by_name.setdefault(d["name"].lower(), []).append(d)

        changes: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        warnings: list[dict[str, Any]] = []
        wanted = set()
        for bp in bundle.policies:
            wanted.add(bp.name.lower())
            desired = _desired(bp)
            broad = is_broad(Principals(**desired["principals"]), Resources(**desired["resources"]))
            if bp.effect == "allow" and broad and not bp.confirm_broad_grant:
                errors.append({"policy": bp.name, "code": "BROAD_GRANT_CONFIRMATION_REQUIRED",
                               "message": f"Grants wildcard access ({', '.join(broad)}); add confirm_broad_grant: true"})
            matches = by_name.get(bp.name.lower(), [])
            if len(matches) > 1:
                errors.append({"policy": bp.name, "code": "AMBIGUOUS_NAME",
                               "message": "Several existing policies have this name; rename them first"})
                continue
            cur = matches[0] if matches else None
            if cur is not None and cur.get("system"):
                errors.append({"policy": bp.name, "code": "SYSTEM_POLICY", "message": "System policies cannot be managed"})
                continue
            owner = (cur or {}).get("managed_by", {}) or {}
            if cur is None:
                changes.append({"action": "create", "name": bp.name, "policy_id": None, "broad": broad,
                                "diff": _diff({}, desired), "desired": desired})
            elif owner.get("bundle") not in (None, name):
                errors.append({"policy": bp.name, "code": "OWNED_BY_OTHER_BUNDLE",
                               "message": f"Owned by bundle {owner.get('bundle')!r}"})
            else:
                diff = _diff(_current(cur), desired)
                action = "adopt" if owner.get("bundle") != name else ("update" if diff else "unchanged")
                changes.append({"action": action, "name": bp.name, "policy_id": cur["_id"], "broad": broad,
                                "diff": diff, "desired": desired, "version": cur.get("version", 1)})
        for d in existing:
            owned = (d.get("managed_by") or {}).get("bundle") == name
            if owned and d["name"].lower() not in wanted:
                changes.append({"action": "delete" if prune else "orphan", "name": d["name"], "policy_id": d["_id"],
                                "diff": {}, "version": d.get("version", 1)})
        warnings += await self._reference_warnings(tenant_id if tenant_id != "*" else p.tenant_id, bundle)

        effective = [c for c in changes if c["action"] not in ("unchanged", "orphan")]
        fingerprint = hashlib.sha256(json.dumps(
            {"bundle": name, "scope": bundle.metadata.scope, "tenant": tenant_id, "prune": prune,
             "changes": [{k: c.get(k) for k in ("action", "name", "policy_id", "version", "desired")}
                         for c in sorted(effective, key=lambda c: c["name"].lower())]},
            sort_keys=True, default=str).encode()).hexdigest()
        summary = {a: sum(1 for c in changes if c["action"] == a)
                   for a in ("create", "update", "adopt", "delete", "unchanged", "orphan")}
        return {"bundle": name, "scope": bundle.metadata.scope, "tenant_id": tenant_id, "prune": prune,
                "valid": not errors, "errors": errors, "warnings": warnings, "summary": summary,
                "changes": [{k: v for k, v in c.items() if k != "desired"} for c in changes],
                "fingerprint": fingerprint, "_changes": effective, "_bundle": bundle}

    async def _reference_warnings(self, tenant_id: str, bundle: PolicyBundle) -> list[dict[str, Any]]:
        """Exact (non-wildcard) names that don't exist yet. Warnings, not errors: a server may be registered
        after its policy, and the engine simply won't match until then."""
        servers: set[str] = set()
        for s in await self.repos.servers.find_all(tenant_id, {}):
            servers |= {str(v) for v in (s.get("alias"), s.get("name"), s["_id"]) if v}
        tools: set[str] = set()
        for t in await self.repos.tools.find_all(tenant_id, {"archived": {"$ne": True}}):
            tools |= {str(v) for v in (t.get("upstream_name"), t.get("gateway_name"), t["_id"]) if v}
        agents = {a["_id"] for a in await self.repos.agents.find_all(tenant_id, {})}
        out = []
        for bp in bundle.policies:
            for kind, values, known in (("server", bp.resources.servers, servers), ("tool", bp.resources.tools, tools),
                                        ("agent", [i for i in bp.principals.ids if i.startswith("agt_")], agents)):
                for v in values:
                    if "*" not in v and v not in known:
                        out.append({"policy": bp.name, "code": f"UNKNOWN_{kind.upper()}",
                                    "message": f"No {kind} named {v!r} in this tenant (yet)"})
        return out[:200]

    @staticmethod
    def public_plan(plan: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in plan.items() if not k.startswith("_")}

    # ------------------------------------------------------------------ apply
    async def apply(self, p: Principal, content: str, *, expected_fingerprint: str, prune: bool) -> dict[str, Any]:
        plan = await self.plan(p, content, prune=prune)
        if not plan["valid"]:
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "The bundle has errors; run plan to see them.",
                               details=[{"field": e["policy"], "code": e["code"], "message": e["message"]}
                                        for e in plan["errors"]])
        if plan["fingerprint"] != expected_fingerprint:
            raise GatewayError(ErrorCode.VERSION_CONFLICT,
                               "Policies changed since this plan was made. Run plan again and review the new diff.",
                               extra={"fingerprint": plan["fingerprint"]})
        tenant_id, name = plan["tenant_id"], plan["bundle"]
        owner = {"kind": "bundle", "bundle": name}
        undo: list[tuple[str, Any]] = []  # ("delete", id) | ("restore", original document)
        events: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        try:
            for c in plan["_changes"]:
                d = c.get("desired") or {}
                broad = c.get("broad") or []
                if c["action"] == "create":
                    doc = await self.repos.policies.insert(tenant_id, {
                        **d, "name": c["name"], "kind": "standard", "broad": broad, "managed_by": owner,
                        "created_by": p.principal_id, "updated_by": p.principal_id})
                    undo.append(("delete", doc["_id"]))
                    events.append(("policy.created", doc, {}))
                elif c["action"] in ("update", "adopt"):
                    original = await self.repos.policies.get(tenant_id, c["policy_id"])
                    doc = await self.repos.policies.update(tenant_id, c["policy_id"], {
                        **d, "broad": broad, "managed_by": owner, "updated_by": p.principal_id},
                        expected_version=c["version"])
                    undo.append(("restore", original))
                    events.append(("policy.changed", doc, {"changed_fields": sorted(c["diff"]),
                                                           "adopted": c["action"] == "adopt"}))
                elif c["action"] == "delete":
                    original = await self.repos.policies.get(tenant_id, c["policy_id"])
                    if original is None or original.get("version", 1) != c["version"]:
                        raise GatewayError(ErrorCode.VERSION_CONFLICT, f"Policy {c['name']} changed during apply.")
                    await self.repos.policies.delete(tenant_id, c["policy_id"])
                    undo.append(("restore", original))
                    events.append(("policy.deleted", original, {}))
        except Exception as exc:
            await self._rollback(tenant_id, undo)
            await self.audit.record(p.tenant_id, "policy.bundle.rolled_back", principal=p, severity="high",
                                    status="failure", metadata={"bundle": name, "error": type(exc).__name__,
                                                                "reverted": len(undo)})
            if isinstance(exc, GatewayError):
                raise
            raise GatewayError(ErrorCode.GATEWAY_INTERNAL_ERROR, "Apply failed; all changes were reverted.") from exc

        for event_type, doc, extra in events:
            await self.audit.record(p.tenant_id, event_type, principal=p,
                                    resource={"policy_id": doc["_id"], "policy_name": doc["name"]},
                                    metadata={"source": "bundle", "bundle": name, "snapshot": _snapshot(doc), **extra})
        await self.audit.record(p.tenant_id, "policy.bundle.applied", principal=p, severity="high",
                                metadata={"bundle": name, "scope": plan["scope"], "fingerprint": plan["fingerprint"],
                                          "summary": plan["summary"], "prune": prune})
        return {**self.public_plan(plan), "applied": True, "applied_at": utcnow().isoformat()}

    async def _rollback(self, tenant_id: str, undo: list[tuple[str, Any]]) -> None:
        for op, value in reversed(undo):
            try:
                if op == "delete":
                    await self.repos.policies.col.delete_one({"_id": value, "tenant_id": tenant_id})
                else:
                    await self.repos.policies.col.replace_one({"_id": value["_id"]}, value, upsert=True)
            except Exception as exc:  # noqa: BLE001 - keep reverting the rest; the failure is logged
                log.error("policy.bundle.rollback_failed", op=op, error=type(exc).__name__)


def _snapshot(doc: dict[str, Any]) -> dict[str, Any]:
    return {k: doc.get(k) for k in ("name", *FIELDS, "version")}
