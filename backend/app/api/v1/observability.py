"""Audit, usage, overview, metrics, settings and the REST invocation endpoint (spec §15, §16.6)."""

from __future__ import annotations

import csv
import io
import json
import re
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse, Response
from pydantic import Field

from app.api.deps import client_ip, get_container, page_params, require_agent, require_user
from app.container import Container
from app.core.errors import ErrorCode, GatewayError, not_found
from app.core.identity import AUDIT_READ, Principal
from app.core.ids import utcnow
from app.db import redis_ping
from app.models.registry import Strict
from app.services.invocation_service import InvocationContext
from app.workers.heartbeat import HEARTBEAT_FRESH_SECONDS, HEARTBEAT_KEY

router = APIRouter(tags=["audit & usage"])


def _clean(doc: dict[str, Any]) -> dict[str, Any]:
    return {**{k: v for k, v in doc.items() if k != "_id"}, "id": doc["_id"]}


def _audit_query(params: dict[str, Any]) -> dict[str, Any]:
    q: dict[str, Any] = {}
    if params.get("start") or params.get("end"):
        q["timestamp"] = {}
        if params.get("start"):
            q["timestamp"]["$gte"] = params["start"]
        if params.get("end"):
            q["timestamp"]["$lte"] = params["end"]
    for field, key in (("event_type", "event_type"), ("decision", "decision"), ("status", "status"),
                       ("request_id", "request_id"), ("invocation_id", "invocation_id"),
                       ("approval_id", "approval_id"), ("server_id", "resource.server_id"),
                       ("tool_id", "resource.tool_id")):
        if params.get(field):
            if field == "event_type" and params[field].endswith("*"):
                q[key] = {"$regex": "^" + re.escape(params[field][:-1])}
            else:
                q[key] = params[field]
    if params.get("principal"):
        q["$or"] = [{"principal.id": params["principal"]}, {"principal.name": params["principal"]}]
    if params.get("tool"):
        rx = {"$regex": re.escape(params["tool"]), "$options": "i"}
        q.setdefault("$and", []).append({"$or": [{"resource.tool_name": rx}, {"resource.gateway_name": rx}]})
    if params.get("severity"):
        q["severity"] = params["severity"]
    return q


def _audit_params(start: datetime | None = None, end: datetime | None = None, event_type: str | None = None,
                  decision: str | None = None, status: str | None = None, request_id: str | None = None,
                  invocation_id: str | None = None, approval_id: str | None = None, server_id: str | None = None,
                  tool_id: str | None = None, principal: str | None = None, tool: str | None = None,
                  severity: str | None = None, tenant: str | None = None) -> dict[str, Any]:
    return {k: v for k, v in locals().items() if v is not None}


async def _audit_cross_tenant(c: Container, p: Principal, target: str, what: dict[str, Any]) -> None:
    """A platform administrator reading another tenant's audit trail (or all of them) leaves a trace: in the
    target tenant (so its own auditors see it) or, for a search across all tenants, in the administrator's."""
    await c.audit.record(p.tenant_id if target == "*" else target, "audit.searched.cross_tenant", principal=p,
                         severity="high", required=True,
                         metadata={"target_tenant": target, **{k: str(v)[:200] for k, v in what.items()}})


async def _search(c: Container, p: Principal, params: dict[str, Any], **page: Any) -> Any:
    q = _audit_query(params)
    tenant = params.get("tenant")
    if tenant and tenant != p.tenant_id:
        if not p.is_global_admin:
            raise not_found("Tenant")
        if tenant != "*" and not await c.repos.tenants.get(tenant):
            raise not_found("Tenant")
        # Only the first page is recorded: paging through one search is one search.
        if not page.get("cursor"):
            await _audit_cross_tenant(c, p, tenant, {k: v for k, v in params.items() if k != "tenant"})
        if tenant == "*":
            return await c.repos.audit.search_global(q, **page)
        return await c.repos.audit.search(tenant, q, **page)
    return await c.repos.audit.search(p.tenant_id, q, **page)


@router.get("/audit/events")
async def audit_events(params: dict[str, Any] = Depends(_audit_params), page: dict[str, Any] = Depends(page_params),
                       p: Principal = Depends(require_user(*AUDIT_READ)), c: Container = Depends(get_container)) -> dict[str, Any]:
    res = await _search(c, p, params, **page)
    return {**res, "items": [_clean(e) for e in res["items"]]}


@router.get("/audit/events/{event_id}")
async def audit_event(event_id: str, p: Principal = Depends(require_user(*AUDIT_READ)),
                      c: Container = Depends(get_container)) -> dict[str, Any]:
    e = await c.repos.audit.get(p.tenant_id, event_id)
    if not e and p.is_global_admin:
        e = await c.repos.audit.col.find_one({"_id": event_id})
        if e:
            await _audit_cross_tenant(c, p, e["tenant_id"], {"event_id": event_id})
    if not e:
        raise not_found("Audit event")
    correlated: list[dict[str, Any]] = []
    keys = [{"invocation_id": e["invocation_id"]}] if e.get("invocation_id") else []
    if e.get("approval_id"):
        keys.append({"approval_id": e["approval_id"]})
    if e.get("request_id"):
        keys.append({"request_id": e["request_id"]})
    if keys:
        res = await c.repos.audit.search(e["tenant_id"], {"$or": keys, "_id": {"$ne": event_id}}, limit=100)
        correlated = sorted((_clean(x) for x in res["items"]), key=lambda x: x["timestamp"])
    approval = None
    if e.get("approval_id"):
        a = await c.repos.approvals.get(e["tenant_id"], e["approval_id"])
        if a:
            approval = {"id": a["_id"], "status": a["status"], "approvals": a.get("approvals", []),
                        "rejection": a.get("rejection"), "expires_at": a.get("expires_at")}
    return {**_clean(e), "correlated": correlated, "approval": approval}


class ExportFilters(Strict):
    """The same filters as the search endpoint, as plain values: an object here (a MongoDB operator such as
    {"$regex": ...} or {"$ne": null}) is rejected rather than passed into the query."""

    start: datetime | None = None
    end: datetime | None = None
    event_type: str | None = Field(default=None, max_length=200)
    decision: str | None = Field(default=None, max_length=100)
    status: str | None = Field(default=None, max_length=100)
    request_id: str | None = Field(default=None, max_length=100)
    invocation_id: str | None = Field(default=None, max_length=100)
    approval_id: str | None = Field(default=None, max_length=100)
    server_id: str | None = Field(default=None, max_length=100)
    tool_id: str | None = Field(default=None, max_length=100)
    principal: str | None = Field(default=None, max_length=200)
    tool: str | None = Field(default=None, max_length=200)
    severity: str | None = Field(default=None, max_length=50)
    tenant: str | None = Field(default=None, max_length=100)  # accepted for symmetry; exports are own-tenant only


class ExportRequest(Strict):
    format: str = Field(default="json", pattern="^(json|csv)$")
    filters: ExportFilters = Field(default_factory=ExportFilters)
    max_rows: int = Field(default=10_000, ge=1, le=100_000)


EXPORT_COLUMNS = ["timestamp", "event_type", "severity", "principal.type", "principal.id", "principal.name",
                  "resource.server_id", "resource.tool_name", "decision", "reason_code", "status", "duration_ms",
                  "request_id", "invocation_id", "approval_id", "input_hash", "output_hash", "event_id"]


def _get(d: dict[str, Any], path: str) -> Any:
    for part in path.split("."):
        d = d.get(part) if isinstance(d, dict) else None  # type: ignore[assignment]
    return d


@router.post("/audit/export")
async def audit_export(body: ExportRequest, p: Principal = Depends(require_user(*AUDIT_READ)),
                       c: Container = Depends(get_container)) -> Response:
    allowed = {k: v for k, v in body.filters.model_dump(exclude={"tenant"}).items() if v not in (None, "")}
    limit = min(body.max_rows, c.settings.audit_export_max_rows)
    q = _audit_query(allowed)
    total = await c.repos.audit.count(p.tenant_id, q)
    if total > limit:
        raise GatewayError(ErrorCode.VALIDATION_FAILED,
                           f"The export would contain {total} events; narrow the filters (limit {limit}).")
    rows = [e async for e in c.repos.audit.col.find({**q, "tenant_id": p.tenant_id}).sort("timestamp", -1).limit(limit)]
    # The export itself is audited before data is released (spec §15.3).
    await c.audit.record(p.tenant_id, "audit.exported", principal=p, severity="high", required=True,
                         metadata={"format": body.format, "rows": len(rows), "filters": {k: str(v) for k, v in allowed.items()}})
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    if body.format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(EXPORT_COLUMNS)
        for e in rows:
            w.writerow(["" if _get(e, col) is None else _sanitize_csv(str(_get(e, col))) for col in EXPORT_COLUMNS])
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="audit-{stamp}.csv"'})
    data = json.dumps([_clean(e) for e in rows], default=str, indent=1)
    return Response(data, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="audit-{stamp}.json"'})


def _sanitize_csv(value: str) -> str:
    """Prevent CSV formula injection when exports are opened in spreadsheets."""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


@router.get("/invocations")
async def invocations(principal: str | None = None, tool_id: str | None = None, status: str | None = None,
                      page: dict[str, Any] = Depends(page_params), p: Principal = Depends(require_user(*AUDIT_READ)),
                      c: Container = Depends(get_container)) -> dict[str, Any]:
    q: dict[str, Any] = {}
    if principal:
        q["principal.id"] = principal
    if tool_id:
        q["tool_id"] = tool_id
    if status:
        q["status"] = status
    res = await c.repos.invocations.list(p.tenant_id, q, **page)
    return {**res, "items": [_clean(i) for i in res["items"]]}


@router.get("/usage/summary")
async def usage_summary(days: int = 7, p: Principal = Depends(require_user()),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    days = max(1, min(days, 90))
    tenant = await c.repos.tenants.get(p.tenant_id) or {}
    return {**await c.usage.summary(p.tenant_id, days),
            "quotas": await c.quotas.usage_snapshot(p.tenant_id, tenant.get("settings", {})),
            "in_flight": await c.quotas.in_flight(p.tenant_id),
            "limits": {"max_concurrent_calls_per_agent": c.settings.max_concurrent_calls_per_agent}}


@router.get("/usage/by-tool")
async def usage_by_tool(days: int = 7, p: Principal = Depends(require_user()),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    return {"items": await c.usage.by_tool(p.tenant_id, max(1, min(days, 90)))}


@router.get("/usage/by-agent")
async def usage_by_agent(days: int = 7, p: Principal = Depends(require_user()),
                         c: Container = Depends(get_container)) -> dict[str, Any]:
    return {"items": await c.usage.by_agent(p.tenant_id, max(1, min(days, 90)))}


@router.get("/overview")
async def overview(p: Principal = Depends(require_user()), c: Container = Depends(get_container)) -> dict[str, Any]:
    data = await c.usage.overview(p.tenant_id)
    data["health"] = await _health_components(c)
    data["approvals"] = await c.approvals.counts(p.tenant_id)
    return data


async def _health_components(c: Container) -> list[dict[str, Any]]:
    mongo = await c.db.ping()
    redis = await redis_ping(c.redis)
    worker_beat: str | None = None
    workers_alive = 0
    try:
        beats = await c.redis.zrangebyscore(HEARTBEAT_KEY, time.time() - HEARTBEAT_FRESH_SECONDS, "+inf",
                                            withscores=True)
        workers_alive = len(beats)
        if beats:
            worker_beat = datetime.fromtimestamp(max(float(b[1]) for b in beats), tz=UTC).isoformat()
    except Exception:  # noqa: BLE001
        worker_beat = None
    worker_ok = workers_alive > 0
    queue_depth = None
    try:
        queue_depth = await c.redis.xlen("jobs:approved")
    except Exception:  # noqa: BLE001
        queue_depth = None
    return [
        {"name": "Gateway API", "status": "healthy"},
        {"name": "Worker", "status": "healthy" if worker_ok else "unhealthy", "last_heartbeat": worker_beat,
         "workers_alive": workers_alive,
         "queue_depth": queue_depth},
        {"name": "MongoDB", "status": "healthy" if mongo else "unhealthy"},
        {"name": "Redis", "status": "healthy" if redis else "unhealthy"},
    ]


@router.get("/metrics", response_class=PlainTextResponse)
async def metrics(p: Principal = Depends(require_user("platform_admin", "security_admin", "tenant_admin", "auditor")),
                  c: Container = Depends(get_container)) -> str:
    """Prometheus text format, scoped to the caller's tenant (no cross-tenant labels)."""
    t = p.tenant_id
    lines = ["# HELP mgw_invocations_total Tool invocations by status (last 24h)",
             "# TYPE mgw_invocations_total gauge"]
    since = utcnow().replace(minute=0, second=0, microsecond=0)
    from datetime import timedelta

    async for row in await c.repos.invocations.col.aggregate([
        {"$match": {"tenant_id": t, "created_at": {"$gte": since - timedelta(hours=24)}}},
        {"$group": {"_id": {"status": "$status", "decision": "$decision"}, "n": {"$sum": 1},
                    "avg": {"$avg": "$duration_ms"}}}]):
        s, d = row["_id"].get("status"), row["_id"].get("decision")
        lines.append(f'mgw_invocations_total{{status="{s}",decision="{d}"}} {row["n"]}')
        lines.append(f'mgw_invocation_duration_ms_avg{{status="{s}",decision="{d}"}} {round(row["avg"] or 0, 1)}')
    counts = await c.approvals.counts(t)
    lines += ["# TYPE mgw_approval_queue_depth gauge", f"mgw_approval_queue_depth {counts['pending']}",
              "# TYPE mgw_approval_oldest_age_seconds gauge",
              f"mgw_approval_oldest_age_seconds {counts['oldest_pending_age_seconds']}"]
    for comp in await _health_components(c):
        name = comp["name"].lower().replace(" ", "_")
        lines.append(f'mgw_component_up{{component="{name}"}} {1 if comp["status"] == "healthy" else 0}')
        if "workers_alive" in comp:
            lines += ["# TYPE mgw_workers_alive gauge", f"mgw_workers_alive {comp['workers_alive']}"]
    lines.append(f"mgw_in_flight_calls {await c.quotas.in_flight(t)}")
    servers = await c.repos.servers.find_all(t, {"archived": {"$ne": True}})
    for s in servers:
        lines.append(f'mgw_upstream_healthy{{server="{s["alias"]}"}} {1 if s.get("health_status") == "healthy" else 0}')
    siem = await c.siem.status() if p.is_global_admin else {"enabled": False}  # platform-level state
    if siem["enabled"]:
        lines += ["# HELP mgw_siem_up 1 if the last SIEM forwarding attempt succeeded", "# TYPE mgw_siem_up gauge",
                  f"mgw_siem_up {0 if siem['failing'] else 1}",
                  "# TYPE mgw_siem_forwarded_events counter", f"mgw_siem_forwarded_events {siem['forwarded_total']}",
                  "# HELP mgw_siem_lag_seconds Age of the newest audit event already forwarded",
                  "# TYPE mgw_siem_lag_seconds gauge", f"mgw_siem_lag_seconds {siem['lag_seconds'] or 0}",
                  "# TYPE mgw_siem_pending_events gauge", f"mgw_siem_pending_events {siem['pending_events'] or 0}"]
    return "\n".join(lines) + "\n"


# ---------------- system settings ----------------
SETTING_KEYS = {"global_limits", "payload_limits", "feature_flags", "session", "network", "tls", "audit"}


class SettingsUpdate(Strict):
    values: dict[str, Any]


def _key_management(s: Any) -> dict[str, Any]:
    """Which secrets the key service unwrapped at startup, and the (non-secret) key service settings."""
    from app.core import kms

    wrapped = s.kms_wrapped
    return {"wrapped": wrapped, **(kms.KmsConfig.from_env().describe() if wrapped else {"provider": None})}


@router.get("/settings")
async def get_settings_(p: Principal = Depends(require_user()), c: Container = Depends(get_container)) -> dict[str, Any]:
    """Every signed-in user sees what affects their work (endpoint, session, limits); the platform's key service,
    network allowlists, CORS origins and stored global settings are for global administrators only."""
    s = c.settings
    tenant = await c.repos.tenants.get(p.tenant_id) or {}
    admin = p.is_global_admin
    security: dict[str, Any] = {"default_deny": True, "audit_required_for_execution": s.audit_required_for_execution}
    system: dict[str, Any] = {
        "version": s.app_version, "environment": s.app_env, "mcp_endpoint": s.mcp_endpoint_path,
        "public_base_url": s.public_base_url,
        "session": {"ttl_minutes": s.session_ttl_minutes, "idle_minutes": s.session_idle_minutes,
                    "cookie_secure": s.cookie_secure},
        "security": security,
        "payload_limits": {"max_input_bytes": s.max_input_bytes, "max_output_bytes": s.max_output_bytes,
                           "max_json_depth": s.max_json_depth, "default_tool_timeout_seconds":
                               s.default_tool_timeout_seconds, "max_tool_timeout_seconds": s.max_tool_timeout_seconds},
        "audit": {"retention_days": s.audit_retention_days, "export_max_rows": s.audit_export_max_rows},
    }
    stored: dict[str, Any] = {}
    if admin:
        security.update({"allow_private_upstream_networks": s.allow_private_upstream_networks,
                         "key_management": _key_management(s)})
        system["network"] = {"upstream_host_allowlist": s.upstream_host_allowlist,
                             "stdio_executable_allowlist": s.stdio_executable_allowlist,
                             "cors_allowed_origins": s.cors_allowed_origins}
        stored = {k: v for k, v in (await c.repos.settings.all()).items() if k in SETTING_KEYS}
    else:
        # The global call limits apply to everyone's calls, so they stay visible (read-only).
        gl = await c.repos.settings.get_value("global_limits")
        if gl:
            stored = {"global_limits": gl}
    return {
        "system": system,
        "stored": stored,
        "tenant": tenant.get("settings", {}),
        "health": await _health_components(c),
        "editable": admin,
    }


@router.patch("/settings")
async def update_settings(body: SettingsUpdate, p: Principal = Depends(require_user("platform_admin")),
                          c: Container = Depends(get_container)) -> dict[str, Any]:
    if not p.is_global_admin:
        raise GatewayError(ErrorCode.ACCESS_DENIED, "Platform administrator role required.")
    unknown = set(body.values) - SETTING_KEYS
    if unknown:
        raise GatewayError(ErrorCode.VALIDATION_FAILED, f"Unknown settings: {', '.join(sorted(unknown))}")
    gl = body.values.get("global_limits")
    if gl is not None and (not isinstance(gl, dict) or any(
            k not in ("per_minute", "per_hour", "per_day", "per_month") or not (v is None or (isinstance(v, int) and v > 0))
            for k, v in gl.items())):
        raise GatewayError(ErrorCode.VALIDATION_FAILED, "global_limits must map windows to positive integers.")
    for k, v in body.values.items():
        await c.repos.settings.set_value(k, v, p.principal_id)
    await c.audit.record(p.tenant_id, "settings.changed", principal=p, severity="high",
                         metadata={"keys": sorted(body.values)})
    return {"stored": {k: v for k, v in (await c.repos.settings.all()).items() if k in SETTING_KEYS}}


# ---------------- REST invocation for agents (same pipeline as MCP) ----------------
class InvokeRequest(Strict):
    arguments: dict[str, Any] = Field(default_factory=dict)
    purpose: str | None = Field(default=None, max_length=1000)


@router.get("/gateway/tools")
async def gateway_tools(p: Principal = Depends(require_agent("tools:list")),
                        c: Container = Depends(get_container)) -> dict[str, Any]:
    tools = await c.invocations.discover(p)
    return {"items": [{"name": t["gateway_name"], "description": t.get("description_override") or t.get("description"),
                       "input_schema": t.get("input_schema"), "risk_level": t.get("risk_level")} for t in tools]}


@router.post("/gateway/tools/{gateway_name}/invoke")
async def gateway_invoke(gateway_name: str, body: InvokeRequest, request: Request,
                         p: Principal = Depends(require_agent("tools:invoke")),
                         c: Container = Depends(get_container)) -> Any:
    out = await c.invocations.invoke(p, gateway_name, body.arguments,
                                     InvocationContext(source="rest", source_ip=client_ip(request),
                                                       purpose=body.purpose))
    if out.status == "pending_approval":
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=202, content={
            "status": "pending_approval", "code": "APPROVAL_PENDING", "approval_id": out.approval_id,
            "invocation_id": out.invocation_id, "expires_at": out.expires_at.isoformat() if out.expires_at else None,
            "status_url": f"/api/v1/approvals/{out.approval_id}/status"})
    return {"status": out.status, "invocation_id": out.invocation_id, "is_error": out.is_error,
            "content": out.content, "structured_content": out.structured_content, "metadata": out.metadata}
