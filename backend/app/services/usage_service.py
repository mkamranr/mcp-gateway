"""Usage reporting and dashboard aggregates (spec §13.4, §18.3, §18.11)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from app.core.ids import utcnow
from app.repositories.collections import Repos


def _period_floor(days: int) -> str:
    return (utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H")


class UsageService:
    def __init__(self, repos: Repos) -> None:
        self.repos = repos

    async def _agg(self, tenant_id: str, days: int, group: Any) -> list[dict[str, Any]]:
        pipeline = [
            {"$match": {"tenant_id": tenant_id, "period": {"$gte": _period_floor(days)}}},
            {"$group": {"_id": group, "count": {"$sum": "$count"}, "units": {"$sum": "$weighted_units"},
                        "completed": {"$sum": {"$ifNull": ["$outcomes.completed", 0]}},
                        "failed": {"$sum": {"$ifNull": ["$outcomes.failed", 0]}},
                        "tool_error": {"$sum": {"$ifNull": ["$outcomes.tool_error", 0]}},
                        "rejected": {"$sum": {"$ifNull": ["$outcomes.rejected", 0]}},
                        "pending": {"$sum": {"$ifNull": ["$outcomes.pending_approval", 0]}}}},
            {"$sort": {"count": -1}},
            {"$limit": 500},
        ]
        return [d async for d in await self.repos.usage.col.aggregate(pipeline)]

    async def summary(self, tenant_id: str, days: int = 7) -> dict[str, Any]:
        rows = await self._agg(tenant_id, days, None)
        totals = rows[0] if rows else {}
        series = await self._agg(tenant_id, days, {"$substrCP": ["$period", 0, 10]})
        return {
            "days": days,
            "totals": {k: totals.get(k, 0) for k in ("count", "units", "completed", "failed", "tool_error",
                                                    "rejected", "pending")},
            "daily": sorted(({"date": r["_id"], **{k: r[k] for k in ("count", "completed", "failed", "rejected",
                                                                       "pending", "tool_error")}}
                             for r in series), key=lambda r: r["date"]),
        }

    async def by_tool(self, tenant_id: str, days: int = 7) -> list[dict[str, Any]]:
        rows = await self._agg(tenant_id, days, "$tool_id")
        tools = {t["_id"]: t for t in await self.repos.tools.find_all(tenant_id, {"_id": {"$in": [r["_id"] for r in rows]}})}
        return [{"tool_id": r["_id"], "gateway_name": tools.get(r["_id"], {}).get("gateway_name"),
                 "risk_level": tools.get(r["_id"], {}).get("risk_level"),
                 **{k: r[k] for k in ("count", "units", "completed", "failed", "rejected", "pending", "tool_error")}}
                for r in rows]

    async def by_agent(self, tenant_id: str, days: int = 7) -> list[dict[str, Any]]:
        rows = await self._agg(tenant_id, days, "$principal_id")
        agents = {a["_id"]: a for a in await self.repos.agents.find_all(tenant_id, {"_id": {"$in": [r["_id"] for r in rows]}})}
        return [{"agent_id": r["_id"], "agent_name": agents.get(r["_id"], {}).get("name"),
                 **{k: r[k] for k in ("count", "units", "completed", "failed", "rejected", "pending", "tool_error")}}
                for r in rows]

    async def tool_call_counts(self, tenant_id: str, days: int = 7) -> dict[str, int]:
        return {r["_id"]: r["count"] for r in await self._agg(tenant_id, days, "$tool_id")}

    async def overview(self, tenant_id: str) -> dict[str, Any]:
        """Aggregates for the Overview dashboard."""
        today = utcnow().strftime("%Y-%m-%d")
        servers = await self.repos.servers.find_all(tenant_id, {"archived": {"$ne": True}})
        enabled_tools = await self.repos.tools.count(tenant_id, {"enabled": True, "archived": {"$ne": True}})
        total_tools = await self.repos.tools.count(tenant_id, {"archived": {"$ne": True}})
        active_agents = await self.repos.agents.count(tenant_id, {"status": "active"})
        pending = await self.repos.approvals.count(tenant_id, {"status": "PENDING"})
        today_rows = await self.repos.usage.col.aggregate([
            {"$match": {"tenant_id": tenant_id, "period": {"$regex": f"^{today}"}}},
            {"$group": {"_id": None, "count": {"$sum": "$count"},
                        "rejected": {"$sum": {"$ifNull": ["$outcomes.rejected", 0]}}}}])
        t = [d async for d in today_rows]
        decisions = await self.repos.invocations.col.aggregate([
            {"$match": {"tenant_id": tenant_id, "created_at": {"$gte": utcnow() - timedelta(days=7)}}},
            {"$group": {"_id": "$decision", "count": {"$sum": 1}}}])
        recent = await self.repos.invocations.list(tenant_id, {}, limit=10)
        return {
            "cards": {
                "servers": len(servers),
                "servers_healthy": sum(1 for s in servers if s.get("health_status") == "healthy"),
                "enabled_tools": enabled_tools, "total_tools": total_tools, "active_agents": active_agents,
                "calls_today": t[0]["count"] if t else 0, "denied_today": t[0]["rejected"] if t else 0,
                "pending_approvals": pending,
            },
            "decisions": {d["_id"] or "UNKNOWN": d["count"] async for d in decisions},
            "series": (await self.summary(tenant_id, 7))["daily"],
            "top_tools": (await self.by_tool(tenant_id, 7))[:5],
            "server_health": [{"id": s["_id"], "name": s["name"], "status": s.get("health_status", "unknown"),
                               "enabled": s.get("enabled", False), "latency_ms": s.get("last_latency_ms"),
                               "last_check": s.get("last_health_check_at")} for s in servers],
            "recent": [{"id": r["_id"], "at": r["created_at"], "principal": r.get("principal"),
                        "tool": r.get("gateway_name"), "decision": r.get("decision"), "status": r.get("status"),
                        "duration_ms": r.get("duration_ms")} for r in recent["items"]],
        }
