"""Audit retention (spec §27): old events are purged per tenant, and the purge itself is audited."""

from datetime import timedelta

from app.core.ids import new_id, utcnow
from app.workers.main import Worker


async def _event(container, tenant_id: str, age_days: int) -> str:
    eid = new_id("evt")
    await container.repos.audit.col.insert_one({
        "_id": eid, "event_id": eid, "tenant_id": tenant_id, "event_type": "test.event", "severity": "info",
        "timestamp": utcnow() - timedelta(days=age_days)})
    return eid


async def test_retention_purges_only_expired_events_of_each_tenant(scenario, container):
    s = await scenario.setup(enable={})
    other = (await s.admin.post("/api/v1/tenants", json={
        "name": "Globex", "slug": "globex", "admin_username": "globex-admin",
        "admin_password": "Globex-Admin-Pass-1", "settings": {"audit_retention_days": 3650}})).json()
    await container.repos.tenants.col.update_one({"_id": s.tenant_id}, {"$set": {"settings.audit_retention_days": 30}})

    old_a = await _event(container, s.tenant_id, 400)
    recent_a = await _event(container, s.tenant_id, 5)
    old_b = await _event(container, other["id"], 400)  # tenant B keeps 10 years

    deleted = await Worker(container).retention_once()
    assert deleted >= 1
    ids = {d["_id"] async for d in container.repos.audit.col.find({"_id": {"$in": [old_a, recent_a, old_b]}})}
    assert ids == {recent_a, old_b}
    purge = await container.repos.audit.col.find_one({"tenant_id": s.tenant_id, "event_type": "audit.retention.purged"})
    assert purge and purge["metadata"]["retention_days"] == 30 and purge["severity"] == "high"


async def test_retention_never_goes_below_minimum(scenario, container):
    s = await scenario.setup(enable={})
    await container.repos.tenants.col.update_one({"_id": s.tenant_id}, {"$set": {"settings.audit_retention_days": 1}})
    recent = await _event(container, s.tenant_id, 10)
    await Worker(container).retention_once()
    assert await container.repos.audit.col.find_one({"_id": recent})  # 30-day floor protects it
