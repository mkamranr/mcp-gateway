"""MongoDB elections and Redis failovers fail closed with a retryable 503 and never lose or repeat an approved call
(docs/high-availability.md)."""

from datetime import timedelta

import pytest
from conftest import new_user_client, run_worker_once
from pymongo.errors import NotPrimaryError, ServerSelectionTimeoutError
from redis.exceptions import ReadOnlyError

from app.core.ids import utcnow
from devtools import mock_mcp_server

EMAIL = {"to": "cfo@example.com", "subject": "Report", "body": "Quarterly numbers"}


@pytest.mark.parametrize("exc", [ServerSelectionTimeoutError("no primary"), NotPrimaryError("not primary")])
async def test_policy_store_outage_is_a_retryable_503_audited_as_deny(scenario, container, monkeypatch, exc):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])

    async def unavailable(*_a, **_k):
        raise exc

    monkeypatch.setattr(container.repos.policies, "enabled_for_tenant", unavailable)
    r = await s.invoke("get_attendance_summary", {"employee_id": "E1001"})
    assert r.status_code == 503, r.text
    assert r.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
    assert r.headers["retry-after"] == "5"
    assert "primary" not in r.text and "before_dispatch" not in r.text  # no internals leak
    assert mock_mcp_server.CALLS["get_attendance_summary"] == 0
    ev = await container.repos.audit.col.find_one({"event_type": "tool.invocation.rejected", "tenant_id": s.tenant_id},
                                                  sort=[("timestamp", -1)])
    assert ev["decision"] == "DENY" and ev["reason_code"] == "POLICY_ENGINE_UNAVAILABLE"


async def test_unhandled_database_errors_are_503_not_500(admin, container, monkeypatch):
    async def read_only(*_a, **_k):
        raise ReadOnlyError("You can't write against a read only replica.")

    monkeypatch.setattr(container.policy, "list_policies", read_only)
    r = await admin.get("/api/v1/policies")
    assert r.status_code == 503 and r.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
    assert "read only" not in r.text


async def _approved(scenario, app):
    s = await scenario.setup(enable={"send_email": "high"})
    await s.allow(["send_email"], require_approval=True)
    r = await s.invoke("send_email", EMAIL)
    approval_id = r.json()["approval_id"]
    approver = await new_user_client(app, s.admin, s.tenant_id, ["approver"])
    r = await approver.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    await approver.http.aclose()
    assert r.json()["status"] == "APPROVED"
    return s, approval_id


async def test_outage_during_revalidation_defers_the_approved_call_then_runs_it_once(scenario, app, container,
                                                                                    monkeypatch):
    s, approval_id = await _approved(scenario, app)
    real = container.repos.policies.enabled_for_tenant

    async def election(*_a, **_k):
        raise NotPrimaryError("election in progress")

    monkeypatch.setattr(container.repos.policies, "enabled_for_tenant", election)
    assert await container.invocations.execute_approved(s.tenant_id, approval_id) == "DEFERRED"
    doc = await container.repos.approvals.get(s.tenant_id, approval_id)
    assert doc["status"] == "APPROVED" and doc.get("execution") is None  # not aborted, not failed
    assert mock_mcp_server.CALLS["send_email"] == 0
    assert await container.repos.audit.col.find_one({"approval_id": approval_id,
                                                     "event_type": "approval.execution.deferred"})

    monkeypatch.setattr(container.repos.policies, "enabled_for_tenant", real)  # the election is over
    assert await container.invocations.execute_approved(s.tenant_id, approval_id) == "COMPLETED"
    assert mock_mcp_server.CALLS["send_email"] == 1
    assert await container.invocations.execute_approved(s.tenant_id, approval_id) == "not_claimed"


async def test_outage_after_dispatch_is_never_retried(scenario, app, container, monkeypatch):
    """Once the call may have reached the upstream, a later database error must not make it run again."""
    s, approval_id = await _approved(scenario, app)

    async def lost_primary(*_a, **_k):
        raise NotPrimaryError("primary stepped down")

    monkeypatch.setattr(container.invocations, "_finish", lost_primary)  # fails after the upstream call
    assert await container.invocations.execute_approved(s.tenant_id, approval_id) == "FAILED"
    assert mock_mcp_server.CALLS["send_email"] == 1
    doc = await container.repos.approvals.get(s.tenant_id, approval_id)
    assert doc["execution"]["error_code"] == "DEPENDENCY_UNAVAILABLE"
    assert "sent to the upstream" in doc["execution"]["message"]
    assert await container.invocations.execute_approved(s.tenant_id, approval_id) == "not_claimed"
    # Had even that write failed, the claim would sit in EXECUTING. The sweep sees the dispatch record and
    # leaves it alone rather than run the call a second time.
    await container.repos.approvals.col.update_one(
        {"_id": approval_id}, {"$set": {"status": "EXECUTING", "updated_at": utcnow() - timedelta(minutes=10)}})
    assert await container.invocations.release_stale_claims() == 0
    assert (await container.repos.approvals.get(s.tenant_id, approval_id))["status"] == "EXECUTING"
    assert mock_mcp_server.CALLS["send_email"] == 1


async def test_claim_abandoned_before_dispatch_is_returned_and_runs_once(scenario, app, container):
    """A worker died after claiming (or a write failed during the outage): the sweep hands it back."""
    s, approval_id = await _approved(scenario, app)
    await container.repos.approvals.col.update_one(
        {"_id": approval_id}, {"$set": {"status": "REVALIDATING", "updated_at": utcnow() - timedelta(minutes=10)}})
    assert await container.invocations.release_stale_claims() == 1
    assert (await container.repos.approvals.get(s.tenant_id, approval_id))["status"] == "APPROVED"
    await container.approvals.enqueue(s.tenant_id, approval_id)
    await run_worker_once(container)
    assert (await container.repos.approvals.get(s.tenant_id, approval_id))["status"] == "COMPLETED"
    assert mock_mcp_server.CALLS["send_email"] == 1


async def test_fresh_claims_are_left_alone(scenario, app, container):
    s, approval_id = await _approved(scenario, app)
    await container.repos.approvals.col.update_one({"_id": approval_id},
                                                   {"$set": {"status": "REVALIDATING", "updated_at": utcnow()}})
    assert await container.invocations.release_stale_claims() == 0
