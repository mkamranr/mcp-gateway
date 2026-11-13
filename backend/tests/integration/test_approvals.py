"""Approval workflow (spec §14, §23.2, §23.3)."""

import asyncio

from conftest import new_user_client, run_worker_once

from devtools import mock_mcp_server

EMAIL = {"to": "cfo@example.com", "subject": "Report", "body": "Quarterly numbers"}


async def _setup(scenario, **policy):
    s = await scenario.setup(enable={"send_email": "high"})
    await s.allow(["send_email"], require_approval=True, **policy)
    return s


async def _pending(s):
    r = await s.invoke("send_email", EMAIL)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["code"] == "APPROVAL_PENDING" and body["approval_id"]
    return body["approval_id"]


async def test_pending_approval_does_not_execute(scenario, container):
    s = await _setup(scenario)
    approval_id = await _pending(s)
    assert mock_mcp_server.CALLS["send_email"] == 0
    await run_worker_once(container)  # nothing approved yet
    assert mock_mcp_server.CALLS["send_email"] == 0
    detail = (await s.admin.get(f"/api/v1/approvals/{approval_id}")).json()
    assert detail["status"] == "PENDING" and detail["arguments"] == EMAIL and detail["integrity"] == "verified"


async def test_approve_executes_exactly_once_after_revalidation(scenario, app, container):
    s = await _setup(scenario)
    approval_id = await _pending(s)
    approver = await new_user_client(app, s.admin, s.tenant_id, ["approver"])
    try:
        r = await approver.post(f"/api/v1/approvals/{approval_id}/approve", json={"comment": "ok"})
        assert r.status_code == 200 and r.json()["status"] == "APPROVED", r.text
    finally:
        await approver.http.aclose()
    assert await run_worker_once(container) == 1
    assert mock_mcp_server.CALLS["send_email"] == 1
    assert await run_worker_once(container) == 0
    await container.approvals.enqueue(s.tenant_id, approval_id)  # duplicate job
    await run_worker_once(container)
    assert mock_mcp_server.CALLS["send_email"] == 1  # never twice

    from conftest import make_client
    async with make_client(app) as http:
        status = (await http.get(f"/api/v1/approvals/{approval_id}/status", headers=s.agent_headers())).json()
    assert status["status"] == "COMPLETED"
    assert "Email queued" in status["result"]["content"][0]["text"]
    events = (await s.admin.get(f"/api/v1/audit/events?approval_id={approval_id}")).json()["items"]
    types = {e["event_type"] for e in events}
    assert {"approval.created", "approval.approved", "approval.revalidating", "tool.invocation.dispatched",
            "tool.invocation.completed", "approval.execution.completed"} <= types


async def test_concurrent_workers_execute_once(scenario, app, container):
    s = await _setup(scenario)
    approval_id = await _pending(s)
    approver = await new_user_client(app, s.admin, s.tenant_id, ["approver"])
    await approver.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    await approver.http.aclose()
    results = await asyncio.gather(*[container.invocations.execute_approved(s.tenant_id, approval_id)
                                     for _ in range(5)])
    assert results.count("COMPLETED") == 1 and results.count("not_claimed") == 4
    assert mock_mcp_server.CALLS["send_email"] == 1


async def test_requester_cannot_self_approve(scenario):
    """The admin created (owns) the agent, so they are the requester for separation of duties."""
    s = await _setup(scenario)
    approval_id = await _pending(s)
    r = await s.admin.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    assert r.status_code == 403 and r.json()["error"]["code"] == "SEPARATION_OF_DUTIES"
    detail = (await s.admin.get(f"/api/v1/approvals/{approval_id}")).json()
    assert detail["separation_of_duties_warning"] is True and detail["can_decide"] is False


async def test_non_approver_role_cannot_approve(scenario, app):
    s = await _setup(scenario)
    approval_id = await _pending(s)
    dev = await new_user_client(app, s.admin, s.tenant_id, ["developer"])
    r = await dev.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    await dev.http.aclose()
    assert r.status_code == 403


async def test_two_person_approval(scenario, app, container):
    s = await _setup(scenario, required_approvals=2)
    approval_id = await _pending(s)
    a1 = await new_user_client(app, s.admin, s.tenant_id, ["approver"])
    a2 = await new_user_client(app, s.admin, s.tenant_id, ["approver"])
    try:
        r = await a1.post(f"/api/v1/approvals/{approval_id}/approve", json={})
        assert r.json()["status"] == "PENDING"
        r = await a1.post(f"/api/v1/approvals/{approval_id}/approve", json={})
        assert r.status_code == 403  # same approver twice does not count
        await run_worker_once(container)
        assert mock_mcp_server.CALLS["send_email"] == 0
        r = await a2.post(f"/api/v1/approvals/{approval_id}/approve", json={})
        assert r.json()["status"] == "APPROVED"
    finally:
        await a1.http.aclose()
        await a2.http.aclose()
    await run_worker_once(container)
    assert mock_mcp_server.CALLS["send_email"] == 1


async def test_reject_requires_comment_and_never_executes(scenario, app, container):
    s = await _setup(scenario)
    approval_id = await _pending(s)
    approver = await new_user_client(app, s.admin, s.tenant_id, ["approver"])
    try:
        assert (await approver.post(f"/api/v1/approvals/{approval_id}/reject", json={})).status_code == 422
        r = await approver.post(f"/api/v1/approvals/{approval_id}/reject", json={"comment": "no"})
        assert r.json()["status"] == "REJECTED"
        r = await approver.post(f"/api/v1/approvals/{approval_id}/approve", json={})
        assert r.status_code == 409
    finally:
        await approver.http.aclose()
    assert await container.invocations.execute_approved(s.tenant_id, approval_id) == "not_claimed"
    assert mock_mcp_server.CALLS["send_email"] == 0


async def test_expired_approval_never_executes(scenario, app, container):
    s = await _setup(scenario)
    approval_id = await _pending(s)
    from datetime import timedelta

    from app.core.ids import utcnow
    await container.repos.approvals.col.update_one({"_id": approval_id},
                                                   {"$set": {"expires_at": utcnow() - timedelta(minutes=1)}})
    assert await container.approvals.expire_due() == 1
    approver = await new_user_client(app, s.admin, s.tenant_id, ["approver"])
    r = await approver.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    await approver.http.aclose()
    assert r.status_code == 409
    assert mock_mcp_server.CALLS["send_email"] == 0


async def test_credential_revoked_while_pending_aborts_execution(scenario, app, container):
    s = await _setup(scenario)
    approval_id = await _pending(s)
    creds = (await s.admin.get(f"/api/v1/auth/agent-keys?agent_id={s.agent['id']}")).json()["items"]
    await s.admin.post(f"/api/v1/auth/agent-keys/{creds[0]['id']}/revoke", json={"reason": "leak"})
    approver = await new_user_client(app, s.admin, s.tenant_id, ["approver"])
    await approver.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    await approver.http.aclose()
    await run_worker_once(container)
    doc = await container.repos.approvals.get(s.tenant_id, approval_id)
    assert doc["status"] == "EXECUTION_ABORTED" and doc["execution"]["error_code"] == "CREDENTIAL_REVOKED"
    assert mock_mcp_server.CALLS["send_email"] == 0


async def test_tool_disabled_after_approval_aborts(scenario, app, container):
    s = await _setup(scenario)
    approval_id = await _pending(s)
    approver = await new_user_client(app, s.admin, s.tenant_id, ["approver"])
    await approver.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    await approver.http.aclose()
    t = s.tools["send_email"]
    await s.admin.patch(f"/api/v1/tools/{t['id']}", json={"version": t["version"], "enabled": False})
    await run_worker_once(container)
    doc = await container.repos.approvals.get(s.tenant_id, approval_id)
    assert doc["status"] == "EXECUTION_ABORTED" and mock_mcp_server.CALLS["send_email"] == 0


async def test_payload_substitution_is_detected(scenario, app, container):
    """Tampering with stored arguments (or swapping ciphertexts between requests) invalidates the approval."""
    s = await _setup(scenario)
    a1 = await _pending(s)
    r = await s.invoke("send_email", {**EMAIL, "to": "attacker@evil.example"})
    a2 = r.json()["approval_id"]
    doc2 = await container.repos.approvals.get(s.tenant_id, a2)
    # Swap a2's ciphertext into a1. AES-GCM associated data binds it to a2, so decryption fails.
    await container.repos.approvals.col.update_one({"_id": a1}, {"$set": {"arguments_encrypted": doc2["arguments_encrypted"]}})
    approver = await new_user_client(app, s.admin, s.tenant_id, ["approver"])
    await approver.post(f"/api/v1/approvals/{a1}/approve", json={})
    await approver.http.aclose()
    await run_worker_once(container)
    doc = await container.repos.approvals.get(s.tenant_id, a1)
    assert doc["status"] == "EXECUTION_ABORTED" and doc["execution"]["error_code"] == "APPROVAL_INVALIDATED"
    assert mock_mcp_server.CALLS["send_email"] == 0


async def test_critical_requires_confirmation_and_agent_can_cancel(scenario, app, container):
    s = await scenario.setup(enable={"drop_collection": "critical"})
    await s.allow(["drop_collection"])
    r = await s.invoke("drop_collection", {"collection": "payroll"})
    approval_id = r.json()["approval_id"]
    approver = await new_user_client(app, s.admin, s.tenant_id, ["approver"])
    r = await approver.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    assert r.status_code == 422
    await approver.http.aclose()
    from conftest import make_client
    async with make_client(app) as http:
        r = await http.post(f"/api/v1/approvals/{approval_id}/cancel", json={"reason": "not needed"},
                            headers=s.agent_headers())
    assert r.json()["status"] == "CANCELLED"
    assert mock_mcp_server.CALLS["drop_collection"] == 0


async def test_approval_changes_since_request_flag(scenario, app):
    s = await _setup(scenario)
    approval_id = await _pending(s)
    await s.allow(["get_attendance_summary"])  # policy set changed after the request
    detail = (await s.admin.get(f"/api/v1/approvals/{approval_id}")).json()
    assert "policies_changed" in detail["changes_since_request"]
