"""An approval covers the tool definition and the server the approver saw, and a long call isn't swept as stale."""

from datetime import timedelta

from conftest import new_user_client, run_worker_once

from app.core.ids import utcnow
from devtools import mock_mcp_server

EMAIL = {"to": "cfo@example.com", "subject": "Report", "body": "Quarterly numbers"}


async def _approved(scenario, app):
    s = await scenario.setup(enable={"send_email": "high"})
    await s.allow(["send_email"], require_approval=True)
    r = await s.invoke("send_email", EMAIL)
    assert r.status_code == 202, r.text
    approval_id = r.json()["approval_id"]
    approver = await new_user_client(app, s.admin, s.tenant_id, ["approver"])
    r = await approver.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    await approver.http.aclose()
    assert r.status_code == 200, r.text
    return s, approval_id


async def _aborted(container, s, approval_id):
    await run_worker_once(container)
    doc = await container.repos.approvals.get(s.tenant_id, approval_id)
    assert doc["status"] == "EXECUTION_ABORTED", doc["status"]
    assert doc["execution"]["error_code"] == "APPROVAL_INVALIDATED"
    assert mock_mcp_server.CALLS["send_email"] == 0


async def test_tool_definition_changed_after_approval_aborts(scenario, app, container):
    s, approval_id = await _approved(scenario, app)
    # An upstream schema change that an admin has since acknowledged: the tool is usable again, but not under an
    # approval given for the old definition.
    await container.repos.tools.col.update_one({"_id": s.tools["send_email"]["id"]},
                                               {"$set": {"schema_hash": "changed-and-acknowledged"}})
    await _aborted(container, s, approval_id)


async def test_server_repointed_after_approval_aborts(scenario, app, container):
    s, approval_id = await _approved(scenario, app)
    doc = await container.repos.approvals.get(s.tenant_id, approval_id)
    assert doc.get("server_config_hash")
    server = await container.repos.servers.get(s.tenant_id, doc["server_id"])
    cfg = {**server["connection_config"], "endpoint": server["connection_config"]["endpoint"] + "?moved=1"}
    await container.repos.servers.col.update_one({"_id": server["_id"]}, {"$set": {"connection_config": cfg}})
    await _aborted(container, s, approval_id)


async def test_unchanged_approval_still_runs(scenario, app, container):
    s, approval_id = await _approved(scenario, app)
    await run_worker_once(container)
    doc = await container.repos.approvals.get(s.tenant_id, approval_id)
    assert doc["status"] == "COMPLETED" and mock_mcp_server.CALLS["send_email"] == 1


async def test_long_running_claim_is_not_swept(scenario, app, container):
    """Slot wait plus connect plus the longest tool timeout can exceed ten minutes: such a claim is still live."""
    s, approval_id = await _approved(scenario, app)
    await container.repos.approvals.col.update_one(
        {"_id": approval_id}, {"$set": {"status": "EXECUTING", "updated_at": utcnow() - timedelta(minutes=10)}})
    assert container.invocations.stale_claim_cutoff() > timedelta(minutes=12)
    assert await container.invocations.release_stale_claims() == 0
    assert (await container.repos.approvals.get(s.tenant_id, approval_id))["status"] == "EXECUTING"
