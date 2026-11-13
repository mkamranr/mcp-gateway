"""The shared invocation pipeline (spec §11.4, §12, §13, §23.2)."""

from devtools import mock_mcp_server


async def test_denied_call_never_reaches_upstream(scenario):
    s = await scenario.setup(enable={"get_attendance_summary": "low", "send_email": "medium"})
    await s.allow(["get_attendance_summary"])
    r = await s.invoke("send_email", {"to": "a@b.c", "subject": "s", "body": "b"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "ACCESS_DENIED"
    assert mock_mcp_server.CALLS["send_email"] == 0
    ev = (await s.admin.get("/api/v1/audit/events?event_type=tool.invocation.rejected")).json()["items"][0]
    assert ev["decision"] == "DENY" and ev["reason_code"] == "NO_MATCHING_ALLOW"
    assert "policy" not in r.text.lower() or "pol_" not in r.text  # no policy internals to the agent


async def test_explicit_deny_overrides_allow(scenario):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    r = await s.admin.post("/api/v1/policies", json={
        "name": "block", "effect": "deny", "principals": {"types": ["agent"], "ids": [s.agent["id"]]},
        "resources": {"servers": ["hr"], "tools": ["get_attendance_summary"]}, "actions": ["invoke"]})
    assert r.status_code == 201
    r = await s.invoke("get_attendance_summary", {"employee_id": "E1001"})
    assert r.status_code == 403 and mock_mcp_server.CALLS["get_attendance_summary"] == 0


async def test_invalid_arguments_rejected_before_dispatch(scenario):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    for args in ({}, {"employee_id": "not-valid"}, {"employee_id": "E1001", "unexpected": True}):
        r = await s.invoke("get_attendance_summary", args)
        assert r.status_code == 422 and r.json()["error"]["code"] == "TOOL_ARGUMENT_VALIDATION_FAILED"
    assert mock_mcp_server.CALLS["get_attendance_summary"] == 0


async def test_disabled_tool_cannot_be_invoked_even_if_cached(scenario):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    t = s.tools["get_attendance_summary"]
    await s.admin.patch(f"/api/v1/tools/{t['id']}", json={"version": t["version"], "enabled": False})
    r = await s.invoke("get_attendance_summary", {"employee_id": "E1001"})
    assert r.json()["error"]["code"] == "TOOL_DISABLED" and mock_mcp_server.CALLS["get_attendance_summary"] == 0


async def test_unreviewed_and_unknown_tools(scenario):
    s = await scenario.setup()
    # Never enabled and not granted: the caller is denied without learning the tool's state.
    r = await s.invoke("send_email", {"to": "a", "subject": "b", "body": "c"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "ACCESS_DENIED"
    # Granted but still unreviewed: the specific state is reported to an authorized caller.
    await s.allow(["send_email"])
    r = await s.invoke("send_email", {"to": "a", "subject": "b", "body": "c"})
    assert r.json()["error"]["code"] == "TOOL_DISABLED"
    assert mock_mcp_server.CALLS["send_email"] == 0
    r = await s.invoke("does_not_exist", {})
    assert r.status_code == 404 and r.json()["error"]["code"] == "TOOL_NOT_FOUND"


async def test_policy_rate_limit_returns_429_with_retry_after(scenario):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"], max_calls_per_minute=2)
    assert (await s.invoke("get_attendance_summary", {"employee_id": "E1001"})).status_code == 200
    assert (await s.invoke("get_attendance_summary", {"employee_id": "E1001"})).status_code == 200
    r = await s.invoke("get_attendance_summary", {"employee_id": "E1001"})
    assert r.status_code == 429 and r.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert int(r.headers["retry-after"]) >= 1
    assert mock_mcp_server.CALLS["get_attendance_summary"] == 2
    assert (await s.admin.get("/api/v1/audit/events?event_type=quota.exceeded")).json()["total"] == 1


async def test_tool_daily_quota(scenario):
    s = await scenario.setup(enable={})
    await s.enable_tool("get_attendance_summary", "low", limits={"per_day": 1})
    await s.allow(["get_attendance_summary"])
    assert (await s.invoke("get_attendance_summary", {"employee_id": "E1001"})).status_code == 200
    r = await s.invoke("get_attendance_summary", {"employee_id": "E1001"})
    assert r.status_code == 429 and r.json()["error"]["code"] == "QUOTA_EXCEEDED"


async def test_concurrent_requests_respect_rate_limit_exactly(scenario):
    import asyncio

    s = await scenario.setup()
    await s.allow(["get_attendance_summary"], max_calls_per_minute=5)
    results = await asyncio.gather(*[s.invoke("get_attendance_summary", {"employee_id": "E1001"})
                                     for _ in range(12)])
    codes = sorted(r.status_code for r in results)
    assert codes.count(200) == 5 and codes.count(429) == 7
    assert mock_mcp_server.CALLS["get_attendance_summary"] == 5


async def test_upstream_timeout(scenario):
    s = await scenario.setup(enable={})
    await s.enable_tool("slow_tool", "low", timeout_seconds=1)
    await s.allow(["slow_tool"])
    r = await s.invoke("slow_tool", {"seconds": 5})
    assert r.status_code == 504 and r.json()["error"]["code"] == "UPSTREAM_TIMEOUT"
    assert (await s.admin.get("/api/v1/audit/events?event_type=tool.invocation.timed_out")).json()["total"] == 1


async def test_tool_error_is_returned_as_error_result(scenario):
    s = await scenario.setup(enable={"fail_tool": "low"})
    await s.allow(["fail_tool"])
    r = await s.invoke("fail_tool", {})
    assert r.status_code == 200 and r.json()["is_error"] is True and r.json()["status"] == "tool_error"


async def test_output_redaction_and_size_limit(scenario):
    s = await scenario.setup(enable={})
    await s.enable_tool("get_employee_record", "medium", output={"redact_fields": ["ssn"], "validate_output": True})
    await s.enable_tool("big_output", "low", max_output_bytes=1000)
    await s.allow(["get_employee_record", "big_output"])
    r = await s.invoke("get_employee_record", {"employee_id": "E1"})
    assert r.status_code == 200 and "123-45-6789" not in r.text
    assert r.json()["structured_content"]["ssn"] == "[REDACTED]" and r.json()["metadata"]["untrusted"] is True
    r = await s.invoke("big_output", {"size": 5000})
    assert r.status_code == 413 and r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


async def test_every_attempt_is_audited_and_correlated(scenario):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    r = await s.invoke("get_attendance_summary", {"employee_id": "E1001"})
    inv = r.json()["invocation_id"]
    events = (await s.admin.get(f"/api/v1/audit/events?invocation_id={inv}")).json()["items"]
    types = {e["event_type"] for e in events}
    assert {"tool.invocation.requested", "tool.invocation.dispatched", "tool.invocation.completed"} <= types
    done = next(e for e in events if e["event_type"] == "tool.invocation.completed")
    assert done["input_hash"].startswith("sha256:") and done["output_hash"].startswith("sha256:")
    assert done["resource"]["schema_hash"] and done["duration_ms"] is not None
    assert "E1001" not in str(events)  # raw arguments are not stored in audit
    detail = (await s.admin.get(f"/api/v1/audit/events/{done['id']}")).json()
    assert len(detail["correlated"]) >= 2
    usage = (await s.admin.get("/api/v1/usage/by-tool")).json()["items"]
    assert usage[0]["completed"] == 1


async def test_revoked_and_invalid_keys_rejected(scenario):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    r = await s.invoke("get_attendance_summary", {"employee_id": "E1001"}, key="mgw_live_0123456789abcdef_" + "x" * 40)
    assert r.status_code == 401 and r.json()["error"]["code"] == "INVALID_CREDENTIAL"
    creds = (await s.admin.get(f"/api/v1/auth/agent-keys?agent_id={s.agent['id']}")).json()["items"]
    await s.admin.post(f"/api/v1/auth/agent-keys/{creds[0]['id']}/revoke", json={"reason": "test"})
    r = await s.invoke("get_attendance_summary", {"employee_id": "E1001"})
    assert r.status_code == 401 and r.json()["error"]["code"] == "CREDENTIAL_REVOKED"


async def test_key_rotation(scenario):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    creds = (await s.admin.get(f"/api/v1/auth/agent-keys?agent_id={s.agent['id']}")).json()["items"]
    r = await s.admin.post(f"/api/v1/auth/agent-keys/{creds[0]['id']}/rotate")
    new_key = r.json()["secret"]
    assert (await s.invoke("get_attendance_summary", {"employee_id": "E1001"})).status_code == 401
    assert (await s.invoke("get_attendance_summary", {"employee_id": "E1001"}, key=new_key)).status_code == 200


async def test_agent_revocation_blocks_calls(scenario):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    await s.admin.post(f"/api/v1/agents/{s.agent['id']}/revoke", json={"reason": "compromised"})
    r = await s.invoke("get_attendance_summary", {"employee_id": "E1001"})
    assert r.status_code == 401


async def test_policy_simulator_never_dispatches(scenario):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    r = await s.admin.post("/api/v1/policies/simulate", json={
        "principal_id": s.agent["id"], "gateway_name": "hr__get_attendance_summary",
        "arguments": {"employee_id": "bad"}})
    body = r.json()
    assert body["decision"] == "ALLOW" and body["dispatched"] is False and body["validation"]["valid"] is False
    assert any(e["matched"] for e in body["explanation"])
    assert mock_mcp_server.CALLS["get_attendance_summary"] == 0


async def test_broad_grant_requires_confirmation(scenario):
    s = await scenario.setup()
    body = {"name": "everything", "effect": "allow", "principals": {"types": ["agent"], "ids": [s.agent["id"]]},
            "resources": {"servers": ["*"], "tools": ["*"]}, "actions": ["invoke"]}
    r = await s.admin.post("/api/v1/policies", json=body)
    assert r.status_code == 422 and r.json()["error"]["code"] == "BROAD_GRANT_CONFIRMATION_REQUIRED"
    r = await s.admin.post("/api/v1/policies", json={**body, "confirm_broad_grant": True})
    assert r.status_code == 201 and set(r.json()["broad"]) == {"servers", "tools"}


async def test_policy_unknown_fields_rejected(admin):
    r = await admin.post("/api/v1/policies", json={
        "name": "x1", "effect": "allow", "principals": {"types": ["agent"], "ids": ["a"]},
        "resources": {"servers": ["s"], "tools": ["t"]}, "actions": ["invoke"], "surprise": True})
    assert r.status_code == 422


async def test_system_default_deny_policy_is_immutable(admin):
    pols = (await admin.get("/api/v1/policies")).json()["items"]
    default = next(p for p in pols if p["kind"] == "default_deny")
    r = await admin.patch(f"/api/v1/policies/{default['id']}", json={"version": default["version"], "enabled": False})
    assert r.status_code == 409
    assert (await admin.delete(f"/api/v1/policies/{default['id']}")).status_code == 409
