"""Contract tests: a real MCP SDK client talking to the gateway's /mcp endpoint (spec §11, §23.4)."""

import json
from contextlib import asynccontextmanager

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from devtools import mock_mcp_server


@asynccontextmanager
async def mcp_client(app, key):
    http = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://gateway",
                              headers={"Authorization": f"Bearer {key}"})
    async with http, Client(streamable_http_client("http://gateway/mcp", http_client=http)) as client:
        yield client


async def test_discovery_is_filtered_by_policy(scenario, app):
    s = await scenario.setup(enable={"get_attendance_summary": "low", "send_email": "high", "drop_collection": "critical"})
    await s.allow(["get_attendance_summary"])
    async with mcp_client(app, s.key) as client:
        names = {t.name for t in (await client.list_tools()).tools}
    assert names == {"hr__get_attendance_summary", "gateway__approval_status"}
    # hidden tools, servers, endpoints and credentials are not revealed
    async with mcp_client(app, s.key) as client:
        tools = (await client.list_tools()).tools
    assert all("127.0.0.1" not in json.dumps(t.model_dump()) for t in tools)


async def test_call_allowed_tool(scenario, app):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    async with mcp_client(app, s.key) as client:
        res = await client.call_tool("hr__get_attendance_summary", {"employee_id": "E1001"})
    assert res.is_error is False
    assert json.loads(res.content[0].text)["employee_id"] == "E1001"
    assert mock_mcp_server.CALLS["get_attendance_summary"] == 1


async def test_denied_and_invalid_calls_return_stable_error_codes(scenario, app):
    s = await scenario.setup(enable={"get_attendance_summary": "low", "send_email": "medium"})
    await s.allow(["get_attendance_summary"])
    async with mcp_client(app, s.key) as client:
        denied = await client.call_tool("hr__send_email", {"to": "a", "subject": "b", "body": "c"})
        invalid = await client.call_tool("hr__get_attendance_summary", {"employee_id": 42})
    assert denied.is_error and denied.structured_content["error"]["code"] == "ACCESS_DENIED"
    assert invalid.is_error and invalid.structured_content["error"]["code"] == "TOOL_ARGUMENT_VALIDATION_FAILED"
    assert mock_mcp_server.CALLS["send_email"] == 0 and mock_mcp_server.CALLS["get_attendance_summary"] == 0


async def test_pending_approval_over_mcp_is_not_success(scenario, app, container):
    s = await scenario.setup(enable={"send_email": "high"})
    await s.allow(["send_email"], require_approval=True)
    async with mcp_client(app, s.key) as client:
        res = await client.call_tool("hr__send_email", {"to": "a@b.c", "subject": "s", "body": "b"})
        assert res.is_error is True
        payload = res.structured_content
        assert payload["code"] == "APPROVAL_PENDING" and payload["status"] == "pending_approval"
        status = await client.call_tool("gateway__approval_status", {"approval_id": payload["approval_id"]})
        assert status.structured_content["status"] == "PENDING"
    assert mock_mcp_server.CALLS["send_email"] == 0


async def test_unauthenticated_requests_rejected(app):
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://gateway") as http:
        r = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert r.status_code == 401 and "Bearer" in r.headers["www-authenticate"]
        r = await http.post("/mcp", json={}, headers={"Authorization": "Bearer mgw_live_0123456789abcdef_" + "z" * 40})
        assert r.status_code == 401 and r.json()["error"]["code"] == "INVALID_CREDENTIAL"


async def test_user_session_cannot_use_mcp(admin, app):
    # Admin cookies are not agent credentials.
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://gateway",
                                  cookies=dict(admin.http.cookies)) as http:
        r = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401


@pytest.mark.parametrize("scope_set", [["tools:list"]])
async def test_scopes_are_enforced(scenario, app, scope_set):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    r = await s.admin.post("/api/v1/auth/agent-keys", json={"agent_id": s.agent["id"], "scopes": scope_set})
    key = r.json()["secret"]
    async with mcp_client(app, key) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert "gateway__approval_status" not in names
        res = await client.call_tool("hr__get_attendance_summary", {"employee_id": "E1001"})
    assert res.is_error and res.structured_content["error"]["code"] == "ACCESS_DENIED"
