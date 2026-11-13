"""Registry and tool catalog (spec §10, §23.2)."""

from devtools import mock_mcp_server


async def test_register_discover_tools_disabled_by_default(scenario):
    s = await scenario.setup(enable={})
    names = set(s.tools)
    assert {"get_attendance_summary", "send_email", "drop_collection"} <= names
    assert "bad name!" not in names  # invalid upstream tool name rejected
    assert all(not t["enabled"] and t["review_status"] == "pending_review" and t["risk_level"] is None
               for t in s.tools.values())
    server = (await s.admin.get(f"/api/v1/servers/{s.server['id']}")).json()
    assert server["discovery"]["summary"]["rejected"] == 1
    assert server["tool_count"] == len(names) and server["enabled_tool_count"] == 0


async def test_enable_requires_risk_level(scenario):
    s = await scenario.setup(enable={})
    t = s.tools["send_email"]
    r = await s.admin.patch(f"/api/v1/tools/{t['id']}", json={"version": t["version"], "enabled": True})
    assert r.status_code == 422 and r.json()["error"]["details"][0]["field"] == "risk_level"


async def test_critical_tools_always_require_approval(scenario):
    s = await scenario.setup(enable={})
    t = await s.enable_tool("drop_collection", "critical", approval={"required": False})
    assert t["approval"]["required"] is True


async def test_test_connection_records_health(scenario):
    s = await scenario.setup(enable={})
    r = await s.admin.post(f"/api/v1/servers/{s.server['id']}/test")
    assert r.status_code == 200 and r.json()["healthy"] and r.json()["tool_count"] == 8
    server = (await s.admin.get(f"/api/v1/servers/{s.server['id']}")).json()
    assert server["health_status"] == "healthy" and server["health_history"]


async def test_unreachable_upstream_reports_sanitized_error(admin):
    r = await admin.post("/api/v1/servers", json={
        "name": "Dead", "alias": "dead", "transport": "streamable_http",
        "endpoint": "http://127.0.0.1:1/mcp", "allow_private_network": True})
    sid = r.json()["id"]
    r = await admin.post(f"/api/v1/servers/{sid}/test")
    body = r.json()
    assert body["healthy"] is False and "127.0.0.1" not in str(body)
    r = await admin.post(f"/api/v1/servers/{sid}/refresh-tools")
    assert r.status_code == 502 and r.json()["error"]["code"] == "UPSTREAM_UNAVAILABLE"


async def test_ssrf_registration_blocked_without_private_permission(admin, settings):
    settings.allow_private_upstream_networks = False  # production default
    for endpoint in ("http://169.254.169.254/latest", "http://127.0.0.1:9000/mcp", "http://10.1.2.3/mcp",
                     "ftp://x/y", "http://user:pw@example.com/mcp"):
        r = await admin.post("/api/v1/servers", json={"name": "Bad", "alias": "bad", "transport": "streamable_http",
                                                      "endpoint": endpoint})
        assert r.status_code == 422, (endpoint, r.text)
    # Link-local / metadata stays blocked even when the server is allowed private networks.
    r = await admin.post("/api/v1/servers", json={"name": "Meta", "alias": "meta", "transport": "streamable_http",
                                                  "endpoint": "http://169.254.169.254/", "allow_private_network": True})
    assert r.status_code == 422


async def test_stdio_registration_requires_allowlist(admin):
    r = await admin.post("/api/v1/servers", json={"name": "Local", "alias": "local", "transport": "stdio",
                                                  "command": "python", "args": ["-c", "print(1)"]})
    assert r.status_code == 422 and r.json()["error"]["code"] == "UPSTREAM_BLOCKED"


async def test_schema_change_creates_version_and_blocks_invocation(scenario):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    assert (await s.invoke("get_attendance_summary", {"employee_id": "E1001"})).status_code == 200

    mock_mcp_server.STATE["schema_variant"] = 1
    r = await s.admin.post(f"/api/v1/servers/{s.server['id']}/refresh-tools")
    assert r.json()["changed"] == ["get_attendance_summary"]
    tool = (await s.admin.get(f"/api/v1/tools/{s.tools['get_attendance_summary']['id']}")).json()
    assert tool["review_status"] == "schema_changed" and tool["schema_version"] == 2
    versions = (await s.admin.get(f"/api/v1/tools/{tool['id']}/versions")).json()["items"]
    assert len(versions) == 2

    r = await s.invoke("get_attendance_summary", {"employee_id": "E1001"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "TOOL_SCHEMA_CHANGED"

    r = await s.admin.patch(f"/api/v1/tools/{tool['id']}", json={"version": tool["version"],
                                                                 "acknowledge_schema_change": True})
    assert r.status_code == 200
    assert (await s.invoke("get_attendance_summary", {"employee_id": "E1001"})).status_code == 200
    events = (await s.admin.get("/api/v1/audit/events?event_type=tool.schema.changed")).json()["items"]
    assert events and events[0]["severity"] == "high"


async def test_optimistic_concurrency(scenario):
    s = await scenario.setup(enable={})
    srv = s.server
    r1 = await s.admin.patch(f"/api/v1/servers/{srv['id']}", json={"version": srv["version"], "description": "a"})
    assert r1.status_code == 200
    r2 = await s.admin.patch(f"/api/v1/servers/{srv['id']}", json={"version": srv["version"], "description": "b"})
    assert r2.status_code == 409 and r2.json()["error"]["code"] == "VERSION_CONFLICT"


async def test_upstream_secret_is_used_but_never_returned(admin, upstream_url):
    mock_mcp_server.STATE["expected_token"] = "upstream-token-xyz"
    r = await admin.post("/api/v1/servers", json={
        "name": "Auth", "alias": "auth", "transport": "streamable_http", "endpoint": upstream_url,
        "allow_private_network": True, "authentication_mode": "bearer", "secret": {"token": "upstream-token-xyz"}})
    assert r.status_code == 201
    assert "upstream-token-xyz" not in r.text and r.json()["has_secret"] is True
    sid = r.json()["id"]
    assert (await admin.post(f"/api/v1/servers/{sid}/test")).json()["healthy"] is True
    assert mock_mcp_server.STATE["last_auth"] == "Bearer upstream-token-xyz"
    for url in (f"/api/v1/servers/{sid}", "/api/v1/servers", f"/api/v1/servers/{sid}/history",
                "/api/v1/audit/events"):
        assert "upstream-token-xyz" not in (await admin.get(url)).text


async def test_disable_server_and_archive(scenario):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    assert (await s.admin.post(f"/api/v1/servers/{s.server['id']}/disable")).status_code == 200
    r = await s.invoke("get_attendance_summary", {"employee_id": "E1001"})
    assert r.json()["error"]["code"] == "SERVER_DISABLED"
    assert (await s.admin.delete(f"/api/v1/servers/{s.server['id']}")).status_code == 204
    assert (await s.admin.get(f"/api/v1/servers/{s.server['id']}")).status_code == 404
    # audit history survives deletion
    hist = (await s.admin.get("/api/v1/audit/events?event_type=server.deleted")).json()["items"]
    assert hist and hist[0]["resource"]["server_id"] == s.server["id"]
    # the alias can be reused
    r = await s.admin.post("/api/v1/servers", json={"name": s.server["name"], "alias": s.server["alias"],
                                                    "transport": "streamable_http", "endpoint": s.upstream_url,
                                                    "allow_private_network": True})
    assert r.status_code == 201
