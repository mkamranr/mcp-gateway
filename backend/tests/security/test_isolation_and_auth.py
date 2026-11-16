"""Release-blocking security tests (spec §23.3): tenant isolation, forged identity, CSRF, secrets."""

import logging

import pytest
from conftest import ADMIN_PASSWORD, ApiClient, make_client, new_user_client

from devtools import mock_mcp_server


async def _tenant_b(admin, app):
    r = await admin.post("/api/v1/tenants", json={"name": "Beta Ltd", "slug": "beta", "admin_username": "beta-admin",
                                                  "admin_password": "Beta-Admin-Password-1"})
    assert r.status_code == 201, r.text
    client = ApiClient(make_client(app))
    await client.login("beta-admin", "Beta-Admin-Password-1")
    return r.json()["id"], client


async def test_tenant_b_cannot_access_tenant_a_resources(scenario, app, container):
    s = await scenario.setup(enable={"get_attendance_summary": "low", "send_email": "high"})
    pol = await s.allow(["get_attendance_summary"])
    await s.allow(["send_email"], require_approval=True)
    approval_id = (await s.invoke("send_email", {"to": "a", "subject": "b", "body": "c"})).json()["approval_id"]
    creds = (await s.admin.get("/api/v1/auth/agent-keys")).json()["items"]
    event = (await s.admin.get("/api/v1/audit/events")).json()["items"][0]

    tb, b = await _tenant_b(s.admin, app)
    try:
        tool_id = s.tools["get_attendance_summary"]["id"]
        reads = [f"/api/v1/servers/{s.server['id']}", f"/api/v1/tools/{tool_id}", f"/api/v1/agents/{s.agent['id']}",
                 f"/api/v1/policies/{pol['id']}", f"/api/v1/approvals/{approval_id}",
                 f"/api/v1/audit/events/{event['id']}", f"/api/v1/tenants/{s.tenant_id}",
                 f"/api/v1/tenants/{s.tenant_id}/users", f"/api/v1/servers/{s.server['id']}/tools",
                 f"/api/v1/tools/{tool_id}/versions"]
        for url in reads:
            r = await b.get(url)
            assert r.status_code in (403, 404), (url, r.status_code)
        # list endpoints only show tenant B data
        assert (await b.get("/api/v1/servers")).json()["total"] == 0
        assert (await b.get("/api/v1/tools")).json()["total"] == 0
        assert (await b.get("/api/v1/approvals")).json()["total"] == 0
        assert (await b.get("/api/v1/auth/agent-keys")).json()["total"] == 0
        assert all(e["tenant_id"] == tb for e in (await b.get("/api/v1/audit/events")).json()["items"])
        assert all(p["tenant_id"] in (tb, "*") for p in (await b.get("/api/v1/policies")).json()["items"])
        # writes
        writes = [
            ("patch", f"/api/v1/servers/{s.server['id']}", {"version": 1, "description": "x"}),
            ("patch", f"/api/v1/tools/{tool_id}", {"version": 1, "enabled": False}),
            ("patch", f"/api/v1/policies/{pol['id']}", {"version": 1, "enabled": False}),
            ("post", f"/api/v1/servers/{s.server['id']}/disable", None),
            ("post", f"/api/v1/agents/{s.agent['id']}/revoke", {"reason": "x"}),
            ("post", f"/api/v1/auth/agent-keys/{creds[0]['id']}/revoke", {"reason": "x"}),
            ("post", f"/api/v1/approvals/{approval_id}/approve", {}),
            ("post", f"/api/v1/approvals/{approval_id}/reject", {"comment": "x"}),
            ("post", f"/api/v1/tenants/{s.tenant_id}/agents", {"name": "intruder"}),
            ("delete", f"/api/v1/servers/{s.server['id']}", None),
            ("delete", f"/api/v1/policies/{pol['id']}", None),
        ]
        for method, url, body in writes:
            r = await (getattr(b, method)(url, json=body) if body is not None else getattr(b, method)(url))
            assert r.status_code in (403, 404), (method, url, r.status_code, r.text)
        # nothing changed in tenant A
        assert (await s.admin.get(f"/api/v1/servers/{s.server['id']}")).json()["enabled"] is True
        assert (await s.invoke("get_attendance_summary", {"employee_id": "E1001"})).status_code == 200
    finally:
        await b.http.aclose()


async def test_agent_of_tenant_b_cannot_use_tenant_a_tools(scenario, app):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    tb, b = await _tenant_b(s.admin, app)
    try:
        agent = (await b.post(f"/api/v1/tenants/{tb}/agents", json={"name": "beta-agent"})).json()
        key = (await b.post("/api/v1/auth/agent-keys", json={"agent_id": agent["id"]})).json()["secret"]
        r = await s.invoke("get_attendance_summary", {"employee_id": "E1"}, key=key)
        assert r.status_code == 404 and r.json()["error"]["code"] == "TOOL_NOT_FOUND"
        # a tenant-B admin cannot mint keys for tenant-A agents
        r = await b.post("/api/v1/auth/agent-keys", json={"agent_id": s.agent["id"]})
        assert r.status_code == 404
    finally:
        await b.http.aclose()
    assert mock_mcp_server.CALLS["get_attendance_summary"] == 0


async def test_forged_tenant_identity_is_ignored(scenario, app):
    s = await scenario.setup()
    tb, b = await _tenant_b(s.admin, app)
    try:
        # tenant_id in body is ignored: the record lands in the caller's tenant
        r = await b.post("/api/v1/servers", json={"name": "Forged", "alias": "forged", "transport": "streamable_http",
                                                  "endpoint": s.upstream_url, "tenant_id": s.tenant_id})
        assert r.status_code == 422  # unknown fields are rejected outright
        r = await b.post("/api/v1/policies", headers={"X-Tenant-ID": s.tenant_id}, json={
            "name": "p1", "effect": "allow", "principals": {"types": ["agent"], "ids": ["x"]},
            "resources": {"servers": ["x"], "tools": ["y"]}, "actions": ["invoke"]})
        assert r.status_code == 201 and r.json()["tenant_id"] == tb
        # switching to a tenant the user is not a member of is refused
        r = await b.post("/api/v1/auth/switch-tenant", json={"tenant_id": s.tenant_id})
        assert r.status_code == 404
    finally:
        await b.http.aclose()


async def test_tenant_suspension_blocks_agents_but_keeps_audit(scenario, app):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    tb, b = await _tenant_b(s.admin, app)
    try:
        agent = (await b.post(f"/api/v1/tenants/{tb}/agents", json={"name": "beta-agent"})).json()
        key = (await b.post("/api/v1/auth/agent-keys", json={"agent_id": agent["id"]})).json()["secret"]
        # tenant admin cannot suspend their own tenant; platform admin can
        assert (await b.patch(f"/api/v1/tenants/{tb}", json={"status": "suspended"})).status_code == 403
        assert (await s.admin.patch(f"/api/v1/tenants/{tb}", json={"status": "suspended"})).status_code == 200
        r = await s.invoke("get_attendance_summary", {}, key=key)
        assert r.status_code == 403 and r.json()["error"]["code"] == "TENANT_SUSPENDED"
        events = (await s.admin.get(f"/api/v1/audit/events?tenant={tb}")).json()
        assert events["total"] > 0
    finally:
        await b.http.aclose()


async def test_csrf_required_for_cookie_mutations(app):
    async with make_client(app) as http:
        r = await http.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        assert r.status_code == 200
        body = {"name": "csrf-agent"}
        tenant = r.json()["tenant_id"]
        r = await http.post(f"/api/v1/tenants/{tenant}/agents", json=body)
        assert r.status_code == 403 and r.json()["error"]["code"] == "CSRF_FAILED"
        r = await http.post(f"/api/v1/tenants/{tenant}/agents", json=body, headers={"X-CSRF-Token": "wrong"})
        assert r.status_code == 403
        assert (await http.get("/api/v1/servers")).status_code == 200  # safe methods do not need CSRF


async def test_logout_requires_csrf_for_a_live_session(app):
    """A cross-site request must not be able to end an administrator's session (forced-logout CSRF)."""
    async with make_client(app) as http:
        r = await http.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        csrf = r.json()["csrf_token"]
        r = await http.post("/api/v1/auth/logout")
        assert r.status_code == 403 and r.json()["error"]["code"] == "CSRF_FAILED"
        assert (await http.get("/api/v1/auth/me")).status_code == 200  # still signed in
        assert (await http.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})).status_code == 204
        assert (await http.get("/api/v1/auth/me")).status_code == 401
        # With no live session there is nothing to protect: logout just clears cookies.
        assert (await http.post("/api/v1/auth/logout")).status_code == 204


async def test_session_cookie_flags_and_fixation(app):
    async with make_client(app) as http:
        r = await http.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD},
                            headers={"Cookie": "mgw_session=attacker-chosen-session-id"})
        cookie = r.headers.get_list("set-cookie")
        session_cookie = next(c for c in cookie if c.startswith("mgw_session="))
        assert "HttpOnly" in session_cookie and "SameSite=strict" in session_cookie.lower().replace("samesite=strict", "SameSite=strict")
        sid = session_cookie.split(";")[0].split("=", 1)[1]
        assert sid != "attacker-chosen-session-id" and len(sid) >= 40
        csrf = r.json()["csrf_token"]
    # logout invalidates the server-side session even if the cookie is replayed
    async with make_client(app) as http:
        r = await http.post("/api/v1/auth/logout", headers={"Cookie": f"mgw_session={sid}", "X-CSRF-Token": csrf})
        assert r.status_code == 204
        r = await http.get("/api/v1/auth/me", headers={"Cookie": f"mgw_session={sid}"})
        assert r.status_code == 401


async def test_login_failures_are_uniform_and_rate_limited(app, settings):
    settings.login_max_attempts_per_window = 3
    async with make_client(app) as http:
        r1 = await http.post("/api/v1/auth/login", json={"username": "admin", "password": "nope"})
        r2 = await http.post("/api/v1/auth/login", json={"username": "ghost", "password": "nope"})
        assert r1.status_code == r2.status_code == 401
        assert r1.json()["error"]["message"] == r2.json()["error"]["message"]
        for _ in range(3):
            r = await http.post("/api/v1/auth/login", json={"username": "admin", "password": "nope"})
        assert r.status_code == 429


async def test_role_enforcement(scenario, app):
    s = await scenario.setup()
    auditor = await new_user_client(app, s.admin, s.tenant_id, ["auditor"])
    try:
        assert (await auditor.get("/api/v1/audit/events")).status_code == 200
        assert (await auditor.post("/api/v1/servers", json={"name": "X", "alias": "xx", "transport": "streamable_http",
                                                            "endpoint": s.upstream_url})).status_code == 403
        t = s.tools["get_attendance_summary"]
        assert (await auditor.patch(f"/api/v1/tools/{t['id']}", json={"version": t["version"],
                                                                      "enabled": False})).status_code == 403
        assert (await auditor.post("/api/v1/tenants", json={"name": "N", "slug": "nn", "admin_username": "nnn"})
                ).status_code == 403
        assert (await auditor.patch("/api/v1/settings", json={"values": {}})).status_code == 403
    finally:
        await auditor.http.aclose()


async def test_secrets_never_leak_in_responses_or_logs(scenario, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    await s.invoke("get_attendance_summary", {"employee_id": "E1001"})
    secret_part = s.key.split("_")[-1]
    responses = [await s.admin.get(u) for u in ("/api/v1/auth/agent-keys", f"/api/v1/agents/{s.agent['id']}",
                                                "/api/v1/audit/events?limit=200", "/api/v1/invocations")]
    for r in responses:
        assert secret_part not in r.text and "secret_hash" not in r.text and "password_hash" not in r.text
    out = capsys.readouterr().out + caplog.text
    assert secret_part not in out and ADMIN_PASSWORD not in out


async def test_audit_events_are_append_only(container):
    with pytest.raises(PermissionError):
        await container.repos.audit.update("t", "e", {"x": 1})
    with pytest.raises(PermissionError):
        await container.repos.audit.delete("t", "e")


async def test_audit_export_is_audited_and_csv_safe(scenario):
    s = await scenario.setup()
    r = await s.admin.post("/api/v1/audit/export", json={"format": "csv", "filters": {}})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.text.splitlines()[0].startswith("timestamp,event_type")
    ev = (await s.admin.get("/api/v1/audit/events?event_type=audit.exported")).json()["items"]
    assert ev and ev[0]["severity"] == "high"


async def test_oversized_request_body_rejected(admin):
    r = await admin.post("/api/v1/policies", json={"name": "x" * 3_000_000})
    assert r.status_code == 413
