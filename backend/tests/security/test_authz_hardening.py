"""Security review: authorization and tenancy hardening (approvals, registry, tenants, sign-in, proxies)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import ADMIN_PASSWORD, ApiClient, make_client, new_user_client

from app.api.proxy import PEER_KEY, TrustedProxyMiddleware
from app.config import ConfigError, Settings, get_settings
from app.core.client_certs import parse_networks
from app.services.policy_service import NO_APPROVER

EMAIL = {"to": "cfo@example.com", "subject": "Report", "body": "Quarterly numbers"}


async def _pending(s: Any, key: str | None = None) -> str:
    r = await s.invoke("send_email", EMAIL, key=key)
    assert r.status_code == 202, r.text
    return str(r.json()["approval_id"])


# ------------------------------------------------------------------ separation of duties
async def test_whoever_issued_the_agents_key_cannot_approve_its_requests(scenario, app):
    s = await scenario.setup(enable={"send_email": "high"})
    await s.allow(["send_email"], require_approval=True)
    sec = await new_user_client(app, s.admin, s.tenant_id, ["security_admin"])
    approver = await new_user_client(app, s.admin, s.tenant_id, ["approver"])
    try:
        r = await sec.post("/api/v1/auth/agent-keys", json={"agent_id": s.agent["id"]})
        assert r.status_code == 201, r.text
        approval_id = await _pending(s, key=r.json()["secret"])
        detail = (await sec.get(f"/api/v1/approvals/{approval_id}")).json()
        assert detail["can_decide"] is False and "Separation of duties" in detail["cannot_decide_reason"]
        r = await sec.post(f"/api/v1/approvals/{approval_id}/approve", json={"comment": "mine"})
        assert r.status_code in (403, 409), r.text
        r = await approver.post(f"/api/v1/approvals/{approval_id}/approve", json={"comment": "ok"})
        assert r.status_code == 200, r.text
    finally:
        await sec.http.aclose()
        await approver.http.aclose()


async def test_the_agents_creator_cannot_approve_its_requests(scenario):
    s = await scenario.setup(enable={"send_email": "high"})  # the admin created the agent (and its key)
    await s.allow(["send_email"], require_approval=True)
    approval_id = await _pending(s)
    detail = (await s.admin.get(f"/api/v1/approvals/{approval_id}")).json()
    assert detail["can_decide"] is False and detail["separation_of_duties_warning"] is True


async def test_an_admin_cannot_delegate_someone_elses_authority_to_themselves(scenario, app):
    s = await scenario.setup()
    sec = await new_user_client(app, s.admin, s.tenant_id, ["security_admin"])
    approver = await new_user_client(app, s.admin, s.tenant_id, ["approver"], username="appr-deleg")
    try:
        me = (await sec.get("/api/v1/auth/me")).json()
        appr = (await approver.get("/api/v1/auth/me")).json()
        r = await sec.post("/api/v1/approvals/delegations", json={
            "delegator_user_id": appr["principal_id"], "delegate_user_id": me["principal_id"],
            "ends_at": "2099-01-01T00:00:00Z", "reason": "holiday"})
        assert r.status_code == 403, r.text
    finally:
        await sec.http.aclose()
        await approver.http.aclose()


def test_policy_approver_lists_only_narrow():
    from app.services.policy_service import PolicyService  # noqa: F401  (sentinel lives next to the merge)

    assert NO_APPROVER not in ("approver", "security_admin", "tenant_admin", "platform_admin")


async def test_policies_with_disjoint_approver_roles_leave_no_tenant_approver(scenario, app):
    s = await scenario.setup(enable={"send_email": "high"})
    await s.allow(["send_email"], require_approval=True, approver_roles=["security_admin"])
    await s.allow(["send_email"], require_approval=True, approver_roles=["approver"])
    approval_id = await _pending(s)
    doc = (await s.admin.get(f"/api/v1/approvals/{approval_id}")).json()
    assert doc["approval_policy"]["approver_roles"] == [NO_APPROVER]
    approver = await new_user_client(app, s.admin, s.tenant_id, ["approver"])
    try:
        assert (await approver.post(f"/api/v1/approvals/{approval_id}/approve", json={})).status_code in (403, 409)
    finally:
        await approver.http.aclose()


async def test_unknown_approver_roles_are_rejected(scenario):
    s = await scenario.setup()
    r = await s.admin.post("/api/v1/policies", json={
        "name": "bad-roles", "effect": "allow", "principals": {"types": ["agent"]},
        "resources": {"servers": [s.server["alias"]], "tools": ["*"]}, "actions": ["invoke"],
        "constraints": {"require_approval": True, "approver_roles": ["developer"]}})
    assert r.status_code == 422


# ------------------------------------------------------------------ registry: re-pointing a server
async def _server_with_secret(s: Any) -> dict[str, Any]:
    srv = (await s.admin.get(f"/api/v1/servers/{s.server['id']}")).json()
    r = await s.admin.patch(f"/api/v1/servers/{srv['id']}", json={
        "version": srv["version"], "authentication_mode": "bearer", "secret": {"token": "upstream-token-1"}})
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


async def test_a_stored_credential_is_never_sent_to_a_new_destination(scenario, app):
    s = await scenario.setup()
    srv = await _server_with_secret(s)
    dev = await new_user_client(app, s.admin, s.tenant_id, ["developer"])
    try:
        for change in ({"endpoint": "https://collector.attacker.example/mcp"}, {"verify_tls": False}):
            r = await dev.patch(f"/api/v1/servers/{srv['id']}", json={"version": srv["version"], **change})
            assert r.status_code in (403, 422), (change, r.text)
        # The private-network grant was for the old destination: only an administrator may move it.
        r = await dev.patch(f"/api/v1/servers/{srv['id']}", json={
            "version": srv["version"], "endpoint": s.upstream_url.replace("127.0.0.1", "localhost"),
            "secret": {"token": "the-developers-own"}})
        assert r.status_code == 403, r.text
    finally:
        await dev.http.aclose()
    # An administrator re-pointing it must enter the credential again too.
    r = await s.admin.patch(f"/api/v1/servers/{srv['id']}", json={
        "version": srv["version"], "endpoint": s.upstream_url + "?v=2"})
    assert r.status_code == 422 and "credential" in r.json()["error"]["message"]
    r = await s.admin.patch(f"/api/v1/servers/{srv['id']}", json={
        "version": srv["version"], "endpoint": s.upstream_url + "?v=2", "secret": {"token": "upstream-token-2"}})
    assert r.status_code == 200, r.text
    # Unrelated changes don't need it.
    r = await s.admin.patch(f"/api/v1/servers/{srv['id']}", json={"version": r.json()["version"],
                                                                 "description": "HR"})
    assert r.status_code == 200, r.text


async def test_stdio_servers_are_platform_admin_only(scenario, app):
    s = await scenario.setup()
    ta = await new_user_client(app, s.admin, s.tenant_id, ["tenant_admin"])
    try:
        r = await ta.post("/api/v1/servers", json={"name": "Local tool", "alias": "localtool", "transport": "stdio",
                                                   "command": "python", "args": ["-c", "print(1)"]})
        assert r.status_code == 403, r.text
    finally:
        await ta.http.aclose()


async def test_private_networks_need_both_opt_ins(scenario, settings):
    s = await scenario.setup()
    settings.allow_private_upstream_networks = False
    try:
        r = await s.admin.post("/api/v1/servers", json={
            "name": "Internal", "alias": "internal", "transport": "streamable_http",
            "endpoint": "http://10.1.2.3:8080/mcp", "allow_private_network": True})
        assert r.status_code == 422 or r.json()["error"]["code"] == "UPSTREAM_BLOCKED", r.text
        from app.mcp.client_manager import ClientManager

        cm = ClientManager.__new__(ClientManager)
        cm.settings = settings
        assert cm.net_policy_for({"allow_private_network": True}).allow_private is False
        settings.allow_private_upstream_networks = True
        assert cm.net_policy_for({"allow_private_network": False}).allow_private is False
        assert cm.net_policy_for({"allow_private_network": True}).allow_private is True
    finally:
        settings.allow_private_upstream_networks = True


# ------------------------------------------------------------------ tenants and users
async def test_tenant_admins_cannot_shorten_audit_retention(scenario, app, container):
    s = await scenario.setup()
    ta = await new_user_client(app, s.admin, s.tenant_id, ["tenant_admin"])
    try:
        tenant = (await ta.get(f"/api/v1/tenants/{s.tenant_id}")).json()
        settings = {**tenant.get("settings", {}), "audit_retention_days": 30}
        r = await ta.patch(f"/api/v1/tenants/{s.tenant_id}", json={"settings": settings})
        assert r.status_code == 403, r.text
        r = await ta.patch(f"/api/v1/tenants/{s.tenant_id}", json={"settings": {**settings,
                                                                                "audit_retention_days": 730}})
        assert r.status_code == 200, r.text
    finally:
        await ta.http.aclose()
    ev = await container.repos.audit.col.find_one({"tenant_id": s.tenant_id, "event_type": "tenant.changed"},
                                                  sort=[("timestamp", -1)])
    assert ev["metadata"]["settings_changed"]["audit_retention_days"]["to"] == 730
    r = await s.admin.patch(f"/api/v1/tenants/{s.tenant_id}", json={"settings": {**settings}})
    assert r.status_code == 200  # a platform administrator may


async def test_tenant_admins_cannot_pull_in_other_tenants_users(admin: ApiClient, app):
    r = await admin.post("/api/v1/tenants", json={"name": "Other Co", "slug": "other-co", "admin_username": "otheradm",
                                                  "admin_password": "Other-Admin-Pass-123"})
    assert r.status_code == 201, r.text
    other = r.json()["id"] if "id" in r.json() else r.json()["tenant"]["id"]
    async with make_client(app) as http:
        ta = ApiClient(http)
        await ta.login("otheradm", "Other-Admin-Pass-123")
        for username in ("admin",):  # the platform administrator
            r = await ta.post(f"/api/v1/tenants/{other}/users", json={"username": username, "roles": ["approver"]})
            assert r.status_code == 403, r.text


async def test_disabling_a_membership_sticks_and_ends_only_that_tenants_sessions(scenario, app, container):
    s = await scenario.setup()
    member = await new_user_client(app, s.admin, s.tenant_id, ["developer"], username="sticky")
    try:
        uid = (await member.get("/api/v1/auth/me")).json()["principal_id"]
        r = await s.admin.patch(f"/api/v1/tenants/{s.tenant_id}/users/{uid}", json={"status": "disabled"})
        assert r.status_code == 200, r.text
        m = await container.repos.memberships.find_one(s.tenant_id, {"user_id": uid})
        assert m["disabled_by_admin"] is True
        r = await s.admin.patch(f"/api/v1/tenants/{s.tenant_id}/users/{uid}", json={"status": "active"})
        m = await container.repos.memberships.find_one(s.tenant_id, {"user_id": uid})
        assert m["disabled_by_admin"] is False
    finally:
        await member.http.aclose()


async def test_tenant_scoped_session_revocation(container):
    auth = container.auth
    await auth.redis.set(auth._skey("s-a"), json.dumps({"user_id": "u1", "tenant_id": "t-a"}))
    await auth.redis.set(auth._skey("s-b"), json.dumps({"user_id": "u1", "tenant_id": "t-b"}))
    await auth.redis.sadd("usess:u1", "s-a", "s-b")
    await auth.revoke_user_sessions("u1", "t-a")
    assert await auth.redis.get(auth._skey("s-a")) is None
    assert await auth.redis.get(auth._skey("s-b")) is not None
    await auth.revoke_user_sessions("u1")
    assert await auth.redis.get(auth._skey("s-b")) is None


# ------------------------------------------------------------------ sign-in throttling
async def test_one_account_is_capped_across_addresses(app, container, settings):
    settings.login_max_attempts_per_account_window = 3
    container.auth.settings.login_max_attempts_per_account_window = 3
    async with make_client(app) as http:
        codes = []
        for i in range(4):
            r = await http.post("/api/v1/auth/login", json={"username": "victim-x", "password": f"wrong-{i}"},
                                headers={"X-Forwarded-For": f"203.0.113.{i}"})
            codes.append(r.status_code)
    assert codes[:3] == [401, 401, 401] and codes[3] == 429


async def test_break_glass_accounts_have_no_per_account_lockout(app, container, admin):
    container.auth.settings.login_max_attempts_per_account_window = 1
    await container.repos.settings.col.update_one(
        {"key": "oidc"}, {"$set": {"value": {"enabled": False, "break_glass_usernames": ["admin"]}}}, upsert=True)
    async with make_client(app) as http:
        for _ in range(3):
            r = await http.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
            assert r.status_code == 401
        r = await http.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        assert r.status_code == 200, r.text


async def test_change_password_is_throttled(admin: ApiClient, container):
    container.auth.settings.login_max_attempts_per_window = 2
    codes = [(await admin.post("/api/v1/auth/change-password", json={
        "current_password": f"wrong-{i}", "new_password": "A-New-Strong-Pass-1"})).status_code for i in range(3)]
    assert codes[-1] == 429, codes


# ------------------------------------------------------------------ proxies
async def _scope_through(trusted: list[str], peer: str, headers: dict[str, str]) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    async def inner(scope, receive, send):  # type: ignore[no-untyped-def]
        seen.update(scope)

    mw = TrustedProxyMiddleware(inner, parse_networks(trusted))
    scope = {"type": "http", "client": (peer, 1234), "scheme": "http",
             "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]}
    await mw(scope, None, None)  # type: ignore[arg-type]
    return seen


async def test_forwarded_headers_are_believed_only_from_trusted_proxies():
    h = {"X-Forwarded-For": "172.31.250.2", "X-Forwarded-Proto": "https"}
    s = await _scope_through(["172.31.250.0/24"], "10.9.9.9", h)  # someone reaching the API port directly
    assert s["client"][0] == "10.9.9.9" and s["scheme"] == "http" and s[PEER_KEY] == "10.9.9.9"
    s = await _scope_through(["172.31.250.0/24"], "172.31.250.3", {"X-Forwarded-For": "1.2.3.4, 203.0.113.9",
                                                                    "X-Forwarded-Proto": "https"})
    assert s["client"][0] == "203.0.113.9" and s["scheme"] == "https" and s[PEER_KEY] == "172.31.250.3"
    s = await _scope_through(["172.31.250.0/24"], "172.31.250.3", {"X-Forwarded-For": "not-an-ip"})
    assert s["client"][0] == "172.31.250.3"


async def test_client_certificate_header_is_judged_on_the_tcp_peer(container):
    auth = container.auth
    auth.cert_verifier = object()  # anything: the peer check comes first
    auth.cert_proxies = parse_networks(["172.31.250.0/24"])
    headers = {"x-client-cert": "-----BEGIN%20CERTIFICATE-----"}
    # A forged forwarded address inside the proxy range proves nothing when the peer is elsewhere.
    assert await auth.authenticate_agent(headers, source="172.31.250.2", peer="10.9.9.9") is None


def test_configuration_errors_never_echo_values(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_PASSWORD", "Sup3rSecretAdminPw!")
    monkeypatch.setenv("SESSION_SECRET", "s" * 48)
    monkeypatch.setenv("REDIS_SENTINELS", "not a sentinel")
    get_settings.cache_clear()
    try:
        with pytest.raises(ConfigError) as exc:
            get_settings()
    finally:
        get_settings.cache_clear()
    assert "Sup3rSecretAdminPw!" not in str(exc.value) and "s" * 48 not in str(exc.value)
    assert str(exc.value).startswith("Invalid configuration: ")
    assert Settings  # imported for the type
