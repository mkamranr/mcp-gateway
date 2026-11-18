"""Security review hardening: secrets bound to their destination, SIEM network checks, SSO account linking,
audit export filters, settings exposure, cross-tenant audit reads, request ids and log scrubbing."""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.core.logging import REDACTED, scrub
from app.services import siem_service
from tests.conftest import ApiClient, make_client, new_user_client
from tests.integration.test_siem import StreamReceiver, until
from tests.security.test_sso import configure as sso_configure
from tests.security.test_sso import sso_error, sso_login

TOKEN = "Bearer siem-token-123"  # noqa: S105 (test value)


@pytest.fixture(autouse=True)
def no_lag(monkeypatch):
    monkeypatch.setattr(siem_service, "LAG_SECONDS", 0)


async def siem_put(admin: ApiClient, **kw: Any) -> Any:
    body = {"enabled": False, "transport": "http", "url": "https://siem.corp.example/ingest", **kw}
    return await admin.put("/api/v1/siem/config", json=body)


# ---------------------------------------------------------------- SIEM: credential bound to its destination
async def test_siem_credential_must_be_reentered_when_the_destination_changes(admin):
    assert (await siem_put(admin, http_auth_value=TOKEN)).status_code == 200
    assert (await siem_put(admin)).status_code == 200  # nothing about the destination changed: kept
    for change in ({"url": "https://attacker.example/x"}, {"http_auth_header": "X-Token"},
                   {"transport": "syslog_tls", "host": "attacker.example"}):
        r = await siem_put(admin, **change)
        assert r.status_code == 422 and "again" in r.json()["error"]["message"], change
    r = await siem_put(admin, url="https://new.corp.example/ingest", http_auth_value=TOKEN)
    assert r.status_code == 200 and r.json()["has_http_auth_value"]
    r = await siem_put(admin, url="https://other.corp.example/ingest", http_auth_value="")  # cleared explicitly
    assert r.status_code == 200 and not r.json()["has_http_auth_value"]


async def test_siem_tls_cannot_be_weakened(admin, settings):
    r = await siem_put(admin, tls_verify_hostname=False)
    assert r.status_code == 422  # no pinned CA: any public certificate for any name would pass
    settings.app_env = "production"
    try:
        r = await siem_put(admin, url="http://siem.corp.example/ingest", http_auth_value=TOKEN)
        assert r.status_code == 422 and "https" in r.json()["error"]["message"]
        assert (await siem_put(admin, url="http://siem.corp.example/ingest")).status_code == 200  # no credential
    finally:
        settings.app_env = "test"


@pytest.mark.parametrize("dest", [
    {"transport": "syslog_tcp", "host": "169.254.170.2", "port": 514},  # ECS task credentials
    {"transport": "syslog_tcp", "host": "::ffff:169.254.169.254", "port": 514},
    {"transport": "http", "url": "http://[::ffff:169.254.169.254]/x"},
    {"transport": "http", "url": "http://100.100.100.200/x"},  # CGNAT / Alibaba metadata
])
async def test_siem_blocked_destinations_are_refused_when_saved(admin, dest):
    r = await admin.put("/api/v1/siem/config", json={"enabled": False, **dest})
    assert r.status_code == 422, r.text


async def test_siem_checks_resolved_addresses_at_connect_time(admin, container, monkeypatch):
    async def to_metadata(host: str, port: int) -> list[str]:
        return ["169.254.169.254"]

    monkeypatch.setattr(siem_service, "resolve", to_metadata)
    for dest in ({"transport": "syslog_tcp", "host": "collector.corp.example", "port": 514},
                 {"transport": "syslog_udp", "host": "collector.corp.example", "port": 514}):
        assert (await admin.put("/api/v1/siem/config", json={"enabled": False, **dest})).status_code == 200
        r = (await admin.post("/api/v1/siem/test")).json()
        assert r["ok"] is False and "not permitted" in r["error"], r


async def test_siem_test_errors_are_generic(admin):
    assert (await admin.put("/api/v1/siem/config", json={"enabled": False, "transport": "syslog_tcp",
                                                         "host": "127.0.0.1", "port": 1})).status_code == 200
    r = (await admin.post("/api/v1/siem/test")).json()
    assert r["ok"] is False and r["error"] == "connect 127.0.0.1:1: could not connect or send"


async def test_siem_auth_value_must_be_ascii(admin):
    r = await siem_put(admin, http_auth_value="Splunk tökén")
    assert r.status_code == 422


async def test_unexpected_send_error_is_a_recorded_failure(admin, container, monkeypatch):
    rx = await StreamReceiver().start()
    try:
        r = await admin.put("/api/v1/siem/config", json={"enabled": True, "transport": "syslog_tcp",
                                                         "host": "127.0.0.1", "port": rx.port})
        assert r.status_code == 200
        await container.audit.record("ten_x", "drill.event", principal={"type": "user", "id": "u", "name": "u"})

        async def boom(*a: Any, **k: Any) -> None:
            raise UnicodeEncodeError("ascii", "x", 0, 1, "nope")

        monkeypatch.setattr(container.siem, "_send_stream", boom)
        assert await container.siem.forward_once("w1") == 0
        status = (await admin.get("/api/v1/siem/status")).json()
        assert status["failing"] and "UnicodeEncodeError" in status["last_error"]
        assert await container.repos.audit.col.find_one({"event_type": "siem.forwarding.failed"})
        monkeypatch.undo()
        monkeypatch.setattr(siem_service, "LAG_SECONDS", 0)
        await container.redis.delete(siem_service.STATUS_KEY + ":backoff")
        assert await container.siem.forward_once("w1") >= 1
        await until(lambda: bool(rx.messages))
    finally:
        await rx.stop()


# ---------------------------------------------------------------- SSO and LDAP secrets bound to their destination
async def test_sso_client_secret_must_be_reentered_when_the_issuer_changes(admin, mock_idp):
    await sso_configure(admin, mock_idp)  # with a client secret
    body = (await admin.get("/api/v1/sso/config")).json()
    keep = {k: body[k] for k in ("enabled", "issuer", "client_id", "group_rules", "platform_admin_groups")}
    assert (await admin.put("/api/v1/sso/config", json=keep)).status_code == 200  # same issuer: kept
    moved = {**keep, "enabled": False, "issuer": "https://idp.attacker.example"}
    r = await admin.put("/api/v1/sso/config", json=moved)
    assert r.status_code == 422 and "again" in r.json()["error"]["message"]
    assert (await admin.put("/api/v1/sso/config", json={**moved, "client_secret": "new"})).status_code == 200


async def test_ldap_bind_password_must_be_reentered_when_the_servers_change(admin):
    base = {"server_urls": ["ldaps://ldap.corp.example"], "bind_dn": "cn=svc,dc=corp,dc=example"}
    assert (await admin.put("/api/v1/ldap/config", json={**base, "bind_password": "svc-pass"})).status_code == 200
    assert (await admin.put("/api/v1/ldap/config", json=base)).status_code == 200  # unchanged: kept
    for change in ({"server_urls": ["ldaps://ldap.attacker.example"]}, {"bind_dn": "cn=other,dc=corp,dc=example"}):
        r = await admin.put("/api/v1/ldap/config", json={**base, **change})
        assert r.status_code == 422 and "again" in r.json()["error"]["message"], change
    r = await admin.put("/api/v1/ldap/config", json={**base, "server_urls": ["ldaps://ldap2.corp.example"],
                                                    "bind_password": "svc-pass"})
    assert r.status_code == 200 and r.json()["has_bind_password"]


# ---------------------------------------------------------------- SSO account linking
async def _local_user(admin: ApiClient, username: str, **extra: Any) -> str:
    me = (await admin.get("/api/v1/auth/me")).json()
    r = await admin.post(f"/api/v1/tenants/{me['tenant_id']}/users",
                         json={"username": username, "roles": ["auditor"], "password": "Local-Known-Pass-1", **extra})
    assert r.status_code == 201, r.text
    return r.json()["user_id"]


async def test_linking_removes_the_local_password(app, admin, mock_idp, container):
    """A tenant admin pre-creates the account with a password they know: after the link it no longer works, and
    the platform-admin flag that follows the IdP group can't be used through it."""
    uid = await _local_user(admin, "root.sso")
    async with make_client(app) as http:  # a session opened with the known password before the link
        stale = ApiClient(http)
        await stale.login("root.sso", "Local-Known-Pass-1")
        await sso_configure(admin, mock_idp, link_local_accounts=True)
        async with make_client(app) as sso:
            await sso_login(sso, "root")
            me = (await sso.get("/api/v1/auth/me")).json()
            assert me["principal_id"] == uid and me["is_platform_admin"] and me["auth_source"] == "oidc"
        assert (await stale.get("/api/v1/auth/me")).status_code == 401  # revoked at the link
    async with make_client(app) as http:
        r = await http.post("/api/v1/auth/login", json={"username": "root.sso", "password": "Local-Known-Pass-1"})
        assert r.status_code == 401
    linked = await container.repos.audit.col.find_one({"event_type": "user.oidc.linked"})
    assert linked and linked["metadata"]["local_sign_in_removed"] is True
    changed = await container.repos.audit.col.find_one({"event_type": "user.platform_admin.changed"})
    assert changed and changed["metadata"]["is_platform_admin"] is True


async def test_platform_admin_flag_is_revoked_when_the_idp_group_goes(app, admin, mock_idp, container):
    await _local_user(admin, "root.sso")
    await sso_configure(admin, mock_idp, link_local_accounts=True,
                        group_rules=[{"group": "mgw-platform-admins",
                                      "tenant_id": (await admin.get("/api/v1/auth/me")).json()["tenant_id"],
                                      "roles": ["auditor"]}, {"group": "ops",
                                      "tenant_id": (await admin.get("/api/v1/auth/me")).json()["tenant_id"],
                                      "roles": ["auditor"]}])
    async with make_client(app) as http:
        await sso_login(http, "root")
        assert (await http.get("/api/v1/auth/me")).json()["is_platform_admin"]
    mock_idp.users["root"]["groups"] = ["ops"]
    async with make_client(app) as http:
        await sso_login(http, "root")
        assert not (await http.get("/api/v1/auth/me")).json()["is_platform_admin"]
    events = [e async for e in container.repos.audit.col.find({"event_type": "user.platform_admin.changed"})]
    assert [e["metadata"]["is_platform_admin"] for e in events] == [True, False]


async def test_privileged_accounts_are_never_linked_by_username(app, admin, mock_idp, container):
    # A local platform administrator with the IdP user's name.
    uid = await _local_user(admin, "alice.sso")
    await container.repos.users.update(uid, {"is_platform_admin": True})
    await sso_configure(admin, mock_idp, link_local_accounts=True)
    async with make_client(app) as http:
        assert sso_error(await sso_login(http, "alice")) == "account_conflict"
    # A break-glass account.
    await _local_user(admin, "bob.sso")
    await sso_configure(admin, mock_idp, link_local_accounts=True, break_glass_usernames=["bob.sso"])
    async with make_client(app) as http:
        assert sso_error(await sso_login(http, "bob")) == "account_conflict"
    user = await container.repos.users.by_username("bob.sso")
    assert user["password_hash"] and not user.get("oidc")
    denied = [e async for e in container.repos.audit.col.find({"event_type": "auth.oidc.denied"})]
    assert any("never linked" in e["metadata"]["reason"] for e in denied)


# ---------------------------------------------------------------- audit export, settings, cross-tenant reads
@pytest.mark.parametrize("filters", [{"principal": {"$regex": "(a+)+$"}}, {"status": {"$ne": None}},
                                     {"event_type": {"x": 1}}, {"unknown": "x"}])
async def test_audit_export_rejects_operator_filters(admin, filters):
    r = await admin.post("/api/v1/audit/export", json={"format": "json", "filters": filters})
    assert r.status_code == 422, r.text


async def test_audit_export_with_plain_filters(admin):
    r = await admin.post("/api/v1/audit/export", json={"format": "json", "filters": {
        "event_type": "auth.*", "start": "2020-01-01T00:00:00Z", "tenant": "ignored"}})
    assert r.status_code == 200, r.text
    assert all(e["event_type"].startswith("auth.") for e in json.loads(r.text))


async def test_settings_hide_platform_configuration_from_tenant_users(app, admin):
    me = (await admin.get("/api/v1/auth/me")).json()
    full = (await admin.get("/api/v1/settings")).json()
    assert "network" in full["system"] and "key_management" in full["system"]["security"]
    dev = await new_user_client(app, admin, me["tenant_id"], ["developer"])
    try:
        s = (await dev.get("/api/v1/settings")).json()
        assert "network" not in s["system"] and set(s["system"]["security"]) == {"default_deny",
                                                                                 "audit_required_for_execution"}
        assert set(s["stored"]) <= {"global_limits"} and s["editable"] is False
        assert s["system"]["mcp_endpoint"] and s["system"]["payload_limits"]
    finally:
        await dev.http.aclose()


async def test_cross_tenant_audit_reads_are_audited(admin, container):
    r = await admin.post("/api/v1/tenants", json={"name": "Other", "slug": "other-t", "admin_username": "other-ta",
                                                   "admin_password": "Other-Tenant-Admin-1"})
    assert r.status_code == 201, r.text
    other = r.json()["tenant"]["id"] if "tenant" in r.json() else r.json()["id"]
    assert (await admin.get("/api/v1/audit/events", params={"tenant": other})).status_code == 200
    ev = await container.repos.audit.col.find_one({"event_type": "audit.searched.cross_tenant", "tenant_id": other})
    assert ev and ev["severity"] == "high" and ev["metadata"]["target_tenant"] == other
    assert (await admin.get("/api/v1/audit/events", params={"tenant": "*", "event_type": "auth.*"})).status_code == 200
    me = (await admin.get("/api/v1/auth/me")).json()
    ev = await container.repos.audit.col.find_one({"event_type": "audit.searched.cross_tenant",
                                                   "metadata.target_tenant": "*"})
    assert ev and ev["tenant_id"] == me["tenant_id"] and ev["metadata"]["event_type"] == "auth.*"
    other_event = await container.repos.audit.col.find_one({"tenant_id": other,
                                                            "event_type": {"$ne": "audit.searched.cross_tenant"}})
    assert other_event
    assert (await admin.get(f"/api/v1/audit/events/{other_event['_id']}")).status_code == 200
    assert await container.repos.audit.col.find_one({"event_type": "audit.searched.cross_tenant",
                                                     "metadata.event_id": other_event["_id"]})
    assert (await admin.get("/api/v1/audit/events", params={"tenant": "ten_nope"})).status_code == 404


# ---------------------------------------------------------------- request ids and log scrubbing
async def test_client_cannot_choose_the_request_id(anon):
    r = await anon.get("/health/live", headers={"X-Request-ID": "victim-request-0001"})
    assert r.headers["x-request-id"].startswith("req_") and r.headers["x-request-id"] != "victim-request-0001"


def test_scrub_redacts_beyond_the_depth_limit():
    deep: Any = {"password": "hunter2"}
    for i in range(12):
        deep = {f"k{i}": deep}
    assert "hunter2" not in json.dumps(scrub(deep))
    assert scrub([[[[[[[[[["s3cret"]]]]]]]]]]) != [[[[[[[[[["s3cret"]]]]]]]]]]


@pytest.mark.parametrize("text,secret", [
    ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="),
    ("GET /cb?code=1&access_token=abc.def.ghi&x=1", "abc.def.ghi"),
    ("password=hunter2 next", "hunter2"),
    ("api_key: k-123456", "k-123456"),
    ("client_secret=xyz;", "xyz"),
    ("Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi.payload.sig"),
])
def test_scrub_redacts_secrets_in_text(text, secret):
    out = scrub({"msg": text})["msg"]
    assert secret not in out and REDACTED in out


def test_scrub_leaves_ordinary_text_alone():
    assert scrub({"msg": "my_token_count=3 tokens left"})["msg"] == "my_token_count=3 tokens left"
