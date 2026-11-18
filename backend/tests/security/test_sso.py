"""OIDC single sign-on (Phase 6): provisioning, group sync, and rejection of every tampered or replayed flow."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import pytest

from tests.conftest import ADMIN_PASSWORD, ApiClient, make_client

SECRET = "mock-client-secret"


async def configure(admin: ApiClient, idp: Any, **overrides: Any) -> dict[str, Any]:
    me = (await admin.get("/api/v1/auth/me")).json()
    body = {
        "enabled": True, "display_name": "Corp SSO", "issuer": idp.issuer, "client_id": idp.client_id,
        "client_secret": SECRET,
        "group_rules": [
            {"group": "mgw-acme-admins", "tenant_id": me["tenant_id"], "roles": ["tenant_admin"]},
            {"group": "mgw-acme-developers", "tenant_id": me["tenant_id"], "roles": ["developer"]},
            {"group": "mgw-auditors", "tenant_id": me["tenant_id"], "roles": ["auditor"]},
        ],
        "platform_admin_groups": ["mgw-platform-admins"],
        **overrides,
    }
    r = await admin.put("/api/v1/sso/config", json=body)
    assert r.status_code == 200, r.text
    return r.json()


async def start(http: httpx.AsyncClient, return_to: str = "/tools") -> str:
    r = await http.get("/api/v1/auth/oidc/login", params={"return_to": return_to})
    assert r.status_code == 303, r.text
    return r.headers["location"]


async def at_idp(authorize_url: str, user: str = "alice", **extra: str) -> str:
    """Plays the browser at the IdP: returns the callback URL the IdP redirects to."""
    sep = "&" if "?" in authorize_url else "?"
    async with httpx.AsyncClient() as browser:
        r = await browser.get(authorize_url + sep + urlencode({"mock_user": user, **extra}))
    assert r.status_code == 302, r.text
    return r.headers["location"]


async def callback(http: httpx.AsyncClient, callback_url: str) -> httpx.Response:
    q = urlparse(callback_url).query
    return await http.get("/api/v1/auth/oidc/callback?" + q)


async def sso_login(http: httpx.AsyncClient, user: str = "alice", return_to: str = "/tools", **extra: str) -> httpx.Response:
    return await callback(http, await at_idp(await start(http, return_to), user, **extra))


def sso_error(r: httpx.Response) -> str | None:
    assert r.status_code == 303, r.text
    return parse_qs(urlparse(r.headers["location"]).query).get("sso_error", [None])[0]


# ---------------------------------------------------------------- happy path and group sync
async def test_login_provisions_user_with_mapped_roles(app, admin, mock_idp):
    await configure(admin, mock_idp)
    async with make_client(app) as http:
        r = await sso_login(http, "alice")
        assert r.status_code == 303 and r.headers["location"] == "/tools"
        assert "mgw_session" in http.cookies and r.headers["cache-control"] == "no-store"
        me = (await http.get("/api/v1/auth/me")).json()
        assert me["auth_source"] == "oidc" and me["roles"] == ["tenant_admin"] and not me["is_platform_admin"]
        assert me["display_name"] == "Alice SSO" and me["csrf_token"]
    events = (await admin.get("/api/v1/audit/events", params={"limit": 50})).json()["items"]
    login = [e for e in events if e["event_type"] == "auth.login.succeeded" and e["metadata"].get("method") == "oidc"]
    assert login and login[0]["principal"]["name"] == "alice.sso"


async def test_group_changes_resync_roles_and_revoke_access(app, admin, mock_idp):
    await configure(admin, mock_idp)
    async with make_client(app) as http:
        await sso_login(http, "bob")
        assert (await http.get("/api/v1/auth/me")).json()["roles"] == ["auditor", "developer"]
    mock_idp.users["bob"]["groups"] = ["mgw-auditors"]
    async with make_client(app) as http:
        await sso_login(http, "bob")
        assert (await http.get("/api/v1/auth/me")).json()["roles"] == ["auditor"]
    mock_idp.users["bob"]["groups"] = []
    async with make_client(app) as http:
        assert sso_error(await sso_login(http, "bob")) == "no_access"
        assert (await http.get("/api/v1/auth/me")).status_code == 401
    me = (await admin.get("/api/v1/auth/me")).json()
    users = (await admin.get(f"/api/v1/tenants/{me['tenant_id']}/users")).json()["items"]
    assert next(u for u in users if u["username"] == "bob.sso")["status"] == "disabled"


async def test_manual_membership_is_not_touched_by_sync(app, admin, mock_idp, container):
    await configure(admin, mock_idp)
    async with make_client(app) as http:
        await sso_login(http, "bob")
    other = (await admin.post("/api/v1/tenants", json={"name": "Globex", "slug": "globex",
                                                        "admin_username": "globex-admin",
                                                        "admin_password": "Globex-Admin-Pass-1"})).json()
    r = await admin.post(f"/api/v1/tenants/{other['id']}/users", json={"username": "bob.sso", "roles": ["approver"]})
    assert r.status_code == 201, r.text
    async with make_client(app) as http:
        await sso_login(http, "bob")
    m = await container.repos.memberships.find_one(other["id"], {"user_id": r.json()["user_id"]})
    assert m["status"] == "active" and m["roles"] == ["approver"]


async def test_unmapped_user_is_denied_and_not_created(app, admin, mock_idp, container):
    await configure(admin, mock_idp)
    async with make_client(app) as http:
        assert sso_error(await sso_login(http, "carol")) == "no_access"
    assert await container.repos.users.by_username("carol.sso") is None
    denied = await container.repos.audit.col.find_one({"event_type": "auth.oidc.denied"})
    assert denied and denied["metadata"]["reason"] == "no group mapping grants access"


async def test_platform_admin_follows_idp_group(app, admin, mock_idp):
    await configure(admin, mock_idp)
    async with make_client(app) as http:
        await sso_login(http, "root")
        me = (await http.get("/api/v1/auth/me")).json()
        assert me["is_platform_admin"] and (await http.get("/api/v1/sso/config")).status_code == 200
    mock_idp.users["root"]["groups"] = []
    async with make_client(app) as http:
        assert sso_error(await sso_login(http, "root")) == "no_access"  # demoted, and no tenant mapping


async def test_groups_from_userinfo_when_missing_in_id_token(app, admin, mock_idp):
    await configure(admin, mock_idp)
    mock_idp.tamper.add("omit_groups")
    async with make_client(app) as http:
        await sso_login(http, "alice")
        assert (await http.get("/api/v1/auth/me")).json()["roles"] == ["tenant_admin"]
    mock_idp.tamper.add("userinfo_sub_mismatch")  # userinfo for a different subject must be ignored
    async with make_client(app) as http:
        assert sso_error(await sso_login(http, "bob")) == "no_access"


# ---------------------------------------------------------------- token and flow attacks
@pytest.mark.parametrize("tamper", ["nonce", "aud", "iss", "expired", "alg_none", "hs256", "wrong_key",
                                    "multi_aud_no_azp"])
async def test_tampered_id_tokens_are_rejected(app, admin, mock_idp, container, tamper):
    await configure(admin, mock_idp)
    mock_idp.tamper.add(tamper)
    async with make_client(app) as http:
        assert sso_error(await sso_login(http, "alice")) == "token_invalid"
        assert "mgw_session" not in http.cookies
        assert (await http.get("/api/v1/auth/me")).status_code == 401
    assert await container.repos.users.by_username("alice.sso") is None
    failed = await container.repos.audit.col.find_one({"event_type": "auth.oidc.failed"})
    assert failed and failed["metadata"]["error"] == "token_invalid"


async def test_state_is_single_use_and_bound_to_the_browser(app, admin, mock_idp):
    await configure(admin, mock_idp)
    async with make_client(app) as http:
        cb = await at_idp(await start(http), "alice")
        assert (await callback(http, cb)).headers["location"] == "/tools"
        assert sso_error(await callback(http, cb)) == "state_invalid"  # replay
    async with make_client(app) as victim, make_client(app) as attacker:
        cb = await at_idp(await start(attacker), "alice")  # attacker's own flow...
        assert sso_error(await callback(victim, cb)) == "state_invalid"  # ...cannot be completed in another browser
        assert "mgw_session" not in victim.cookies
    async with make_client(app) as http:
        assert sso_error(await http.get("/api/v1/auth/oidc/callback", params={"code": "x", "state": "forged"})) \
            == "state_invalid"


async def test_idp_error_is_reported(app, admin, mock_idp):
    await configure(admin, mock_idp)
    async with make_client(app) as http:
        assert sso_error(await sso_login(http, "alice", mock_deny="1")) == "idp_error"


@pytest.mark.parametrize("target", ["//evil.example/x", "https://evil.example", "/\\evil.example", "evil", "/api/v1/x"])
async def test_return_to_cannot_redirect_off_site(app, admin, mock_idp, target):
    await configure(admin, mock_idp)
    async with make_client(app) as http:
        r = await sso_login(http, "alice", return_to=target)
        assert r.headers["location"] == "/"


async def test_local_account_is_not_taken_over_by_matching_username(app, admin, mock_idp, container):
    await configure(admin, mock_idp)
    me = (await admin.get("/api/v1/auth/me")).json()
    r = await admin.post(f"/api/v1/tenants/{me['tenant_id']}/users",
                         json={"username": "alice.sso", "roles": ["auditor"], "password": "Local-Alice-Pass-1"})
    assert r.status_code == 201
    async with make_client(app) as http:
        assert sso_error(await sso_login(http, "alice")) == "account_conflict"
    await configure(admin, mock_idp, link_local_accounts=True)  # explicit opt-in links the accounts
    async with make_client(app) as http:
        await sso_login(http, "alice")
        assert (await http.get("/api/v1/auth/me")).json()["principal_id"] == r.json()["user_id"]
    assert await container.repos.audit.col.find_one({"event_type": "user.oidc.linked"})


async def test_sso_user_has_no_password(app, admin, mock_idp):
    await configure(admin, mock_idp)
    async with make_client(app) as http:
        await sso_login(http, "alice")
        c = ApiClient(http)
        c.csrf = (await http.get("/api/v1/auth/me")).json()["csrf_token"]
        r = await c.post("/api/v1/auth/change-password", json={"current_password": "x", "new_password": "N3w-Passw0rd!!"})
        assert r.status_code == 409
    async with make_client(app) as http:
        r = await http.post("/api/v1/auth/login", json={"username": "alice.sso", "password": "anything-at-all"})
        assert r.status_code == 401


async def test_disabled_sso_refuses_to_start(anon, admin, mock_idp):
    await configure(admin, mock_idp, enabled=False)
    assert sso_error(await anon.http.get("/api/v1/auth/oidc/login")) == "sso_disabled"
    assert (await anon.get("/api/v1/auth/oidc/config")).json() == {"enabled": False, "display_name": "Corp SSO",
                                                                   "local_login": "enabled"}


# ---------------------------------------------------------------- local login restriction
async def test_break_glass_only(app, admin, mock_idp, container):
    me = (await admin.get("/api/v1/auth/me")).json()
    await admin.post(f"/api/v1/tenants/{me['tenant_id']}/users",
                     json={"username": "dev1", "roles": ["developer"], "password": "Dev1-Local-Pass-1"})
    r = await admin.put("/api/v1/sso/config", json={
        "enabled": True, "issuer": mock_idp.issuer, "client_id": "c", "local_login": "break_glass_only",
        "break_glass_usernames": ["dev1"]})
    assert r.status_code == 422  # dev1 is not a platform administrator: would lock everyone out
    await configure(admin, mock_idp, local_login="break_glass_only", break_glass_usernames=["admin"])
    async with make_client(app) as http:
        r = await http.post("/api/v1/auth/login", json={"username": "dev1", "password": "Dev1-Local-Pass-1"})
        assert r.status_code == 401 and r.json()["error"]["code"] == "INVALID_CREDENTIAL"  # no password oracle
        r = await http.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        assert r.status_code == 200
    assert await container.repos.audit.col.find_one({"event_type": "auth.break_glass.used", "severity": "high"})
    assert (await admin.get("/api/v1/auth/oidc/config")).json()["local_login"] == "break_glass_only"


# ---------------------------------------------------------------- configuration
async def test_client_secret_is_write_only_and_encrypted(admin, mock_idp, container):
    cfg = await configure(admin, mock_idp)
    assert cfg["has_client_secret"] is True and SECRET not in str(cfg) and "client_secret_enc" not in cfg
    assert cfg["redirect_uri"].endswith("/api/v1/auth/oidc/callback")
    raw = await container.repos.settings.col.find_one({"key": "oidc"})
    assert SECRET not in str(raw) and raw["value"]["client_secret_enc"]
    # Saving without a secret keeps the stored one.
    keep = {k: v for k, v in cfg.items() if k not in ("has_client_secret", "redirect_uri", "updated_at", "updated_by")}
    assert (await admin.put("/api/v1/sso/config", json=keep)).json()["has_client_secret"] is True
    events = [e async for e in container.repos.audit.col.find({"event_type": "sso.config.updated"})]
    assert events and all(SECRET not in str(e) for e in events) and events[0]["severity"] == "high"


async def test_config_validation(admin, mock_idp, settings):
    bad_tenant = {"enabled": True, "issuer": mock_idp.issuer, "client_id": "c",
                  "group_rules": [{"group": "g", "tenant_id": "ten_missing", "roles": ["developer"]}]}
    assert (await admin.put("/api/v1/sso/config", json=bad_tenant)).status_code == 422
    bad_role = {**bad_tenant, "group_rules": [{"group": "g", "tenant_id": "x", "roles": ["platform_admin"]}]}
    assert (await admin.put("/api/v1/sso/config", json=bad_role)).status_code == 422
    assert (await admin.put("/api/v1/sso/config", json={"enabled": True, "issuer": mock_idp.issuer})).status_code == 422
    settings.oidc_allow_insecure_http = False
    r = await admin.put("/api/v1/sso/config", json={"enabled": True, "issuer": mock_idp.issuer, "client_id": "c"})
    assert r.status_code == 422 and "https" in r.json()["error"]["message"]


async def test_config_endpoints_require_platform_admin(app, admin, mock_idp):
    await configure(admin, mock_idp)
    async with make_client(app) as http:
        await sso_login(http, "alice")  # tenant_admin, not platform admin
        assert (await http.get("/api/v1/sso/config")).status_code == 403


async def test_connection_check(admin, mock_idp):
    await configure(admin, mock_idp)
    r = (await admin.post("/api/v1/sso/test")).json()
    assert r["ok"] and r["signing_keys"] == 1 and r["algorithm_overlap"] == ["RS256"]
