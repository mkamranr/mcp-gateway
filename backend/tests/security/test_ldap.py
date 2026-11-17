"""LDAP / Active Directory sign-in: provisioning, group sync, local-account precedence, break-glass, and the
directory-specific attacks (filter injection, unauthenticated bind, account takeover by username)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest

from app.services.ldap_client import LdapError
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, ApiClient, make_client
from tests.ldap_fake import PEOPLE, SVC_PASSWORD, FakeDirectory, config, group

PW = "Alice-Directory-Pw1"  # noqa: S105


@pytest.fixture
def directory(container: Any) -> FakeDirectory:
    d = FakeDirectory()
    container.ldap.directory.opener = d.opener
    d.container = container
    return d


async def configure(admin: ApiClient, **overrides: Any) -> dict[str, Any]:
    me = (await admin.get("/api/v1/auth/me")).json()
    r = await admin.put("/api/v1/ldap/config", json=config(me["tenant_id"], **overrides))
    assert r.status_code == 200, r.text
    return r.json()


async def sign_in(app: Any, username: str, password: str) -> tuple[int, dict[str, Any], ApiClient | None]:
    http = make_client(app)
    r = await http.post("/api/v1/auth/login", json={"username": username, "password": password})
    if r.status_code != 200:
        await http.aclose()
        return r.status_code, r.json(), None
    c = ApiClient(http)
    c.csrf = r.json()["csrf_token"]
    return 200, r.json(), c


@asynccontextmanager
async def closing(c: ApiClient | None) -> AsyncIterator[ApiClient]:
    assert c is not None
    try:
        yield c
    finally:
        await c.http.aclose()


async def events(directory: FakeDirectory, event_type: str) -> list[dict[str, Any]]:
    """Newest first, across tenants (sign-in failures are recorded before a tenant is known)."""
    c = directory.container
    return [d async for d in c.repos.audit.col.find({"event_type": event_type}).sort("timestamp", -1)]


# ---------------------------------------------------------------- configuration
async def test_config_secret_is_write_only_and_audited(admin, directory):
    out = await configure(admin)
    assert out["has_bind_password"] is True and "bind_password" not in out
    assert SVC_PASSWORD not in (await admin.get("/api/v1/ldap/config")).text
    # Saving again without the password keeps it.
    me = (await admin.get("/api/v1/auth/me")).json()
    body = config(me["tenant_id"], display_name="Corp AD")
    body.pop("bind_password")
    r = await admin.put("/api/v1/ldap/config", json=body)
    assert r.status_code == 200 and r.json()["has_bind_password"] is True
    ev = await events(directory, "ldap.config.updated")
    assert ev and "display_name" in ev[0]["metadata"]["changed"]
    assert SVC_PASSWORD not in str(ev)


@pytest.mark.parametrize("override", [
    {"server_urls": ["ldap://ldap.corp.example"]},  # clear text without StartTLS
    {"server_urls": ["https://ldap.corp.example"]},
    {"server_urls": ["ldaps://ldap.corp.example"], "start_tls": True},
    {"user_filter": "(uid=alice)"},  # no {username}
    {"user_filter": "(&(uid={username})"},  # unbalanced
    {"user_filter": "(&(uid={username})(x={0}))"},  # stray placeholder
    {"group_search_filter": "(member=x)"},
    {"user_search_base": "not a dn"},
    {"platform_admin_groups": ["MGW Platform"]},  # not a DN
    {"ca_pem": "not a certificate"},
    {"enabled": True, "server_urls": []},
    {"local_login": "break_glass_only", "break_glass_usernames": []},
])
async def test_config_rejects_unsafe_or_invalid_values(admin, directory, override):
    me = (await admin.get("/api/v1/auth/me")).json()
    r = await admin.put("/api/v1/ldap/config", json=config(me["tenant_id"], **override))
    assert r.status_code in (400, 422), (override, r.text)


async def test_config_group_rules_need_dns_and_known_tenants(admin, directory):
    me = (await admin.get("/api/v1/auth/me")).json()
    r = await admin.put("/api/v1/ldap/config", json=config(me["tenant_id"], group_rules=[
        {"group": "MGW Admins", "tenant_id": me["tenant_id"], "roles": ["developer"]}]))
    assert r.status_code in (400, 422)
    r = await admin.put("/api/v1/ldap/config", json=config(me["tenant_id"], group_rules=[
        {"group": group("x"), "tenant_id": "no-such-tenant", "roles": ["developer"]}]))
    assert r.status_code == 422 and "Unknown tenant" in r.text


async def test_config_requires_platform_admin(app, admin, directory):
    me = (await admin.get("/api/v1/auth/me")).json()
    r = await admin.post(f"/api/v1/tenants/{me['tenant_id']}/users",
                         json={"username": "dev1", "password": "Developer-Pass-123", "roles": ["tenant_admin"]})
    assert r.status_code == 201, r.text
    status, _, dev = await sign_in(app, "dev1", "Developer-Pass-123")
    assert status == 200 and dev is not None
    async with closing(dev):
        assert (await dev.get("/api/v1/ldap/config")).status_code == 403
        assert (await dev.put("/api/v1/ldap/config", json={})).status_code == 403


# ---------------------------------------------------------------- sign-in and provisioning
async def test_directory_user_is_provisioned_with_mapped_roles(app, admin, directory):
    directory.person("alice", PW, groups=("CN=MGW Admins, OU=Groups, DC=corp, DC=example",),  # DN case/spacing
                     mail="Alice@Corp.Example", name="Alice Directory")
    await configure(admin)
    status, me, c = await sign_in(app, "Alice", PW)
    assert status == 200, me
    async with closing(c):
        me = (await c.get("/api/v1/auth/me")).json()
    assert me["auth_source"] == "ldap" and me["roles"] == ["tenant_admin"] and not me["is_platform_admin"]
    assert me["display_name"] == "Alice Directory"
    login = [e for e in await events(directory, "auth.login.succeeded") if e["metadata"].get("method") == "ldap"]
    assert login and login[0]["principal"]["name"] == "alice"
    assert await events(directory, "user.ldap.provisioned")


async def test_group_search_mode(app, admin, directory):
    dn = directory.person("gina", PW)
    directory.add(group("MGW Developers"), {"objectClass": "groupOfNames", "cn": "MGW Developers", "member": [dn]})
    await configure(admin, group_membership_attribute="", group_search_base="ou=groups,dc=corp,dc=example")
    status, me, c = await sign_in(app, "gina", PW)
    assert status == 200, me
    async with closing(c):
        assert (await c.get("/api/v1/auth/me")).json()["roles"] == ["developer"]


async def test_wrong_and_empty_password_never_authenticate(app, admin, directory, container):
    dn = directory.person("alice", PW, groups=(group("MGW Admins"),))
    await configure(admin)
    status, body, _ = await sign_in(app, "alice", "wrong-password")
    assert status == 401 and body["error"]["code"] == "INVALID_CREDENTIAL"
    failed = [e for e in await events(directory, "auth.login.failed") if e["metadata"].get("method") == "ldap"]
    assert failed and "wrong-password" not in str(failed)
    # An empty password would be an "unauthenticated bind" that many directories report as success.
    directory.binds.clear()
    cfg = await container.ldap.admin_view()
    with pytest.raises(LdapError) as exc:
        container.ldap.directory.authenticate(cfg, SVC_PASSWORD, "alice", "")
    assert exc.value.code == "invalid_credentials" and dn not in directory.binds and not directory.binds


@pytest.mark.parametrize("username", ["*", "al*", "alice)(uid=*", "*)(|(uid=*", "alice\x00", "a" * 300])
async def test_filter_injection_is_escaped(app, admin, directory, username):
    directory.person("alice", PW, groups=(group("MGW Admins"),))
    directory.person("bob", PW, groups=(group("MGW Admins"),))
    await configure(admin)
    status, _, _ = await sign_in(app, username, PW)
    assert status in (401, 422)
    assert f"uid=alice,{PEOPLE}" not in directory.binds and f"uid=bob,{PEOPLE}" not in directory.binds


async def test_local_account_takes_precedence_over_directory(app, admin, directory):
    me = (await admin.get("/api/v1/auth/me")).json()
    r = await admin.post(f"/api/v1/tenants/{me['tenant_id']}/users",
                         json={"username": "bob", "password": "Local-Bob-Pass-123", "roles": ["developer"]})
    assert r.status_code == 201, r.text
    directory.person("bob", "Directory-Bob-1", groups=(group("MGW Platform"),))
    await configure(admin)
    assert (await sign_in(app, "bob", "Directory-Bob-1"))[0] == 401  # never reaches the directory
    status, body, c = await sign_in(app, "bob", "Local-Bob-Pass-123")
    assert status == 200 and body["auth_source"] == "local" and not body["is_platform_admin"]
    await c.http.aclose()
    assert f"uid=bob,{PEOPLE}" not in directory.binds


async def test_directory_cannot_take_over_an_account_through_another_login_name(app, admin, directory):
    me = (await admin.get("/api/v1/auth/me")).json()
    r = await admin.post(f"/api/v1/tenants/{me['tenant_id']}/users",
                         json={"username": "carol", "password": "Local-Carol-Pass-1", "roles": ["developer"]})
    assert r.status_code == 201
    directory.person("carol", PW, mail="carol@corp.example", groups=(group("MGW Admins"),))
    await configure(admin, user_filter="(&(objectClass=person)(|(uid={username})(mail={username})))")
    status, body, _ = await sign_in(app, "carol@corp.example", PW)
    assert status == 401
    denied = [e for e in await events(directory, "auth.login.failed") if e["metadata"].get("method") == "ldap"]
    assert denied[0]["metadata"]["reason"] == "username belongs to another account"


async def test_recreated_directory_entry_does_not_inherit_the_old_account(app, admin, directory):
    directory.person("dave", PW, groups=(group("MGW Admins"),), uuid="11111111-1111-1111-1111-111111111111")
    await configure(admin)
    status, _, c = await sign_in(app, "dave", PW)
    assert status == 200
    await c.http.aclose()
    # Deleted and re-created in the directory: same name, new entryUUID.
    directory.person("dave", PW, groups=(group("MGW Admins"),), uuid="22222222-2222-2222-2222-222222222222")
    assert (await sign_in(app, "dave", PW))[0] == 401


async def test_group_changes_resync_roles_and_admin_flag(app, admin, directory):
    directory.person("erin", PW, groups=(group("MGW Admins"), group("MGW Platform")))
    await configure(admin)
    status, body, c = await sign_in(app, "erin", PW)
    assert status == 200 and body["is_platform_admin"] is True
    await c.http.aclose()
    directory.set_groups("erin", (group("MGW Developers"),))
    status, body, c = await sign_in(app, "erin", PW)
    assert status == 200 and body["is_platform_admin"] is False and body["roles"] == ["developer"]
    await c.http.aclose()
    directory.set_groups("erin", ())
    status, body, _ = await sign_in(app, "erin", PW)
    assert status == 403  # no group maps to any tenant any more
    changed = await events(directory, "user.platform_admin.changed")
    assert changed and changed[0]["metadata"] == {"is_platform_admin": False, "source": "ldap"}


async def test_manual_memberships_are_never_touched_by_sync(app, admin, directory, container):
    directory.person("fay", PW, groups=(group("MGW Developers"),))
    await configure(admin)
    assert (await sign_in(app, "fay", PW))[0] == 200
    user = await container.repos.users.by_username("fay")
    other = (await admin.post("/api/v1/tenants", json={"name": "Other", "slug": "other",
                                                       "admin_username": "other-admin",
                                                       "admin_password": "Other-Admin-Pass-1"})).json()
    await container.repos.memberships.insert(other["id"], {"user_id": user["_id"], "roles": ["auditor"],
                                                           "status": "active", "managed_by": "manual"})
    directory.set_groups("fay", ())
    status, body, c = await sign_in(app, "fay", PW)
    assert status == 200 and body["tenant_id"] == other["id"] and body["roles"] == ["auditor"]
    await c.http.aclose()


async def test_jit_off_and_disabled_directory(app, admin, directory):
    directory.person("hank", PW, groups=(group("MGW Admins"),))
    await configure(admin, jit_provisioning=False)
    assert (await sign_in(app, "hank", PW))[0] == 401
    await configure(admin, jit_provisioning=True)
    status, _, c = await sign_in(app, "hank", PW)
    assert status == 200
    await c.http.aclose()
    await configure(admin, enabled=False)
    assert (await sign_in(app, "hank", PW))[0] == 401  # directory accounts have no local password


async def test_disabled_account_is_refused(app, admin, directory, container):
    directory.person("ivy", PW, groups=(group("MGW Admins"),))
    await configure(admin)
    assert (await sign_in(app, "ivy", PW))[0] == 200
    user = await container.repos.users.by_username("ivy")
    await container.repos.users.update(user["_id"], {"status": "disabled"})
    assert (await sign_in(app, "ivy", PW))[0] == 401


async def test_directory_outage_keeps_local_admins_working(app, admin, directory):
    directory.person("jack", PW, groups=(group("MGW Admins"),))
    await configure(admin)
    directory.down = True
    status, body, _ = await sign_in(app, "jack", PW)
    assert status == 503 and body["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
    assert (await events(directory, "auth.ldap.failed"))[0]["severity"] == "high"
    status, _, c = await sign_in(app, ADMIN_USER, ADMIN_PASSWORD)
    assert status == 200
    await c.http.aclose()


async def test_break_glass_only_restricts_local_passwords(app, admin, directory):
    me = (await admin.get("/api/v1/auth/me")).json()
    r = await admin.post(f"/api/v1/tenants/{me['tenant_id']}/users",
                         json={"username": "local-dev", "password": "Local-Dev-Pass-123", "roles": ["developer"]})
    assert r.status_code == 201
    directory.person("kim", PW, groups=(group("MGW Developers"),))
    r = await admin.put("/api/v1/ldap/config", json=config(me["tenant_id"], local_login="break_glass_only",
                                                           break_glass_usernames=["local-dev"]))
    assert r.status_code == 422  # not a platform administrator: would leave no working break-glass account
    await configure(admin, local_login="break_glass_only", break_glass_usernames=[ADMIN_USER])
    status, body, _ = await sign_in(app, "local-dev", "Local-Dev-Pass-123")
    assert status == 403 and "directory" in body["error"]["message"]
    for user, pw in ((ADMIN_USER, ADMIN_PASSWORD), ("kim", PW)):
        status, _, c = await sign_in(app, user, pw)
        assert status == 200, user
        await c.http.aclose()
    assert await events(directory, "auth.break_glass.used")


async def test_directory_users_cannot_set_a_local_password(app, admin, directory):
    directory.person("liam", PW, groups=(group("MGW Admins"),))
    await configure(admin)
    _, _, c = await sign_in(app, "liam", PW)
    async with closing(c):
        r = await c.post("/api/v1/auth/change-password", json={"current_password": PW,
                                                                "new_password": "Brand-New-Pass-123"})
    assert r.status_code == 409


async def test_test_endpoint_explains_access_without_a_password(admin, directory):
    directory.person("mia", PW, groups=(group("MGW Developers"), group("Unrelated")), mail="mia@corp.example")
    await configure(admin)
    r = await admin.post("/api/v1/ldap/test", json={"username": "mia"})
    assert r.status_code == 200, r.text
    out = r.json()
    me = (await admin.get("/api/v1/auth/me")).json()
    assert out["ok"] and out["user"]["grants"] == {me["tenant_id"]: ["developer"]}
    assert out["user"]["email"] == "mia@corp.example" and out["user"]["platform_admin"] is False
    assert (await admin.post("/api/v1/ldap/test", json={"username": "nobody"})).json()["user"] is None
    assert (await admin.post("/api/v1/ldap/test")).json() == {"ok": True, "server": "ldaps://ldap.corp.example"}
    directory.down = True
    assert (await admin.post("/api/v1/ldap/test")).json()["error"] == "unavailable"


async def test_wrong_service_password_is_a_config_error(app, admin, directory):
    directory.person("noah", PW, groups=(group("MGW Admins"),))
    await configure(admin, bind_password="not-the-service-password")
    r = await admin.post("/api/v1/ldap/test")
    assert r.json()["ok"] is False and r.json()["error"] == "config"
    assert (await sign_in(app, "noah", PW))[0] == 503


async def test_public_config(anon, admin, directory):
    assert (await anon.get("/api/v1/auth/ldap/config")).json() == {"enabled": False, "display_name": "Directory account"}
    await configure(admin, display_name="Corp AD")
    assert (await anon.get("/api/v1/auth/ldap/config")).json() == {"enabled": True, "display_name": "Corp AD"}
