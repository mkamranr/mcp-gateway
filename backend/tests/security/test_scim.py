"""SCIM 2.0 provisioning (docs/scim.md): the IdP manages users and groups, and the token can reach nothing else."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.conftest import ADMIN_USER, ApiClient, make_client
from tests.security.test_sso import configure, sso_error, sso_login

BASE = "/api/v1/scim/v2"
USER = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"


class Idp:
    """Plays the identity provider's SCIM client."""

    def __init__(self, app: Any, token: str) -> None:
        self.app, self.token = app, token

    async def req(self, method: str, path: str, body: Any = None, token: str | None = None, **kw: Any) -> Any:
        async with make_client(self.app) as http:
            headers = {"Authorization": f"Bearer {token if token is not None else self.token}",
                       "Content-Type": "application/scim+json"}
            content = json.dumps(body) if body is not None and not isinstance(body, bytes) else body
            return await http.request(method, BASE + path, content=content, headers=headers, **kw)

    async def user(self, user_name: str, external_id: str | None = None, **extra: Any) -> dict[str, Any]:
        r = await self.req("POST", "/Users", {"schemas": [USER], "userName": user_name, "externalId": external_id,
                                              "active": True, **extra})
        assert r.status_code == 201, r.text
        return r.json()  # type: ignore[no-any-return]

    async def group(self, name: str, members: list[str], external_id: str | None = None) -> dict[str, Any]:
        r = await self.req("POST", "/Groups", {"schemas": [GROUP], "displayName": name, "externalId": external_id,
                                               "members": [{"value": m} for m in members]})
        assert r.status_code == 201, r.text
        return r.json()  # type: ignore[no-any-return]

    async def patch(self, kind: str, obj_id: str, *ops: dict[str, Any]) -> Any:
        return await self.req("PATCH", f"/{kind}/{obj_id}", {"schemas": [PATCH], "Operations": list(ops)})


async def enable(admin: ApiClient, app: Any, **cfg: Any) -> Idp:
    r = await admin.post("/api/v1/scim/token")
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    r = await admin.put("/api/v1/scim/config", json={"enabled": True, "link_claim": "sub", **cfg})
    assert r.status_code == 200, r.text
    return Idp(app, token)


async def memberships(container: Any, user_id: str) -> dict[str, list[str]]:
    return {m["tenant_id"]: m["roles"] async for m in container.repos.memberships.col.find(
        {"user_id": user_id, "status": "active"})}


# ---------------------------------------------------------------- token and configuration
async def test_token_is_shown_once_and_required(app, admin, container):
    r = await admin.put("/api/v1/scim/config", json={"enabled": True})
    assert r.status_code == 422  # no token yet
    idp = await enable(admin, app)
    assert idp.token.startswith("mgw_scim_")
    view = (await admin.get("/api/v1/scim/config")).json()
    assert view["enabled"] and view["has_token"] and "token" not in view and "token_hash" not in view
    assert view["base_url"].endswith("/api/v1/scim/v2")
    assert idp.token not in json.dumps(view)

    assert (await idp.req("GET", "/Users")).status_code == 200
    for bad in ("", "mgw_scim_wrong", "Basic abc"):
        r = await idp.req("GET", "/Users", token=bad)
        assert r.status_code == 401 and r.json()["schemas"] == [ERROR], r.text
        assert r.headers["content-type"].startswith("application/scim+json")
    async with make_client(app) as http:  # an admin session is not a SCIM credential
        r = await http.get(BASE + "/Users", cookies=admin.http.cookies)
        assert r.status_code == 401

    # Rotation invalidates the old token; revocation disables SCIM.
    r = await admin.post("/api/v1/scim/token")
    new = r.json()["token"]
    assert (await idp.req("GET", "/Users")).status_code == 401
    assert (await idp.req("GET", "/Users", token=new)).status_code == 200
    r = await admin.delete("/api/v1/scim/token")
    assert r.status_code == 200 and not r.json()["enabled"]
    assert (await idp.req("GET", "/Users", token=new)).status_code == 401

    events = [e async for e in container.repos.audit.col.find({"event_type": {"$regex": "^scim\\."}})]
    assert {e["event_type"] for e in events} >= {"scim.token.rotated", "scim.config.updated", "scim.token.revoked"}
    assert all(e["severity"] == "high" for e in events)
    assert idp.token not in json.dumps(events, default=str) and new not in json.dumps(events, default=str)


async def test_only_platform_admins_configure_scim(app, admin, scenario):
    from tests.conftest import new_user_client

    s = await scenario.setup()
    tenant_admin = await new_user_client(app, admin, s.tenant_id, ["tenant_admin"])
    try:
        assert (await tenant_admin.get("/api/v1/scim/config")).status_code == 403
        assert (await tenant_admin.post("/api/v1/scim/token")).status_code == 403
    finally:
        await tenant_admin.http.aclose()


async def test_discovery_endpoints(app, admin):
    idp = await enable(admin, app)
    cfg = (await idp.req("GET", "/ServiceProviderConfig")).json()
    assert cfg["patch"]["supported"] and not cfg["bulk"]["supported"]
    types = (await idp.req("GET", "/ResourceTypes")).json()
    assert {t["id"] for t in types["Resources"]} == {"User", "Group"}
    schemas = (await idp.req("GET", "/Schemas")).json()
    assert {s["id"] for s in schemas["Resources"]} == {USER, GROUP}
    r = await idp.req("GET", "/Nope")
    assert r.status_code == 404 and r.json()["schemas"] == [ERROR]


# ---------------------------------------------------------------- users
async def test_user_lifecycle(app, admin, container):
    idp = await enable(admin, app)
    u = await idp.user("Dana@Corp.Example", "ext-dana", displayName="Dana Scully",
                       emails=[{"value": "dana@corp.example", "type": "work", "primary": True}],
                       name={"givenName": "Dana", "familyName": "Scully"})
    assert u["userName"] == "Dana@Corp.Example" and u["active"] and u["externalId"] == "ext-dana"
    assert u["meta"]["location"].endswith(f"/Users/{u['id']}") and u["emails"][0]["value"] == "dana@corp.example"
    doc = await container.repos.users.get(u["id"])
    assert doc["username"] == "dana@corp.example" and doc["auth_source"] == "oidc" and not doc.get("password_hash")
    assert not doc["is_platform_admin"]

    # Lookups as the IdPs do them.
    for flt in ('userName eq "dana@corp.example"', 'externalId eq "ext-dana"', f'id eq "{u["id"]}"'):
        r = await idp.req("GET", "/Users", params={"filter": flt})
        assert r.json()["totalResults"] == 1, (flt, r.text)
    r = await idp.req("GET", "/Users", params={"filter": 'userName eq "nobody"'})
    assert r.json()["totalResults"] == 0 and r.json()["Resources"] == []
    r = await idp.req("GET", "/Users", params={"filter": 'title co "x"'})
    assert r.status_code == 400 and r.json()["scimType"] == "invalidFilter"

    r = await idp.req("POST", "/Users", {"schemas": [USER], "userName": "dana@corp.example"})
    assert r.status_code == 409 and r.json()["scimType"] == "uniqueness"

    # Entra ID style PATCH: capitalised op, no path, string booleans, attributes we don't keep.
    r = await idp.patch("Users", u["id"], {"op": "Replace", "path": "displayName", "value": "Dana K. Scully"},
                        {"op": "Add", "value": {"title": "Agent", "name.givenName": "Dana K."}},
                        {"op": "replace", "path": 'emails[type eq "work"].value', "value": "dks@corp.example"})
    assert r.status_code == 200, r.text
    assert r.json()["displayName"] == "Dana K. Scully" and r.json()["name"]["givenName"] == "Dana K."
    assert r.json()["emails"][0]["value"] == "dks@corp.example"

    r = await idp.req("PUT", f"/Users/{u['id']}", {"schemas": [USER], "userName": "dana@corp.example",
                                                    "externalId": "ext-dana", "active": True})
    assert r.status_code == 200 and r.json()["active"]

    r = await idp.req("DELETE", f"/Users/{u['id']}")
    assert r.status_code == 204
    assert (await idp.req("GET", f"/Users/{u['id']}")).status_code == 404
    assert (await container.repos.users.get(u["id"]))["status"] == "disabled"
    again = await idp.user("dana@corp.example", "ext-dana")  # re-provisioned: same record, history kept
    assert again["id"] == u["id"] and again["active"]
    types = {e["event_type"] async for e in container.repos.audit.col.find({"resource.user_id": u["id"]})}
    assert {"user.scim.created", "user.scim.updated", "user.scim.deleted"} <= types


async def test_scim_cannot_see_or_take_over_other_accounts(app, admin, container):
    idp = await enable(admin, app)
    local = await container.repos.users.by_username(ADMIN_USER)
    r = await idp.req("POST", "/Users", {"schemas": [USER], "userName": ADMIN_USER, "active": False})
    assert r.status_code == 409
    listed = (await idp.req("GET", "/Users")).json()
    assert all(x["id"] != local["_id"] for x in listed["Resources"]) and listed["totalResults"] == 0
    assert (await idp.req("GET", f"/Users/{local['_id']}")).status_code == 404
    r = await idp.patch("Users", local["_id"], {"op": "replace", "path": "active", "value": False})
    assert r.status_code == 404
    assert (await idp.req("DELETE", f"/Users/{local['_id']}")).status_code == 404
    u = await idp.user("eve", "ext-eve")
    r = await idp.patch("Users", u["id"], {"op": "replace", "path": "userName", "value": ADMIN_USER})
    assert r.status_code == 409
    # Local admins can't be added to SCIM groups (and so get no roles through them).
    g = await idp.group("mgw-platform-admins", [local["_id"], u["id"]])
    assert [m["value"] for m in g["members"]] == [u["id"]]
    assert (await container.repos.users.get(local["_id"]))["status"] == "active"
    # The admin console still works.
    assert (await admin.get("/api/v1/auth/me")).status_code == 200


async def test_deactivation_ends_sessions_at_once(app, admin, mock_idp, container):
    await configure(admin, mock_idp)
    idp = await enable(admin, app)
    u = await idp.user("bob.sso", "u-1002")
    await idp.group("mgw-acme-developers", [u["id"]])
    async with make_client(app) as http:
        r = await sso_login(http, "bob")
        assert sso_error(r) is None
        me = (await http.get("/api/v1/auth/me")).json()
        assert me["principal_id"] == u["id"]
        r = await idp.patch("Users", u["id"], {"op": "Replace", "path": "active", "value": "False"})
        assert r.status_code == 200 and r.json()["active"] is False
        assert (await http.get("/api/v1/auth/me")).status_code == 401
        assert sso_error(await sso_login(http, "bob")) is not None  # and can't sign in again
    ev = await container.repos.audit.col.find_one({"event_type": "user.scim.deactivated"})
    assert ev and ev["severity"] == "high"


# ---------------------------------------------------------------- groups -> roles
async def test_groups_drive_memberships_and_platform_admin(app, admin, mock_idp, container):
    await configure(admin, mock_idp)
    tenant = (await admin.get("/api/v1/auth/me")).json()["tenant_id"]
    idp = await enable(admin, app)
    a, b = await idp.user("frank", "ext-frank"), await idp.user("grace", "ext-grace")
    dev = await idp.group("Developers", [a["id"]], external_id="mgw-acme-developers")  # matched by externalId
    assert await memberships(container, a["id"]) == {tenant: ["developer"]}
    assert await memberships(container, b["id"]) == {}

    r = await idp.patch("Groups", dev["id"], {"op": "add", "path": "members", "value": [{"value": b["id"]}]})
    assert r.status_code == 204
    assert await memberships(container, b["id"]) == {tenant: ["developer"]}
    r = await idp.patch("Groups", dev["id"], {"op": "remove", "path": f'members[value eq "{a["id"]}"]'})
    assert r.status_code == 204
    assert await memberships(container, a["id"]) == {}
    # Entra ID removes with a value list.
    r = await idp.patch("Groups", dev["id"], {"op": "Remove", "path": "members", "value": [{"value": b["id"]}]})
    assert r.status_code == 204 and await memberships(container, b["id"]) == {}

    admins = await idp.group("mgw-platform-admins", [a["id"]])
    assert (await container.repos.users.get(a["id"]))["is_platform_admin"] is True
    r = await idp.req("GET", f"/Groups/{admins['id']}", params={"excludedAttributes": "members"})
    assert "members" not in r.json()
    r = await idp.req("GET", "/Groups", params={"filter": 'displayName eq "mgw-platform-admins"'})
    assert r.json()["totalResults"] == 1
    assert (await idp.req("DELETE", f"/Groups/{admins['id']}")).status_code == 204
    assert (await container.repos.users.get(a["id"]))["is_platform_admin"] is False

    # Renaming a group re-evaluates its members.
    await idp.patch("Groups", dev["id"], {"op": "add", "path": "members", "value": [{"value": a["id"]}]})
    assert await memberships(container, a["id"]) == {tenant: ["developer"]}
    await idp.patch("Groups", dev["id"], {"op": "replace", "value": {"externalId": "mgw-auditors"}})
    assert await memberships(container, a["id"]) == {tenant: ["auditor"]}
    # Deleting the user drops it from every group.
    await idp.req("DELETE", f"/Users/{a['id']}")
    g = (await idp.req("GET", f"/Groups/{dev['id']}")).json()
    assert g["members"] == [] and await memberships(container, a["id"]) == {}


# ---------------------------------------------------------------- single sign-on
async def test_sso_links_by_external_id_and_scim_groups_win(app, admin, mock_idp, container):
    await configure(admin, mock_idp)
    tenant = (await admin.get("/api/v1/auth/me")).json()["tenant_id"]
    idp = await enable(admin, app)
    u = await idp.user("bob.sso", "u-1002", displayName="Bob (HR)")
    await idp.group("mgw-auditors", [u["id"]])  # the ID token says developers + auditors
    async with make_client(app) as http:
        assert sso_error(await sso_login(http, "bob")) is None
        me = (await http.get("/api/v1/auth/me")).json()
        assert me["principal_id"] == u["id"] and me["roles"] == ["auditor"]
        assert me["display_name"] == "Bob (HR)"  # the profile is SCIM's too
    doc = await container.repos.users.get(u["id"])
    assert doc["oidc"]["subject"] == "u-1002"
    assert await container.repos.users.col.count_documents({"username": "bob.sso"}) == 1
    assert await memberships(container, u["id"]) == {tenant: ["auditor"]}
    ev = await container.repos.audit.col.find_one({"event_type": "user.oidc.linked"})
    assert ev["metadata"]["source"] == "scim"


async def test_sso_never_links_by_username_alone(app, admin, mock_idp, container):
    await configure(admin, mock_idp)
    idp = await enable(admin, app)
    u = await idp.user("bob.sso", "someone-else")
    async with make_client(app) as http:
        assert sso_error(await sso_login(http, "bob")) == "account_conflict"
    assert not (await container.repos.users.get(u["id"])).get("oidc")


async def test_groups_from_the_id_token_when_scim_is_not_authoritative(app, admin, mock_idp, container):
    await configure(admin, mock_idp)
    tenant = (await admin.get("/api/v1/auth/me")).json()["tenant_id"]
    idp = await enable(admin, app, groups_authoritative=False)
    u = await idp.user("bob.sso", "u-1002")
    await idp.group("mgw-acme-admins", [u["id"]])
    assert await memberships(container, u["id"]) == {}  # SCIM groups ignored
    async with make_client(app) as http:
        assert sso_error(await sso_login(http, "bob")) is None
        assert sorted((await http.get("/api/v1/auth/me")).json()["roles"]) == ["auditor", "developer"]
    assert await memberships(container, u["id"]) == {tenant: ["auditor", "developer"]}


@pytest.mark.parametrize("body", [b"{not json", b"[]", json.dumps({"schemas": [PATCH]}).encode()])
async def test_malformed_requests_get_scim_errors(app, admin, body):
    idp = await enable(admin, app)
    u = await idp.user("henry")
    r = await idp.req("PATCH", f"/Users/{u['id']}", body)
    assert r.status_code == 400 and r.json()["schemas"] == [ERROR], r.text
