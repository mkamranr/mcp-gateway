"""Security review fixes for SCIM and group sync: recycled userNames, group display names, admin-disabled access."""

from __future__ import annotations

from app.services.group_sync import sync_memberships
from tests.conftest import ApiClient
from tests.security.test_scim import enable, memberships
from tests.security.test_sso import configure


async def _tenant(admin: ApiClient) -> str:
    return (await admin.get("/api/v1/auth/me")).json()["tenant_id"]  # type: ignore[no-any-return]


async def _other_tenant(admin: ApiClient) -> str:
    return "ten_recycled_co"  # a second tenant: memberships only need its id


# ---------------------------------------------------------------- recycled userName
async def test_deleting_a_scim_user_disables_every_membership(app, admin, mock_idp, container):
    await configure(admin, mock_idp)
    tenant, other = await _tenant(admin), await _other_tenant(admin)
    idp = await enable(admin, app)
    u = await idp.user("j.smith@corp.example", "ext-js-1")
    await idp.group("Developers", [u["id"]], external_id="mgw-acme-developers")
    # A hand-made membership (a tenant admin granted it): group sync never touches these.
    await container.repos.memberships.insert(other, {"user_id": u["id"], "roles": ["tenant_admin"],
                                                     "status": "active", "managed_by": None})
    assert await memberships(container, u["id"]) == {tenant: ["developer"], other: ["tenant_admin"]}

    assert (await idp.req("DELETE", f"/Users/{u['id']}")).status_code == 204
    assert await memberships(container, u["id"]) == {}
    ev = await container.repos.audit.col.find_one({"event_type": "user.membership.changed", "tenant_id": other,
                                                   "resource.user_id": u["id"]})
    assert ev and ev["metadata"]["status"] == "disabled" and ev["metadata"]["reason"] == "SCIM user deleted"


async def test_a_recycled_username_inherits_nothing(app, admin, mock_idp, container):
    """UPN reuse: the IdP deletes j.smith, later provisions a different person with the same userName."""
    await configure(admin, mock_idp)
    other = await _other_tenant(admin)
    idp = await enable(admin, app, groups_authoritative=False)  # resync does nothing in this mode
    u = await idp.user("j.smith@corp.example", "ext-js-1")
    await container.repos.memberships.insert(other, {"user_id": u["id"], "roles": ["tenant_admin"],
                                                     "status": "active", "managed_by": None})
    assert (await idp.req("DELETE", f"/Users/{u['id']}")).status_code == 204

    again = await idp.user("j.smith@corp.example", "ext-js-2")
    assert again["id"] == u["id"] and again["active"]  # same record, so the audit history stays attached
    assert await memberships(container, u["id"]) == {}


async def test_recreating_also_clears_access_left_by_an_older_delete(app, admin, mock_idp, container):
    """A record deleted before this fix may still have active memberships: re-creating it clears them."""
    await configure(admin, mock_idp)
    other = await _other_tenant(admin)
    idp = await enable(admin, app)
    u = await idp.user("k.jones@corp.example", "ext-kj-1")
    await container.repos.users.update(u["id"], {"status": "disabled", "scim": {"deleted": True}})
    await container.repos.memberships.insert(other, {"user_id": u["id"], "roles": ["approver"],
                                                     "status": "active", "managed_by": None})
    await idp.user("k.jones@corp.example", "ext-kj-2")
    assert await memberships(container, u["id"]) == {}
    ev = await container.repos.audit.col.find_one({"event_type": "user.membership.changed", "tenant_id": other,
                                                   "metadata.reason": "SCIM user re-created"})
    assert ev is not None


# ---------------------------------------------------------------- group display names
async def test_group_display_name_is_not_trusted_by_default(app, admin, mock_idp, container):
    await configure(admin, mock_idp)
    tenant = await _tenant(admin)
    idp = await enable(admin, app)
    a, b = await idp.user("mallory", "ext-mallory"), await idp.user("trudy", "ext-trudy")
    # Anyone who can create a group in the IdP names it after the admin group (no externalId) ...
    await idp.group("mgw-platform-admins", [a["id"]])
    # ... or gives it the admin group's name while it has an externalId of its own.
    await idp.group("mgw-acme-admins", [b["id"]], external_id="9f1c-user-created-group")
    for x in (a, b):
        assert (await container.repos.users.get(x["id"]))["is_platform_admin"] is False
        assert await memberships(container, x["id"]) == {}

    r = await admin.get("/api/v1/scim/config")
    assert r.json()["match_group_display_name"] is False

    # Opt-in for IdPs that send no externalId: then a group without one matches by displayName. Turning it on
    # re-evaluates provisioned users at once.
    r = await admin.put("/api/v1/scim/config", json={"enabled": True, "link_claim": "sub",
                                                     "match_group_display_name": True})
    assert r.status_code == 200 and r.json()["match_group_display_name"] is True
    assert (await container.repos.users.get(a["id"]))["is_platform_admin"] is True
    # A group that has an externalId is still matched only by it.
    assert await memberships(container, b["id"]) == {}
    ev = await container.repos.audit.col.find_one({"event_type": "scim.config.updated",
                                                   "metadata.match_group_display_name": True})
    assert ev is not None

    # And off again: the access goes.
    await admin.put("/api/v1/scim/config", json={"enabled": True, "link_claim": "sub"})
    assert (await container.repos.users.get(a["id"]))["is_platform_admin"] is False
    assert tenant  # (the tenant rule for mgw-acme-admins exists; b never matched it)


# ---------------------------------------------------------------- admin-disabled memberships
async def test_group_sync_never_reenables_an_admin_disabled_membership(admin, container):
    tenant = await _tenant(admin)
    user = await container.repos.users.insert({"username": "sync-victim", "display_name": "S", "status": "active",
                                               "auth_source": "oidc", "is_platform_admin": False})
    m = await container.repos.memberships.insert(tenant, {
        "user_id": user["_id"], "roles": ["developer"], "status": "disabled", "managed_by": "oidc",
        "disabled_by_admin": True})
    for source in ("oidc", "ldap"):
        await container.repos.memberships.update(tenant, m["_id"], {"managed_by": source})
        await sync_memberships(container.repos, container.audit, user, {tenant: {"developer", "approver"}}, source)
        doc = await container.repos.memberships.get(tenant, m["_id"])
        assert doc["status"] == "disabled" and doc["roles"] == ["developer"], source

    # Control: without the flag, sync restores a source-managed membership as before.
    await container.repos.memberships.col.update_one({"_id": m["_id"]}, {"$unset": {"disabled_by_admin": ""}})
    await sync_memberships(container.repos, container.audit, user, {tenant: {"developer"}}, "ldap")
    assert (await container.repos.memberships.get(tenant, m["_id"]))["status"] == "active"
