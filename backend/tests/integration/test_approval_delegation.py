"""Approval delegation, approver groups, escalation and expiry reminders."""

from datetime import timedelta

from conftest import new_user_client

from app.core.ids import utcnow

EMAIL = {"to": "cfo@example.com", "subject": "Report", "body": "Quarterly numbers"}


async def _setup(scenario, **policy):
    s = await scenario.setup(enable={"send_email": "high"})
    await s.allow(["send_email"], require_approval=True, **policy)
    return s


async def _pending(s):
    r = await s.invoke("send_email", EMAIL)
    assert r.status_code == 202, r.text
    return r.json()["approval_id"]


async def _user(app, s, roles, username=None):
    client = await new_user_client(app, s.admin, s.tenant_id, roles, username)
    me = (await client.get("/api/v1/auth/me")).json()
    return client, me["principal_id"]


def _window(start_minutes=-1, end_minutes=60):
    now = utcnow()
    return {"starts_at": (now + timedelta(minutes=start_minutes)).isoformat(),
            "ends_at": (now + timedelta(minutes=end_minutes)).isoformat()}


async def _delegate(client, delegate_id, **window):
    return await client.post("/api/v1/approvals/delegations",
                             json={"delegate_user_id": delegate_id, "reason": "Annual leave", **(window or _window())})


async def test_delegate_without_approver_role_approves_on_behalf(scenario, app, container):
    s = await _setup(scenario)
    approval_id = await _pending(s)
    alice, alice_id = await _user(app, s, ["approver"], "alice.approver")
    bob, bob_id = await _user(app, s, ["auditor"], "bob.cover")
    try:
        r = await bob.post(f"/api/v1/approvals/{approval_id}/approve", json={})
        assert r.status_code == 403  # no authority of his own

        r = await _delegate(alice, bob_id)
        assert r.status_code == 201, r.text
        delegation = r.json()
        assert delegation["status"] == "active" and delegation["delegator_user_id"] == alice_id
        assert delegation["delegate_name"] == "bob.cover"

        detail = (await bob.get(f"/api/v1/approvals/{approval_id}")).json()
        assert detail["can_decide"] is True
        assert detail["decide_as"]["on_behalf_of"] == alice_id
        assert detail["decide_as"]["delegation_id"] == delegation["id"]

        r = await bob.post(f"/api/v1/approvals/{approval_id}/approve", json={"comment": "covering for Alice"})
        assert r.status_code == 200 and r.json()["status"] == "APPROVED", r.text
        entry = r.json()["approvals"][0]
        assert entry["approver_id"] == bob_id and entry["on_behalf_of"] == alice_id
        assert entry["delegation_id"] == delegation["id"]

        ev = await container.repos.audit.col.find_one({"approval_id": approval_id, "event_type": "approval.approved"})
        assert ev["principal"]["id"] == bob_id and ev["metadata"]["on_behalf_of"] == alice_id
        created = await container.repos.audit.col.find_one({"event_type": "approval.delegation.created",
                                                            "tenant_id": s.tenant_id})
        assert created["metadata"]["delegate_user_id"] == bob_id
    finally:
        await alice.http.aclose()
        await bob.http.aclose()


async def test_scheduled_or_revoked_delegation_grants_nothing(scenario, app):
    s = await _setup(scenario)
    approval_id = await _pending(s)
    alice, _ = await _user(app, s, ["approver"])
    bob, bob_id = await _user(app, s, ["auditor"])
    try:
        future = (await _delegate(alice, bob_id, **_window(60, 120))).json()
        assert future["status"] == "scheduled"
        assert (await bob.post(f"/api/v1/approvals/{approval_id}/approve", json={})).status_code == 403

        now = (await _delegate(alice, bob_id)).json()
        r = await alice.delete(f"/api/v1/approvals/delegations/{now['id']}")
        assert r.status_code == 200 and r.json()["status"] == "revoked"
        assert (await alice.delete(f"/api/v1/approvals/delegations/{now['id']}")).status_code == 409
        assert (await bob.post(f"/api/v1/approvals/{approval_id}/approve", json={})).status_code == 403
    finally:
        await alice.http.aclose()
        await bob.http.aclose()


async def test_one_persons_authority_never_counts_twice(scenario, app):
    """Two-person rule: once Alice approved, her delegate can't add a second approval in her name."""
    s = await _setup(scenario, required_approvals=2)
    approval_id = await _pending(s)
    alice, _ = await _user(app, s, ["approver"], "alice.two")
    bob, bob_id = await _user(app, s, ["auditor"])
    carol, _ = await _user(app, s, ["approver"])
    try:
        await _delegate(alice, bob_id)
        r = await alice.post(f"/api/v1/approvals/{approval_id}/approve", json={})
        assert r.status_code == 200 and r.json()["status"] == "PENDING"
        r = await bob.post(f"/api/v1/approvals/{approval_id}/approve", json={})
        assert r.status_code == 403
        assert "alice.two has already approved" in r.json()["error"]["message"]
        r = await carol.post(f"/api/v1/approvals/{approval_id}/approve", json={})
        assert r.status_code == 200 and r.json()["status"] == "APPROVED"
    finally:
        for c in (alice, bob, carol):
            await c.http.aclose()


async def test_delegate_acting_for_the_requester_is_separation_of_duties(scenario, app):
    """The admin owns the requesting agent; a delegate can't use the admin's authority to approve it."""
    s = await _setup(scenario)
    approval_id = await _pending(s)
    bob, bob_id = await _user(app, s, ["auditor"])
    try:
        assert (await _delegate(s.admin, bob_id)).status_code == 201
        r = await bob.post(f"/api/v1/approvals/{approval_id}/approve", json={})
        assert r.status_code == 403 and r.json()["error"]["code"] == "SEPARATION_OF_DUTIES"
        detail = (await bob.get(f"/api/v1/approvals/{approval_id}")).json()
        assert detail["can_decide"] is False and "Separation" in detail["cannot_decide_reason"]
    finally:
        await bob.http.aclose()


async def test_delegations_do_not_chain_and_follow_the_delegators_current_roles(scenario, app):
    s = await _setup(scenario)
    approval_id = await _pending(s)
    alice, alice_id = await _user(app, s, ["approver"])
    bob, bob_id = await _user(app, s, ["auditor"])
    carol, carol_id = await _user(app, s, ["auditor"])
    try:
        assert (await _delegate(alice, bob_id)).status_code == 201
        # Bob holds delegated authority only; he cannot pass it on.
        r = await _delegate(bob, carol_id)
        assert r.status_code == 422 and r.json()["error"]["details"][0]["code"] == "not_an_approver"
        # Alice loses the approver role: the delegation now carries nothing.
        r = await s.admin.patch(f"/api/v1/tenants/{s.tenant_id}/users/{alice_id}", json={"roles": ["auditor"]})
        assert r.status_code == 200, r.text
        assert (await bob.post(f"/api/v1/approvals/{approval_id}/approve", json={})).status_code == 403
    finally:
        for c in (alice, bob, carol):
            await c.http.aclose()


async def test_delegation_validation_and_visibility(scenario, app):
    s = await scenario.setup()
    alice, alice_id = await _user(app, s, ["approver"])
    bob, bob_id = await _user(app, s, ["auditor"])
    eve, eve_id = await _user(app, s, ["approver"])
    try:
        assert (await _delegate(alice, alice_id)).status_code == 422  # self
        r = await _delegate(alice, bob_id, **_window(0, 60 * 24 * 91))
        assert r.status_code == 422 and r.json()["error"]["details"][0]["code"] == "too_long"
        assert (await _delegate(alice, bob_id, **_window(-120, -60))).status_code == 422  # already over
        assert (await _delegate(alice, "usr_doesnotexist")).status_code == 422
        # Only administrators delegate someone else's authority.
        r = await eve.post("/api/v1/approvals/delegations",
                           json={"delegate_user_id": bob_id, "delegator_user_id": alice_id, **_window()})
        assert r.status_code == 403
        r = await s.admin.post("/api/v1/approvals/delegations",
                               json={"delegate_user_id": bob_id, "delegator_user_id": alice_id, **_window()})
        assert r.status_code == 201 and r.json()["created_by"] != alice_id
        dlg = r.json()

        mine = (await alice.get("/api/v1/approvals/delegations")).json()["items"]
        assert [d["id"] for d in mine] == [dlg["id"]]
        assert [d["id"] for d in (await bob.get("/api/v1/approvals/delegations")).json()["items"]] == [dlg["id"]]
        assert (await eve.get("/api/v1/approvals/delegations")).json()["items"] == []
        assert (await eve.get("/api/v1/approvals/delegations?scope=all")).status_code == 403
        assert len((await s.admin.get("/api/v1/approvals/delegations?scope=all")).json()["items"]) == 1
        assert (await eve.delete(f"/api/v1/approvals/delegations/{dlg['id']}")).status_code == 404

        names = {c["id"]: c for c in (await alice.get("/api/v1/approvals/delegations/candidates")).json()["items"]}
        assert alice_id not in names and bob_id in names and names[eve_id]["can_approve"] is True
        assert "password_hash" not in str(names)
    finally:
        for c in (alice, bob, eve):
            await c.http.aclose()


async def test_approver_groups_restrict_who_may_approve(scenario, app, container):
    s = await _setup(scenario, approver_groups=["hr-approvers"])
    approval_id = await _pending(s)
    alice, alice_id = await _user(app, s, ["approver"])
    try:
        r = await alice.post(f"/api/v1/approvals/{approval_id}/approve", json={})
        assert r.status_code == 403 and "hr-approvers" in r.json()["error"]["message"]
        # Groups come from the user's last SSO login.
        await container.repos.users.col.update_one({"_id": alice_id}, {"$set": {"last_oidc_groups": ["hr-approvers"]}})
        r = await alice.post(f"/api/v1/approvals/{approval_id}/approve", json={})
        assert r.status_code == 200 and r.json()["status"] == "APPROVED"
    finally:
        await alice.http.aclose()


async def test_escalation_opens_the_request_to_escalation_roles(scenario, app, container):
    s = await _setup(scenario, approver_roles=["approver"], escalate_after_minutes=30,
                     escalation_roles=["security_admin"])
    approval_id = await _pending(s)
    doc = await container.repos.approvals.get(s.tenant_id, approval_id)
    assert doc["escalate_at"] is not None and doc["escalated_at"] is None
    sec, _ = await _user(app, s, ["security_admin"])
    try:
        assert (await sec.post(f"/api/v1/approvals/{approval_id}/approve", json={})).status_code == 403
        assert await container.approvals.escalate_due() == 0  # not due yet
        await container.repos.approvals.col.update_one(
            {"_id": approval_id}, {"$set": {"escalate_at": utcnow() - timedelta(seconds=1)}})
        assert await container.approvals.escalate_due() == 1
        assert await container.approvals.escalate_due() == 0  # once only
        ev = await container.repos.audit.col.find_one({"approval_id": approval_id, "event_type": "approval.escalated"})
        assert ev["metadata"]["escalation_roles"] == ["security_admin"]
        r = await sec.post(f"/api/v1/approvals/{approval_id}/approve", json={})
        assert r.status_code == 200 and r.json()["status"] == "APPROVED"
    finally:
        await sec.http.aclose()


async def test_expiry_reminder_is_raised_once(scenario, container):
    s = await _setup(scenario, remind_before_expiry_minutes=10)
    approval_id = await _pending(s)
    doc = await container.repos.approvals.get(s.tenant_id, approval_id)
    assert doc["remind_at"] is not None and doc["remind_at"] < doc["expires_at"]
    assert await container.approvals.remind_due() == 0
    await container.repos.approvals.col.update_one(
        {"_id": approval_id}, {"$set": {"remind_at": utcnow() - timedelta(seconds=1)}})
    assert await container.approvals.remind_due() == 1
    assert await container.approvals.remind_due() == 0
    ev = await container.repos.audit.col.find_one({"approval_id": approval_id, "event_type": "approval.expiring"})
    assert ev["metadata"]["expires_at"]


async def test_escalation_roles_are_validated(scenario):
    s = await scenario.setup(enable={"send_email": "high"})
    r = await s.admin.post("/api/v1/policies", json={
        "name": "bad escalation", "effect": "allow", "principals": {"types": ["agent"], "ids": [s.agent["id"]]},
        "resources": {"servers": ["hr"], "tools": ["send_email"]}, "actions": ["invoke"],
        "constraints": {"require_approval": True, "escalate_after_minutes": 5, "escalation_roles": ["developer"]}})
    assert r.status_code == 422
