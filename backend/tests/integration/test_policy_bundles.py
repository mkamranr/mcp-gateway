"""Policy-as-code: bundle plan / apply / export, ownership, drift, prune, rollback, authorization."""

from __future__ import annotations

from typing import Any

import pytest
import yaml
from conftest import ApiClient, make_client, new_user_client

PLAN = "/api/v1/policies/bundle/plan"
APPLY = "/api/v1/policies/bundle/apply"
EXPORT = "/api/v1/policies/bundle/export"


def bundle(policies: list[dict[str, Any]], name: str = "team-a", scope: str = "tenant") -> str:
    return yaml.safe_dump({"apiVersion": "mcp-gateway/v1", "kind": "PolicyBundle",
                           "metadata": {"name": name, "scope": scope}, "policies": policies}, sort_keys=False)


def pol(name: str, agent: str, tools: list[str], server: str = "hr", **extra: Any) -> dict[str, Any]:
    return {"name": name, "effect": "allow", "principals": {"types": ["agent"], "ids": [agent]},
            "resources": {"servers": [server], "tools": tools}, "actions": ["discover", "invoke"], **extra}


async def plan(c: ApiClient, content: str, prune: bool = False) -> dict[str, Any]:
    r = await c.post(PLAN + ("?prune=true" if prune else ""), json={"content": content})
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


async def apply(c: ApiClient, content: str, prune: bool = False) -> dict[str, Any]:
    p = await plan(c, content, prune)
    assert p["valid"], p["errors"]
    r = await c.post(APPLY, json={"content": content, "expected_fingerprint": p["fingerprint"], "prune": prune})
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


async def by_name(c: ApiClient) -> dict[str, dict[str, Any]]:
    return {p["name"]: p for p in (await c.get("/api/v1/policies?limit=200")).json()["items"]}


async def test_apply_creates_policies_that_the_engine_enforces(scenario):
    s = await scenario.setup()
    content = bundle([pol("attendance", s.agent["id"], ["get_attendance_summary"])])
    assert (await s.invoke("get_attendance_summary", {"employee_id": "E1001"})).status_code == 403

    p = await plan(s.admin, content)
    assert p["valid"] and p["summary"]["create"] == 1 and p["changes"][0]["action"] == "create"
    assert "_changes" not in p and "_bundle" not in p
    assert "attendance" not in await by_name(s.admin)  # plan changed nothing

    res = await apply(s.admin, content)
    assert res["applied"] is True
    created = (await by_name(s.admin))["attendance"]
    assert created["managed_by"] == {"kind": "bundle", "bundle": "team-a"}
    assert (await s.invoke("get_attendance_summary", {"employee_id": "E1001"})).status_code == 200

    again = await plan(s.admin, content)
    assert again["summary"]["unchanged"] == 1 and again["summary"]["create"] == 0

    events = (await s.admin.get("/api/v1/audit/events?limit=50")).json()["items"]
    types = [e["event_type"] for e in events]
    assert "policy.bundle.applied" in types
    created_ev = next(e for e in events if e["event_type"] == "policy.created")
    assert created_ev["metadata"]["source"] == "bundle" and created_ev["metadata"]["bundle"] == "team-a"


async def test_update_shows_field_diff_and_bumps_version(scenario):
    s = await scenario.setup()
    await apply(s.admin, bundle([pol("attendance", s.agent["id"], ["get_attendance_summary"])]))
    before = (await by_name(s.admin))["attendance"]
    changed = bundle([pol("attendance", s.agent["id"], ["get_attendance_summary"], priority=50,
                          constraints={"max_calls_per_minute": 5})])
    p = await plan(s.admin, changed)
    ch = p["changes"][0]
    assert ch["action"] == "update" and set(ch["diff"]) == {"priority", "constraints"}
    assert ch["diff"]["priority"] == {"from": 100, "to": 50}
    await apply(s.admin, changed)
    after = (await by_name(s.admin))["attendance"]
    assert after["priority"] == 50 and after["version"] == before["version"] + 1
    assert after["id"] == before["id"]


async def test_stale_plan_is_refused(scenario):
    s = await scenario.setup()
    await apply(s.admin, bundle([pol("attendance", s.agent["id"], ["get_attendance_summary"])]))
    content = bundle([pol("attendance", s.agent["id"], ["get_attendance_summary"], priority=10)])
    p = await plan(s.admin, content)
    # someone edits the live policy after the plan was reviewed
    cur = (await by_name(s.admin))["attendance"]
    r = await s.admin.patch(f"/api/v1/policies/{cur['id']}", json={"version": cur["version"], "priority": 20,
                                                                   "confirm_managed_override": True})
    assert r.status_code == 200, r.text
    r = await s.admin.post(APPLY, json={"content": content, "expected_fingerprint": p["fingerprint"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "VERSION_CONFLICT"
    assert r.json()["error"]["fingerprint"] != p["fingerprint"]
    assert (await by_name(s.admin))["attendance"]["priority"] == 20  # nothing applied


async def test_hand_edit_of_managed_policy_needs_override_and_shows_as_drift(scenario):
    s = await scenario.setup()
    content = bundle([pol("attendance", s.agent["id"], ["get_attendance_summary"])])
    await apply(s.admin, content)
    cur = (await by_name(s.admin))["attendance"]
    pid = cur["id"]

    r = await s.admin.patch(f"/api/v1/policies/{pid}", json={"version": cur["version"], "priority": 7})
    assert r.status_code == 409 and r.json()["error"]["code"] == "POLICY_MANAGED_BY_CODE"
    assert r.json()["error"]["bundle"] == "team-a"
    for url in (f"/api/v1/policies/{pid}/disable", f"/api/v1/policies/{pid}/enable"):
        assert (await s.admin.post(url)).json()["error"]["code"] == "POLICY_MANAGED_BY_CODE"
    r = await s.admin.delete(f"/api/v1/policies/{pid}")
    assert r.status_code == 409

    r = await s.admin.post(f"/api/v1/policies/{pid}/disable?confirm_managed_override=true")
    assert r.status_code == 200 and r.json()["enabled"] is False
    ev = (await s.admin.get("/api/v1/audit/events?limit=5")).json()["items"][0]
    assert ev["event_type"] == "policy.disabled" and ev["metadata"]["managed_override"] is True

    p = await plan(s.admin, content)  # drift: the bundle wants it enabled
    assert p["changes"][0]["action"] == "update" and p["changes"][0]["diff"]["enabled"] == {"from": False, "to": True}
    await apply(s.admin, content)
    assert (await by_name(s.admin))["attendance"]["enabled"] is True

    # cloning a managed policy gives an unmanaged copy
    r = await s.admin.post(f"/api/v1/policies/{pid}/clone")
    assert r.status_code == 201 and r.json()["managed_by"] is None


async def test_prune_only_removes_policies_owned_by_the_bundle(scenario):
    s = await scenario.setup()
    hand = await s.allow(["get_attendance_summary"], name="hand-made")
    await apply(s.admin, bundle([pol("other", s.agent["id"], ["x"])], name="team-b"))
    await apply(s.admin, bundle([pol("keep", s.agent["id"], ["a"]), pol("drop", s.agent["id"], ["b"])]))

    smaller = bundle([pol("keep", s.agent["id"], ["a"])])
    p = await plan(s.admin, smaller)
    assert p["summary"]["orphan"] == 1 and p["summary"]["delete"] == 0
    await apply(s.admin, smaller)  # without prune the orphan stays
    assert "drop" in await by_name(s.admin)

    p = await plan(s.admin, smaller, prune=True)
    assert [c["name"] for c in p["changes"] if c["action"] == "delete"] == ["drop"]
    await apply(s.admin, smaller, prune=True)
    names = await by_name(s.admin)
    assert "drop" not in names and {"keep", "other", hand["name"]} <= set(names)

    # an empty bundle with prune removes everything the bundle owns, and nothing else
    await apply(s.admin, bundle([]), prune=True)
    names = await by_name(s.admin)
    assert "keep" not in names and {"other", hand["name"]} <= set(names)


async def test_adopts_unowned_policy_but_not_other_bundles(scenario):
    s = await scenario.setup()
    hand = await s.allow(["get_attendance_summary"], name="shared-name")
    p = await plan(s.admin, bundle([pol("shared-name", s.agent["id"], ["get_attendance_summary"])]))
    assert p["changes"][0]["action"] == "adopt" and p["changes"][0]["policy_id"] == hand["id"]
    await apply(s.admin, bundle([pol("shared-name", s.agent["id"], ["get_attendance_summary"])]))
    assert (await by_name(s.admin))["shared-name"]["managed_by"]["bundle"] == "team-a"

    p = await plan(s.admin, bundle([pol("shared-name", s.agent["id"], ["x"])], name="team-b"))
    assert not p["valid"] and p["errors"][0]["code"] == "OWNED_BY_OTHER_BUNDLE"


async def test_validation_errors(scenario):
    s = await scenario.setup()
    agent = s.agent["id"]
    # wildcard grant without acknowledgement in the file
    p = await plan(s.admin, bundle([pol("wide", agent, ["*"])]))
    assert not p["valid"] and p["errors"][0]["code"] == "BROAD_GRANT_CONFIRMATION_REQUIRED"
    r = await s.admin.post(APPLY, json={"content": bundle([pol("wide", agent, ["*"])]),
                                        "expected_fingerprint": p["fingerprint"]})
    assert r.status_code == 422
    assert (await plan(s.admin, bundle([pol("wide", agent, ["*"], confirm_broad_grant=True)])))["valid"]

    r = await s.admin.post(PLAN, json={"content": "policies: [\n  - name: x\n bad"})
    assert r.status_code == 422 and "line" in r.json()["error"]["message"]
    r = await s.admin.post(PLAN, json={"content": "- just\n- a list\n"})
    assert r.status_code == 422
    bad = yaml.safe_load(bundle([pol("x1", agent, ["a"])]))
    bad["policies"][0]["efect"] = "allow"
    r = await s.admin.post(PLAN, json={"content": yaml.safe_dump(bad)})
    assert r.status_code == 422
    assert any(d["field"] == "policies.0.efect" for d in r.json()["error"]["details"])
    r = await s.admin.post(PLAN, json={"content": bundle([pol("dup", agent, ["a"]), pol("DUP", agent, ["b"])])})
    assert r.status_code == 422
    r = await s.admin.post(PLAN, json={"content": bundle([{**pol("d", agent, ["a"]), "effect": "deny",
                                                           "constraints": {"require_approval": True}}])})
    assert r.status_code == 422
    # YAML tags that construct objects are rejected by safe_load
    r = await s.admin.post(PLAN, json={"content": "!!python/object/apply:os.system ['echo hi']"})
    assert r.status_code == 422


async def test_unknown_references_are_warnings(scenario):
    s = await scenario.setup()
    p = await plan(s.admin, bundle([pol("future", "agt_doesnotexist", ["nope_tool", "get_*"], server="later", confirm_broad_grant=True)]))
    assert p["valid"]
    codes = sorted(w["code"] for w in p["warnings"])
    assert codes == ["UNKNOWN_AGENT", "UNKNOWN_SERVER", "UNKNOWN_TOOL"]
    known = await plan(s.admin, bundle([pol("now", s.agent["id"], ["get_attendance_summary"])]))
    assert known["warnings"] == []


async def test_export_round_trip(scenario):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"], name="hand-made", max_calls_per_minute=3)
    r = await s.admin.get(EXPORT + "?bundle=exported")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/yaml")
    doc = yaml.safe_load(r.text)
    assert doc["metadata"] == {"name": "exported", "scope": "tenant"}
    names = [p["name"] for p in doc["policies"]]
    assert "hand-made" in names and all("system" not in p for p in doc["policies"])

    p = await plan(s.admin, r.text)
    assert p["valid"] and p["summary"]["create"] == 0
    assert all(c["action"] == "adopt" and not c["diff"] for c in p["changes"])
    await apply(s.admin, r.text)
    owned = (await s.admin.get(EXPORT + "?bundle=exported&include=bundle")).text
    assert (await plan(s.admin, owned))["summary"]["unchanged"] == len(names)


async def test_failed_apply_is_rolled_back(scenario, container, monkeypatch):
    s = await scenario.setup()
    await apply(s.admin, bundle([pol("a1", s.agent["id"], ["a"]), pol("a2", s.agent["id"], ["b"])]))
    before = await by_name(s.admin)
    content = bundle([pol("a1", s.agent["id"], ["a"], priority=1), pol("a2", s.agent["id"], ["b"], priority=2),
                      pol("a3", s.agent["id"], ["c"])])
    p = await plan(s.admin, content)

    repo = container.repos.policies
    real_insert = repo.insert

    async def failing_insert(*a: Any, **kw: Any) -> Any:
        raise RuntimeError("disk full")
    # changes run in file order: a1 and a2 are updated, then creating a3 fails
    monkeypatch.setattr(repo, "insert", failing_insert)

    r = await s.admin.post(APPLY, json={"content": content, "expected_fingerprint": p["fingerprint"]})
    assert r.status_code == 500 and "reverted" in r.json()["error"]["message"]
    monkeypatch.setattr(repo, "insert", real_insert)
    after = await by_name(s.admin)
    assert "a3" not in after
    for n in ("a1", "a2"):
        assert {k: after[n][k] for k in ("priority", "version")} == {k: before[n][k] for k in ("priority", "version")}
    ev = (await s.admin.get("/api/v1/audit/events?limit=5")).json()["items"][0]
    assert ev["event_type"] == "policy.bundle.rolled_back"


async def test_authorization(scenario, app, admin):
    s = await scenario.setup()
    content = bundle([pol("attendance", s.agent["id"], ["get_attendance_summary"])])
    dev = await new_user_client(app, admin, s.tenant_id, ["developer"])
    auditor = await new_user_client(app, admin, s.tenant_id, ["auditor"])
    try:
        p = await plan(dev, content)  # developers may plan (CI jobs run plan on pull requests)
        r = await dev.post(APPLY, json={"content": content, "expected_fingerprint": p["fingerprint"]})
        assert r.status_code == 403
        assert (await dev.get(EXPORT)).status_code == 403
        assert (await auditor.get(EXPORT)).status_code == 200
        r = await auditor.post(APPLY, json={"content": content, "expected_fingerprint": p["fingerprint"]})
        assert r.status_code == 403
    finally:
        await dev.http.aclose()
        await auditor.http.aclose()

    # global bundles are for platform administrators only
    r = await admin.post("/api/v1/tenants", json={"name": "Beta Ltd", "slug": "beta", "admin_username": "beta-admin",
                                                  "admin_password": "Beta-Admin-Password-1"})
    assert r.status_code == 201, r.text
    beta = ApiClient(make_client(app))
    try:
        await beta.login("beta-admin", "Beta-Admin-Password-1")
        g = bundle([pol("g1", "agt_x", ["a"])], name="platform", scope="global")
        assert (await beta.post(PLAN, json={"content": g})).status_code == 403
        assert (await beta.get(EXPORT + "?scope=global")).status_code == 403
        # tenant B's bundle never sees or prunes tenant A's policies
        await apply(admin, content)
        pb = await plan(beta, bundle([pol("attendance", "agt_x", ["a"])]), prune=True)
        assert pb["changes"][0]["action"] == "create" and pb["summary"]["delete"] == 0
    finally:
        await beta.http.aclose()
    gp = await plan(admin, bundle([pol("g1", "agt_x", ["a"])], name="platform", scope="global"))
    assert gp["tenant_id"] == "*" and gp["valid"]


@pytest.mark.parametrize("bad", ["Upper", "-lead", "x" * 64, "sp ace"])
async def test_bundle_name_rules(admin, bad):
    r = await admin.post(PLAN, json={"content": bundle([], name=bad)})
    assert r.status_code == 422
