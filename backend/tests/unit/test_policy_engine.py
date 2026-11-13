"""Policy evaluation: default deny, deny-overrides, constraints, approval obligations, fail closed."""

from datetime import UTC, datetime

import pytest

from app.core.identity import Principal
from app.services.policy_service import RequestContext, evaluate

AGENT = Principal(principal_type="agent", principal_id="agt_1", tenant_id="t1", scopes=("tools:invoke",),
                  agent_id="agt_1")
SERVER = {"_id": "srv_1", "alias": "hr", "name": "HR", "environment": "production"}
TOOL = {"_id": "tool_1", "upstream_name": "get_record", "gateway_name": "hr__get_record", "risk_level": "low",
        "approval": {"required": False}}
DEFAULT = {"_id": "pol_default", "name": "default-deny", "effect": "deny", "kind": "default_deny", "enabled": True,
           "priority": 1_000_000}


def pol(pid, effect="allow", **kw):
    base = {"_id": pid, "name": pid, "effect": effect, "enabled": True, "priority": 100,
            "principals": {"types": ["agent"], "ids": ["agt_1"], "roles": []},
            "resources": {"servers": ["hr"], "tools": ["get_record"]},
            "actions": ["discover", "invoke"], "constraints": {}}
    for k, v in kw.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = {**base[k], **v}
        else:
            base[k] = v
    return base


def ctx(**kw):
    return RequestContext(principal=kw.pop("principal", AGENT), action=kw.pop("action", "invoke"),
                          server=kw.pop("server", SERVER), tool=kw.pop("tool", TOOL), **kw)


def test_no_policies_means_deny():
    d = evaluate([DEFAULT], ctx())
    assert d.decision == "DENY" and d.reason_code == "NO_MATCHING_ALLOW" and d.policy_ids == ["pol_default"]


def test_matching_allow():
    d = evaluate([DEFAULT, pol("p1")], ctx())
    assert d.decision == "ALLOW" and d.policy_ids == ["p1"]


@pytest.mark.parametrize("deny_priority", [1, 100, 999_999])
def test_deny_overrides_allow_regardless_of_priority(deny_priority):
    d = evaluate([pol("allow1", priority=1), pol("deny1", effect="deny", priority=deny_priority)], ctx())
    assert d.decision == "DENY" and d.reason_code == "EXPLICIT_DENY" and d.policy_ids == ["deny1"]


def test_disabled_policies_are_ignored():
    assert evaluate([pol("p1", enabled=False)], ctx()).decision == "DENY"
    assert evaluate([pol("p1"), pol("d1", effect="deny", enabled=False)], ctx()).decision == "ALLOW"


@pytest.mark.parametrize("override,field", [
    ({"principals": {"ids": ["agt_other"]}}, "principal"),
    ({"principals": {"types": ["user"]}}, "principal_type"),
    ({"resources": {"servers": ["finance"]}}, "server"),
    ({"resources": {"tools": ["other_tool"]}}, "tool"),
    ({"actions": ["discover"]}, "action"),
    ({"resources": {"risk_levels": ["high"]}}, "risk_level"),
    ({"constraints": {"environments": ["development"]}}, "environment"),
])
def test_non_matching_dimensions(override, field):
    d = evaluate([pol("p1", **override)], ctx())
    assert d.decision == "DENY"
    assert d.explanation[0]["not_matched_on"] == field


def test_wildcards_and_globs():
    assert evaluate([pol("p1", resources={"servers": ["*"], "tools": ["get_*"]})], ctx()).decision == "ALLOW"
    assert evaluate([pol("p1", resources={"servers": ["*"], "tools": ["set_*"]})], ctx()).decision == "DENY"
    assert evaluate([pol("p1", principals={"types": ["*"], "ids": []})], ctx()).decision == "ALLOW"


def test_tool_can_be_matched_by_gateway_name_or_id():
    assert evaluate([pol("p1", resources={"tools": ["hr__get_record"]})], ctx()).decision == "ALLOW"
    assert evaluate([pol("p1", resources={"tools": ["tool_1"]})], ctx()).decision == "ALLOW"


def test_role_based_principal_match():
    user = Principal(principal_type="user", principal_id="usr_1", tenant_id="t1", roles=("developer",))
    p = pol("p1", principals={"types": ["user"], "ids": [], "roles": ["developer"]})
    assert evaluate([p], ctx(principal=user)).decision == "ALLOW"
    other = Principal(principal_type="user", principal_id="usr_2", tenant_id="t1", roles=("auditor",))
    assert evaluate([p], ctx(principal=other)).decision == "DENY"


def test_source_network_constraint():
    p = pol("p1", constraints={"source_cidrs": ["10.0.0.0/8"]})
    assert evaluate([p], ctx(source_ip="10.1.2.3")).decision == "ALLOW"
    assert evaluate([p], ctx(source_ip="192.168.1.1")).decision == "DENY"
    assert evaluate([p], ctx(source_ip=None)).decision == "DENY"


def test_time_window_constraint():
    p = pol("p1", constraints={"time_windows": [{"days": [0, 1, 2, 3, 4], "start": "08:00", "end": "18:00"}]})
    monday_noon = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
    sunday_noon = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
    monday_night = datetime(2026, 11, 9, 22, 0, tzinfo=UTC)
    assert evaluate([p], ctx(now=monday_noon)).decision == "ALLOW"
    assert evaluate([p], ctx(now=sunday_noon)).decision == "DENY"
    assert evaluate([p], ctx(now=monday_night)).decision == "DENY"


def test_approval_required_by_policy():
    d = evaluate([pol("p1", constraints={"require_approval": True, "required_approvals": 2})], ctx())
    assert d.decision == "REQUIRE_APPROVAL" and d.reason_code == "SENSITIVE_TOOL_REQUIRES_APPROVAL"
    assert d.obligations["approval"]["required_approvals"] == 2
    assert d.obligations["approval"]["allow_self_approval"] is False


def test_approval_required_by_tool_and_critical_risk():
    tool = {**TOOL, "approval": {"required": True, "policy": {"required_approvals": 1, "ttl_minutes": 5}}}
    d = evaluate([pol("p1")], ctx(tool=tool))
    assert d.decision == "REQUIRE_APPROVAL" and d.obligations["approval"]["ttl_minutes"] == 5
    critical = {**TOOL, "risk_level": "critical"}
    assert evaluate([pol("p1")], ctx(tool=critical)).decision == "REQUIRE_APPROVAL"
    assert evaluate([pol("p1")], ctx(tool=critical, critical_requires_approval=False)).decision == "ALLOW"


def test_discover_never_requires_approval():
    p = pol("p1", constraints={"require_approval": True})
    assert evaluate([p], ctx(action="discover")).decision == "ALLOW"


def test_rate_limit_obligations_take_minimum():
    d = evaluate([pol("p1", constraints={"max_calls_per_minute": 30}),
                  pol("p2", constraints={"max_calls_per_minute": 10, "max_calls_per_day": 500})], ctx())
    assert d.obligations["limits"] == {"per_minute": 10, "per_day": 500}


def test_engine_error_fails_closed():
    broken = [{"_id": "x", "enabled": True, "effect": "allow"}]  # malformed: missing fields
    broken[0]["principals"] = None  # type: ignore[assignment]
    d = evaluate(broken, ctx())
    assert d.decision == "DENY"


def test_public_view_hides_internals():
    d = evaluate([pol("p1", effect="deny")], ctx())
    assert set(d.public()) == {"decision", "reason_code"}
