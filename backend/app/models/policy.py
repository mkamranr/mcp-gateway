"""Declarative policy documents (spec §8.3). Unknown fields are rejected."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from app.models.registry import Strict

Action = Literal["discover", "invoke"]
PATTERN = re.compile(r"^[A-Za-z0-9_\-.*]{1,160}$")


def _patterns(v: list[str]) -> list[str]:
    for item in v:
        if not PATTERN.match(item):
            raise ValueError(f"Invalid pattern {item!r}")
    return list(dict.fromkeys(v))


class TimeWindow(Strict):
    days: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4], description="0=Monday … 6=Sunday")
    start: str = Field(default="00:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    end: str = Field(default="23:59", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")

    @field_validator("days")
    @classmethod
    def _days(cls, v: list[int]) -> list[int]:
        if not v or any(d < 0 or d > 6 for d in v):
            raise ValueError("days must contain values 0-6")
        return sorted(set(v))


class Principals(Strict):
    types: list[Literal["agent", "user", "service", "*"]] = Field(default_factory=lambda: ["agent"], min_length=1)  # type: ignore[arg-type]
    ids: list[str] = Field(default_factory=list, max_length=500)
    roles: list[str] = Field(default_factory=list, max_length=20)

    _ids = field_validator("ids")(_patterns)


class Resources(Strict):
    servers: list[str] = Field(min_length=1, max_length=500)
    tools: list[str] = Field(min_length=1, max_length=1000)
    risk_levels: list[Literal["low", "medium", "high", "critical"]] = Field(default_factory=list)

    _s = field_validator("servers")(_patterns)
    _t = field_validator("tools")(_patterns)


ApproverRole = Literal["approver", "security_admin", "tenant_admin", "platform_admin"]


class Constraints(Strict):
    environments: list[Literal["development", "test", "production"]] = Field(default_factory=list)
    max_calls_per_minute: int | None = Field(default=None, ge=1)
    max_calls_per_hour: int | None = Field(default=None, ge=1)
    max_calls_per_day: int | None = Field(default=None, ge=1)
    require_approval: bool = False
    required_approvals: Literal[1, 2] | None = None
    approver_roles: list[str] | None = None
    # Only users in one of these SSO groups (as of their last SSO login) may approve. Narrows approver_roles.
    approver_groups: list[str] | None = Field(default=None, max_length=50)
    # A request still pending after this long is opened to escalation_roles too (and an audit event is raised).
    escalate_after_minutes: int | None = Field(default=None, ge=1, le=10080)
    escalation_roles: list[ApproverRole] | None = Field(default=None, max_length=4)
    # Raise an approval.expiring audit event (forwarded to the SIEM) this long before the request expires.
    remind_before_expiry_minutes: int | None = Field(default=None, ge=1, le=10080)
    approval_policy_id: str | None = Field(default=None, max_length=100)
    time_windows: list[TimeWindow] = Field(default_factory=list, max_length=10)
    source_cidrs: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("source_cidrs")
    @classmethod
    def _cidrs(cls, v: list[str]) -> list[str]:
        for c in v:
            ipaddress.ip_network(c, strict=False)
        return v


class PolicyBase(Strict):
    description: str = Field(default="", max_length=2000)
    effect: Literal["allow", "deny"]
    principals: Principals
    resources: Resources
    actions: list[Action] = Field(min_length=1)
    constraints: Constraints = Field(default_factory=Constraints)
    priority: int = Field(default=100, ge=0, le=999_999)
    enabled: bool = True


class PolicyCreate(PolicyBase):
    name: str = Field(min_length=2, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]+$")
    scope: Literal["tenant", "global"] = "tenant"
    confirm_broad_grant: bool = False

    @model_validator(mode="after")
    def _deny_constraints(self) -> PolicyCreate:
        if self.effect == "deny" and self.constraints.require_approval:
            raise ValueError("Deny policies cannot require approval")
        return self


class PolicyUpdate(Strict):
    version: int
    name: str | None = Field(default=None, min_length=2, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]+$")
    description: str | None = Field(default=None, max_length=2000)
    effect: Literal["allow", "deny"] | None = None
    principals: Principals | None = None
    resources: Resources | None = None
    actions: list[Action] | None = None
    constraints: Constraints | None = None
    priority: int | None = Field(default=None, ge=0, le=999_999)
    enabled: bool | None = None
    confirm_broad_grant: bool = False
    # Policies applied from a bundle are owned by code; editing one by hand needs explicit acknowledgement
    # (the next bundle apply shows the edit as drift and reverts it).
    confirm_managed_override: bool = False


class SimulateRequest(Strict):
    principal_type: Literal["agent", "user", "service"] = "agent"
    principal_id: str
    tool_id: str | None = None
    gateway_name: str | None = None
    action: Action = "invoke"
    arguments: dict[str, Any] | None = None
    source_ip: str | None = None

    @model_validator(mode="after")
    def _tool(self) -> SimulateRequest:
        if not self.tool_id and not self.gateway_name:
            raise ValueError("tool_id or gateway_name is required")
        return self


def is_broad(principals: Principals, resources: Resources) -> list[str]:
    reasons = []
    if any("*" in s for s in resources.servers):
        reasons.append("servers")
    if any("*" in t for t in resources.tools):
        reasons.append("tools")
    if "*" in principals.types or any("*" in i for i in principals.ids) or (
            not principals.ids and not principals.roles):
        reasons.append("principals")
    return reasons


def policy_to_api(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": doc["_id"], "tenant_id": doc["tenant_id"], "scope": "global" if doc["tenant_id"] == "*" else "tenant",
        "name": doc["name"], "description": doc.get("description", ""), "effect": doc["effect"],
        "kind": doc.get("kind", "standard"), "system": doc.get("system", False),
        "principals": doc.get("principals"), "resources": doc.get("resources"), "actions": doc.get("actions"),
        "constraints": doc.get("constraints", {}), "priority": doc.get("priority", 100),
        "enabled": doc.get("enabled", False), "broad": doc.get("broad", []), "version": doc.get("version", 1),
        "managed_by": doc.get("managed_by"),
        "created_by": doc.get("created_by"), "updated_by": doc.get("updated_by"),
        "created_at": doc.get("created_at"), "updated_at": doc.get("updated_at"),
    }
