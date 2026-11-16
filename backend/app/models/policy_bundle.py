"""Policy-as-code bundle format (Phase 6). YAML or JSON; see docs/policy-as-code.md.

    apiVersion: mcp-gateway/v1
    kind: PolicyBundle
    metadata:
      name: hr-team          # bundle identity: apply/prune only touch policies owned by this bundle
      scope: tenant          # tenant (the caller's current tenant) | global (platform administrators)
    policies:
      - name: hr-read
        effect: allow
        principals: {types: [agent], ids: [agt_123]}
        resources: {servers: [hr], tools: [get_employee]}
        actions: [discover, invoke]
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from app.models.policy import PolicyBase
from app.models.registry import Strict

BUNDLE_NAME = r"^[a-z0-9][a-z0-9._-]{0,62}$"
POLICY_NAME = r"^[A-Za-z0-9][A-Za-z0-9 ._-]+$"
MAX_BUNDLE_BYTES = 1_000_000


class BundlePolicy(PolicyBase):
    name: str = Field(min_length=2, max_length=100, pattern=POLICY_NAME)
    # Wildcard grants must be acknowledged in the file itself, so the review of the pull request sees it.
    confirm_broad_grant: bool = False

    @model_validator(mode="after")
    def _deny_constraints(self) -> BundlePolicy:
        if self.effect == "deny" and self.constraints.require_approval:
            raise ValueError("Deny policies cannot require approval")
        return self


class BundleMetadata(Strict):
    name: str = Field(pattern=BUNDLE_NAME)
    scope: Literal["tenant", "global"] = "tenant"
    description: str = Field(default="", max_length=2000)


class PolicyBundle(Strict):
    apiVersion: Literal["mcp-gateway/v1"]  # noqa: N815 (wire format)
    kind: Literal["PolicyBundle"]
    metadata: BundleMetadata
    policies: list[BundlePolicy] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def _unique(self) -> PolicyBundle:
        seen: set[str] = set()
        for p in self.policies:
            key = p.name.lower()
            if key in seen:
                raise ValueError(f"Duplicate policy name in bundle: {p.name}")
            seen.add(key)
        return self


class BundleRequest(Strict):
    content: str = Field(min_length=1, max_length=MAX_BUNDLE_BYTES)


class BundleApplyRequest(BundleRequest):
    # The fingerprint returned by /plan. Apply refuses if anything changed since (drift or a concurrent edit).
    expected_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    prune: bool = False
