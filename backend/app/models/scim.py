"""SCIM 2.0 provisioning settings (docs/scim.md)."""

from __future__ import annotations

from pydantic import Field

from app.models.registry import Strict
from app.models.sso import CLAIM


class ScimConfigUpdate(Strict):
    enabled: bool = False
    # ID-token claim compared with the SCIM externalId to link a provisioned user at first SSO sign-in:
    # "oid" for Microsoft Entra ID (its SCIM externalId is usually the object ID), "sub" for most others.
    link_claim: str = Field(default="sub", pattern=CLAIM)
    # On: memberships of provisioned users come from SCIM groups. Off: from the ID token at sign-in.
    groups_authoritative: bool = True
