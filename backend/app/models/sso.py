"""OIDC single sign-on configuration (Phase 6). One platform-wide IdP; groups map to tenants and roles."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.models.identity import _check_roles
from app.models.registry import Strict

# Asymmetric algorithms only: HS* would let anyone holding the client secret mint ID tokens, and "none" is never valid.
SUPPORTED_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA")
CLAIM = r"^[A-Za-z0-9_.:/-]{1,100}$"


class GroupRule(Strict):
    """Members of ``group`` get ``roles`` in ``tenant_id``. Roles from several matching rules are combined."""

    group: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=64)
    roles: list[str] = Field(min_length=1)

    _roles = field_validator("roles")(_check_roles)


class OidcConfigBase(Strict):
    enabled: bool = False
    display_name: str = Field(default="Single sign-on", min_length=1, max_length=60)
    issuer: str = Field(default="", max_length=500)
    client_id: str = Field(default="", max_length=200)
    token_auth_method: Literal["client_secret_basic", "client_secret_post"] = "client_secret_basic"  # noqa: S105
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"], max_length=20)
    allowed_algorithms: list[Literal[SUPPORTED_ALGORITHMS]] = Field(  # type: ignore[valid-type]
        default_factory=lambda: ["RS256", "PS256", "ES256"], min_length=1)
    username_claim: str = Field(default="preferred_username", pattern=CLAIM)
    email_claim: str = Field(default="email", pattern=CLAIM)
    name_claim: str = Field(default="name", pattern=CLAIM)
    groups_claim: str = Field(default="groups", pattern=CLAIM)
    group_rules: list[GroupRule] = Field(default_factory=list, max_length=500)
    platform_admin_groups: list[str] = Field(default_factory=list, max_length=20)
    jit_provisioning: bool = True
    # Off by default: linking an SSO identity to an existing local account by username would let anyone who
    # can choose their IdP username take over that local account.
    link_local_accounts: bool = False
    local_login: Literal["enabled", "break_glass_only"] = "enabled"
    break_glass_usernames: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("scopes")
    @classmethod
    def _scopes(cls, v: list[str]) -> list[str]:
        out = sorted({s.strip() for s in v if s.strip()})
        if "openid" not in out:
            out.insert(0, "openid")
        for s in out:
            if not s.replace("_", "").replace("-", "").replace(":", "").replace(".", "").isalnum():
                raise ValueError(f"Invalid scope: {s}")
        return out

    @field_validator("issuer")
    @classmethod
    def _issuer(cls, v: str) -> str:
        v = v.strip()
        if v and not v.startswith(("https://", "http://")):
            raise ValueError("Issuer must be an absolute URL")
        return v

    @field_validator("break_glass_usernames", "platform_admin_groups")
    @classmethod
    def _dedupe(cls, v: list[str]) -> list[str]:
        return sorted({x.strip() for x in v if x.strip()})

    @model_validator(mode="after")
    def _complete(self) -> OidcConfigBase:
        if self.enabled and (not self.issuer or not self.client_id):
            raise ValueError("Issuer and client ID are required to enable SSO")
        if self.local_login == "break_glass_only":
            if not self.enabled:
                raise ValueError("Local login can only be restricted while SSO is enabled")
            if not self.break_glass_usernames:
                raise ValueError("Name at least one break-glass account before restricting local login")
        return self


class OidcConfigUpdate(OidcConfigBase):
    # Write-only. Omit (null) to keep the stored secret; "" clears it.
    client_secret: str | None = Field(default=None, max_length=4096, repr=False)
