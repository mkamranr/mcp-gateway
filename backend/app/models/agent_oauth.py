"""OAuth 2.0 for agents: trusted token issuers (platform-wide) whose access tokens agents may present."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.models.registry import Strict
from app.models.sso import CLAIM, SUPPORTED_ALGORITHMS

SCOPE = r"^[\x21\x23-\x5B\x5D-\x7E]{1,200}$"  # RFC 6749 §3.3 scope-token


class TrustedIssuer(Strict):
    issuer: str = Field(min_length=1, max_length=500)  # exactly the token's "iss"
    display_name: str = Field(default="", max_length=60)
    # The gateway's resource identifier at this IdP (e.g. api://mcp-gateway, or the MCP URL). Never the client ID of
    # an agent or of the console's SSO app: ID tokens issued to that client carry it as their audience.
    audience: str = Field(min_length=1, max_length=500)
    jwks_uri: str = Field(default="", max_length=500)  # "" = from the issuer's discovery document
    subject_claim: str = Field(default="sub", pattern=CLAIM)  # which claim identifies the client
    allowed_algorithms: list[Literal[SUPPORTED_ALGORITHMS]] = Field(  # type: ignore[valid-type]
        default_factory=lambda: ["RS256", "PS256", "ES256"], min_length=1)
    required_scopes: list[str] = Field(default_factory=list, max_length=20)
    max_token_lifetime_seconds: int = Field(default=86_400, ge=60, le=7 * 86_400)
    require_at_jwt_type: bool = False  # RFC 9068 "typ": "at+jwt"
    # Listed as an authorization server in the protected resource metadata (RFC 9728), so MCP clients can find it.
    advertise: bool = True

    @field_validator("issuer", "jwks_uri")
    @classmethod
    def _url(cls, v: str) -> str:
        v = v.strip()
        if v and not v.startswith(("https://", "http://")):
            raise ValueError("Must be an absolute URL")
        return v

    @field_validator("required_scopes")
    @classmethod
    def _scopes(cls, v: list[str]) -> list[str]:
        import re

        out = sorted({s.strip() for s in v if s.strip()})
        for s in out:
            if not re.match(SCOPE, s):
                raise ValueError(f"Invalid scope: {s[:50]}")
        return out


class AgentOAuthConfig(Strict):
    enabled: bool = False
    issuers: list[TrustedIssuer] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def _unique(self) -> AgentOAuthConfig:
        names = [i.issuer for i in self.issuers]
        if len(names) != len(set(names)):
            raise ValueError("Each issuer can be listed once")
        if self.enabled and not self.issuers:
            raise ValueError("Add a trusted issuer before enabling OAuth for agents")
        return self


class AgentOAuthTest(Strict):
    issuer: str = Field(min_length=1, max_length=500)
