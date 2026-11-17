"""OAuth 2.0 for agents: agents present access tokens (JWTs) issued by a trusted IdP, typically through the
client-credentials grant, instead of a gateway API key.

Validation (all explicit, nothing left to library defaults):
  * the issuer must be configured (exact ``iss`` match); its keys come from its JWKS, refreshed at most once a
    minute for an unknown ``kid`` (key rotation);
  * asymmetric algorithms only, from the issuer's allowlist (never ``none`` or ``HS*``);
  * ``aud`` must contain the gateway's audience for that issuer; ``exp`` is required, ``nbf``/``iat`` honoured,
    60 s leeway; the token's lifetime is capped;
  * ID tokens are refused (a ``nonce`` claim), and optionally anything not typed ``at+jwt`` (RFC 9068);
  * required scopes, if configured, must all be granted (``scope`` or ``scp``).
The client is then identified by ``issuer`` + the configured subject claim and matched to exactly one active
OAuth credential, so revocation, expiry, scopes and policies work as for API keys.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

import jwt

from app.config import Settings
from app.core.errors import ErrorCode, GatewayError
from app.core.identity import Principal
from app.core.ids import utcnow
from app.core.logging import get_logger
from app.models.agent_oauth import AgentOAuthConfig
from app.repositories.collections import Repos
from app.services.audit_service import AuditService
from app.services.oidc_client import CACHE_SECONDS, LEEWAY_SECONDS, OidcClient, OidcError, _Cached

log = get_logger(__name__)
CONFIG_KEY = "agent_oauth"
MAX_TOKEN_BYTES = 16_384
CONFIG_CACHE_SECONDS = 5.0


def looks_like_jwt(value: str) -> bool:
    return value.count(".") == 2 and len(value) <= MAX_TOKEN_BYTES and not value.startswith("mgw_")


def oauth_match(issuer: str, subject: str) -> str:
    return f"{issuer}\n{subject}"


def _scopes(claims: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for name in ("scope", "scp"):
        v = claims.get(name)
        if isinstance(v, str):
            out.update(v.split())
        elif isinstance(v, list):
            out.update(str(s) for s in v if isinstance(s, str))
    return out


class TokenRejected(Exception):
    """The token is not acceptable. ``reason`` goes to logs only; the caller always sees a generic 401."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason[:300]


class AgentOAuthService:
    def __init__(self, settings: Settings, repos: Repos, audit: AuditService,
                 client: OidcClient | None = None) -> None:
        self.settings = settings
        self.repos = repos
        self.audit = audit
        self.client = client or OidcClient(settings)
        self._jwks_uris: dict[str, _Cached] = {}
        self._config: _Cached | None = None

    # ------------------------------------------------------------------ configuration
    async def config(self, *, fresh: bool = False) -> dict[str, Any]:
        """Stored configuration, cached for a few seconds: it is read on every agent request with a JWT."""
        now = time.monotonic()
        if not fresh and self._config and self._config.expires > now:
            return dict(self._config.value)
        raw = await self.repos.settings.get_value(CONFIG_KEY) or {}
        known = {k: v for k, v in raw.items() if k in AgentOAuthConfig.model_fields}
        cfg = AgentOAuthConfig.model_validate(known).model_dump() if known else AgentOAuthConfig().model_dump()
        cfg.update({"updated_at": raw.get("updated_at"), "updated_by": raw.get("updated_by")})
        self._config = _Cached(cfg, now + CONFIG_CACHE_SECONDS)
        return dict(cfg)

    async def public_view(self) -> dict[str, Any]:
        cfg = await self.config()
        return {"enabled": cfg["enabled"],
                "issuers": [{"issuer": i["issuer"], "display_name": i["display_name"] or i["issuer"],
                             "subject_claim": i["subject_claim"]} for i in cfg["issuers"]]}

    async def update_config(self, p: Principal, body: AgentOAuthConfig) -> dict[str, Any]:
        old = await self.config(fresh=True)
        data = body.model_dump()
        for i in data["issuers"]:
            for url, what in ((i["issuer"], "issuer"), (i["jwks_uri"], "jwks_uri")):
                if url:
                    try:
                        self.client.check_url(url, what)
                    except OidcError as exc:
                        raise GatewayError(ErrorCode.VALIDATION_FAILED, f"The {what} must use https.") from exc
        changed = sorted(k for k in ("enabled", "issuers") if data.get(k) != old.get(k))
        data.update({"updated_at": utcnow().isoformat(), "updated_by": p.principal_id})
        await self.repos.settings.set_value(CONFIG_KEY, data, p.principal_id)
        self._config = None
        self._jwks_uris.clear()
        await self.audit.record(p.tenant_id, "agent_oauth.config.updated", principal=p, severity="high",
                                metadata={"changed": changed, "enabled": data["enabled"],
                                          "issuers": [i["issuer"] for i in data["issuers"]]})
        return await self.config(fresh=True)

    async def test_issuer(self, p: Principal, issuer: str) -> dict[str, Any]:
        cfg = await self.config(fresh=True)
        entry = next((i for i in cfg["issuers"] if i["issuer"] == issuer), None)
        if entry is None:
            raise GatewayError(ErrorCode.NOT_FOUND, "Save the issuer first.")
        try:
            uri = await self._jwks_uri(entry, force=True)
            keys = await self.client.key_count(uri)
        except OidcError as exc:
            return {"ok": False, "error": exc.code, "detail": exc.detail}
        await self.audit.record(p.tenant_id, "agent_oauth.issuer.tested", principal=p, metadata={"issuer": issuer})
        return {"ok": True, "jwks_uri": uri, "signing_keys": keys}

    # ------------------------------------------------------------------ keys
    async def _jwks_uri(self, entry: dict[str, Any], *, force: bool = False) -> str:
        if entry.get("jwks_uri"):
            self.client.check_url(entry["jwks_uri"], "jwks_uri")
            return str(entry["jwks_uri"])
        issuer = entry["issuer"]
        cached = self._jwks_uris.get(issuer)
        if cached and not force and cached.expires > time.monotonic():
            return str(cached.value)
        base = issuer.rstrip("/")
        last: OidcError | None = None
        # OpenID Connect discovery, then OAuth authorization server metadata (RFC 8414).
        for url in (base + "/.well-known/openid-configuration", base + "/.well-known/oauth-authorization-server"):
            try:
                doc = await self.client._get_json(url, "discovery")  # noqa: SLF001
            except OidcError as exc:
                last = exc
                continue
            if doc.get("issuer") != issuer:
                raise OidcError("idp_misconfigured", f"discovery issuer {str(doc.get('issuer'))[:200]!r} != configured")
            uri = doc.get("jwks_uri")
            if not isinstance(uri, str):
                raise OidcError("idp_misconfigured", "discovery is missing jwks_uri")
            self.client.check_url(uri, "jwks_uri")
            self._jwks_uris[issuer] = _Cached(uri, time.monotonic() + CACHE_SECONDS)
            return uri
        raise last or OidcError("idp_unreachable", "discovery failed")

    # ------------------------------------------------------------------ validation
    async def validate(self, token: str) -> tuple[str, str, dict[str, Any]]:
        """Returns (issuer, subject, claims). Raises TokenRejected, or GatewayError(DEPENDENCY_UNAVAILABLE) when the
        issuer's keys can't be fetched."""
        cfg = await self.config()
        if not cfg["enabled"]:
            raise TokenRejected("OAuth for agents is disabled")
        if len(token) > MAX_TOKEN_BYTES:
            raise TokenRejected("token too large")
        try:
            header = jwt.get_unverified_header(token)
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError as exc:
            raise TokenRejected(f"malformed token: {exc}") from exc
        # The unverified issuer only selects which configured issuer's keys and rules to apply.
        entry = next((i for i in cfg["issuers"] if i["issuer"] == unverified.get("iss")), None)
        if entry is None:
            raise TokenRejected(f"untrusted issuer {str(unverified.get('iss'))[:200]!r}")
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in entry["allowed_algorithms"] or alg.startswith("HS") \
                or alg.lower() == "none":
            raise TokenRejected(f"algorithm {str(alg)[:20]!r} not allowed")
        if entry.get("require_at_jwt_type") and str(header.get("typ", "")).lower() not in ("at+jwt",
                                                                                          "application/at+jwt"):
            raise TokenRejected("token type is not at+jwt")
        try:
            key = await self.client._signing_key(await self._jwks_uri(entry), header.get("kid"))  # noqa: SLF001
        except OidcError as exc:
            if exc.code == "token_invalid":
                raise TokenRejected(exc.detail) from exc
            log.warning("agent_oauth.keys_unavailable", issuer=entry["issuer"], code=exc.code, detail=exc.detail)
            raise GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE,
                               "The token issuer's signing keys are unavailable. Try again later.") from exc
        try:
            claims: dict[str, Any] = jwt.decode(
                token, key=key, algorithms=[alg], audience=entry["audience"], issuer=entry["issuer"],
                leeway=LEEWAY_SECONDS, options={"require": ["exp", "iss", "aud"]})
        except jwt.PyJWTError as exc:
            raise TokenRejected(f"{type(exc).__name__}: {exc}") from exc
        if "nonce" in claims:
            raise TokenRejected("an ID token is not an access token")
        exp = float(claims["exp"])
        start = float(claims["iat"]) if isinstance(claims.get("iat"), int | float) else time.time()
        if exp - start > entry["max_token_lifetime_seconds"] + LEEWAY_SECONDS:
            raise TokenRejected("token lifetime exceeds the configured maximum")
        missing = set(entry["required_scopes"]) - _scopes(claims)
        if missing:
            raise TokenRejected(f"missing required scopes: {' '.join(sorted(missing))[:200]}")
        subject = claims.get(entry["subject_claim"])
        if not isinstance(subject, str) or not subject or len(subject) > 256:
            raise TokenRejected(f"missing {entry['subject_claim']} claim")
        return entry["issuer"], subject, claims

    @staticmethod
    def throttle_key(issuer: str, subject: str) -> str:
        return "oauth:" + hashlib.sha256(oauth_match(issuer, subject).encode()).hexdigest()[:32]
