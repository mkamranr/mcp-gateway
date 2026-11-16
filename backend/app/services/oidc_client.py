"""Minimal, strict OpenID Connect relying-party client (authorization code + PKCE).

Only what the gateway needs: discovery, JWKS, the token endpoint, the userinfo endpoint and ID-token
validation. Every check that matters for security is explicit here rather than delegated to defaults:
asymmetric algorithms only, exact issuer match, audience and ``azp``, expiry with small leeway, nonce,
no redirects, size caps and TLS verification (optionally against an internal CA bundle).
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from jwt import PyJWK, PyJWKSet

from app.config import Settings
from app.core.crypto import constant_time_equals, random_token

MAX_DOC_BYTES = 1_000_000
CACHE_SECONDS = 3600
JWKS_MIN_REFRESH_SECONDS = 60
LEEWAY_SECONDS = 60


class OidcError(Exception):
    """``code`` is safe to show (it becomes ``?sso_error=<code>``); ``detail`` is for the audit log only."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail[:500]


@dataclass
class _Cached:
    value: Any
    expires: float
    fetched: float = field(default_factory=time.monotonic)


def pkce_pair() -> tuple[str, str]:
    verifier = random_token(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


class OidcClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._discovery: dict[str, _Cached] = {}
        self._jwks: dict[str, _Cached] = {}

    # ------------------------------------------------------------------ http
    def _client(self) -> httpx.AsyncClient:
        verify: Any = self.settings.oidc_ca_bundle_file or True
        return httpx.AsyncClient(timeout=self.settings.oidc_http_timeout_seconds, verify=verify,
                                 follow_redirects=False, headers={"Accept": "application/json"})

    def check_url(self, url: str, what: str) -> None:
        if url.startswith("https://"):
            return
        if url.startswith("http://") and self.settings.oidc_allow_insecure_http and self.settings.app_env != "production":
            return
        raise OidcError("idp_misconfigured", f"{what} must use https: {url[:200]}")

    async def _get_json(self, url: str, what: str) -> dict[str, Any]:
        self.check_url(url, what)
        try:
            async with self._client() as c:
                r = await c.get(url)
        except httpx.HTTPError as exc:
            raise OidcError("idp_unreachable", f"{what}: {type(exc).__name__}: {exc}") from exc
        if r.status_code != 200:
            raise OidcError("idp_unreachable", f"{what}: HTTP {r.status_code}")
        if len(r.content) > MAX_DOC_BYTES:
            raise OidcError("idp_misconfigured", f"{what}: response too large")
        try:
            data = r.json()
        except ValueError as exc:
            raise OidcError("idp_misconfigured", f"{what}: not JSON") from exc
        if not isinstance(data, dict):
            raise OidcError("idp_misconfigured", f"{what}: not a JSON object")
        return data

    # ------------------------------------------------------------------ discovery & keys
    async def discover(self, issuer: str, *, force: bool = False) -> dict[str, Any]:
        cached = self._discovery.get(issuer)
        if cached and not force and cached.expires > time.monotonic():
            return dict(cached.value)
        doc = await self._get_json(issuer.rstrip("/") + "/.well-known/openid-configuration", "discovery")
        # OIDC Discovery §4.3: the issuer in the document must be exactly the configured issuer.
        if doc.get("issuer") != issuer:
            raise OidcError("idp_misconfigured", f"discovery issuer {str(doc.get('issuer'))[:200]!r} != configured")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not isinstance(doc.get(key), str):
                raise OidcError("idp_misconfigured", f"discovery is missing {key}")
            self.check_url(doc[key], key)
        if isinstance(doc.get("userinfo_endpoint"), str):
            self.check_url(doc["userinfo_endpoint"], "userinfo_endpoint")
        methods = doc.get("code_challenge_methods_supported")
        if isinstance(methods, list) and methods and "S256" not in methods:
            raise OidcError("idp_misconfigured", "IdP does not support PKCE S256")
        self._discovery[issuer] = _Cached(doc, time.monotonic() + CACHE_SECONDS)
        return dict(doc)

    async def _keyset(self, jwks_uri: str, *, force: bool = False) -> PyJWKSet:
        cached = self._jwks.get(jwks_uri)
        now = time.monotonic()
        if cached and cached.expires > now and not (force and now - cached.fetched >= JWKS_MIN_REFRESH_SECONDS):
            return cached.value  # type: ignore[no-any-return]
        data = await self._get_json(jwks_uri, "jwks")
        try:
            keyset = PyJWKSet.from_dict(data)
        except jwt.PyJWTError as exc:
            raise OidcError("idp_misconfigured", f"jwks: {exc}") from exc
        self._jwks[jwks_uri] = _Cached(keyset, now + CACHE_SECONDS)
        return keyset

    async def _signing_key(self, jwks_uri: str, kid: str | None) -> PyJWK:
        for force in (False, True):  # unknown kid: refetch once (key rotation), rate-limited
            keyset = await self._keyset(jwks_uri, force=force)
            keys = [k for k in keyset.keys if k.public_key_use in (None, "sig")]
            if kid is not None:
                match = [k for k in keys if k.key_id == kid]
            else:
                match = keys if len(keys) == 1 else []
            if match:
                return match[0]
        raise OidcError("token_invalid", f"no signing key for kid {str(kid)[:64]!r}")

    async def key_count(self, jwks_uri: str) -> int:
        return len((await self._keyset(jwks_uri, force=True)).keys)

    # ------------------------------------------------------------------ protocol
    async def exchange_code(self, disc: dict[str, Any], *, client_id: str, client_secret: str | None,
                            auth_method: str, code: str, verifier: str, redirect_uri: str) -> dict[str, Any]:
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                "code_verifier": verifier, "client_id": client_id}
        auth: tuple[str | bytes, str | bytes] | None = None
        if client_secret:
            if auth_method == "client_secret_post":
                form["client_secret"] = client_secret
            else:  # RFC 6749 §2.3.1: form-urlencode the credentials before Basic encoding
                from urllib.parse import quote

                auth = (quote(client_id, safe=""), quote(client_secret, safe=""))
        url = disc["token_endpoint"]
        self.check_url(url, "token_endpoint")
        try:
            async with self._client() as c:
                r = await c.post(url, data=form, auth=auth) if auth else await c.post(url, data=form)
        except httpx.HTTPError as exc:
            raise OidcError("idp_unreachable", f"token endpoint: {type(exc).__name__}") from exc
        if len(r.content) > MAX_DOC_BYTES:
            raise OidcError("token_invalid", "token response too large")
        try:
            data = r.json()
        except ValueError:
            data = {}
        if r.status_code != 200:
            err = data.get("error") if isinstance(data, dict) else None
            raise OidcError("token_exchange_failed", f"HTTP {r.status_code} {str(err)[:100]}")
        if not isinstance(data, dict) or not isinstance(data.get("id_token"), str):
            raise OidcError("token_invalid", "token response has no id_token")
        return data

    async def validate_id_token(self, disc: dict[str, Any], id_token: str, *, client_id: str, nonce: str,
                                algorithms: list[str]) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise OidcError("token_invalid", f"malformed id_token: {exc}") from exc
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in algorithms or alg.lower() == "none" or alg.startswith("HS"):
            raise OidcError("token_invalid", f"algorithm {str(alg)[:20]!r} not allowed")
        key = await self._signing_key(disc["jwks_uri"], header.get("kid"))
        try:
            claims: dict[str, Any] = jwt.decode(
                id_token, key=key, algorithms=[alg], audience=client_id, issuer=disc["issuer"],
                leeway=LEEWAY_SECONDS, options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise OidcError("token_invalid", f"{type(exc).__name__}: {exc}") from exc
        aud = claims.get("aud")
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != client_id:
            raise OidcError("token_invalid", "azp does not match client_id for a multi-audience token")
        if not isinstance(claims.get("nonce"), str) or not constant_time_equals(claims["nonce"], nonce):
            raise OidcError("token_invalid", "nonce mismatch")
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise OidcError("token_invalid", "missing sub")
        return claims

    async def userinfo(self, disc: dict[str, Any], access_token: str) -> dict[str, Any]:
        url = disc.get("userinfo_endpoint")
        if not isinstance(url, str):
            return {}
        self.check_url(url, "userinfo_endpoint")
        try:
            async with self._client() as c:
                r = await c.get(url, headers={"Authorization": f"Bearer {access_token}"})
        except httpx.HTTPError:
            return {}
        if r.status_code != 200 or len(r.content) > MAX_DOC_BYTES:
            return {}
        try:
            data = r.json()
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}
