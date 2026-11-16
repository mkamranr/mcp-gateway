"""Mock OpenID Connect provider for tests and the no-Docker dev stack. NEVER use it in production.

Implements discovery, JWKS, /authorize (auto-approves a chosen user), /token (code + PKCE S256, client
secret basic or post), and /userinfo. ``MockIdP.tamper`` makes it misbehave on purpose so tests can
prove the gateway rejects bad tokens.

    uv run python -m devtools.mock_oidc --port 9400
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

DEFAULT_USERS: dict[str, dict[str, Any]] = {
    "alice": {"sub": "u-1001", "preferred_username": "alice.sso", "email": "alice@corp.example",
              "name": "Alice SSO", "groups": ["mgw-acme-admins"]},
    "bob": {"sub": "u-1002", "preferred_username": "bob.sso", "email": "bob@corp.example",
            "name": "Bob SSO", "groups": ["mgw-acme-developers", "mgw-auditors"]},
    "carol": {"sub": "u-1003", "preferred_username": "carol.sso", "email": "carol@corp.example",
              "name": "Carol SSO", "groups": ["unrelated-group"]},
    "root": {"sub": "u-0001", "preferred_username": "root.sso", "email": "root@corp.example",
             "name": "Platform Root", "groups": ["mgw-platform-admins"]},
}


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass
class MockIdP:
    issuer: str
    client_id: str = "mcp-gateway"
    client_secret: str = "mock-client-secret"  # noqa: S105 (test fixture)
    redirect_uris: list[str] = field(default_factory=list)  # empty = accept any (dev only)
    users: dict[str, dict[str, Any]] = field(default_factory=lambda: json.loads(json.dumps(DEFAULT_USERS)))
    tamper: set[str] = field(default_factory=set)
    key: rsa.RSAPrivateKey = field(default_factory=_new_key)
    kid: str = "mock-key-1"
    codes: dict[str, dict[str, Any]] = field(default_factory=dict)
    access_tokens: dict[str, str] = field(default_factory=dict)
    token_requests: int = 0

    def reset(self) -> None:
        self.tamper.clear()
        self.users = json.loads(json.dumps(DEFAULT_USERS))
        self.codes.clear()
        self.access_tokens.clear()
        self.token_requests = 0

    # ---------------------------------------------------------------- tokens
    def jwk(self) -> dict[str, Any]:
        pub = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        return {**pub, "kid": self.kid, "use": "sig", "alg": "RS256"}

    def id_token(self, user: dict[str, Any], nonce: str) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {**user, "iss": self.issuer, "aud": self.client_id, "iat": now, "exp": now + 300,
                                  "nonce": nonce, "auth_time": now}
        if "omit_groups" in self.tamper:
            claims.pop("groups", None)
        if "nonce" in self.tamper:
            claims["nonce"] = "not-the-nonce"
        if "aud" in self.tamper:
            claims["aud"] = "some-other-client"
        if "iss" in self.tamper:
            claims["iss"] = "https://evil.example"
        if "expired" in self.tamper:
            claims.update(iat=now - 7200, exp=now - 3600)
        if "multi_aud_no_azp" in self.tamper:
            claims["aud"] = [self.client_id, "other-client"]
        if "alg_none" in self.tamper:
            return jwt.encode(claims, key=None, algorithm="none")  # type: ignore[arg-type]
        if "hs256" in self.tamper:
            return jwt.encode(claims, self.client_secret, algorithm="HS256", headers={"kid": self.kid})
        key = _new_key() if "wrong_key" in self.tamper else self.key
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": self.kid})


def build_app(idp: MockIdP) -> Starlette:
    async def discovery(_: Request) -> JSONResponse:
        i = idp.issuer
        return JSONResponse({
            "issuer": i, "authorization_endpoint": f"{i}/authorize", "token_endpoint": f"{i}/token",
            "userinfo_endpoint": f"{i}/userinfo", "jwks_uri": f"{i}/jwks", "end_session_endpoint": f"{i}/logout",
            "response_types_supported": ["code"], "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"], "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        })

    async def jwks(_: Request) -> JSONResponse:
        return JSONResponse({"keys": [idp.jwk()]})

    async def authorize(request: Request) -> Response:
        q = request.query_params
        if q.get("client_id") != idp.client_id:
            return JSONResponse({"error": "unauthorized_client"}, status_code=400)
        redirect_uri = q.get("redirect_uri", "")
        if idp.redirect_uris and redirect_uri not in idp.redirect_uris:
            return JSONResponse({"error": "invalid_request", "error_description": "redirect_uri"}, status_code=400)
        if q.get("response_type") != "code" or q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        user_key = q.get("mock_user")
        if q.get("mock_deny"):
            return RedirectResponse(f"{redirect_uri}?{urlencode({'error': 'access_denied', 'state': q.get('state', '')})}",
                                    status_code=302)
        if not user_key:  # dev: a tiny "who are you" page
            rows = "".join(
                f'<li><a href="?{html.escape(urlencode({**dict(q), "mock_user": k}))}">{html.escape(u["name"])}</a>'
                f' <small>{html.escape(", ".join(u.get("groups", [])))}</small></li>' for k, u in idp.users.items())
            return HTMLResponse(f"<!doctype html><title>Mock IdP</title><body style='font-family:sans-serif'>"
                                f"<h2>Mock IdP (development only)</h2><p>Sign in as:</p><ul>{rows}</ul></body>")
        if user_key not in idp.users:
            return JSONResponse({"error": "unknown mock user"}, status_code=400)
        code = secrets.token_urlsafe(24)
        idp.codes[code] = {"user": user_key, "redirect_uri": redirect_uri, "nonce": q.get("nonce", ""),
                           "challenge": q["code_challenge"], "exp": time.time() + 60}
        return RedirectResponse(f"{redirect_uri}?{urlencode({'code': code, 'state': q.get('state', '')})}",
                                status_code=302)

    async def token(request: Request) -> JSONResponse:
        idp.token_requests += 1
        form = await request.form()
        client_id, secret = form.get("client_id"), form.get("client_secret")
        auth = request.headers.get("authorization", "")
        if auth.startswith("Basic "):
            from urllib.parse import unquote

            cid, _, sec = base64.b64decode(auth[6:]).decode().partition(":")
            client_id, secret = unquote(cid), unquote(sec)
        if client_id != idp.client_id or secret != idp.client_secret:
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        entry = idp.codes.pop(str(form.get("code", "")), None)  # single use
        if not entry or entry["exp"] < time.time() or form.get("redirect_uri") != entry["redirect_uri"]:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        verifier = str(form.get("code_verifier", ""))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        if challenge != entry["challenge"]:
            return JSONResponse({"error": "invalid_grant", "error_description": "PKCE"}, status_code=400)
        user = idp.users[entry["user"]]
        access = secrets.token_urlsafe(24)
        idp.access_tokens[access] = entry["user"]
        return JSONResponse({"access_token": access, "token_type": "Bearer", "expires_in": 300,
                             "id_token": idp.id_token(user, entry["nonce"])})

    async def userinfo(request: Request) -> JSONResponse:
        auth = request.headers.get("authorization", "")
        user_key = idp.access_tokens.get(auth[7:]) if auth.startswith("Bearer ") else None
        if not user_key:
            return JSONResponse({"error": "invalid_token"}, status_code=401)
        info = dict(idp.users[user_key])
        if "userinfo_sub_mismatch" in idp.tamper:
            info["sub"] = "someone-else"
        return JSONResponse(info)

    return Starlette(routes=[
        Route("/.well-known/openid-configuration", discovery), Route("/jwks", jwks),
        Route("/authorize", authorize), Route("/token", token, methods=["POST"]), Route("/userinfo", userinfo),
    ])


def main() -> None:
    import uvicorn

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=9400)
    a = ap.parse_args()
    idp = MockIdP(issuer=f"http://127.0.0.1:{a.port}")
    print(f"Mock IdP {idp.issuer}  client_id={idp.client_id}  client_secret={idp.client_secret}")
    uvicorn.run(build_app(idp), host="127.0.0.1", port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
