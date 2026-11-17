"""OAuth 2.0 for agents: IdP-issued access tokens authenticate agents, and every forged, misdirected or
over-broad token is refused (docs/agent-oauth.md)."""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.conftest import Scenario, make_client

ARGS = {"employee_id": "E1001"}


async def trust(admin: Any, idp: Any, **overrides: Any) -> dict[str, Any]:
    issuer = {"issuer": idp.issuer, "display_name": "Mock IdP", "audience": idp.api_audience, **overrides}
    r = await admin.put("/api/v1/agent-oauth/config", json={"enabled": True, "issuers": [issuer]})
    assert r.status_code == 200, r.text
    return r.json()


async def setup(scenario: Scenario, admin: Any, idp: Any, subject: str = "hr-bot", **issuer: Any) -> Scenario:
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    await trust(admin, idp, **issuer)
    r = await admin.post("/api/v1/auth/agent-oauth-clients", json={
        "agent_id": s.agent["id"], "issuer": idp.issuer, "subject": subject, "name": "hr-bot via IdP"})
    assert r.status_code == 201, r.text
    s.oauth_cred = r.json()  # type: ignore[attr-defined]
    return s


async def call(s: Scenario, token: str) -> httpx.Response:
    return await s.invoke("get_attendance_summary", ARGS, key=token)


async def client_credentials(idp: Any, client: str = "hr-bot", secret: str = "hr-bot-secret") -> str:
    async with httpx.AsyncClient() as http:
        r = await http.post(f"{idp.issuer}/token", data={"grant_type": "client_credentials"}, auth=(client, secret))
    assert r.status_code == 200, r.text
    return r.json()["access_token"]  # type: ignore[no-any-return]


# ---------------------------------------------------------------- happy path
async def test_client_credentials_token_authenticates_the_agent(scenario, admin, mock_idp, container):
    s = await setup(scenario, admin, mock_idp)
    token = await client_credentials(mock_idp)
    r = await call(s, token)
    assert r.status_code == 200, r.text
    ev = await container.repos.audit.col.find_one({"event_type": "tool.invocation.completed"})
    assert ev["principal"]["id"] == s.agent["id"] and ev["principal"]["credential_id"] == s.oauth_cred["id"]
    assert token not in json.dumps(ev, default=str)
    # MCP endpoint too.
    async with make_client(s.app) as http:
        r = await http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream"})
    assert r.status_code == 200, r.text


async def test_credential_api_and_audit(scenario, admin, mock_idp):
    s = await setup(scenario, admin, mock_idp)
    cred = s.oauth_cred
    assert cred["type"] == "oauth_client" and cred["key_prefix"] is None
    assert cred["oauth"] == {"issuer": mock_idp.issuer, "subject": "hr-bot", "subject_claim": "sub"}
    r = await admin.post(f"/api/v1/auth/agent-keys/{cred['id']}/rotate")
    assert r.status_code == 422
    # One active credential per issuer + client.
    r = await admin.post("/api/v1/auth/agent-oauth-clients", json={
        "agent_id": s.agent["id"], "issuer": mock_idp.issuer, "subject": "hr-bot"})
    assert r.status_code == 409
    # Only configured issuers.
    r = await admin.post("/api/v1/auth/agent-oauth-clients", json={
        "agent_id": s.agent["id"], "issuer": "https://evil.example", "subject": "hr-bot"})
    assert r.status_code == 422
    status = (await admin.get("/api/v1/auth/agent-oauth/status")).json()
    assert status == {"enabled": True, "issuers": [{"issuer": mock_idp.issuer, "display_name": "Mock IdP",
                                                    "subject_claim": "sub"}]}


async def test_revocation_and_expiry_are_immediate(scenario, admin, mock_idp):
    s = await setup(scenario, admin, mock_idp)
    token = mock_idp.access_token("hr-bot")
    assert (await call(s, token)).status_code == 200
    r = await admin.post(f"/api/v1/auth/agent-keys/{s.oauth_cred['id']}/revoke", json={"reason": "test"})
    assert r.status_code == 200, r.text
    assert (await call(s, token)).status_code == 401


# ---------------------------------------------------------------- forged and misdirected tokens
def _b64(data: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


@pytest.mark.parametrize("case", [
    "expired", "wrong_audience", "wrong_issuer", "wrong_key", "alg_none", "alg_hs256_with_public_key",
    "id_token", "unknown_client", "too_long_lived", "not_yet_valid", "no_exp", "tampered_payload",
])
async def test_bad_tokens_are_refused(scenario, admin, mock_idp, case):
    s = await setup(scenario, admin, mock_idp)
    idp = mock_idp
    if case == "expired":
        token = idp.access_token("hr-bot", iat=1_700_000_000, exp=1_700_000_300)
    elif case == "wrong_audience":
        token = idp.access_token("hr-bot", aud="api://something-else")
    elif case == "wrong_issuer":
        token = idp.access_token("hr-bot", iss="https://evil.example")
    elif case == "wrong_key":
        token = idp.access_token("hr-bot", key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
    elif case == "alg_none":
        good = jwt.decode(idp.access_token("hr-bot"), options={"verify_signature": False})
        token = f"{_b64({'alg': 'none', 'typ': 'JWT', 'kid': idp.kid})}.{_b64(good)}."
    elif case == "alg_hs256_with_public_key":
        from cryptography.hazmat.primitives import serialization

        pub = idp.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
        good = jwt.decode(idp.access_token("hr-bot"), options={"verify_signature": False})
        signing = f"{_b64({'alg': 'HS256', 'typ': 'JWT', 'kid': idp.kid})}.{_b64(good)}"
        import hashlib
        import hmac

        sig = base64.urlsafe_b64encode(hmac.new(pub, signing.encode(), hashlib.sha256).digest()).decode().rstrip("=")
        token = f"{signing}.{sig}"
    elif case == "id_token":
        token = idp.access_token("hr-bot", nonce="n-123")
    elif case == "unknown_client":
        token = idp.access_token("someone-else")
    elif case == "too_long_lived":
        token = idp.access_token("hr-bot", lifetime=30 * 86_400)
    elif case == "not_yet_valid":
        import time

        token = idp.access_token("hr-bot", nbf=int(time.time()) + 3600)
    elif case == "no_exp":
        token = idp.access_token("hr-bot", exp=None)
    else:
        header, payload, sig = idp.access_token("hr-bot").split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
        claims["sub"] = "admin-bot"
        token = f"{header}.{_b64(claims)}.{sig}"
    r = await call(s, token)
    assert r.status_code == 401, (case, r.text)
    assert r.json()["error"]["code"] == "INVALID_CREDENTIAL"


async def test_required_scopes_subject_claim_and_token_type(scenario, admin, mock_idp):
    s = await setup(scenario, admin, mock_idp, subject="hr-bot-app", subject_claim="azp",
                    required_scopes=["mcp.tools"], require_at_jwt_type=True)
    assert (await call(s, mock_idp.access_token("hr-bot-app", sub="service-account-uuid"))).status_code == 200
    assert (await call(s, mock_idp.access_token("hr-bot-app", scope="openid profile"))).status_code == 401
    assert (await call(s, mock_idp.access_token("hr-bot-app", scope=None, scp=["mcp.tools"]))).status_code == 200
    assert (await call(s, mock_idp.access_token("hr-bot-app", headers={"typ": "JWT"}))).status_code == 401
    # The subject claim is azp: a token for another client with a matching "sub" is not this agent.
    assert (await call(s, mock_idp.access_token("other-app", sub="hr-bot-app"))).status_code == 401


async def test_disabled_or_untrusted_issuer(scenario, admin, mock_idp):
    s = await setup(scenario, admin, mock_idp)
    token = mock_idp.access_token("hr-bot")
    r = await admin.put("/api/v1/agent-oauth/config", json={"enabled": False, "issuers": [
        {"issuer": mock_idp.issuer, "audience": mock_idp.api_audience}]})
    assert r.status_code == 200
    assert (await call(s, token)).status_code == 401
    # API keys are unaffected.
    assert (await call(s, s.key)).status_code == 200


async def test_key_rotation_at_the_idp(scenario, admin, mock_idp, container):
    s = await setup(scenario, admin, mock_idp)
    assert (await call(s, mock_idp.access_token("hr-bot"))).status_code == 200  # JWKS now cached
    old_key, old_kid = mock_idp.key, mock_idp.kid
    try:
        mock_idp.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        mock_idp.kid = "mock-key-2"
        # The unknown kid triggers one JWKS refetch, rate-limited to once a minute: allow it now.
        for cached in container.agent_oauth.client._jwks.values():  # noqa: SLF001
            cached.fetched -= 120
        assert (await call(s, mock_idp.access_token("hr-bot"))).status_code == 200
    finally:
        mock_idp.key, mock_idp.kid = old_key, old_kid


async def test_unreachable_issuer_is_503_not_401(scenario, admin, mock_idp, container):
    s = await setup(scenario, admin, mock_idp, jwks_uri="http://127.0.0.1:9/jwks")
    r = await call(s, mock_idp.access_token("hr-bot"))
    assert r.status_code == 503 and r.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"


async def test_ambiguous_mapping_is_refused(scenario, admin, mock_idp, container):
    s = await setup(scenario, admin, mock_idp)
    cred = await container.repos.credentials.get(s.tenant_id, s.oauth_cred["id"])
    dup = {k: v for k, v in cred.items() if k not in ("_id",)}
    await container.repos.credentials.insert(s.tenant_id, dup)  # bypasses the API's uniqueness check
    assert (await call(s, mock_idp.access_token("hr-bot"))).status_code == 401


# ---------------------------------------------------------------- configuration
async def test_config_requires_platform_admin_and_https(app, admin, mock_idp, scenario):
    from tests.conftest import new_user_client

    s = await scenario.setup()
    sec = await new_user_client(app, admin, s.tenant_id, ["security_admin"])
    try:
        assert (await sec.get("/api/v1/agent-oauth/config")).status_code == 403
        assert (await sec.put("/api/v1/agent-oauth/config", json={"enabled": False, "issuers": []})).status_code == 403
        assert (await sec.get("/api/v1/auth/agent-oauth/status")).status_code == 200
    finally:
        await sec.http.aclose()
    for bad in ({"enabled": True, "issuers": []},
                {"enabled": True, "issuers": [{"issuer": "ftp://x", "audience": "a"}]},
                {"enabled": True, "issuers": [{"issuer": "https://a.example", "audience": ""}]},
                {"enabled": True, "issuers": [{"issuer": "https://a.example", "audience": "a",
                                               "allowed_algorithms": ["HS256"]}]},
                {"enabled": True, "issuers": [{"issuer": "https://a.example", "audience": "a"},
                                              {"issuer": "https://a.example", "audience": "b"}]}):
        assert (await admin.put("/api/v1/agent-oauth/config", json=bad)).status_code in (400, 422), bad


async def test_issuer_test_endpoint(admin, mock_idp):
    await trust(admin, mock_idp)
    r = await admin.post("/api/v1/agent-oauth/test", json={"issuer": mock_idp.issuer})
    assert r.json() == {"ok": True, "jwks_uri": f"{mock_idp.issuer}/jwks", "signing_keys": 1}
    assert (await admin.post("/api/v1/agent-oauth/test", json={"issuer": "https://x.example"})).status_code == 404
