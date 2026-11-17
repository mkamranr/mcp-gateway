"""mTLS: agents authenticate with client certificates forwarded by a trusted TLS proxy, and the gateway presents
client certificates to upstream servers that require them (docs/mtls.md)."""

from __future__ import annotations

import socket
import ssl
import threading
import time
import urllib.parse
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import uvicorn
from conftest import ApiClient
from pki import Issued, make_ca, make_leaf

from devtools import mock_mcp_server

AGENT_CA = make_ca("Agent CA")
OTHER_CA = make_ca("Someone else's CA")
SPIFFE = "spiffe://corp.example/agents/hr-bot"
HEADER = "x-client-cert"


def forwarded(cert: Issued) -> dict[str, str]:
    """The header the bundled nginx sends: $ssl_client_escaped_cert (URL-escaped PEM)."""
    return {HEADER: urllib.parse.quote(cert.cert_pem)}


@pytest.fixture
def settings(settings, tmp_path: Path):  # noqa: ANN001, ANN201 - extends the conftest fixture
    ca_file = tmp_path / "agent-ca.pem"
    ca_file.write_text(AGENT_CA.cert_pem)
    return settings.model_copy(update={"mtls_client_ca_file": str(ca_file),
                                       "mtls_trusted_proxies": ["127.0.0.1/32"]})


def from_address(app, host: str) -> httpx.AsyncClient:  # noqa: ANN001
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(host, 40000)), base_url="http://testserver")


async def _cert_credential(scenario, **body) -> dict:  # noqa: ANN001, ANN003
    r = await scenario.admin.post("/api/v1/auth/agent-certificates", json={"agent_id": scenario.agent["id"], **body})
    assert r.status_code == 201, r.text
    return r.json()


async def _invoke(app, headers: dict[str, str], host: str = "127.0.0.1") -> httpx.Response:  # noqa: ANN001
    async with from_address(app, host) as http:
        return await http.post("/api/v1/gateway/tools/hr__get_attendance_summary/invoke",
                               json={"arguments": {"employee_id": "E1001"}}, headers=headers)


async def test_pinned_certificate_authenticates_the_agent(scenario, app, container):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    cert = make_leaf(AGENT_CA, "hr-bot", uris=(SPIFFE,))
    cred = await _cert_credential(s, certificate_pem=cert.cert_pem)
    assert cred["type"] == "client_certificate" and cred["key_prefix"] is None
    assert cred["certificate"]["fingerprint_sha256"] == cert.fingerprint
    assert cred["expires_at"]  # capped at the certificate's own expiry

    r = await _invoke(app, forwarded(cert))
    assert r.status_code == 200, r.text
    assert mock_mcp_server.CALLS["get_attendance_summary"] == 1
    ev = await container.repos.audit.col.find_one({"event_type": "tool.invocation.completed"}, sort=[("timestamp", -1)])
    assert ev["principal"]["id"] == s.agent["id"] and ev["principal"]["credential_id"] == cred["id"]

    # The same certificate works on the MCP endpoint.
    async with from_address(app, "127.0.0.1") as http:
        r = await http.post("/mcp", headers={**forwarded(cert), "accept": "application/json, text/event-stream"},
                            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                                "protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "t", "version": "1"}}})
    assert r.status_code == 200, r.text


async def test_subject_name_match_survives_certificate_renewal(scenario, app):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    await _cert_credential(s, subject_name=SPIFFE)
    for _ in range(2):  # two different certificates, same SPIFFE ID: no console change needed to renew
        r = await _invoke(app, forwarded(make_leaf(AGENT_CA, "hr-bot", uris=(SPIFFE,))))
        assert r.status_code == 200, r.text
    r = await _invoke(app, forwarded(make_leaf(AGENT_CA, "other-bot", uris=("spiffe://corp.example/agents/other",))))
    assert r.status_code == 401 and r.json()["error"]["code"] == "INVALID_CREDENTIAL"


@pytest.mark.parametrize("case", ["other_ca", "expired", "not_yet_valid", "server_only", "untrusted_proxy",
                                  "garbage", "revoked"])
async def test_certificates_that_must_not_authenticate(scenario, app, case):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    cred = await _cert_credential(s, subject_name=SPIFFE)
    good = make_leaf(AGENT_CA, "hr-bot", uris=(SPIFFE,))
    headers, host = forwarded(good), "127.0.0.1"
    if case == "other_ca":  # right name, wrong issuer
        headers = forwarded(make_leaf(OTHER_CA, "hr-bot", uris=(SPIFFE,)))
    elif case == "expired":
        headers = forwarded(make_leaf(AGENT_CA, "hr-bot", uris=(SPIFFE,), valid_from_days=-10, valid_days=2))
    elif case == "not_yet_valid":
        headers = forwarded(make_leaf(AGENT_CA, "hr-bot", uris=(SPIFFE,), valid_from_days=2))
    elif case == "server_only":  # a TLS server certificate is not a client credential
        headers = forwarded(make_leaf(AGENT_CA, "hr-bot", uris=(SPIFFE,), usage="server"))
    elif case == "untrusted_proxy":  # a valid certificate, but the header didn't come from the TLS proxy
        host = "10.20.30.40"
    elif case == "garbage":
        headers = {HEADER: "not-a-certificate"}
    elif case == "revoked":
        r = await s.admin.post(f"/api/v1/auth/agent-keys/{cred['id']}/revoke", json={"reason": "lost laptop"})
        assert r.status_code == 200
    r = await _invoke(app, headers, host)
    assert r.status_code == 401, r.text
    assert mock_mcp_server.CALLS["get_attendance_summary"] == 0


async def test_bearer_key_wins_and_spoofed_header_is_ignored_for_console(scenario, app):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    await _cert_credential(s, subject_name=SPIFFE)
    stranger = make_leaf(OTHER_CA, "x", uris=(SPIFFE,))
    r = await _invoke(app, {**forwarded(stranger), "Authorization": f"Bearer {s.key}"})
    assert r.status_code == 200  # an API key is checked as an API key; the header is not consulted
    async with from_address(app, "127.0.0.1") as http:
        r = await http.get("/api/v1/policies", headers=forwarded(make_leaf(AGENT_CA, "hr-bot", uris=(SPIFFE,))))
    assert r.status_code == 403  # an agent certificate never opens the console


async def test_certificate_credential_rules(scenario, admin):
    s = await scenario.setup()
    cert = make_leaf(AGENT_CA, "hr-bot", uris=(SPIFFE,))
    first = await _cert_credential(s, certificate_pem=cert.cert_pem)
    r = await admin.post("/api/v1/auth/agent-certificates", json={"agent_id": s.agent["id"],
                                                                  "certificate_pem": cert.cert_pem})
    assert r.status_code == 409  # one active credential per certificate
    r = await admin.post("/api/v1/auth/agent-certificates",
                         json={"agent_id": s.agent["id"], "certificate_pem": make_leaf(OTHER_CA, "x").cert_pem})
    assert r.status_code == 422 and "trusted CA" in r.text
    r = await admin.post("/api/v1/auth/agent-certificates",
                         json={"agent_id": s.agent["id"], "subject_name": SPIFFE, "certificate_pem": cert.cert_pem})
    assert r.status_code == 422  # exactly one matcher
    r = await admin.post(f"/api/v1/auth/agent-keys/{first['id']}/rotate")
    assert r.status_code == 422
    r = await admin.get("/api/v1/auth/agent-certificates/status")
    assert r.json()["enabled"] is True and "Agent CA" in r.json()["trusted_cas"][0]["subject"]
    keys = (await admin.get(f"/api/v1/auth/agent-keys?agent_id={s.agent['id']}")).json()["items"]
    assert {k["type"] for k in keys} == {"api_key", "client_certificate"}


async def test_disabled_without_a_ca_bundle(scenario, app, container, monkeypatch):
    monkeypatch.setattr(container.auth, "cert_verifier", None)
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    r = await s.admin.post("/api/v1/auth/agent-certificates", json={"agent_id": s.agent["id"], "subject_name": SPIFFE})
    assert r.status_code == 422 and "isn't enabled" in r.text
    r = await _invoke(app, forwarded(make_leaf(AGENT_CA, "hr-bot", uris=(SPIFFE,))))
    assert r.status_code == 401 and r.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


# ---------------------------------------------------------------- upstream servers that require mTLS
UPSTREAM_CA = make_ca("Upstream server CA")
GATEWAY_CLIENT_CA = make_ca("CA the upstream trusts for clients")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def mtls_upstream(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """The mock MCP server behind TLS that requires a client certificate from GATEWAY_CLIENT_CA."""
    d = tmp_path_factory.mktemp("upstream-tls")
    server_cert = make_leaf(UPSTREAM_CA, "upstream", ips=("127.0.0.1",), usage="server")
    (d / "cert.pem").write_text(server_cert.cert_pem)
    (d / "key.pem").write_text(server_cert.key_pem)
    (d / "clients.pem").write_text(GATEWAY_CLIENT_CA.cert_pem)
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(
        mock_mcp_server.build_http_app(), host="127.0.0.1", port=port, log_level="error", lifespan="on",
        ssl_certfile=str(d / "cert.pem"), ssl_keyfile=str(d / "key.pem"), ssl_ca_certs=str(d / "clients.pem"),
        ssl_cert_reqs=ssl.CERT_REQUIRED))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"https://127.0.0.1:{port}/mcp"
    server.should_exit = True
    thread.join(timeout=5)


async def _register(admin: ApiClient, endpoint: str, **extra) -> dict:  # noqa: ANN003
    r = await admin.post("/api/v1/servers", json={"name": "Secure HR", "alias": "shr", "transport": "streamable_http",
                                                  "endpoint": endpoint, "allow_private_network": True, **extra})
    assert r.status_code == 201, r.text
    return r.json()


async def test_gateway_presents_a_client_certificate_to_the_upstream(admin, container, mtls_upstream):
    client = make_leaf(GATEWAY_CLIENT_CA, "mcp-gateway", dns=("gateway.corp.example",))
    srv = await _register(admin, mtls_upstream, tls_ca_pem=UPSTREAM_CA.cert_pem,
                          client_certificate={"cert_pem": client.cert_pem, "key_pem": client.key_pem})
    assert srv["tls"]["client_certificate"]["fingerprint_sha256"] == client.fingerprint
    assert "Upstream server CA" in srv["tls"]["ca_certificates"][0]["subject"]
    assert "PRIVATE KEY" not in str(srv)
    r = await admin.post(f"/api/v1/servers/{srv['id']}/refresh-tools")
    assert r.status_code == 200, r.text
    tools = (await admin.get(f"/api/v1/servers/{srv['id']}/tools")).json()["items"]
    assert {t["upstream_name"] for t in tools} >= {"get_attendance_summary"}
    # The key is stored encrypted, never in clear.
    doc = await container.repos.servers.get(srv["tenant_id"], srv["id"])
    secret = await container.repos.secrets.get(srv["tenant_id"], doc["tls_secret_ref"])
    assert "PRIVATE KEY" not in str(secret) and "PRIVATE KEY" not in str(doc)

    # Removing the certificate: the upstream now refuses the handshake.
    r = await admin.patch(f"/api/v1/servers/{srv['id']}", json={"version": doc["version"],
                                                                "remove_client_certificate": True})
    assert r.status_code == 200 and r.json()["tls"]["client_certificate"] is None
    assert await container.repos.secrets.get(srv["tenant_id"], doc["tls_secret_ref"]) is None
    r = await admin.post(f"/api/v1/servers/{srv['id']}/refresh-tools")
    assert r.status_code >= 400


async def test_upstream_without_its_ca_is_not_trusted(admin, mtls_upstream):
    client = make_leaf(GATEWAY_CLIENT_CA, "mcp-gateway")
    srv = await _register(admin, mtls_upstream, client_certificate={"cert_pem": client.cert_pem,
                                                                    "key_pem": client.key_pem})
    r = await admin.post(f"/api/v1/servers/{srv['id']}/refresh-tools")
    assert r.status_code >= 400  # the upstream's certificate is from a private CA the gateway wasn't given


@pytest.mark.parametrize("case", ["mismatched_key", "bad_ca"])
async def test_invalid_upstream_tls_settings_are_rejected(admin, case):
    client = make_leaf(GATEWAY_CLIENT_CA, "mcp-gateway")
    body = {"client_certificate": {"cert_pem": client.cert_pem, "key_pem": make_leaf(GATEWAY_CLIENT_CA, "x").key_pem}} \
        if case == "mismatched_key" else {"tls_ca_pem": "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"}
    r = await admin.post("/api/v1/servers", json={"name": "Bad TLS", "alias": "bad", "transport": "streamable_http",
                                                  "endpoint": "https://upstream.example/mcp", **body})
    assert r.status_code == 422, r.text
    assert "PRIVATE KEY" not in r.text


@pytest.mark.parametrize("proxies,error", [([], "MTLS_TRUSTED_PROXIES is required"),
                                           (["0.0.0.0/0"], "must not trust every address")])
def test_settings_require_a_narrow_proxy_allowlist(settings, proxies, error):
    from app.config import Settings

    with pytest.raises(ValueError, match=error):
        Settings(**{**settings.model_dump(), "mtls_client_ca_file": settings.mtls_client_ca_file,
                    "mtls_trusted_proxies": proxies})


# Real OpenSSL 1.1.1 output: "req -x509 -addext basicConstraints=..." writes basicConstraints twice. OpenSSL and
# nginx accept such certificates; the gateway must handle them instead of failing with a 500.
LEGACY_CA = """\n-----BEGIN CERTIFICATE-----
MIIBjTCCATSgAwIBAgIUab0Iuoc+wCHTDgDEMqymS75TdD8wCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJTGVnYWN5IENBMB4XDTI2MTExNzA0NTEwN1oXDTM2MTExNDA0
NTEwN1owFDESMBAGA1UEAwwJTGVnYWN5IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAExjREgcdvNr+jy+iWp+DJ7fwCv1pOz7myyHZT1BMZTj7zZUig7034sBck
Ce3IxjoFFuHsFeAkLS39yKImaAuGeaNkMGIwHQYDVR0OBBYEFBgOw7eGXXfGAeCO
QrwSFmw71Qt7MB8GA1UdIwQYMBaAFBgOw7eGXXfGAeCOQrwSFmw71Qt7MA8GA1Ud
EwEB/wQFMAMBAf8wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBe
x5zvQ0xyiwD1JBUo9N0ad0xuXoJEjo000D0qDcQmjgIgbW9FtwbT9bdkkI/vSEm4
Qtf9CyIUxp5gE3WxHhVfCwg=
-----END CERTIFICATE-----
"""
LEGACY_LEAF = """\n-----BEGIN CERTIFICATE-----
MIIBYjCCAQigAwIBAgIUORMsGhGLtVNXSXtufOqRjrWzwzEwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJTGVnYWN5IENBMB4XDTI2MTExNzA0NTEwN1oXDTM2MTExNDA0
NTEwN1owEzERMA8GA1UEAwwIZHVwLWxlYWYwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAAQhnkId+9tXdH4GLbp6G9RwX9d2DbGcp4xf6LacKd0jVcicWDGVel63NJNz
Uk9scPn46zm4963FDw6znl/+TflNozkwNzATBgNVHSUEDDAKBggrBgEFBQcDAjAg
BgNVHREEGTAXhhVzcGlmZmU6Ly9sZWdhY3kvYWdlbnQwCgYIKoZIzj0EAwIDSAAw
RQIhAOf7ilQSrjKYmuasmAp8hk1dC4wXir10xjxsLZfkc1sSAiA+yHloFHSpShdg
L7sza7Qy1OZZHExem9RBlrFFOVqlVw==
-----END CERTIFICATE-----
"""
SELF_SIGNED_DUPLICATE = """\n-----BEGIN CERTIFICATE-----
MIIBmzCCAUKgAwIBAgIUXu+FK+VkKBbHmTYnVu/OZawvBU0wCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHc2VsZmR1cDAeFw0yNjExMTcwNDUxMjFaFw0zNjExMTQwNDUx
MjFaMBIxEDAOBgNVBAMMB3NlbGZkdXAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAQhnkId+9tXdH4GLbp6G9RwX9d2DbGcp4xf6LacKd0jVcicWDGVel63NJNzUk9s
cPn46zm4963FDw6znl/+TflNo3YwdDAdBgNVHQ4EFgQUHR9DXf9X5G225dxIEAkC
INUHTNkwHwYDVR0jBBgwFoAUHR9DXf9X5G225dxIEAkCINUHTNkwDwYDVR0TAQH/
BAUwAwEB/zAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAoGCCqG
SM49BAMCA0cAMEQCIBHv1Zjot57Aqsh6Iv5/JA6Bsp5vhLmSHrzblvZHgcBEAiB9
aAXiR3EfdbUjIYruFUdEz3TyWk6K37eLiQIXKnmy8w==
-----END CERTIFICATE-----
"""


def test_certificates_with_duplicate_extensions_are_handled_not_500():
    from cryptography import x509

    from app.core.client_certs import CertificateError, ClientCertVerifier, describe

    legacy = ClientCertVerifier(LEGACY_CA)
    assert "Legacy CA" in describe(legacy.cas[0]).subject  # readable for display despite the duplicate
    leaf = x509.load_pem_x509_certificate(LEGACY_LEAF.encode())
    assert legacy.verify(leaf).sans == ("spiffe://legacy/agent",)  # it can still issue agent certificates
    dup = x509.load_pem_x509_certificate(SELF_SIGNED_DUPLICATE.encode())
    with pytest.raises(CertificateError, match="duplicate extensions"):
        ClientCertVerifier(SELF_SIGNED_DUPLICATE).verify(dup)  # a client certificate like that is refused cleanly


async def test_legacy_ca_bundle_registers_and_reports(admin):
    r = await admin.post("/api/v1/servers", json={"name": "Legacy CA HR", "alias": "lhr", "transport": "streamable_http",
                                                  "endpoint": "https://hr.internal.example/mcp", "tls_ca_pem": LEGACY_CA})
    assert r.status_code == 201, r.text
    assert "Legacy CA" in r.json()["tls"]["ca_certificates"][0]["subject"]
