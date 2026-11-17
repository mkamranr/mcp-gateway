"""End-to-end checks for OAuth 2.0 for agents against a real Keycloak (.github/oauth/docker-compose.oauth.yml).
Standard library only.

Usage: oauth_check.py <console-base> <keycloak-base> <admin-password-file> <pki-dir>

Requires, through the real nginx and gateway containers:
  * the gateway fetches Keycloak's keys over HTTPS from an internal CA;
  * an agent authenticates with a client-credentials access token, over REST and MCP, audited against its
    OAuth credential;
  * a token for another client, a token without the gateway's audience, an ID token, a tampered token and a token
    missing a required scope are refused; API keys keep working;
  * revoking the credential locks the agent out at once.
"""

from __future__ import annotations

import base64
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

ISSUER = "https://keycloak:8443/realms/ci"
AUDIENCE = "api://mcp-gateway"
INVOKE = "/api/v1/gateway/tools/hr__get_attendance_summary/invoke"
TIMEOUT = 30


def call(base: str, method: str, path: str, body: Any = None, headers: dict[str, str] | None = None,
         cookies: dict[str, str] | None = None, ctx: ssl.SSLContext | None = None,
         form: dict[str, str] | None = None) -> tuple[int, Any]:
    if not base.startswith(("http://", "https://")):
        raise SystemExit("base URL must be http(s)")
    data = json.dumps(body).encode() if body is not None else (urllib.parse.urlencode(form).encode() if form else None)
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers or {})  # noqa: S310
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if cookies:
        req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:  # noqa: S310
            if cookies is not None:
                for c in r.headers.get_all("Set-Cookie") or []:
                    k, v = c.split("=", 1)
                    cookies[k.strip()] = v.split(";", 1)[0]
            raw = r.read()
            try:
                return r.status, json.loads(raw) if raw else None
            except ValueError:
                return r.status, raw[:300].decode(errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw[:300].decode(errors="replace")
    except (urllib.error.URLError, ssl.SSLError, ConnectionError, TimeoutError) as e:
        return 0, f"{type(e).__name__}: {e}"


class Admin:
    def __init__(self, base: str, password: str) -> None:
        self.base, self.cookies = base, {}
        status, me = call(base, "POST", "/api/v1/auth/login", {"username": "admin", "password": password},
                          cookies=self.cookies)
        if status != 200:
            raise SystemExit(f"admin sign-in failed: {status} {me}")
        self.csrf, self.tenant = me["csrf_token"], me["tenant_id"]

    def try_(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        return call(self.base, method, path, body, headers={"X-CSRF-Token": self.csrf} if method != "GET" else {},
                    cookies=self.cookies)

    def ok(self, method: str, path: str, body: Any = None) -> Any:
        status, data = self.try_(method, path, body)
        if status not in (200, 201):
            raise SystemExit(f"{method} {path} -> {status} {data}")
        return data


def main() -> None:
    console, keycloak, password_file, pki = sys.argv[1:5]
    ctx = ssl.create_default_context(cafile=f"{pki}/idp-ca.pem")
    problems: list[str] = []

    def expect(label: str, ok: bool, detail: Any = "") -> None:
        print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f": {detail}"))
        if not ok:
            problems.append(label)

    def token(client: str, secret: str, field: str = "access_token", scope: str | None = None) -> str:
        form = {"grant_type": "client_credentials", **({"scope": scope} if scope else {})}
        basic = base64.b64encode(f"{client}:{secret}".encode()).decode()
        status, data = call(keycloak, "POST", "/realms/ci/protocol/openid-connect/token", headers={
            "Authorization": f"Basic {basic}"}, ctx=ctx, form=form)
        if status != 200 or field not in (data or {}):
            raise SystemExit(f"token for {client}: {status} {data}")
        return str(data[field])

    # ---- Keycloak takes a while to start and import the realm
    for _ in range(90):
        status, disc = call(keycloak, "GET", "/realms/ci/.well-known/openid-configuration", ctx=ctx)
        if status == 200:
            break
        time.sleep(2)
    else:
        raise SystemExit(f"keycloak did not come up: {status} {disc}")
    expect("Keycloak issuer is the configured one", disc.get("issuer") == ISSUER, disc.get("issuer"))

    admin = Admin(console, open(password_file, encoding="utf-8").read().strip())
    issuer = {"issuer": ISSUER, "display_name": "Keycloak (CI)", "audience": AUDIENCE, "subject_claim": "azp"}
    admin.ok("PUT", "/api/v1/agent-oauth/config", {"enabled": True, "issuers": [issuer]})
    test = admin.ok("POST", "/api/v1/agent-oauth/test", {"issuer": ISSUER})
    expect("gateway fetches Keycloak's keys over HTTPS (internal CA)", test.get("ok") is True
           and test.get("signing_keys", 0) >= 1, test)

    # ---- upstream, agent, OAuth credential, policy
    srv = admin.ok("POST", "/api/v1/servers", {"name": "HR", "alias": "hr", "transport": "streamable_http",
                                               "endpoint": "http://mock-upstream:9100/mcp",
                                               "allow_private_network": True})
    admin.ok("POST", f"/api/v1/servers/{srv['id']}/refresh-tools")
    tools = {t["upstream_name"]: t for t in admin.ok("GET", f"/api/v1/servers/{srv['id']}/tools")["items"]}
    t = tools["get_attendance_summary"]
    admin.ok("PATCH", f"/api/v1/tools/{t['id']}", {"version": t["version"], "risk_level": "low", "enabled": True})
    agent = admin.ok("POST", f"/api/v1/tenants/{admin.tenant}/agents", {"name": "hr-bot"})
    cred = admin.ok("POST", "/api/v1/auth/agent-oauth-clients", {"agent_id": agent["id"], "issuer": ISSUER,
                                                                   "subject": "hr-bot"})
    key = admin.ok("POST", "/api/v1/auth/agent-keys", {"agent_id": agent["id"]})["secret"]
    admin.ok("POST", "/api/v1/policies", {
        "name": "hr-bot attendance", "effect": "allow", "principals": {"types": ["agent"], "ids": [agent["id"]]},
        "resources": {"servers": ["hr"], "tools": ["get_attendance_summary"]}, "actions": ["discover", "invoke"]})
    args = {"arguments": {"employee_id": "E1001"}}

    def invoke(bearer: str) -> int:
        return call(console, "POST", INVOKE, args, headers={"Authorization": f"Bearer {bearer}"})[0]

    # ---- the agent's own token
    access = token("hr-bot", "hr-bot-secret")
    expect("client-credentials token: tool call", invoke(access) == 200)
    status, data = call(console, "POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "ci", "version": "1"}}},
        headers={"Authorization": f"Bearer {access}", "Accept": "application/json, text/event-stream"})
    expect("client-credentials token: MCP initialize", status == 200, (status, data))
    events = admin.ok("GET", f"/api/v1/audit/events?principal={agent['id']}&event_type=tool.invocation.completed"
                             "&limit=5")["items"]
    expect("call audited against the OAuth credential",
           bool(events) and events[0]["principal"].get("credential_id") == cred["id"], events[:1])
    expect("access token not written to the audit log", access not in json.dumps(events))

    # ---- tokens that must be refused
    expect("token for another client (no credential): 401", invoke(token("stranger", "stranger-secret")) == 401)
    expect("token without the gateway's audience: 401", invoke(token("no-audience", "no-audience-secret")) == 401)
    expect("ID token: 401", invoke(token("hr-bot", "hr-bot-secret", "id_token", scope="openid")) == 401)
    h, p, s = access.split(".")
    claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    claims["azp"] = "stranger"
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    expect("tampered token: 401", invoke(f"{h}.{forged}.{s}") == 401)
    expect("API key still works alongside", invoke(key) == 200)

    admin.ok("PUT", "/api/v1/agent-oauth/config", {"enabled": True, "issuers": [{**issuer,
                                                                                "required_scopes": ["mcp.tools"]}]})
    time.sleep(6)  # the configuration is cached for a few seconds per replica
    expect("token missing a required scope: 401", invoke(token("hr-bot", "hr-bot-secret")) == 401)
    admin.ok("PUT", "/api/v1/agent-oauth/config", {"enabled": True, "issuers": [issuer]})
    time.sleep(6)
    expect("required scope removed: accepted again", invoke(token("hr-bot", "hr-bot-secret")) == 200)

    admin.ok("POST", f"/api/v1/auth/agent-keys/{cred['id']}/revoke", {"reason": "ci"})
    expect("revoked OAuth credential: 401 at once", invoke(token("hr-bot", "hr-bot-secret")) == 401)

    if problems:
        raise SystemExit(f"FAILED: {len(problems)} check(s)")
    print("all agent OAuth checks passed")


if __name__ == "__main__":
    main()
