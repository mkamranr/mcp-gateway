"""End-to-end checks for agent and upstream mTLS (.github/mtls/docker-compose.mtls.yml). Standard library only.

Usage: mtls_check.py <console-base> <agent-tls-base> <admin-password-file> <pki-dir>

Requires, through the real nginx and gateway containers:
  * an agent with a registered certificate is served on the mTLS listener, over REST and MCP;
  * no certificate, or one from another CA, is refused by nginx; a trusted but unregistered one by the gateway;
  * a certificate header sent to the console listener is stripped (spoofing), and so is a bearer key on the
    mTLS listener (certificate only);
  * the call is audited against the certificate credential, and revoking it locks the agent out;
  * the gateway reaches an upstream that requires a client certificate only once it has one.
"""

from __future__ import annotations

import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

SPIFFE = "spiffe://ci.example/agents/hr-bot"
INVOKE = "/api/v1/gateway/tools/hr__get_attendance_summary/invoke"
TIMEOUT = 30


def call(base: str, method: str, path: str, body: Any = None, headers: dict[str, str] | None = None,
         ctx: ssl.SSLContext | None = None, cookies: dict[str, str] | None = None) -> tuple[int, Any]:
    if not base.startswith(("http://", "https://")):
        raise SystemExit("base URL must be http(s)")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers or {})  # noqa: S310
    if data is not None:
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

    def ok(self, method: str, path: str, body: Any = None, expect: tuple[int, ...] = (200, 201)) -> Any:
        status, data = self.try_(method, path, body)
        if status not in expect:
            raise SystemExit(f"{method} {path} -> {status} {data}")
        return data

    def try_(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        return call(self.base, method, path, body, headers={"X-CSRF-Token": self.csrf} if method != "GET" else {},
                    cookies=self.cookies)


def tls(pki: str, cert: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=f"{pki}/edge-ca.pem")  # trusts nginx's listener certificate
    if cert:
        ctx.load_cert_chain(f"{pki}/{cert}.pem", f"{pki}/{cert}.key")
    return ctx


def main() -> None:
    console, agent_base, password_file, pki = sys.argv[1:5]
    problems: list[str] = []

    def expect(label: str, ok: bool, detail: Any = "") -> None:
        print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f": {detail}"))
        if not ok:
            problems.append(label)

    admin = Admin(console, open(password_file, encoding="utf-8").read().strip())
    status = admin.ok("GET", "/api/v1/auth/agent-certificates/status")
    expect("client certificates enabled on the gateway", status["enabled"] is True, status)

    # ---- upstream that requires a client certificate
    srv = admin.ok("POST", "/api/v1/servers", {
        "name": "HR (mTLS)", "alias": "hr", "transport": "streamable_http",
        "endpoint": "https://mock-upstream-tls:9443/mcp", "allow_private_network": True,
        "tls_ca_pem": open(f"{pki}/upstream-ca.pem", encoding="utf-8").read()})
    code, data = admin.try_("POST", f"/api/v1/servers/{srv['id']}/refresh-tools")
    expect("upstream refuses the gateway without a client certificate", code >= 400, (code, data))
    srv = admin.ok("PATCH", f"/api/v1/servers/{srv['id']}", {"version": srv["version"], "client_certificate": {
        "cert_pem": open(f"{pki}/gateway-client.pem", encoding="utf-8").read(),
        "key_pem": open(f"{pki}/gateway-client.key", encoding="utf-8").read()}})
    expect("server API never returns the private key", "PRIVATE KEY" not in json.dumps(srv))
    code, data = admin.try_("POST", f"/api/v1/servers/{srv['id']}/refresh-tools")
    expect("upstream accepts the gateway's client certificate", code == 200, (code, data))
    tools = {t["upstream_name"]: t for t in admin.ok("GET", f"/api/v1/servers/{srv['id']}/tools")["items"]}
    t = tools["get_attendance_summary"]
    admin.ok("PATCH", f"/api/v1/tools/{t['id']}", {"version": t["version"], "risk_level": "low", "enabled": True})

    # ---- agent with a certificate credential
    agent = admin.ok("POST", f"/api/v1/tenants/{admin.tenant}/agents", {"name": "hr-bot"})
    cred = admin.ok("POST", "/api/v1/auth/agent-certificates", {"agent_id": agent["id"], "subject_name": SPIFFE})
    key = admin.ok("POST", "/api/v1/auth/agent-keys", {"agent_id": agent["id"]})["secret"]
    admin.ok("POST", "/api/v1/policies", {
        "name": "hr-bot attendance", "effect": "allow", "principals": {"types": ["agent"], "ids": [agent["id"]]},
        "resources": {"servers": ["hr"], "tools": ["get_attendance_summary"]}, "actions": ["discover", "invoke"]})
    args = {"arguments": {"employee_id": "E1001"}}

    code, data = call(agent_base, "POST", INVOKE, args, ctx=tls(pki, "agent"))
    expect("agent certificate: tool call through the mTLS listener", code == 200, (code, data))
    code, data = call(agent_base, "POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "ci", "version": "1"}}},
        headers={"Accept": "application/json, text/event-stream"}, ctx=tls(pki, "agent"))
    expect("agent certificate: MCP initialize through the mTLS listener", code == 200, (code, data))

    code, data = call(agent_base, "POST", INVOKE, args, ctx=tls(pki, None))
    expect("no client certificate: refused by nginx", code in (0, 400, 495, 496), (code, data))
    code, data = call(agent_base, "POST", INVOKE, args, ctx=tls(pki, "impostor"))
    expect("certificate from another CA: refused by nginx", code in (0, 400, 495, 496), (code, data))
    code, data = call(agent_base, "POST", INVOKE, args, ctx=tls(pki, "unknown"))
    expect("trusted but unregistered certificate: 401 from the gateway", code == 401, (code, data))
    code, data = call(agent_base, "POST", INVOKE, args, headers={"Authorization": f"Bearer {key}"},
                      ctx=tls(pki, "unknown"))
    expect("bearer key on the mTLS listener is stripped (certificate only)", code == 401, (code, data))
    code, data = call(agent_base, "GET", "/api/v1/policies", ctx=tls(pki, "agent"))
    expect("mTLS listener serves agent endpoints only", code == 404, (code, data))

    pem = open(f"{pki}/agent.pem", encoding="utf-8").read()
    code, data = call(console, "POST", INVOKE, args, headers={"X-Client-Cert": urllib.parse.quote(pem)})
    expect("spoofed certificate header on the console listener is stripped", code == 401, (code, data))

    events = admin.ok("GET", f"/api/v1/audit/events?principal={agent['id']}&event_type=tool.invocation.completed"
                             "&limit=5")["items"]
    expect("call audited against the certificate credential",
           bool(events) and events[0]["principal"].get("credential_id") == cred["id"], events[:1])

    admin.ok("POST", f"/api/v1/auth/agent-keys/{cred['id']}/revoke", {"reason": "ci"})
    code, data = call(agent_base, "POST", INVOKE, args, ctx=tls(pki, "agent"))
    expect("revoked certificate credential: 401", code == 401, (code, data))

    if problems:
        raise SystemExit(f"FAILED: {len(problems)} check(s)")
    print("all mTLS checks passed")


if __name__ == "__main__":
    main()
