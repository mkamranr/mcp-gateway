"""Backup and restore drill against a running Docker Compose stack (spec Phase 5: "restore procedure tested").

    python restore_drill.py seed   <base-url> <bootstrap-password-file> <state.json>
    python restore_drill.py mutate <base-url> <bootstrap-password-file> <state.json>
    python restore_drill.py check  <base-url> <bootstrap-password-file> <state.json> <before.json> <after.json>

seed:   creates data that exercises every kind of stored state (tenant + tenant admin, upstream server with
        an encrypted bearer secret, agent + API key, encrypted SSO client secret) and proves the key works.
mutate: run after the backup. Creates an agent that must NOT survive the restore.
check:  run after the restore. Everything from seed is back and usable, the post-backup agent is gone, and
        the verify_data reports taken before the backup and after the restore match.

Standard library only. Cookies are handled by hand (the session cookie is Secure and this talks plain HTTP).
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from typing import Any

MODE, BASE, PASSWORD_FILE, STATE_FILE = sys.argv[1], sys.argv[2].rstrip("/"), sys.argv[3], sys.argv[4]
if not BASE.startswith(("http://", "https://")):
    sys.exit("base URL must be http(s)")
PASSWORD = open(PASSWORD_FILE, encoding="utf-8").read().strip()
TENANT_ADMIN_PASSWORD = "Drill-Tenant-Admin-Pass-1"  # noqa: S105 (throwaway CI data)
SSO_SECRET = "drill-sso-client-secret"  # noqa: S105
FAILURES: list[str] = []
# Collections whose size must be identical before the backup and after the restore. Audit and usage grow
# during the drill itself (logins, health checks) and are compared with >= instead.
STABLE = ("tenants", "users", "tenant_memberships", "agents", "credentials", "mcp_servers", "secrets", "tools",
          "policies", "system_settings")
GROWING = ("audit_events",)


class Session:
    def __init__(self) -> None:
        self.cookies: dict[str, str] = {}
        self.csrf = ""

    def call(self, method: str, path: str, body: Any = None, bearer: str | None = None) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(BASE + path, data=data, method=method)  # noqa: S310 (scheme checked)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if bearer:
            req.add_header("Authorization", f"Bearer {bearer}")
        elif self.cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
        if self.csrf and method not in ("GET", "HEAD") and not bearer:
            req.add_header("X-CSRF-Token", self.csrf)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310
                status, msg, payload = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            status, msg, payload = e.code, e.headers, e.read()
        for raw in msg.get_all("Set-Cookie") or []:
            name, _, rest = raw.partition("=")
            self.cookies[name.strip()] = rest.split(";", 1)[0]
        try:
            return status, json.loads(payload) if payload else None
        except ValueError:
            return status, payload[:200]

    def login(self, username: str, password: str) -> int:
        status, body = self.call("POST", "/api/v1/auth/login", {"username": username, "password": password})
        if status == 200:
            self.csrf = body["csrf_token"]
        return status


def check(cond: bool, label: str, detail: Any = "") -> None:
    print(("PASS " if cond else "FAIL ") + label + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


def must(status: int, body: Any, expected: int, what: str) -> Any:
    if status != expected:
        sys.exit(f"{what}: HTTP {status} {str(body)[:300]}")
    return body


def admin() -> Session:
    s = Session()
    if s.login("admin", PASSWORD) != 200:
        sys.exit("bootstrap admin cannot sign in")
    return s


def seed() -> None:
    s = admin()
    me = must(*s.call("GET", "/api/v1/auth/me"), 200, "me")
    tenant = must(*s.call("POST", "/api/v1/tenants", {
        "name": "Drill Corp", "slug": "drill", "admin_username": "drill-admin",
        "admin_password": TENANT_ADMIN_PASSWORD}), 201, "create tenant")
    server = must(*s.call("POST", "/api/v1/servers", {
        "name": "Drill upstream", "alias": "drill", "transport": "streamable_http",
        "endpoint": "https://mcp.drill.invalid/mcp", "authentication_mode": "bearer",
        "secret": {"token": "drill-upstream-token"}}), 201, "create server")
    agent = must(*s.call("POST", f"/api/v1/tenants/{me['tenant_id']}/agents", {"name": "drill-agent"}),
                 201, "create agent")
    key = must(*s.call("POST", "/api/v1/auth/agent-keys", {"agent_id": agent["id"], "name": "drill",
                                                           "scopes": ["tools:list"]}), 201, "create key")
    must(*s.call("PUT", "/api/v1/sso/config", {"enabled": False, "issuer": "https://idp.drill.invalid",
                                               "client_id": "drill", "client_secret": SSO_SECRET}), 200, "sso")
    status, _ = Session().call("GET", "/api/v1/gateway/tools", bearer=key["secret"])
    check(status == 200, "agent key works before the backup", status)
    state = {"tenant_id": me["tenant_id"], "drill_tenant_id": tenant["id"], "server_id": server["id"],
             "agent_id": agent["id"], "agent_key": key["secret"]}
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f)
    print(f"seeded tenant={tenant['id']} server={server['id']} agent={agent['id']}")


def mutate() -> None:
    state = json.load(open(STATE_FILE, encoding="utf-8"))
    s = admin()
    agent = must(*s.call("POST", f"/api/v1/tenants/{state['tenant_id']}/agents", {"name": "post-backup-agent"}),
                 201, "create post-backup agent")
    state["post_backup_agent_id"] = agent["id"]
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f)
    print(f"created post-backup agent {agent['id']}")


def check_restore(before_file: str, after_file: str) -> None:
    state = json.load(open(STATE_FILE, encoding="utf-8"))
    s = Session()
    check(s.login("admin", PASSWORD) == 200, "bootstrap admin signs in after the restore")
    check(Session().login("drill-admin", TENANT_ADMIN_PASSWORD) == 200, "tenant admin created before the backup signs in")
    status, tenants = s.call("GET", "/api/v1/tenants")
    check(status == 200 and any(t["id"] == state["drill_tenant_id"] for t in tenants["items"]), "tenant restored")
    status, server = s.call("GET", f"/api/v1/servers/{state['server_id']}")
    check(status == 200 and server.get("has_secret") is True, "server and its secret reference restored", status)
    status, _ = s.call("GET", f"/api/v1/agents/{state['agent_id']}")
    check(status == 200, "agent restored", status)
    status, _ = s.call("GET", f"/api/v1/agents/{state['post_backup_agent_id']}")
    check(status == 404, "agent created after the backup is gone", status)
    status, _ = Session().call("GET", "/api/v1/gateway/tools", bearer=state["agent_key"])
    check(status == 200, "agent key issued before the backup still authenticates (same pepper)", status)
    status, sso = s.call("GET", "/api/v1/sso/config")
    check(status == 200 and sso.get("has_client_secret") is True and SSO_SECRET not in json.dumps(sso),
          "SSO configuration restored, secret still write-only")

    before = json.load(open(before_file, encoding="utf-8"))
    after = json.load(open(after_file, encoding="utf-8"))
    check(after["ciphertexts"]["failed"] == [], "every ciphertext decrypts after the restore", after["ciphertexts"])
    check(after["ciphertexts"]["checked"] == before["ciphertexts"]["checked"] >= 2,
          "same number of ciphertexts as at backup time", (before["ciphertexts"], after["ciphertexts"]))
    for name in STABLE:
        b, a = before["collections"].get(name, 0), after["collections"].get(name, 0)
        check(a == b, f"{name}: {b} documents at backup, {a} after restore", (b, a))
    for name in GROWING:
        b, a = before["collections"].get(name, 0), after["collections"].get(name, 0)
        check(a >= b > 0, f"{name}: {b} at backup, {a} after restore (history kept)", (b, a))


if MODE == "seed":
    seed()
elif MODE == "mutate":
    mutate()
elif MODE == "check":
    check_restore(sys.argv[5], sys.argv[6])
else:
    sys.exit(f"unknown mode {MODE}")
if FAILURES:
    print(f"\n{len(FAILURES)} check(s) failed")
    sys.exit(1)
print("\nall checks passed")
