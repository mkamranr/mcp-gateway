"""Checks for the failover test (.github/failover/docker-compose.failover.yml). Standard library only.

Usage:
  failover_check.py setup     <base> <admin-password-file> <state>   server, tools, agent, policies, an approver
  failover_check.py load      <base> <state> <seconds> <out>         steady agent calls + console requests
  failover_check.py approvals <base> <state> <n> <out>               n approval requests, each approved at once
  failover_check.py verify    <base> <state> <load-out> <approvals>  the guarantees (see below)
  failover_check.py login     <base> <admin-password-file>           a fresh console sign-in works

What "verify" requires, after the failover:
  * every response was a success or a fail-closed, retryable 503 DEPENDENCY_UNAVAILABLE: no 500, no hang, no
    lost session, no wrong ACCESS_DENIED;
  * the gateway recovered on its own: the last RECOVERED_SECONDS of the load were all successes;
  * every approved call completed, and reached the upstream exactly once: exactly one completion and no failed
    attempt (a deferred attempt may leave a dispatch event of its own; it never called the upstream);
  * every successful agent call has its completion in the audit log.
"""

from __future__ import annotations

import json
import secrets
import sys
import time
import urllib.error
import urllib.request
from typing import Any

RECOVERED_SECONDS = 10
TIMEOUT = 40  # longer than any server-side dependency timeout: a hang shows up as status 0


class Session:
    def __init__(self, base: str, cookies: dict[str, str] | None = None, csrf: str = "", bearer: str = "") -> None:
        if not base.startswith(("http://", "https://")):
            raise SystemExit("base URL must be http(s)")
        self.base, self.cookies, self.csrf, self.bearer = base.rstrip("/"), cookies or {}, csrf, bearer

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)  # noqa: S310
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
        if self.csrf and method != "GET":
            req.add_header("X-CSRF-Token", self.csrf)
        if self.bearer:
            req.add_header("Authorization", f"Bearer {self.bearer}")
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # noqa: S310
                for c in r.headers.get_all("Set-Cookie") or []:
                    k, v = c.split("=", 1)
                    self.cookies[k.strip()] = v.split(";", 1)[0]
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw[:200].decode(errors="replace")
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            return 0, str(e)

    def ok(self, method: str, path: str, body: Any = None, expect: tuple[int, ...] = (200, 201)) -> Any:
        status, data = self.call(method, path, body)
        if status not in expect:
            raise SystemExit(f"{method} {path} -> {status} {data}")
        return data

    def dump(self) -> dict[str, Any]:
        return {"cookies": self.cookies, "csrf": self.csrf}


def sign_in(base: str, username: str, password: str) -> Session:
    s = Session(base)
    me = s.ok("POST", "/api/v1/auth/login", {"username": username, "password": password})
    s.csrf = me["csrf_token"]
    return s


def code_of(data: Any) -> str | None:
    return data.get("error", {}).get("code") if isinstance(data, dict) else None


def setup(base: str, password_file: str, state_file: str) -> None:
    admin = sign_in(base, "admin", open(password_file, encoding="utf-8").read().strip())
    tid = admin.ok("GET", "/api/v1/auth/me")["tenant_id"]
    srv = admin.ok("POST", "/api/v1/servers", {
        "name": "HR (mock)", "alias": "hr", "transport": "streamable_http", "endpoint": "http://mock-upstream:9100/mcp",
        "environment": "production", "allow_private_network": True})
    admin.ok("POST", f"/api/v1/servers/{srv['id']}/refresh-tools")
    tools = {t["upstream_name"]: t for t in admin.ok("GET", f"/api/v1/servers/{srv['id']}/tools")["items"]}
    for name, risk in (("get_attendance_summary", "low"), ("send_email", "high")):
        t = tools[name]
        admin.ok("PATCH", f"/api/v1/tools/{t['id']}", {"version": t["version"], "risk_level": risk, "enabled": True})
    agent = admin.ok("POST", f"/api/v1/tenants/{tid}/agents", {"name": "failover-agent"})
    key = admin.ok("POST", "/api/v1/auth/agent-keys", {"agent_id": agent["id"]})["secret"]
    for name, tool, approval in (("attendance", "get_attendance_summary", False), ("email", "send_email", True)):
        admin.ok("POST", "/api/v1/policies", {
            "name": name, "effect": "allow", "principals": {"types": ["agent"], "ids": [agent["id"]]},
            "resources": {"servers": ["hr"], "tools": [tool]}, "actions": ["discover", "invoke"],
            "constraints": {"require_approval": approval}})
    password = "Fo-" + secrets.token_urlsafe(18)
    admin.ok("POST", f"/api/v1/tenants/{tid}/users", {"username": "failover.approver", "password": password,
                                                      "roles": ["approver"]})
    approver = sign_in(base, "failover.approver", password)
    status, data = Session(base, bearer=key).call("POST", "/api/v1/gateway/tools/hr__get_attendance_summary/invoke",
                                                   {"arguments": {"employee_id": "E1001"}})
    if status != 200:
        raise SystemExit(f"baseline agent call failed: {status} {data}")
    json.dump({"admin": admin.dump(), "approver": approver.dump(), "key": key, "agent_id": agent["id"]},
              open(state_file, "w", encoding="utf-8"))
    print("set up: server, 2 tools, agent, 2 policies, approver; baseline call ok")


def sessions(base: str, state_file: str) -> tuple[dict[str, Any], Session, Session, Session]:
    st = json.load(open(state_file, encoding="utf-8"))
    admin = Session(base, dict(st["admin"]["cookies"]), st["admin"]["csrf"])
    approver = Session(base, dict(st["approver"]["cookies"]), st["approver"]["csrf"])
    return st, admin, approver, Session(base, bearer=st["key"])


def load(base: str, state_file: str, seconds: float, out: str) -> None:
    _, admin, _, agent = sessions(base, state_file)
    t0, results, i = time.time(), [], 0
    while time.time() - t0 < seconds:
        i += 1
        if i % 2:
            kind, (status, data) = "agent", agent.call("POST", "/api/v1/gateway/tools/hr__get_attendance_summary/invoke",
                                                       {"arguments": {"employee_id": f"E{1000 + i % 90}"}})
        else:
            kind, (status, data) = "console", admin.call("GET", "/api/v1/auth/me")
        results.append({"t": round(time.time() - t0, 2), "kind": kind, "status": status, "code": code_of(data),
                        "detail": None if status == 200 else str(data)[:160]})
        time.sleep(0.1)
    json.dump({"t0": t0, "results": results}, open(out, "w", encoding="utf-8"))
    bad = [r for r in results if r["status"] != 200]
    window = f"{bad[0]['t']}s-{bad[-1]['t']}s" if bad else "none"
    print(f"{len(results)} requests, {len(results) - len(bad)} ok, {len(bad)} not ok (window {window})")


def approvals(base: str, state_file: str, n: int, out: str) -> None:
    _, _, approver, agent = sessions(base, state_file)
    ids = []
    for i in range(n):
        data = agent.ok("POST", "/api/v1/gateway/tools/hr__send_email/invoke", {"arguments": {
            "to": f"new.hire{i}@example.org", "subject": "Welcome", "body": "Your first day is Monday."}}, expect=(202,))
        approver.ok("POST", f"/api/v1/approvals/{data['approval_id']}/approve", {"comment": "failover test"})
        ids.append(data["approval_id"])
    json.dump(ids, open(out, "w", encoding="utf-8"))
    print(f"{n} approvals approved: {', '.join(ids)}")


def verify(base: str, state_file: str, load_out: str, approvals_out: str) -> None:
    st, admin, _, _ = sessions(base, state_file)
    problems: list[str] = []
    loaded = json.load(open(load_out, encoding="utf-8"))
    t0, results = loaded["t0"], loaded["results"]
    wrong = [r for r in results if r["status"] != 200 and not (r["status"] == 503 and r["code"] == "DEPENDENCY_UNAVAILABLE")]
    for r in wrong[:10]:
        problems.append(f"at {r['t']}s {r['kind']} got {r['status']} {r['code'] or ''} {r['detail'] or ''}")
    end = results[-1]["t"]
    tail = [r for r in results if r["t"] >= end - RECOVERED_SECONDS]
    if not tail or any(r["status"] != 200 for r in tail):
        problems.append(f"not recovered: the last {RECOVERED_SECONDS}s still had failures")
    fail_closed = sum(1 for r in results if r["status"] == 503)
    print(f"load: {len(results)} requests, {fail_closed} fail-closed 503, {len(wrong)} wrong")

    ids = json.load(open(approvals_out, encoding="utf-8"))
    deadline, final = time.time() + 180, {}
    while time.time() < deadline:
        for a in ids:
            if a not in final:
                status, doc = admin.call("GET", f"/api/v1/approvals/{a}")
                if status == 200 and doc["status"] in ("COMPLETED", "FAILED", "EXECUTION_ABORTED", "REJECTED",
                                                       "EXPIRED", "CANCELLED", "CANCELLED_BY_ADMIN"):
                    final[a] = doc
        if len(final) == len(ids):
            break
        time.sleep(3)
    for a in ids:
        doc = final.get(a)
        if not doc:
            problems.append(f"approval {a} did not finish within 180 s")
            continue
        def count(event: str, a: str = a) -> int:
            return int(admin.ok("GET", f"/api/v1/audit/events?approval_id={a}&event_type={event}&limit=1")["total"])
        completed = count("tool.invocation.completed")
        failed = count("tool.invocation.failed") + count("tool.invocation.timed_out")
        deferred = count("approval.execution.deferred")
        print(f"approval {a}: {doc['status']}, upstream completions {completed}, failed attempts {failed}, "
              f"deferred {deferred}x")
        if doc["status"] != "COMPLETED":
            problems.append(f"approval {a} ended {doc['status']}: {doc.get('execution')}")
        if completed != 1 or failed:
            problems.append(f"approval {a} reached the upstream {completed + failed} times")

    ok_calls = sum(1 for r in results if r["kind"] == "agent" and r["status"] == 200)
    window = (f"start={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(t0 - 5))}"
              f"&end={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(t0 + end + 60))}")
    audited = admin.ok("GET", f"/api/v1/audit/events?principal={st['agent_id']}&event_type=tool.invocation.completed"
                              f"&{window}&limit=1")["total"]
    print(f"agent calls answered 200 during the load: {ok_calls}; completions audited in that window: {audited}")
    if audited < ok_calls:
        problems.append(f"{ok_calls - audited} successful calls have no audit record")
    if problems:
        raise SystemExit("FAILED:\n  " + "\n  ".join(problems))
    print("all guarantees held")


def login(base: str, password_file: str) -> None:
    sign_in(base, "admin", open(password_file, encoding="utf-8").read().strip())
    print("fresh sign-in ok")


def main() -> None:
    cmd, a = sys.argv[1], sys.argv[2:]
    if cmd == "setup":
        setup(a[0], a[1], a[2])
    elif cmd == "load":
        load(a[0], a[1], float(a[2]), a[3])
    elif cmd == "approvals":
        approvals(a[0], a[1], int(a[2]), a[3])
    elif cmd == "verify":
        verify(a[0], a[1], a[2], a[3])
    elif cmd == "login":
        login(a[0], a[1])
    else:
        raise SystemExit(f"unknown command {cmd}")


if __name__ == "__main__":
    main()
