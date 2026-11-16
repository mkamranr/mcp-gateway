"""Smoke test against a running Docker Compose stack (through the web-ui proxy, as a browser would).

Usage: python compose_smoke.py <base-url> <bootstrap-password-file>
Standard library only. Cookies are handled by hand because the session cookie is Secure (``__Host-``)
and this check talks plain HTTP to 127.0.0.1.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from typing import Any

BASE = sys.argv[1].rstrip("/")
if not BASE.startswith(("http://", "https://")):
    sys.exit("base URL must be http(s)")
PASSWORD = open(sys.argv[2], encoding="utf-8").read().strip()
COOKIES: dict[str, str] = {}
FAILURES: list[str] = []


def call(method: str, path: str, body: Any = None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)  # noqa: S310 (scheme checked above)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if COOKIES:
        req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in COOKIES.items()))
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310
            status, msg, payload = r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        status, msg, payload = e.code, e.headers, e.read()
    for raw in msg.get_all("Set-Cookie") or []:
        name, _, rest = raw.partition("=")
        COOKIES[name.strip()] = rest.split(";", 1)[0]
    return status, {k.lower(): v for k, v in msg.items()}, payload


def check(cond: bool, label: str, detail: Any = "") -> None:
    print(("PASS " if cond else "FAIL ") + label + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


status, _, body = call("GET", "/health/ready")
check(status == 200 and b"ready" in body, "readiness reports ready", body[:200])

status, headers, body = call("GET", "/")
check(status == 200 and b'<div id="root">' in body, "console HTML is served", status)
check("content-security-policy" in headers, "CSP header present on the console")
check("http" not in headers.get("content-security-policy", ""), "CSP allows no external origins", headers.get("content-security-policy"))
check(headers.get("x-frame-options", "").upper() == "DENY" or "frame-ancestors 'none'" in headers.get("content-security-policy", ""),
      "framing is blocked")

status, _, _ = call("GET", "/api/v1/auth/me")
check(status == 401, "anonymous /auth/me is 401", status)

status, _, body = call("POST", "/api/v1/auth/login", {"username": "admin", "password": "wrong-password-123"})
check(status == 401, "wrong password is rejected", status)

status, _, body = call("POST", "/api/v1/auth/login", {"username": "admin", "password": PASSWORD})
check(status == 200, "bootstrap admin can sign in", body[:300])
login = json.loads(body) if status == 200 else {}
csrf = login.get("csrf_token", "")
check(bool(csrf), "login returns a CSRF token")
check(not any("hash" in k for k in login), "login response has no hash fields")

status, _, body = call("GET", "/api/v1/auth/me")
me = json.loads(body) if status == 200 else {}
check(status == 200 and me.get("principal_type") == "user" and me.get("is_platform_admin") is True,
      "session works for /auth/me (platform admin)", body[:300])

status, _, body = call("POST", "/api/v1/auth/logout")
check(status == 403 and b"CSRF_FAILED" in body, "mutation without CSRF token is refused", body[:200])

status, _, _ = call("POST", "/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
check(status == 204, "logout with CSRF token succeeds", status)

status, _, _ = call("GET", "/api/v1/auth/me")
check(status == 401, "session is gone after logout", status)

status, _, _ = call("GET", "/api/docs")
check(status == 404, "OpenAPI docs are disabled in production", status)

if FAILURES:
    print(f"\n{len(FAILURES)} smoke check(s) failed")
    sys.exit(1)
print("\nAll smoke checks passed")
