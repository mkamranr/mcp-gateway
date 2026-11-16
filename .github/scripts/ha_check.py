"""Checks for the multi-replica Compose stack (docker-compose.ha.yml), run between replica stops and starts.

Usage:
  python ha_check.py login   <base-url> <password-file> <session-file>   sign in once, keep the session
  python ha_check.py hammer  <base-url> <session-file> <n>               n authenticated requests, all must succeed
  python ha_check.py workers <base-url> <session-file> <expected>        console reports <expected> live workers

Standard library only. The session cookie is kept by hand (it is Secure and this talks plain HTTP to 127.0.0.1).
A session created on one replica must work on every other: sessions live in Redis.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any


def call(base: str, method: str, path: str, cookies: dict[str, str], body: Any = None) -> tuple[int, Any, list[str]]:
    if not base.startswith(("http://", "https://")):
        raise SystemExit("base URL must be http(s)")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base.rstrip("/") + path, data=data, method=method)  # noqa: S310
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if cookies:
        req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
    try:
        with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310
            return r.status, json.loads(r.read() or b"null"), r.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:300], []
    except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
        return 0, str(e), []


def main() -> None:
    cmd, base = sys.argv[1], sys.argv[2]
    if cmd == "login":
        password = open(sys.argv[3], encoding="utf-8").read().strip()
        status, body, set_cookies = call(base, "POST", "/api/v1/auth/login", {}, {"username": "admin", "password": password})
        if status != 200:
            raise SystemExit(f"login failed: {status} {body}")
        cookies = {c.split("=", 1)[0].strip(): c.split("=", 1)[1].split(";", 1)[0] for c in set_cookies}
        json.dump(cookies, open(sys.argv[4], "w", encoding="utf-8"))
        print("signed in")
        return
    cookies = json.load(open(sys.argv[3], encoding="utf-8"))
    if cmd == "hammer":
        n = int(sys.argv[4])
        failures = []
        for i in range(n):
            status, body, _ = call(base, "GET", "/api/v1/auth/me", cookies)
            if status != 200:
                failures.append((i, status, body))
            time.sleep(0.05)
        print(f"{n - len(failures)}/{n} requests succeeded")
        if failures:
            raise SystemExit(f"failures: {failures[:5]}")
        return
    if cmd == "workers":
        expected = int(sys.argv[4])
        deadline = time.time() + 60
        alive = None
        while time.time() < deadline:
            status, body, _ = call(base, "GET", "/api/v1/overview", cookies)
            if status == 200:
                worker = next(h for h in body["health"] if h["name"] == "Worker")
                alive = worker.get("workers_alive")
                if alive == expected and worker["status"] == ("healthy" if expected else "unhealthy"):
                    print(f"console reports {alive} live worker(s)")
                    return
            time.sleep(2)
        raise SystemExit(f"expected {expected} live workers, console reports {alive}")
    raise SystemExit(f"unknown command {cmd}")


if __name__ == "__main__":
    main()
