#!/usr/bin/env python3
"""mgw-policy: manage MCP Gateway policies as code (export / validate / plan / apply).

Standard library only (Python 3.9+), so it runs on any CI runner or admin host without installing anything.

Connection settings come from the environment (flags override them):
  MGW_URL        base URL of the gateway console/API, e.g. https://gateway.example.internal
  MGW_USERNAME   a *local* account (SSO accounts cannot sign in non-interactively)
  MGW_PASSWORD   its password; read from the environment only, never from a flag
  MGW_TENANT     tenant id to act in (optional; defaults to the account's default tenant)
  MGW_CA_FILE    PEM bundle for an internal CA (optional)

Roles: plan/validate need developer, auditor, security admin or tenant admin; apply needs security admin or
tenant admin; global bundles need a platform administrator.

Exit codes: 0 success; 1 the bundle is invalid or the request failed; 2 (plan --detailed-exitcode only)
the bundle is valid and would change something; 3 apply refused because live policies changed since the plan.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

API = "/api/v1"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class Client:
    def __init__(self, url: str, ca_file: str | None) -> None:
        if not url.startswith(("https://", "http://")):
            raise SystemExit("MGW_URL must start with https:// (or http:// for a local test stack)")
        self.base = url.rstrip("/")
        host = urllib.parse.urlsplit(self.base).hostname or ""
        if self.base.startswith("http://") and host not in ("localhost", "127.0.0.1", "::1"):
            print(f"warning: {self.base} is not HTTPS; the password and session travel unencrypted", file=sys.stderr)
        ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        # No redirects (a redirect could carry the session elsewhere) and no HTTP proxy surprises for the cookie:
        # the session cookie is kept by hand and only ever sent to self.base. (A CookieJar would also refuse to send
        # the Secure __Host- cookie over plain http to a local test stack.)
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect())
        self.cookies: dict[str, str] = {}
        self.csrf: str | None = None

    def request(self, method: str, path: str, body: Any = None, query: dict[str, Any] | None = None,
                raw: bool = False) -> tuple[int, Any]:
        url = self.base + API + path + ("?" + urllib.parse.urlencode(query) if query else "")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)  # noqa: S310 (scheme checked in __init__)
        req.add_header("Accept", "application/json, application/yaml")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.csrf and method != "GET":
            req.add_header("X-CSRF-Token", self.csrf)
        if self.cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
        try:
            with self.opener.open(req, timeout=60) as resp:
                self._keep_cookies(resp.headers.get_all("Set-Cookie") or [])
                text = resp.read().decode("utf-8")
                return resp.status, (text if raw else json.loads(text or "null"))
        except urllib.error.HTTPError as exc:
            self._keep_cookies(exc.headers.get_all("Set-Cookie") or [])
            text = exc.read().decode("utf-8", "replace")
            try:
                return exc.code, json.loads(text)
            except ValueError:
                return exc.code, {"error": {"code": f"HTTP_{exc.code}", "message": text[:300]}}
        except urllib.error.URLError as exc:
            raise SystemExit(f"Cannot reach {self.base}: {exc.reason}") from None

    def _keep_cookies(self, headers: list[str]) -> None:
        for raw in headers:
            name, _, rest = raw.partition("=")
            value = rest.split(";", 1)[0]
            if "max-age=0" in raw.lower() or not value:
                self.cookies.pop(name.strip(), None)
            else:
                self.cookies[name.strip()] = value

    def login(self, username: str, password: str, tenant: str | None) -> None:
        body: dict[str, Any] = {"username": username, "password": password}
        if tenant:
            body["tenant_id"] = tenant
        status, res = self.request("POST", "/auth/login", body)
        if status != 200:
            fail(status, res, "sign-in failed")
        self.csrf = res.get("csrf_token")

    def logout(self) -> None:
        try:
            self.request("POST", "/auth/logout")
        except SystemExit:
            pass


def fail(status: int, res: Any, what: str) -> None:
    err = (res or {}).get("error", {}) if isinstance(res, dict) else {}
    print(f"error: {what} (HTTP {status} {err.get('code', '')}): {err.get('message', '')}", file=sys.stderr)
    for d in err.get("details") or []:
        print(f"  - {d.get('field', '')}: {d.get('message') or d.get('code')}", file=sys.stderr)
    raise SystemExit(1)


SYMBOL = {"create": "+", "update": "~", "adopt": "&", "delete": "-", "orphan": "?", "unchanged": "="}


def _short(v: Any) -> str:
    s = json.dumps(v, sort_keys=True, separators=(",", ":"))
    return s if len(s) <= 100 else s[:97] + "..."


def _leaf_changes(path: str, old: Any, new: Any) -> list[tuple[str, Any, Any]]:
    """constraints: {...} -> constraints.max_calls_per_minute: 30 -> 10 (only what actually differs)."""
    if isinstance(old, dict) and isinstance(new, dict):
        out: list[tuple[str, Any, Any]] = []
        for k in sorted(set(old) | set(new)):
            if old.get(k) != new.get(k):
                out += _leaf_changes(f"{path}.{k}", old.get(k), new.get(k))
        return out
    return [(path, old, new)]


def print_plan(plan: dict[str, Any], verbose: bool) -> None:
    scope = "global" if plan["scope"] == "global" else f"tenant {plan['tenant_id']}"
    print(f"Bundle {plan['bundle']!r} ({scope}){'  [prune]' if plan['prune'] else ''}")
    for c in plan["changes"]:
        if c["action"] == "unchanged" and not verbose:
            continue
        note = {"adopt": "  (adopt existing hand-made policy)",
                "orphan": "  (owned by this bundle but not in the file; use --prune to delete)"}.get(c["action"], "")
        print(f"  {SYMBOL[c['action']]} {c['name']}{note}")
        if c["action"] != "create":
            for field, d in sorted((c.get("diff") or {}).items()):
                for path, old, new in _leaf_changes(field, d["from"], d["to"]):
                    print(f"      {path}: {_short(old)} -> {_short(new)}")
    for w in plan["warnings"]:
        print(f"  warning: {w['policy']}: {w['message']}")
    for e in plan["errors"]:
        print(f"  ERROR: {e['policy']}: {e['message']} [{e['code']}]")
    s = plan["summary"]
    print(f"Plan: {s['create']} to create, {s['update'] + s['adopt']} to change ({s['adopt']} adopted), "
          f"{s['delete']} to delete, {s['unchanged']} unchanged" + (f", {s['orphan']} orphaned" if s["orphan"] else ""))
    print(f"Fingerprint: {plan['fingerprint']}")


def has_changes(plan: dict[str, Any]) -> bool:
    s = plan["summary"]
    return bool(s["create"] or s["update"] or s["adopt"] or s["delete"])


def read_file(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def do_plan(c: Client, content: str, prune: bool) -> dict[str, Any]:
    status, res = c.request("POST", "/policies/bundle/plan", {"content": content}, {"prune": str(prune).lower()})
    if status != 200:
        fail(status, res, "the bundle was rejected")
    return res  # type: ignore[no-any-return]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mgw-policy", description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default=os.environ.get("MGW_URL"))
    ap.add_argument("--username", default=os.environ.get("MGW_USERNAME"))
    ap.add_argument("--tenant", default=os.environ.get("MGW_TENANT"))
    ap.add_argument("--ca-file", default=os.environ.get("MGW_CA_FILE"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    ex = sub.add_parser("export", help="write the live policies as a bundle")
    ex.add_argument("--bundle", default="exported", help="bundle name to put in metadata (default: exported)")
    ex.add_argument("--scope", choices=["tenant", "global"], default="tenant")
    ex.add_argument("--only-owned", action="store_true", help="only policies owned by --bundle")
    ex.add_argument("-o", "--output", default="-")

    for name, hlp in (("validate", "check a bundle; changes nothing"), ("plan", "show what apply would change")):
        p = sub.add_parser(name, help=hlp)
        p.add_argument("file", help="bundle file (YAML or JSON), or - for stdin")
        p.add_argument("--prune", action="store_true", help="delete owned policies missing from the file")
        if name == "plan":
            p.add_argument("--out", help="save the plan (with its fingerprint) for a later apply --plan")
            p.add_argument("--json", action="store_true", help="print the plan as JSON")
            p.add_argument("--detailed-exitcode", action="store_true", help="exit 2 when there are changes")
            p.add_argument("-v", "--verbose", action="store_true", help="also list unchanged policies")

    p = sub.add_parser("apply", help="apply a bundle")
    p.add_argument("file", help="bundle file (YAML or JSON), or - for stdin")
    p.add_argument("--prune", action="store_true")
    p.add_argument("--plan", dest="plan_file", help="apply exactly this saved plan (refused if anything changed)")
    p.add_argument("--auto-approve", action="store_true", help="don't ask for confirmation (CI)")
    args = ap.parse_args(argv)

    if not args.url or not args.username or not os.environ.get("MGW_PASSWORD"):
        raise SystemExit("Set MGW_URL, MGW_USERNAME and MGW_PASSWORD (the password is read from the environment only).")
    c = Client(args.url, args.ca_file)
    c.login(args.username, os.environ["MGW_PASSWORD"], args.tenant)
    try:
        return run(c, args)
    finally:
        c.logout()


def run(c: Client, args: argparse.Namespace) -> int:
    if args.cmd == "export":
        q = {"bundle": args.bundle, "scope": args.scope, "include": "bundle" if args.only_owned else "all"}
        status, text = c.request("GET", "/policies/bundle/export", query=q, raw=True)
        if status != 200:
            fail(status, json.loads(text) if text.startswith("{") else {}, "export failed")
        if args.output == "-":
            sys.stdout.write(text)
        else:
            with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            print(f"Wrote {args.output}", file=sys.stderr)
        return 0

    content = read_file(args.file)
    if args.cmd in ("validate", "plan"):
        plan = do_plan(c, content, args.prune)
        if args.cmd == "validate":
            for w in plan["warnings"]:
                print(f"warning: {w['policy']}: {w['message']}")
            for e in plan["errors"]:
                print(f"ERROR: {e['policy']}: {e['message']} [{e['code']}]")
            print("valid" if plan["valid"] else "invalid")
            return 0 if plan["valid"] else 1
        if args.json:
            print(json.dumps(plan, indent=2))
        else:
            print_plan(plan, args.verbose)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(plan, fh, indent=2)
        if not plan["valid"]:
            return 1
        return 2 if args.detailed_exitcode and has_changes(plan) else 0

    # apply
    if args.plan_file:
        with open(args.plan_file, encoding="utf-8") as fh:
            saved = json.load(fh)
        if saved.get("prune") != args.prune:
            raise SystemExit("--prune must match the saved plan")
        fingerprint = saved["fingerprint"]
        print(f"Applying saved plan {fingerprint}")
    else:
        plan = do_plan(c, content, args.prune)
        print_plan(plan, False)
        if not plan["valid"]:
            return 1
        if not has_changes(plan):
            print("Nothing to apply.")
            return 0
        if not args.auto_approve:
            if not sys.stdin.isatty():
                raise SystemExit("Refusing to apply without confirmation; pass --auto-approve or a reviewed --plan.")
            try:
                answer = input("Apply these changes? Type 'yes': ")
            except EOFError:
                raise SystemExit("\nRefusing to apply without confirmation; pass --auto-approve or a reviewed "
                                 "--plan.") from None
            if answer.strip() != "yes":
                print("Cancelled.")
                return 1
        fingerprint = plan["fingerprint"]
    status, res = c.request("POST", "/policies/bundle/apply",
                            {"content": content, "expected_fingerprint": fingerprint, "prune": args.prune})
    if status == 409 and (res.get("error") or {}).get("code") == "VERSION_CONFLICT":
        print("error: live policies changed since the plan was made; run plan again and review it.", file=sys.stderr)
        return 3
    if status != 200:
        fail(status, res, "apply failed")
    s = res["summary"]
    print(f"Applied: {s['create']} created, {s['update'] + s['adopt']} changed, {s['delete']} deleted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
