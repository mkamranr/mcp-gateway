"""End-to-end checks for LDAP sign-in against real OpenLDAP (.github/ldap/docker-compose.ldap.yml). Stdlib only.

Usage: ldap_check.py <console-base> <admin-password-file> <pki-dir>

Requires, through the real nginx and gateway containers and a real OpenLDAP server:
  * LDAPS and StartTLS with the directory's CA; a host name not in the certificate, or another CA, is refused;
  * clear-text ldap:// without StartTLS can't even be saved;
  * directory users get the roles their groups map to (group search and memberOf); unmapped users, wrong
    passwords and filter metacharacters are refused;
  * removing a user from a group in the directory removes their access at the next sign-in;
  * with the directory down, directory users get 503 and the local administrator still signs in.
"""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any

BASE = "dc=ci,dc=example"
TIMEOUT = 30


def call(base: str, method: str, path: str, body: Any = None, headers: dict[str, str] | None = None,
         cookies: dict[str, str] | None = None) -> tuple[int, Any]:
    if not base.startswith(("http://", "https://")):
        raise SystemExit("base URL must be http(s)")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers or {})  # noqa: S310
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if cookies:
        req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # noqa: S310
            if cookies is not None:
                for c in r.headers.get_all("Set-Cookie") or []:
                    k, v = c.split("=", 1)
                    cookies[k.strip()] = v.split(";", 1)[0]
            raw = r.read()
            return r.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw[:300].decode(errors="replace")


def sign_in(base: str, username: str, password: str) -> tuple[int, Any]:
    return call(base, "POST", "/api/v1/auth/login", {"username": username, "password": password}, cookies={})


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


def ldapmodify(ldif: str) -> None:
    subprocess.run(["docker", "compose", "exec", "-T", "openldap", "ldapmodify", "-x", "-H", "ldap://localhost",  # noqa: S607
                    "-D", f"cn=admin,{BASE}", "-w", "ci-admin-password"], input=ldif.encode(), check=True)


def main() -> None:
    console, password_file, pki = sys.argv[1:4]
    problems: list[str] = []

    def expect(label: str, ok: bool, detail: Any = "") -> None:
        print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f": {detail}"))
        if not ok:
            problems.append(label)

    admin = Admin(console, open(password_file, encoding="utf-8").read().strip())
    ca = open(f"{pki}/ldap-ca.pem", encoding="utf-8").read()
    other_ca = open(f"{pki}/other-ca.pem", encoding="utf-8").read()
    cfg: dict[str, Any] = {
        "enabled": True, "display_name": "CI directory", "server_urls": ["ldaps://openldap:636"], "ca_pem": ca,
        "bind_dn": f"cn=readonly,{BASE}", "bind_password": "ci-readonly-password",
        "user_search_base": f"ou=people,{BASE}", "group_membership_attribute": "",
        "group_search_base": f"ou=groups,{BASE}",
        "group_rules": [
            {"group": f"cn=mgw-admins,ou=groups,{BASE}", "tenant_id": admin.tenant, "roles": ["tenant_admin"]},
            {"group": f"CN=MGW-Developers, OU=Groups, {BASE.upper()}", "tenant_id": admin.tenant,
             "roles": ["developer"]},
        ],
    }

    def configure(**overrides: Any) -> tuple[int, Any]:
        return admin.try_("PUT", "/api/v1/ldap/config", {**cfg, **overrides})

    def roles(username: str, pw: str) -> Any:
        status, me = sign_in(console, username, pw)
        return (me["auth_source"], me["roles"]) if status == 200 else status

    # ---- configuration and TLS
    status, out = configure()
    expect("LDAPS configuration saved", status == 200, (status, out))
    expect("service account password is write-only", "ci-readonly-password" not in json.dumps(out), out)
    test = admin.ok("POST", "/api/v1/ldap/test", {"username": "alice"})
    expect("test connection over LDAPS", test.get("ok") is True, test)
    expect("lookup explains access", (test.get("user") or {}).get("grants") == {admin.tenant: ["tenant_admin"]}, test)

    status, out = configure(server_urls=["ldap://openldap:389"])
    expect("clear-text ldap:// without StartTLS is refused", status == 422, (status, out))
    configure(server_urls=["ldaps://ldap-alias:636"])
    test = admin.ok("POST", "/api/v1/ldap/test")
    expect("host name not in the certificate is refused", test.get("error") == "tls", test)
    configure(ca_pem=other_ca)
    test = admin.ok("POST", "/api/v1/ldap/test")
    expect("certificate from another CA is refused", test.get("error") == "tls", test)
    configure(server_urls=["ldap://openldap:389"], start_tls=True)
    test = admin.ok("POST", "/api/v1/ldap/test")
    expect("StartTLS works", test.get("ok") is True, test)
    expect("StartTLS: directory user signs in", roles("alice", "Alice-Ldap-Pass-1") == ("ldap", ["tenant_admin"]))
    configure(bind_password="wrong")
    test = admin.ok("POST", "/api/v1/ldap/test")
    expect("wrong service password is reported", test.get("ok") is False and test.get("error") == "config", test)

    # ---- sign-in (group search)
    configure()
    expect("alice: tenant admin via group search", roles("alice", "Alice-Ldap-Pass-1") == ("ldap", ["tenant_admin"]))
    expect("bob: developer (rule DN matched case-insensitively)",
           roles("bob", "Bob-Ldap-Pass-1") == ("ldap", ["developer"]))
    expect("carol: no mapped group, refused", roles("carol", "Carol-Ldap-Pass-1") == 401)
    expect("wrong password refused", roles("alice", "not-her-password") == 401)
    for name in ("*", "a*", "alice)(uid=*", "*)(|(objectClass=*"):
        expect(f"filter metacharacters refused: {name!r}", roles(name, "Alice-Ldap-Pass-1") == 401)

    # ---- group removal in the directory
    ldapmodify(f"dn: cn=mgw-developers,ou=groups,{BASE}\nchangetype: modify\ndelete: uniqueMember\n"
               f"uniqueMember: uid=bob,ou=people,{BASE}\n")
    expect("bob removed from the group: access gone at next sign-in", roles("bob", "Bob-Ldap-Pass-1") == 403)

    # ---- memberOf (overlay) instead of a group search
    configure(group_membership_attribute="memberOf", group_search_base="")
    expect("memberOf: alice is still tenant admin", roles("alice", "Alice-Ldap-Pass-1") == ("ldap", ["tenant_admin"]))
    expect("memberOf: dave is a developer", roles("dave", "Dave-Ldap-Pass-1") == ("ldap", ["developer"]))

    # ---- audit
    status, events = admin.try_("GET", "/api/v1/audit/events?event_type=auth.login.succeeded&limit=100")
    methods = {e["metadata"].get("method") for e in (events or {}).get("items", [])}
    expect("directory sign-ins audited with method=ldap", "ldap" in methods, methods)

    # ---- outage
    subprocess.run(["docker", "compose", "stop", "openldap"], check=True)  # noqa: S607
    expect("directory down: 503 for directory users", roles("alice", "Alice-Ldap-Pass-1") == 503)
    status, _ = sign_in(console, "admin", open(password_file, encoding="utf-8").read().strip())
    expect("directory down: local administrator still signs in", status == 200, status)

    if problems:
        raise SystemExit(f"FAILED: {len(problems)} check(s)")
    print("all LDAP checks passed")


if __name__ == "__main__":
    main()
