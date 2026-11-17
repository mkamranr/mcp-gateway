"""End-to-end SCIM 2.0 checks through the real nginx and gateway containers, driven the way Microsoft Entra ID
and Okta drive a SCIM app. Standard library only.

Usage: scim_check.py <console-base> <admin-password-file>

Requires:
  * the SCIM token is shown once, required on every request, and invalidated by rotation;
  * users are created, found by filter, patched (Entra ID's capitalised ops and string booleans), deactivated
    and deleted; errors come back in SCIM's format;
  * pushed groups become tenant roles through the SSO group rules, and membership changes apply at once;
  * local accounts are invisible to SCIM and can't be taken over.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

USER = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
TIMEOUT = 30


def call(base: str, method: str, path: str, body: Any = None, headers: dict[str, str] | None = None,
         cookies: dict[str, str] | None = None, content_type: str = "application/json") -> tuple[int, Any, Any]:
    if not base.startswith(("http://", "https://")):
        raise SystemExit("base URL must be http(s)")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers or {})  # noqa: S310
    if body is not None:
        req.add_header("Content-Type", content_type)
    if cookies:
        req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # noqa: S310
            if cookies is not None:
                for c in r.headers.get_all("Set-Cookie") or []:
                    k, v = c.split("=", 1)
                    cookies[k.strip()] = v.split(";", 1)[0]
            raw = r.read()
            return r.status, json.loads(raw) if raw else None, r.headers
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw), e.headers
        except ValueError:
            return e.code, raw[:300].decode(errors="replace"), e.headers


class Admin:
    def __init__(self, base: str, password: str) -> None:
        self.base, self.cookies = base, {}
        status, me, _ = call(base, "POST", "/api/v1/auth/login", {"username": "admin", "password": password},
                             cookies=self.cookies)
        if status != 200:
            raise SystemExit(f"admin sign-in failed: {status} {me}")
        self.csrf, self.tenant, self.id = me["csrf_token"], me["tenant_id"], me["principal_id"]

    def ok(self, method: str, path: str, body: Any = None) -> Any:
        status, data, _ = call(self.base, method, path, body, cookies=self.cookies,
                               headers={"X-CSRF-Token": self.csrf} if method != "GET" else {})
        if status not in (200, 201):
            raise SystemExit(f"{method} {path} -> {status} {data}")
        return data


def main() -> None:
    console, password_file = sys.argv[1:3]
    problems: list[str] = []

    def expect(label: str, ok: bool, detail: Any = "") -> None:
        print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f": {detail}"))
        if not ok:
            problems.append(label)

    admin = Admin(console, open(password_file, encoding="utf-8").read().strip())
    admin.ok("PUT", "/api/v1/sso/config", {  # group rules only; SSO itself stays off
        "enabled": False, "group_rules": [
            {"group": "mgw-developers", "tenant_id": admin.tenant, "roles": ["developer"]},
            {"group": "mgw-auditors", "tenant_id": admin.tenant, "roles": ["auditor"]}]})
    token = admin.ok("POST", "/api/v1/scim/token")["token"]
    admin.ok("PUT", "/api/v1/scim/config", {"enabled": True, "link_claim": "oid"})
    view = admin.ok("GET", "/api/v1/scim/config")
    expect("token shown once (not in the configuration view)", token not in json.dumps(view) and view["has_token"])

    def scim(method: str, path: str, body: Any = None, tok: str | None = None) -> tuple[int, Any, Any]:
        return call(console, method, "/api/v1/scim/v2" + path, body, content_type="application/scim+json",
                    headers={"Authorization": f"Bearer {token if tok is None else tok}"})

    def roles(user_id: str) -> list[str]:
        users = admin.ok("GET", f"/api/v1/tenants/{admin.tenant}/users?limit=200")["items"]
        return next((u["roles"] for u in users if u["user_id"] == user_id and u["status"] == "active"), [])

    # ---- authentication
    status, body, headers = scim("GET", "/Users", tok="mgw_scim_wrong")
    expect("wrong token: 401 in SCIM format", status == 401 and body.get("schemas") == [ERROR]
           and headers.get("Content-Type", "").startswith("application/scim+json"), (status, body))
    status, body, _ = scim("GET", "/ServiceProviderConfig")
    expect("ServiceProviderConfig", status == 200 and body["patch"]["supported"] is True, (status, body))

    # ---- Entra ID's user flow: look up, create, patch
    status, body, _ = scim("GET", "/Users?filter=" + urllib.parse.quote('userName eq "ivy@corp.example"'))
    expect("lookup before create: none", status == 200 and body["totalResults"] == 0, body)
    status, ivy, headers = scim("POST", "/Users", {
        "schemas": [USER], "externalId": "0b1c-ivy", "userName": "ivy@corp.example", "active": True,
        "displayName": "Ivy Example", "emails": [{"primary": True, "type": "work", "value": "ivy@corp.example"}],
        "name": {"givenName": "Ivy", "familyName": "Example"}})
    expect("create user: 201 with Location", status == 201 and headers.get("Location", "").endswith(ivy.get("id", "?")),
           (status, ivy))
    status, body, _ = scim("POST", "/Users", {"schemas": [USER], "userName": "ivy@corp.example"})
    expect("duplicate userName: 409 uniqueness", status == 409 and body.get("scimType") == "uniqueness", body)
    status, body, _ = scim("PATCH", f"/Users/{ivy['id']}", {"schemas": [PATCH], "Operations": [
        {"op": "Replace", "path": "displayName", "value": "Ivy E."},
        {"op": "Add", "path": "title", "value": "Analyst"}]})
    expect("Entra-style PATCH", status == 200 and body.get("displayName") == "Ivy E.", (status, body))

    # ---- groups -> roles
    status, group, _ = scim("POST", "/Groups", {"schemas": [GROUP], "displayName": "mgw-developers", "members": []})
    expect("create group", status == 201, (status, group))
    status, _, _ = scim("PATCH", f"/Groups/{group['id']}", {"schemas": [PATCH], "Operations": [
        {"op": "Add", "path": "members", "value": [{"value": ivy["id"]}]}]})
    expect("add member: 204, developer role at once", status == 204 and roles(ivy["id"]) == ["developer"],
           (status, roles(ivy["id"])))
    status, _, _ = scim("PATCH", f"/Groups/{group['id']}", {"schemas": [PATCH], "Operations": [
        {"op": "Replace", "value": {"displayName": "mgw-auditors"}}]})
    expect("rename group: role follows the rules", status == 204 and roles(ivy["id"]) == ["auditor"], roles(ivy["id"]))
    status, _, _ = scim("PATCH", f"/Groups/{group['id']}", {"schemas": [PATCH], "Operations": [
        {"op": "Remove", "path": "members", "value": [{"value": ivy["id"]}]}]})
    expect("remove member: role gone", status == 204 and roles(ivy["id"]) == [], roles(ivy["id"]))
    users = admin.ok("GET", f"/api/v1/tenants/{admin.tenant}/users?limit=200")["items"]
    expect("console shows the account as SCIM-provisioned",
           any(u["user_id"] == ivy["id"] and u.get("provisioned_by") == "scim" for u in users))

    # ---- boundaries
    status, _, _ = scim("PATCH", f"/Users/{admin.id}", {"schemas": [PATCH], "Operations": [
        {"op": "replace", "path": "active", "value": False}]})
    expect("local admin invisible to SCIM: 404", status == 404, status)
    status, _, _ = scim("POST", "/Users", {"schemas": [USER], "userName": "admin", "active": False})
    expect("local admin can't be taken over: 409", status == 409, status)
    status, body, _ = scim("GET", "/Users?filter=" + urllib.parse.quote('title co "x"'))
    expect("unsupported filter: 400 invalidFilter", status == 400 and body.get("scimType") == "invalidFilter", body)

    # ---- deactivate (Okta: PUT active=false; Entra ID: PATCH "False"), delete
    status, body, _ = scim("PATCH", f"/Users/{ivy['id']}", {"schemas": [PATCH], "Operations": [
        {"op": "Replace", "path": "active", "value": "False"}]})
    expect("deactivate", status == 200 and body.get("active") is False, (status, body))
    status, _, _ = scim("DELETE", f"/Users/{ivy['id']}")
    expect("delete: 204, then 404", status == 204 and scim("GET", f"/Users/{ivy['id']}")[0] == 404, status)

    # ---- rotation
    new = admin.ok("POST", "/api/v1/scim/token")["token"]
    expect("rotated: old token refused, new one accepted",
           scim("GET", "/Users")[0] == 401 and scim("GET", "/Users", tok=new)[0] == 200)
    events = admin.ok("GET", "/api/v1/audit/events?limit=200")["items"]
    expect("tokens never in the audit log", token not in json.dumps(events) and new not in json.dumps(events))

    if problems:
        raise SystemExit(f"FAILED: {len(problems)} check(s)")
    print("all SCIM checks passed")


if __name__ == "__main__":
    main()
