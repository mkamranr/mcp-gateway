"""An in-memory directory for the LDAP tests (ldap3's MOCK_SYNC strategy behind the LdapDirectory opener hook)."""

from __future__ import annotations

from typing import Any

from ldap3 import MOCK_SYNC, NONE, Connection, Server

from app.services.ldap_client import LdapError

BASE = "dc=corp,dc=example"
PEOPLE = f"ou=people,{BASE}"
GROUPS = f"ou=groups,{BASE}"
SVC_DN = f"cn=svc-mgw,ou=service,{BASE}"
SVC_PASSWORD = "svc-secret-Passw0rd"  # noqa: S105


def group(cn: str) -> str:
    return f"cn={cn},{GROUPS}"


class FakeDirectory:
    def __init__(self) -> None:
        self.entries: dict[str, dict[str, Any]] = {}
        self.binds: list[str | None] = []  # DNs the gateway tried to bind as
        self.down = False
        self.container: Any = None  # set by the test fixture
        self.add(BASE, {"objectClass": ["domain"], "dc": "corp"})
        for ou in ("people", "groups", "service"):
            self.add(f"ou={ou},{BASE}", {"objectClass": ["organizationalUnit"], "ou": ou})
        self.add(SVC_DN, {"objectClass": ["person"], "cn": "svc-mgw", "userPassword": SVC_PASSWORD})

    def add(self, dn: str, attrs: dict[str, Any]) -> None:
        self.entries[dn] = attrs

    def person(self, uid: str, password: str, *, groups: tuple[str, ...] = (), uuid: str | None = None,
               mail: str | None = None, name: str | None = None) -> str:
        dn = f"uid={uid},{PEOPLE}"
        attrs: dict[str, Any] = {"objectClass": ["person", "inetOrgPerson"], "uid": uid, "cn": uid,
                                 "userPassword": password, "entryUUID": uuid or f"00000000-0000-0000-0000-{uid:0>12}"[:36]}
        if groups:
            attrs["memberOf"] = list(groups)
        if mail:
            attrs["mail"] = mail
        if name:
            attrs["displayName"] = name
        self.add(dn, attrs)
        return dn

    def set_groups(self, uid: str, groups: tuple[str, ...]) -> None:
        self.entries[f"uid={uid},{PEOPLE}"]["memberOf"] = list(groups)

    def opener(self, url: str, cfg: dict[str, Any], user: str | None, password: str | None) -> Connection:
        if self.down:
            raise LdapError("unavailable", f"{url}: connection refused")
        self.binds.append(user)
        conn = Connection(Server("mock", get_info=NONE), user=user, password=password, client_strategy=MOCK_SYNC,
                          raise_exceptions=False)
        for dn, attrs in self.entries.items():
            conn.strategy.add_entry(dn, attrs)
        return conn


def config(tenant_id: str, **overrides: Any) -> dict[str, Any]:
    return {
        "enabled": True, "server_urls": ["ldaps://ldap.corp.example"], "bind_dn": SVC_DN,
        "bind_password": SVC_PASSWORD, "user_search_base": PEOPLE,
        "group_rules": [
            {"group": group("MGW Admins"), "tenant_id": tenant_id, "roles": ["tenant_admin"]},
            {"group": group("MGW Developers"), "tenant_id": tenant_id, "roles": ["developer"]},
        ],
        "platform_admin_groups": [group("MGW Platform")],
        **overrides,
    }
