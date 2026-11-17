"""LDAP / Active Directory console sign-in. One platform-wide directory; groups map to tenants and roles."""

from __future__ import annotations

import re
from typing import Literal

from ldap3.core.exceptions import LDAPInvalidDnError
from ldap3.utils.dn import parse_dn
from pydantic import Field, field_validator, model_validator

from app.models.registry import Strict
from app.models.sso import GroupRule

ATTRIBUTE = r"^[A-Za-z][A-Za-z0-9-]{0,63}$"
URL = re.compile(r"^ldaps?://(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(:\d{1,5})?/?$")


def normalize_dn(dn: str) -> str:
    """Canonical form for comparing DNs: attribute names and values lower-cased, no spaces around separators.

    Raises ValueError for anything that is not a DN.
    """
    try:
        parts = parse_dn(dn.strip(), escape=False, strip=True)
    except (LDAPInvalidDnError, IndexError, TypeError) as exc:
        raise ValueError(f"Not a valid DN: {dn[:100]}") from exc
    if not parts:
        raise ValueError("Empty DN")
    out = ""
    for attr, value, sep in parts:
        out += f"{attr.strip().lower()}={value.strip().lower()}" + ("," if sep == "," else "+" if sep == "+" else "")
    return out


def _filter_ok(value: str, placeholders: tuple[str, ...]) -> str:
    v = value.strip()
    if not (v.startswith("(") and v.endswith(")")):
        raise ValueError("A filter must be enclosed in parentheses")
    depth = 0
    for ch in v:
        depth += 1 if ch == "(" else -1 if ch == ")" else 0
        if depth < 0:
            break
    if depth != 0:
        raise ValueError("Unbalanced parentheses in filter")
    if not any(p in v for p in placeholders):
        raise ValueError(f"The filter must contain {' or '.join(placeholders)}")
    # Only the documented placeholders: a stray {...} would be a format error at sign-in time.
    rest = v
    for p in placeholders:
        rest = rest.replace(p, "")
    if "{" in rest or "}" in rest:
        raise ValueError(f"Only {', '.join(placeholders)} may appear in braces")
    return v


class LdapConfigBase(Strict):
    enabled: bool = False
    display_name: str = Field(default="Directory account", min_length=1, max_length=60)
    server_urls: list[str] = Field(default_factory=list, max_length=5)
    start_tls: bool = False
    ca_pem: str = Field(default="", max_length=65536)  # CA bundle for the directory's certificate; "" = system CAs
    # Whole seconds: ldap3 packs the receive timeout into a socket option that takes an integer (Linux).
    timeout_seconds: int = Field(default=5, ge=1, le=30)
    bind_dn: str = Field(default="", max_length=500)  # read-only service account; "" = anonymous search
    user_search_base: str = Field(default="", max_length=500)
    user_filter: str = Field(default="(&(objectClass=person)(uid={username}))", max_length=500)
    username_attribute: str = Field(default="uid", pattern=ATTRIBUTE)
    unique_id_attribute: str = Field(default="entryUUID", pattern=ATTRIBUTE)
    email_attribute: str = Field(default="mail", pattern=ATTRIBUTE)
    name_attribute: str = Field(default="displayName", pattern=ATTRIBUTE)
    group_membership_attribute: str = Field(default="memberOf", max_length=64)  # "" = don't read it
    group_search_base: str = Field(default="", max_length=500)  # "" = no group search
    group_search_filter: str = Field(default="(|(member={user_dn})(uniqueMember={user_dn}))", max_length=500)
    group_rules: list[GroupRule] = Field(default_factory=list, max_length=500)
    platform_admin_groups: list[str] = Field(default_factory=list, max_length=20)
    jit_provisioning: bool = True
    local_login: Literal["enabled", "break_glass_only"] = "enabled"
    break_glass_usernames: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("server_urls")
    @classmethod
    def _urls(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for u in (x.strip() for x in v):
            if not u:
                continue
            if not URL.match(u):
                raise ValueError(f"Not an LDAP URL (ldap://host:389 or ldaps://host:636): {u[:100]}")
            if u not in out:
                out.append(u.rstrip("/"))
        return out

    @field_validator("bind_dn", "user_search_base", "group_search_base")
    @classmethod
    def _dn(cls, v: str) -> str:
        v = v.strip()
        if v:
            normalize_dn(v)
        return v

    @field_validator("user_filter")
    @classmethod
    def _user_filter(cls, v: str) -> str:
        return _filter_ok(v, ("{username}",))

    @field_validator("group_search_filter")
    @classmethod
    def _group_filter(cls, v: str) -> str:
        return _filter_ok(v, ("{user_dn}", "{username}"))

    @field_validator("group_membership_attribute")
    @classmethod
    def _member_attr(cls, v: str) -> str:
        v = v.strip()
        if v and not re.match(ATTRIBUTE, v):
            raise ValueError("Invalid attribute name")
        return v

    @field_validator("group_rules")
    @classmethod
    def _rule_dns(cls, v: list[GroupRule]) -> list[GroupRule]:
        for r in v:
            try:
                normalize_dn(r.group)
            except ValueError as exc:
                raise ValueError(f"Group rules use the group's full DN: {r.group[:100]}") from exc
        return v

    @field_validator("platform_admin_groups")
    @classmethod
    def _admin_dns(cls, v: list[str]) -> list[str]:
        out = sorted({x.strip() for x in v if x.strip()})
        for g in out:
            try:
                normalize_dn(g)
            except ValueError as exc:
                raise ValueError(f"Platform administrator groups use the group's full DN: {g[:100]}") from exc
        return out

    @field_validator("break_glass_usernames")
    @classmethod
    def _dedupe(cls, v: list[str]) -> list[str]:
        return sorted({x.strip().lower() for x in v if x.strip()})

    @field_validator("ca_pem")
    @classmethod
    def _ca(cls, v: str) -> str:
        v = v.strip()
        if v and "-----BEGIN CERTIFICATE-----" not in v:
            raise ValueError("The CA bundle must be PEM certificates")
        return v

    @model_validator(mode="after")
    def _complete(self) -> LdapConfigBase:
        if self.enabled and (not self.server_urls or not self.user_search_base):
            raise ValueError("A server URL and the user search base are required to enable directory sign-in")
        if self.start_tls and any(u.startswith("ldaps://") for u in self.server_urls):
            raise ValueError("StartTLS applies to ldap:// URLs; ldaps:// is already encrypted")
        if self.local_login == "break_glass_only":
            if not self.enabled:
                raise ValueError("Local login can only be restricted while directory sign-in is enabled")
            if not self.break_glass_usernames:
                raise ValueError("Name at least one break-glass account before restricting local login")
        return self


class LdapConfigUpdate(LdapConfigBase):
    # Write-only. Omit (null) to keep the stored password; "" clears it.
    bind_password: str | None = Field(default=None, max_length=1024, repr=False)


class LdapTestRequest(Strict):
    username: str | None = Field(default=None, max_length=256)  # optional: look this user up (no password)
