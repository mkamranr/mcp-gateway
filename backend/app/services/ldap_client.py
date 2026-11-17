"""LDAP / Active Directory client: search-then-bind authentication and group lookup (ldap3, run in a thread).

Security properties:
  * TLS always (LDAPS or StartTLS) with full certificate and host-name verification through our own SSLContext;
    plain ldap:// only with LDAP_ALLOW_INSECURE outside production.
  * The username is escaped (RFC 4515) before it goes into a filter; placeholders are substituted, never
    str.format()ed.
  * Empty passwords are refused before any bind: many directories treat a simple bind with a DN and an empty
    password as an anonymous bind and report success (RFC 4513 §5.1.2, "unauthenticated bind").
  * Referrals are never followed, so credentials are never sent to a server named by the directory.
  * Exactly one entry must match the user filter.
"""

from __future__ import annotations

import ssl
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ldap3 import ANONYMOUS, NONE, SIMPLE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from app.config import Settings
from app.models.ldap import normalize_dn

INVALID_CREDENTIALS = 49
MAX_GROUPS = 1000


class LdapError(Exception):
    """code: invalid_credentials | unavailable | tls | config | directory. detail is for logs and the audit log."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail[:300]


@dataclass
class DirectoryUser:
    dn: str
    unique_id: str
    username: str
    email: str | None
    name: str | None
    groups: set[str] = field(default_factory=set)  # normalised group DNs
    server: str = ""


class _StrictTls(Tls):  # type: ignore[misc]
    """ldap3's own host-name check falls back to the subject CN and is skipped on some paths; use the stdlib's."""

    def __init__(self, context: ssl.SSLContext, host: str) -> None:
        super().__init__(validate=ssl.CERT_REQUIRED)
        self._context = context
        self._host = host

    def wrap_socket(self, connection: Any, do_handshake: bool = False) -> None:
        connection.socket = self._context.wrap_socket(connection.socket, server_side=False,
                                                      do_handshake_on_connect=do_handshake,
                                                      server_hostname=self._host)


def ssl_context(ca_pem: str) -> ssl.SSLContext:
    try:
        ctx = ssl.create_default_context(cadata=ca_pem) if ca_pem else ssl.create_default_context()
    except (ssl.SSLError, ValueError) as exc:
        raise LdapError("config", f"CA bundle could not be loaded: {exc}") from exc
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def check_username(username: str) -> str:
    u = username.strip()
    if not u or len(u) > 256 or any(ord(ch) < 32 for ch in u):
        raise LdapError("invalid_credentials", "unusable username")
    return u


def _text(values: Any) -> str | None:
    if not values:
        return None
    v = values[0] if isinstance(values, list | tuple) else values
    if isinstance(v, bytes):
        try:
            s = v.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return s if s.isprintable() else None
    return str(v)


def _unique_id(values: Any) -> str | None:
    if not values:
        return None
    v = values[0] if isinstance(values, list | tuple) else values
    if isinstance(v, bytes):
        text = _text([v])
        if text:
            return text.strip().lower()
        # Binary IDs: AD's objectGUID is 16 bytes, little-endian GUID layout.
        return str(uuid.UUID(bytes_le=v)) if len(v) == 16 else v.hex()
    return str(v).strip().lower() or None


# (url, cfg, user DN or None, password or None) -> an open, TLS-protected, not yet bound connection
Opener = Callable[[str, dict[str, Any], str | None, str | None], Connection]


class LdapDirectory:
    def __init__(self, settings: Settings, opener: Opener | None = None) -> None:
        self.settings = settings
        self.opener: Opener = opener or self._open

    # ------------------------------------------------------------------ connections
    def _open(self, url: str, cfg: dict[str, Any], user: str | None, password: str | None) -> Connection:
        u = urlparse(url)
        host = u.hostname or ""
        secure = u.scheme == "ldaps"
        if not secure and not cfg.get("start_tls"):
            if not (self.settings.ldap_allow_insecure and self.settings.app_env != "production"):
                raise LdapError("config", "the directory connection must use ldaps:// or StartTLS")
        timeout = int(cfg.get("timeout_seconds") or 5)
        tls = _StrictTls(ssl_context(cfg.get("ca_pem") or ""), host) if secure or cfg.get("start_tls") else None
        server = Server(host, port=u.port or (636 if secure else 389), use_ssl=secure, tls=tls, get_info=NONE,
                        connect_timeout=timeout)
        conn = Connection(server, user=user, password=password, authentication=SIMPLE if user else ANONYMOUS,
                          auto_referrals=False, receive_timeout=timeout, read_only=True, raise_exceptions=False,
                          check_names=False)
        try:
            conn.open()
            if cfg.get("start_tls") and not secure:
                conn.start_tls()
        except ssl.SSLError as exc:
            conn.unbind()
            raise LdapError("tls", f"{host}: {exc}") from exc
        except LDAPException as exc:
            conn.unbind()
            cause = exc.__context__ or exc
            code = "tls" if isinstance(cause, ssl.SSLError) or "certificate" in str(exc).lower() else "unavailable"
            raise LdapError(code, f"{host}: {exc}") from exc
        except Exception as exc:  # noqa: BLE001 - socket-level errors that ldap3 doesn't wrap
            conn.unbind()
            raise LdapError("unavailable", f"{host}: {type(exc).__name__}: {exc}") from exc
        return conn

    def _bind(self, url: str, cfg: dict[str, Any], user: str | None, password: str | None) -> Connection:
        conn = self.opener(url, cfg, user, password)
        if user is None:
            return conn
        try:
            ok = conn.bind()
        except LDAPException as exc:
            conn.unbind()
            raise LdapError("unavailable", f"bind failed: {exc}") from exc
        if not ok:
            result = conn.result or {}
            conn.unbind()
            if result.get("result") == INVALID_CREDENTIALS:
                raise LdapError("invalid_credentials", f"bind rejected for {user[:200]}")
            raise LdapError("directory", f"bind failed: {result.get('description')} {result.get('message', '')}")
        return conn

    def _service(self, cfg: dict[str, Any], bind_password: str | None) -> tuple[str, Connection]:
        """Binds the service account on the first reachable server (failover only on connection errors)."""
        bind_dn = cfg.get("bind_dn") or None
        if bind_dn and not bind_password:
            raise LdapError("config", "the service account has no password")
        errors: list[str] = []
        last: LdapError | None = None
        for url in cfg.get("server_urls") or []:
            try:
                return url, self._bind(url, cfg, bind_dn, bind_password)
            except LdapError as exc:
                if exc.code == "invalid_credentials":
                    raise LdapError("config", "the directory rejected the service account credentials") from exc
                if exc.code == "config":
                    raise
                errors.append(f"{url}: {exc.detail}")
                last = exc
        if last is None:
            raise LdapError("config", "no directory server configured")
        raise LdapError(last.code, "; ".join(errors))

    # ------------------------------------------------------------------ lookups
    @staticmethod
    def _entries(conn: Connection) -> list[dict[str, Any]]:
        return [r for r in (conn.response or []) if r.get("type", "searchResEntry") == "searchResEntry" and r.get("dn")]

    def _find_user(self, conn: Connection, cfg: dict[str, Any], username: str) -> dict[str, Any]:
        flt = cfg["user_filter"].replace("{username}", escape_filter_chars(username))
        attrs = sorted({cfg["username_attribute"], cfg["unique_id_attribute"], cfg["email_attribute"],
                        cfg["name_attribute"], "cn", *([cfg["group_membership_attribute"]]
                                                       if cfg.get("group_membership_attribute") else [])})
        timeout = int(cfg.get("timeout_seconds") or 5)
        try:
            conn.search(cfg["user_search_base"], flt, SUBTREE, attributes=attrs, size_limit=2, time_limit=timeout)
        except LDAPException as exc:
            raise LdapError("directory", f"user search failed: {exc}") from exc
        entries = self._entries(conn)
        if not entries:
            raise LdapError("invalid_credentials", "no directory entry matches the username")
        if len(entries) > 1:
            raise LdapError("invalid_credentials", "more than one directory entry matches the username")
        return entries[0]

    def _groups(self, conn: Connection, cfg: dict[str, Any], entry: dict[str, Any], username: str) -> set[str]:
        raw = entry.get("raw_attributes") or {}
        found: set[str] = set()
        attr = cfg.get("group_membership_attribute")
        if attr:
            for v in raw.get(attr, []) or []:
                text = _text([v])
                if text:
                    found.add(text)
        if cfg.get("group_search_base"):
            flt = (cfg["group_search_filter"].replace("{user_dn}", escape_filter_chars(entry["dn"]))
                   .replace("{username}", escape_filter_chars(username)))
            try:
                conn.search(cfg["group_search_base"], flt, SUBTREE, attributes=["cn"], size_limit=MAX_GROUPS,
                            time_limit=int(cfg.get("timeout_seconds") or 5))
            except LDAPException as exc:
                raise LdapError("directory", f"group search failed: {exc}") from exc
            found.update(r["dn"] for r in self._entries(conn))
        out: set[str] = set()
        for g in list(found)[:MAX_GROUPS]:
            try:
                out.add(normalize_dn(g))
            except ValueError:
                continue
        return out

    def _identity(self, cfg: dict[str, Any], entry: dict[str, Any], username: str, groups: set[str],
                  server: str) -> DirectoryUser:
        raw = entry.get("raw_attributes") or {}
        uid = _unique_id(raw.get(cfg["unique_id_attribute"]))
        if not uid:
            raise LdapError("directory", f"the entry has no {cfg['unique_id_attribute']} attribute")
        name = _text(raw.get(cfg["name_attribute"])) or _text(raw.get("cn"))
        email = _text(raw.get(cfg["email_attribute"]))
        return DirectoryUser(dn=entry["dn"], unique_id=uid,
                             username=(_text(raw.get(cfg["username_attribute"])) or username).strip().lower()[:64],
                             email=email.strip().lower()[:254] if email and "@" in email else None,
                             name=name.strip()[:120] if name and name.strip() else None, groups=groups, server=server)

    # ------------------------------------------------------------------ public (synchronous; call in a thread)
    def authenticate(self, cfg: dict[str, Any], bind_password: str | None, username: str,
                     password: str) -> DirectoryUser:
        username = check_username(username)
        if not password or len(password) > 1024:
            raise LdapError("invalid_credentials", "empty password")  # never attempt an unauthenticated bind
        url, svc = self._service(cfg, bind_password)
        try:
            entry = self._find_user(svc, cfg, username)
            user_conn = self._bind(url, cfg, entry["dn"], password)
            user_conn.unbind()
            groups = self._groups(svc, cfg, entry, username)
            return self._identity(cfg, entry, username, groups, url)
        finally:
            svc.unbind()

    def lookup(self, cfg: dict[str, Any], bind_password: str | None, username: str) -> DirectoryUser:
        username = check_username(username)
        url, svc = self._service(cfg, bind_password)
        try:
            entry = self._find_user(svc, cfg, username)
            return self._identity(cfg, entry, username, self._groups(svc, cfg, entry, username), url)
        finally:
            svc.unbind()

    def check(self, cfg: dict[str, Any], bind_password: str | None) -> str:
        """Binds the service account and reads the user search base. Returns the server used."""
        url, svc = self._service(cfg, bind_password)
        try:
            try:
                ok = svc.search(cfg["user_search_base"], "(objectClass=*)", "BASE", attributes=["objectClass"],
                                size_limit=1)
            except LDAPException as exc:
                raise LdapError("directory", f"cannot read the user search base: {exc}") from exc
            if not ok and not self._entries(svc):
                raise LdapError("directory", f"cannot read the user search base: {(svc.result or {}).get('description')}")
            return url
        finally:
            svc.unbind()
