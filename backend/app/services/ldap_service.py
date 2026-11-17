"""LDAP / Active Directory sign-in for console users.

Users sign in on the normal login form with their directory username and password. Accounts that exist here
as local accounts keep signing in locally (so a directory user can never take over a local account by sharing
its username); everyone else is authenticated against the directory with search-then-bind. At every directory
sign-in the user's groups are mapped to tenant roles through the group rules (shared with OIDC SSO), and
directory-managed memberships are re-synchronised.
"""

from __future__ import annotations

import asyncio
from typing import Any

from pymongo.errors import DuplicateKeyError

from app.config import Settings
from app.core.crypto import Encryptor
from app.core.errors import ErrorCode, GatewayError
from app.core.identity import Principal
from app.core.ids import utcnow
from app.core.logging import get_logger
from app.models.ldap import LdapConfigUpdate, normalize_dn
from app.repositories.collections import Repos
from app.services.audit_service import AuditService
from app.services.auth_service import SYSTEM_TENANT
from app.services.group_sync import desired_memberships, sync_memberships
from app.services.ldap_client import DirectoryUser, LdapDirectory, LdapError, ssl_context

log = get_logger(__name__)
CONFIG_KEY = "ldap"
SECRET_AAD = "system:ldap:bind_password"  # noqa: S105 (associated data label, not a secret)
SOURCE = "ldap"


class LdapService:
    def __init__(self, settings: Settings, repos: Repos, encryptor: Encryptor, audit: AuditService,
                 directory: LdapDirectory | None = None) -> None:
        self.settings = settings
        self.repos = repos
        self.encryptor = encryptor
        self.audit = audit
        self.directory = directory or LdapDirectory(settings)
        self._slots = asyncio.Semaphore(settings.ldap_max_concurrent_binds)

    # ------------------------------------------------------------------ configuration
    async def _stored(self) -> dict[str, Any]:
        return dict(await self.repos.settings.get_value(CONFIG_KEY) or {})

    def _config(self, cfg: dict[str, Any]) -> dict[str, Any]:
        """Stored values merged over the defaults, so older stored documents gain new fields."""
        known = {k: v for k, v in cfg.items() if k in LdapConfigUpdate.model_fields}
        return LdapConfigUpdate.model_validate(known).model_dump(exclude={"bind_password"}) if known else \
            LdapConfigUpdate().model_dump(exclude={"bind_password"})

    def _password(self, cfg: dict[str, Any]) -> str | None:
        enc = cfg.get("bind_password_enc")
        return self.encryptor.decrypt(enc, SECRET_AAD).decode() if enc else None

    async def admin_view(self) -> dict[str, Any]:
        cfg = await self._stored()
        out = self._config(cfg)
        out.update({"has_bind_password": bool(cfg.get("bind_password_enc")), "updated_at": cfg.get("updated_at"),
                    "updated_by": cfg.get("updated_by")})
        return out

    async def enabled(self) -> bool:
        return bool((await self._stored()).get("enabled"))

    async def update_config(self, p: Principal, body: LdapConfigUpdate) -> dict[str, Any]:
        cfg = await self._stored()
        data = body.model_dump(exclude={"bind_password"})
        tenant_ids = sorted({r["tenant_id"] for r in data["group_rules"]})
        if tenant_ids:
            found = {t["_id"] async for t in self.repos.tenants.col.find({"_id": {"$in": tenant_ids}}, {"_id": 1})}
            missing = [t for t in tenant_ids if t not in found]
            if missing:
                raise GatewayError(ErrorCode.VALIDATION_FAILED, f"Unknown tenant in group rules: {', '.join(missing)}")
        if data["local_login"] == "break_glass_only":
            ok = await self.repos.users.col.count_documents({
                "username": {"$in": data["break_glass_usernames"]}, "is_platform_admin": True, "status": "active",
                "password_hash": {"$type": "string"}, "auth_source": {"$nin": ["oidc", "ldap"]}})
            if not ok:
                raise GatewayError(ErrorCode.VALIDATION_FAILED,
                                   "At least one break-glass account must be an active local platform administrator.")
        insecure = [u for u in data["server_urls"] if u.startswith("ldap://")] if not data["start_tls"] else []
        if insecure and not (self.settings.ldap_allow_insecure and self.settings.app_env != "production"):
            raise GatewayError(ErrorCode.VALIDATION_FAILED,
                               "Use ldaps:// or turn on StartTLS: passwords must never cross the network in clear text.")
        if data["ca_pem"]:
            try:
                ssl_context(data["ca_pem"])
            except LdapError as exc:
                raise GatewayError(ErrorCode.VALIDATION_FAILED, "The CA bundle could not be loaded.") from exc
        if body.bind_password is not None:
            data["bind_password_enc"] = (self.encryptor.encrypt(body.bind_password.encode(), SECRET_AAD)
                                         if body.bind_password else None)
        else:
            data["bind_password_enc"] = cfg.get("bind_password_enc")
        if data["bind_dn"] and not data["bind_password_enc"] and data["enabled"]:
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "Set the service account password.")
        changed = sorted(k for k in (set(data) | set(cfg)) - {"updated_at", "updated_by"} if data.get(k) != cfg.get(k))
        data.update({"updated_at": utcnow().isoformat(), "updated_by": p.principal_id})
        await self.repos.settings.set_value(CONFIG_KEY, data, p.principal_id)
        await self.audit.record(
            p.tenant_id, "ldap.config.updated", principal=p, severity="high",
            metadata={"changed": [("bind_password" if k == "bind_password_enc" else k) for k in changed],
                      "enabled": data["enabled"], "local_login": data["local_login"]},
        )
        return await self.admin_view()

    async def test_connection(self, p: Principal, username: str | None) -> dict[str, Any]:
        """Checks the saved configuration; with a username, also looks the user up (no password) and shows the
        groups and the access the group rules would grant."""
        stored = await self._stored()
        cfg = self._config(stored)
        if not cfg["server_urls"] or not cfg["user_search_base"]:
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "Set a server URL and the user search base first.")
        try:
            password = self._password(stored)
            async with self._slots:
                server = await asyncio.to_thread(self.directory.check, cfg, password)
                user = await asyncio.to_thread(self.directory.lookup, cfg, password, username) if username else None
        except LdapError as exc:
            if exc.code == "invalid_credentials" and username:
                return {"ok": True, "user": None, "detail": "No unique directory entry matches that username."}
            return {"ok": False, "error": exc.code, "detail": exc.detail}
        except Exception as exc:  # noqa: BLE001 - report, don't 500
            return {"ok": False, "error": "unavailable", "detail": f"{type(exc).__name__}: {exc}"[:300]}
        out: dict[str, Any] = {"ok": True, "server": server}
        if user is not None:
            desired = desired_memberships(cfg["group_rules"], user.groups, normalize_dn)
            out["user"] = {"dn": user.dn, "unique_id": user.unique_id, "username": user.username, "email": user.email,
                           "display_name": user.name, "groups": sorted(user.groups)[:200],
                           "grants": {t: sorted(r) for t, r in desired.items()},
                           "platform_admin": self._is_admin(cfg, user)}
        await self.audit.record(p.tenant_id, "ldap.config.tested", principal=p,
                                metadata={"ok": True, "lookup": bool(username)})
        return out

    # ------------------------------------------------------------------ sign-in
    @staticmethod
    def _is_admin(cfg: dict[str, Any], user: DirectoryUser) -> bool:
        admins: set[str] = set()
        for g in cfg.get("platform_admin_groups") or []:
            try:
                admins.add(normalize_dn(g))
            except ValueError:
                continue
        return bool(user.groups & admins)

    async def _deny(self, reason: str, username: str, source_ip: str, user_id: str | None = None) -> GatewayError:
        await self.audit.record(
            SYSTEM_TENANT, "auth.login.failed", status="failure",
            principal={"type": "user", "id": user_id, "name": username[:64]},
            metadata={"source_ip": source_ip, "method": "ldap", "reason": reason},
        )
        return GatewayError(ErrorCode.INVALID_CREDENTIAL, "Invalid username or password.")

    async def authenticate(self, username: str, password: str, source_ip: str) -> dict[str, Any]:
        """Returns the provisioned, synchronised user. Raises INVALID_CREDENTIAL (audited) or
        DEPENDENCY_UNAVAILABLE when the directory can't be reached."""
        stored = await self._stored()
        cfg = self._config(stored)
        try:
            async with self._slots:
                found = await asyncio.to_thread(self._authenticate, cfg, stored, username, password)
        except LdapError as exc:
            if exc.code == "invalid_credentials":
                raise await self._deny(exc.detail, username, source_ip) from exc
            log.warning("ldap.login.unavailable", code=exc.code, detail=exc.detail)
            await self.audit.record(SYSTEM_TENANT, "auth.ldap.failed", status="failure", severity="high",
                                    principal={"type": "user", "id": None, "name": username[:64]},
                                    metadata={"source_ip": source_ip, "error": exc.code, "detail": exc.detail})
            raise GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE,
                               "The directory is unavailable. Try again later.") from exc
        return await self._provision(cfg, found, source_ip)

    def _authenticate(self, cfg: dict[str, Any], stored: dict[str, Any], username: str,
                      password: str) -> DirectoryUser:
        try:
            return self.directory.authenticate(cfg, self._password(stored), username, password)
        except LdapError:
            raise
        except Exception as exc:  # noqa: BLE001 - an unexpected client error is an outage, not a 500
            raise LdapError("unavailable", f"{type(exc).__name__}: {exc}") from exc

    async def _provision(self, cfg: dict[str, Any], found: DirectoryUser, source_ip: str) -> dict[str, Any]:
        desired = desired_memberships(cfg["group_rules"], found.groups, normalize_dn)
        is_admin = self._is_admin(cfg, found)
        user = await self.repos.users.col.find_one({"ldap.id": found.unique_id})
        if user is None:
            existing = await self.repos.users.by_username(found.username)
            if existing is not None:
                # A local or SSO account, or a directory account for a different entry (deleted and re-created
                # with the same name): never take it over.
                raise await self._deny("username belongs to another account", found.username, source_ip,
                                       existing["_id"])
            if not cfg.get("jit_provisioning", True):
                raise await self._deny("no account and JIT provisioning is off", found.username, source_ip)
            if not desired and not is_admin:
                raise await self._deny("no group mapping grants access", found.username, source_ip)
            doc = {"username": found.username, "email": found.email, "display_name": found.name or found.username,
                   "status": "active", "is_platform_admin": False, "auth_source": SOURCE,
                   "must_change_password": False, "ldap": {"id": found.unique_id, "dn": found.dn}}
            try:
                user = await self.repos.users.insert(doc)
            except DuplicateKeyError:  # e.g. the email is already used by another account
                try:
                    user = await self.repos.users.insert({**doc, "email": None})
                except DuplicateKeyError:  # a concurrent first sign-in won the race
                    user = await self.repos.users.col.find_one({"ldap.id": found.unique_id})
                    if user is None:
                        raise await self._deny("username belongs to another account", found.username,
                                               source_ip) from None
            else:
                await self.audit.record(SYSTEM_TENANT, "user.ldap.provisioned",
                                        principal={"type": "user", "id": user["_id"], "name": found.username},
                                        metadata={"groups_matched": sorted(desired), "server": found.server})
        assert user is not None
        if user.get("status") != "active":
            raise await self._deny("account is disabled", found.username, source_ip, user["_id"])

        updates: dict[str, Any] = {"last_ldap_groups": sorted(found.groups)[:200],
                                   "ldap": {"id": found.unique_id, "dn": found.dn}}
        if found.name:
            updates["display_name"] = found.name
        if user.get("is_platform_admin") != is_admin:
            updates["is_platform_admin"] = is_admin
            await self.audit.record(SYSTEM_TENANT, "user.platform_admin.changed", severity="high",
                                    principal={"type": "user", "id": user["_id"], "name": user["username"]},
                                    metadata={"is_platform_admin": is_admin, "source": SOURCE})
        await self.repos.users.update(user["_id"], updates)
        await sync_memberships(self.repos, self.audit, user, desired, SOURCE)
        return await self.repos.users.get(user["_id"]) or user
