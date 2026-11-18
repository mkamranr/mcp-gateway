"""SCIM 2.0 provisioning (RFC 7643/7644): the identity provider pushes users and groups to the gateway.

Scope and boundaries:
  * SCIM sees and changes only accounts it created (``scim`` on the user). Local accounts, break-glass
    administrators and directory (LDAP) accounts are invisible to it, so a provisioning token can't disable them.
  * Provisioned users are single sign-on accounts (no password). At their first SSO sign-in they are linked to
    their IdP identity when the configured ID-token claim equals the SCIM ``externalId`` (never by username).
  * Group memberships go through the SSO group rules: a group's displayName or externalId is matched against the
    rule's group. Changes apply at once: sessions re-read memberships and user status on every request, and
    deactivation also ends the user's sessions.
  * The SCIM bearer token is shown once and stored as an HMAC (like agent keys).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from app.config import Settings
from app.core.crypto import constant_time_equals, hash_api_key, random_token
from app.core.errors import ErrorCode, GatewayError, ScimError
from app.core.identity import Principal
from app.core.ids import utcnow
from app.core.logging import get_logger
from app.repositories.collections import Repos
from app.services.audit_service import AuditService
from app.services.auth_service import SYSTEM_TENANT, AuthService
from app.services.group_sync import desired_memberships, sync_memberships

log = get_logger(__name__)
CONFIG_KEY = "scim"
TOKEN_PREFIX = "mgw_scim_"  # noqa: S105 (a prefix, not a secret)
SOURCE = "oidc"  # memberships are the SSO group rules' (managed_by "oidc"), whichever way they are applied
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
MAX_COUNT = 200
ACTOR = {"type": "service", "id": "scim", "name": "SCIM provisioning"}
FILTER = re.compile(r'^\s*([A-Za-z][A-Za-z0-9.]*)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$', re.IGNORECASE)
MEMBER_FILTER = re.compile(r'^members\[\s*value\s+eq\s+"([^"]+)"\s*\]$', re.IGNORECASE)


def _iso(v: Any) -> str | None:
    return v.isoformat() if isinstance(v, datetime) else (str(v) if v else None)


def _parse(v: Any) -> datetime | None:
    try:
        d = datetime.fromisoformat(str(v)) if v else None
    except ValueError:
        return None
    return d.replace(tzinfo=UTC) if d is not None and d.tzinfo is None else d


def _bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("true", "false"):  # Entra ID sends "True"/"False"
        return v.strip().lower() == "true"
    raise ScimError(400, "active must be a boolean", "invalidValue")


def _str(v: Any, what: str, limit: int = 256) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str) or len(v) > limit or any(ord(ch) < 32 for ch in v):
        raise ScimError(400, f"invalid {what}", "invalidValue")
    return v.strip() or None


class ScimService:
    def __init__(self, settings: Settings, repos: Repos, audit: AuditService, auth: AuthService) -> None:
        self.settings = settings
        self.repos = repos
        self.audit = audit
        self.auth = auth

    # ------------------------------------------------------------------ configuration and token
    async def _stored(self) -> dict[str, Any]:
        return dict(await self.repos.settings.get_value(CONFIG_KEY) or {})

    async def admin_view(self) -> dict[str, Any]:
        cfg = await self._stored()
        return {"enabled": bool(cfg.get("enabled")), "link_claim": cfg.get("link_claim") or "sub",
                "groups_authoritative": cfg.get("groups_authoritative", True),
                "match_group_display_name": bool(cfg.get("match_group_display_name", False)),
                "has_token": bool(cfg.get("token_hash")), "token_prefix": cfg.get("token_prefix"),
                "token_created_at": cfg.get("token_created_at"), "last_used_at": cfg.get("last_used_at"),
                "base_url": self.settings.public_base_url.rstrip("/") + "/api/v1/scim/v2",
                "updated_at": cfg.get("updated_at")}

    async def update_config(self, p: Principal, enabled: bool, link_claim: str, groups_authoritative: bool,
                            match_group_display_name: bool = False) -> dict[str, Any]:
        cfg = await self._stored()
        if enabled and not cfg.get("token_hash"):
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "Generate a SCIM token first.")
        matching_changed = bool(cfg.get("match_group_display_name", False)) != match_group_display_name
        cfg.update({"enabled": enabled, "link_claim": link_claim, "groups_authoritative": groups_authoritative,
                    "match_group_display_name": match_group_display_name,
                    "updated_at": utcnow().isoformat(), "updated_by": p.principal_id})
        await self.repos.settings.set_value(CONFIG_KEY, cfg, p.principal_id)
        await self.audit.record(p.tenant_id, "scim.config.updated", principal=p, severity="high",
                                metadata={"enabled": enabled, "link_claim": link_claim,
                                          "groups_authoritative": groups_authoritative,
                                          "match_group_display_name": match_group_display_name})
        if matching_changed:  # which groups match the rules changed: re-evaluate every provisioned user
            ids = [u["_id"] async for u in self.repos.users.col.find({"scim": {"$exists": True}}, {"_id": 1})]
            await self.resync(ids)
        return await self.admin_view()

    async def rotate_token(self, p: Principal) -> dict[str, Any]:
        cfg = await self._stored()
        token = TOKEN_PREFIX + random_token(32)
        cfg.update({"token_hash": hash_api_key(token, self.settings.api_key_hash_pepper),
                    "token_prefix": token[:len(TOKEN_PREFIX) + 6], "token_created_at": utcnow().isoformat(),
                    "token_created_by": p.principal_id})
        await self.repos.settings.set_value(CONFIG_KEY, cfg, p.principal_id)
        await self.audit.record(p.tenant_id, "scim.token.rotated", principal=p, severity="high",
                                metadata={"token_prefix": cfg["token_prefix"]})
        return {**await self.admin_view(), "token": token}

    async def revoke_token(self, p: Principal) -> dict[str, Any]:
        cfg = await self._stored()
        cfg.update({"token_hash": None, "token_prefix": None, "enabled": False})
        await self.repos.settings.set_value(CONFIG_KEY, cfg, p.principal_id)
        await self.audit.record(p.tenant_id, "scim.token.revoked", principal=p, severity="high")
        return await self.admin_view()

    async def authenticate(self, authorization: str, source: str) -> dict[str, Any]:
        cfg = await self._stored()
        token = authorization[7:].strip() if authorization[:7].lower() == "bearer " else ""
        expected = cfg.get("token_hash") or hash_api_key("x" * 40, self.settings.api_key_hash_pepper)
        presented = hash_api_key(token or "-", self.settings.api_key_hash_pepper)
        valid = constant_time_equals(presented, expected) and token.startswith(TOKEN_PREFIX) and bool(cfg.get("token_hash"))
        if not valid or not cfg.get("enabled"):
            # Only failures are counted: an IdP's sync can send many requests a minute.
            await self.auth._throttle(f"scim:{source}", 30, 60)  # noqa: SLF001
            raise ScimError(401, "invalid or missing SCIM token")
        now = utcnow()
        last = _parse(cfg.get("last_used_at"))
        if last is None or (now - last).total_seconds() > 60:
            await self.repos.settings.col.update_one({"key": CONFIG_KEY},
                                                     {"$set": {"value.last_used_at": now.isoformat()}})
        return cfg

    # ------------------------------------------------------------------ representation
    def _location(self, kind: str, obj_id: str) -> str:
        return f"{self.settings.public_base_url.rstrip('/')}/api/v1/scim/v2/{kind}/{obj_id}"

    def user_resource(self, u: dict[str, Any]) -> dict[str, Any]:
        s = u.get("scim") or {}
        out: dict[str, Any] = {
            "schemas": [USER_SCHEMA], "id": u["_id"], "userName": s.get("userName") or u["username"],
            "displayName": u.get("display_name"), "active": u.get("status") == "active",
            "meta": {"resourceType": "User", "created": _iso(u.get("created_at")), "lastModified": _iso(u.get("updated_at")),
                     "location": self._location("Users", u["_id"])},
        }
        if s.get("externalId"):
            out["externalId"] = s["externalId"]
        if s.get("name"):
            out["name"] = s["name"]
        if u.get("email"):
            out["emails"] = [{"value": u["email"], "type": "work", "primary": True}]
        return out

    async def group_resource(self, g: dict[str, Any], *, members: bool = True) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schemas": [GROUP_SCHEMA], "id": g["_id"], "displayName": g["displayName"],
            "meta": {"resourceType": "Group", "created": _iso(g.get("created_at")),
                     "lastModified": _iso(g.get("updated_at")),
                     "location": self._location("Groups", g["_id"])},
        }
        if g.get("externalId"):
            out["externalId"] = g["externalId"]
        if members:
            names = {u["_id"]: u.get("display_name") or u["username"] async for u in self.repos.users.col.find(
                {"_id": {"$in": g.get("members", [])}}, {"display_name": 1, "username": 1})}
            out["members"] = [{"value": m, "display": names.get(m), "$ref": self._location("Users", m)}
                              for m in g.get("members", []) if m in names]
        return out

    @staticmethod
    def list_response(resources: list[dict[str, Any]], total: int, start: int) -> dict[str, Any]:
        return {"schemas": [LIST_SCHEMA], "totalResults": total, "startIndex": start,
                "itemsPerPage": len(resources), "Resources": resources}

    @staticmethod
    def _filter(expr: str | None, allowed: dict[str, str]) -> dict[str, Any]:
        if not expr:
            return {}
        m = FILTER.match(expr)
        if not m or m.group(1).lower() not in allowed:
            raise ScimError(400, f"unsupported filter; use one of: {', '.join(sorted(allowed))} eq \"...\"",
                            "invalidFilter")
        field, value = allowed[m.group(1).lower()], m.group(2).replace('\\"', '"')
        if field == "username":
            value = value.strip().lower()
        return {field: value}

    # ------------------------------------------------------------------ users
    async def _user(self, user_id: str) -> dict[str, Any]:
        u = await self.repos.users.col.find_one({"_id": user_id, "scim": {"$exists": True}, "scim.deleted": {"$ne": True}})
        if not u:
            raise ScimError(404, "User not found")
        return u

    async def list_users(self, flt: str | None, start: int, count: int) -> dict[str, Any]:
        q: dict[str, Any] = {"scim": {"$exists": True}, "scim.deleted": {"$ne": True}}
        q.update(self._filter(flt, {"username": "username", "externalid": "scim.externalId", "id": "_id",
                                    "emails.value": "email"}))
        if "email" in q:
            q["email"] = str(q["email"]).lower()
        total = await self.repos.users.col.count_documents(q)
        start, count = max(1, start), max(0, min(count, MAX_COUNT))
        docs = [u async for u in self.repos.users.col.find(q).sort("_id", 1).skip(start - 1).limit(count)]
        return self.list_response([self.user_resource(u) for u in docs], total, start)

    async def get_user(self, user_id: str) -> dict[str, Any]:
        return self.user_resource(await self._user(user_id))

    @staticmethod
    def _user_fields(body: dict[str, Any]) -> dict[str, Any]:
        """SCIM User attributes -> our fields. Unsupported attributes are ignored."""
        out: dict[str, Any] = {}
        if "userName" in body:
            name = _str(body["userName"], "userName", 128)
            if not name:
                raise ScimError(400, "userName is required", "invalidValue")
            out["userName"] = name
        if "externalId" in body:
            out["externalId"] = _str(body["externalId"], "externalId")
        if "displayName" in body:
            out["displayName"] = _str(body["displayName"], "displayName", 120)
        if "name" in body and isinstance(body["name"], dict):
            out["name"] = {k: str(v)[:120] for k, v in body["name"].items()
                           if k in ("formatted", "givenName", "familyName") and isinstance(v, str)}
        if "emails" in body and isinstance(body["emails"], list):
            emails = [e for e in body["emails"] if isinstance(e, dict) and isinstance(e.get("value"), str)]
            primary = next((e for e in emails if e.get("primary") in (True, "true", "True")), emails[0] if emails else None)
            out["email"] = _str(primary["value"], "email", 254) if primary else None
        if "active" in body:
            out["active"] = _bool(body["active"])
        return out

    def _apply_user(self, u: dict[str, Any], f: dict[str, Any]) -> dict[str, Any]:
        """Our document updates for parsed SCIM fields."""
        s = dict(u.get("scim") or {})
        upd: dict[str, Any] = {}
        if "userName" in f:
            s["userName"] = f["userName"]
            upd["username"] = f["userName"].lower()
        if "externalId" in f:
            s["externalId"] = f["externalId"]
        if "name" in f:
            s["name"] = f["name"]
        display = f.get("displayName") or (f.get("name") or {}).get("formatted")
        if display:
            upd["display_name"] = display
        if "email" in f:
            upd["email"] = f["email"].lower() if f["email"] else None
        if "active" in f:
            upd["status"] = "active" if f["active"] else "disabled"
        upd["scim"] = s
        return upd

    async def create_user(self, body: dict[str, Any]) -> dict[str, Any]:
        f = self._user_fields(body)
        if not f.get("userName"):
            raise ScimError(400, "userName is required", "invalidValue")
        username = f["userName"].lower()
        existing = await self.repos.users.by_username(username)
        if existing and not (existing.get("scim") or {}).get("deleted"):
            # Includes local, LDAP and SSO accounts that SCIM didn't create: never taken over.
            raise ScimError(409, "userName is already in use", "uniqueness")
        doc = {"username": username, "display_name": f.get("displayName") or username, "email": None,
               "status": "active", "is_platform_admin": False, "auth_source": "oidc", "must_change_password": False,
               "scim": {}}
        doc.update(self._apply_user(doc, {"active": True, **f}))
        if existing:  # re-created after a SCIM delete: reuse the record (its audit history stays attached)
            # userNames are recycled (UPN reuse), so this may be a different person: none of the previous
            # owner's access carries over. Memberships come back only through this user's own groups.
            await self._disable_memberships(existing, "SCIM user re-created")
            doc["scim"]["deleted"] = False
            await self.repos.users.col.update_one({"_id": existing["_id"]}, {"$set": {**doc, "updated_at": utcnow()},
                                                                             "$unset": {"oidc": ""}})
            user = await self.repos.users.get(existing["_id"])
        else:
            user = await self._insert_user(doc)
        assert user is not None
        await self.audit.record(SYSTEM_TENANT, "user.scim.created", principal=ACTOR,
                                resource={"user_id": user["_id"], "username": username},
                                metadata={"externalId": doc["scim"].get("externalId"), "active": doc["status"] == "active"})
        return self.user_resource(user)

    async def _insert_user(self, doc: dict[str, Any]) -> dict[str, Any]:
        try:
            return await self.repos.users.insert(doc)
        except GatewayError as exc:
            if exc.code != ErrorCode.CONFLICT:
                raise
            if doc.get("email"):  # the email belongs to another account: keep the user, drop the email
                try:
                    return await self.repos.users.insert({**doc, "email": None})
                except GatewayError:
                    pass
            raise ScimError(409, "userName is already in use", "uniqueness") from None

    async def replace_user(self, user_id: str, body: dict[str, Any]) -> dict[str, Any]:
        u = await self._user(user_id)
        f = self._user_fields(body)
        if not f.get("userName"):
            raise ScimError(400, "userName is required", "invalidValue")
        f.setdefault("active", True)
        return await self._update_user(u, f)

    async def patch_user(self, user_id: str, body: dict[str, Any]) -> dict[str, Any]:
        u = await self._user(user_id)
        f: dict[str, Any] = {}
        for op in self._operations(body):
            kind, path, value = op
            if kind == "remove":
                if path in ("externalId", "displayName"):
                    f[path] = None
                elif path in ("emails", 'emails[type eq "work"].value', "emails.value"):
                    f["email"] = None
                continue
            if path is None:
                if not isinstance(value, dict):
                    raise ScimError(400, "a patch without a path needs an object value", "invalidValue")
                f.update(self._user_fields(value))
                for k, v in value.items():  # Entra ID: {"name.givenName": "..."} style keys
                    if k.startswith("name.") and isinstance(v, str):
                        f.setdefault("name", dict((u.get("scim") or {}).get("name") or {}))[k[5:]] = v[:120]
            elif path in ("active", "userName", "externalId", "displayName"):
                f.update(self._user_fields({path: value}))
            elif path.startswith("name."):
                name = dict(f.get("name") or (u.get("scim") or {}).get("name") or {})
                if path[5:] in ("formatted", "givenName", "familyName") and isinstance(value, str):
                    name[path[5:]] = value[:120]
                f["name"] = name
            elif path in ('emails[type eq "work"].value', "emails.value"):
                f["email"] = _str(value, "email", 254)
            elif path == "emails":
                f.update(self._user_fields({"emails": value if isinstance(value, list) else [value]}))
            # Anything else (title, addresses, enterprise extension, ...) is accepted and ignored.
        if "userName" in f and f["userName"].lower() != u["username"]:
            other = await self.repos.users.by_username(f["userName"].lower())
            if other and other["_id"] != u["_id"]:
                raise ScimError(409, "userName is already in use", "uniqueness")
        return await self._update_user(u, f)

    @staticmethod
    def _operations(body: dict[str, Any]) -> list[tuple[str, str | None, Any]]:
        if PATCH_SCHEMA not in (body.get("schemas") or []) or not isinstance(body.get("Operations"), list):
            raise ScimError(400, "expected a PatchOp request", "invalidSyntax")
        ops = []
        for op in body["Operations"][:100]:
            if not isinstance(op, dict):
                raise ScimError(400, "invalid operation", "invalidSyntax")
            kind = str(op.get("op", "")).lower()
            if kind not in ("add", "replace", "remove"):
                raise ScimError(400, f"unsupported op {kind[:20]!r}", "invalidSyntax")
            path = op.get("path")
            ops.append((kind, str(path).strip() if isinstance(path, str) and path.strip() else None, op.get("value")))
        return ops

    async def _update_user(self, u: dict[str, Any], f: dict[str, Any]) -> dict[str, Any]:
        upd = self._apply_user(u, f)
        if "username" in upd and upd["username"] != u["username"]:
            other = await self.repos.users.by_username(upd["username"])
            if other and other["_id"] != u["_id"]:
                raise ScimError(409, "userName is already in use", "uniqueness")
        try:
            user = await self.repos.users.update(u["_id"], upd)
        except GatewayError as exc:
            if exc.code != ErrorCode.CONFLICT or not upd.get("email"):
                raise
            user = await self.repos.users.update(u["_id"], {**upd, "email": None})
        assert user is not None
        deactivated = u.get("status") == "active" and user.get("status") != "active"
        if deactivated:
            await self.auth.revoke_user_sessions(u["_id"])
        changed = sorted(k for k in upd if upd[k] != u.get(k))
        if changed:
            await self.audit.record(
                SYSTEM_TENANT, "user.scim.deactivated" if deactivated else "user.scim.updated", principal=ACTOR,
                severity="high" if deactivated else None,
                resource={"user_id": u["_id"], "username": user["username"]}, metadata={"changed": changed})
        return self.user_resource(user)

    async def delete_user(self, user_id: str) -> None:
        u = await self._user(user_id)
        await self.repos.users.update(u["_id"], {"status": "disabled", "scim": {**(u.get("scim") or {}),
                                                                                  "deleted": True}})
        await self.auth.revoke_user_sessions(u["_id"])
        # Every membership, hand-made ones included: a later user with the same userName must not inherit them.
        await self._disable_memberships(u, "SCIM user deleted")
        await self.repos.scim_groups.col.update_many({"members": u["_id"]}, {"$pull": {"members": u["_id"]}})
        await self.resync([u["_id"]])
        await self.audit.record(SYSTEM_TENANT, "user.scim.deleted", principal=ACTOR, severity="high",
                                resource={"user_id": u["_id"], "username": u["username"]})

    async def _disable_memberships(self, user: dict[str, Any], reason: str) -> None:
        """Disable all of ``user``'s active memberships, whoever created them, and audit each one."""
        who = {"user_id": user["_id"], "username": user["username"]}
        async for m in self.repos.memberships.col.find({"user_id": user["_id"], "status": "active"}):
            await self.repos.memberships.update(m["tenant_id"], m["_id"], {"status": "disabled"})
            await self.audit.record(m["tenant_id"], "user.membership.changed", principal=ACTOR, resource=who,
                                    metadata={"status": "disabled", "roles": m.get("roles", []),
                                              "managed_by": m.get("managed_by"), "reason": reason})

    # ------------------------------------------------------------------ groups
    async def _group(self, group_id: str) -> dict[str, Any]:
        g = await self.repos.scim_groups.get(group_id)
        if not g:
            raise ScimError(404, "Group not found")
        return g

    async def list_groups(self, flt: str | None, start: int, count: int, members: bool) -> dict[str, Any]:
        q = self._filter(flt, {"displayname": "displayName", "externalid": "externalId", "id": "_id"})
        total = await self.repos.scim_groups.col.count_documents(q)
        start, count = max(1, start), max(0, min(count, MAX_COUNT))
        docs = [g async for g in self.repos.scim_groups.col.find(q).sort("_id", 1).skip(start - 1).limit(count)]
        return self.list_response([await self.group_resource(g, members=members) for g in docs], total, start)

    async def get_group(self, group_id: str, members: bool = True) -> dict[str, Any]:
        return await self.group_resource(await self._group(group_id), members=members)

    async def _member_ids(self, value: Any) -> list[str]:
        items = value if isinstance(value, list) else [value]
        ids = [str(m.get("value")) for m in items if isinstance(m, dict) and m.get("value")]
        known = {u["_id"] async for u in self.repos.users.col.find(
            {"_id": {"$in": ids}, "scim": {"$exists": True}, "scim.deleted": {"$ne": True}}, {"_id": 1})}
        unknown = [i for i in ids if i not in known]
        if unknown:  # only SCIM-provisioned users can be members; anything else is ignored, not an error
            log.info("scim.group.unknown_members", count=len(unknown))
        return [i for i in ids if i in known]

    async def create_group(self, body: dict[str, Any]) -> dict[str, Any]:
        name = _str(body.get("displayName"), "displayName")
        if not name:
            raise ScimError(400, "displayName is required", "invalidValue")
        if await self.repos.scim_groups.col.find_one({"displayName": name}):
            raise ScimError(409, "displayName is already in use", "uniqueness")
        members = await self._member_ids(body.get("members") or [])
        g = await self.repos.scim_groups.insert({"displayName": name, "externalId": _str(body.get("externalId"),
                                                                                           "externalId"),
                                                 "members": sorted(set(members))})
        await self.audit.record(SYSTEM_TENANT, "group.scim.created", principal=ACTOR,
                                resource={"group_id": g["_id"], "group": name}, metadata={"members": len(members)})
        await self.resync(members)
        return await self.group_resource(g)

    async def replace_group(self, group_id: str, body: dict[str, Any]) -> dict[str, Any]:
        g = await self._group(group_id)
        name = _str(body.get("displayName"), "displayName") or g["displayName"]
        members = sorted(set(await self._member_ids(body.get("members") or [])))
        new = await self.repos.scim_groups.update(g["_id"], {"displayName": name, "members": members,
                                                             "externalId": _str(body.get("externalId"), "externalId")})
        return await self._after_group_change(g, new)

    async def patch_group(self, group_id: str, body: dict[str, Any]) -> dict[str, Any]:
        g = await self._group(group_id)
        col = self.repos.scim_groups.col
        for kind, path, value in self._operations(body):
            m = MEMBER_FILTER.match(path or "")
            if kind == "remove" and m:
                await col.update_one({"_id": g["_id"]}, {"$pull": {"members": m.group(1)}})
            elif (path or "").lower() == "members":
                if kind == "remove" and value is None:
                    await col.update_one({"_id": g["_id"]}, {"$set": {"members": []}})
                elif kind == "remove":  # Entra ID: remove with a value list
                    ids = [str(x.get("value")) for x in (value if isinstance(value, list) else [value])
                           if isinstance(x, dict)]
                    await col.update_one({"_id": g["_id"]}, {"$pull": {"members": {"$in": ids}}})
                elif kind == "add":
                    await col.update_one({"_id": g["_id"]},
                                         {"$addToSet": {"members": {"$each": await self._member_ids(value)}}})
                else:
                    await col.update_one({"_id": g["_id"]}, {"$set": {"members": sorted(set(
                        await self._member_ids(value)))}})
            elif path is None and isinstance(value, dict):
                upd = {}
                if "displayName" in value:
                    upd["displayName"] = _str(value["displayName"], "displayName") or g["displayName"]
                if "externalId" in value:
                    upd["externalId"] = _str(value["externalId"], "externalId")
                if "members" in value:
                    upd["members"] = sorted(set(await self._member_ids(value["members"])))
                if upd:
                    await col.update_one({"_id": g["_id"]}, {"$set": upd})
            elif path in ("displayName", "externalId"):
                await col.update_one({"_id": g["_id"]}, {"$set": {path: _str(value, path) if kind != "remove"
                                                                  else None}})
            else:
                raise ScimError(400, f"unsupported path {str(path)[:60]!r}", "invalidPath")
        await col.update_one({"_id": g["_id"]}, {"$set": {"updated_at": utcnow()}})
        return await self._after_group_change(g, await self.repos.scim_groups.get(g["_id"]))

    async def _after_group_change(self, old: dict[str, Any], new: dict[str, Any] | None) -> dict[str, Any]:
        assert new is not None
        before, after = set(old.get("members", [])), set(new.get("members", []))
        renamed = (old.get("displayName"), old.get("externalId")) != (new.get("displayName"), new.get("externalId"))
        affected = sorted(before | after) if renamed else sorted(before ^ after)
        await self.audit.record(SYSTEM_TENANT, "group.scim.updated", principal=ACTOR,
                                resource={"group_id": new["_id"], "group": new["displayName"]},
                                metadata={"added": len(after - before), "removed": len(before - after),
                                          "renamed": renamed})
        await self.resync(affected)
        return await self.group_resource(new)

    async def delete_group(self, group_id: str) -> None:
        g = await self._group(group_id)
        await self.repos.scim_groups.col.delete_one({"_id": g["_id"]})
        await self.audit.record(SYSTEM_TENANT, "group.scim.deleted", principal=ACTOR,
                                resource={"group_id": g["_id"], "group": g["displayName"]})
        await self.resync(g.get("members", []))

    # ------------------------------------------------------------------ access
    async def user_groups(self, user_id: str, match_display_name: bool = False) -> set[str]:
        """The names the group rules see for ``user_id``'s SCIM groups: each group's externalId.

        displayName is not trusted by default: in many IdPs any user can create a group and name it freely, for
        example after an admin group's object ID. With ``match_display_name``, a group *without* an externalId is
        matched by its displayName; a group with one is still matched only by it."""
        names: set[str] = set()
        async for g in self.repos.scim_groups.col.find({"members": user_id}, {"displayName": 1, "externalId": 1}):
            if g.get("externalId"):
                names.add(g["externalId"])
            elif match_display_name:
                names.add(g["displayName"])
        return names

    async def resync(self, user_ids: list[str]) -> None:
        """Re-apply the SSO group rules to these users from their SCIM groups. Takes effect on their next request.

        Only when SCIM groups are authoritative; otherwise memberships come from the ID token at sign-in."""
        cfg = await self._stored()
        if not user_ids or not cfg.get("groups_authoritative", True):
            return
        by_name = bool(cfg.get("match_group_display_name", False))
        sso = await self.repos.settings.get_value("oidc") or {}
        rules, admin_groups = sso.get("group_rules") or [], set(sso.get("platform_admin_groups") or [])
        async for u in self.repos.users.col.find({"_id": {"$in": list(user_ids)}, "scim": {"$exists": True}}):
            live = u.get("status") == "active" and not (u.get("scim") or {}).get("deleted")
            groups = await self.user_groups(u["_id"], by_name) if live else set()
            await sync_memberships(self.repos, self.audit, u, desired_memberships(rules, groups), SOURCE,
                                   via="scim")
            is_admin = bool(groups & admin_groups)
            upd: dict[str, Any] = {"last_scim_groups": sorted(groups)[:200]}
            if bool(u.get("is_platform_admin")) != is_admin:
                upd["is_platform_admin"] = is_admin
                await self.audit.record(SYSTEM_TENANT, "user.platform_admin.changed", severity="high",
                                        principal={"type": "user", "id": u["_id"], "name": u["username"]},
                                        metadata={"is_platform_admin": is_admin, "source": "scim"})
            await self.repos.users.update(u["_id"], upd)

    async def link_claim(self) -> tuple[bool, str, bool]:
        """(enabled, ID-token claim compared with externalId, SCIM groups authoritative) for the SSO service."""
        cfg = await self._stored()
        return bool(cfg.get("enabled")), cfg.get("link_claim") or "sub", bool(cfg.get("groups_authoritative", True))
