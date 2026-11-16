"""OIDC single sign-on for console users (Phase 6).

One platform-wide IdP. On every SSO login the user's IdP groups are mapped to tenant memberships and roles
through the configured group rules, and memberships created by SSO are re-synchronised (a group removed in
the IdP removes the access here). Memberships an administrator created by hand are never touched.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlencode

from pymongo.errors import DuplicateKeyError
from redis.asyncio import Redis

from app.config import Settings
from app.core.crypto import Encryptor, constant_time_equals, random_token
from app.core.errors import ErrorCode, GatewayError
from app.core.identity import Principal
from app.core.ids import utcnow
from app.core.logging import get_logger
from app.models.sso import OidcConfigUpdate
from app.repositories.collections import Repos
from app.services.audit_service import AuditService
from app.services.auth_service import SYSTEM_TENANT, AuthService
from app.services.oidc_client import OidcClient, OidcError, pkce_pair

log = get_logger(__name__)
CONFIG_KEY = "oidc"
SECRET_AAD = "system:oidc:client_secret"  # noqa: S105 (associated data label, not a secret)
STATE_TTL_SECONDS = 600
MANAGED_BY = "oidc"


def safe_return_to(value: str | None) -> str:
    """Only same-origin absolute paths: blocks open redirects such as //evil.example or /\\evil.example."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value or "\n" in value \
            or "\r" in value or value.startswith("/api/"):
        return "/"
    return value[:500]


class SsoService:
    def __init__(self, settings: Settings, repos: Repos, redis: Redis, encryptor: Encryptor,
                 audit: AuditService, auth: AuthService, client: OidcClient | None = None) -> None:
        self.settings = settings
        self.repos = repos
        self.redis = redis
        self.encryptor = encryptor
        self.audit = audit
        self.auth = auth
        self.client = client or OidcClient(settings)

    # ------------------------------------------------------------------ configuration
    async def _stored(self) -> dict[str, Any]:
        return dict(await self.repos.settings.get_value(CONFIG_KEY) or {})

    async def admin_view(self) -> dict[str, Any]:
        cfg = await self._stored()
        secret = cfg.pop("client_secret_enc", None)
        base = OidcConfigUpdate.model_validate({k: v for k, v in cfg.items() if k in OidcConfigUpdate.model_fields}
                                               ) if cfg else OidcConfigUpdate()
        out = base.model_dump(exclude={"client_secret"})
        out.update({"has_client_secret": bool(secret), "redirect_uri": self.settings.oidc_redirect_uri,
                    "updated_at": cfg.get("updated_at"), "updated_by": cfg.get("updated_by")})
        return out

    async def public_view(self) -> dict[str, Any]:
        cfg = await self._stored()
        enabled = bool(cfg.get("enabled"))
        return {"enabled": enabled, "display_name": cfg.get("display_name") or "Single sign-on",
                "local_login": cfg.get("local_login", "enabled") if enabled else "enabled"}

    async def update_config(self, p: Principal, body: OidcConfigUpdate) -> dict[str, Any]:
        cfg = await self._stored()
        data = body.model_dump(exclude={"client_secret"})
        # Group rules must point at real tenants.
        tenant_ids = sorted({r["tenant_id"] for r in data["group_rules"]})
        if tenant_ids:
            found = {t["_id"] async for t in self.repos.tenants.col.find({"_id": {"$in": tenant_ids}}, {"_id": 1})}
            missing = [t for t in tenant_ids if t not in found]
            if missing:
                raise GatewayError(ErrorCode.VALIDATION_FAILED, f"Unknown tenant in group rules: {', '.join(missing)}")
        # Restricting local login must leave at least one working break-glass platform administrator.
        if data["local_login"] == "break_glass_only":
            ok = await self.repos.users.col.count_documents({
                "username": {"$in": data["break_glass_usernames"]}, "is_platform_admin": True, "status": "active",
                "password_hash": {"$type": "string"}, "auth_source": {"$ne": "oidc"}})
            if not ok:
                raise GatewayError(ErrorCode.VALIDATION_FAILED,
                                   "At least one break-glass account must be an active local platform administrator.")
        if body.client_secret is not None:
            data["client_secret_enc"] = (self.encryptor.encrypt(body.client_secret.encode(), SECRET_AAD)
                                         if body.client_secret else None)
        else:
            data["client_secret_enc"] = cfg.get("client_secret_enc")
        if data["issuer"]:
            self._issuer_ok(data["issuer"])
        changed = sorted(k for k in (set(data) | set(cfg)) - {"updated_at", "updated_by"} if data.get(k) != cfg.get(k))
        data.update({"updated_at": utcnow().isoformat(), "updated_by": p.principal_id})
        await self.repos.settings.set_value(CONFIG_KEY, data, p.principal_id)
        await self.audit.record(
            p.tenant_id, "sso.config.updated", principal=p, severity="high",
            metadata={"changed": [("client_secret" if k == "client_secret_enc" else k) for k in changed],
                      "enabled": data["enabled"], "local_login": data["local_login"]},
        )
        return await self.admin_view()

    def _issuer_ok(self, issuer: str) -> None:
        try:
            self.client.check_url(issuer, "issuer")
        except OidcError as exc:
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "The issuer must use https.") from exc

    async def test_connection(self, p: Principal) -> dict[str, Any]:
        cfg = await self._stored()
        if not cfg.get("issuer"):
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "Set the issuer first.")
        try:
            disc = await self.client.discover(cfg["issuer"], force=True)
            keys = await self.client.key_count(disc["jwks_uri"])
        except OidcError as exc:
            return {"ok": False, "error": exc.code, "detail": exc.detail}
        algs = disc.get("id_token_signing_alg_values_supported") or []
        return {"ok": True, "authorization_endpoint": disc["authorization_endpoint"],
                "token_endpoint": disc["token_endpoint"], "userinfo_endpoint": disc.get("userinfo_endpoint"),
                "end_session_endpoint": disc.get("end_session_endpoint"), "signing_keys": keys,
                "signing_algorithms": algs,
                "algorithm_overlap": sorted(set(algs) & set(cfg.get("allowed_algorithms") or [])) if algs else None}

    # ------------------------------------------------------------------ login
    @staticmethod
    def _state_key(state: str) -> str:
        return f"oidc:state:{hashlib.sha256(state.encode()).hexdigest()}"

    async def start_login(self, return_to: str | None, source_ip: str) -> tuple[str, str]:
        """Returns (authorization URL, browser-binding token for the short-lived state cookie)."""
        cfg = await self._stored()
        if not cfg.get("enabled"):
            raise OidcError("sso_disabled", "SSO is not enabled")
        await self.auth._throttle(f"oidc-start:{source_ip}", 60, 300)
        disc = await self.client.discover(cfg["issuer"])
        state, nonce, binding = random_token(24), random_token(24), random_token(24)
        verifier, challenge = pkce_pair()
        entry = {"nonce": nonce, "verifier": verifier, "return_to": safe_return_to(return_to),
                 "binding": hashlib.sha256(binding.encode()).hexdigest(), "issuer": cfg["issuer"]}
        await self.redis.set(self._state_key(state), json.dumps(entry), ex=STATE_TTL_SECONDS)
        params = {"response_type": "code", "client_id": cfg["client_id"], "redirect_uri": self.settings.oidc_redirect_uri,
                  "scope": " ".join(cfg.get("scopes") or ["openid"]), "state": state, "nonce": nonce,
                  "code_challenge": challenge, "code_challenge_method": "S256"}
        sep = "&" if "?" in disc["authorization_endpoint"] else "?"
        return disc["authorization_endpoint"] + sep + urlencode(params), binding

    async def complete_login(self, *, code: str | None, state: str | None, error: str | None,
                             binding: str | None, source_ip: str) -> tuple[dict[str, Any], str]:
        """Validates the callback and returns (session, return_to). Raises OidcError with a displayable code."""
        await self.auth._throttle(f"oidc-cb:{source_ip}", 60, 300)
        if not state:
            raise OidcError("state_invalid", "missing state")
        # Single use: fetch and delete atomically, so a replayed callback finds nothing.
        raw = await self.redis.getdel(self._state_key(state))
        if not raw:
            raise OidcError("state_invalid", "unknown, expired or replayed state")
        entry = json.loads(raw)
        if not binding or not constant_time_equals(hashlib.sha256(binding.encode()).hexdigest(), entry["binding"]):
            raise OidcError("state_invalid", "state was not issued to this browser")
        if error:
            raise OidcError("idp_error", f"IdP returned error={error[:100]}")
        if not code:
            raise OidcError("idp_error", "missing code")
        cfg = await self._stored()
        if not cfg.get("enabled") or cfg.get("issuer") != entry["issuer"]:
            raise OidcError("sso_disabled", "SSO was disabled or reconfigured during sign-in")
        disc = await self.client.discover(cfg["issuer"])
        secret = (self.encryptor.decrypt(cfg["client_secret_enc"], SECRET_AAD).decode()
                  if cfg.get("client_secret_enc") else None)
        tokens = await self.client.exchange_code(
            disc, client_id=cfg["client_id"], client_secret=secret, auth_method=cfg.get("token_auth_method", ""),
            code=code, verifier=entry["verifier"], redirect_uri=self.settings.oidc_redirect_uri)
        claims = await self.client.validate_id_token(
            disc, tokens["id_token"], client_id=cfg["client_id"], nonce=entry["nonce"],
            algorithms=list(cfg.get("allowed_algorithms") or ["RS256"]))
        groups_claim = cfg.get("groups_claim") or "groups"
        if groups_claim not in claims and isinstance(tokens.get("access_token"), str):
            info = await self.client.userinfo(disc, tokens["access_token"])
            if info.get("sub") == claims["sub"]:  # OIDC Core §5.3.2: userinfo sub must match the ID token
                claims = {**info, **claims}
        user = await self._provision(cfg, claims, source_ip)
        try:
            session = await self.auth.create_session(user, source_ip, method="oidc")
        except GatewayError as exc:
            raise OidcError("no_access", exc.message) from exc
        return session, entry["return_to"]

    # ------------------------------------------------------------------ provisioning
    @staticmethod
    def _groups(claims: dict[str, Any], claim: str) -> set[str]:
        value = claims.get(claim)
        if isinstance(value, str):
            return {value}
        if isinstance(value, list):
            return {str(g) for g in value if isinstance(g, str | int)}
        return set()

    async def _deny(self, reason: str, claims: dict[str, Any], source_ip: str, code: str = "no_access") -> OidcError:
        await self.audit.record(
            SYSTEM_TENANT, "auth.oidc.denied", status="failure",
            principal={"type": "user", "id": None, "name": str(claims.get("sub", ""))[:64]},
            metadata={"source_ip": source_ip, "reason": reason, "issuer": claims.get("iss")},
        )
        return OidcError(code, reason)

    async def _provision(self, cfg: dict[str, Any], claims: dict[str, Any], source_ip: str) -> dict[str, Any]:
        issuer, subject = claims["iss"], claims["sub"]
        groups = self._groups(claims, cfg.get("groups_claim") or "groups")
        desired: dict[str, set[str]] = {}
        for rule in cfg.get("group_rules") or []:
            if rule["group"] in groups:
                desired.setdefault(rule["tenant_id"], set()).update(rule["roles"])
        is_admin = bool(groups & set(cfg.get("platform_admin_groups") or []))

        user = await self.repos.users.col.find_one({"oidc.issuer": issuer, "oidc.subject": subject})
        username = str(claims.get(cfg.get("username_claim") or "preferred_username") or "").strip().lower()[:64]
        email = claims.get(cfg.get("email_claim") or "email")
        email = email.strip().lower()[:254] if isinstance(email, str) and email.strip() else None
        name = claims.get(cfg.get("name_claim") or "name")
        name = name.strip()[:120] if isinstance(name, str) and name.strip() else None

        if user is None:
            if not username:
                raise await self._deny("username claim missing", claims, source_ip)
            existing = await self.repos.users.by_username(username)
            if existing is not None:
                linkable = (cfg.get("link_local_accounts") and existing.get("auth_source") != "oidc"
                            and not existing.get("oidc"))
                if not linkable:
                    raise await self._deny("username belongs to another account", claims, source_ip, "account_conflict")
                await self.repos.users.update(existing["_id"], {"oidc": {"issuer": issuer, "subject": subject}})
                user = await self.repos.users.get(existing["_id"])
                await self.audit.record(SYSTEM_TENANT, "user.oidc.linked", severity="high",
                                        principal={"type": "user", "id": existing["_id"], "name": username},
                                        metadata={"issuer": issuer})
            else:
                if not cfg.get("jit_provisioning", True):
                    raise await self._deny("no account and JIT provisioning is off", claims, source_ip)
                if not desired and not is_admin:
                    raise await self._deny("no group mapping grants access", claims, source_ip)
                doc = {"username": username, "email": email, "display_name": name or username, "status": "active",
                       "is_platform_admin": False, "auth_source": "oidc", "must_change_password": False,
                       "oidc": {"issuer": issuer, "subject": subject}}
                try:
                    user = await self.repos.users.insert(doc)
                except DuplicateKeyError:  # e.g. the email is already used by another account
                    user = await self.repos.users.insert({**doc, "email": None})
                await self.audit.record(SYSTEM_TENANT, "user.oidc.provisioned",
                                        principal={"type": "user", "id": user["_id"], "name": username},
                                        metadata={"issuer": issuer, "groups_matched": sorted(desired)})
        assert user is not None
        if user.get("status") != "active":
            raise await self._deny("account is disabled", claims, source_ip)

        # Profile and platform-admin flag follow the IdP for SSO-only accounts (never demote a local admin).
        updates: dict[str, Any] = {"last_oidc_groups": sorted(groups)[:200]}
        if user.get("auth_source") == "oidc":
            if name:
                updates["display_name"] = name
            if user.get("is_platform_admin") != is_admin:
                updates["is_platform_admin"] = is_admin
                await self.audit.record(SYSTEM_TENANT, "user.platform_admin.changed", severity="high",
                                        principal={"type": "user", "id": user["_id"], "name": user["username"]},
                                        metadata={"is_platform_admin": is_admin, "source": "oidc"})
        elif is_admin and not user.get("is_platform_admin"):
            updates["is_platform_admin"] = True
        await self.repos.users.update(user["_id"], updates)
        await self._sync_memberships(user, desired)
        return await self.repos.users.get(user["_id"]) or user

    async def _sync_memberships(self, user: dict[str, Any], desired: dict[str, set[str]]) -> None:
        existing = [m async for m in self.repos.memberships.col.find({"user_id": user["_id"]})]
        by_tenant = {m["tenant_id"]: m for m in existing}
        actor = {"type": "system", "id": "oidc-sync", "name": "SSO group sync"}
        for tenant_id, roles in desired.items():
            m = by_tenant.get(tenant_id)
            role_list = sorted(roles)
            if m is None:
                await self.repos.memberships.insert(tenant_id, {"user_id": user["_id"], "roles": role_list,
                                                                "status": "active", "managed_by": MANAGED_BY})
                await self.audit.record(tenant_id, "user.membership.created", principal=actor,
                                        resource={"user_id": user["_id"], "username": user["username"]},
                                        metadata={"roles": role_list, "source": "oidc"})
            elif m.get("managed_by") == MANAGED_BY and (m.get("roles") != role_list or m.get("status") != "active"):
                await self.repos.memberships.update(tenant_id, m["_id"], {"roles": role_list, "status": "active"})
                await self.audit.record(tenant_id, "user.membership.changed", principal=actor,
                                        resource={"user_id": user["_id"], "username": user["username"]},
                                        metadata={"roles": role_list, "status": "active", "source": "oidc"})
        for tenant_id, m in by_tenant.items():
            if tenant_id not in desired and m.get("managed_by") == MANAGED_BY and m.get("status") == "active":
                await self.repos.memberships.update(tenant_id, m["_id"], {"status": "disabled"})
                await self.audit.record(tenant_id, "user.membership.changed", principal=actor,
                                        resource={"user_id": user["_id"], "username": user["username"]},
                                        metadata={"status": "disabled", "source": "oidc",
                                                  "reason": "IdP group no longer maps to this tenant"})
