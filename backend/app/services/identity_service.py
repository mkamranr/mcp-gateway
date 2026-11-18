"""Tenant, user, agent and credential administration (spec §7.4, §9.4)."""

from __future__ import annotations

import asyncio
import os
import socket
from typing import Any

from app.config import Settings
from app.core.client_certs import CertificateError, describe, load_certificate
from app.core.crypto import generate_api_key, hash_password, random_token
from app.core.errors import ErrorCode, GatewayError, denied, not_found
from app.core.identity import Principal, Role
from app.core.ids import ensure_aware, utcnow
from app.core.lease import Lease
from app.models.identity import (
    AgentCertificateCreate,
    AgentCreate,
    AgentKeyCreate,
    AgentOAuthClientCreate,
    AgentUpdate,
    MembershipUpdate,
    TenantCreate,
    TenantSettings,
    TenantUpdate,
    UserCreate,
    credential_to_api,
)
from app.models.policy import Constraints, Principals, Resources
from app.repositories.collections import Repos
from app.services.agent_oauth import oauth_match
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService

DEFAULT_DENY_POLICY = {
    "name": "default-deny",
    "description": "Fallback decision when no policy allows a request. Cannot be edited or deleted.",
    "effect": "deny",
    "kind": "default_deny",
    # Built from the policy models so the stored document has the same complete shape as API-created ones.
    "principals": Principals(types=["*"], ids=["*"]).model_dump(),
    "resources": Resources(servers=["*"], tools=["*"]).model_dump(),
    "actions": ["discover", "invoke"],
    "constraints": Constraints().model_dump(),
    "priority": 1_000_000,
    "enabled": True,
    "system": True,
}


class IdentityService:
    def __init__(self, settings: Settings, repos: Repos, audit: AuditService, auth: AuthService) -> None:
        self.settings = settings
        self.repos = repos
        self.audit = audit
        self.auth = auth

    # ------------------------------------------------------------------ tenants
    def _require_platform_admin(self, p: Principal) -> None:
        if not p.is_global_admin:
            raise denied("Platform administrator role required.")

    def _require_tenant_access(self, p: Principal, tenant_id: str) -> None:
        if tenant_id != p.tenant_id and not p.is_global_admin:
            raise not_found("Tenant")  # do not disclose existence

    async def create_tenant(self, p: Principal | None, data: TenantCreate) -> dict[str, Any]:
        if p is not None:
            self._require_platform_admin(p)
        tenant = await self.repos.tenants.insert(
            {"name": data.name, "slug": data.slug, "status": "active", "settings": data.settings.model_dump()}
        )
        tid = tenant["_id"]
        await self.repos.policies.insert(tid, {**DEFAULT_DENY_POLICY, "created_by": "system", "updated_by": "system"})
        user = await self.repos.users.by_username(data.admin_username)
        temp_password = None
        if user is None:
            temp_password = data.admin_password or random_token(18)
            user = await self.repos.users.insert({
                "username": data.admin_username.lower(), "email": (data.admin_email or None),
                "display_name": data.admin_username, "password_hash": hash_password(temp_password),
                "status": "active", "is_platform_admin": False,
                "must_change_password": data.admin_password is None,
            })
        await self.repos.memberships.insert(
            tid, {"user_id": user["_id"], "roles": [Role.TENANT_ADMIN.value], "status": "active"}
        )
        await self.audit.record(
            tid, "tenant.created", principal=p, resource={"tenant_id": tid, "tenant_name": data.name},
            metadata={"admin_user_id": user["_id"]},
        )
        result = dict(tenant)
        if temp_password and data.admin_password is None:
            result["initial_admin_password"] = temp_password  # returned once
        return result

    async def list_tenants(self, p: Principal, **kw: Any) -> Any:
        if p.is_global_admin:
            return await self.repos.tenants.list({}, sort=[("name", 1)], **kw)
        tenant = await self.repos.tenants.get(p.tenant_id)
        return {"items": [tenant] if tenant else [], "next_cursor": None, "total": 1 if tenant else 0}

    async def get_tenant(self, p: Principal, tenant_id: str) -> dict[str, Any]:
        self._require_tenant_access(p, tenant_id)
        tenant = await self.repos.tenants.get(tenant_id)
        if not tenant:
            raise not_found("Tenant")
        return tenant

    async def update_tenant(self, p: Principal, tenant_id: str, data: TenantUpdate) -> dict[str, Any]:
        tenant = await self.get_tenant(p, tenant_id)
        changes = data.model_dump(exclude_unset=True)
        if "status" in changes and not p.is_global_admin:
            raise denied("Only platform administrators can suspend or reactivate tenants.")
        if not p.has_any_role(Role.PLATFORM_ADMIN, Role.TENANT_ADMIN):
            raise denied()
        before = dict(tenant.get("settings") or {})
        if data.settings is not None:
            changes["settings"] = data.settings.model_dump()
            new_days = changes["settings"]["audit_retention_days"]
            old_days = int(before.get("audit_retention_days") or TenantSettings().audit_retention_days)
            if new_days < old_days and not p.is_global_admin:
                # A shorter retention makes the worker purge history: a tenant administrator could erase the record
                # of their own actions. Only lengthening it is theirs to decide.
                raise denied("Only platform administrators can shorten audit retention.")
        updated = await self.repos.tenants.update(tenant_id, changes)
        assert updated is not None
        event = "tenant.changed"
        if changes.get("status") and changes["status"] != tenant.get("status"):
            event = "tenant.suspended" if changes["status"] == "suspended" else "tenant.reactivated"
        settings_diff = {k: {"from": before.get(k), "to": v} for k, v in (changes.get("settings") or {}).items()
                         if before.get(k) != v}
        await self.audit.record(tenant_id, event, principal=p, resource={"tenant_id": tenant_id},
                                severity="high" if "audit_retention_days" in settings_diff else None,
                                metadata={"changed_fields": sorted(changes), "settings_changed": settings_diff})
        return updated

    # ------------------------------------------------------------------ users / memberships
    async def list_users(self, p: Principal, tenant_id: str, **kw: Any) -> dict[str, Any]:
        self._require_tenant_access(p, tenant_id)
        page = await self.repos.memberships.list(tenant_id, {}, **kw)
        user_ids = [m["user_id"] for m in page["items"]]
        users = {u["_id"]: u async for u in self.repos.users.col.find({"_id": {"$in": user_ids}})}
        items = []
        for m in page["items"]:
            u = users.get(m["user_id"], {})
            items.append({
                "membership_id": m["_id"], "user_id": m["user_id"], "username": u.get("username"),
                "email": u.get("email"), "display_name": u.get("display_name"), "roles": m.get("roles", []),
                "status": m.get("status"), "user_status": u.get("status"), "last_login_at": u.get("last_login_at"),
                "created_at": m.get("created_at"), "auth_source": u.get("auth_source", "local"),
                "managed_by": m.get("managed_by", "manual"),
                "provisioned_by": "scim" if u.get("scim") else None,
            })
        return {"items": items, "next_cursor": page["next_cursor"], "total": page["total"]}

    async def add_user(self, p: Principal, tenant_id: str, data: UserCreate) -> dict[str, Any]:
        self._require_tenant_access(p, tenant_id)
        user = await self.repos.users.by_username(data.username)
        temp_password = None
        if user is not None and not p.is_global_admin and await self._belongs_elsewhere(user, tenant_id):
            # Accounts are global: a tenant administrator must not pull in (and then manage) another tenant's user
            # or a platform administrator.
            raise denied("This account belongs to another tenant. Ask a platform administrator to add it.")
        if user is None:
            temp_password = data.password or random_token(18)
            user = await self.repos.users.insert({
                "username": data.username.lower(), "email": data.email or None,
                "display_name": data.display_name or data.username, "password_hash": hash_password(temp_password),
                "status": "active", "is_platform_admin": False, "must_change_password": data.password is None,
            })
        existing = await self.repos.memberships.find_one(tenant_id, {"user_id": user["_id"]})
        if existing:
            raise GatewayError(ErrorCode.CONFLICT, "User is already a member of this tenant.")
        m = await self.repos.memberships.insert(tenant_id, {"user_id": user["_id"], "roles": data.roles,
                                                            "status": "active"})
        await self.audit.record(tenant_id, "user.membership.created", principal=p,
                                resource={"user_id": user["_id"], "username": user["username"]},
                                metadata={"roles": data.roles})
        result: dict[str, Any] = {"membership_id": m["_id"], "user_id": user["_id"], "username": user["username"],
                                  "roles": data.roles, "status": "active"}
        if temp_password and data.password is None:
            result["initial_password"] = temp_password
        return result

    async def update_membership(self, p: Principal, tenant_id: str, user_id: str, data: MembershipUpdate) -> dict[str, Any]:
        self._require_tenant_access(p, tenant_id)
        m = await self.repos.memberships.find_one(tenant_id, {"user_id": user_id})
        if not m:
            raise not_found("User")
        if user_id == p.principal_id and (data.status == "disabled" or (
                data.roles is not None and Role.TENANT_ADMIN.value not in data.roles and not p.is_global_admin)):
            raise GatewayError(ErrorCode.CONFLICT, "You cannot remove your own administrator access.")
        changes = data.model_dump(exclude_unset=True, exclude={"display_name"})
        if data.status is not None:
            # Group sync (SSO, LDAP, SCIM) never re-activates a membership an administrator disabled.
            changes["disabled_by_admin"] = data.status == "disabled"
        if data.display_name and not p.is_global_admin:
            user = await self.repos.users.get(user_id)
            if user and await self._belongs_elsewhere(user, tenant_id):
                raise denied("This account also belongs to other tenants. Ask a platform administrator to rename it.")
        updated = await self.repos.memberships.update(tenant_id, m["_id"], changes)
        if data.display_name:
            await self.repos.users.update(user_id, {"display_name": data.display_name})
        if data.status == "disabled" or data.roles is not None:
            await self.auth.revoke_user_sessions(user_id, None if p.is_global_admin else tenant_id)
        await self.audit.record(tenant_id, "user.membership.changed", principal=p, resource={"user_id": user_id},
                                metadata=changes)
        return updated

    async def _belongs_elsewhere(self, user: dict[str, Any], tenant_id: str) -> bool:
        """A platform administrator, or a member (any status) of a tenant other than ``tenant_id``."""
        if user.get("is_platform_admin"):
            return True
        return await self.repos.memberships.col.count_documents(
            {"user_id": user["_id"], "tenant_id": {"$ne": tenant_id}}, limit=1) > 0

    # ------------------------------------------------------------------ agents
    async def create_agent(self, p: Principal, tenant_id: str, data: AgentCreate) -> dict[str, Any]:
        self._require_tenant_access(p, tenant_id)
        agent = await self.repos.agents.insert(tenant_id, {
            **data.model_dump(), "owner_user_id": data.owner_user_id or p.principal_id, "status": "active",
            "created_by": p.principal_id,
        })
        await self.audit.record(tenant_id, "agent.created", principal=p,
                                resource={"agent_id": agent["_id"], "agent_name": agent["name"]})
        return agent

    async def get_agent(self, p: Principal, agent_id: str) -> dict[str, Any]:
        agent = await self.repos.agents.get(p.tenant_id, agent_id)
        if not agent:
            raise not_found("Agent")
        return agent

    async def list_agents(self, p: Principal, tenant_id: str, **kw: Any) -> Any:
        self._require_tenant_access(p, tenant_id)
        return await self.repos.agents.list(tenant_id, {}, sort=[("name", 1)], **kw)

    async def update_agent(self, p: Principal, agent_id: str, data: AgentUpdate) -> dict[str, Any]:
        current = await self.get_agent(p, agent_id)
        if current.get("status") == "revoked":
            raise GatewayError(ErrorCode.CONFLICT, "A revoked agent cannot be modified.")
        changes = data.model_dump(exclude_unset=True, exclude={"version"})
        agent = await self.repos.agents.update(p.tenant_id, agent_id, changes, expected_version=data.version)
        await self.audit.record(p.tenant_id, "agent.changed", principal=p, resource={"agent_id": agent_id},
                                metadata={"changed_fields": sorted(changes)})
        return agent

    async def revoke_agent(self, p: Principal, agent_id: str, reason: str) -> dict[str, Any]:
        await self.get_agent(p, agent_id)
        agent = await self.repos.agents.update(p.tenant_id, agent_id, {"status": "revoked", "revoked_at": utcnow(),
                                                                         "revoked_by": p.principal_id})
        res = await self.repos.credentials.col.update_many(
            {"tenant_id": p.tenant_id, "principal_id": agent_id, "revoked_at": None},
            {"$set": {"revoked_at": utcnow(), "revoked_by": p.principal_id, "revoke_reason": "agent revoked"}},
        )
        await self.audit.record(p.tenant_id, "agent.revoked", principal=p, resource={"agent_id": agent_id},
                                metadata={"reason": reason, "credentials_revoked": res.modified_count})
        return agent

    # ------------------------------------------------------------------ credentials
    async def create_key(self, p: Principal, data: AgentKeyCreate, rotated_from: str | None = None) -> dict[str, Any]:
        agent = await self.get_agent(p, data.agent_id)
        if agent.get("status") != "active":
            raise GatewayError(ErrorCode.CONFLICT, "Credentials can only be issued to active agents.")
        expires = ensure_aware(data.expires_at)
        if expires and expires <= utcnow():
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "Expiry must be in the future.")
        env = "test" if agent.get("environment") in ("development", "test") else "live"
        key = generate_api_key(self.settings.api_key_hash_pepper, env=env)
        cred = await self.repos.credentials.insert(p.tenant_id, {
            "name": data.name, "principal_type": "agent", "principal_id": agent["_id"],
            "key_prefix": key.key_prefix, "secret_hash": key.secret_hash, "scopes": list(data.scopes),
            "expires_at": expires, "revoked_at": None, "last_used_at": None, "created_by": p.principal_id,
            "rotated_from": rotated_from,
        })
        await self.audit.record(
            p.tenant_id, "credential.rotated" if rotated_from else "credential.created", principal=p,
            resource={"agent_id": agent["_id"], "credential_id": cred["_id"], "key_prefix": key.key_prefix},
        )
        return {**credential_to_api(cred), "secret": key.secret}  # the only time the secret is returned

    async def create_certificate(self, p: Principal, data: AgentCertificateCreate) -> dict[str, Any]:
        """Register a client certificate credential (docs/mtls.md). Nothing secret is stored: the private key
        never leaves the agent, and the TLS proxy checks that the agent holds it."""
        verifier = self.auth.cert_verifier
        if verifier is None:
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "Client certificate authentication isn't enabled on this "
                                                            "gateway (MTLS_CLIENT_CA_FILE).")
        agent = await self.get_agent(p, data.agent_id)
        if agent.get("status") != "active":
            raise GatewayError(ErrorCode.CONFLICT, "Credentials can only be issued to active agents.")
        expires = ensure_aware(data.expires_at)
        if expires and expires <= utcnow():
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "Expiry must be in the future.")
        info = None
        if data.certificate_pem:
            try:
                info = verifier.verify(load_certificate(data.certificate_pem))
            except CertificateError as exc:
                raise GatewayError(ErrorCode.VALIDATION_FAILED, str(exc)) from None
            match = f"fp:{info.fingerprint_sha256}"
            expires = min(expires, info.not_after) if expires else info.not_after
        else:
            match = f"san:{data.subject_name}"
        if await self.repos.credentials.by_cert_match_global([match]):
            raise GatewayError(ErrorCode.CONFLICT, "An active credential already uses this certificate or subject "
                                                   "name.")
        cred = await self.repos.credentials.insert(p.tenant_id, {
            "type": "client_certificate", "name": data.name, "principal_type": "agent", "principal_id": agent["_id"],
            "cert_match": match, "subject_name": data.subject_name,
            "certificate": info.to_api() if info else None,
            "scopes": list(data.scopes), "expires_at": expires, "revoked_at": None, "last_used_at": None,
            "created_by": p.principal_id,
        })
        await self.audit.record(p.tenant_id, "credential.created", principal=p, resource={
            "agent_id": agent["_id"], "credential_id": cred["_id"], "credential_type": "client_certificate"},
            metadata={"match": "fingerprint" if info else "subject_name",
                      "fingerprint_sha256": info.fingerprint_sha256 if info else None,
                      "subject_name": data.subject_name})
        return credential_to_api(cred)

    async def create_oauth_client(self, p: Principal, data: AgentOAuthClientCreate) -> dict[str, Any]:
        """Register an OAuth credential (docs/agent-oauth.md). Nothing secret is stored: the agent authenticates to
        its IdP, and the gateway verifies the IdP's signature on each access token."""
        oauth = self.auth.agent_oauth
        cfg: dict[str, Any] = await oauth.config(fresh=True) if oauth is not None else {"enabled": False, "issuers": []}
        entry = next((i for i in cfg["issuers"] if i["issuer"] == data.issuer), None)
        if entry is None:
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "That issuer isn't trusted for agent tokens. A platform "
                                                            "administrator adds issuers under Settings.")
        agent = await self.get_agent(p, data.agent_id)
        if agent.get("status") != "active":
            raise GatewayError(ErrorCode.CONFLICT, "Credentials can only be issued to active agents.")
        expires = ensure_aware(data.expires_at)
        if expires and expires <= utcnow():
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "Expiry must be in the future.")
        match = oauth_match(data.issuer, data.subject)
        if await self.repos.credentials.by_oauth_match_global(match):
            raise GatewayError(ErrorCode.CONFLICT, "An active credential already uses this client.")
        cred = await self.repos.credentials.insert(p.tenant_id, {
            "type": "oauth_client", "name": data.name, "principal_type": "agent", "principal_id": agent["_id"],
            "oauth_match": match, "oauth": {"issuer": data.issuer, "subject": data.subject,
                                            "subject_claim": entry["subject_claim"]},
            "scopes": list(data.scopes), "expires_at": expires, "revoked_at": None, "last_used_at": None,
            "created_by": p.principal_id,
        })
        await self.audit.record(p.tenant_id, "credential.created", principal=p, resource={
            "agent_id": agent["_id"], "credential_id": cred["_id"], "credential_type": "oauth_client"},
            metadata={"issuer": data.issuer, "subject": data.subject})
        return credential_to_api(cred)

    def certificate_status(self) -> dict[str, Any]:
        """Whether agents can use client certificates here, and which CAs may issue them (public information)."""
        verifier = self.auth.cert_verifier
        return {"enabled": verifier is not None,
                "trusted_cas": [describe(ca).to_api() for ca in verifier.cas] if verifier else []}

    async def list_keys(self, p: Principal, agent_id: str | None = None, **kw: Any) -> Any:
        q: dict[str, Any] = {"principal_type": "agent"}
        if agent_id:
            q["principal_id"] = agent_id
        return await self.repos.credentials.list(p.tenant_id, q, **kw)

    async def rotate_key(self, p: Principal, cred_id: str) -> dict[str, Any]:
        cred = await self.repos.credentials.get(p.tenant_id, cred_id)
        if not cred or cred.get("revoked_at"):
            raise not_found("Credential")
        if cred.get("type") == "oauth_client":
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "OAuth credentials have no secret here to rotate. Rotate "
                               "the client secret or key at your identity provider.")
        if cred.get("type") == "client_certificate":
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "Certificate credentials aren't rotated here. Match by "
                               "subject name to renew certificates freely, or add the new certificate and revoke "
                               "the old one.")
        new = await self.create_key(
            p, AgentKeyCreate(agent_id=cred["principal_id"], name=cred.get("name", "default"),
                              scopes=cred.get("scopes", []), expires_at=cred.get("expires_at")),
            rotated_from=cred_id,
        )
        await self.repos.credentials.update(p.tenant_id, cred_id, {
            "revoked_at": utcnow(), "revoked_by": p.principal_id, "revoke_reason": "rotated", "rotated_to": new["id"],
        })
        return new

    async def revoke_key(self, p: Principal, cred_id: str, reason: str) -> dict[str, Any]:
        cred = await self.repos.credentials.get(p.tenant_id, cred_id)
        if not cred:
            raise not_found("Credential")
        if cred.get("revoked_at"):
            return cred
        updated = await self.repos.credentials.update(p.tenant_id, cred_id, {
            "revoked_at": utcnow(), "revoked_by": p.principal_id, "revoke_reason": reason or "revoked",
        })
        await self.audit.record(p.tenant_id, "credential.revoked", principal=p,
                                resource={"credential_id": cred_id, "agent_id": cred["principal_id"]},
                                metadata={"reason": reason})
        return updated

    async def emergency_revoke_all(self, p: Principal, reason: str) -> int:
        """Tenant-wide emergency revocation of every agent credential (spec §7.4)."""
        if not p.has_any_role(Role.PLATFORM_ADMIN, Role.TENANT_ADMIN, Role.SECURITY_ADMIN):
            raise denied()
        res = await self.repos.credentials.col.update_many(
            {"tenant_id": p.tenant_id, "revoked_at": None},
            {"$set": {"revoked_at": utcnow(), "revoked_by": p.principal_id, "revoke_reason": f"emergency: {reason}"}},
        )
        await self.audit.record(p.tenant_id, "emergency.action", principal=p, severity="critical",
                                metadata={"action": "revoke_all_credentials", "count": res.modified_count,
                                          "reason": reason})
        return int(res.modified_count)

    # ------------------------------------------------------------------ bootstrap
    async def bootstrap(self, wait_seconds: float = 60) -> None:
        """Create the bootstrap platform administrator and default tenant if none exist.

        Several API replicas start at once: a Redis lease lets one of them bootstrap while the others wait, then
        find the administrator already there (instead of failing on a duplicate key and restarting)."""
        s = self.settings
        if not s.bootstrap_admin_username or not s.bootstrap_admin_password:
            return
        if await self.repos.users.find_one({"is_platform_admin": True}):
            return
        owner = f"{socket.gethostname()}-{os.getpid()}-{random_token(6)}"  # unique per attempt, not per process
        lease = Lease(self.auth.redis, "lease:bootstrap", owner, 60)
        for _ in range(int(wait_seconds / 0.25)):
            if await lease.acquire():
                break
            await asyncio.sleep(0.25)
        else:
            raise GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE, "Another replica is still bootstrapping.")
        try:
            await self._bootstrap()
        finally:
            await lease.release()

    async def _bootstrap(self) -> None:
        s = self.settings
        if await self.repos.users.find_one({"is_platform_admin": True}):
            return
        tenant = await self.repos.tenants.find_one({"slug": s.bootstrap_tenant_slug})
        if tenant is None:
            tenant = await self.repos.tenants.insert({
                "name": s.bootstrap_tenant_slug.replace("-", " ").title(), "slug": s.bootstrap_tenant_slug,
                "status": "active", "settings": {"audit_retention_days": s.audit_retention_days,
                                                 "default_environment": "production",
                                                 "quotas": {"per_minute": 600, "per_day": 100_000},
                                                 "critical_requires_approval": True},
            })
            await self.repos.policies.insert(tenant["_id"], {**DEFAULT_DENY_POLICY, "created_by": "system",
                                                             "updated_by": "system"})
        user = await self.repos.users.insert({
            "username": s.bootstrap_admin_username.lower(), "email": None, "display_name": s.bootstrap_admin_username,
            "password_hash": hash_password(s.bootstrap_admin_password), "status": "active", "is_platform_admin": True,
        })
        await self.repos.memberships.insert(tenant["_id"], {"user_id": user["_id"], "roles": [
            Role.TENANT_ADMIN.value, Role.SECURITY_ADMIN.value, Role.APPROVER.value], "status": "active"})
        await self.audit.record(tenant["_id"], "system.bootstrap", principal={"type": "service", "id": "bootstrap"},
                                severity="high", metadata={"admin_user_id": user["_id"]})
