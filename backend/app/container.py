"""Wires settings, connections, repositories and services. Shared by the API and the worker."""

from __future__ import annotations

from redis.asyncio import Redis

from app.config import Settings
from app.core.crypto import Encryptor
from app.db import Database, create_redis
from app.mcp.client_manager import ClientManager
from app.repositories.collections import Repos
from app.services.approval_service import ApprovalService
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService
from app.services.identity_service import IdentityService
from app.services.invocation_service import InvocationService
from app.services.policy_bundle_service import PolicyBundleService
from app.services.policy_service import PolicyService
from app.services.quota_service import QuotaService
from app.services.registry_service import RegistryService
from app.services.siem_service import SiemService
from app.services.sso_service import SsoService
from app.services.usage_service import UsageService
from app.services.validation_service import ValidationService


class Container:
    def __init__(self, settings: Settings, db: Database | None = None, redis: Redis | None = None) -> None:
        self.settings = settings
        self.db = db or Database(settings)
        self.redis = redis or create_redis(settings)
        self.repos = Repos(self.db)
        self.encryptor = Encryptor(settings.encryption_key_bytes())
        self.audit = AuditService(self.repos)
        self.clients = ClientManager(settings, self.repos, self.encryptor, self.redis)
        self.auth = AuthService(settings, self.repos, self.redis, self.audit)
        self.identity = IdentityService(settings, self.repos, self.audit, self.auth)
        self.sso = SsoService(settings, self.repos, self.redis, self.encryptor, self.audit, self.auth)
        self.siem = SiemService(settings, self.repos, self.redis, self.encryptor, self.audit)
        self.registry = RegistryService(settings, self.repos, self.encryptor, self.audit, self.clients)
        self.policy = PolicyService(self.repos, self.audit)
        self.policy_bundles = PolicyBundleService(self.repos, self.audit)
        self.validation = ValidationService(settings)
        self.quotas = QuotaService(settings, self.redis)
        self.approvals = ApprovalService(settings, self.repos, self.redis, self.encryptor, self.audit)
        self.invocations = InvocationService(
            settings, self.repos, self.encryptor, self.audit, self.auth, self.policy, self.validation,
            self.quotas, self.approvals, self.clients,
        )
        self.usage = UsageService(self.repos)

    async def close(self) -> None:
        await self.db.close()
        try:
            await self.redis.aclose()
        except Exception:  # noqa: BLE001,S110
            pass
