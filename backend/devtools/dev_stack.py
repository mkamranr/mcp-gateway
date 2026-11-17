"""Local development stack without Docker. DEVELOPMENT ONLY.

Starts, in one process:
  * a real ``mongod`` (downloaded once by pymongo-inmemory) on a free port,
  * an in-process fakeredis (Lua enabled) shared by the API and the worker,
    or a real Redis when ``DEV_REDIS_URL`` is set,
  * the mock upstream MCP server on :9100 (``/mcp``),
  * the gateway API + MCP endpoint on :8080,
  * the background worker (approved-call execution, expiry, health checks).

Secrets are generated randomly per run and data is not persisted.
Run the UI separately with ``npm run dev`` in ``frontend/`` (it proxies /api and /mcp to :8080).

    uv run python -m devtools.dev_stack [--api-port 8080] [--mock-port 9100]
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import os
import secrets
import socket
import threading
import time
from typing import Any

import uvicorn


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _port_available(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


def _start_thread_server(app: object, port: int) -> uvicorn.Server:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on"))  # type: ignore[arg-type]
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    return server


def _non_blocking_worker_class() -> type:
    from app.workers.main import Worker

    class NonBlockingWorker(Worker):
        """In-process fakeredis implements blocking XREADGROUP synchronously, which would stall the shared
        event loop. Poll without blocking instead (real Redis deployments use the normal Worker)."""

        async def process_jobs_once(self, block_ms: int = 1000) -> int:
            n = await super().process_jobs_once(block_ms=None)  # type: ignore[arg-type]
            if not n:
                await asyncio.sleep(block_ms / 1000)
            return n

    return NonBlockingWorker


async def _run(api_port: int, mock_port: int, admin_password: str, oidc_port: int | None = None,
               public_base_url: str | None = None, vault_port: int | None = None) -> None:
    import fakeredis
    from pymongo_inmemory.context import Context
    from pymongo_inmemory.mongod import Mongod

    from app.config import Settings
    from app.container import Container
    from app.core.logging import configure_logging
    from app.main import create_app
    from app.migrations.indexes import ensure_indexes
    from app.workers.main import Worker
    from devtools import mock_mcp_server

    _NonBlockingWorker = _non_blocking_worker_class()  # noqa: N806

    redis_url = os.environ.get("DEV_REDIS_URL", "")
    if not _port_available(mock_port):
        fallback = _free_port()
        print(f"  Port {mock_port} is in use; serving the mock upstream on {fallback} instead.")
        mock_port = fallback
    ctx = Context()
    ctx.mongod_port = _free_port()
    with Mongod(ctx) as mongod:
        _start_thread_server(mock_mcp_server.build_http_app(), mock_port)
        idp = None
        if oidc_port is not None:
            from devtools import mock_oidc

            if not _port_available(oidc_port):
                oidc_port = _free_port()
            idp = mock_oidc.MockIdP(issuer=f"http://127.0.0.1:{oidc_port}")
            _start_thread_server(mock_oidc.build_app(idp), oidc_port)
        session_secret = secrets.token_urlsafe(48)
        data_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        pepper = secrets.token_urlsafe(48)
        if vault_port is not None:
            # Keys protected by a (mock) Vault Transit, exactly as in production (docs/key-management.md).
            from app.core import kms
            from devtools import mock_vault

            if not _port_available(vault_port):
                vault_port = _free_port()
            vault = mock_vault.MockVault()
            _start_thread_server(mock_vault.build_app(vault), vault_port)
            os.environ.update({"KMS_PROVIDER": "vault", "VAULT_ADDR": f"http://127.0.0.1:{vault_port}",
                               "VAULT_TRANSIT_KEY": vault.key_name, "VAULT_TOKEN": vault.root_token,
                               "KMS_ALLOW_INSECURE_HTTP": "true", "APP_ENV": "development"})
            provider = kms.provider_for(kms.KmsConfig.from_env())
            session_secret, data_key, pepper = (kms.wrap(provider, v) for v in (session_secret, data_key, pepper))
        settings = Settings(
            app_env="development", app_port=api_port, log_level="INFO",
            mongodb_uri=mongod.connection_string, mongodb_database="mcp_gateway_dev",
            redis_url=redis_url or "redis://unused-in-process-fakeredis:6379/0",
            session_secret=session_secret, data_encryption_key=data_key, api_key_hash_pepper=pepper,
            cookie_secure=False, public_base_url=public_base_url or f"http://localhost:{api_port}",
            oidc_allow_insecure_http=True,
            allow_private_upstream_networks=True,
            stdio_executable_allowlist=[],
            bootstrap_admin_username="admin", bootstrap_admin_password=admin_password,
            bootstrap_tenant_slug="acme", worker_poll_interval_seconds=1.0, health_check_interval_seconds=30,
        )
        configure_logging(settings.log_level, json_output=False)
        # One container shared by API and worker so both see the same (in-process) Redis.
        redis = None if redis_url else fakeredis.FakeAsyncRedis(decode_responses=True)
        container = Container(settings, redis=redis)
        await ensure_indexes(container.db)
        app = create_app(settings, container)
        worker = (Worker if redis_url else _NonBlockingWorker)(container)
        api = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=api_port, log_level="warning", lifespan="on"))

        print("\n  MCP-Gateway dev stack (DEVELOPMENT ONLY, data is not persisted)")
        print(f"  API + MCP     http://127.0.0.1:{api_port}  (MCP at /mcp)")
        print(f"  Mock upstream http://127.0.0.1:{mock_port}/mcp")
        print(f"  Admin login   admin / {admin_password}")
        print("  UI            cd frontend && npm run dev  ->  http://localhost:5173\n")
        if idp is not None:
            print(f"  Mock IdP      {idp.issuer}  (users: {', '.join(idp.users)}; SSO pre-configured)")
            print(f"  SSO callback  {settings.oidc_redirect_uri}\n")
        worker_task = asyncio.create_task(worker.run())
        seed_task = asyncio.create_task(_seed_sso(api, container, idp)) if idp is not None else None
        try:
            await api.serve()
        finally:
            worker.stop()
            if seed_task is not None:
                seed_task.cancel()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(worker_task, 5)
            with contextlib.suppress(Exception):
                await container.close()


async def _seed_sso(api: uvicorn.Server, container: object, idp: object) -> None:
    """Once the API has bootstrapped the 'acme' tenant, point SSO at the mock IdP with demo group rules."""
    from app.services.sso_service import CONFIG_KEY, SECRET_AAD

    while not api.started:  # noqa: ASYNC110 (uvicorn exposes no event to await)
        await asyncio.sleep(0.2)
    c: Any = container
    tenant = await c.repos.tenants.col.find_one({"slug": "acme"})
    if tenant is None:
        return
    tid = tenant["_id"]
    await c.repos.settings.set_value(CONFIG_KEY, {
        "enabled": True, "display_name": "Mock IdP", "issuer": idp.issuer, "client_id": idp.client_id,  # type: ignore[attr-defined]
        "client_secret_enc": c.encryptor.encrypt(idp.client_secret.encode(), SECRET_AAD),  # type: ignore[attr-defined]
        "token_auth_method": "client_secret_basic", "scopes": ["email", "openid", "profile"],
        "allowed_algorithms": ["RS256"], "username_claim": "preferred_username", "email_claim": "email",
        "name_claim": "name", "groups_claim": "groups",
        "group_rules": [
            {"group": "mgw-acme-admins", "tenant_id": tid, "roles": ["tenant_admin"]},
            {"group": "mgw-acme-developers", "tenant_id": tid, "roles": ["developer"]},
            {"group": "mgw-auditors", "tenant_id": tid, "roles": ["auditor"]},
        ],
        "platform_admin_groups": ["mgw-platform-admins"], "jit_provisioning": True, "link_local_accounts": False,
        "local_login": "enabled", "break_glass_usernames": [],
    }, "dev-stack")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api-port", type=int, default=8080)
    parser.add_argument("--mock-port", type=int, default=9100)
    parser.add_argument("--admin-password", default=os.environ.get("DEV_ADMIN_PASSWORD") or "Dev-Admin-" + secrets.token_hex(6))
    parser.add_argument("--with-oidc", nargs="?", type=int, const=9400, default=None, metavar="PORT",
                        help="also run the mock OIDC provider (default port 9400) and pre-configure SSO")
    parser.add_argument("--public-base-url", default=None,
                        help="URL the browser uses (default: http://localhost:5173 with --with-oidc, so the "
                             "IdP redirects back through the Vite dev server)")
    parser.add_argument("--with-vault", nargs="?", type=int, const=9500, default=None, metavar="PORT",
                        help="also run a mock Vault Transit (default port 9500) and wrap the keys with it")
    ns = parser.parse_args()
    base = ns.public_base_url or ("http://localhost:5173" if ns.with_oidc is not None else None)
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_run(ns.api_port, ns.mock_port, ns.admin_password, ns.with_oidc, base, ns.with_vault))


if __name__ == "__main__":
    main()
