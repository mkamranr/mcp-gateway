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


async def _run(api_port: int, mock_port: int, admin_password: str) -> None:
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
        settings = Settings(
            app_env="development", app_port=api_port, log_level="INFO",
            mongodb_uri=mongod.connection_string, mongodb_database="mcp_gateway_dev",
            redis_url=redis_url or "redis://unused-in-process-fakeredis:6379/0",
            session_secret=secrets.token_urlsafe(48),
            data_encryption_key=base64.urlsafe_b64encode(os.urandom(32)).decode(),
            api_key_hash_pepper=secrets.token_urlsafe(48),
            cookie_secure=False, public_base_url=f"http://localhost:{api_port}",
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
        worker_task = asyncio.create_task(worker.run())
        try:
            await api.serve()
        finally:
            worker.stop()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(worker_task, 5)
            with contextlib.suppress(Exception):
                await container.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api-port", type=int, default=8080)
    parser.add_argument("--mock-port", type=int, default=9100)
    parser.add_argument("--admin-password", default=os.environ.get("DEV_ADMIN_PASSWORD") or "Dev-Admin-" + secrets.token_hex(6))
    ns = parser.parse_args()
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_run(ns.api_port, ns.mock_port, ns.admin_password))


if __name__ == "__main__":
    main()
