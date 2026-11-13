"""Test fixtures.

* MongoDB: a real ``mongod`` started once per session by pymongo-inmemory, or an existing
  server if ``TEST_MONGODB_URI`` is set. Each test gets its own database.
* Redis: fakeredis with Lua support, a fresh instance per test, or ``TEST_REDIS_URL``.
* Upstream: the mock MCP server served by uvicorn on a random localhost port.
"""

from __future__ import annotations

import base64
import os
import socket
import threading
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx
import pytest
import uvicorn

from app.config import Settings
from app.container import Container
from app.db import Database
from app.main import create_app
from devtools import mock_mcp_server

ADMIN_USER = "admin"
ADMIN_PASSWORD = "Sup3r-Secret-Admin-Pass!"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="session")
def mongo_uri() -> Iterator[str]:
    if os.environ.get("TEST_MONGODB_URI"):
        yield os.environ["TEST_MONGODB_URI"]
        return
    from pymongo_inmemory.context import Context
    from pymongo_inmemory.mongod import Mongod

    ctx = Context()
    ctx.mongod_port = _free_port()
    with Mongod(ctx) as m:
        yield m.connection_string


@pytest.fixture(scope="session")
def upstream_url() -> Iterator[str]:
    port = _free_port()
    config = uvicorn.Config(mock_mcp_server.build_http_app(), host="127.0.0.1", port=port, log_level="error",
                            lifespan="on")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="session")
def db_name() -> str:
    return f"mgw_test_{uuid.uuid4().hex[:10]}"


@pytest.fixture
def settings(mongo_uri: str, db_name: str) -> Settings:
    return Settings(
        app_env="test",
        mongodb_uri=mongo_uri,
        mongodb_database=db_name,
        redis_url="redis://unused",
        session_secret="s" * 40,
        data_encryption_key=base64.urlsafe_b64encode(os.urandom(32)).decode(),
        api_key_hash_pepper="p" * 40,
        cookie_secure=False,
        allow_private_upstream_networks=True,
        bootstrap_admin_username=ADMIN_USER,
        bootstrap_admin_password=ADMIN_PASSWORD,
        bootstrap_tenant_slug="acme",
        login_max_attempts_per_window=50,
    )


@pytest.fixture
async def container(settings: Settings) -> AsyncIterator[Container]:
    if os.environ.get("TEST_REDIS_URL"):
        from redis.asyncio import Redis

        redis = Redis.from_url(os.environ["TEST_REDIS_URL"], decode_responses=True)
        await redis.flushdb()
    else:
        import fakeredis

        redis = fakeredis.FakeAsyncRedis(decode_responses=True)
    db = Database(settings)
    c = Container(settings, db=db, redis=redis)
    yield c
    # One database per session (creating indexed collections is slow); empty it between tests.
    for name in await db.db.list_collection_names():
        await db.db[name].delete_many({})
    await c.close()


@pytest.fixture(autouse=True)
def reset_upstream() -> None:
    mock_mcp_server.CALLS.clear()
    mock_mcp_server.STATE.update({"schema_variant": 0, "expected_token": None, "last_auth": None})


@pytest.fixture
async def app(settings: Settings, container: Container) -> AsyncIterator[Any]:
    import asyncio

    application = create_app(settings, container)
    started, stop = asyncio.Event(), asyncio.Event()

    async def run_lifespan() -> None:
        # anyio task groups must be exited by the task that entered them.
        async with application.router.lifespan_context(application):
            started.set()
            await stop.wait()

    task = asyncio.create_task(run_lifespan())
    await asyncio.wait_for(started.wait(), 30)
    yield application
    stop.set()
    await task


class ApiClient:
    """Thin wrapper that keeps the session cookie and CSRF header."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.http = client
        self.csrf: str | None = None

    async def login(self, username: str = ADMIN_USER, password: str = ADMIN_PASSWORD) -> dict[str, Any]:
        r = await self.http.post("/api/v1/auth/login", json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        self.csrf = r.json()["csrf_token"]
        return r.json()  # type: ignore[no-any-return]

    def _h(self, headers: dict[str, str] | None) -> dict[str, str]:
        h = dict(headers or {})
        if self.csrf:
            h.setdefault("X-CSRF-Token", self.csrf)
        return h

    async def get(self, url: str, **kw: Any) -> httpx.Response:
        return await self.http.get(url, **kw)

    async def post(self, url: str, json: Any = None, headers: dict[str, str] | None = None) -> httpx.Response:
        return await self.http.post(url, json=json, headers=self._h(headers))

    async def patch(self, url: str, json: Any = None, headers: dict[str, str] | None = None) -> httpx.Response:
        return await self.http.patch(url, json=json, headers=self._h(headers))

    async def delete(self, url: str, headers: dict[str, str] | None = None) -> httpx.Response:
        return await self.http.delete(url, headers=self._h(headers))


def make_client(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


@pytest.fixture
async def admin(app: Any) -> AsyncIterator[ApiClient]:
    async with make_client(app) as http:
        client = ApiClient(http)
        await client.login()
        yield client


@pytest.fixture
async def anon(app: Any) -> AsyncIterator[ApiClient]:
    async with make_client(app) as http:
        yield ApiClient(http)


# ---------------------------------------------------------------- scenario helpers
class Scenario:
    """Builds a tenant with a registered mock server, enabled tools, an agent and a key."""

    def __init__(self, admin: ApiClient, app: Any, upstream_url: str) -> None:
        self.admin = admin
        self.app = app
        self.upstream_url = upstream_url
        self.tenant_id: str = ""
        self.server: dict[str, Any] = {}
        self.tools: dict[str, dict[str, Any]] = {}
        self.agent: dict[str, Any] = {}
        self.key: str = ""

    async def setup(self, *, enable: dict[str, str] | None = None, alias: str = "hr") -> Scenario:
        me = (await self.admin.get("/api/v1/auth/me")).json()
        self.tenant_id = me["tenant_id"]
        r = await self.admin.post("/api/v1/servers", json={
            "name": f"HR {alias}", "alias": alias, "transport": "streamable_http", "endpoint": self.upstream_url,
            "environment": "production", "allow_private_network": True})
        assert r.status_code == 201, r.text
        self.server = r.json()
        r = await self.admin.post(f"/api/v1/servers/{self.server['id']}/refresh-tools")
        assert r.status_code == 200, r.text
        tools = (await self.admin.get(f"/api/v1/servers/{self.server['id']}/tools")).json()["items"]
        self.tools = {t["upstream_name"]: t for t in tools}
        for name, risk in (enable if enable is not None else {"get_attendance_summary": "low"}).items():
            await self.enable_tool(name, risk)
        r = await self.admin.post(f"/api/v1/tenants/{self.tenant_id}/agents", json={"name": f"agent-{alias}"})
        assert r.status_code == 201, r.text
        self.agent = r.json()
        r = await self.admin.post("/api/v1/auth/agent-keys", json={"agent_id": self.agent["id"]})
        assert r.status_code == 201, r.text
        self.key = r.json()["secret"]
        return self

    async def enable_tool(self, name: str, risk: str, **extra: Any) -> dict[str, Any]:
        t = (await self.admin.get(f"/api/v1/tools/{self.tools[name]['id']}")).json()
        r = await self.admin.patch(f"/api/v1/tools/{t['id']}", json={"version": t["version"], "risk_level": risk,
                                                                     "enabled": True, **extra})
        assert r.status_code == 200, r.text
        self.tools[name] = r.json()
        return r.json()

    async def allow(self, tools: list[str], *, require_approval: bool = False, name: str | None = None,
                    **constraints: Any) -> dict[str, Any]:
        r = await self.admin.post("/api/v1/policies", json={
            "name": name or f"allow-{uuid.uuid4().hex[:6]}", "effect": "allow",
            "principals": {"types": ["agent"], "ids": [self.agent["id"]]},
            "resources": {"servers": [self.server["alias"]], "tools": tools},
            "actions": ["discover", "invoke"],
            "constraints": {"require_approval": require_approval, **constraints}})
        assert r.status_code == 201, r.text
        return r.json()  # type: ignore[no-any-return]

    def agent_headers(self, key: str | None = None) -> dict[str, str]:
        return {"Authorization": f"Bearer {key or self.key}"}

    async def invoke(self, tool: str, arguments: dict[str, Any], key: str | None = None) -> httpx.Response:
        async with make_client(self.app) as http:
            return await http.post(f"/api/v1/gateway/tools/{self.server['alias']}__{tool}/invoke",
                                   json={"arguments": arguments}, headers=self.agent_headers(key))


@pytest.fixture
async def scenario(admin: ApiClient, app: Any, upstream_url: str) -> Scenario:
    return Scenario(admin, app, upstream_url)


async def new_user_client(app: Any, admin: ApiClient, tenant_id: str, roles: list[str],
                          username: str | None = None) -> ApiClient:
    """Create a tenant member with ``roles`` and return a logged-in client (caller closes .http)."""
    username = username or f"user{uuid.uuid4().hex[:6]}"
    password = "Another-Strong-Pass-123"
    r = await admin.post(f"/api/v1/tenants/{tenant_id}/users",
                         json={"username": username, "password": password, "roles": roles})
    assert r.status_code == 201, r.text
    client = ApiClient(make_client(app))
    await client.login(username, password)
    return client


async def run_worker_once(container: Container) -> int:
    from app.workers.main import Worker

    w = Worker(container)
    await w.ensure_group()
    return await w.process_jobs_once(block_ms=10)
