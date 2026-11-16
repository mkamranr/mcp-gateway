"""Behaviour with several API replicas and workers sharing one MongoDB and Redis.

A "replica" here is a second Container on the same database and Redis, which is exactly what a second
gateway-api or worker process is.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from app.container import Container
from app.core.lease import Lease
from app.mcp.adapters.base import UpstreamError
from app.migrations.indexes import ensure_indexes
from app.workers.heartbeat import HEARTBEAT_KEY
from app.workers.main import Worker


@pytest.fixture
def replica(container: Container) -> Container:
    """A second process: own services, same MongoDB and Redis (not closed separately)."""
    return Container(container.settings, db=container.db, redis=container.redis)


def _server(max_calls: int = 2, timeout: float = 0.3) -> dict[str, Any]:
    return {"_id": "srv_test", "tenant_id": "ten_x", "max_concurrent_calls": max_calls,
            "request_timeout_seconds": timeout, "connection_timeout_seconds": 1}


class _NullAdapter:
    async def connect(self, config: Any) -> None:
        return None

    async def close(self) -> None:
        return None


def _no_upstream(c: Container) -> None:
    async def config(server: dict[str, Any]) -> Any:
        return None
    c.clients.build_config = config  # type: ignore[method-assign]
    c.clients.adapter_factory = lambda server: _NullAdapter()  # type: ignore[assignment,return-value]


# ---------------------------------------------------------------- per-server concurrency cap
async def test_server_concurrency_cap_is_shared_by_all_replicas(container, replica):
    srv = _server(max_calls=2)
    for c in (container, replica):
        _no_upstream(c)
    hold = asyncio.Event()
    entered: list[str] = []

    async def call(c: Container, label: str) -> None:
        async with c.clients.limited_session(srv):
            entered.append(label)
            await hold.wait()

    a = asyncio.create_task(call(container, "a1"))
    b = asyncio.create_task(call(replica, "b1"))
    await asyncio.sleep(0.1)
    assert sorted(entered) == ["a1", "b1"]
    assert await container.clients.in_flight(srv) == 2
    # the cap is reached across replicas: a third call on either replica waits, then gives up
    for c in (container, replica):
        with pytest.raises(UpstreamError):
            async with c.clients.limited_session(srv):
                pass
    hold.set()
    await asyncio.gather(a, b)
    assert await container.clients.in_flight(srv) == 0
    async with replica.clients.limited_session(srv):  # free again
        assert await container.clients.in_flight(srv) == 1


async def test_slot_is_released_when_the_call_fails(container):
    srv = _server(max_calls=1)
    _no_upstream(container)
    with pytest.raises(RuntimeError):
        async with container.clients.limited_session(srv):
            raise RuntimeError("tool blew up")
    async with container.clients.limited_session(srv):
        pass


async def test_slot_of_a_crashed_replica_is_reclaimed(container):
    srv = _server(max_calls=1)
    _no_upstream(container)
    # a replica died holding the only slot; its hold expired a moment ago
    key = container.clients.semaphore_key(srv)
    await container.redis.zadd(key, {"dead-replica-token": time.time() * 1000 - 1})
    async with container.clients.limited_session(srv):
        assert await container.clients.in_flight(srv) == 1


async def test_waiting_call_gets_the_slot_when_it_frees(container, replica):
    srv = _server(max_calls=1, timeout=3)
    for c in (container, replica):
        _no_upstream(c)
    release = asyncio.Event()

    async def holder() -> None:
        async with container.clients.limited_session(srv):
            await release.wait()

    t = asyncio.create_task(holder())
    await asyncio.sleep(0.05)
    asyncio.get_running_loop().call_later(0.3, release.set)
    started = time.monotonic()
    async with replica.clients.limited_session(srv):
        waited = time.monotonic() - started
    await t
    assert 0.2 < waited < 2.5


# ---------------------------------------------------------------- leases
async def test_lease_is_exclusive_and_owner_checked(container):
    a = Lease(container.redis, "lease:t", "worker-a", 30)
    b = Lease(container.redis, "lease:t", "worker-b", 30)
    assert await a.acquire() and not await b.acquire()
    assert await a.acquire()  # re-acquire by the holder refreshes it
    await b.release()  # not the holder: no effect
    assert await a.holder() == "worker-a"
    await container.redis.pexpire("lease:t", 1)  # worker-a stalls past its lease
    await asyncio.sleep(0.05)
    assert await b.acquire()
    assert not await a.renew()  # a learns it lost the lease
    await a.release()  # and can't delete b's lease
    assert await b.holder() == "worker-b"
    await b.release()
    assert await b.holder() is None


# ---------------------------------------------------------------- bootstrap
async def test_concurrent_bootstrap_creates_one_admin_without_errors(container, replica):
    await ensure_indexes(container.db)
    third = Container(container.settings, db=container.db, redis=container.redis)
    await asyncio.gather(*(c.identity.bootstrap() for c in (container, replica, third)))
    admins = await container.db.db["users"].count_documents({"is_platform_admin": True})
    tenants = await container.db.db["tenants"].count_documents({"slug": "acme"})
    assert admins == 1 and tenants == 1
    assert await container.redis.get("lease:bootstrap") is None


# ---------------------------------------------------------------- workers
def _worker(c: Container, host: str) -> Worker:
    w = Worker(c)
    w.host, w.name = host, f"{host}-1"
    return w


async def test_each_worker_has_its_own_heartbeat(container, replica, monkeypatch):
    from app.api.v1.observability import _health_components
    from app.workers import healthcheck

    w1, w2 = _worker(container, "worker-1"), _worker(replica, "worker-2")
    await w1.maintenance_once()
    await w2.maintenance_once()
    worker = next(h for h in await _health_components(container) if h["name"] == "Worker")
    assert worker["status"] == "healthy" and worker["workers_alive"] == 2

    # worker-2 hangs: its own container healthcheck fails even though worker-1 is fine
    await container.redis.zadd(HEARTBEAT_KEY, {"worker-2": time.time() - 600})
    monkeypatch.setattr(healthcheck, "get_settings", lambda: container.settings)
    monkeypatch.setattr(healthcheck, "create_redis", lambda s: _NoClose(container.redis))
    monkeypatch.setattr(healthcheck.socket, "gethostname", lambda: "worker-2")
    assert await healthcheck._check() is False
    monkeypatch.setattr(healthcheck.socket, "gethostname", lambda: "worker-1")
    assert await healthcheck._check() is True
    worker = next(h for h in await _health_components(container) if h["name"] == "Worker")
    assert worker["workers_alive"] == 1

    await w1.shutdown()  # a clean stop removes the worker at once
    worker = next(h for h in await _health_components(container) if h["name"] == "Worker")
    assert worker["status"] == "unhealthy" and worker["workers_alive"] == 0


class _NoClose:
    def __init__(self, redis: Any) -> None:
        self._r = redis

    def __getattr__(self, name: str) -> Any:
        return getattr(self._r, name)

    async def aclose(self) -> None:
        return None


async def test_health_checks_run_on_one_worker_per_round(container, replica, monkeypatch):
    for i in range(3):
        await container.repos.servers.insert("ten_x", {"name": f"s{i}", "alias": f"s{i}", "enabled": True,
                                                      "transport": "streamable_http"})
    probed: list[str] = []

    async def fake_test(p: Any, server: dict[str, Any]) -> dict[str, Any]:
        probed.append(server["_id"])
        await asyncio.sleep(0.01)
        return {"ok": True}
    for c in (container, replica):
        monkeypatch.setattr(c.registry, "test_connection", fake_test)
    w1, w2 = _worker(container, "worker-1"), _worker(replica, "worker-2")
    counts = await asyncio.gather(w1.health_checks_once(), w2.health_checks_once())
    assert sorted(counts) == [0, 3] and len(probed) == 3
    await w1.shutdown()
    await w2.shutdown()
    # after the holder hands over, the other worker runs the next round
    assert await w2.health_checks_once() == 3


async def test_retention_runs_once_per_interval_across_workers(container, replica):
    w1, w2 = _worker(container, "worker-1"), _worker(replica, "worker-2")
    results = await asyncio.gather(w1.retention_due(), w2.retention_due(), w1.retention_due())
    assert sorted(results) == [False, False, True]


async def test_siem_lease_hands_over_on_shutdown(container, replica):
    from app.services.siem_service import LEASE_KEY, STATUS_KEY

    await container.repos.settings.set_value("siem", {"enabled": True, "transport": "http",
                                                      "url": "https://127.0.0.1:9/x"}, "test")
    await container.redis.set(STATUS_KEY + ":backoff", "1", ex=60)  # nothing is actually sent
    w1 = _worker(container, "worker-1")
    assert await container.siem.forward_once(w1.name) == 0  # takes the lease (then backs off)
    assert await container.redis.get(LEASE_KEY) == w1.name
    assert await replica.siem.forward_once("worker-2-1") == 0  # can't: worker-1 holds it
    assert await container.redis.get(LEASE_KEY) == w1.name
    await w1.shutdown()
    assert await container.redis.get(LEASE_KEY) is None
    await replica.siem.forward_once("worker-2-1")
    assert await container.redis.get(LEASE_KEY) == "worker-2-1"
