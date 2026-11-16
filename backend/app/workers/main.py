"""Background worker: approved executions, approval expiry, upstream health checks, audit retention,
SIEM forwarding.

Run with ``python -m app.workers.main``. It shares the application modules with the API but
runs as a separate process, so long tool calls never occupy web workers.
"""

from __future__ import annotations

import asyncio
import os
import signal
import socket
from datetime import timedelta
from typing import Any

from app.config import get_settings
from app.container import Container
from app.core.ids import utcnow
from app.core.logging import configure_logging, get_logger
from app.migrations.indexes import ensure_indexes
from app.services.approval_service import JOB_GROUP, JOB_STREAM

log = get_logger("worker")

RETENTION_INTERVAL_SECONDS = 6 * 3600
MIN_RETENTION_DAYS = 30
SIEM_INTERVAL_SECONDS = 2


class Worker:
    def __init__(self, container: Container) -> None:
        self.c = container
        self.name = f"{socket.gethostname()}-{os.getpid()}"
        self._stop = asyncio.Event()
        self._siem_task: asyncio.Task[int] | None = None

    def stop(self) -> None:
        self._stop.set()

    async def ensure_group(self) -> None:
        try:
            await self.c.redis.xgroup_create(JOB_STREAM, JOB_GROUP, id="0", mkstream=True)
        except Exception as exc:  # noqa: BLE001
            if "BUSYGROUP" not in str(exc):
                raise

    async def process_jobs_once(self, block_ms: int = 1000) -> int:
        """Read and execute queued approval jobs. Returns the number processed."""
        resp: Any = await self.c.redis.xreadgroup(JOB_GROUP, self.name, {JOB_STREAM: ">"}, count=10, block=block_ms)
        # Also reclaim messages another worker took but never acknowledged (crash recovery).
        try:
            claimed = await self.c.redis.xautoclaim(JOB_STREAM, JOB_GROUP, self.name, min_idle_time=60_000,
                                                    start_id="0-0", count=10)
            if claimed and claimed[1]:
                resp = (resp or []) + [[JOB_STREAM, claimed[1]]]
        except Exception:  # noqa: BLE001,S110
            pass
        n = 0
        for _stream, messages in resp or []:
            for msg_id, fields in messages:
                await self.handle(dict(fields))
                await self.c.redis.xack(JOB_STREAM, JOB_GROUP, msg_id)
                n += 1
        return n

    async def handle(self, fields: dict[str, Any]) -> str:
        tenant_id, approval_id = fields.get("tenant_id"), fields.get("approval_id")
        if not tenant_id or not approval_id:
            return "invalid"
        try:
            result = await self.c.invocations.execute_approved(tenant_id, approval_id)
            log.info("worker.approval_processed", approval_id=approval_id, result=result)
            return result
        except Exception as exc:  # noqa: BLE001
            log.error("worker.approval_failed", approval_id=approval_id, error=type(exc).__name__)
            return "error"

    async def maintenance_once(self) -> None:
        await self.c.redis.set("worker:heartbeat", utcnow().isoformat(), ex=120)
        expired = await self.c.approvals.expire_due()
        requeued = await self.c.approvals.requeue_stuck()
        if expired or requeued:
            log.info("worker.maintenance", expired=expired, requeued=requeued)

    async def retention_once(self) -> int:
        """Delete audit events older than each tenant's retention period (spec §27 audit retention)."""
        total = 0
        async for tenant in self.c.repos.tenants.col.find({}, {"settings": 1}):
            days = int((tenant.get("settings") or {}).get("audit_retention_days")
                       or self.c.settings.audit_retention_days)
            days = max(days, MIN_RETENTION_DAYS)
            cutoff = utcnow() - timedelta(days=days)
            deleted = await self.c.repos.audit.purge_expired(tenant["_id"], cutoff)
            if deleted:
                total += deleted
                await self.c.audit.record(tenant["_id"], "audit.retention.purged", severity="high",
                                          principal={"type": "system", "id": "worker", "name": "retention"},
                                          metadata={"deleted": deleted, "retention_days": days,
                                                    "cutoff": cutoff.isoformat()}, required=False)
        if total:
            log.info("worker.retention", deleted=total)
        return total

    async def siem_once(self) -> int:
        try:
            return await self.c.siem.forward_once(self.name)
        except Exception as exc:  # noqa: BLE001 - forwarding problems must never stop the worker
            log.error("worker.siem_error", error=type(exc).__name__)
            return 0

    async def health_checks_once(self) -> None:
        servers = [s async for s in self.c.repos.servers.col.find({"enabled": True, "archived": {"$ne": True}})]
        for s in servers:
            try:
                await self.c.registry.test_connection(None, s)
            except Exception as exc:  # noqa: BLE001
                log.warning("worker.health_check_failed", server_id=s["_id"], error=type(exc).__name__)

    async def run(self) -> None:
        await self.ensure_group()
        last_maint = last_health = last_siem = 0.0
        last_retention = float("-inf")  # run once at startup, then every RETENTION_INTERVAL_SECONDS
        loop = asyncio.get_running_loop()
        log.info("worker.started", name=self.name)
        while not self._stop.is_set():
            now = loop.time()
            try:
                if now - last_maint >= self.c.settings.worker_poll_interval_seconds * 5:
                    await self.maintenance_once()
                    last_maint = now
                if now - last_retention >= RETENTION_INTERVAL_SECONDS:
                    await self.retention_once()
                    last_retention = now
                if now - last_health >= self.c.settings.health_check_interval_seconds:
                    asyncio.create_task(self.health_checks_once())  # noqa: RUF006
                    last_health = now
                if now - last_siem >= SIEM_INTERVAL_SECONDS and (self._siem_task is None or self._siem_task.done()):
                    self._siem_task = asyncio.create_task(self.siem_once())  # never blocks approval jobs
                    last_siem = now
                await self.process_jobs_once(block_ms=int(self.c.settings.worker_poll_interval_seconds * 1000))
            except Exception as exc:  # noqa: BLE001
                log.error("worker.loop_error", error=type(exc).__name__)
                await asyncio.sleep(2)
        log.info("worker.stopped")


async def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, json_output=not settings.is_dev)
    container = Container(settings)
    await ensure_indexes(container.db)
    worker = Worker(container)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, worker.stop)
        except NotImplementedError:  # Windows
            pass
    try:
        await worker.run()
    finally:
        await container.close()


if __name__ == "__main__":
    asyncio.run(main())
