"""SIEM forwarding (Phase 6): stream audit events to syslog (TCP, TLS, UDP) or an HTTP collector.

Delivery is *at least once*, in timestamp order, from the audit collection itself (the outbox):

* a durable cursor (``system_settings[siem_state]``) records the newest event timestamp shipped;
* each pass re-reads a small overlap window behind the cursor and skips event IDs already sent (kept in a
  Redis sorted set), so an event committed late by a slow writer is still delivered, not skipped;
* events younger than ``LAG_SECONDS`` wait one more pass for the same reason;
* when the collector is down nothing advances: events are delivered after it recovers (backoff up to 5 min)
  for as long as audit retention keeps them;
* one worker forwards at a time (Redis lease), so several worker replicas don't send duplicates.

Forwarding never blocks or slows tool calls: it runs in the worker, reading what the API already wrote.
"""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
from datetime import datetime, timedelta
from typing import Any

import httpx2
from redis.asyncio import Redis

from app.config import Settings
from app.core.crypto import Encryptor
from app.core.errors import ErrorCode, GatewayError
from app.core.identity import Principal
from app.core.ids import new_id, utcnow
from app.core.lease import Lease
from app.core.logging import get_logger
from app.mcp.net_guard import METADATA_HOSTS, NetPolicy, check_ip, guarded_client, resolve, validate_url
from app.models.siem import SiemConfigUpdate
from app.repositories.collections import Repos
from app.services.audit_service import AuditService
from app.services.auth_service import SYSTEM_TENANT
from app.services.siem_format import encode, frame_tcp, severity_at_least, syslog_message, to_json

log = get_logger(__name__)
CONFIG_KEY = "siem"
STATE_KEY = "siem_state"
SECRET_AAD = "system:siem:http_auth_value"  # noqa: S105 (associated-data label, not a secret)
SENT_KEY = "siem:sent"
LEASE_KEY = "siem:lease"
LEASE_SECONDS = 60  # longer than one batch (send timeout 15 s); renewed before each batch
STATUS_KEY = "siem:status"
LAG_SECONDS = 5
OVERLAP_SECONDS = 120
MAX_BATCHES_PER_PASS = 10
MAX_BACKOFF_SECONDS = 300
SEND_TIMEOUT_SECONDS = 15
MAX_RESPONSE_BYTES = 64_000
# Collectors are usually on internal networks, so private ranges are allowed; link-local and cloud-metadata
# addresses never are. Checked when the destination is saved and again at every connection (after DNS).
NET_POLICY = NetPolicy(allow_private=True)
# Fields that decide where the stored credential is sent, or how it is protected on the way. Changing any of
# them without entering the credential again would send it to a destination it was never meant for.
DESTINATION_FIELDS = ("transport", "host", "port", "url", "http_auth_header", "tls_ca_pem", "tls_verify_hostname")


class SiemError(Exception):
    pass


class SiemService:
    def __init__(self, settings: Settings, repos: Repos, redis: Redis, encryptor: Encryptor,
                 audit: AuditService) -> None:
        self.settings = settings
        self.repos = repos
        self.redis = redis
        self.encryptor = encryptor
        self.audit = audit
        self.hostname = socket.gethostname()

    # ------------------------------------------------------------------ configuration
    async def _stored(self) -> dict[str, Any]:
        return dict(await self.repos.settings.get_value(CONFIG_KEY) or {})

    @staticmethod
    def _normalized(cfg: dict[str, Any]) -> dict[str, Any]:
        """Stored settings merged over the defaults (older documents lack newer fields)."""
        fields = {k: v for k, v in cfg.items() if k in SiemConfigUpdate.model_fields}
        return SiemConfigUpdate.model_construct(**{**SiemConfigUpdate().model_dump(), **fields}).model_dump(
            exclude={"http_auth_value"})

    async def admin_view(self) -> dict[str, Any]:
        cfg = await self._stored()
        secret = cfg.pop("http_auth_value_enc", None)
        out = self._normalized(cfg)
        out.update({"has_http_auth_value": bool(secret), "updated_at": cfg.get("updated_at"),
                    "updated_by": cfg.get("updated_by")})
        return out

    def _check_destination(self, data: dict[str, Any]) -> None:
        blocked = GatewayError(ErrorCode.VALIDATION_FAILED, "That destination address is not permitted.")
        try:
            if data["transport"] == "http":
                if data["url"]:
                    validate_url(data["url"], NET_POLICY)
            elif data["host"]:
                host = data["host"].lower().strip("[]").rstrip(".")
                if host in METADATA_HOSTS:
                    raise blocked
                try:
                    check_ip(host, NET_POLICY)
                except ValueError:
                    pass  # a host name: checked after DNS resolution at every connection
        except GatewayError as exc:
            raise blocked from exc
        if data["tls_ca_pem"]:
            try:
                ssl.create_default_context(cadata=data["tls_ca_pem"])
            except (ssl.SSLError, ValueError) as exc:
                raise GatewayError(ErrorCode.VALIDATION_FAILED, "The CA bundle could not be parsed.") from exc

    async def update_config(self, p: Principal, body: SiemConfigUpdate) -> dict[str, Any]:
        cfg = await self._stored()
        data = body.model_dump(exclude={"http_auth_value"})
        self._check_destination(data)
        if body.http_auth_value is not None:
            data["http_auth_value_enc"] = (self.encryptor.encrypt(body.http_auth_value.encode(), SECRET_AAD)
                                           if body.http_auth_value else None)
        else:
            if cfg.get("http_auth_value_enc"):
                before = self._normalized(cfg)
                moved = [k for k in DESTINATION_FIELDS if data.get(k) != before.get(k)]
                if moved:
                    raise GatewayError(
                        ErrorCode.VALIDATION_FAILED,
                        "Enter the collector credential again (or clear it) when changing the destination or its "
                        "TLS settings: a stored credential is only sent where it was saved for.",
                        details=[{"field": k} for k in moved])
            data["http_auth_value_enc"] = cfg.get("http_auth_value_enc")
        if (data["http_auth_value_enc"] and data["transport"] == "http" and data["url"].startswith("http://")
                and self.settings.app_env == "production"):
            raise GatewayError(ErrorCode.VALIDATION_FAILED,
                               "Use an https:// collector URL: the credential must not cross the network in clear text.")
        changed = sorted(k for k in (set(data) | set(cfg)) - {"updated_at", "updated_by"} if data.get(k) != cfg.get(k))
        data.update({"updated_at": utcnow().isoformat(), "updated_by": p.principal_id})
        await self.repos.settings.set_value(CONFIG_KEY, data, p.principal_id)
        if data["enabled"] and not cfg.get("enabled"):
            # Start from "now": enabling forwarding does not replay the whole audit history.
            state = await self.repos.settings.get_value(STATE_KEY) or {}
            if not state.get("cursor"):
                now = utcnow().isoformat()
                await self.repos.settings.set_value(STATE_KEY, {"cursor": now, "floor": now}, p.principal_id)
        await self.redis.delete(STATUS_KEY + ":backoff")
        await self.audit.record(
            p.tenant_id, "siem.config.updated", principal=p, severity="high",
            metadata={"changed": [("http_auth_value" if k == "http_auth_value_enc" else k) for k in changed],
                      "enabled": data["enabled"], "transport": data["transport"]},
        )
        return await self.admin_view()

    async def status(self) -> dict[str, Any]:
        cfg = await self._stored()
        state = await self.repos.settings.get_value(STATE_KEY) or {}
        raw = await self.redis.hgetall(STATUS_KEY)  # type: ignore[misc]
        cursor = state.get("cursor")
        lag = pending = None
        if cursor and cfg.get("enabled"):
            cur = datetime.fromisoformat(cursor)
            lag = max(0, int((utcnow() - cur).total_seconds()))
            pending = await self.repos.audit.col.count_documents({"timestamp": {"$gt": cur}})
        return {
            "enabled": bool(cfg.get("enabled")), "cursor": cursor, "lag_seconds": lag, "pending_events": pending,
            "forwarded_total": int(raw.get("forwarded_total") or 0), "last_success_at": raw.get("last_success_at"),
            "last_error": raw.get("last_error"), "last_error_at": raw.get("last_error_at"),
            "failing": raw.get("failing") == "1",
        }

    # ------------------------------------------------------------------ transports
    def _ssl_context(self, cfg: dict[str, Any]) -> ssl.SSLContext:
        ctx = ssl.create_default_context(cadata=cfg["tls_ca_pem"]) if cfg.get("tls_ca_pem") \
            else ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if not cfg.get("tls_verify_hostname", True):
            ctx.check_hostname = False  # the chain is still verified against the CA
        return ctx

    @staticmethod
    async def _address(host: str, port: int) -> str:
        """The address to connect to: resolved now, every answer checked, and the checked address is the one
        used (no DNS rebinding between check and connect)."""
        name = host.strip("[]").rstrip(".")
        if name.lower() in METADATA_HOSTS:
            raise SiemError(f"connect {host}:{port}: destination not permitted")
        try:
            addresses = await resolve(name, port)
        except OSError as exc:
            raise SiemError(f"connect {host}:{port}: DNS resolution failed") from exc
        if not addresses:
            raise SiemError(f"connect {host}:{port}: DNS resolution failed")
        try:
            for ip in addresses:
                check_ip(ip, NET_POLICY)
        except GatewayError as exc:
            raise SiemError(f"connect {host}:{port}: destination not permitted") from exc
        return addresses[0]

    @staticmethod
    def _failure(where: str, exc: BaseException) -> SiemError:
        """A failure description without the exception text (the test endpoint must not be a port scanner);
        the detail goes to the worker log only."""
        log.info("siem.send.error_detail", where=where, error=f"{type(exc).__name__}: {exc}"[:300])
        if isinstance(exc, ssl.SSLError) or "SSL" in str(exc) or "CERTIFICATE" in str(exc).upper():
            return SiemError(f"{where}: TLS handshake failed (SSL certificate or protocol error)")
        if isinstance(exc, TimeoutError | httpx2.TimeoutException):
            return SiemError(f"{where}: timed out")
        return SiemError(f"{where}: could not connect or send")

    async def _send_stream(self, cfg: dict[str, Any], frames: list[bytes]) -> None:
        tls = self._ssl_context(cfg) if cfg["transport"] == "syslog_tls" else None
        where = f"connect {cfg['host']}:{cfg['port']}"
        address = await self._address(cfg["host"], cfg["port"])
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, cfg["port"], ssl=tls,
                                        server_hostname=cfg["host"].strip("[]") if tls else None),
                SEND_TIMEOUT_SECONDS)
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            raise self._failure(where, exc) from exc
        try:
            writer.write(b"".join(frames))
            await asyncio.wait_for(writer.drain(), SEND_TIMEOUT_SECONDS)
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            raise self._failure("send", exc) from exc
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 5)
            except Exception:  # noqa: BLE001,S110 - peer already gone; data was flushed by drain()
                pass

    async def _send_udp(self, cfg: dict[str, Any], messages: list[bytes]) -> None:
        loop = asyncio.get_running_loop()
        address = await self._address(cfg["host"], cfg["port"])
        try:
            transport, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol,
                                                               remote_addr=(address, cfg["port"]))
        except OSError as exc:
            raise self._failure(f"udp {cfg['host']}:{cfg['port']}", exc) from exc
        try:
            for m in messages:
                transport.sendto(m[:8192])
        finally:
            transport.close()

    async def _send_http(self, cfg: dict[str, Any], events: list[dict[str, Any]]) -> None:
        if cfg["http_body"] == "splunk_hec":
            body = "\n".join(json.dumps({"time": round(e["timestamp"].timestamp(), 3) if isinstance(
                e.get("timestamp"), datetime) else None, "source": "mcp-gateway", "sourcetype": "mcp-gateway:audit",
                "host": self.hostname, "event": to_json(e)}, separators=(",", ":"), default=str) for e in events)
            ctype = "application/json"
        elif cfg["http_body"] == "json_array":
            body = "[" + ",".join(encode(e, "json") if cfg["format"] == "json" else json.dumps(encode(e, "cef"))
                                  for e in events) + "]"
            ctype = "application/json"
        else:
            body = "\n".join(encode(e, cfg["format"]) for e in events) + "\n"
            ctype = "application/x-ndjson" if cfg["format"] == "json" else "text/plain"
        headers = {"Content-Type": ctype, "User-Agent": "mcp-gateway-siem"}
        if cfg.get("http_auth_value_enc"):
            headers[cfg.get("http_auth_header") or "Authorization"] = self.encryptor.decrypt(
                cfg["http_auth_value_enc"], SECRET_AAD).decode()
        verify: Any = self._ssl_context(cfg) if cfg["url"].startswith("https://") else True
        try:
            validate_url(cfg["url"], NET_POLICY)
        except GatewayError as exc:
            raise SiemError("http: destination not permitted") from exc
        try:
            # The guarded client resolves, checks every address against NET_POLICY and connects to the checked
            # one; no redirects, no proxy variables, no connection reuse.
            async with guarded_client(NET_POLICY, timeout=SEND_TIMEOUT_SECONDS, verify=verify) as c:
                r = await c.post(cfg["url"], content=body.encode("utf-8"), headers=headers)
        except httpx2.HTTPError as exc:
            if "blocked by gateway network policy" in str(exc):
                raise SiemError("http: destination not permitted") from exc
            raise self._failure("http", exc) from exc
        if not 200 <= r.status_code < 300:
            raise SiemError(f"http: collector returned HTTP {r.status_code}")

    async def send(self, cfg: dict[str, Any], events: list[dict[str, Any]]) -> None:
        if not events:
            return
        try:
            t = cfg["transport"]
            if t == "http":
                await self._send_http(cfg, events)
                return
            msgs = [syslog_message(e, cfg["format"], facility=cfg.get("syslog_facility", 13), hostname=self.hostname)
                    for e in events]
            if t == "syslog_udp":
                await self._send_udp(cfg, msgs)
            else:
                await self._send_stream(cfg, [frame_tcp(m) for m in msgs])
        except SiemError:
            raise
        except Exception as exc:  # noqa: BLE001 - any failure must reach _failed (status, audit, backoff)
            log.warning("siem.send.unexpected", error=type(exc).__name__)
            raise SiemError(f"send failed ({type(exc).__name__})") from exc

    async def test(self, p: Principal) -> dict[str, Any]:
        cfg = await self._stored()
        if not (cfg.get("host") or cfg.get("url")):
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "Save a destination first.")
        event = {"event_id": new_id("evt"), "timestamp": utcnow(), "event_type": "siem.test", "severity": "info",
                 "tenant_id": p.tenant_id, "principal": p.audit_ref(), "resource": {}, "status": "success",
                 "metadata": {"message": "MCP-Gateway SIEM connectivity test"}}
        try:
            await self.send(cfg, [event])
        except SiemError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "event_id": event["event_id"],
                "note": "UDP gives no delivery confirmation" if cfg["transport"] == "syslog_udp" else None}

    # ------------------------------------------------------------------ forwarding
    def _wanted(self, cfg: dict[str, Any], e: dict[str, Any]) -> bool:
        if not severity_at_least(e.get("severity"), cfg.get("min_severity", "info")):
            return False
        prefixes = cfg.get("event_types") or []
        et = str(e.get("event_type") or "")
        return not prefixes or any(et.startswith(x.rstrip("*")) for x in prefixes)

    async def release_lease(self, owner: str) -> None:
        """On worker shutdown: hand forwarding to another worker now instead of after the lease expires."""
        await Lease(self.redis, LEASE_KEY, owner, LEASE_SECONDS).release()

    async def forward_once(self, owner: str) -> int:
        """One pass. Returns the number of events sent. Safe to call often; does nothing when disabled,
        when another worker holds the lease, or while backing off after a failure."""
        cfg = await self._stored()
        if not cfg.get("enabled"):
            return 0
        lease = Lease(self.redis, LEASE_KEY, owner, LEASE_SECONDS)
        if not await lease.acquire():
            return 0
        if await self.redis.exists(STATUS_KEY + ":backoff"):
            return 0
        state = await self.repos.settings.get_value(STATE_KEY) or {}
        cursor = datetime.fromisoformat(state["cursor"]) if state.get("cursor") else utcnow()
        floor = datetime.fromisoformat(state["floor"]) if state.get("floor") else None
        horizon = utcnow() - timedelta(seconds=LAG_SECONDS)
        sent_total = 0
        for _ in range(MAX_BATCHES_PER_PASS):
            # Renewed before every batch: a pass can outlast one lease period, and if the lease was lost
            # (this worker stalled), another worker owns the cursor now and this one must stop.
            if not await lease.renew():
                log.warning("siem.lease_lost", owner=owner)
                break
            batch, processed, newest = await self._collect(cfg, cursor, horizon, floor)
            if not processed:
                break
            try:
                await self.send(cfg, batch)
            except SiemError as exc:
                await self._failed(str(exc))
                break
            await self.redis.zadd(SENT_KEY, {eid: ts.timestamp() for eid, ts in processed})
            cursor = max(cursor, newest)
            if not await lease.renew():  # never move a cursor another worker now owns
                log.warning("siem.lease_lost", owner=owner)
                break
            await self.repos.settings.set_value(
                STATE_KEY, {"cursor": cursor.isoformat(), "floor": floor.isoformat() if floor else None}, owner)
            await self.redis.zremrangebyscore(SENT_KEY, "-inf", (cursor - timedelta(seconds=OVERLAP_SECONDS * 2)).timestamp())
            sent_total += len(batch)
            await self._succeeded(len(batch))
            if len(processed) < cfg.get("batch_size", 200):
                break
        return sent_total

    async def _collect(self, cfg: dict[str, Any], cursor: datetime, horizon: datetime, floor: datetime | None
                       ) -> tuple[list[dict[str, Any]], list[tuple[str, datetime]], datetime]:
        """Up to batch_size not-yet-processed events in (cursor - overlap, horizon], oldest first, never
        older than ``floor`` (the moment forwarding was first enabled)."""
        limit = int(cfg.get("batch_size", 200))
        start = cursor - timedelta(seconds=OVERLAP_SECONDS)
        if floor is not None and floor > start:
            start = floor
        query = {"timestamp": {"$gte" if start == floor else "$gt": start, "$lte": horizon}}
        batch: list[dict[str, Any]] = []
        processed: list[tuple[str, datetime]] = []
        newest = cursor
        sent_floor = (cursor - timedelta(seconds=OVERLAP_SECONDS + 1)).timestamp()
        already = set(await self.redis.zrangebyscore(SENT_KEY, sent_floor, "+inf"))
        async for e in self.repos.audit.col.find(query).sort([("timestamp", 1), ("_id", 1)]):
            if e["_id"] in already:
                continue
            processed.append((e["_id"], e["timestamp"]))
            newest = max(newest, e["timestamp"])
            if self._wanted(cfg, e):
                batch.append(e)
            if len(processed) >= limit:
                break
        return batch, processed, newest

    async def _succeeded(self, n: int) -> None:
        was_failing = await self.redis.hget(STATUS_KEY, "failing") == "1"  # type: ignore[misc]
        await self.redis.hincrby(STATUS_KEY, "forwarded_total", n)  # type: ignore[misc]
        await self.redis.hset(STATUS_KEY, mapping={"last_success_at": utcnow().isoformat(), "failing": "0"})  # type: ignore[misc]
        await self.redis.delete(STATUS_KEY + ":failures")
        if was_failing:
            log.info("siem.forwarding.recovered")
            await self.audit.record(SYSTEM_TENANT, "siem.forwarding.recovered", severity="warning",
                                    principal={"type": "system", "id": "worker", "name": "siem"})

    async def _failed(self, error: str) -> None:
        failures = int(await self.redis.incr(STATUS_KEY + ":failures"))
        backoff = min(MAX_BACKOFF_SECONDS, 2 ** min(failures, 9))
        await self.redis.set(STATUS_KEY + ":backoff", "1", ex=backoff)
        was_failing = await self.redis.hget(STATUS_KEY, "failing") == "1"  # type: ignore[misc]
        await self.redis.hset(STATUS_KEY, mapping={"last_error": error, "last_error_at": utcnow().isoformat(),  # type: ignore[misc]
                                                   "failing": "1"})
        log.warning("siem.forwarding.failed", error=error, retry_in_seconds=backoff)
        if not was_failing:  # audit the transition only, not every retry
            await self.audit.record(SYSTEM_TENANT, "siem.forwarding.failed", severity="high", status="failure",
                                    principal={"type": "system", "id": "worker", "name": "siem"},
                                    metadata={"error": error})
