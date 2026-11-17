"""Creates upstream adapter sessions from stored server documents and enforces per-server concurrency.

The per-server cap (``max_concurrent_calls``) is shared by every API replica and worker: it is a Redis lease
semaphore (a sorted set of call tokens scored by their expiry, using Redis' clock). A replica that dies mid-call
can't leak its slot for longer than the call could have lasted.
"""

from __future__ import annotations

import json
import secrets
import ssl
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

import anyio
import certifi
from redis.asyncio import Redis

from app.config import Settings
from app.core.client_certs import build_ssl_context
from app.core.crypto import Encryptor
from app.core.errors import ErrorCode, GatewayError
from app.core.logging import get_logger
from app.mcp.adapters.base import MCPServerAdapter, ServerConfig, UpstreamError
from app.mcp.adapters.sdk import SdkAdapter
from app.mcp.net_guard import NetPolicy
from app.repositories.collections import Repos

AdapterFactory = Callable[[], MCPServerAdapter]
log = get_logger(__name__)

# KEYS[1]: semaphore zset. ARGV: limit, token, hold_ms. Returns 1 when a slot was taken.
SEM_ACQUIRE = """
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then return 0 end
redis.call('ZADD', KEYS[1], now + tonumber(ARGV[3]), ARGV[2])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[3]) + 60000)
return 1
"""


class ClientManager:
    def __init__(self, settings: Settings, repos: Repos, encryptor: Encryptor, redis: Redis) -> None:
        self.settings = settings
        self.repos = repos
        self.encryptor = encryptor
        self.redis = redis
        self._sem_acquire = redis.register_script(SEM_ACQUIRE)
        # SSL contexts for upstreams with a custom CA or a client certificate, per server version: building one
        # decrypts the key and parses the bundle, which is too slow to repeat on every call.
        self._ssl_cache: dict[str, tuple[Any, ssl.SSLContext]] = {}
        self.adapter_factory: Callable[[dict[str, Any]], MCPServerAdapter] = self._default_factory

    def net_policy_for(self, server: dict[str, Any]) -> NetPolicy:
        allow_private = self.settings.allow_private_upstream_networks or bool(server.get("allow_private_network"))
        return NetPolicy(allow_private=allow_private, host_allowlist=tuple(self.settings.upstream_host_allowlist))

    def _default_factory(self, server: dict[str, Any]) -> MCPServerAdapter:
        return SdkAdapter(self.net_policy_for(server), self.settings.stdio_executable_allowlist)

    async def build_config(self, server: dict[str, Any]) -> ServerConfig:
        cfg = server.get("connection_config", {})
        headers: dict[str, str] = {}
        env: dict[str, str] = dict(cfg.get("env") or {})
        if server.get("secret_ref"):
            secret = await self.repos.secrets.get(server["tenant_id"], server["secret_ref"])
            if secret:
                value = json.loads(
                    self.encryptor.decrypt(secret["ciphertext"], f"{server['tenant_id']}:{secret['_id']}")
                )
                mode = server.get("authentication_mode", "none")
                if mode == "bearer":
                    headers["Authorization"] = f"Bearer {value['token']}"
                elif mode == "header":
                    headers[value.get("header_name", "X-API-Key")] = value["token"]
                elif mode == "env":
                    env.update({k: str(v) for k, v in value.get("env", {}).items()})
        ssl_context = await self._ssl_context(server, cfg)
        return ServerConfig(
            server_id=server["_id"],
            transport=server["transport"],
            endpoint=cfg.get("endpoint"),
            command=cfg.get("command"),
            args=list(cfg.get("args") or []),
            env=env,
            cwd=cfg.get("cwd"),
            headers=headers,
            connection_timeout_seconds=float(server.get("connection_timeout_seconds", 10)),
            request_timeout_seconds=float(server.get("request_timeout_seconds", 30)),
            verify_tls=bool(cfg.get("verify_tls", True)),
            ssl_context=ssl_context,
        )

    async def _ssl_context(self, server: dict[str, Any], cfg: dict[str, Any]) -> ssl.SSLContext | None:
        if server.get("transport") != "streamable_http" or not (cfg.get("tls_ca_pem") or server.get("tls_secret_ref")):
            return None  # the HTTP client's defaults
        stamp = (server.get("version"), server.get("updated_at"), server.get("tls_secret_ref"), cfg.get("verify_tls"))
        cached = self._ssl_cache.get(server["_id"])
        if cached and cached[0] == stamp:
            return cached[1]
        key_pem = None
        if server.get("tls_secret_ref"):
            secret = await self.repos.secrets.get(server["tenant_id"], server["tls_secret_ref"])
            if secret:
                key_pem = json.loads(self.encryptor.decrypt(
                    secret["ciphertext"], f"{server['tenant_id']}:{secret['_id']}"))["key_pem"]
        try:
            ctx = build_ssl_context(verify=bool(cfg.get("verify_tls", True)), ca_pem=cfg.get("tls_ca_pem"),
                                    cert_pem=(cfg.get("tls_client_info") or {}).get("cert_pem"), key_pem=key_pem,
                                    default_cafile=certifi.where())
        except (ssl.SSLError, OSError, ValueError) as exc:
            raise UpstreamError("blocked", "The server's TLS settings could not be loaded") from exc
        self._ssl_cache[server["_id"]] = (stamp, ctx)
        return ctx

    @staticmethod
    def semaphore_key(server: dict[str, Any]) -> str:
        return f"sem:srv:{server['_id']}"

    async def in_flight(self, server: dict[str, Any]) -> int:
        """Calls currently holding a slot for ``server`` across all replicas."""
        key = self.semaphore_key(server)
        now_ms = int(time.time() * 1000)
        return int(await self.redis.zcount(key, now_ms, "+inf"))

    async def _acquire_slot(self, server: dict[str, Any]) -> tuple[str, str]:
        key = self.semaphore_key(server)
        limit = max(1, int(server.get("max_concurrent_calls", 10)))
        wait = float(server.get("request_timeout_seconds", 30))
        # The slot outlives the longest call this server allows; after that a dead holder's slot is reclaimed.
        hold_ms = int((wait + float(server.get("connection_timeout_seconds", 10)) + 30) * 1000)
        token = secrets.token_hex(12)
        delay = 0.02
        try:
            with anyio.fail_after(wait):
                while not int(await self._sem_acquire(keys=[key], args=[limit, token, hold_ms])):
                    await anyio.sleep(delay)
                    delay = min(delay * 2, 0.5)
        except TimeoutError as exc:
            raise UpstreamError("unavailable", "Server concurrency limit reached") from exc
        except UpstreamError:
            raise
        except Exception as exc:  # Redis unavailable: fail closed, like the other hard limits
            log.error("upstream.concurrency_unavailable", error=type(exc).__name__)
            raise GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE, "Concurrency control is unavailable.") from exc
        return key, token

    async def _release_slot(self, key: str, token: str) -> None:
        try:
            await self.redis.zrem(key, token)
        except Exception as exc:  # noqa: BLE001 - the slot expires on its own
            log.warning("upstream.concurrency_release_failed", error=type(exc).__name__)

    @asynccontextmanager
    async def session(self, server: dict[str, Any]) -> AsyncIterator[MCPServerAdapter]:
        config = await self.build_config(server)
        adapter = self.adapter_factory(server)
        await adapter.connect(config)
        try:
            yield adapter
        finally:
            await adapter.close()

    @asynccontextmanager
    async def limited_session(self, server: dict[str, Any]) -> AsyncIterator[MCPServerAdapter]:
        key, token = await self._acquire_slot(server)
        try:
            async with self.session(server) as adapter:
                yield adapter
        finally:
            with anyio.CancelScope(shield=True):
                await self._release_slot(key, token)
