"""Creates upstream adapter sessions from stored server documents and enforces per-server concurrency."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

import anyio

from app.config import Settings
from app.core.crypto import Encryptor
from app.mcp.adapters.base import MCPServerAdapter, ServerConfig, UpstreamError
from app.mcp.adapters.sdk import SdkAdapter
from app.mcp.net_guard import NetPolicy
from app.repositories.collections import Repos

AdapterFactory = Callable[[], MCPServerAdapter]


class ClientManager:
    def __init__(self, settings: Settings, repos: Repos, encryptor: Encryptor) -> None:
        self.settings = settings
        self.repos = repos
        self.encryptor = encryptor
        self._limiters: dict[str, anyio.CapacityLimiter] = {}
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
        )

    def limiter(self, server: dict[str, Any]) -> anyio.CapacityLimiter:
        key = server["_id"]
        size = max(1, int(server.get("max_concurrent_calls", 10)))
        lim = self._limiters.get(key)
        if lim is None or lim.total_tokens != size:
            lim = anyio.CapacityLimiter(size)
            self._limiters[key] = lim
        return lim

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
        lim = self.limiter(server)
        try:
            with anyio.fail_after(float(server.get("request_timeout_seconds", 30))):
                await lim.acquire()
        except TimeoutError as exc:
            raise UpstreamError("unavailable", "Server concurrency limit reached") from exc
        try:
            async with self.session(server) as adapter:
                yield adapter
        finally:
            lim.release()
