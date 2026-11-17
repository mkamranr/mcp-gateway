"""MCP adapter built on the official SDK ``mcp.Client`` (streamable HTTP and stdio)."""

from __future__ import annotations

import os
import shutil
import time
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

import anyio
from mcp import Client, StdioServerParameters
from mcp.client.stdio import get_default_environment
from mcp.client.streamable_http import streamable_http_client

from app.core.errors import GatewayError
from app.mcp.adapters.base import HealthResult, ServerConfig, ToolDefinition, ToolResult, UpstreamError
from app.mcp.net_guard import NetPolicy, guarded_client, validate_url

SHELL_METACHARS = set(";|&$`<>\n\r\x00")
FORBIDDEN_ENV = {"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "PYTHONSTARTUP", "NODE_OPTIONS",
                 "PYTHONPATH", "BASH_ENV", "ENV", "PATH"}


def validate_stdio_config(command: str, args: list[str], env: dict[str, str], allowlist: list[str]) -> str:
    """Stdio servers execute processes: only allowlisted executables, fixed args, no shell (spec §10.2).

    Returns the resolved absolute executable path.
    """
    if not command or any(c in SHELL_METACHARS for c in command):
        raise UpstreamError("blocked", "Invalid executable")
    if not allowlist:
        raise UpstreamError("blocked", "No stdio executables are allowlisted on this gateway")
    resolved = shutil.which(command) if not os.path.isabs(command) else command
    if not resolved:
        raise UpstreamError("blocked", "Executable not found")
    resolved_norm = os.path.normcase(str(Path(resolved).resolve()))
    allowed = {os.path.normcase(str(Path(p).resolve())) for p in allowlist}
    if resolved_norm not in allowed:
        raise UpstreamError("blocked", "Executable is not in the stdio allowlist")
    if len(args) > 64:
        raise UpstreamError("blocked", "Too many arguments")
    for a in args:
        if not isinstance(a, str) or "\x00" in a or len(a) > 4096:
            raise UpstreamError("blocked", "Invalid argument")
    for k, v in env.items():
        if k.upper() in FORBIDDEN_ENV or not k.replace("_", "").isalnum() or "\x00" in v:
            raise UpstreamError("blocked", f"Environment variable {k!r} is not permitted")
    return resolved


class SdkAdapter:
    """Opens one upstream MCP session for the lifetime of ``connect()``..``close()``."""

    def __init__(self, net_policy: NetPolicy, stdio_allowlist: list[str]) -> None:
        self.net_policy = net_policy
        self.stdio_allowlist = stdio_allowlist
        self._stack: AsyncExitStack | None = None
        self._client: Client | None = None
        self._config: ServerConfig | None = None

    async def connect(self, config: ServerConfig) -> None:
        self._config = config
        stack = AsyncExitStack()
        try:
            if config.transport == "streamable_http":
                if not config.endpoint:
                    raise UpstreamError("blocked", "Endpoint is required")
                try:
                    validate_url(config.endpoint, self.net_policy)
                except GatewayError as exc:
                    raise UpstreamError("blocked", exc.message) from exc
                http = guarded_client(
                    self.net_policy,
                    headers=config.headers,
                    timeout=config.request_timeout_seconds,
                    verify=config.ssl_context if config.ssl_context is not None else config.verify_tls,
                )
                await stack.enter_async_context(http)
                server: Any = streamable_http_client(config.endpoint, http_client=http)
            elif config.transport == "stdio":
                exe = validate_stdio_config(config.command or "", config.args, config.env, self.stdio_allowlist)
                server = StdioServerParameters(
                    command=exe, args=list(config.args), env={**get_default_environment(), **config.env},
                    cwd=config.cwd,
                )
            else:
                raise UpstreamError("blocked", "Unsupported transport")
            # Connection/handshake time is bounded by the HTTP client's connect timeout and the
            # SDK read timeout. (Do not wrap __aenter__ in a cancel scope: the client's task group
            # outlives it.)
            self._client = await stack.enter_async_context(
                Client(server, read_timeout_seconds=min(config.connection_timeout_seconds * 3,
                                                        config.request_timeout_seconds))
            )
            self._stack = stack
        except UpstreamError:
            await stack.aclose()
            raise
        except TimeoutError as exc:
            await _safe_close(stack)
            raise UpstreamError("timeout", "Connection timed out") from exc
        except Exception as exc:  # noqa: BLE001
            await _safe_close(stack)
            raise UpstreamError("unavailable", _sanitize(exc)) from exc

    async def list_tools(self) -> list[ToolDefinition]:
        client = self._require()
        tools: list[ToolDefinition] = []
        cursor: str | None = None
        try:
            for _ in range(50):  # pagination guard
                res = await client.list_tools(cursor=cursor, cache_mode="bypass")
                for t in res.tools:
                    tools.append(
                        ToolDefinition(
                            name=t.name,
                            description=t.description or "",
                            input_schema=dict(t.input_schema or {"type": "object"}),
                            output_schema=dict(t.output_schema) if t.output_schema else None,
                            annotations=t.annotations.model_dump(exclude_none=True) if t.annotations else None,
                        )
                    )
                cursor = getattr(res, "next_cursor", None)
                if not cursor:
                    break
        except Exception as exc:  # noqa: BLE001
            raise UpstreamError("protocol", _sanitize(exc)) from exc
        return tools

    async def call_tool(self, tool_name: str, arguments: dict[str, Any], timeout: float) -> ToolResult:
        client = self._require()
        try:
            with anyio.fail_after(timeout):
                res = await client.call_tool(tool_name, arguments, read_timeout_seconds=timeout)
        except TimeoutError as exc:
            raise UpstreamError("timeout", "Tool call timed out") from exc
        except Exception as exc:  # noqa: BLE001
            raise UpstreamError("unavailable", _sanitize(exc)) from exc
        return ToolResult(
            content=[c.model_dump(mode="json", exclude_none=True, by_alias=True) for c in (res.content or [])],
            structured_content=getattr(res, "structured_content", None),
            is_error=bool(res.is_error),
        )

    async def health_check(self) -> HealthResult:
        start = time.perf_counter()
        try:
            tools = await self.list_tools()
            return HealthResult(True, int((time.perf_counter() - start) * 1000), tool_count=len(tools))
        except UpstreamError as exc:
            return HealthResult(False, int((time.perf_counter() - start) * 1000), error=exc.detail or exc.kind)

    async def close(self) -> None:
        if self._stack:
            await _safe_close(self._stack)
            self._stack = None
            self._client = None

    def _require(self) -> Client:
        if self._client is None:
            raise UpstreamError("unavailable", "Not connected")
        return self._client


async def _safe_close(stack: AsyncExitStack) -> None:
    # Note: no extra cancel scope here, and never swallow CancelledError. Either one corrupts
    # anyio's cancel-scope bookkeeping for the enclosing task.
    try:
        await stack.aclose()
    except Exception:  # noqa: BLE001,S110 - closing a broken upstream must not mask the original error
        pass
    except BaseExceptionGroup as eg:  # anyio task-group errors during shutdown
        if eg.subgroup(lambda e: not isinstance(e, Exception)):
            raise


def _sanitize(exc: BaseException) -> str:
    """Never surface upstream stack traces, hostnames or paths to callers."""
    # Unwrap exception groups produced by anyio task groups.
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    name = type(exc).__name__
    if "ConnectError" in name or "ConnectTimeout" in name:
        return "Connection failed"
    if "Timeout" in name:
        return "Timed out"
    if "HTTPStatus" in name:
        return "Upstream returned an HTTP error"
    return name
