"""Upstream MCP adapter interface (spec §10.2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol


@dataclass
class ServerConfig:
    server_id: str
    transport: Literal["streamable_http", "stdio"]
    endpoint: str | None = None
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    headers: dict[str, str] = field(default_factory=dict)  # includes decrypted auth header; never logged
    connection_timeout_seconds: float = 10
    request_timeout_seconds: float = 30
    verify_tls: bool = True
    ssl_context: Any = None  # custom CA and/or client certificate (mTLS); overrides verify_tls when set


@dataclass
class ToolDefinition:
    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None


@dataclass
class ToolResult:
    content: list[dict[str, Any]]
    structured_content: dict[str, Any] | None = None
    is_error: bool = False


@dataclass
class HealthResult:
    healthy: bool
    latency_ms: int
    error: str | None = None
    tool_count: int | None = None
    server_info: dict[str, Any] | None = None


class MCPServerAdapter(Protocol):
    async def connect(self, config: ServerConfig) -> None: ...
    async def list_tools(self) -> list[ToolDefinition]: ...
    async def call_tool(self, tool_name: str, arguments: dict[str, Any], timeout: float) -> ToolResult: ...
    async def health_check(self) -> HealthResult: ...
    async def close(self) -> None: ...


class UpstreamError(Exception):
    """Raised by adapters. ``kind`` maps to a gateway error code; ``detail`` is sanitized text."""

    def __init__(self, kind: Literal["unavailable", "timeout", "blocked", "protocol"], detail: str = "") -> None:
        self.kind = kind
        self.detail = detail
        super().__init__(f"{kind}: {detail}")
