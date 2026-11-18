"""Upstream network guard: SSRF, DNS-rebinding and redirect protection (spec §10.2, §19).

* URL validation at registration time (scheme, host allowlist, credentials in URL).
* Connect-time enforcement: a custom httpcore2 network backend resolves the hostname, checks
  every resolved address against the policy and connects to the *validated IP*. The address
  that is checked is the address that is used, so DNS rebinding between check and connect is
  not possible. TLS still verifies against the original hostname (SNI is passed separately).
* Redirects: the MCP SDK only follows same-origin redirects; our client also disables
  ``follow_redirects`` and the connect-time check applies to every connection.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import anyio
import httpcore2
import httpx2
from httpcore2._backends.auto import AutoBackend
from httpcore2._backends.base import AsyncNetworkBackend, AsyncNetworkStream

from app.core.errors import ErrorCode, GatewayError

METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data", "169.254.169.254", "fd00:ec2::254"}
ALWAYS_BLOCKED = [
    ipaddress.ip_network("169.254.0.0/16"),  # link-local incl. cloud metadata
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("fd00:ec2::/32"),
]
PRIVATE = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fec0::/10"),  # deprecated IPv6 site-local, still routed on some networks
]


@dataclass(frozen=True)
class NetPolicy:
    allow_private: bool = False
    host_allowlist: tuple[str, ...] = field(default_factory=tuple)
    require_tls: bool = False

    def host_allowed(self, host: str) -> bool:
        if not self.host_allowlist:
            return True
        host = host.lower().rstrip(".")
        for entry in self.host_allowlist:
            entry = entry.lower().strip()
            if entry.startswith("*.") and (host.endswith(entry[1:]) or host == entry[2:]):
                return True
            if host == entry:
                return True
        return False


def check_ip(ip: str, policy: NetPolicy) -> None:
    addr = ipaddress.ip_address(ip.split("%")[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if any(addr in net for net in ALWAYS_BLOCKED) or addr.is_unspecified or addr.is_reserved:
        raise GatewayError(ErrorCode.UPSTREAM_BLOCKED, "Destination address is not permitted.")
    if not policy.allow_private and (addr.is_private or addr.is_loopback or any(addr in n for n in PRIVATE)):
        raise GatewayError(ErrorCode.UPSTREAM_BLOCKED, "Private or loopback destinations are not permitted.")


def validate_url(url: str, policy: NetPolicy) -> str:
    """Static validation used at registration and before every connection."""
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise GatewayError(ErrorCode.UPSTREAM_BLOCKED, "Malformed endpoint URL.") from exc
    if parts.scheme not in ("http", "https"):
        raise GatewayError(ErrorCode.UPSTREAM_BLOCKED, "Endpoint must use http or https.")
    if policy.require_tls and parts.scheme != "https":
        raise GatewayError(ErrorCode.UPSTREAM_BLOCKED, "Endpoint must use https.")
    if parts.username or parts.password:
        raise GatewayError(ErrorCode.UPSTREAM_BLOCKED, "Credentials must not be embedded in the URL.")
    host = (parts.hostname or "").lower()
    if not host:
        raise GatewayError(ErrorCode.UPSTREAM_BLOCKED, "Endpoint host is required.")
    if host in METADATA_HOSTS:
        raise GatewayError(ErrorCode.UPSTREAM_BLOCKED, "Destination address is not permitted.")
    if not policy.host_allowed(host):
        raise GatewayError(ErrorCode.UPSTREAM_BLOCKED, "Endpoint host is not in the upstream allowlist.")
    try:
        ipaddress.ip_address(host.strip("[]"))
        check_ip(host.strip("[]"), policy)
    except ValueError:
        pass  # hostname; checked at connect time after resolution
    return url


async def resolve(host: str, port: int) -> list[str]:
    infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


class GuardedNetworkBackend(AsyncNetworkBackend):
    def __init__(self, policy: NetPolicy) -> None:
        self.policy = policy
        self._inner = AutoBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> AsyncNetworkStream:
        if host.lower().rstrip(".") in METADATA_HOSTS or not self.policy.host_allowed(host):
            raise httpcore2.ConnectError("Destination blocked by gateway network policy")
        try:
            addresses = await resolve(host, port)
        except OSError as exc:
            raise httpcore2.ConnectError("DNS resolution failed") from exc
        if not addresses:
            raise httpcore2.ConnectError("DNS resolution returned no addresses")
        try:
            for ip in addresses:  # every answer must be acceptable
                check_ip(ip, self.policy)
        except GatewayError as exc:
            raise httpcore2.ConnectError("Destination blocked by gateway network policy") from exc
        return await self._inner.connect_tcp(
            addresses[0], port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )

    async def connect_unix_socket(self, *a: Any, **k: Any) -> AsyncNetworkStream:
        raise httpcore2.ConnectError("Unix sockets are not permitted")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class ResponseTooLarge(httpx2.ReadError):
    """An upstream response body exceeded the gateway's limit: read is aborted before it is buffered or parsed."""


class _CappedStream(httpx2.AsyncByteStream):
    def __init__(self, inner: httpx2.AsyncByteStream, limit: int, request: httpx2.Request) -> None:
        self._inner, self._limit, self._request = inner, limit, request

    async def __aiter__(self) -> AsyncIterator[bytes]:
        seen = 0
        async for chunk in self._inner:
            seen += len(chunk)
            if seen > self._limit:
                raise ResponseTooLarge("Upstream response exceeds the size limit", request=self._request)
            yield chunk

    async def aclose(self) -> None:
        await self._inner.aclose()


class GuardedTransport(httpx2.AsyncHTTPTransport):
    def __init__(self, policy: NetPolicy, verify: Any = True,
                 max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES) -> None:
        super().__init__(verify=verify, trust_env=False)
        self.max_response_bytes = max_response_bytes
        ssl_context = self._pool._ssl_context  # reuse the context the parent built
        self._pool = httpcore2.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=20,
            max_keepalive_connections=0,  # no reuse: every request re-resolves and re-checks
            network_backend=GuardedNetworkBackend(policy),
        )

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        """Bound every response body. The MCP SDK reads JSON responses whole and parses them before the gateway's
        output limits apply, and a streamed (SSE) response could grow without end."""
        response = await super().handle_async_request(request)
        length = response.headers.get("content-length", "")
        if length.isdigit() and int(length) > self.max_response_bytes:
            await response.aclose()
            raise ResponseTooLarge("Upstream response exceeds the size limit", request=request)
        assert isinstance(response.stream, httpx2.AsyncByteStream)
        response.stream = _CappedStream(response.stream, self.max_response_bytes, request)
        return response


def guarded_client(
    policy: NetPolicy, *, headers: dict[str, str] | None = None, timeout: float = 30, verify: Any = True,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=GuardedTransport(policy, verify=verify, max_response_bytes=max_response_bytes),
        headers=headers or {},
        timeout=httpx2.Timeout(timeout, connect=min(timeout, 10)),
        follow_redirects=False,
        trust_env=False,
    )
