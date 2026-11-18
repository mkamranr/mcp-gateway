"""Client addresses behind the reverse proxy.

The gateway sits behind nginx (Compose, Helm), which overwrites ``X-Forwarded-For`` with the address it saw. Those
headers are believed only when the TCP peer is a configured proxy (``TRUSTED_PROXIES``, plus
``MTLS_TRUSTED_PROXIES``); from anyone else they are ignored, so a caller reaching the API port directly can't
pick their own address (and with it a source-network policy, a login throttle bucket or an audit record).

The TCP peer itself is kept in the scope under ``PEER_KEY``: the agent client-certificate header is accepted only
from the proxy that did the TLS handshake, which is decided on the peer, never on a forwarded address.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.client_certs import address_in

PEER_KEY = "mgw.peer"


def peer_address(scope: Scope) -> str | None:
    """The address of the TCP peer (the proxy, when there is one)."""
    if PEER_KEY in scope:
        return scope[PEER_KEY]  # type: ignore[no-any-return]
    client = scope.get("client")
    return client[0] if client else None


class TrustedProxyMiddleware:
    def __init__(self, app: ASGIApp, trusted: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> None:
        self.app = app
        self.trusted = list(trusted)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            client = scope.get("client")
            peer = client[0] if client else None
            scope[PEER_KEY] = peer
            if peer and address_in(peer, self.trusted):
                self._apply_forwarded(scope)
        await self.app(scope, receive, send)

    @staticmethod
    def _apply_forwarded(scope: Scope) -> None:
        forwarded_for = forwarded_proto = None
        for name, value in scope.get("headers") or []:
            if name == b"x-forwarded-for":
                forwarded_for = value.decode("latin-1")
            elif name == b"x-forwarded-proto":
                forwarded_proto = value.decode("latin-1")
        if forwarded_for:
            # The right-most entry is the one our proxy added (nginx overwrites the header, so it's the only one);
            # anything to its left came from the client and proves nothing.
            candidate = forwarded_for.split(",")[-1].strip()
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                pass
            else:
                scope["client"] = (str(ip), 0)
        if forwarded_proto and forwarded_proto.strip().lower() in ("http", "https"):
            scope["scheme"] = forwarded_proto.strip().lower()
