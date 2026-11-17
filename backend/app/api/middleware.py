"""Request correlation, security headers, body-size limits and the error envelope."""

from __future__ import annotations

import re
import secrets
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import DEPENDENCY_ERRORS, ErrorCode, GatewayError, dependency_unavailable
from app.core.logging import get_logger, request_id_var

log = get_logger(__name__)
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{8,64}$")

SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    (b"cache-control", b"no-store"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
]


class CorrelationMiddleware:
    """Pure ASGI middleware (streaming safe): request ids, security headers, body size limit."""

    def __init__(self, app: ASGIApp, max_body: int, hsts: bool) -> None:
        self.app = app
        self.max_body = max_body
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        incoming = headers.get(b"x-request-id", b"").decode("latin-1")
        rid = incoming if REQUEST_ID_RE.match(incoming) else f"req_{secrets.token_hex(10)}"
        token = request_id_var.set(rid)
        scope.setdefault("state", {})["request_id"] = rid

        declared = headers.get(b"content-length")
        if declared and declared.isdigit() and int(declared) > self.max_body:
            await _send_json(send, 413, _envelope(ErrorCode.PAYLOAD_TOO_LARGE, "Request body too large.", rid))
            request_id_var.reset(token)
            return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body:
                    raise GatewayError(ErrorCode.PAYLOAD_TOO_LARGE, "Request body too large.")
            return message

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                hdrs = list(message.get("headers") or [])
                existing = {k.lower() for k, _ in hdrs}
                hdrs.append((b"x-request-id", rid.encode()))
                for k, v in SECURITY_HEADERS:
                    if k not in existing:
                        hdrs.append((k, v))
                if self.hsts:
                    hdrs.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                message["headers"] = hdrs
            await send(message)

        try:
            await self.app(scope, limited_receive, send_wrapper)
        finally:
            request_id_var.reset(token)


async def _send_json(send: Send, status: int, body: dict[str, Any]) -> None:
    import json

    data = json.dumps(body).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]})
    await send({"type": "http.response.body", "body": data})


def _envelope(code: ErrorCode | str, message: str, rid: str | None, details: list[Any] | None = None,
              extra: dict[str, Any] | None = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": str(code), "message": message, "request_id": rid, "details": details or []}
    if extra:
        err.update(extra)
    return {"error": err}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(GatewayError)
    async def gateway_error(request: Request, exc: GatewayError) -> JSONResponse:
        safe_extra = {k: v for k, v in exc.extra.items() if k in ("retry_after_seconds", "scope", "window",
                                                                   "approval_id", "status_url", "expires_at", "fingerprint",
                                                                   "bundle")}
        headers = dict(exc.headers or {})
        if exc.status == 401 and request.url.path.startswith("/api/v1/gateway/"):
            container = getattr(request.app.state, "container", None)
            if container is not None:
                headers["WWW-Authenticate"] = await container.agent_oauth.challenge(
                    "authorization" in request.headers)
        return JSONResponse(
            _envelope(exc.code, exc.message, request_id_var.get(), exc.details, safe_extra or None),
            status_code=exc.status, headers=headers or None,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = []
        for e in exc.errors()[:50]:
            loc = [str(x) for x in e.get("loc", []) if x not in ("body", "query", "path")]
            details.append({"field": ".".join(loc) or "$", "code": e.get("type", "invalid"),
                            "message": str(e.get("msg", ""))[:200]})
        return JSONResponse(_envelope(ErrorCode.VALIDATION_FAILED, "The request is invalid.", request_id_var.get(),
                                      details), status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: ErrorCode.NOT_FOUND, 405: ErrorCode.VALIDATION_FAILED, 401: ErrorCode.AUTHENTICATION_REQUIRED,
                403: ErrorCode.ACCESS_DENIED}.get(exc.status_code, ErrorCode.GATEWAY_INTERNAL_ERROR)
        msg = "Not found." if exc.status_code == 404 else str(exc.detail)[:200]
        return JSONResponse(_envelope(code, msg, request_id_var.get()), status_code=exc.status_code)

    # MongoDB or Redis unreachable, mid-election or mid-failover: fail closed with a retryable 503. Registered per
    # class so they are handled like GatewayError, not by the catch-all below.
    async def dependency_error(request: Request, exc: Exception) -> JSONResponse:
        log.warning("dependency_unavailable", error=type(exc).__name__, path=request.url.path)
        return await gateway_error(request, dependency_unavailable(exc) or GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE))

    for cls in DEPENDENCY_ERRORS:
        app.add_exception_handler(cls, dependency_error)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled_error", error=type(exc).__name__, path=request.url.path)
        return JSONResponse(_envelope(ErrorCode.GATEWAY_INTERNAL_ERROR, "An internal error occurred.",
                                      request_id_var.get()), status_code=500)
