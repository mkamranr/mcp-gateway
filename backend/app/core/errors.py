"""Stable gateway error codes (spec §20) and their HTTP mapping."""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    INVALID_CREDENTIAL = "INVALID_CREDENTIAL"
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    TENANT_SUSPENDED = "TENANT_SUSPENDED"
    ACCESS_DENIED = "ACCESS_DENIED"
    CSRF_FAILED = "CSRF_FAILED"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    VERSION_CONFLICT = "VERSION_CONFLICT"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    BROAD_GRANT_CONFIRMATION_REQUIRED = "BROAD_GRANT_CONFIRMATION_REQUIRED"
    SERVER_DISABLED = "SERVER_DISABLED"
    TOOL_DISABLED = "TOOL_DISABLED"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    TOOL_SCHEMA_CHANGED = "TOOL_SCHEMA_CHANGED"
    TOOL_ARGUMENT_VALIDATION_FAILED = "TOOL_ARGUMENT_VALIDATION_FAILED"
    TOOL_OUTPUT_VALIDATION_FAILED = "TOOL_OUTPUT_VALIDATION_FAILED"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    CONCURRENCY_LIMIT_EXCEEDED = "CONCURRENCY_LIMIT_EXCEEDED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_INVALIDATED = "APPROVAL_INVALIDATED"
    APPROVAL_STATE_CONFLICT = "APPROVAL_STATE_CONFLICT"
    SEPARATION_OF_DUTIES = "SEPARATION_OF_DUTIES"
    UPSTREAM_BLOCKED = "UPSTREAM_BLOCKED"
    UPSTREAM_UNAVAILABLE = "UPSTREAM_UNAVAILABLE"
    UPSTREAM_TIMEOUT = "UPSTREAM_TIMEOUT"
    UPSTREAM_EXECUTION_FAILED = "UPSTREAM_EXECUTION_FAILED"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    GATEWAY_INTERNAL_ERROR = "GATEWAY_INTERNAL_ERROR"
    POLICY_MANAGED_BY_CODE = "POLICY_MANAGED_BY_CODE"


HTTP_STATUS: dict[ErrorCode, int] = {
    ErrorCode.AUTHENTICATION_REQUIRED: 401,
    ErrorCode.INVALID_CREDENTIAL: 401,
    ErrorCode.CREDENTIAL_REVOKED: 401,
    ErrorCode.CREDENTIAL_EXPIRED: 401,
    ErrorCode.TENANT_SUSPENDED: 403,
    ErrorCode.ACCESS_DENIED: 403,
    ErrorCode.CSRF_FAILED: 403,
    ErrorCode.SEPARATION_OF_DUTIES: 403,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.TOOL_NOT_FOUND: 404,
    ErrorCode.CONFLICT: 409,
    ErrorCode.VERSION_CONFLICT: 409,
    ErrorCode.APPROVAL_STATE_CONFLICT: 409,
    ErrorCode.SERVER_DISABLED: 409,
    ErrorCode.TOOL_DISABLED: 409,
    ErrorCode.TOOL_SCHEMA_CHANGED: 409,
    ErrorCode.APPROVAL_EXPIRED: 409,
    ErrorCode.APPROVAL_INVALIDATED: 409,
    ErrorCode.VALIDATION_FAILED: 422,
    ErrorCode.BROAD_GRANT_CONFIRMATION_REQUIRED: 422,
    ErrorCode.TOOL_ARGUMENT_VALIDATION_FAILED: 422,
    ErrorCode.TOOL_OUTPUT_VALIDATION_FAILED: 502,
    ErrorCode.PAYLOAD_TOO_LARGE: 413,
    ErrorCode.RATE_LIMIT_EXCEEDED: 429,
    ErrorCode.QUOTA_EXCEEDED: 429,
    ErrorCode.CONCURRENCY_LIMIT_EXCEEDED: 429,
    ErrorCode.APPROVAL_REQUIRED: 202,
    ErrorCode.APPROVAL_PENDING: 202,
    ErrorCode.UPSTREAM_BLOCKED: 422,
    ErrorCode.UPSTREAM_UNAVAILABLE: 502,
    ErrorCode.UPSTREAM_TIMEOUT: 504,
    ErrorCode.UPSTREAM_EXECUTION_FAILED: 502,
    ErrorCode.AUDIT_UNAVAILABLE: 503,
    ErrorCode.DEPENDENCY_UNAVAILABLE: 503,
    ErrorCode.GATEWAY_INTERNAL_ERROR: 500,
    ErrorCode.POLICY_MANAGED_BY_CODE: 409,
}

DEFAULT_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.AUTHENTICATION_REQUIRED: "Authentication is required.",
    ErrorCode.INVALID_CREDENTIAL: "The supplied credential is not valid.",
    ErrorCode.ACCESS_DENIED: "Access denied.",
    ErrorCode.NOT_FOUND: "Resource not found.",
    ErrorCode.TOOL_NOT_FOUND: "Tool not found.",
    ErrorCode.TOOL_ARGUMENT_VALIDATION_FAILED: "The supplied arguments do not match the tool schema.",
    ErrorCode.RATE_LIMIT_EXCEEDED: "Rate limit exceeded.",
    ErrorCode.QUOTA_EXCEEDED: "Quota exceeded.",
    ErrorCode.UPSTREAM_UNAVAILABLE: "The upstream MCP server is unavailable.",
    ErrorCode.UPSTREAM_TIMEOUT: "The upstream MCP server timed out.",
    ErrorCode.UPSTREAM_EXECUTION_FAILED: "The upstream tool reported an error.",
    ErrorCode.GATEWAY_INTERNAL_ERROR: "An internal error occurred.",
}


class GatewayError(Exception):
    """Raised by services; rendered by the API layer into the standard error envelope."""

    def __init__(
        self,
        code: ErrorCode,
        message: str | None = None,
        *,
        details: list[dict[str, Any]] | None = None,
        status: int | None = None,
        headers: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.message = message or DEFAULT_MESSAGES.get(code, code.value.replace("_", " ").capitalize() + ".")
        self.details = details or []
        self.status = status or HTTP_STATUS.get(code, 400)
        self.headers = headers or {}
        self.extra = extra or {}
        super().__init__(f"{code}: {self.message}")


def not_found(what: str = "Resource") -> GatewayError:
    return GatewayError(ErrorCode.NOT_FOUND, f"{what} not found.")


def denied(message: str = "Access denied.") -> GatewayError:
    return GatewayError(ErrorCode.ACCESS_DENIED, message)


# A database or cache that is unreachable, mid-election or mid-failover. These fail closed with a retryable 503
# (DEPENDENCY_UNAVAILABLE) rather than surfacing as an internal error.
def _dependency_errors() -> tuple[type[Exception], ...]:
    from pymongo.errors import ConnectionFailure, WaitQueueTimeoutError
    from redis.exceptions import ConnectionError as RedisConnectionError
    from redis.exceptions import ReadOnlyError
    from redis.exceptions import TimeoutError as RedisTimeoutError

    # ConnectionFailure covers AutoReconnect, NotPrimaryError, NetworkTimeout and ServerSelectionTimeoutError.
    # ReadOnlyError is a write that reached a Redis master that was just demoted to a replica.
    return (ConnectionFailure, WaitQueueTimeoutError, RedisConnectionError, RedisTimeoutError, ReadOnlyError)


DEPENDENCY_ERRORS = _dependency_errors()


def dependency_unavailable(exc: BaseException) -> GatewayError | None:
    """The fail-closed error for an unavailable MongoDB or Redis, or None if ``exc`` is something else."""
    if isinstance(exc, DEPENDENCY_ERRORS):
        return GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE, "A required service is temporarily unavailable. Retry shortly.",
                            headers={"Retry-After": "5"})
    return None
