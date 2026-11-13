"""Structured JSON logging with secret scrubbing and request correlation."""

from __future__ import annotations

import logging
import re
import sys
from contextvars import ContextVar
from typing import Any

import structlog

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

SENSITIVE_KEYS = re.compile(
    r"(pass(word)?|secret|token|authorization|api[_-]?key|cookie|credential|private[_-]?key|pepper)", re.I
)
SECRET_VALUE = re.compile(r"(mgw_(live|test)_[A-Za-z0-9]+_)[A-Za-z0-9_\-]+|(Bearer\s+)[^\s\"']+", re.I)
REDACTED = "[REDACTED]"


def scrub(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        return value
    if isinstance(value, dict):
        return {
            k: (REDACTED if isinstance(k, str) and SENSITIVE_KEYS.search(k) else scrub(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [scrub(v, depth + 1) for v in value]
    if isinstance(value, str):
        return SECRET_VALUE.sub(lambda m: (m.group(1) or m.group(3) or "") + REDACTED, value)
    return value


def _scrub_processor(_: Any, __: str, event_dict: Any) -> Any:
    return scrub(event_dict)  # type: ignore[no-any-return]


def _add_request_id(_: Any, __: str, event_dict: Any) -> Any:
    rid = request_id_var.get()
    if rid and "request_id" not in event_dict:
        event_dict["request_id"] = rid
    return event_dict


def configure_logging(level: str = "INFO", json_output: bool = True) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(stream=sys.stdout, level=lvl, format="%(message)s")
    for noisy in ("pymongo", "httpx", "httpx2", "httpcore", "mcp", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _add_request_id,
            _scrub_processor,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer() if json_output else structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(lvl),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> Any:
    return structlog.get_logger(name)
