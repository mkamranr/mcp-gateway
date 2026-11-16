"""Audit event encodings for SIEM forwarding: JSON, CEF (ArcSight/QRadar), RFC 5424 syslog framing."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from app.config import Settings

__version__ = Settings.model_fields["app_version"].default

VENDOR, PRODUCT = "MCP-Gateway", "MCP-Gateway"
_SEVERITY_RANK = {"info": 0, "warning": 1, "high": 2, "critical": 3}
_CEF_SEVERITY = {"info": 3, "warning": 5, "high": 8, "critical": 10}
_SYSLOG_SEVERITY = {"info": 6, "warning": 4, "high": 3, "critical": 2}  # informational, warning, error, critical
MAX_UDP_BYTES = 8192


def severity_at_least(event_severity: str | None, minimum: str) -> bool:
    return _SEVERITY_RANK.get(event_severity or "info", 0) >= _SEVERITY_RANK.get(minimum, 0)


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return value if isinstance(value, str) else None


def _plain(value: Any) -> Any:
    if isinstance(value, datetime):
        return _iso(value)
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    return value


def to_json(event: dict[str, Any]) -> dict[str, Any]:
    """Stable, documented schema (docs/siem.md). Never contains payloads or secrets: the audit log doesn't."""
    return {
        "@timestamp": _iso(event.get("timestamp")),
        "source": "mcp-gateway",
        "gateway_version": __version__,
        "event_id": event.get("event_id") or event.get("_id"),
        "event_type": event.get("event_type"),
        "severity": event.get("severity") or "info",
        "tenant_id": event.get("tenant_id"),
        "principal": _plain(event.get("principal")),
        "delegated_by_user_id": event.get("delegated_by_user_id"),
        "resource": _plain(event.get("resource") or {}),
        "decision": event.get("decision"),
        "reason_code": event.get("reason_code"),
        "status": event.get("status"),
        "policy_ids": event.get("policy_ids") or [],
        "request_id": event.get("request_id"),
        "invocation_id": event.get("invocation_id"),
        "approval_id": event.get("approval_id"),
        "duration_ms": event.get("duration_ms"),
        "input_hash": event.get("input_hash"),
        "output_hash": event.get("output_hash"),
        "metadata": _plain(event.get("metadata") or {}),
    }


def _cef_header(value: Any) -> str:
    return str(value if value is not None else "").replace("\\", "\\\\").replace("|", "\\|").replace(
        "\r", " ").replace("\n", " ")


def _cef_ext(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def to_cef(event: dict[str, Any]) -> str:
    """CEF:0 (Micro Focus ArcSight CEF Implementation Standard): header fields escape | and \\; extension
    values escape =, \\ and newlines."""
    j = to_json(event)
    sev = j["severity"]
    principal = j["principal"] or {}
    meta = j["metadata"] or {}
    ext: list[tuple[str, Any]] = []
    ts = event.get("timestamp")
    if isinstance(ts, datetime):
        ext.append(("rt", int((ts if ts.tzinfo else ts.replace(tzinfo=UTC)).timestamp() * 1000)))
    ext += [("externalId", j["event_id"]), ("cs1Label", "tenantId"), ("cs1", j["tenant_id"])]
    if principal.get("name") or principal.get("id"):
        ext += [("suser", principal.get("name") or principal.get("id")), ("suid", principal.get("id")),
                ("cs2Label", "principalType"), ("cs2", principal.get("type"))]
    if isinstance(meta.get("source_ip"), str):
        ext.append(("src", meta["source_ip"]))
    if j["status"]:
        ext.append(("outcome", j["status"]))
    if j["decision"]:
        ext.append(("act", j["decision"]))
    if j["reason_code"]:
        ext.append(("reason", j["reason_code"]))
    if j["request_id"]:
        ext += [("cs3Label", "requestId"), ("cs3", j["request_id"])]
    if j["invocation_id"]:
        ext += [("cs4Label", "invocationId"), ("cs4", j["invocation_id"])]
    if j["approval_id"]:
        ext += [("cs5Label", "approvalId"), ("cs5", j["approval_id"])]
    if j["resource"]:
        ext += [("cs6Label", "resource"), ("cs6", json.dumps(j["resource"], separators=(",", ":"))[:1000])]
    if meta:
        ext.append(("msg", json.dumps(meta, separators=(",", ":"), default=str)[:2000]))
    head = "|".join(_cef_header(x) for x in ("CEF:0", VENDOR, PRODUCT, __version__, j["event_type"],
                                             j["event_type"], _CEF_SEVERITY.get(sev, 3)))
    return head + "|" + " ".join(f"{k}={_cef_ext(v)}" for k, v in ext if v is not None and v != "")


def encode(event: dict[str, Any], fmt: str) -> str:
    return to_cef(event) if fmt == "cef" else json.dumps(to_json(event), separators=(",", ":"), default=str)


def _token(value: str, limit: int) -> str:
    """RFC 5424 header fields: printable US-ASCII without spaces, or "-"."""
    out = "".join(c for c in value if 33 <= ord(c) <= 126)[:limit]
    return out or "-"


def syslog_message(event: dict[str, Any], fmt: str, *, facility: int, hostname: str) -> bytes:
    """One RFC 5424 message (no framing). MSG is the JSON or CEF encoding of the event."""
    sev = _SYSLOG_SEVERITY.get(event.get("severity") or "info", 6)
    ts = _iso(event.get("timestamp")) or "-"
    head = (f"<{facility * 8 + sev}>1 {ts} {_token(hostname, 255)} mcp-gateway - "
            f"{_token(str(event.get('event_type') or ''), 32)} -")
    return (head + " " + encode(event, fmt)).encode("utf-8")


def frame_tcp(message: bytes) -> bytes:
    """RFC 6587 octet counting (also RFC 5425 for TLS): "<length> <message>"."""
    return str(len(message)).encode() + b" " + message
