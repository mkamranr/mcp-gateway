"""SIEM forwarding configuration (Phase 6): audit events streamed to syslog or an HTTP collector."""

from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from app.models.registry import Strict

SEVERITIES = ("info", "warning", "high", "critical")
EVENT_PREFIX = r"^[a-z0-9_.*-]{1,100}$"
HEADER_NAME = r"^[A-Za-z0-9-]{1,64}$"


class SiemConfigBase(Strict):
    enabled: bool = False
    transport: Literal["syslog_tcp", "syslog_tls", "syslog_udp", "http"] = "syslog_tls"
    # syslog
    host: str = Field(default="", max_length=253)
    port: int = Field(default=6514, ge=1, le=65535)
    syslog_facility: int = Field(default=13, ge=0, le=23)  # 13 = "log audit" (RFC 5424)
    # http
    url: str = Field(default="", max_length=1000)
    http_body: Literal["ndjson", "json_array", "splunk_hec"] = "ndjson"
    http_auth_header: str = Field(default="Authorization", pattern=HEADER_NAME)
    # payload
    format: Literal["json", "cef"] = "json"
    min_severity: Literal["info", "warning", "high", "critical"] = "info"
    event_types: list[str] = Field(default_factory=list, max_length=50)  # prefixes, e.g. "auth." ; empty = all
    # TLS (syslog_tls and https)
    tls_ca_pem: str = Field(default="", max_length=100_000)  # empty = system trust store
    tls_verify_hostname: bool = True
    batch_size: int = Field(default=200, ge=1, le=1000)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip()
        if v and any(c in v for c in "/:@ ?#") and not v.startswith("["):
            raise ValueError("Host must be a host name or IP address (put the port in the port field)")
        return v

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        v = v.strip()
        if v:
            parts = urlsplit(v)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValueError("URL must be an absolute http(s) URL")
            if parts.username or parts.password:
                raise ValueError("Put credentials in the auth header, not in the URL")
        return v

    @field_validator("event_types")
    @classmethod
    def _types(cls, v: list[str]) -> list[str]:
        import re

        out = sorted({x.strip() for x in v if x.strip()})
        for x in out:
            if not re.match(EVENT_PREFIX, x):
                raise ValueError(f"Invalid event type prefix: {x}")
        return out

    @field_validator("tls_ca_pem")
    @classmethod
    def _pem(cls, v: str) -> str:
        v = v.strip()
        if v and "-----BEGIN CERTIFICATE-----" not in v:
            raise ValueError("CA bundle must be PEM (-----BEGIN CERTIFICATE-----)")
        return v

    @model_validator(mode="after")
    def _complete(self) -> SiemConfigBase:
        if self.enabled:
            if self.transport == "http" and not self.url:
                raise ValueError("A collector URL is required for HTTP forwarding")
            if self.transport != "http" and not self.host:
                raise ValueError("A syslog host is required")
        if self.http_body == "splunk_hec" and self.format != "json":
            raise ValueError("Splunk HEC requires the JSON format")
        if not self.tls_verify_hostname and not self.tls_ca_pem:
            # Without a pinned CA, any publicly trusted certificate for any name would be accepted.
            raise ValueError("Turning off host name verification requires a CA bundle (tls_ca_pem)")
        return self


class SiemConfigUpdate(SiemConfigBase):
    # Write-only value of the HTTP auth header (e.g. "Splunk <token>", "Bearer <token>"). Omit (null) to keep
    # the stored value; "" clears it.
    http_auth_value: str | None = Field(default=None, max_length=4096, repr=False)

    @field_validator("http_auth_value")
    @classmethod
    def _auth_value(cls, v: str | None) -> str | None:
        # An HTTP header value: visible ASCII and spaces only (anything else can't be sent and would stop forwarding).
        if v and not all(0x20 <= ord(c) <= 0x7E for c in v):
            raise ValueError("The auth value may contain printable ASCII characters only")
        return v
