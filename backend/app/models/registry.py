"""Request/response models for MCP servers and tools (spec §10)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

RiskLevel = Literal["low", "medium", "high", "critical"]
Transport = Literal["streamable_http", "stdio"]
AuthMode = Literal["none", "bearer", "header", "env"]
Environment = Literal["development", "test", "production"]
ApproverRole = Literal["approver", "security_admin", "tenant_admin", "platform_admin"]
DEFAULT_APPROVER_ROLES: tuple[ApproverRole, ...] = ("approver", "security_admin", "tenant_admin")

ALIAS_PATTERN = r"^[a-z][a-z0-9-]{0,30}[a-z0-9]$"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SecretInput(Strict):
    token: str | None = Field(default=None, max_length=8192)
    header_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9-]{1,64}$")
    env: dict[str, str] | None = None


class ClientCertificateInput(Strict):
    """The client certificate the gateway presents to an upstream that requires mTLS. ``key_pem`` is
    write-only: it is stored encrypted and never returned."""

    cert_pem: str = Field(min_length=1, max_length=65_536, description="Certificate, optionally followed by chain")
    key_pem: str = Field(min_length=1, max_length=16_384, repr=False, description="Unencrypted PEM private key")


class ServerBase(Strict):
    description: str = Field(default="", max_length=2000)
    environment: Environment = "production"
    tags: list[str] = Field(default_factory=list, max_length=20)
    owner: str | None = Field(default=None, max_length=200)
    endpoint: str | None = Field(default=None, max_length=2048)
    command: str | None = Field(default=None, max_length=1024)
    args: list[str] = Field(default_factory=list, max_length=64)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = Field(default=None, max_length=1024)
    verify_tls: bool = True
    tls_ca_pem: str | None = Field(default=None, max_length=262_144,
                                   description="CA bundle for the upstream's certificate; default: system CAs")
    authentication_mode: AuthMode = "none"
    connection_timeout_seconds: float = Field(default=10, ge=1, le=120)
    request_timeout_seconds: float = Field(default=30, ge=1, le=300)
    max_concurrent_calls: int = Field(default=10, ge=1, le=200)
    allow_private_network: bool = False


class ServerCreate(ServerBase):
    name: str = Field(min_length=2, max_length=100)
    alias: str = Field(pattern=ALIAS_PATTERN, description="Namespace used in gateway tool names")
    transport: Transport
    enabled: bool = True
    secret: SecretInput | None = None
    client_certificate: ClientCertificateInput | None = None

    @model_validator(mode="after")
    def _check_transport(self) -> ServerCreate:
        if self.transport != "streamable_http" and (self.client_certificate or self.tls_ca_pem):
            raise ValueError("TLS settings apply to streamable_http servers only")
        if self.transport == "streamable_http" and not self.endpoint:
            raise ValueError("endpoint is required for streamable_http servers")
        if self.transport == "stdio" and not self.command:
            raise ValueError("command is required for stdio servers")
        if self.authentication_mode != "none" and not self.secret:
            raise ValueError("secret is required when authentication_mode is not 'none'")
        return self


class ServerUpdate(Strict):
    version: int
    name: str | None = Field(default=None, min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    environment: Environment | None = None
    tags: list[str] | None = None
    owner: str | None = None
    endpoint: str | None = Field(default=None, max_length=2048)
    command: str | None = None
    args: list[str] | None = None
    env: dict[str, str] | None = None
    cwd: str | None = None
    verify_tls: bool | None = None
    tls_ca_pem: str | None = Field(default=None, max_length=262_144, description="Empty string removes it")
    authentication_mode: AuthMode | None = None
    secret: SecretInput | None = None
    client_certificate: ClientCertificateInput | None = None
    remove_client_certificate: bool = False
    connection_timeout_seconds: float | None = Field(default=None, ge=1, le=120)
    request_timeout_seconds: float | None = Field(default=None, ge=1, le=300)
    max_concurrent_calls: int | None = Field(default=None, ge=1, le=200)
    allow_private_network: bool | None = None
    enabled: bool | None = None


class ApprovalPolicyConfig(Strict):
    required_approvals: Literal[1, 2] = 1
    approver_roles: list[ApproverRole] = Field(default_factory=lambda: list(DEFAULT_APPROVER_ROLES), min_length=1,
                                               max_length=5)
    allow_self_approval: bool = False
    ttl_minutes: int = Field(default=60, ge=1, le=10080)
    require_comment_on_reject: bool = True
    require_comment_on_approve: bool = False
    approver_groups: list[str] = Field(default_factory=list, max_length=50)
    escalate_after_minutes: int | None = Field(default=None, ge=1, le=10080)
    escalation_roles: list[Literal["approver", "security_admin", "tenant_admin", "platform_admin"]] = Field(
        default_factory=list, max_length=4)
    remind_before_expiry_minutes: int | None = Field(default=None, ge=1, le=10080)


class ApprovalConfig(Strict):
    required: bool = False
    policy: ApprovalPolicyConfig = Field(default_factory=ApprovalPolicyConfig)


class ToolLimits(Strict):
    per_minute: int | None = Field(default=None, ge=1)
    per_hour: int | None = Field(default=None, ge=1)
    per_day: int | None = Field(default=None, ge=1)
    per_month: int | None = Field(default=None, ge=1)
    concurrency: int | None = Field(default=None, ge=1, le=1000)
    cost_units: int = Field(default=1, ge=1, le=1000)


class OutputControls(Strict):
    validate_output: bool = True
    redact_fields: list[str] = Field(default_factory=list, max_length=100)


class ToolUpdate(Strict):
    version: int
    display_name: str | None = Field(default=None, max_length=200)
    description_override: str | None = Field(default=None, max_length=4000)
    risk_level: RiskLevel | None = None
    enabled: bool | None = None
    approval: ApprovalConfig | None = None
    timeout_seconds: float | None = Field(default=None, ge=1, le=300)
    max_input_bytes: int | None = Field(default=None, ge=16)
    max_output_bytes: int | None = Field(default=None, ge=16)
    limits: ToolLimits | None = None
    output: OutputControls | None = None
    tags: list[str] | None = None
    owner: str | None = None
    acknowledge_schema_change: bool | None = None

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str] | None) -> list[str] | None:
        if v is not None and (len(v) > 20 or any(len(t) > 50 for t in v)):
            raise ValueError("At most 20 tags of up to 50 characters")
        return v


def server_to_api(doc: dict[str, Any]) -> dict[str, Any]:
    """Serialize a server document without secret material."""
    cfg = doc.get("connection_config", {})
    return {
        "id": doc["_id"],
        "tenant_id": doc["tenant_id"],
        "name": doc["name"],
        "alias": doc["alias"],
        "description": doc.get("description", ""),
        "transport": doc["transport"],
        "endpoint": cfg.get("endpoint"),
        "command": cfg.get("command"),
        "args": cfg.get("args", []),
        "env_keys": sorted((cfg.get("env") or {}).keys()),
        "cwd": cfg.get("cwd"),
        "verify_tls": cfg.get("verify_tls", True),
        "tls": {"ca_certificates": cfg.get("tls_ca_info") or [], "client_certificate": cfg.get("tls_client_info")},
        "enabled": doc.get("enabled", False),
        "archived": doc.get("archived", False),
        "environment": doc.get("environment"),
        "tags": doc.get("tags", []),
        "owner": doc.get("owner"),
        "authentication_mode": doc.get("authentication_mode", "none"),
        "has_secret": bool(doc.get("secret_ref")),
        "connection_timeout_seconds": doc.get("connection_timeout_seconds"),
        "request_timeout_seconds": doc.get("request_timeout_seconds"),
        "max_concurrent_calls": doc.get("max_concurrent_calls"),
        "allow_private_network": doc.get("allow_private_network", False),
        "health_status": doc.get("health_status", "unknown"),
        "last_health_check_at": doc.get("last_health_check_at"),
        "last_health_error": doc.get("last_health_error"),
        "last_latency_ms": doc.get("last_latency_ms"),
        "health_history": doc.get("health_history", [])[-20:],
        "discovery": doc.get("discovery", {}),
        "tool_count": doc.get("tool_count", 0),
        "enabled_tool_count": doc.get("enabled_tool_count", 0),
        "version": doc.get("version", 1),
        "created_at": doc.get("created_at"),
        "updated_at": doc.get("updated_at"),
        "created_by": doc.get("created_by"),
        "updated_by": doc.get("updated_by"),
    }


def tool_to_api(doc: dict[str, Any], server: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": doc["_id"],
        "tenant_id": doc["tenant_id"],
        "server_id": doc["server_id"],
        "server_name": server.get("name") if server else doc.get("server_name"),
        "upstream_name": doc["upstream_name"],
        "gateway_name": doc["gateway_name"],
        "display_name": doc.get("display_name") or doc["upstream_name"],
        "description": doc.get("description_override") or doc.get("description", ""),
        "upstream_description": doc.get("description", ""),
        "input_schema": doc.get("input_schema", {}),
        "output_schema": doc.get("output_schema"),
        "annotations": doc.get("annotations"),
        "schema_hash": doc.get("schema_hash"),
        "schema_version": doc.get("schema_version", 1),
        "risk_level": doc.get("risk_level"),
        "enabled": doc.get("enabled", False),
        "review_status": doc.get("review_status", "pending_review"),
        "available": doc.get("available", True),
        "approval": doc.get("approval", ApprovalConfig().model_dump()),
        "timeout_seconds": doc.get("timeout_seconds"),
        "max_input_bytes": doc.get("max_input_bytes"),
        "max_output_bytes": doc.get("max_output_bytes"),
        "limits": doc.get("limits", ToolLimits().model_dump()),
        "output": doc.get("output", OutputControls().model_dump()),
        "tags": doc.get("tags", []),
        "owner": doc.get("owner"),
        "last_discovered_at": doc.get("last_discovered_at"),
        "version": doc.get("version", 1),
        "created_at": doc.get("created_at"),
        "updated_at": doc.get("updated_at"),
    }
