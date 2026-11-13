"""Application configuration.

All settings come from environment variables (or a `.env` file). Secrets may also be supplied
as mounted files via ``<NAME>_FILE`` (e.g. ``SESSION_SECRET_FILE=/run/secrets/session``).
Startup fails fast on invalid or placeholder secrets in production.
"""

from __future__ import annotations

import base64
import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

PLACEHOLDER_MARKERS = ("replace-with", "changeme", "change-me", "example", "placeholder")
SECRET_FIELDS = ("session_secret", "data_encryption_key", "api_key_hash_pepper", "bootstrap_admin_password")


def _read_secret_files() -> None:
    """Support Docker/K8s style mounted secrets: FOO_FILE=/path -> FOO=<contents>."""
    for key, value in list(os.environ.items()):
        if key.endswith("_FILE") and value and key[:-5] not in os.environ:
            path = Path(value)
            if path.is_file():
                os.environ[key[:-5]] = path.read_text(encoding="utf-8").strip()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: Literal["development", "test", "production"] = "production"
    app_host: str = "0.0.0.0"
    app_port: int = 8080
    log_level: str = "INFO"
    app_version: str = "0.1.0"

    mongodb_uri: str = "mongodb://mongodb:27017"
    mongodb_database: str = "mcp_gateway"
    redis_url: str = "redis://redis:6379/0"

    session_secret: str = Field(default="", repr=False)
    data_encryption_key: str = Field(default="", repr=False)
    api_key_hash_pepper: str = Field(default="", repr=False)
    session_ttl_minutes: int = 480
    session_idle_minutes: int = 60
    cookie_secure: bool = True

    public_base_url: str = "https://mcp-gateway.internal"
    mcp_endpoint_path: str = "/mcp"

    default_tool_timeout_seconds: float = 30
    max_tool_timeout_seconds: float = 300
    max_input_bytes: int = 1_048_576
    max_output_bytes: int = 4_194_304
    max_json_depth: int = 32
    max_string_length: int = 100_000
    max_array_length: int = 10_000
    max_concurrent_calls_per_agent: int = 10
    max_request_body_bytes: int = 2_097_152

    audit_required_for_execution: bool = True
    audit_retention_days: int = 365
    audit_export_max_rows: int = 50_000

    allow_private_upstream_networks: bool = False
    upstream_host_allowlist: Annotated[list[str], NoDecode] = Field(default_factory=list)  # comma-separated in env
    stdio_executable_allowlist: Annotated[list[str], NoDecode] = Field(default_factory=list)  # comma-separated in env
    cors_allowed_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)  # comma-separated in env

    approval_default_ttl_minutes: int = 60
    redis_fail_open_dev: bool = False
    login_max_attempts_per_window: int = 10
    login_window_seconds: int = 300

    bootstrap_admin_username: str = ""
    bootstrap_admin_password: str = Field(default="", repr=False)
    bootstrap_tenant_slug: str = "default"

    worker_poll_interval_seconds: float = 2.0
    health_check_interval_seconds: float = 60.0

    @field_validator(
        "upstream_host_allowlist", "stdio_executable_allowlist", "cors_allowed_origins", mode="before"
    )
    @classmethod
    def _split_csv(cls, v: object) -> object:
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    @model_validator(mode="after")
    def _validate_secrets(self) -> Settings:
        if self.app_env == "production":
            for name in ("session_secret", "data_encryption_key", "api_key_hash_pepper"):
                value = getattr(self, name)
                if not value or len(value) < 32:
                    raise ValueError(f"{name.upper()} must be set to at least 32 characters in production")
                if any(m in value.lower() for m in PLACEHOLDER_MARKERS):
                    raise ValueError(f"{name.upper()} still contains a placeholder value")
            if self.bootstrap_admin_password and len(self.bootstrap_admin_password) < 12:
                raise ValueError("BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters")
            if "*" in self.cors_allowed_origins:
                raise ValueError("Wildcard CORS origins are not permitted")
        if self.data_encryption_key:
            self.encryption_key_bytes()  # raises if malformed
        elif self.app_env == "production":
            raise ValueError("DATA_ENCRYPTION_KEY is required")
        return self

    def encryption_key_bytes(self) -> bytes:
        """DATA_ENCRYPTION_KEY is a urlsafe-base64 encoded 32-byte AES-256 key."""
        try:
            raw = base64.urlsafe_b64decode(self.data_encryption_key + "=" * (-len(self.data_encryption_key) % 4))
        except Exception as exc:  # noqa: BLE001
            raise ValueError("DATA_ENCRYPTION_KEY must be urlsafe base64") from exc
        if len(raw) != 32:
            raise ValueError("DATA_ENCRYPTION_KEY must decode to exactly 32 bytes")
        return raw

    @property
    def is_dev(self) -> bool:
        return self.app_env in ("development", "test")


@lru_cache
def get_settings() -> Settings:
    _read_secret_files()
    return Settings()
