"""Configuration parsing from the environment (spec §26)."""

import base64
import os

import pytest

from app.config import Settings


def test_comma_separated_allowlists_from_env(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("UPSTREAM_HOST_ALLOWLIST", "hr.internal, *.corp.example")
    monkeypatch.setenv("STDIO_EXECUTABLE_ALLOWLIST", "/usr/local/bin/hr-mcp")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://console.example.org")
    s = Settings(_env_file=None)
    assert s.upstream_host_allowlist == ["hr.internal", "*.corp.example"]
    assert s.stdio_executable_allowlist == ["/usr/local/bin/hr-mcp"]
    assert s.cors_allowed_origins == ["https://console.example.org"]


def test_production_rejects_wildcard_cors_and_placeholders(monkeypatch):
    good = {"APP_ENV": "production", "SESSION_SECRET": "s" * 40, "API_KEY_HASH_PEPPER": "p" * 40,
            "DATA_ENCRYPTION_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode()}
    for k, v in good.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "*")
    with pytest.raises(ValueError, match="Wildcard"):
        Settings(_env_file=None)
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "")
    monkeypatch.setenv("SESSION_SECRET", "replace-with-a-long-random-value-xxxxxxxx")
    with pytest.raises(ValueError, match="placeholder"):
        Settings(_env_file=None)
