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


def test_env_comment_mistaken_for_a_value_is_rejected():
    import pytest as _pytest

    with _pytest.raises(ValueError, match="comment"):
        Settings._split_csv("# e.g. hr-mcp.internal.example,*.mcp.internal.example")
    assert Settings._split_csv("") == []
    assert Settings._split_csv("a.example, *.b.example") == ["a.example", "*.b.example"]


def test_redis_sentinel_settings_and_client(monkeypatch):
    from redis.asyncio.sentinel import SentinelConnectionPool

    from app.db import create_redis

    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("REDIS_URL", "rediss://:s3cret%40pw@ignored-host:6379/2")
    monkeypatch.setenv("REDIS_SENTINELS", "sentinel-1:26379, sentinel-2:26379,10.0.0.3:26380")
    monkeypatch.setenv("REDIS_SENTINEL_MASTER", "gateway")
    s = Settings(_env_file=None)
    assert s.redis_sentinels == ["sentinel-1:26379", "sentinel-2:26379", "10.0.0.3:26380"]
    client = create_redis(s)  # builds the client; connects lazily
    pool = client.connection_pool
    assert isinstance(pool, SentinelConnectionPool) and pool.service_name == "gateway"
    kw = pool.connection_kwargs
    assert kw["password"] == "s3cret@pw" and kw["db"] == 2 and kw["decode_responses"] is True
    assert [(h, p) for h, p in ((c.connection_pool.connection_kwargs["host"], c.connection_pool.connection_kwargs["port"])
                                for c in pool.sentinel_manager.sentinels)] == [
        ("sentinel-1", 26379), ("sentinel-2", 26379), ("10.0.0.3", 26380)]


def test_redis_without_sentinels_uses_the_url(monkeypatch):
    from app.db import create_redis

    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("REDIS_URL", "redis://:pw@redis-host:6390/1")
    kw = create_redis(Settings(_env_file=None)).connection_pool.connection_kwargs
    assert (kw["host"], kw["port"], kw["db"]) == ("redis-host", 6390, 1)


@pytest.mark.parametrize("bad", ["sentinel-1", "sentinel-1:port", ":26379"])
def test_malformed_sentinel_entries_are_rejected(monkeypatch, bad):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("REDIS_SENTINELS", bad)
    with pytest.raises(ValueError, match="host:port"):
        Settings(_env_file=None)
