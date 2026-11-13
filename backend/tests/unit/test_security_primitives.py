"""Crypto, API keys, input/output validation, log scrubbing, SSRF guard and stdio validation."""

import base64
import os

import httpcore2
import pytest

from app.config import Settings
from app.core.crypto import (
    Encryptor,
    generate_api_key,
    hash_api_key,
    hash_password,
    split_api_key,
    verify_password,
)
from app.core.errors import ErrorCode, GatewayError
from app.core.ids import sha256_hex
from app.core.logging import scrub
from app.mcp.adapters.base import UpstreamError
from app.mcp.adapters.sdk import validate_stdio_config
from app.mcp.net_guard import GuardedNetworkBackend, NetPolicy, check_ip, validate_url
from app.services.validation_service import ValidationService

SETTINGS = Settings(app_env="test", data_encryption_key=base64.urlsafe_b64encode(os.urandom(32)).decode())


# ------------------------------------------------------------------ crypto
def test_encryption_roundtrip_and_associated_data_binding():
    e = Encryptor(os.urandom(32))
    ct = e.encrypt(b"secret", "tenant-a:apr_1")
    assert e.decrypt(ct, "tenant-a:apr_1") == b"secret"
    with pytest.raises(Exception):
        e.decrypt(ct, "tenant-b:apr_1")  # moved to another tenant/record -> fails
    assert e.encrypt(b"secret", "x") != e.encrypt(b"secret", "x")  # random nonce


def test_password_hashing_argon2id():
    h = hash_password("correct horse battery")
    assert h.startswith("$argon2id$")
    assert verify_password("correct horse battery", h)
    assert not verify_password("wrong", h)
    assert not verify_password("anything", None)


def test_api_key_format_and_hash():
    k = generate_api_key("pepper")
    assert k.secret.startswith(k.key_prefix + "_") and k.key_prefix.startswith("mgw_live_")
    assert split_api_key(k.secret) == k.key_prefix
    assert hash_api_key(k.secret, "pepper") == k.secret_hash
    assert hash_api_key(k.secret, "other-pepper") != k.secret_hash
    assert k.secret not in k.secret_hash
    for bad in ["", "mgw_live_xyz", "Bearer abc", "mgw_live_zzzzzzzzzzzzzzzz_" + "a" * 30, "abc_live_0123456789abcdef_" + "a" * 30]:
        assert split_api_key(bad) is None


def test_canonical_hash_is_order_independent():
    assert sha256_hex({"a": 1, "b": [1, 2]}) == sha256_hex({"b": [1, 2], "a": 1})
    assert sha256_hex({"a": 1}) != sha256_hex({"a": 2})


def test_settings_reject_placeholder_secrets_in_production():
    with pytest.raises(ValueError):
        Settings(app_env="production", session_secret="replace-with-random-secret" * 2,
                 data_encryption_key=base64.urlsafe_b64encode(os.urandom(32)).decode(), api_key_hash_pepper="x" * 40)
    with pytest.raises(ValueError):
        Settings(app_env="production", session_secret="a" * 40, data_encryption_key="",
                 api_key_hash_pepper="x" * 40)
    with pytest.raises(ValueError):
        Settings(app_env="production", session_secret="a" * 40, api_key_hash_pepper="x" * 40,
                 data_encryption_key=base64.urlsafe_b64encode(os.urandom(32)).decode(), cors_allowed_origins="*")


# ------------------------------------------------------------------ log scrubbing
def test_scrub_removes_secrets():
    event = {"authorization": "Bearer abc", "password": "p", "nested": {"api_key": "k", "ok": "fine"},
             "msg": "used key mgw_live_0123456789abcdef_SECRETPART and Bearer tok123"}
    out = scrub(event)
    assert out["authorization"] == "[REDACTED]" and out["password"] == "[REDACTED]"
    assert out["nested"] == {"api_key": "[REDACTED]", "ok": "fine"}
    assert "SECRETPART" not in out["msg"] and "tok123" not in out["msg"]


# ------------------------------------------------------------------ input validation
TOOL = {"input_schema": {"type": "object", "properties": {"id": {"type": "string", "maxLength": 10},
                                                          "n": {"type": "integer", "minimum": 0, "maximum": 5}},
                         "required": ["id"]}}


def _code(fn):
    with pytest.raises(GatewayError) as ei:
        fn()
    return ei.value


def test_valid_input_passes():
    assert ValidationService(SETTINGS).validate_input(TOOL, {"id": "abc", "n": 3}) > 0


@pytest.mark.parametrize("args,code,field", [
    ({}, "required", "id"),
    ({"id": "x", "extra": 1}, "unknown_field", "$"),
    ({"id": "x", "n": 9}, "maximum", "n"),
    ({"id": 5}, "type", "id"),
    ({"id": "a" * 11}, "maxLength", "id"),
])
def test_invalid_input_rejected(args, code, field):
    err = _code(lambda: ValidationService(SETTINGS).validate_input(TOOL, args))
    assert err.code == ErrorCode.TOOL_ARGUMENT_VALIDATION_FAILED
    assert err.details[0]["code"] == code and err.details[0]["field"] == field


def test_deeply_nested_and_oversized_payloads_rejected():
    deep: dict = {}
    cur = deep
    for _ in range(50):
        cur["a"] = {}
        cur = cur["a"]
    open_tool = {"input_schema": {"type": "object"}}
    v = ValidationService(SETTINGS)
    assert _code(lambda: v.validate_input(open_tool, deep)).details[0]["code"] == "max_depth"
    big = {"x": "a" * (SETTINGS.max_input_bytes + 10)}
    assert _code(lambda: v.validate_input(open_tool, big)).code == ErrorCode.PAYLOAD_TOO_LARGE
    assert _code(lambda: v.validate_input(open_tool, {"x": float("nan")})).code == ErrorCode.TOOL_ARGUMENT_VALIDATION_FAILED
    assert _code(lambda: v.validate_input(open_tool, ["not", "an", "object"])).code == ErrorCode.TOOL_ARGUMENT_VALIDATION_FAILED


def test_missing_schema_fails_closed():
    assert _code(lambda: ValidationService(SETTINGS).validate_input({"input_schema": None}, {})).code == \
        ErrorCode.TOOL_SCHEMA_CHANGED


# ------------------------------------------------------------------ output controls
def test_output_redaction_and_schema_validation():
    v = ValidationService(SETTINGS)
    tool = {"output": {"redact_fields": ["ssn"], "validate_output": True},
            "output_schema": {"type": "object", "required": ["id"]}}
    content = [{"type": "text", "text": '{"id": "1", "ssn": "123"}'}]
    c, s, meta = v.process_output(tool, content, {"id": "1", "ssn": "123", "deep": [{"SSN": "x"}]})
    assert s["ssn"] == "[REDACTED]" and s["deep"][0]["SSN"] == "[REDACTED]"
    assert "123" not in c[0]["text"] and meta["redacted_fields"] == 3
    assert _code(lambda: v.process_output(tool, [], {"no_id": 1})).code == ErrorCode.TOOL_OUTPUT_VALIDATION_FAILED
    small = {"max_output_bytes": 50}
    assert _code(lambda: v.process_output(small, [{"type": "text", "text": "x" * 100}], None)).code == \
        ErrorCode.PAYLOAD_TOO_LARGE


# ------------------------------------------------------------------ SSRF guard
STRICT = NetPolicy(allow_private=False)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/mcp", "http://10.0.0.5/mcp", "http://192.168.1.1/mcp", "http://172.16.0.1/mcp",
    "http://169.254.169.254/latest/meta-data", "http://[::1]/mcp", "http://metadata.google.internal/",
    "http://0.0.0.0/", "file:///etc/passwd", "gopher://x", "http://user:pass@example.com/mcp", "http:///nohost",
    "http://[::ffff:127.0.0.1]/",
])
def test_ssrf_urls_blocked(url):
    with pytest.raises(GatewayError) as ei:
        validate_url(url, STRICT)
    assert ei.value.code == ErrorCode.UPSTREAM_BLOCKED


def test_link_local_and_metadata_blocked_even_when_private_allowed():
    permissive = NetPolicy(allow_private=True)
    with pytest.raises(GatewayError):
        check_ip("169.254.169.254", permissive)
    check_ip("10.0.0.1", permissive)  # allowed when explicitly permitted


def test_host_allowlist():
    policy = NetPolicy(allow_private=False, host_allowlist=("mcp.internal.example", "*.tools.example"))
    validate_url("https://mcp.internal.example/mcp", policy)
    validate_url("https://a.tools.example/mcp", policy)
    with pytest.raises(GatewayError):
        validate_url("https://evil.example/mcp", policy)


async def test_connect_time_dns_check_blocks_rebinding(monkeypatch):
    """A public-looking hostname that resolves to a private address is blocked at connect time."""
    async def fake_resolve(host, port):
        return ["127.0.0.1"]

    monkeypatch.setattr("app.mcp.net_guard.resolve", fake_resolve)
    backend = GuardedNetworkBackend(STRICT)
    with pytest.raises(httpcore2.ConnectError):
        await backend.connect_tcp("innocent.example.com", 443)

    async def mixed(host, port):
        return ["93.184.216.34", "10.0.0.1"]  # any bad answer blocks

    monkeypatch.setattr("app.mcp.net_guard.resolve", mixed)
    with pytest.raises(httpcore2.ConnectError):
        await backend.connect_tcp("innocent.example.com", 443)


# ------------------------------------------------------------------ stdio
def test_stdio_requires_allowlist_and_rejects_shell_syntax(tmp_path):
    import sys

    exe = sys.executable
    with pytest.raises(UpstreamError):
        validate_stdio_config(exe, [], {}, [])  # nothing allowlisted
    assert validate_stdio_config(exe, ["-m", "x"], {}, [exe])
    for bad in ["python; rm -rf /", "python | nc", "$(whoami)", "`id`", "a && b"]:
        with pytest.raises(UpstreamError):
            validate_stdio_config(bad, [], {}, [exe])
    with pytest.raises(UpstreamError):
        validate_stdio_config(exe, [], {"LD_PRELOAD": "/tmp/x.so"}, [exe])
    with pytest.raises(UpstreamError):
        validate_stdio_config("/usr/bin/other-binary-not-allowed", [], {}, [exe])
