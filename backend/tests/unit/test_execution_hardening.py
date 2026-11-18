"""Tool execution path hardening: schema regex safety, output redaction, approval preview, network guard limits."""

import base64
import os
import time

import httpx2
import pytest

from app.config import Settings
from app.core.errors import ErrorCode, GatewayError
from app.mcp.net_guard import GuardedTransport, NetPolicy, ResponseTooLarge, check_ip
from app.services.approval_service import mask_arguments, preview_gaps
from app.services.validation_service import (
    MAX_PROPERTY_NAME,
    REDACTED,
    UnsafePattern,
    ValidationService,
    pattern_input_cap,
    unsafe_schema_patterns,
)

SETTINGS = Settings(app_env="test", data_encryption_key=base64.urlsafe_b64encode(os.urandom(32)).decode())


def _tool(schema: dict) -> dict:
    return {"input_schema": schema}


# ------------------------------------------------------------------ regular expressions in schemas
@pytest.mark.parametrize("pattern", [
    r"^(a+)+$", r"(a|a)+", r"(.)\1", r"(\s*,\s*)+", r"^([a-z]+\.?)+$", r"(a{1,100}){1,100}", r"(?i)([a-z]+x)+",
    "a" * 1001,
])
def test_exponential_patterns_are_refused(pattern):
    with pytest.raises(UnsafePattern):
        pattern_input_cap(pattern)


@pytest.mark.parametrize("pattern", [
    r"^[A-Z]{3}-\d+$", r"^\d{4}-\d{2}-\d{2}$", r"^([a-z0-9-]+\.)+[a-z]{2,}$", r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
    r"^(\d{1,3}\.){3}\d{1,3}$", r"^([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$", r"^(foo|bar)+$", r"^(\s*,)+$",
])
def test_common_patterns_are_accepted(pattern):
    assert pattern_input_cap(pattern) >= 400


def test_polynomial_patterns_get_an_input_cap():
    assert pattern_input_cap(r"^.*x.*x.*y") < 1000  # cubic: only applied to short strings
    assert pattern_input_cap(r"^[a-z]+$") > SETTINGS.max_string_length


def test_unsafe_pattern_anywhere_in_the_schema_blocks_the_tool():
    schema = {"type": "object", "properties": {"a": {"type": "object", "properties": {
        "b": {"type": "string", "pattern": r"^(a+)+$"}}}}}
    assert unsafe_schema_patterns(schema)
    started = time.perf_counter()
    with pytest.raises(GatewayError) as e:
        ValidationService(SETTINGS).validate_input(_tool(schema), {"a": {"b": "a" * 40 + "!"}})
    assert e.value.code == ErrorCode.TOOL_SCHEMA_CHANGED
    assert time.perf_counter() - started < 1  # never applied
    # patternProperties keys are patterns too; const/enum/default values are data, not patterns
    assert unsafe_schema_patterns({"patternProperties": {r"(x+)+": {}}})
    assert not unsafe_schema_patterns({"properties": {"p": {"const": {"pattern": r"(x+)+"}}}})


def test_pattern_is_not_applied_past_its_cap():
    schema = {"type": "object", "properties": {"s": {"type": "string", "pattern": r"^.*x.*x.*y"}}}
    v = ValidationService(SETTINGS)
    assert v.validate_input(_tool(schema), {"s": "axbxy"}) > 0
    started = time.perf_counter()
    with pytest.raises(GatewayError) as e:
        v.validate_input(_tool(schema), {"s": "x" * 5000})
    assert e.value.code == ErrorCode.TOOL_ARGUMENT_VALIDATION_FAILED
    assert e.value.details == [{"field": "s", "code": "pattern"}]
    assert time.perf_counter() - started < 1


def test_overlong_property_names_are_refused():
    schema = {"type": "object", "patternProperties": {"^x": {"type": "string"}}}
    with pytest.raises(GatewayError) as e:
        ValidationService(SETTINGS).validate_input(_tool(schema), {"x" * (MAX_PROPERTY_NAME + 1): "v"})
    assert e.value.details[0]["code"] == "max_key_length"


def test_unsafe_output_schema_fails_closed():
    tool = {"output_schema": {"type": "object", "properties": {"s": {"type": "string", "pattern": r"(a*)*$"}}}}
    with pytest.raises(GatewayError) as e:
        ValidationService(SETTINGS).process_output(tool, [], {"s": "a" * 30 + "!"})
    assert e.value.code == ErrorCode.TOOL_OUTPUT_VALIDATION_FAILED


# ------------------------------------------------------------------ output redaction
def _out(content=None, structured=None, fields=("ssn",)):
    tool = {"output": {"redact_fields": list(fields), "validate_output": False}}
    return ValidationService(SETTINGS).process_output(tool, content or [], structured)


def test_redaction_of_json_embedded_in_text():
    content, _, meta = _out([{"type": "text", "text": 'Result: {"ssn": {"n": "123-45-6789"}, "name": "A"} ssn=987'}])
    text = content[0]["text"]
    assert "123-45-6789" not in text and "987" not in text and '"name": "A"' in text
    assert meta["redacted_fields"] == 2


def test_redaction_hides_the_rest_when_the_value_end_is_unclear():
    content, _, _ = _out([{"type": "text", "text": 'x "SSN": {"n": "123-45-6789" (truncated'}])
    assert "123-45-6789" not in content[0]["text"]


def test_redaction_of_resource_blocks():
    block = {"type": "resource", "resource": {"uri": "file:///r.json", "text": '{"ssn": "123-45-6789", "a": 1}'}}
    content, _, meta = _out([block])
    assert "123-45-6789" not in content[0]["resource"]["text"] and meta["redacted_fields"] == 1


def test_values_deeper_than_the_limit_are_hidden():
    deep: dict = {"ssn": "123-45-6789"}
    for _ in range(40):
        deep = {"d": deep}
    content, structured, _ = _out([{"type": "text", "text": __import__("json").dumps(deep)}], structured=deep)
    assert "123-45-6789" not in str(structured) and "123-45-6789" not in content[0]["text"]
    assert REDACTED in str(structured)


def test_text_without_redacted_fields_is_unchanged():
    block = {"type": "text", "text": "plain text, nothing to hide"}
    content, _, meta = _out([block])
    assert content == [block] and meta["redacted_fields"] == 0


# ------------------------------------------------------------------ approval preview
def test_preview_marks_everything_it_leaves_out():
    args = {"recipients": [f"u{i}@corp.example" for i in range(100)] + ["attacker@evil.example"],
            "note": "x" * 3000, "token": "secret"}
    shown = mask_arguments(args, ["token"])
    assert shown["recipients"][-1] == "… (1 more items not shown)"
    assert shown["token"] == "••••••"
    assert preview_gaps(args, ["token"]) == ["fields_masked", "items_omitted", "text_truncated"]
    assert preview_gaps({"a": [1, 2], "b": "short"}, ["token"]) == []


# ------------------------------------------------------------------ network guard
def test_site_local_ipv6_is_private():
    with pytest.raises(GatewayError):
        check_ip("fec0::1", NetPolicy(allow_private=False))
    check_ip("fec0::1", NetPolicy(allow_private=True))


async def _fake_response(body: bytes, length: bool, monkeypatch) -> httpx2.Response:
    async def handle(self, request):
        headers = {"content-length": str(len(body))} if length else {}

        async def chunks():
            for i in range(0, len(body), 1024):
                yield body[i:i + 1024]

        class Stream(httpx2.AsyncByteStream):
            async def __aiter__(self):
                async for c in chunks():
                    yield c

        return httpx2.Response(200, headers=headers, stream=Stream())

    monkeypatch.setattr(httpx2.AsyncHTTPTransport, "handle_async_request", handle)
    transport = GuardedTransport(NetPolicy(), max_response_bytes=4096)
    async with httpx2.AsyncClient(transport=transport) as client:
        return await client.get("https://upstream.example/mcp")


async def test_upstream_response_size_is_capped(monkeypatch):
    with pytest.raises(ResponseTooLarge):
        await _fake_response(b"x" * 10_000, length=True, monkeypatch=monkeypatch)
    with pytest.raises(ResponseTooLarge):  # chunked, no Content-Length: counted while streaming
        await _fake_response(b"x" * 10_000, length=False, monkeypatch=monkeypatch)
    ok = await _fake_response(b"x" * 4000, length=False, monkeypatch=monkeypatch)
    assert len(ok.content) == 4000
