"""Input and output validation (spec §12)."""

from __future__ import annotations

import copy
import json
import math
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from app.config import Settings
from app.core.errors import ErrorCode, GatewayError

REDACTED = "[REDACTED]"


def _walk_limits(value: Any, settings: Settings, depth: int = 0, path: str = "$") -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    if depth > settings.max_json_depth:
        return [{"field": path, "code": "max_depth"}]
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                errors.append({"field": path, "code": "non_string_key"})
                continue
            errors.extend(_walk_limits(v, settings, depth + 1, f"{path}.{k}"))
    elif isinstance(value, list):
        if len(value) > settings.max_array_length:
            errors.append({"field": path, "code": "max_items"})
        for i, v in enumerate(value[: settings.max_array_length]):
            errors.extend(_walk_limits(v, settings, depth + 1, f"{path}[{i}]"))
    elif isinstance(value, str):
        if len(value) > settings.max_string_length:
            errors.append({"field": path, "code": "max_length"})
    elif isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            errors.append({"field": path, "code": "non_finite_number"})
    elif value is not None and not isinstance(value, bool | int):
        errors.append({"field": path, "code": "non_json_value"})
    return errors[:50]


def _strict_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Reject unknown top-level fields unless the schema explicitly allows them (spec §12.1)."""
    s = copy.deepcopy(schema)
    if s.get("type", "object") == "object" and "additionalProperties" not in s and "properties" in s:
        s["additionalProperties"] = False
    return s


class ValidationService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def validate_input(self, tool: dict[str, Any], arguments: Any) -> int:
        """Validate tool arguments. Returns the canonical payload size in bytes."""
        if not isinstance(arguments, dict):
            raise GatewayError(ErrorCode.TOOL_ARGUMENT_VALIDATION_FAILED, details=[{"field": "$", "code": "type"}])
        try:
            encoded = json.dumps(arguments, ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise GatewayError(ErrorCode.TOOL_ARGUMENT_VALIDATION_FAILED,
                               details=[{"field": "$", "code": "not_json"}]) from exc
        max_bytes = min(int(tool.get("max_input_bytes") or self.settings.max_input_bytes), self.settings.max_input_bytes)
        if len(encoded) > max_bytes:
            raise GatewayError(ErrorCode.PAYLOAD_TOO_LARGE, "The tool arguments exceed the maximum size.")
        limit_errors = _walk_limits(arguments, self.settings)
        if limit_errors:
            raise GatewayError(ErrorCode.TOOL_ARGUMENT_VALIDATION_FAILED, details=limit_errors)
        schema = tool.get("input_schema")
        if not isinstance(schema, dict):
            # Schema unavailable or invalid -> do not execute (spec §19.4)
            raise GatewayError(ErrorCode.TOOL_SCHEMA_CHANGED, "The tool schema is unavailable.")
        try:
            validator = Draft202012Validator(_strict_schema(schema))
            errors = sorted(validator.iter_errors(arguments), key=lambda e: list(e.absolute_path))
        except SchemaError as exc:
            raise GatewayError(ErrorCode.TOOL_SCHEMA_CHANGED, "The tool schema is invalid.") from exc
        if errors:
            details = []
            for e in errors[:20]:
                field = ".".join(str(x) for x in e.absolute_path) or "$"
                code = str(e.validator)
                if code == "required" and isinstance(e.instance, dict):
                    missing = [r for r in e.validator_value if r not in e.instance]
                    field = missing[0] if missing else field
                elif code == "additionalProperties":
                    code = "unknown_field"
                details.append({"field": field, "code": code})
            raise GatewayError(ErrorCode.TOOL_ARGUMENT_VALIDATION_FAILED, details=details)
        return len(encoded)

    def process_output(self, tool: dict[str, Any], content: list[dict[str, Any]],
                       structured: dict[str, Any] | None) -> tuple[list[dict[str, Any]], dict[str, Any] | None, dict[str, Any]]:
        """Enforce size, validate against output schema, and redact configured fields.

        Returns (content, structured_content, metadata) where metadata records truncation/redaction.
        """
        meta: dict[str, Any] = {"redacted_fields": 0, "truncated": False, "output_validated": False}
        controls = tool.get("output") or {}
        redact = [f.lower() for f in controls.get("redact_fields", [])]
        if redact:
            structured, n1 = _redact(structured, redact)
            new_content = []
            n2 = 0
            for block in content:
                if block.get("type") == "text":
                    try:
                        parsed = json.loads(block.get("text", ""))
                    except (ValueError, TypeError):
                        new_content.append(block)
                        continue
                    red, n = _redact(parsed, redact)
                    n2 += n
                    new_content.append({**block, "text": json.dumps(red, ensure_ascii=False)})
                else:
                    new_content.append(block)
            content = new_content
            meta["redacted_fields"] = n1 + n2

        output_schema = tool.get("output_schema")
        if output_schema and controls.get("validate_output", True) and structured is not None:
            try:
                errors = list(Draft202012Validator(output_schema).iter_errors(structured))
            except SchemaError:
                errors = [None]
            if errors:
                raise GatewayError(ErrorCode.TOOL_OUTPUT_VALIDATION_FAILED,
                                   "The tool output did not match its declared schema.")
            meta["output_validated"] = True

        max_bytes = min(int(tool.get("max_output_bytes") or self.settings.max_output_bytes),
                        self.settings.max_output_bytes)
        size = len(json.dumps({"c": content, "s": structured}, ensure_ascii=False).encode("utf-8"))
        meta["output_bytes"] = size
        if size > max_bytes:
            raise GatewayError(ErrorCode.PAYLOAD_TOO_LARGE, "The tool output exceeds the maximum size.")
        return content, structured, meta


def _redact(value: Any, fields: list[str], depth: int = 0) -> tuple[Any, int]:
    if depth > 32:
        return value, 0
    count = 0
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and k.lower() in fields:
                out[k] = REDACTED
                count += 1
            else:
                out[k], n = _redact(v, fields, depth + 1)
                count += n
        return out, count
    if isinstance(value, list):
        items = []
        for v in value:
            r, n = _redact(v, fields, depth + 1)
            items.append(r)
            count += n
        return items, count
    return value, 0
