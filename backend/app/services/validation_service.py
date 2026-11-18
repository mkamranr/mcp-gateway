"""Input and output validation (spec §12)."""

from __future__ import annotations

import copy
import json
import math
import re
import sys
from collections.abc import Iterator
from functools import lru_cache
from re import _constants as sre_c  # type: ignore[attr-defined]
from re import _parser as sre_parse  # type: ignore[attr-defined]
from typing import Any

from jsonschema import Draft202012Validator, validators
from jsonschema.exceptions import SchemaError, ValidationError

from app.config import Settings
from app.core.errors import ErrorCode, GatewayError

REDACTED = "[REDACTED]"

# --------------------------------------------------------------------------------------- regular expressions
# Schemas come from upstream servers, the strings come from agents (input) or upstreams (output), and Python's
# ``re`` backtracks and holds the GIL: one bad pattern stalls the whole process. No linear-time engine is available
# offline, so patterns are checked statically instead:
# * refused outright: backreferences, a quantifier nested in an unbounded one, ambiguous alternation inside a
#   quantifier: the constructs with exponential backtracking (``(a+)+``, ``(\w|\d)*``, ``(a|a)+``);
# * what remains is at most polynomial in the input length, with the degree bounded by the number k of wide
#   quantifiers, so a pattern is only applied to strings up to PATTERN_STEP_BUDGET ** (1/k) characters.
PATTERN_STEP_BUDGET = 10**8
MAX_PROPERTY_NAME = 256  # property names longer than this are refused, so patternProperties stay bounded too
_WIDE = 50  # a quantifier allowing more repetitions than this counts as wide
_NEST_BUDGET = 100_000  # bounded nesting allowed while (inner repetitions) ** (outer repetitions) stays below
_REPEATS = {sre_c.MAX_REPEAT, sre_c.MIN_REPEAT, sre_c.POSSESSIVE_REPEAT}
_CATEGORIES = {sre_c.CATEGORY_DIGIT: r"\d", sre_c.CATEGORY_NOT_DIGIT: r"\D", sre_c.CATEGORY_SPACE: r"\s",
               sre_c.CATEGORY_NOT_SPACE: r"\S", sre_c.CATEGORY_WORD: r"\w", sre_c.CATEGORY_NOT_WORD: r"\W"}


class UnsafePattern(ValueError):
    pass


def _flat(seq: Any) -> list[tuple[Any, Any]]:
    """The nodes of a sequence with plain groups expanded in place (they match in sequence)."""
    out: list[tuple[Any, Any]] = []
    for op, av in seq:
        if op is sre_c.SUBPATTERN:
            out.extend(_flat(av[3]))
        else:
            out.append((op, av))
    return out


def _char_may_match(node: tuple[Any, Any], c: int) -> bool:
    """Whether a single-character node can match code point ``c``; True when unsure."""
    op, av = node
    if op is sre_c.LITERAL:
        return bool(av == c)
    if op is sre_c.NOT_LITERAL:
        return bool(av != c)
    if op is sre_c.IN:
        negate, hit = False, False
        for iop, iav in av:
            if iop is sre_c.NEGATE:
                negate = True
            elif iop is sre_c.LITERAL:
                hit = hit or iav == c
            elif iop is sre_c.RANGE:
                hit = hit or iav[0] <= c <= iav[1]
            elif iop is sre_c.CATEGORY and iav in _CATEGORIES:
                hit = hit or re.match(_CATEGORIES[iav], chr(c)) is not None
            else:
                return True
        return hit != negate
    return True  # ANY and everything else


def _delimited(body: Any) -> bool:
    """A repeated body whose iterations are split by a mandatory literal its own quantifiers can't consume, as in
    ``([a-z0-9-]+\\.)+``: each iteration ends at a fixed character, so iterations can't be divided up in many ways."""
    flat = _flat(body)
    literals = [av for op, av in flat if op is sre_c.LITERAL]
    repeats = [av for op, av in flat if op in _REPEATS]
    if not literals or any(op not in _REPEATS and op is not sre_c.LITERAL and op is not sre_c.IN
                           and op is not sre_c.ANY and op is not sre_c.NOT_LITERAL for op, _ in flat):
        return False
    for _lo, _hi, sub in repeats:
        sub = list(sub)
        if len(sub) != 1 or sub[0][0] in _REPEATS or sub[0][0] in (sre_c.SUBPATTERN, sre_c.BRANCH):
            return False
    for c in literals:
        if any(_char_may_match(list(sub)[0], c) for _lo, _hi, sub in repeats):
            continue
        # The quantifiers must all be on one side of the delimiter: in ``(\s*,\s*)+`` the trailing spaces of one
        # iteration and the leading spaces of the next can split the same input in many ways.
        at = [i for i, (op, av) in enumerate(flat) if op is sre_c.LITERAL and av == c]
        rep = [i for i, (op, _) in enumerate(flat) if op in _REPEATS]
        if all(i < at[-1] for i in rep) or all(i > at[0] for i in rep):
            return True
    return False


def _too_many(n: float, outer: float) -> bool:
    return math.isinf(n) or math.isinf(outer) or outer * math.log(max(n, 1)) > math.log(_NEST_BUDGET)


def _scan(seq: Any, outer: float | None, fold: bool) -> int:
    """Raise UnsafePattern for exponential constructs; return the number of wide quantifiers."""
    k = 0
    for op, av in seq:
        if op in (sre_c.GROUPREF, sre_c.GROUPREF_EXISTS):
            raise UnsafePattern("backreferences are not allowed")
        if op in _REPEATS:
            _lo, hi, sub = av
            n = math.inf if hi == sre_c.MAXREPEAT else float(hi)
            if n >= _WIDE:
                k += 1
            if n <= 1:
                k += _scan(sub, outer, fold)
                continue
            if outer is not None and _too_many(n, outer):
                raise UnsafePattern("nested quantifiers")
            if not fold and _delimited(sub):
                k += _scan(sub, None, fold)
            else:
                k += _scan(sub, n if outer is None else outer * n, fold)
        elif op is sre_c.SUBPATTERN:
            k += _scan(av[3], outer, fold or bool(av[1] & sre_c.SRE_FLAG_IGNORECASE))
        elif op is sre_c.BRANCH:
            alts = av[1]
            firsts = [_flat(a)[:1] for a in alts]
            disjoint = (not fold and all(f and f[0][0] is sre_c.LITERAL for f in firsts)
                        and len({f[0][1] for f in firsts}) == len(firsts))
            if outer is not None and not disjoint and _too_many(len(alts), outer):
                raise UnsafePattern("ambiguous alternation inside a quantifier")
            k += max((_scan(a, outer, fold) for a in alts), default=0)
        elif op in (sre_c.ASSERT, sre_c.ASSERT_NOT):
            k += _scan(av[1], outer, fold)
        elif op is sre_c.ATOMIC_GROUP:
            k += _scan(av, outer, fold)
    return k


@lru_cache(maxsize=2048)
def pattern_input_cap(pattern: str) -> int:
    """The longest string ``pattern`` may be applied to. Raises UnsafePattern for patterns never applied."""
    if len(pattern) > 1000:
        raise UnsafePattern("pattern too long")
    try:
        tree = sre_parse.parse(pattern)
    except (re.error, RecursionError, OverflowError, ValueError) as exc:
        raise UnsafePattern("invalid pattern") from exc
    fold = bool(tree.state.flags & sre_c.SRE_FLAG_IGNORECASE)
    k = _scan(tree, None, fold)
    return int(PATTERN_STEP_BUDGET ** (1 / k)) if k else sys.maxsize


_NOT_SCHEMAS = {"const", "enum", "default", "examples"}


def unsafe_schema_patterns(schema: Any) -> list[str]:
    """Problems with the regular expressions in a JSON Schema (``pattern`` and ``patternProperties``); empty if
    none. Used when tools are discovered and before every validation."""
    problems: list[str] = []

    def check(pattern: Any, key_pattern: bool) -> None:
        if not isinstance(pattern, str):
            return
        try:
            cap = pattern_input_cap(pattern)
        except UnsafePattern as exc:
            problems.append(f"{pattern[:80]!r}: {exc}")
            return
        if key_pattern and cap < MAX_PROPERTY_NAME:
            problems.append(f"{pattern[:80]!r}: too many quantifiers for a property-name pattern")

    def walk(node: Any, depth: int) -> None:
        if depth > 64 or len(problems) >= 20:
            return
        if isinstance(node, dict):
            check(node.get("pattern"), False)
            if isinstance(node.get("patternProperties"), dict):
                for key in node["patternProperties"]:
                    check(key, True)
            for key, value in node.items():
                if key not in _NOT_SCHEMAS:
                    walk(value, depth + 1)
        elif isinstance(node, list):
            for value in node:
                walk(value, depth + 1)

    walk(schema, 0)
    return problems


def _pattern_keyword(validator: Any, pattern: str, instance: Any, schema: Any) -> Iterator[ValidationError]:
    if not validator.is_type(instance, "string"):
        return
    try:
        cap = pattern_input_cap(pattern)
    except UnsafePattern:
        yield ValidationError("The schema pattern is not safe to apply.")
        return
    if len(instance) > cap:
        yield ValidationError(f"The value is longer than the {cap} characters this pattern is applied to.")
    elif re.search(pattern, instance) is None:
        yield ValidationError("The value does not match the pattern.")


SafeValidator = validators.extend(Draft202012Validator, {"pattern": _pattern_keyword})


def _long_property_name(value: Any, depth: int = 0) -> bool:
    if depth > 64:
        return False
    if isinstance(value, dict):
        return any(isinstance(k, str) and len(k) > MAX_PROPERTY_NAME for k in value) or any(
            _long_property_name(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        return any(_long_property_name(v, depth + 1) for v in value)
    return False


def _walk_limits(value: Any, settings: Settings, depth: int = 0, path: str = "$") -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    if depth > settings.max_json_depth:
        return [{"field": path, "code": "max_depth"}]
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                errors.append({"field": path, "code": "non_string_key"})
                continue
            if len(k) > MAX_PROPERTY_NAME:
                errors.append({"field": path, "code": "max_key_length"})
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
        if unsafe_schema_patterns(schema):
            raise GatewayError(ErrorCode.TOOL_SCHEMA_CHANGED,
                               "The tool schema contains a regular expression that is not safe to apply.")
        try:
            validator = SafeValidator(_strict_schema(schema))
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
                red_block, n = _redact_block(block, redact)
                new_content.append(red_block)
                n2 += n
            content = new_content
            meta["redacted_fields"] = n1 + n2

        output_schema = tool.get("output_schema")
        if output_schema and controls.get("validate_output", True) and structured is not None:
            errors: list[Any]
            if unsafe_schema_patterns(output_schema) or _long_property_name(structured):
                errors = [None]  # never apply an unsafe pattern, nor any pattern to an overlong property name
            else:
                try:
                    errors = list(SafeValidator(output_schema).iter_errors(structured))
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
        return REDACTED, 1  # too deep to inspect: hidden rather than passed through
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


def _redact_string(text: str, fields: list[str]) -> tuple[str, int]:
    """Redact a text payload: JSON is redacted structurally; other text by finding ``field: value`` pairs."""
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return _redact_text(text, fields)
    if not isinstance(parsed, dict | list):
        return _redact_text(text, fields)
    red, n = _redact(parsed, fields)
    return (json.dumps(red, ensure_ascii=False), n) if n else (text, 0)


_JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.DOTALL)
_SQ_STRING = re.compile(r"'(?:[^'\\]|\\.)*'", re.DOTALL)
_SCALAR = re.compile(r"[^\s,;}\]]*")


def _redact_text(text: str, fields: list[str]) -> tuple[str, int]:
    """Text that isn't a JSON document, e.g. ``Result: {"ssn": "..."}`` or ``ssn=...``. Each value after a
    configured field name is replaced; an embedded object or array whose end can't be found hides the rest."""
    keys = "|".join(re.escape(f) for f in sorted(fields, key=len, reverse=True))
    rx = re.compile(r"(?<![\w-])[\"']?(?:" + keys + r")[\"']?\s*[:=]\s*", re.IGNORECASE)
    out: list[str] = []
    pos, count = 0, 0
    while True:
        m = rx.search(text, pos)
        if m is None:
            out.append(text[pos:])
            break
        start = m.end()
        out.append(text[pos:start])
        count += 1
        nxt = text[start:start + 1]
        end: int | None
        if nxt in ("{", "["):
            try:
                _, end = json.JSONDecoder().raw_decode(text, start)
            except (ValueError, RecursionError):
                end = None
        elif nxt in ('"', "'"):
            sm = (_JSON_STRING if nxt == '"' else _SQ_STRING).match(text, start)
            end = sm.end() if sm else None
        else:
            sm = _SCALAR.match(text, start)
            end = sm.end() if sm else start
        if end is None:
            out.append(REDACTED)  # can't tell where the value ends: hide everything after it
            break
        out.append(REDACTED)
        pos = end
    return ("".join(out), count) if count else (text, 0)


def _redact_block(block: dict[str, Any], fields: list[str]) -> tuple[dict[str, Any], int]:
    """One MCP content block. Text and embedded resource text are searched; other blocks structurally."""
    kind = block.get("type")
    if kind == "text" and isinstance(block.get("text"), str):
        text, n = _redact_string(block["text"], fields)
        return ({**block, "text": text}, n) if n else (block, 0)
    if kind == "resource" and isinstance(block.get("resource"), dict):
        res, count = block["resource"], 0
        if isinstance(res.get("text"), str):
            text, count = _redact_string(res["text"], fields)
            res = {**res, "text": text}
        rest, n = _redact({k: v for k, v in block.items() if k != "resource"}, fields)
        return ({**rest, "resource": res}, count + n) if count + n else (block, 0)
    red, n = _redact(block, fields)
    return (red, n) if n else (block, 0)
