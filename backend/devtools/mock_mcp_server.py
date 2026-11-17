"""Mock upstream MCP server. DEVELOPMENT/TEST FIXTURE ONLY.

Exposes a few realistic tools plus hooks for testing timeouts, errors and oversized output.
It counts every call it receives, so tests can prove that denied or invalid calls never reach
the upstream.

    python -m devtools.mock_mcp_server --port 9100            # streamable HTTP at /mcp
    python -m devtools.mock_mcp_server --stdio                # stdio transport
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections import Counter
from typing import Any

import mcp_types as types
from mcp.server import Server

CALLS: Counter[str] = Counter()
STATE: dict[str, Any] = {"schema_variant": 0, "expected_token": None, "last_auth": None}

BASE_TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_attendance_summary",
        "description": "Return the attendance summary for an employee and month.",
        "input_schema": {
            "type": "object",
            "properties": {
                "employee_id": {"type": "string", "pattern": "^E[0-9]{3,6}$"},
                "month": {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}$"},
            },
            "required": ["employee_id"],
        },
    },
    {
        "name": "get_employee_record",
        "description": "Return an employee record (contains sensitive fields).",
        "input_schema": {"type": "object", "properties": {"employee_id": {"type": "string"}},
                         "required": ["employee_id"]},
        "output_schema": {"type": "object", "properties": {"employee_id": {"type": "string"},
                                                           "name": {"type": "string"},
                                                           "ssn": {"type": "string"}},
                          "required": ["employee_id"]},
    },
    {
        "name": "send_email",
        "description": "Send an email message.",
        "input_schema": {"type": "object", "properties": {
            "to": {"type": "string", "maxLength": 254}, "subject": {"type": "string", "maxLength": 200},
            "body": {"type": "string", "maxLength": 10000}}, "required": ["to", "subject", "body"]},
    },
    {
        "name": "drop_collection",
        "description": "Drop a database collection. Destructive.",
        "input_schema": {"type": "object", "properties": {"collection": {"type": "string"}},
                         "required": ["collection"]},
    },
    {
        "name": "slow_tool",
        "description": "Sleeps for the given number of seconds (timeout testing).",
        "input_schema": {"type": "object", "properties": {"seconds": {"type": "number", "minimum": 0,
                                                                      "maximum": 60}}},
    },
    {
        "name": "fail_tool",
        "description": "Always returns a tool-level error.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "big_output",
        "description": "Returns a large text payload.",
        "input_schema": {"type": "object", "properties": {"size": {"type": "integer", "minimum": 1,
                                                                   "maximum": 20000000}}},
    },
    {"name": "bad name!", "description": "Invalid tool name; the gateway must reject it.",
     "input_schema": {"type": "object"}},
]


def current_tools() -> list[dict[str, Any]]:
    tools = [dict(t) for t in BASE_TOOLS]
    if STATE["schema_variant"]:
        # Simulate an upstream schema change on get_attendance_summary.
        t = json.loads(json.dumps(tools[0]))
        t["input_schema"]["properties"]["include_details"] = {"type": "boolean"}
        tools[0] = t
    return tools


async def _list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
    _check_auth(ctx)
    return types.ListToolsResult(tools=[types.Tool(**t) for t in current_tools()])


def _check_auth(ctx: Any) -> None:
    req = getattr(ctx, "request", None)
    if req is not None and hasattr(req, "headers"):
        STATE["last_auth"] = req.headers.get("authorization")
        expected = STATE.get("expected_token")
        if expected and req.headers.get("authorization") != f"Bearer {expected}":
            raise PermissionError("unauthorized")


def _text(value: Any) -> list[Any]:
    return [types.TextContent(type="text", text=value if isinstance(value, str) else json.dumps(value))]


async def _call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
    _check_auth(ctx)
    name, args = params.name, params.arguments or {}
    CALLS[name] += 1
    if name == "get_attendance_summary":
        data = {"employee_id": args["employee_id"], "month": args.get("month", "2026-11"), "present_days": 19,
                "absent_days": 1}
        return types.CallToolResult(content=_text(data), structured_content=data)
    if name == "get_employee_record":
        data = {"employee_id": args["employee_id"], "name": "Test Employee", "ssn": "123-45-6789"}
        return types.CallToolResult(content=_text(data), structured_content=data)
    if name == "send_email":
        return types.CallToolResult(content=_text(f"Email queued to {args['to']}"))
    if name == "drop_collection":
        return types.CallToolResult(content=_text(f"Dropped {args['collection']}"))
    if name == "slow_tool":
        await asyncio.sleep(float(args.get("seconds", 5)))
        return types.CallToolResult(content=_text("done"))
    if name == "fail_tool":
        return types.CallToolResult(content=_text("Simulated tool failure"), is_error=True)
    if name == "big_output":
        return types.CallToolResult(content=_text("x" * int(args.get("size", 1000))))
    return types.CallToolResult(content=_text(f"Unknown tool {name}"), is_error=True)


def build_server() -> Server[Any]:
    return Server("mock-upstream", version="1.0.0", on_list_tools=_list_tools, on_call_tool=_call_tool)


def build_http_app() -> Any:
    from mcp.server.transport_security import TransportSecuritySettings

    server = build_server()
    return server.streamable_http_app(
        stateless_http=True, json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9100)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--stdio", action="store_true")
    parser.add_argument("--token", default=None, help="Require this bearer token")
    parser.add_argument("--tls-cert", default=None, help="Serve HTTPS with this certificate (PEM)")
    parser.add_argument("--tls-key", default=None, help="Private key for --tls-cert (PEM)")
    parser.add_argument("--client-ca", default=None, help="Require client certificates issued by this CA (mTLS)")
    ns = parser.parse_args()
    STATE["expected_token"] = ns.token
    if ns.stdio:
        from mcp.server.stdio import stdio_server

        server = build_server()

        async def run() -> None:
            async with stdio_server() as (r, w):
                await server.run(r, w, server.create_initialization_options())

        asyncio.run(run())
        return
    import ssl

    import uvicorn

    tls: dict[str, object] = {}
    if ns.tls_cert:
        tls = {"ssl_certfile": ns.tls_cert, "ssl_keyfile": ns.tls_key}
        if ns.client_ca:
            tls |= {"ssl_ca_certs": ns.client_ca, "ssl_cert_reqs": ssl.CERT_REQUIRED}
    uvicorn.run(build_http_app(), host=ns.host, port=ns.port, log_level="warning", **tls)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
