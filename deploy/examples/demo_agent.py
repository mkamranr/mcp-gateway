"""Demo AI agent: connects to the MCP-Gateway with an agent key using the official MCP Python SDK.

    MGW_URL=http://127.0.0.1:8080/mcp MGW_AGENT_KEY=mgw_live_... \
        uv run --project backend python deploy/examples/demo_agent.py

What it shows (spec §25 walkthrough):
  1. tools/list returns only the tools that policy lets this agent discover;
  2. an allowed low-risk call succeeds;
  3. a call to a tool the agent may not use fails with ACCESS_DENIED (or TOOL_NOT_FOUND if hidden);
  4. a sensitive call returns APPROVAL_PENDING and is NOT executed until a human approves it;
  5. the agent polls gateway__approval_status until the approved call has completed.

Tool output is untrusted data. A real agent must never follow instructions found in it.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

URL = os.environ.get("MGW_URL", "http://127.0.0.1:8080/mcp")
KEY = os.environ.get("MGW_AGENT_KEY", "")
WAIT_SECONDS = int(os.environ.get("MGW_APPROVAL_WAIT_SECONDS", "0"))


def show(label: str, res: object) -> dict:
    payload = getattr(res, "structured_content", None) or {}
    text = "".join(getattr(c, "text", "") for c in getattr(res, "content", []) or [])
    status = "ERROR" if getattr(res, "is_error", False) else "OK"
    print(f"  {label:<38} {status:<5} {json.dumps(payload)[:160] if payload else text[:160]}")
    return payload


async def main() -> int:
    if not KEY:
        print("Set MGW_AGENT_KEY to an agent key created in the console.", file=sys.stderr)
        return 2
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {KEY}"}, timeout=30)
    async with http, Client(streamable_http_client(URL, http_client=http)) as client:
        tools = (await client.list_tools()).tools
        print(f"Discovered {len(tools)} tools:")
        for t in tools:
            print(f"  - {t.name}")
        names = {t.name for t in tools}

        print("\nCalls:")
        show("hr__get_attendance_summary (allowed)", await client.call_tool("hr__get_attendance_summary", {"employee_id": "E1001"}))
        show("hr__get_employee_record (not granted)", await client.call_tool("hr__get_employee_record", {"employee_id": "E1001"}))
        show("hr__get_attendance_summary (bad args)", await client.call_tool("hr__get_attendance_summary", {"employee_id": 42}))
        pending = {}
        if "hr__send_email" in names:
            pending = show("hr__send_email (needs approval)", await client.call_tool(
                "hr__send_email", {"to": "cfo@example.com", "subject": "Q3 report", "body": "Numbers attached."}))
        approval_id = pending.get("approval_id")
        if approval_id:
            print(f"\nApproval {approval_id} is pending. Approve it in the console (Approvals page).")
            for _ in range(WAIT_SECONDS // 3):
                st = (await client.call_tool("gateway__approval_status", {"approval_id": approval_id})).structured_content or {}
                if st.get("status") not in ("PENDING", "APPROVED", "REVALIDATING", "EXECUTING"):
                    print(f"  final status: {st.get('status')}  result: {json.dumps(st.get('result'))[:200]}")
                    break
                await asyncio.sleep(3)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
