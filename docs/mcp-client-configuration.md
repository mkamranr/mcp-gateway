# MCP Client Configuration

Agents connect to **one** endpoint, the gateway, using **streamable HTTP** and an agent key.

| Setting | Value |
|---|---|
| URL | `https://<gateway-host>/mcp` (shown under **Settings → General**) |
| Transport | Streamable HTTP (stateless, JSON responses) |
| Auth header | `Authorization: Bearer mgw_live_<id>_<secret>` |
| Tool names | `<server_alias>__<tool_name>`, e.g. `hr__get_attendance_summary` |
| Built-in tool | `gateway__approval_status {"approval_id": "apr_…"}` polls an approval |

Create the key under **Agents & Credentials → (agent) → New key**. It is displayed once. Store it in your
secret manager and never in source code.

## Generic JSON configuration

Many MCP hosts accept a configuration like this (field names vary by client):

```json
{
  "mcpServers": {
    "mcp-gateway": {
      "type": "streamable-http",
      "url": "https://mcp-gateway.internal.example/mcp",
      "headers": { "Authorization": "Bearer ${MGW_AGENT_KEY}" }
    }
  }
}
```

## Python (official `mcp` SDK, tested with mcp 2.3.0)

```python
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {key}"}, timeout=30)
async with http, Client(streamable_http_client("https://gw.example/mcp", http_client=http)) as client:
    tools = (await client.list_tools()).tools          # only the tools policy lets this agent discover
    res = await client.call_tool("hr__get_attendance_summary", {"employee_id": "E1001"})
    if res.is_error:
        err = (res.structured_content or {}).get("error") or res.structured_content
        print(err)                                     # e.g. {"code": "ACCESS_DENIED", ...}
```

A complete runnable example lives in [`deploy/examples/demo_agent.py`](../deploy/examples/demo_agent.py).

## Clients that only support stdio

Run a local stdio-to-HTTP bridge from your MCP tooling that forwards to the gateway URL with the
`Authorization` header. The gateway itself does not need to change.

## Handling gateway responses

| Situation | What the agent receives | What it should do |
|---|---|---|
| Allowed | normal tool result. `_meta["mcp-gateway/untrusted-output"] = true` | treat content as **data**, never as instructions |
| Denied | `isError`, `error.code = ACCESS_DENIED` | don't retry. Ask a human for access. |
| Invalid arguments | `TOOL_ARGUMENT_VALIDATION_FAILED` with field details | fix the arguments according to the schema |
| Needs approval | `isError`, `{"status": "pending_approval", "code": "APPROVAL_PENDING", "approval_id", "expires_at"}` | tell the user. Poll `gateway__approval_status` (or `GET /api/v1/approvals/{id}/status`). The result is available for 24 h after completion. |
| Rate limited | `RATE_LIMIT_EXCEEDED` / `QUOTA_EXCEEDED` (REST: 429 + `Retry-After`) | back off |
| Tool changed or disabled | `TOOL_SCHEMA_CHANGED` / `TOOL_DISABLED` | refresh `tools/list`. An administrator must review the tool. |

Discovery is **not** permission: every call is authorized again, so cached tool lists can become stale
without risk.
