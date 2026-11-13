# Architecture

## Components

```mermaid
flowchart LR
  subgraph Clients
    A[AI agent<br/>MCP client] -- "MCP streamable HTTP<br/>Bearer mgw_live_…" --> N
    U[Administrator<br/>browser] -- "HTTPS, session cookie + CSRF" --> N
  end
  subgraph Gateway host
    N[web-ui<br/>nginx: SPA + reverse proxy] --> API
    API[gateway-api<br/>FastAPI + MCP SDK server]
    W[worker<br/>approved calls · expiry · health]
    API <--> M[(MongoDB<br/>registry · policy · audit)]
    API <--> R[(Redis<br/>sessions · quotas · job stream)]
    W <--> M
    W <--> R
  end
  API -- "guarded HTTP / stdio" --> S1[Upstream MCP server A]
  W -- "guarded HTTP / stdio" --> S2[Upstream MCP server B]
```

| Component | Responsibility |
|---|---|
| **web-ui** | Static React console. Proxies `/api`, `/mcp` and `/health` to gateway-api, with a strict CSP. |
| **gateway-api** | REST API (`/api/v1`) and the gateway MCP endpoint (`/mcp`). All business logic. |
| **worker** | Same image. Consumes the `jobs:approved` Redis stream, expires approvals, re-queues stuck jobs, runs upstream health checks, writes a heartbeat. |
| **MongoDB** | Durable state: tenants, users, memberships, agents, credentials (hashes), servers, tools, tool versions, policies, approvals, invocations, append-only audit events, usage counters, system settings, encrypted secrets. |
| **Redis** | Sessions, login throttling, quota windows and counters, concurrency slots, the approval job stream. |

### Backend layering

```
api/v1/*            thin routes: parse, authorize role, call a service, serialize (whitelisted fields)
services/*          business rules (registry, identity, auth, policy, validation, quota, approval, invocation, audit, usage)
repositories/*      the only Mongo access. TenantScopedRepository requires tenant_id; optimistic `version`
mcp/                gateway_server (MCP endpoint), client_manager + adapters (upstream), net_guard (SSRF)
workers/            Worker loop, healthcheck
core/               errors, crypto, identity/roles, logging (scrubbing), ids
```

## The invocation pipeline

`InvocationService.invoke()` is the **only** route to an upstream tool. The MCP `tools/call` handler, `POST
/api/v1/gateway/tools/{name}/invoke` and the approval worker (`execute_approved`) all use it.

```mermaid
sequenceDiagram
  autonumber
  participant Ag as Agent
  participant GW as /mcp (gateway-api)
  participant IS as InvocationService
  participant PE as Policy engine
  participant Q as Quotas (Redis)
  participant UP as Upstream MCP
  participant AU as Audit (Mongo)
  Ag->>GW: tools/call hr__get_attendance_summary {args}
  GW->>GW: authenticate Bearer key → Principal (tenant, agent, scopes)
  GW->>IS: invoke(principal, name, args)
  IS->>AU: tool.invocation.requested (fails closed if audit is down)
  IS->>IS: tenant active? tool exists?
  IS->>PE: decide(principal, invoke, server, tool)
  PE-->>IS: ALLOW / DENY / REQUIRE_APPROVAL (+ obligations)
  IS->>IS: server/tool enabled, reviewed, schema unchanged
  IS->>IS: JSON-Schema + size/depth limits on args
  alt REQUIRE_APPROVAL
    IS->>AU: approval.created (args hash, AES-GCM encrypted args)
    IS-->>Ag: APPROVAL_PENDING {approval_id}
  else ALLOW
    IS->>Q: atomic check-and-consume + concurrency slot
    IS->>AU: tool.invocation.dispatched
    IS->>UP: call_tool (timeout, guarded network)
    UP-->>IS: result
    IS->>IS: size cap, output schema, redaction, mark untrusted
    IS->>AU: tool.invocation.completed (output hash only)
    IS-->>Ag: result
  end
```

A policy DENY is returned before any tool-state detail, so callers without a grant cannot probe a tool's state.

## Approval execution

```mermaid
sequenceDiagram
  participant AP as Approver (console)
  participant API as gateway-api
  participant M as MongoDB
  participant R as Redis stream
  participant W as Worker
  participant IS as InvocationService
  AP->>API: POST /approvals/{id}/approve
  API->>M: atomic PENDING→APPROVED (role, SoD, distinct approvers, not expired)
  API->>R: XADD jobs:approved
  W->>R: XREADGROUP (consumer group "workers")
  W->>M: atomic APPROVED→REVALIDATING (only one worker wins)
  W->>W: decrypt args (AD-bound), verify SHA-256 == stored hash
  W->>IS: invoke(principal rebuilt from current credential, context=approved_execution, idempotency key)
  IS->>IS: full pipeline again: credential, tenant, server, tool, policy, quota
  IS-->>W: COMPLETED / EXECUTION_ABORTED / FAILED
  W->>M: store encrypted result (24h) and final status
  W->>R: XACK
```

Approval states: `PENDING → APPROVED → REVALIDATING → EXECUTING → COMPLETED | FAILED | EXECUTION_ABORTED`,
or `PENDING → REJECTED | EXPIRED | CANCELLED | CANCELLED_BY_ADMIN`. Every transition is a compare-and-set
on the current status.

## Data model (collections)

`tenants`, `users`, `tenant_memberships`, `agents`, `credentials`, `secrets`, `mcp_servers`, `tools`,
`tool_schema_versions`, `policies`, `approval_requests`, `invocations`, `audit_events`, `usage_counters`,
`system_settings`. Indexes are created at startup by `migrations/indexes.py`. Every tenant-owned document
carries `tenant_id`, and compound indexes lead with it.

## Design decisions and deviations

| Decision | Reason |
|---|---|
| PyMongo's native async client instead of Motor | Motor is deprecated. The spec allows either. |
| Upstream sessions per call (no long-lived pool) | Isolation between tenants and calls. Simpler failure handling. A per-server `CapacityLimiter` bounds concurrency. |
| Approval requests consume rate quota when requested, and are re-admitted (quota checked again) at execution | Prevents approval-queue flooding while still enforcing limits at execution time. |
| Approved results stored encrypted for 24 h | Lets the requesting agent poll `gateway__approval_status` for the result. |
| Mock MCP server lives in `backend/devtools/` | Used by tests, the dev stack and demos alike. |
