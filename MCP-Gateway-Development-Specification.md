# MCP-Gateway --- Secure Agent Tool Gateway

## Product Requirements, Architecture, Security Model, API Contracts, and Delivery Plan

**Document status:** Development specification\
**Version:** 1.0\
**Audience:** Coding agents, backend/frontend engineers, security
reviewers, DevOps engineers\
**Implementation approach:** API-first, modular monolith initially,
Docker-based deployment, air-gap compatible\
**Primary goal:** Provide a centralized, policy-enforced execution
boundary between AI agents and the tools/MCP servers they use.

------------------------------------------------------------------------

## 1. Executive Summary

MCP-Gateway is a self-hosted security and governance layer for agent
tool execution. It provides a central registry for MCP servers and
tools, authenticates users and agent clients, evaluates tenant- and
user-level permissions, validates tool inputs and outputs, enforces
quotas, records immutable audit events, and optionally pauses sensitive
operations for human approval.

Agents must not connect directly to privileged MCP servers in
production. Instead, an agent connects to MCP-Gateway, discovers only
the tools it is allowed to use, and invokes them through the gateway.
The gateway makes the authorization decision and executes the tool call
using a controlled upstream connection.

The gateway should support both: - **MCP-native access:** expose a
gateway MCP endpoint that an MCP-compatible client can connect to. -
**HTTP management and invocation APIs:** provide REST APIs for
administration, policy management, monitoring, and integrations.

The initial release should prioritize secure execution, clear
auditability, tenant isolation, and operational simplicity over a large
number of integrations.

### 1.1 Product principles

1.  **Default deny:** no tool is callable until explicitly enabled and
    authorized.
2.  **No direct bypass:** production agent clients should reach
    privileged tools only through the gateway network boundary.
3.  **Least privilege:** access is granted per tenant, user, agent,
    server, and tool.
4.  **Tenant isolation:** every persisted and runtime object is
    tenant-scoped; cross-tenant access is denied by default.
5.  **Policy before execution:** authenticate, authorize, validate,
    check quotas, and evaluate approval requirements before dispatch.
6.  **Fail closed:** if the policy engine, approval state, or required
    audit persistence is unavailable, sensitive execution must not
    proceed.
7.  **Auditable actions:** record who/what requested an action, what
    policy was applied, what happened, and the result.
8.  **Air-gap ready:** no runtime dependency on public SaaS, CDN assets,
    telemetry services, or external identity providers.
9.  **Protocol-aware, vendor-neutral:** support MCP transports and
    upstream implementations without coupling the gateway to one agent
    framework.
10. **Safe by design:** secrets are never returned in ordinary API
    responses or written to logs.

------------------------------------------------------------------------

## 2. Scope

### 2.1 MVP scope

-   Central MCP server registry.
-   Server connection configuration and health status.
-   Tool discovery and metadata catalog.
-   Gateway MCP endpoint for downstream agent clients.
-   REST management API.
-   Authentication for human administrators and machine/agent clients.
-   Role-based access control (RBAC) plus per-tool policy rules.
-   Tenant, user, and agent identity context.
-   Input schema validation and configurable output validation.
-   Per-user, per-agent, per-tenant, and per-tool rate limits/quotas.
-   Audit event creation for every attempted tool call.
-   Approval workflows for configured sensitive tools.
-   Admin UI for registry, policies, approvals, audit, and usage.
-   Docker Compose deployment.
-   Local configuration and secrets management suitable for isolated
    environments.

### 2.2 Post-MVP scope

-   OIDC/SAML integration with on-prem identity providers.
-   LDAP/Active Directory group synchronization.
-   Advanced policy language and policy simulation.
-   Multiple gateway replicas and distributed rate limiting.
-   Approval delegation, escalation, and time-based expiry.
-   Signed policy bundles and policy change approvals.
-   Tool response redaction and data-loss-prevention rules.
-   MCP server process isolation and sandbox runners.
-   SIEM export (syslog, webhook, OpenTelemetry logs).
-   Multi-region or multi-site federation.
-   Policy-as-code with Git review workflows.
-   Usage-based billing or chargeback reports.
-   Advanced anomaly detection.

### 2.3 Explicit non-goals for the first release

-   Building an AI agent orchestration platform.
-   Replacing MCP servers or implementing every MCP capability.
-   Storing long-term conversational memory.
-   Executing arbitrary shell commands as a general-purpose feature.
-   Automatically trusting tools discovered from an upstream server.
-   Guaranteeing that a permitted tool's business logic is safe. The
    gateway enforces access and execution controls; upstream tools still
    require secure implementation and review.

------------------------------------------------------------------------

## 3. Primary Users and Use Cases

### 3.1 Personas

  -----------------------------------------------------------------------
  Persona                             Responsibilities
  ----------------------------------- -----------------------------------
  Platform administrator              Configure gateway, tenants,
                                      identity providers, global limits,
                                      and system settings

  Security administrator              Define policies, review audit
                                      trails, manage sensitive-tool
                                      approvals

  Tenant administrator                Manage users, agents, server
                                      visibility, and policies within one
                                      tenant

  Agent/service identity              Discover and invoke permitted tools
                                      using machine credentials

  Human approver                      Approve or reject pending high-risk
                                      operations

  Auditor                             Read audit records and export
                                      evidence without changing policies

  Developer                           Register MCP servers, inspect tool
                                      schemas, and test policies in a
                                      controlled environment
  -----------------------------------------------------------------------

### 3.2 Core scenarios

1.  An agent authenticates using a client credential and requests its
    available tools.
2.  The gateway returns only tools permitted for that agent and tenant.
3.  The agent invokes a tool. The gateway validates the identity,
    policy, schema, quota, and approval requirement.
4.  A low-risk tool is executed immediately and the result is returned.
5.  A sensitive tool call is stored as pending approval. No upstream
    execution occurs until approval is granted.
6.  An approver reviews the exact proposed action, its arguments,
    requester, and risk context.
7.  Once approved, the gateway revalidates the policy and executes the
    operation using the approved argument hash.
8.  The gateway records the complete lifecycle and makes it searchable
    to authorized auditors.
9.  An administrator disables a compromised MCP server or revokes an
    agent credential; subsequent calls are blocked.

------------------------------------------------------------------------

## 4. Terminology and Core Concepts

-   **Tenant:** isolation boundary representing an organization,
    department, or environment.
-   **User:** human identity authenticated to the management UI or API.
-   **Agent:** machine identity representing an AI agent, workflow, or
    application.
-   **MCP server:** upstream server exposing tools or other MCP
    capabilities.
-   **Tool:** callable operation discovered from an MCP server.
-   **Gateway client:** downstream MCP client or application connecting
    to the gateway.
-   **Policy:** rule set determining whether an identity can discover or
    invoke a tool and under what conditions.
-   **Approval request:** durable record of a tool invocation awaiting
    human authorization.
-   **Invocation:** one attempted tool call, whether denied, awaiting
    approval, executed, or failed.
-   **Credential:** secret or certificate used by a user, agent, or
    gateway to authenticate.
-   **Tool version:** a specific observed schema/metadata revision for
    an upstream tool.

Identity types must remain distinct. A human who created an agent is not
automatically the runtime identity of every call. Store both the
authenticated caller and optional delegated/on-behalf-of context.

------------------------------------------------------------------------

## 5. High-Level Architecture

``` text
                  +------------------------------+
                  |       Admin / Auditor UI      |
                  +---------------+--------------+
                                  |
                           HTTPS / REST
                                  |
+-------------------+     +-------v-----------------------------+
| Agent / MCP Client|---->|              MCP-Gateway             |
| (LangGraph, etc.) | MCP |                                     |
+-------------------+     |  Authentication & Identity Context  |
                          |  Tool Catalog / MCP Proxy            |
                          |  Policy Decision Point (PDP)          |
                          |  Schema Validation                    |
                          |  Rate Limit / Quota                   |
                          |  Approval Workflow                    |
                          |  Audit & Usage                         |
                          +----+-----------+-----------+----------+
                               |           |           |
                         +-----v--+   +----v----+  +---v---------+
                         | Redis  |   | MongoDB|  | Secret Store|
                         | limits |   | config |  | / encrypted |
                         | cache  |   | audit  |  | credentials |
                         +--------+   +---------+  +-------------+
                               |
                 +-------------+---------------------+
                 |                                   |
          +------v-------+                    +------v-------+
          | MCP Server A |                    | MCP Server B |
          | SQL / DB     |                    | Exchange /   |
          | tools        |                    | GitLab tools |
          +--------------+                    +--------------+
```

### 5.1 Logical components

**API Gateway / Transport Layer** - Terminates TLS at the gateway or
trusted reverse proxy. - Routes REST management endpoints and MCP
requests. - Applies request size, timeout, and connection limits. -
Creates a request/correlation ID.

**Authentication Service** - Validates human sessions, API keys,
OAuth/OIDC tokens, or service credentials. - Resolves tenant, user,
agent, roles, and credential status. - Supports credential revocation
and rotation.

**Tool Registry** - Stores upstream MCP server configurations. -
Connects to upstream servers using configured transports. - Discovers
tools and captures their schemas. - Tracks server health, tool
availability, and schema versions.

**MCP Proxy** - Exposes a gateway MCP endpoint. - Performs filtered tool
discovery. - Maps downstream tool calls to upstream server/tool
identifiers. - Does not expose upstream credentials or internal network
details.

**Policy Decision Point (PDP)** - Evaluates identity, tenant, resource,
action, context, and policy. - Returns allow, deny, or
require-approval. - Produces a structured explanation suitable for audit
and admin debugging.

**Policy Enforcement Point (PEP)** - Enforces the PDP result before
dispatch. - Must be used by every execution path, including background
approval execution.

**Validation Service** - Validates tool arguments against the discovered
JSON Schema. - Enforces configured limits and custom constraints. -
Optionally validates and redacts tool results.

**Quota Service** - Applies token-bucket or sliding-window rate
limits. - Tracks usage counters and hard quotas. - Uses Redis for
distributed counters and atomic operations.

**Approval Service** - Creates approval requests. - Supports
approve/reject/cancel/expire. - Revalidates authorization and approved
payload integrity before execution.

**Audit Service** - Writes structured events for authentication, policy
decisions, tool invocation, approvals, registry changes, and
administrative changes. - Supports immutable retention/export controls.

**Admin UI** - Provides management, monitoring, policy configuration,
approval inbox, and audit search.

### 5.2 Suggested deployment topology

Initial Docker Compose services: - `gateway-api`: FastAPI REST API and
MCP endpoint. - `worker`: background execution for approved calls,
health checks, and cleanup. - `web-ui`: built static frontend served
locally or through the API/reverse proxy. - `mongodb`: persistent
registry, tenants, policies, approvals, and audit metadata. - `redis`:
rate limits, short-lived state, distributed locks, and job
coordination. - `reverse-proxy`: optional Nginx or Traefik TLS
termination.

The API and worker should share application modules but run as separate
processes. Do not run long-running tool calls or approval execution
inside a web request worker if they can exceed normal HTTP timeouts.

For a single-node installation, Compose is sufficient. Design interfaces
so Redis and MongoDB can later be replaced or clustered without
rewriting business logic.

------------------------------------------------------------------------

## 6. Technology Stack

Use stable, pinned versions at implementation time. Avoid floating
`latest` tags in production.

### 6.1 Backend

-   Python 3.12 or a currently supported stable Python version.
-   FastAPI + Uvicorn.
-   Pydantic v2 for request and configuration models.
-   PyMongo (or Motor only if the chosen version and async behavior are
    explicitly validated); use one consistent database access strategy.
-   Official MCP Python SDK for protocol handling, pinned to a tested
    version.
-   Redis for rate limits, short-lived state, and worker coordination.
-   Background worker: start with a Redis-backed task queue or a small
    internal worker. Keep the execution interface replaceable.
-   `jsonschema` or Pydantic-generated JSON Schema validation.
-   `cryptography` for encryption/signing primitives.
-   Structured logging with JSON output.
-   Pytest, pytest-asyncio, HTTPX, and testcontainers where available.

### 6.2 Frontend

-   React + TypeScript.
-   Vite build pipeline.
-   A locally bundled component library and icon set.
-   TanStack Query or equivalent for API state.
-   React Router.
-   Accessible tables, filters, dialogs, and form controls.
-   No CDN-hosted fonts, scripts, styles, analytics, or runtime
    dependencies.

If the repository already has an established frontend stack, preserve it
rather than introducing a second framework without a strong reason.

### 6.3 Infrastructure

-   Docker Engine and Docker Compose.
-   MongoDB.
-   Redis.
-   Nginx or Traefik (optional).
-   Local persistent volumes.
-   Health checks and resource limits.
-   Offline image/dependency bundle process.

### 6.4 Air-gapped requirements

-   All Python wheels and frontend packages must be lockfile-pinned and
    transferable.
-   Build container images on an internet-connected build machine,
    export with `docker save`, transfer, then `docker load` on the
    isolated environment.
-   Runtime must not download models, packages, fonts, schemas,
    telemetry agents, or assets.
-   Disable telemetry by default.
-   Do not use remote authentication, license, or analytics services as
    mandatory dependencies.
-   Provide an offline installation guide and checksum manifest.
-   Provide an SBOM and image/dependency vulnerability scan output as
    release artifacts.
-   Do not assume DNS or public certificate authorities are available;
    support customer-provided CA certificates and internal PKI.

------------------------------------------------------------------------

## 7. Authentication and Identity

### 7.1 Authentication methods

Implement in stages:

**MVP** - Human administrator login using local accounts. - Agent
credentials using high-entropy API keys. - API key prefix shown in UI;
secret shown only once. - Password hashing using Argon2id. - Secure,
HttpOnly, SameSite cookies for browser sessions. - Session expiry,
logout, and revocation.

**Next** - OIDC authorization code flow for human users. - OAuth 2.0
client credentials for agents. - LDAP/Active Directory integration and
group mapping. - mTLS for service-to-service identity. - JWT validation
with issuer/audience/expiry checks.

Do not invent a custom OAuth protocol. Use established libraries and
standards.

### 7.2 Agent credential format

A generated API key should contain: - Public key identifier/prefix,
e.g. `mgw_live_<public-id>`. - Cryptographically random secret
portion. - Creation timestamp. - Optional expiry. - Tenant ID and agent
ID. - Scopes and status. - Last-used timestamp and source metadata.

Store only a one-way hash of the secret. Compare using constant-time
operations where applicable. The full secret must be displayed only at
creation time.

### 7.3 Identity context

Every authenticated request should resolve to an immutable request
context:

``` python
class Principal:
    principal_type: Literal["user", "agent", "service"]
    principal_id: str
    tenant_id: str
    roles: list[str]
    scopes: list[str]
    credential_id: str | None
    delegated_by_user_id: str | None
    agent_id: str | None
```

Do not accept `tenant_id`, `user_id`, or role claims from an untrusted
request body as authoritative. Derive them from the validated
credential/session. Delegation must be explicit, validated, and audited.

### 7.4 Credential lifecycle

-   Create, list metadata, rotate, revoke, expire.
-   Never return secret values after creation.
-   Support emergency tenant-wide and agent-wide revocation.
-   Record who created, rotated, or revoked credentials.
-   Rate-limit authentication attempts.
-   Provide last-used and expiry information.
-   Do not log authorization headers or raw credentials.

------------------------------------------------------------------------

## 8. Authorization and Policy Model

### 8.1 Authorization dimensions

Evaluate access using all applicable dimensions:

-   Tenant.
-   Principal type and principal ID.
-   Agent ID.
-   User roles/groups.
-   MCP server.
-   Tool.
-   Action (`discover`, `invoke`, `approve`, `administer`).
-   Environment (`development`, `test`, `production`).
-   Risk classification.
-   Request context (time, source network, invocation metadata).
-   Quota and approval state.

### 8.2 Policy evaluation order

1.  Authenticate the request.
2.  Confirm principal and credential are active.
3.  Resolve tenant from trusted identity.
4.  Confirm server and tool are enabled for that tenant.
5.  Apply explicit deny rules.
6.  Evaluate allow rules and scopes.
7.  Validate tool arguments.
8.  Evaluate rate limits and quotas.
9.  Determine whether approval is required.
10. Dispatch only if the result is `ALLOW`.
11. Record the decision and result.

**Deny overrides allow.** No matching allow rule means deny. Avoid
implicit global permissions.

### 8.3 MVP policy model

Start with declarative JSON policy documents rather than a complex
general-purpose policy language.

Example:

``` json
{
  "name": "finance-read-only",
  "tenant_id": "tenant-123",
  "effect": "allow",
  "principals": {
    "types": ["agent"],
    "ids": ["agent-reporting"]
  },
  "resources": {
    "servers": ["sql-reporting"],
    "tools": ["get_attendance_summary", "get_employee_record"]
  },
  "actions": ["discover", "invoke"],
  "constraints": {
    "environments": ["production"],
    "max_calls_per_minute": 30,
    "require_approval": false
  },
  "enabled": true
}
```

Sensitive operation example:

``` json
{
  "name": "gitlab-create-merge-request",
  "tenant_id": "tenant-123",
  "effect": "allow",
  "principals": {
    "types": ["agent"],
    "ids": ["agent-securefix"]
  },
  "resources": {
    "servers": ["gitlab-admin"],
    "tools": ["create_merge_request"]
  },
  "actions": ["invoke"],
  "constraints": {
    "require_approval": true,
    "approval_policy_id": "two-person-review",
    "max_calls_per_hour": 10
  },
  "enabled": true
}
```

These examples illustrate the configuration shape; implementation must
validate every field and reject unknown or malformed policy properties.

### 8.4 Policy decision response

``` json
{
  "decision": "REQUIRE_APPROVAL",
  "reason_code": "SENSITIVE_TOOL_REQUIRES_APPROVAL",
  "policy_ids": ["policy-456"],
  "obligations": {
    "approval_policy_id": "two-person-review"
  }
}
```

Avoid returning sensitive policy internals to an agent. Provide a safe,
concise reason code externally and a detailed explanation to authorized
administrators.

### 8.5 Policy administration

-   Create, edit, enable, disable, clone, and delete policies.
-   Policy changes must be audited.
-   Show policy priority and deny-overrides behavior.
-   Provide a "test policy" simulator using a sample principal, tool,
    and arguments.
-   Display which rule allowed or denied a sample request.
-   Prevent tenant administrators from editing global policies.
-   Require a confirmation for broad grants (e.g., wildcard tool
    access).
-   Consider two-person approval for changes to production-wide policies
    in a later release.

------------------------------------------------------------------------

## 9. Tenant Isolation

Tenant isolation is a foundational security requirement, not a UI
filter.

### 9.1 Data isolation

Every tenant-owned document must include `tenant_id`. All repository
methods must require tenant context, except explicitly global
administrative operations.

Examples: - MCP server registrations. - Tool visibility and overrides. -
Agent identities. - Policies. - Approval requests. - Audit records. -
Quotas and usage. - API credentials. - User-to-tenant memberships.

### 9.2 Enforcement

-   Resolve tenant from authenticated principal.
-   Apply tenant filter in every database query and update.
-   Never trust tenant IDs supplied by the client.
-   Include tenant ID in Redis key namespaces.
-   Include tenant in background job payloads and revalidate it during
    execution.
-   Use composite indexes beginning with `tenant_id` where appropriate.
-   Add tests that attempt cross-tenant reads, updates, deletes, tool
    discovery, and invocation.
-   Global administrators must use explicit privileged code paths with
    audit records.

### 9.3 Database access pattern

Prefer repository methods such as:

``` python
await tool_repository.get_by_name(
    tenant_id=principal.tenant_id,
    server_id=server_id,
    tool_name=tool_name,
)
```

Avoid generic unscoped `find_by_id(id)` calls for tenant-owned records.
Where a globally unique ID is used, still include tenant ID in the
query.

### 9.4 Tenant provisioning

Tenant creation should provision: - Tenant record and status. - Initial
tenant administrator. - Default deny policy. - Default quotas. -
Tenant-specific audit and retention settings. - Optional default
environment.

Tenant suspension must block new invocations and agent credential use
without deleting audit history.

------------------------------------------------------------------------

## 10. MCP Server Registry and Tool Catalog

### 10.1 Server registration fields

-   `id`
-   `tenant_id` (or explicit global/shared scope)
-   `name`
-   `description`
-   `transport_type` (stdio, streamable HTTP, or other SDK-supported
    transport)
-   `endpoint` or process configuration
-   `enabled`
-   `environment`
-   `tags`
-   `owner`
-   `authentication_mode`
-   `credential_reference`
-   `connection_timeout_seconds`
-   `request_timeout_seconds`
-   `max_concurrent_calls`
-   `health_status`
-   `last_health_check_at`
-   `created_at`, `updated_at`
-   `created_by`, `updated_by`

Do not store raw upstream passwords, tokens, or private keys in ordinary
server documents. Store an encrypted secret reference or integrate with
a supported secret store.

### 10.2 Transport support

Implement only transports supported and tested by the pinned MCP SDK
version. Keep transport adapters behind a common interface.

Suggested interface:

``` python
class MCPServerAdapter(Protocol):
    async def connect(self, config: ServerConfig) -> None: ...
    async def list_tools(self) -> list[ToolDefinition]: ...
    async def call_tool(
        self, tool_name: str, arguments: dict, timeout: float
    ) -> ToolResult: ...
    async def health_check(self) -> HealthResult: ...
    async def close(self) -> None: ...
```

For stdio servers, treat process execution as privileged: - Explicit
executable allowlist. - No shell interpolation. - Fixed,
administrator-managed arguments. - Restricted environment variables. -
Non-root container/process. - Filesystem and network restrictions. -
CPU, memory, process, and execution limits. - No arbitrary user-provided
command or path.

For HTTP-based upstreams: - Enforce destination allowlists. - Block
loopback, link-local, metadata, and private network destinations unless
explicitly permitted by an administrator. - Revalidate DNS resolutions
to mitigate DNS rebinding. - Prevent redirects to disallowed
destinations. - Set request and response size limits. - Use TLS
verification by default.

### 10.3 Tool discovery

On registration or manual refresh: 1. Connect to upstream. 2. Retrieve
tool definitions. 3. Validate tool names and JSON schemas. 4. Persist
tool metadata and schema fingerprint. 5. Mark new tools as
**disabled/pending review** by default. 6. Require an administrator to
enable tools and assign risk classification. 7. Record schema changes
and notify administrators.

A tool's display name is not a stable identity. Use a stable internal
tool ID and track upstream server ID + tool name + schema
version/fingerprint.

### 10.4 Tool metadata

-   Internal tool ID.
-   Tenant ID.
-   Server ID.
-   Upstream tool name.
-   Display name and description.
-   Input JSON Schema.
-   Optional output schema.
-   Schema fingerprint and version.
-   Risk level (`low`, `medium`, `high`, `critical`).
-   Enabled status.
-   Approval requirement.
-   Timeout.
-   Maximum input/output size.
-   Tags and owner.
-   Last discovered timestamp.

### 10.5 Registry lifecycle

-   Register, edit, enable, disable, test connection, refresh tools,
    view history, delete/archive.
-   Disabling a server immediately blocks new calls.
-   In-flight call behavior must be explicit and configurable; default
    is to stop dispatching new calls and allow already-dispatched calls
    to finish within their timeout.
-   Deleting a server must not delete audit history.
-   Credential rotation must not require re-registering the server.

------------------------------------------------------------------------

## 11. Gateway MCP Endpoint

### 11.1 Client experience

An MCP client configures one gateway endpoint rather than many direct
upstream endpoints. The gateway presents a filtered tool catalog based
on the authenticated principal.

Example conceptual client configuration:

``` json
{
  "mcpServers": {
    "enterprise-gateway": {
      "url": "https://mcp-gateway.internal/mcp",
      "headers": {
        "Authorization": "Bearer <agent-api-key>"
      }
    }
  }
}
```

The exact configuration depends on the MCP client and transport
supported by the selected SDK. Document tested clients and versions.

### 11.2 Discovery behavior

-   Return only tools the principal is authorized to discover.
-   Do not reveal hidden server names, endpoints, credentials, or tools.
-   Include a stable gateway tool identifier.
-   Include concise tool description and validated input schema.
-   Re-evaluate policy on every invocation; discovery is not an
    authorization grant.
-   Refresh tool lists according to a controlled cache TTL and
    invalidation strategy.

### 11.3 Tool naming

Avoid ambiguous names when multiple upstream servers expose the same
tool name. Use a gateway namespace such as:

`<server_alias>__<tool_name>`

Maintain a mapping to internal server and tool IDs. Validate names
against MCP naming constraints and avoid exposing internal IDs
unnecessarily.

### 11.4 Invocation pipeline

Every call must use one shared execution service:

``` text
Receive MCP call
  -> Resolve request identity
  -> Resolve tenant and agent
  -> Resolve gateway tool mapping
  -> Check server/tool enabled state
  -> Evaluate policy
  -> Validate input schema and custom constraints
  -> Enforce request size and timeout
  -> Enforce rate limit and quota
  -> If approval required: persist pending approval and return safe pending result
  -> Else: create invocation record
  -> Dispatch to upstream
  -> Validate/redact output
  -> Persist completion audit
  -> Return sanitized result
```

Never implement a separate, less-secure path for MCP calls versus REST
calls.

### 11.5 Approval response over MCP

MCP clients may not support a durable asynchronous approval interaction
uniformly. The gateway should return a documented structured response
indicating that the call is pending, including an opaque approval
request ID and status endpoint reference where supported. Do not execute
the action before approval.

Do not pretend that a pending approval is a successful tool execution.
Clients should be able to poll status through the gateway's documented
API or receive a supported notification.

------------------------------------------------------------------------

## 12. Input and Output Validation

### 12.1 Input validation

-   Validate arguments against the upstream tool's JSON Schema.
-   Reject unknown fields unless the schema explicitly permits them.
-   Enforce maximum nesting depth, string length, array length, and
    total payload size.
-   Enforce numeric ranges, enum values, formats, and required fields.
-   Reject non-JSON values and malformed encodings.
-   Apply custom constraints for high-risk tools.
-   Normalize only where semantics are unambiguous; do not silently
    rewrite user intent.

### 12.2 Output validation

-   Validate against a configured output schema when available.
-   Enforce maximum output size.
-   Redact configured sensitive fields.
-   Do not return upstream stack traces, credentials, internal
    hostnames, or filesystem paths.
-   Preserve useful error codes while sanitizing error details.
-   Record validation failures and truncation/redaction metadata.

### 12.3 Untrusted tool output

Tool output is untrusted data, even when the upstream server is
registered. The gateway should: - Preserve data as data; never interpret
tool output as gateway instructions. - Clearly separate content from
metadata. - Avoid automatically following URLs or executing returned
code. - Sanitize HTML where rendered. - Mark tool output as untrusted in
logs and downstream metadata where protocol permits. - Apply
content-size and encoding checks.

------------------------------------------------------------------------

## 13. Rate Limits, Quotas, and Concurrency

### 13.1 Limit dimensions

Support configurable limits at: - Global gateway. - Tenant. - User. -
Agent. - Credential. - MCP server. - Tool. - Combined tenant + tool.

### 13.2 Limit types

-   Requests per second/minute/hour.
-   Daily and monthly call quotas.
-   Concurrent in-flight calls.
-   Maximum execution duration.
-   Maximum request/response bytes.
-   Optional weighted cost units per tool.

### 13.3 Implementation

Use Redis atomic operations (Lua scripts or an equivalent atomic
primitive) for distributed enforcement. A local in-memory fallback may
be offered only for development/single-process mode and must be clearly
labeled as non-distributed.

Return HTTP `429` for REST calls with `Retry-After`. For MCP, return a
protocol-appropriate error with a stable gateway error code.

### 13.4 Quota behavior

-   Distinguish soft warning thresholds from hard stops.
-   Define whether failed calls consume quota.
-   Define whether approval-pending calls reserve quota.
-   Prevent race conditions when multiple requests approach a quota
    simultaneously.
-   Record usage by tenant, agent, tool, and time bucket.
-   Provide admin-configurable quota reset windows.

------------------------------------------------------------------------

## 14. Approval Workflows

### 14.1 Risk classification

Every enabled tool must have a risk classification: - **Low:** read-only
lookup with limited data exposure. - **Medium:** bounded internal change
or write with easy rollback. - **High:** external communication,
privileged modification, sensitive data access, or impactful change. -
**Critical:** destructive, financial, identity/security administration,
broad infrastructure, or irreversible action.

Risk is assigned by administrators, not inferred solely from tool
descriptions.

### 14.2 Approval policy options

-   No approval.
-   One approver.
-   Two distinct approvers.
-   Approver from a specified role/group.
-   Approver must not be the requester.
-   Approval expires after a configured duration.
-   Require a comment for rejection.
-   Optional reason/comment for approval.
-   Restrict approvers by tenant and environment.

### 14.3 Approval lifecycle

``` text
PENDING
  |-- approve --> APPROVED -> REVALIDATING -> EXECUTING -> COMPLETED / FAILED
  |-- reject  --> REJECTED
  |-- cancel  --> CANCELLED
  |-- timeout --> EXPIRED
```

Additional terminal states may include `CANCELLED_BY_ADMIN` and
`EXECUTION_ABORTED`.

### 14.4 Approval security requirements

-   Approval applies to the exact tool, server, tenant, principal, and
    argument payload hash.
-   Store a canonicalized argument representation and cryptographic
    hash.
-   Any argument change invalidates the approval.
-   Re-evaluate current authorization immediately before execution.
-   Re-check server/tool enabled state and credential status.
-   Re-check quotas and applicable safety constraints.
-   Prevent the requester from approving their own request when
    separation of duties is enabled.
-   Use atomic state transitions to prevent double execution.
-   Idempotency key prevents duplicate upstream execution where
    supported.
-   Expired or rejected requests must never execute.
-   Approvers see a clear summary and exact arguments, with sensitive
    values masked according to policy.
-   Record approver identity, timestamp, decision, and comment.

### 14.5 Approval UX

Approval inbox columns: - Request ID. - Requested action. - Tenant. -
Requester/agent. - Risk. - Created time. - Expiry. - Status.

Approval detail: - Tool and server. - Business purpose/reason if
supplied. - Exact arguments (redacted as configured). - Requester
identity and delegated user. - Policy requiring approval. - Risk
classification. - Previous related actions. - Approve/reject controls. -
Mandatory confirmation for critical actions.

------------------------------------------------------------------------

## 15. Audit Logging and Observability

### 15.1 Events to record

-   Authentication success/failure.
-   Credential created, rotated, revoked, expired.
-   Server registered, changed, enabled, disabled, deleted.
-   Tool discovered, enabled, disabled, schema changed.
-   Policy created, changed, enabled, disabled, deleted.
-   Authorization allow/deny/approval-required.
-   Tool invocation requested, rejected, pending, dispatched, completed,
    failed, timed out.
-   Approval created, viewed (optional), approved, rejected, expired,
    cancelled.
-   Tenant and user administration changes.
-   Quota exceeded.
-   Configuration and security-setting changes.

### 15.2 Audit event schema

``` json
{
  "event_id": "evt_...",
  "tenant_id": "tenant-123",
  "timestamp": "2026-11-13T08:00:00Z",
  "event_type": "tool.invocation.completed",
  "severity": "info",
  "request_id": "req_...",
  "invocation_id": "inv_...",
  "principal": {
    "type": "agent",
    "id": "agent-reporting",
    "credential_id": "cred_..."
  },
  "delegated_by_user_id": null,
  "resource": {
    "server_id": "srv_...",
    "tool_id": "tool_...",
    "tool_name": "get_attendance_summary"
  },
  "decision": "ALLOW",
  "policy_ids": ["pol_..."],
  "status": "success",
  "duration_ms": 245,
  "input_hash": "sha256:...",
  "output_hash": "sha256:...",
  "metadata": {
    "schema_version": "..."
  }
}
```

### 15.3 Audit integrity

-   Append-only application behavior.
-   Restrict update/delete permissions on audit collections.
-   Use hash chaining or signed batch manifests as a later integrity
    enhancement.
-   Export to customer-controlled immutable storage or SIEM.
-   Retention configurable by tenant and event type.
-   Audit export actions themselves.
-   Do not store full input/output payloads by default. Store hashes,
    safe summaries, and explicitly configured redacted fields.
-   If payload capture is enabled for troubleshooting, require explicit
    policy, encryption, restricted access, and short retention.

### 15.4 Monitoring

Expose: - Request count and latency. - Tool call count and latency by
server/tool. - Authorization denials. - Approval queue depth and age. -
Upstream health and connection failures. - Rate-limit rejections. -
Worker queue depth. - Redis/Mongo connectivity. - In-flight call
count. - Error rates and timeouts.

Provide `/health/live` and `/health/ready`. Readiness should fail if
critical dependencies are unavailable. Metrics should be local and
protected; do not expose sensitive tenant labels without access control.

------------------------------------------------------------------------

## 16. REST API Design

Prefix all management APIs with `/api/v1`.

### 16.1 Authentication

  Method   Endpoint                         Purpose
  -------- -------------------------------- --------------------------
  POST     `/auth/login`                    Local user login
  POST     `/auth/logout`                   End browser session
  GET      `/auth/me`                       Current principal
  POST     `/auth/agent-keys`               Create agent credential
  GET      `/auth/agent-keys`               List credential metadata
  POST     `/auth/agent-keys/{id}/rotate`   Rotate credential
  POST     `/auth/agent-keys/{id}/revoke`   Revoke credential

### 16.2 Tenants and identities

  Method      Endpoint                 Purpose
  ----------- ------------------------ ------------------------------------
  GET/POST    `/tenants`               List/create tenants (global admin)
  GET/PATCH   `/tenants/{id}`          Read/update tenant
  GET/POST    `/tenants/{id}/users`    Manage tenant users
  GET/POST    `/tenants/{id}/agents`   Manage agent identities
  GET/PATCH   `/agents/{id}`           Read/update agent
  POST        `/agents/{id}/revoke`    Disable agent

### 16.3 MCP registry

  Method             Endpoint                        Purpose
  ------------------ ------------------------------- ----------------------------------
  GET/POST           `/servers`                      List/register MCP servers
  GET/PATCH/DELETE   `/servers/{id}`                 Manage server
  POST               `/servers/{id}/test`            Test connection
  POST               `/servers/{id}/refresh-tools`   Rediscover tools
  GET                `/servers/{id}/tools`           List tools
  GET                `/tools/{id}`                   Tool details
  PATCH              `/tools/{id}`                   Configure risk/enablement/limits
  GET                `/tools/{id}/versions`          Schema history

### 16.4 Policies

  Method             Endpoint                   Purpose
  ------------------ -------------------------- -------------------------
  GET/POST           `/policies`                List/create
  GET/PATCH/DELETE   `/policies/{id}`           Manage policy
  POST               `/policies/{id}/enable`    Enable
  POST               `/policies/{id}/disable`   Disable
  POST               `/policies/simulate`       Evaluate sample request

### 16.5 Approvals

  Method   Endpoint                    Purpose
  -------- --------------------------- ------------------------
  GET      `/approvals`                List approval requests
  GET      `/approvals/{id}`           Approval detail
  POST     `/approvals/{id}/approve`   Approve
  POST     `/approvals/{id}/reject`    Reject
  POST     `/approvals/{id}/cancel`    Cancel if permitted

### 16.6 Audit and usage

  Method   Endpoint               Purpose
  -------- ---------------------- ----------------------------
  GET      `/audit/events`        Search audit events
  GET      `/audit/events/{id}`   Event detail
  POST     `/audit/export`        Create export
  GET      `/usage/summary`       Usage overview
  GET      `/usage/by-tool`       Tool usage
  GET      `/usage/by-agent`      Agent usage
  GET      `/metrics`             Protected metrics endpoint

### 16.7 API conventions

-   Use consistent pagination (`limit`, `cursor`) for large collections.
-   Validate all request bodies with Pydantic.
-   Use stable error codes and a consistent error envelope.
-   Include `request_id` in responses and logs.
-   Support idempotency keys for create/execute operations where
    appropriate.
-   Use optimistic concurrency (`version` or ETag) for policy and
    registry updates.
-   Return `401` for unauthenticated, `403` for unauthorized, `404`
    where resource existence should not be disclosed, `409` for state
    conflicts, `422` for validation errors, `429` for rate limits, and
    `503` for unavailable dependencies.
-   Never expose stack traces in production responses.

Example error:

``` json
{
  "error": {
    "code": "TOOL_ARGUMENT_VALIDATION_FAILED",
    "message": "The supplied arguments do not match the tool schema.",
    "request_id": "req_...",
    "details": [
      {"field": "employee_id", "code": "required"}
    ]
  }
}
```

------------------------------------------------------------------------

## 17. Data Model

Use MongoDB collections initially. Define indexes and validation rules
in migrations/startup checks.

### 17.1 Collections

**tenants** - `_id`, `name`, `slug`, `status`, `settings`, `created_at`,
`updated_at`.

**users** - `_id`, `username`, `email`, `password_hash`, `status`,
`created_at`, `last_login_at`.

**tenant_memberships** - `_id`, `tenant_id`, `user_id`, `roles`,
`status`, `created_at`.

**agents** - `_id`, `tenant_id`, `name`, `description`, `status`,
`owner_user_id`, `tags`, `created_at`.

**credentials** - `_id`, `tenant_id`, `principal_type`, `principal_id`,
`key_prefix`, `secret_hash`, `scopes`, `expires_at`, `revoked_at`,
`last_used_at`, `created_at`.

**mcp_servers** - `_id`, `tenant_id`, `name`, `transport`,
`connection_config`, `secret_ref`, `status`, `health`, `created_at`,
`updated_at`.

**tools** - `_id`, `tenant_id`, `server_id`, `upstream_name`,
`gateway_name`, `description`, `input_schema`, `output_schema`,
`schema_hash`, `risk_level`, `enabled`, `approval_config`, `limits`,
`updated_at`.

**tool_schema_versions** - `_id`, `tenant_id`, `tool_id`, `schema_hash`,
`input_schema`, `output_schema`, `discovered_at`, `discovered_by`.

**policies** - `_id`, `tenant_id` (nullable only for explicitly global
policies), `name`, `description`, `effect`, `principals`, `resources`,
`actions`, `constraints`, `priority`, `enabled`, `version`,
`created_by`, `updated_by`, timestamps.

**approval_requests** - `_id`, `tenant_id`, `invocation_id`,
`requester`, `tool_id`, `server_id`, `arguments_encrypted` or
policy-approved redacted representation, `arguments_hash`, `policy_id`,
`required_approvals`, `approvals`, `status`, `expires_at`, timestamps.

**invocations** - `_id`, `tenant_id`, `request_id`, `principal`,
`tool_id`, `server_id`, `decision`, `status`, `input_hash`,
`output_hash`, `duration_ms`, `error_code`, timestamps.

**audit_events** - `_id`, `event_id`, `tenant_id`, `timestamp`,
`event_type`, `principal`, `resource`, `decision`, `request_id`,
`invocation_id`, `metadata`, `integrity_hash` (optional later).

**usage_counters** - `_id`, `tenant_id`, `period`, `principal_id`,
`tool_id`, `count`, `weighted_units`, `updated_at`.

**system_settings** - `_id`, `key`, `value`, `updated_at`, `updated_by`.

### 17.2 Indexes

At minimum: - `tenants.slug` unique. - `users.username` unique (and
normalized email where applicable). - `tenant_memberships`: unique
`(tenant_id, user_id)`. - `agents`: `(tenant_id, status)`. -
`credentials`: unique `key_prefix`; indexes on
`(tenant_id, principal_id, revoked_at)`. - `mcp_servers`: unique
`(tenant_id, name)`. - `tools`: unique
`(tenant_id, server_id, upstream_name)` and
`(tenant_id, gateway_name)`. - `policies`:
`(tenant_id, enabled, priority)`. - `approval_requests`:
`(tenant_id, status, created_at)` and `(tenant_id, expires_at)`. -
`invocations`: `(tenant_id, created_at)`,
`(tenant_id, principal.id, created_at)`,
`(tenant_id, tool_id, created_at)`. - `audit_events`:
`(tenant_id, timestamp)`, `(tenant_id, event_type, timestamp)`,
`(tenant_id, request_id)`. - TTL indexes only for explicitly expiring
transient data, never as the only retention control for audit evidence.

Use MongoDB transactions where supported and required for multi-document
state transitions. Do not assume a standalone MongoDB deployment
supports replica-set transactions; document the required topology or
design operations to be safe without them.

------------------------------------------------------------------------

## 18. Frontend Application Design

The UI should feel like a professional enterprise security console: dark
navy/neutral surfaces, restrained accent color, clear status indicators,
dense but readable tables, and responsive layouts. Prioritize clarity
and operational workflows over decorative dashboards.

### 18.1 Global layout

-   Left navigation sidebar.
-   Top bar with tenant selector (only for users with multiple tenants),
    environment indicator, global search, notifications, and profile
    menu.
-   Main content with breadcrumbs, page title, short description, and
    contextual actions.
-   Persistent request/error feedback.
-   Role-aware navigation; hiding a menu item is not authorization.

### 18.2 Navigation

1.  Overview
2.  MCP Servers
3.  Tool Catalog
4.  Policies
5.  Agents & Credentials
6.  Approvals
7.  Audit Logs
8.  Usage & Quotas
9.  Users & Tenants (admin roles)
10. Settings

### 18.3 Overview dashboard

Cards: - Registered MCP servers. - Enabled tools. - Active agents. -
Tool calls today. - Pending approvals. - Denied calls.

Charts: - Tool invocations over time. - Allow/deny/approval-required
distribution. - Top tools by usage. - Upstream server health.

Recent activity table: - Time, principal, tool, decision, duration,
status.

Health panel: - Gateway API, worker, MongoDB, Redis, MCP upstreams.

### 18.4 MCP Servers page

Table columns: - Server name. - Transport. - Environment. - Health. -
Discovered tools. - Enabled tools. - Last check. - Status. - Actions.

Actions: - Add server. - Test connection. - Refresh tools. -
Enable/disable. - Edit. - View details.

Add/edit wizard: 1. Basic information. 2. Transport and endpoint/process
configuration. 3. Authentication and secret reference. 4. Timeouts and
concurrency. 5. Test connection. 6. Review and save.

Security warning for stdio process configuration and private network
destinations.

### 18.5 Server detail page

Tabs: - Overview. - Tools. - Configuration. - Health. - Audit/history.

Show endpoint without secrets, transport, owner, environment, health
history, connection errors (sanitized), and tool discovery status.

### 18.6 Tool Catalog page

Filters: - Server. - Risk. - Enabled/disabled. - Approval required. -
Environment. - Search.

Columns: - Tool. - Server. - Risk. - Enabled. - Approval. - Calls
(period). - Schema version. - Updated.

Tool detail: - Description. - Input schema viewer. - Output schema
viewer. - Risk classification. - Enable/disable. - Approval policy. -
Timeout and payload limits. - Per-tool quotas. - Allowed
principals/policies. - Schema history. - "Test policy" action (must not
execute the real tool).

### 18.7 Policies page

-   Policy list with name, effect, scope, status, priority, updated
    by/time.
-   Policy editor with guided principal/resource/action/constraint
    controls.
-   Advanced JSON view for developers.
-   Validation errors inline.
-   Policy simulator.
-   Change history.
-   Clear warning when policy grants broad or wildcard access.

### 18.8 Agents & Credentials page

-   Agent list, owner, tenant, status, credential count, last activity.
-   Agent detail with assigned policies, permitted tools, quota,
    invocation history.
-   Create/rotate/revoke key flow.
-   Show generated secret exactly once with copy action and warning.
-   Never show stored hashes or secret material.

### 18.9 Approvals page

-   Queue tabs: Pending, Approved, Rejected, Expired.
-   Filters by risk, requester, tool, age.
-   Detail side panel or page.
-   Exact action arguments with configured redaction.
-   Approve/reject with comments.
-   Separation-of-duties warning.
-   Show whether the policy or tool changed after request creation.

### 18.10 Audit Logs page

Filters: - Date range. - Tenant. - Principal. - Agent. - Server/tool. -
Event type. - Decision. - Status. - Request ID.

Table: - Timestamp. - Principal. - Action/tool. - Decision. - Status. -
Duration. - Request ID.

Detail view: - Identity context. - Policy decision and policy
references. - Tool/schema version. - Input/output hashes. - Redacted
metadata. - Approval lifecycle. - Correlated events.

Export CSV/JSON with authorization checks, export size limits, and an
audit event for every export.

### 18.11 Usage & Quotas page

-   Usage summary by tenant/agent/tool.
-   Rate-limit configuration.
-   Daily/monthly quota utilization.
-   Concurrent calls.
-   Threshold warnings.
-   Historical usage chart.

### 18.12 Settings

-   Authentication and session settings.
-   Default-deny and global security settings.
-   Audit retention.
-   Payload limits.
-   Upstream network allowlists.
-   TLS/CA configuration.
-   System health and version information.
-   Feature flags.

------------------------------------------------------------------------

## 19. Security Requirements and Threat Model

### 19.1 Threats to address

-   Stolen or leaked agent credentials.
-   Cross-tenant data access.
-   Privilege escalation through policy misconfiguration.
-   Direct access to upstream MCP servers bypassing the gateway.
-   Malicious or compromised MCP server.
-   Prompt injection embedded in tool output.
-   Tool schema poisoning or unexpected schema changes.
-   SSRF through configurable HTTP endpoints.
-   Command injection through stdio process configuration.
-   DNS rebinding and redirect-based network bypass.
-   Replay or duplicate execution of sensitive operations.
-   Approval payload substitution.
-   Audit tampering or unauthorized access.
-   Denial of service through large payloads or expensive tools.
-   Secret leakage in logs, errors, traces, or UI.
-   Race conditions in quotas and approval transitions.

### 19.2 Required controls

-   Default deny and explicit grants.
-   Tenant scoping at repository and service layers.
-   TLS for all network communication.
-   Strong secret hashing/encryption and rotation.
-   No secrets in logs or API responses.
-   Input/output size and timeout limits.
-   SSRF protections and destination allowlists.
-   No shell interpolation.
-   Per-tool risk classification.
-   Approval payload hash binding.
-   Idempotency and atomic state transitions.
-   Audit every security-relevant action.
-   Restrict management APIs by role.
-   Security headers and CSRF protection for cookie-based sessions.
-   CORS allowlist; no wildcard credentials.
-   Dependency pinning and vulnerability scanning.
-   Container non-root execution and least privilege.
-   Read-only filesystem where practical.
-   Drop unnecessary Linux capabilities.
-   No Docker socket mount in the gateway container.
-   Separate gateway and upstream network segments where possible.

### 19.3 Network architecture recommendation

In production: - Agent network can reach gateway only. - Gateway can
reach approved MCP upstreams. - Upstream MCP servers should not be
publicly exposed. - Management UI/API should be reachable only from
admin networks where possible. - Database and Redis should not be
published to host interfaces unless explicitly required. - Egress rules
should allow only approved destinations. - Do not assume that gateway
authorization alone prevents bypass if clients can reach upstream
servers directly.

### 19.4 Security failure behavior

  -----------------------------------------------------------------------
  Failure                             Required behavior
  ----------------------------------- -----------------------------------
  Authentication service unavailable  Reject new authenticated requests

  Policy engine unavailable           Deny tool invocation

  Redis unavailable                   Fail closed for configured hard
                                      quotas; configurable safe mode only
                                      for non-sensitive development

  Audit persistence unavailable       Block sensitive execution;
                                      configurable policy for low-risk
                                      operations must be explicit

  Upstream unavailable                Return sanitized
                                      upstream-unavailable error

  Approval service unavailable        Do not execute approval-required
                                      action

  Schema unavailable or invalid       Do not execute tool

  Credential revoked during pending   Revalidate and deny execution
  approval                            
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 20. Error Model

Define stable internal error codes, for example:

-   `AUTHENTICATION_REQUIRED`
-   `INVALID_CREDENTIAL`
-   `CREDENTIAL_REVOKED`
-   `TENANT_SUSPENDED`
-   `ACCESS_DENIED`
-   `SERVER_DISABLED`
-   `TOOL_DISABLED`
-   `TOOL_NOT_FOUND`
-   `TOOL_SCHEMA_CHANGED`
-   `TOOL_ARGUMENT_VALIDATION_FAILED`
-   `TOOL_OUTPUT_VALIDATION_FAILED`
-   `RATE_LIMIT_EXCEEDED`
-   `QUOTA_EXCEEDED`
-   `APPROVAL_REQUIRED`
-   `APPROVAL_PENDING`
-   `APPROVAL_EXPIRED`
-   `APPROVAL_INVALIDATED`
-   `UPSTREAM_UNAVAILABLE`
-   `UPSTREAM_TIMEOUT`
-   `UPSTREAM_EXECUTION_FAILED`
-   `AUDIT_UNAVAILABLE`
-   `GATEWAY_INTERNAL_ERROR`

Map these consistently to REST and MCP-compatible errors. Never include
secrets, full stack traces, or untrusted upstream error payloads in
client-facing messages.

------------------------------------------------------------------------

## 21. Repository Structure

Suggested monorepo:

``` text
mcp-gateway/
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── .env.example
├── docker-compose.yml
├── Dockerfile
├── Makefile
├── docs/
│   ├── architecture.md
│   ├── security-model.md
│   ├── deployment.md
│   ├── air-gapped-installation.md
│   ├── api-reference.md
│   ├── mcp-client-configuration.md
│   └── threat-model.md
├── backend/
│   ├── pyproject.toml
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── api/
│   │   │   └── v1/
│   │   ├── mcp/
│   │   │   ├── gateway_server.py
│   │   │   ├── client_manager.py
│   │   │   ├── adapters/
│   │   │   └── schemas.py
│   │   ├── core/
│   │   │   ├── identity.py
│   │   │   ├── errors.py
│   │   │   ├── security.py
│   │   │   └── logging.py
│   │   ├── services/
│   │   │   ├── auth_service.py
│   │   │   ├── registry_service.py
│   │   │   ├── tool_catalog_service.py
│   │   │   ├── policy_service.py
│   │   │   ├── invocation_service.py
│   │   │   ├── validation_service.py
│   │   │   ├── quota_service.py
│   │   │   ├── approval_service.py
│   │   │   └── audit_service.py
│   │   ├── repositories/
│   │   ├── models/
│   │   ├── workers/
│   │   └── migrations/
│   └── tests/
│       ├── unit/
│       ├── integration/
│       ├── security/
│       └── contract/
├── frontend/
│   ├── package.json
│   ├── package-lock.json
│   ├── src/
│   │   ├── app/
│   │   ├── components/
│   │   ├── features/
│   │   │   ├── dashboard/
│   │   │   ├── servers/
│   │   │   ├── tools/
│   │   │   ├── policies/
│   │   │   ├── agents/
│   │   │   ├── approvals/
│   │   │   ├── audit/
│   │   │   └── usage/
│   │   ├── services/
│   │   └── styles/
│   └── public/
├── deploy/
│   ├── nginx/
│   ├── scripts/
│   ├── offline/
│   └── examples/
└── .github/
    └── workflows/
```

Keep business logic out of route handlers. Route handlers should
authenticate, validate transport-level input, call services, and
serialize responses.

------------------------------------------------------------------------

## 22. Configuration

Provide environment variables with safe defaults and validation at
startup.

Example `.env.example`:

``` dotenv
APP_ENV=production
APP_HOST=0.0.0.0
APP_PORT=8080
LOG_LEVEL=INFO

MONGODB_URI=mongodb://mongodb:27017
MONGODB_DATABASE=mcp_gateway

REDIS_URL=redis://redis:6379/0

SESSION_SECRET=replace-with-random-secret
DATA_ENCRYPTION_KEY=replace-with-managed-key
API_KEY_HASH_PEPPER=replace-with-random-secret

PUBLIC_BASE_URL=https://mcp-gateway.internal
MCP_ENDPOINT_PATH=/mcp

DEFAULT_TOOL_TIMEOUT_SECONDS=30
MAX_TOOL_TIMEOUT_SECONDS=300
MAX_INPUT_BYTES=1048576
MAX_OUTPUT_BYTES=4194304
MAX_CONCURRENT_CALLS_PER_AGENT=10

AUDIT_REQUIRED_FOR_EXECUTION=true
AUDIT_RETENTION_DAYS=365

ALLOW_PRIVATE_UPSTREAM_NETWORKS=false
UPSTREAM_HOST_ALLOWLIST=
CORS_ALLOWED_ORIGINS=https://mcp-gateway.internal

BOOTSTRAP_ADMIN_USERNAME=
BOOTSTRAP_ADMIN_PASSWORD=
```

Requirements: - Validate secrets and reject known placeholders in
production. - Do not silently generate a new encryption key on every
restart. - Provide a documented key rotation procedure. - Support
mounted secret files where possible. - Never commit production `.env`
files. - Avoid logging configuration values that contain secrets.

------------------------------------------------------------------------

## 23. Testing Strategy

### 23.1 Unit tests

-   Authentication and credential hashing.
-   Policy evaluation and deny-overrides.
-   Tenant-scoped repository behavior.
-   JSON Schema validation.
-   Risk and approval requirement evaluation.
-   Quota calculations.
-   Error mapping and redaction.
-   Approval state transitions.

### 23.2 Integration tests

-   Register a mock MCP server and discover tools.
-   Invoke a permitted tool.
-   Deny a forbidden tool.
-   Ensure hidden tools are not discoverable.
-   Enforce rate limits.
-   Create and approve a sensitive invocation.
-   Reject/expire/cancel an approval.
-   Verify approved payload cannot be modified.
-   Rotate/revoke an agent key.
-   Handle upstream timeout and disconnect.
-   Validate audit events are created.

### 23.3 Security tests (release blockers)

-   Tenant A cannot list/read/update Tenant B's servers, tools, agents,
    policies, approvals, or audit events.
-   A tenant cannot forge tenant identity in request bodies or headers.
-   A disabled tool cannot be invoked even if cached in client
    discovery.
-   A revoked credential cannot execute a pending approval.
-   Approval cannot be reused for a different argument payload.
-   Two concurrent approval workers cannot execute the same request
    twice.
-   A policy engine error cannot result in an allow.
-   SSRF attempts to loopback, link-local, cloud metadata, and
    disallowed private addresses are blocked.
-   Redirect and DNS-rebinding attempts are blocked.
-   Stdio configuration cannot execute arbitrary shell syntax.
-   Oversized/deeply nested payloads are rejected.
-   Secrets do not appear in logs, error responses, audit metadata, or
    frontend API state.
-   CSRF, session fixation, CORS, and authorization boundary tests pass.

### 23.4 Contract tests

-   Pin MCP SDK version and test protocol compatibility.
-   Test with at least one command-line MCP client and one application
    client.
-   Validate tool discovery and invocation semantics.
-   Validate pending approval behavior.
-   Test reconnects and upstream schema refresh.

### 23.5 Performance tests

Measure: - Gateway overhead for low-latency tools. - Concurrent calls
per agent/tenant. - Redis quota throughput. - MongoDB audit write
throughput. - Tool discovery latency. - Large output behavior. - Worker
backlog under upstream slowness.

Do not publish performance claims until measured on documented hardware
and configuration.

------------------------------------------------------------------------

## 24. Delivery Roadmap

### Phase 0 --- Project foundation

-   Repository and coding standards.
-   Docker Compose baseline.
-   FastAPI app, MongoDB, Redis.
-   Configuration and structured logging.
-   Health endpoints.
-   CI with lint, type checks, tests, dependency scanning.
-   Local mock MCP server.

**Exit criteria:** clean startup, health checks, reproducible local
development, no external runtime calls.

### Phase 1 --- Registry and tool catalog

-   Server CRUD.
-   MCP adapter abstraction.
-   Connect/test/health.
-   Tool discovery and schema storage.
-   Tool enable/disable and risk classification.
-   Schema fingerprint/version history.
-   Basic registry UI.

**Exit criteria:** administrator can register a mock/real supported MCP
server, inspect tools, and explicitly enable selected tools.

### Phase 2 --- Identity and tenant isolation

-   Local human authentication.
-   Tenant and membership model.
-   Agent identities and API keys.
-   Credential rotation/revocation.
-   Principal context middleware.
-   Tenant-scoped repositories and tests.
-   Role-based management authorization.

**Exit criteria:** all tenant-owned resources are isolated; agent
clients authenticate; revoked credentials are denied.

### Phase 3 --- Secure MCP gateway and policy engine

-   Gateway MCP endpoint.
-   Filtered discovery.
-   Central invocation service.
-   Policy CRUD and evaluation.
-   Per-tool allow/deny.
-   Input schema validation.
-   Audit events for all invocation decisions.

**Exit criteria:** an agent can only discover and invoke explicitly
permitted tools through the gateway.

### Phase 4 --- Quotas, approvals, and output controls

-   Redis rate limits and quotas.
-   Concurrency limits and timeouts.
-   Approval policies and inbox.
-   Exact payload hash binding.
-   Worker-based approved execution.
-   Output validation and redaction.
-   Usage dashboard.

**Exit criteria:** sensitive actions cannot execute before approval;
approved calls execute once after revalidation.

### Phase 5 --- Production hardening

-   SSRF and stdio hardening.
-   Audit retention/export.
-   Security headers and CSRF.
-   Backup/restore.
-   Key rotation.
-   Air-gap installation bundle.
-   SBOM and vulnerability scan.
-   Threat-model review and penetration test.
-   Operational runbooks.

**Exit criteria:** documented production deployment, security tests
passing, restore procedure tested, no mandatory external dependency.

### Phase 6 --- Enterprise integrations

-   OIDC/OAuth2.
-   LDAP/AD.
-   mTLS.
-   SIEM integration.
-   Policy-as-code.
-   Multi-replica deployment.
-   Advanced approval delegation.

------------------------------------------------------------------------

## 25. MVP Acceptance Criteria

The MVP is complete only when all of the following are true:

1.  An administrator can register an upstream MCP server and test its
    connection.
2.  The gateway can discover tools and store validated schemas.
3.  Newly discovered tools are not automatically exposed or enabled.
4.  An administrator can create a tenant and an agent identity.
5.  An agent can authenticate with a generated API key.
6.  An agent sees only tools allowed by its tenant and policy.
7.  Every invocation is authorized again at call time.
8.  Invalid arguments are rejected before upstream dispatch.
9.  A denied invocation never reaches the upstream server.
10. Per-tool and per-agent limits are enforced.
11. A sensitive tool can be configured to require approval.
12. A pending approval does not execute the tool.
13. Approval is bound to the exact argument hash and cannot be reused.
14. Approval execution revalidates credential, policy, tool, and server
    status.
15. Every invocation attempt has a correlated audit record.
16. Tenant A cannot access Tenant B's records or tools.
17. Credentials and upstream secrets are never returned after creation.
18. The application starts using Docker Compose without public internet
    access.
19. The frontend contains no runtime CDN dependency.
20. Automated unit, integration, and security tests pass.

------------------------------------------------------------------------

## 26. Coding Agent Implementation Instructions

The coding agent should implement the application incrementally. Do not
generate the entire platform in one pass.

### 26.1 Mandatory engineering rules

-   Read this document before coding and treat it as the source of
    truth.
-   Start by producing a concise implementation plan and repository
    tree.
-   Build a modular monolith; do not introduce microservices or
    Kubernetes for the MVP.
-   Use FastAPI, MongoDB, Redis, Docker Compose, and React/TypeScript
    unless the repository already establishes a compatible alternative.
-   Pin all dependencies and container image versions.
-   Keep API routes thin; put business rules in services.
-   Keep database access in repositories.
-   Every tenant-owned repository method must require tenant context.
-   Use one shared invocation service for MCP and REST execution paths.
-   Never bypass policy evaluation for background jobs.
-   Use default-deny authorization.
-   Never execute an upstream tool before validation, quota checks, and
    approval evaluation.
-   Do not automatically enable newly discovered tools.
-   Do not store plaintext credentials.
-   Do not log raw tool arguments/results by default.
-   Do not use arbitrary shell commands for stdio server configuration.
-   Do not expose MongoDB or Redis publicly in the default Compose file.
-   Do not add cloud APIs, hosted telemetry, CDN resources, or mandatory
    external identity services.
-   Include tests with each feature; security tests are not a final
    optional task.
-   Keep all configuration documented in `.env.example`.
-   Add migrations/index initialization and startup validation.
-   Provide meaningful error messages without leaking internals.
-   Document any deviation from this specification.

### 26.2 Required implementation sequence

For every phase: 1. Inspect existing repository and identify reusable
code. 2. Propose files/modules to add or change. 3. Implement backend
models, services, repositories, and API. 4. Add automated tests. 5.
Implement corresponding UI. 6. Add Docker/configuration updates. 7. Run
tests and report exact results. 8. Update README and relevant docs. 9.
Summarize completed work, limitations, and next phase.

Do not claim a feature is complete unless its tests pass. Do not replace
real implementation with mock responses except in explicitly named
development fixtures.

### 26.3 First coding-agent task

Begin with **Phase 0 and the foundation of Phase 1**: - Create the
repository structure. - Add Docker Compose for API, worker, MongoDB, and
Redis. - Add FastAPI startup/configuration/logging/health checks. - Add
MongoDB connection and repository base. - Add Redis connection and
health check. - Implement a mock MCP server for integration tests. -
Implement MCP adapter interface and server registry data model. - Add
initial server CRUD API and tests. - Add a minimal frontend shell with
navigation and MCP Servers list. - Provide local developer setup and
air-gapped packaging notes.

Do not implement approval execution or production authorization
shortcuts in this first task. Establish the shared service interfaces
and secure defaults so later phases do not need architectural rewrites.

### 26.4 Definition of done for each feature

A feature is done only when: - API and data model are implemented. -
Authorization is enforced server-side. - Tenant isolation is tested
where relevant. - Input validation and error handling exist. - Audit
events are emitted where relevant. - UI states include loading, empty,
success, and error. - Unit/integration tests pass. - Documentation is
updated. - No secrets or sensitive payloads leak into logs.

------------------------------------------------------------------------

## 27. Operational Runbooks

Create runbooks for: - Initial installation and bootstrap
administrator. - Air-gapped image/dependency transfer. - Backup and
restore of MongoDB and encryption keys. - Redis recovery and quota
behavior. - Gateway restart and rolling update. - MCP server outage. -
Compromised agent credential response. - Tenant suspension. - Emergency
server/tool disablement. - Policy rollback. - Approval queue stuck or
worker failure. - Audit export and retention. - Encryption key rotation.

Emergency actions should be available to authorized administrators and
generate high-severity audit events.

------------------------------------------------------------------------

## 28. Documentation Deliverables

The project should include: - `README.md`: overview, quick start,
supported features. - `docs/architecture.md`: component and sequence
diagrams. - `docs/security-model.md`: identity, authorization,
isolation, approval. - `docs/threat-model.md`: threats, mitigations,
residual risks. - `docs/api-reference.md`: REST API and error codes. -
`docs/mcp-client-configuration.md`: client setup examples. -
`docs/deployment.md`: Docker Compose deployment. -
`docs/air-gapped-installation.md`: offline bundle procedure. -
`docs/operations.md`: backups, restore, rotation, incident response. -
`SECURITY.md`: vulnerability reporting and security support policy. -
`CONTRIBUTING.md`: development and testing workflow.

------------------------------------------------------------------------

## 29. Product Success Metrics

Track operational and security outcomes: - Percentage of tool calls
routed through the gateway. - Percentage of tool calls with a recorded
policy decision. - Number of cross-tenant authorization test failures
(target: zero). - Number of unapproved sensitive actions executed
(target: zero). - Credential revocation propagation time. - Median and
p95 gateway overhead. - Upstream availability and invocation success
rate. - Approval turnaround time. - Number of enabled tools without
owner/risk classification (target: zero). - Audit completeness for
invocation lifecycle (target: 100%).

Do not optimize for raw tool-call volume at the expense of safety or
audit completeness.

------------------------------------------------------------------------

## 30. Final Architectural Recommendation

Build MCP-Gateway as a **security enforcement layer**, not simply an MCP
proxy with a registry UI.

The most important architectural boundary is the shared invocation
pipeline. Every tool call---whether initiated through MCP, an
administrative test endpoint, or an approval worker---must pass through
the same identity resolution, tenant isolation, policy evaluation,
validation, quota, approval, audit, and dispatch controls.

For the first release, focus on: 1. Registry and discovery. 2. Agent
identity and tenant isolation. 3. Default-deny per-tool authorization.
4. A single secure MCP invocation path. 5. Auditability. 6.
Approval-gated execution. 7. Docker-based offline deployment.

A smaller implementation that reliably enforces these boundaries is more
valuable than a broad feature set with bypasses or inconsistent policy
enforcement.
