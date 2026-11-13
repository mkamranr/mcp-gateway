# API Reference

Base path `/api/v1`. JSON in and out. Interactive OpenAPI docs are served at `/api/docs`
(`/api/openapi.json`) when `APP_ENV` is `development` or `test`, and are disabled in production.

**Authentication**
- Console users: `POST /auth/login` sets the session cookie and returns `csrf_token`. Every non-GET request
  must send `X-CSRF-Token: <token>`.
- Agents: `Authorization: Bearer mgw_live_…`. Agents may call only `/gateway/*`, `/approvals*` (own requests,
  needs the `approvals:read` scope) and `/mcp`.

**Conventions**
- Lists return `{"items": [...], "next_cursor": "…" | null, "total": n}`. Use `?limit=` (≤200) and `?cursor=`.
- Mutable registry and policy documents carry `version`. PATCH bodies must include it. A stale version → `409 VERSION_CONFLICT`.
- Every response has an `X-Request-ID` header. Errors use one envelope:

```json
{"error": {"code": "TOOL_ARGUMENT_VALIDATION_FAILED", "message": "…", "request_id": "req_…",
           "details": [{"field": "employee_id", "code": "type", "message": "…"}]}}
```

## Endpoints

Roles: P = platform_admin, T = tenant_admin, S = security_admin, A = approver, U = auditor, D = developer,
`any` = any signed-in user.

### Auth & credentials
| Method | Path | Who | Notes |
|---|---|---|---|
| POST | `/auth/login` | public | `{username, password}`. Throttled. Returns the principal and `csrf_token`. |
| POST | `/auth/logout` | user | invalidates the session |
| GET | `/auth/me` | user/agent | current principal and tenants |
| POST | `/auth/switch-tenant` | user | `{tenant_id}` (must be a member) |
| POST | `/auth/change-password` | user | `{current_password, new_password}` (≥12 chars) |
| POST | `/auth/agent-keys` | P T S | `{agent_id, name, scopes[], expires_at?}` → includes `secret` **once** |
| GET | `/auth/agent-keys?agent_id=` | any | never includes secrets or hashes |
| POST | `/auth/agent-keys/{id}/rotate` | P T S | new key (secret once). The old key is revoked. |
| POST | `/auth/agent-keys/{id}/revoke` | P T S | `{reason}` |
| POST | `/emergency/revoke-all-credentials` | P T S | `{reason}` → `{revoked: n}`. High-severity audit event. |

### Tenants, users, agents
| Method | Path | Who |
|---|---|---|
| GET/POST | `/tenants` | any (own) / P |
| GET/PATCH | `/tenants/{id}` | member / P T (`status: suspended` blocks all agents) |
| GET/POST | `/tenants/{id}/users` | P T S U / P T |
| PATCH | `/tenants/{id}/users/{user_id}` | P T (`roles`, `status`) |
| GET/POST | `/tenants/{id}/agents` | any / P T S D |
| GET/PATCH | `/agents/{id}` | any (includes credentials, permitted tools, policies, recent calls) / P T S |
| POST | `/agents/{id}/revoke` | P T S |

### Registry
| Method | Path | Who | Notes |
|---|---|---|---|
| GET/POST | `/servers` | any / P T D | `transport: streamable_http \| stdio`. `secret` is write-only. |
| GET/PATCH/DELETE | `/servers/{id}` | any / P T D / P T | DELETE archives the server |
| POST | `/servers/{id}/enable` \| `/disable` | P T S | |
| POST | `/servers/{id}/test` | P T D S | `{healthy, status, latency_ms, error, tool_count}` |
| POST | `/servers/{id}/refresh-tools` | P T D | `{new[], changed[], unchanged, rejected[], removed[]}` |
| GET | `/servers/{id}/tools`, `/servers/{id}/history` | any | |
| GET | `/tools?server_id&risk&enabled&review_status&approval_required&environment&search` | any | includes `calls_7d` |
| GET/PATCH | `/tools/{id}` | any / P T S | PATCH: `risk_level`, `enabled`, `approval`, `limits`, `timeout_seconds`, `max_*_bytes`, `output`, `tags`, `acknowledge_schema_change` |
| GET | `/tools/{id}/versions` | any | schema history |

### Policies
| Method | Path | Who | Notes |
|---|---|---|---|
| GET/POST | `/policies` | any / P T S | POST with wildcards or all principals needs `confirm_broad_grant: true` |
| GET/PATCH/DELETE | `/policies/{id}` | any / P T S | system and global policies are protected |
| POST | `/policies/{id}/enable` \| `/disable` \| `/clone` | P T S | |
| GET | `/policies/{id}/history` | any | snapshots from audit |
| POST | `/policies/simulate` | P T S D U | `{principal_type, principal_id, tool_id \| gateway_name, action, arguments?, source_ip?}`. **Never dispatches.** |

Policy document:
```json
{"name": "HR agent reads attendance", "effect": "allow", "priority": 100, "enabled": true,
 "principals": {"types": ["agent"], "ids": ["agt_…"], "roles": []},
 "resources": {"servers": ["hr"], "tools": ["get_attendance_summary"], "risk_levels": []},
 "actions": ["discover", "invoke"],
 "constraints": {"environments": [], "max_calls_per_minute": null, "max_calls_per_hour": null,
                 "max_calls_per_day": null, "require_approval": false, "required_approvals": null,
                 "time_windows": [{"days": [0,1,2,3,4], "start": "08:00", "end": "18:00"}], "source_cidrs": []}}
```

### Approvals
| Method | Path | Who | Notes |
|---|---|---|---|
| GET | `/approvals?status=pending\|approved\|rejected\|expired\|cancelled&risk&tool&requester` | users; agents (own) | includes `counts` |
| GET | `/approvals/{id}` | users; agents (own) | users get masked `arguments`, `integrity`, `changes_since_request`, `separation_of_duties_warning`, `can_decide` |
| GET | `/approvals/{id}/status` | users; agents (own) | agent polling. Includes `result` once COMPLETED (24 h). |
| POST | `/approvals/{id}/approve` | P T S A | `{comment, confirm_critical}` |
| POST | `/approvals/{id}/reject` | P T S A | `{comment}` (required by default) |
| POST | `/approvals/{id}/cancel` | requester or admin | `{reason}` |

### Observability & settings
| Method | Path | Who |
|---|---|---|
| GET | `/audit/events?start&end&event_type(prefix*)&decision&status&principal&tool&severity&request_id&invocation_id&approval_id&server_id&tool_id&tenant` | P T S U (`tenant` is for P only, `*` = all) |
| GET | `/audit/events/{id}` | P T S U (includes correlated events) |
| POST | `/audit/export` | P T S U (`{format: csv\|json, filters, max_rows}`, audited) |
| GET | `/invocations` | P T S U |
| GET | `/usage/summary?days=`, `/usage/by-tool`, `/usage/by-agent` | any |
| GET | `/overview` | any |
| GET | `/metrics` | P T S U (Prometheus text, tenant-scoped) |
| GET/PATCH | `/settings` | any / P |
| GET | `/health/live`, `/health/ready` | public (no `/api/v1` prefix) |

### Agent REST API (same pipeline as MCP)
| Method | Path | Scope |
|---|---|---|
| GET | `/gateway/tools` | `tools:list` |
| POST | `/gateway/tools/{gateway_name}/invoke` | `tools:invoke`. Body `{arguments, purpose?}`. Returns `202` + `APPROVAL_PENDING` when approval is needed. |

## Error codes

| Code | HTTP | Meaning |
|---|---|---|
| AUTHENTICATION_REQUIRED | 401 | no or invalid session |
| INVALID_CREDENTIAL / CREDENTIAL_REVOKED / CREDENTIAL_EXPIRED | 401 | agent key problems |
| TENANT_SUSPENDED | 403 | tenant not active |
| ACCESS_DENIED | 403 | role or policy denies (default deny) |
| CSRF_FAILED | 403 | missing or mismatched CSRF token |
| SEPARATION_OF_DUTIES | 403 | requester or agent owner tried to approve |
| NOT_FOUND / TOOL_NOT_FOUND | 404 | unknown, or in another tenant |
| CONFLICT / VERSION_CONFLICT | 409 | state conflict / stale `version` |
| SERVER_DISABLED / TOOL_DISABLED / TOOL_SCHEMA_CHANGED | 409 | tool state blocks a call (reported only to callers with a grant) |
| APPROVAL_EXPIRED / APPROVAL_INVALIDATED / APPROVAL_STATE_CONFLICT | 409 | approval cannot proceed |
| VALIDATION_FAILED | 422 | request body invalid |
| BROAD_GRANT_CONFIRMATION_REQUIRED | 422 | wildcard allow without confirmation |
| TOOL_ARGUMENT_VALIDATION_FAILED | 422 | arguments don't match the schema or limits (never dispatched) |
| UPSTREAM_BLOCKED | 422 | SSRF / allowlist rejection |
| PAYLOAD_TOO_LARGE | 413 | body or argument size limit |
| RATE_LIMIT_EXCEEDED / QUOTA_EXCEEDED / CONCURRENCY_LIMIT_EXCEEDED | 429 | with `Retry-After` |
| APPROVAL_REQUIRED / APPROVAL_PENDING | 202 | call queued for human approval |
| TOOL_OUTPUT_VALIDATION_FAILED / UPSTREAM_UNAVAILABLE / UPSTREAM_EXECUTION_FAILED | 502 | upstream problems (sanitized) |
| UPSTREAM_TIMEOUT | 504 | tool timeout |
| AUDIT_UNAVAILABLE / DEPENDENCY_UNAVAILABLE | 503 | fail-closed dependency outage |
| GATEWAY_INTERNAL_ERROR | 500 | unexpected error (no details exposed) |

Over MCP, errors come back as a tool result with `isError: true` and
`structuredContent: {"error": {"code", "message", "request_id"}}`. A pending approval returns
`{"status": "pending_approval", "code": "APPROVAL_PENDING", "approval_id", "expires_at"}`.
