# Contributing

## Setup

```bash
make install        # backend: uv sync (Python 3.12, locked) · frontend: npm ci (locked)
make dev            # API + worker + mock upstream without Docker
make dev-ui         # console on http://localhost:5173
```

The test suite needs no external services. It starts a real `mongod` through `pymongo-inmemory` (downloaded
once into the virtualenv cache) and uses `fakeredis` with Lua. To test against real services, set
`TEST_MONGODB_URI` / `TEST_REDIS_URL`.

## Workflow

1. Branch from `main`. Keep changes focused.
2. Write or update tests **with** the change. A feature isn't done while its tests fail.
3. Run `make check` (ruff, mypy, tsc, all pytest suites, production build) before opening a PR.
4. Describe the security impact in the PR, even when it is "none".

## Engineering rules (spec §26.1)

- **Thin routes, logic in services, Mongo access only in repositories.** `TenantScopedRepository` requires
  `tenant_id` on every call. Never read the tenant from a request body.
- **One invocation pipeline.** MCP, REST and the approval worker must all call `InvocationService`. Never add a
  second path to an upstream.
- **Default deny and fail closed.** New checks raise `GatewayError` with a stable `ErrorCode`. Unknown means deny.
- **Never return or log secrets.** Add sensitive keys to the log scrubber if you introduce new ones. API
  serializers (`*_to_api`) must whitelist fields.
- **Strict input models.** Pydantic models extend `Strict` (`extra="forbid"`).
- **Optimistic concurrency.** Mutable registry and policy documents carry `version`. PATCH requires it.
- **Audit** every security-relevant state change through `AuditService.record`.
- **Dependencies** are pinned (`uv.lock`, `package-lock.json`). No runtime CDN or network fetches in the UI.

## Test layout

| Suite | Purpose |
|---|---|
| `tests/unit` | policy engine, crypto/key primitives, config parsing |
| `tests/integration` | registry, invocation pipeline, approvals, key rotation (real mongod + fakeredis + mock MCP server) |
| `tests/contract` | a real MCP SDK client against `/mcp` |
| `tests/security` | tenant isolation, authentication, CSRF, secret non-disclosure |

The mock upstream (`backend/devtools/mock_mcp_server.py`) counts calls per tool. Tests assert that denied or
invalid calls **never** reach it.

## Frontend

`frontend/src/features/<page>` holds one folder per console page. Data access goes through
`services/api.ts` (cookie session plus `X-CSRF-Token`) and TanStack Query. Role checks in the UI only hide
controls (`services/roles.ts` mirrors the backend groups). The API is the authority. Run `npm run typecheck`
and `npm run build`.

## Commit messages

Imperative mood, with a short summary line and details in the body. Reference the spec section when you
implement or change a requirement.
