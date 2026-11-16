# MCP-Gateway

A self-hosted, multi-tenant security gateway between AI agents and the MCP (Model Context Protocol)
servers that expose your tools. Agents connect to **one** MCP endpoint. The gateway decides what each
agent can see and call, validates every argument, enforces quotas, asks humans to approve sensitive
actions, and records an append-only audit trail. Built for on-premises and air-gapped environments.

```
 AI agent ──MCP (Bearer agent key)──►  MCP-Gateway  ──►  upstream MCP servers (HTTP / stdio)
                                         │  identity · default-deny policy · schema validation
 Admin console (React) ──REST/cookie──►  │  quotas · human approval · output controls · audit
                                         └─ MongoDB (state, audit) · Redis (sessions, quotas, jobs)
```

## Features (MVP)

- **Registry.** Register upstream MCP servers over streamable HTTP or allowlisted stdio, test connections and
  discover tools. Schemas are fingerprinted and versioned. **New tools are disabled until reviewed.** A schema
  change blocks calls until an administrator acknowledges it.
- **Identity and tenancy.** Tenants, users (Argon2id, server-side sessions, CSRF), six roles, and agents with
  hashed API keys (`mgw_live_…`). A key is shown once and can be rotated, revoked or emergency-revoked.
  Tenant isolation is enforced in every repository.
- **Single sign-on (OIDC).** One platform-wide IdP (Keycloak, Entra ID, AD FS and others). Authorization code
  flow with PKCE. Accounts are created just-in-time. IdP groups map to tenant roles and are re-synced at every
  sign-in. Local password sign-in can be limited to break-glass administrators. See [docs/sso.md](docs/sso.md).
- **Default-deny policy engine.** Allow/deny policies over principals, servers, tools, risk levels and actions.
  Conditions cover environment, time window, source CIDR and rate. Deny overrides allow. Wildcard grants need
  explicit confirmation. Includes a simulator and version history.
- **One enforcement pipeline.** The MCP endpoint, the REST invoke API and the approval worker all go through
  the same steps: authenticate → tool state → policy → JSON-Schema validation → approval → quotas → dispatch →
  output controls → audit.
- **Human approval.** Arguments are bound to the request by SHA-256 hash and AES-GCM encryption. Requires 1 or
  2 approvers with separation of duties, and typed confirmation for critical tools. Requests expire. Before
  executing, the worker revalidates the credential, tenant, server, tool, policy and argument hash, then runs
  the call exactly once.
- **Quotas.** Atomic Redis sliding windows and daily/monthly counters at global, tenant, tool and policy scope,
  plus per-agent concurrency. Hard limits fail closed if Redis is down.
- **Output controls.** Size caps, optional output-schema validation, field redaction. Tool output is marked as
  untrusted.
- **Audit and observability.** Append-only, correlated events (request, invocation and approval IDs). Search,
  CSV/JSON export (the export is itself audited), usage dashboards, Prometheus `/api/v1/metrics`.
- **Admin console.** React 18 + Vite, styled after the mockup. Every asset is bundled, with no CDN.

## Quick start (local development, no Docker)

Requirements: [uv](https://docs.astral.sh/uv/) (Python 3.12) and Node.js 20+.

```bash
make install            # uv sync + npm ci
make dev                # mongod (pymongo-inmemory) + fakeredis + mock MCP server + API :8080 + worker
make dev-ui             # in another terminal: http://localhost:5173
```

`make dev` prints a generated admin password and the mock upstream URL. Then:

1. Sign in, open **MCP Servers → Add server**, enter the printed mock URL and enable *Allow private network*.
2. **Refresh tools**. Open a tool, assign a risk level and enable it.
3. **Agents & Credentials**: register an agent and create a key (shown once).
4. **Policies**: allow that agent to use the tool. Add a policy with *Require approval* for a sensitive tool.
5. Run the demo agent:
   ```bash
   MGW_URL=http://127.0.0.1:8080/mcp MGW_AGENT_KEY=mgw_live_... \
     uv run --project backend python deploy/examples/demo_agent.py
   ```

To try single sign-on, start the stack with the mock IdP instead:
`cd backend && uv run python -m devtools.dev_stack --with-oidc` (then `make dev-ui`). The login page shows
**Sign in with Mock IdP**, with demo users `alice`, `bob`, `carol` and `root`.
6. Approve the pending request as a *different* user with the Approver role, then watch it complete in
   **Audit Logs**.

## Production deployment

Docker Compose, single host, air-gap ready. See [docs/deployment.md](docs/deployment.md) and
[docs/air-gapped-installation.md](docs/air-gapped-installation.md).

```bash
./deploy/scripts/generate-secrets.sh && cp .env.example .env && docker compose up -d
```

## Repository layout

| Path | Contents |
|---|---|
| `backend/app` | FastAPI app: `api/v1` (thin routes), `services` (business logic), `repositories` (tenant-scoped Mongo access), `mcp` (gateway endpoint, adapters, SSRF guard), `workers`, `tools` |
| `backend/tests` | unit, integration, contract (real MCP SDK client) and security suites |
| `backend/devtools` | mock MCP server, no-Docker dev stack |
| `frontend/src` | `app` (shell, auth, routes), `features/*` (one folder per page), `components`, `services` (typed API client) |
| `deploy` | secret generation, offline bundle scripts, SBOM script, demo agent |
| `docs` | architecture, security and threat model, API, client configuration, deployment, operations |

## Quality gates

```bash
make check     # ruff + mypy + tsc + pytest (unit, integration, contract, security) + production build
```

GitHub Actions (`.github/workflows/ci.yml`) runs on every push and pull request to `main`:

| Job | What it checks |
|---|---|
| Backend | ruff, mypy, full pytest suite against real MongoDB 7 and Redis 7 service containers |
| Frontend | typecheck, production build, and `check:offline`, which fails if the bundle references any external origin |
| Dependency scan | `pip-audit` on the locked production dependencies, `npm audit --omit=dev` (high and above) |
| Compose smoke test | builds the images, **blocks all container egress to public addresses**, starts the full stack with `--pull never`, then checks health, published ports, MongoDB auth, sign-in, CSRF, logout and security headers through the web-ui proxy. Then a **backup and restore drill**: seed data, back up with `backup.sh`, wipe every volume, restore with `restore.sh`, and verify data, keys and secrets. It also checks that a damaged archive and a wrong encryption key are refused. |

`release-bundle.yml` (run manually) builds the air-gap bundle, deletes every image, then verifies,
loads and starts the bundle with egress blocked, as an air-gapped host would. Dependabot proposes
weekly updates for uv, npm, Actions and base images.

## Documentation

[Architecture](docs/architecture.md) · [Security model](docs/security-model.md) ·
[Threat model](docs/threat-model.md) · [API reference](docs/api-reference.md) ·
[MCP client configuration](docs/mcp-client-configuration.md) · [Deployment](docs/deployment.md) ·
[Air-gapped installation](docs/air-gapped-installation.md) · [Single sign-on](docs/sso.md) · [Operations & runbooks](docs/operations.md) ·
[Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)
