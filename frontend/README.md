# MCP-Gateway Admin Console

React 19 + TypeScript 7 + Vite 8 admin console for MCP-Gateway. It talks to the FastAPI backend through
`/api/v1` using the session cookie plus a CSRF header. Every authorization, validation, quota, approval and
audit rule is enforced **server-side**. The UI hides actions a role can't perform as a convenience only.

## Structure

```
src/
  main.tsx              providers: React Query, router, toasts, auth
  app/                  AppShell (sidebar, tenant selector, health), routes, auth context
  components/ui.tsx     shared UI: panels, badges, modals, drawers, typed confirmations, query states
  services/             api.ts (fetch client, CSRF, error envelope), types, formatting, role groups
  features/             one folder per page: overview, servers, tools, policies, agents,
                        approvals, audit, usage, users, settings, auth
```

## Development

Requirements: Node.js 20+ and a running backend (see `../backend`, or the no-Docker dev stack
`uv run python -m devtools.dev_stack` in `backend/`).

```bash
npm ci
npm run dev          # http://localhost:5173; proxies /api, /mcp, /health to GATEWAY_URL (default http://127.0.0.1:8080)
npm run typecheck
npm run build        # output in dist/
```

## Docker

The `Dockerfile` builds the bundle and serves it with `nginx-unprivileged` on port 8080. `nginx.conf`
proxies `/api/`, `/mcp` and `/health/` to `gateway-api:8080` and applies the strict security headers in
`nginx-security-headers.conf` (CSP without external origins). It's normally run through the root
`docker-compose.yml`.

## Air-gapped

The bundle has no CDN fonts, remote scripts, analytics or external calls. Dependencies are pinned
exactly in `package.json` and `package-lock.json`. Build on a connected host and ship the image (see
`../docs/air-gapped-installation.md`).
