# Deployment (Docker Compose)

Single-host deployment of five containers: `web-ui` (nginx), `gateway-api`, `worker`, `mongodb` and `redis`.
For an air-gapped site, build the bundle on a connected host first ([air-gapped-installation.md](air-gapped-installation.md)).

> Status: CI (`compose-smoke` job) builds the images and starts this Compose stack on every push with all
> container egress to public addresses blocked, then checks health, published ports, MongoDB
> authentication, sign-in, CSRF and security headers. Still run the verification checklist below on your
> first install: CI does not cover your TLS setup, firewall or upstream servers.

## Requirements

Docker Engine 24+ with Compose v2 · 2 vCPU / 4 GB RAM minimum · persistent disk for MongoDB and Redis
volumes · a TLS certificate (terminate TLS at your load balancer, or add it to the nginx config).

## Install

```bash
./deploy/scripts/generate-secrets.sh        # ./secrets/ (dir 0700, files 0644); never commit
cp .env.example .env                         # set PUBLIC_BASE_URL, allowlists, limits
docker compose up -d                         # air-gapped: add --no-build --pull never
docker compose ps                            # all services healthy
```

Sign in at `http://<host>:8088` (the default bind is `127.0.0.1:8088`; change `MGW_HTTP_BIND`/`MGW_HTTP_PORT`)
as `admin` with the password from `secrets/bootstrap_admin_password`. **Change it immediately** (Settings →
My account).

## What the Compose file enforces

| Control | Where |
|---|---|
| Only `web-ui` publishes a port, bound to localhost by default | `ports` |
| MongoDB and Redis are on an `internal: true` network with no host ports | `networks.backend` |
| Secrets are mounted as files (`/run/secrets/*`) and read through `*_FILE` variables. On the host they sit in a 0700 directory (files 0644, so the non-root container users can read them) | `secrets` |
| Read-only root filesystems, `tmpfs` for `/tmp` | `read_only`, `tmpfs` |
| `cap_drop: [ALL]`, `no-new-privileges` | all services |
| Non-root processes (backend uid 10001, nginx-unprivileged uid 101, Redis uid 999; MongoDB drops to uid 999 after start-up) | Dockerfiles, `user` |
| MongoDB `--auth`, Redis `requirepass`, AOF persistence | service commands |
| Health checks (API `/health/live`, worker heartbeat, DB pings) and `depends_on: service_healthy` | `healthcheck` |
| Pinned image tags (pin digests in your registry) | `image` |
| Log rotation | `logging` |

## Configuration reference

All settings are in [`.env.example`](../.env.example) with comments. Ones you'll usually set:

| Variable | Purpose |
|---|---|
| `PUBLIC_BASE_URL` | external URL. Used to show the MCP endpoint to administrators. |
| `UPSTREAM_HOST_ALLOWLIST` | comma-separated hosts or `*.domain` that upstream servers may use |
| `ALLOW_PRIVATE_UPSTREAM_NETWORKS` | must be `true` (plus the per-server flag) for internal upstreams |
| `STDIO_EXECUTABLE_ALLOWLIST` | absolute paths of permitted stdio server binaries. Empty disables stdio. |
| `COOKIE_SECURE` | keep `true` behind HTTPS |
| `MAX_*`, `DEFAULT_TOOL_TIMEOUT_SECONDS` | payload and execution limits |
| `AUDIT_RETENTION_DAYS`, `AUDIT_EXPORT_MAX_ROWS` | audit policy |

Startup fails fast in production on missing, short or placeholder secrets, a malformed encryption key, or
wildcard CORS.

## Network egress

`gateway-api` and `worker` need outbound access to your upstream MCP servers (they join the `frontend`
network for that). Restrict egress with host firewall rules or an egress proxy to the upstream subnets. Use
the application allowlist as a second layer.

## TLS

Either terminate TLS at a load balancer in front of `web-ui` and forward to it over a trusted network, or
mount a certificate into `web-ui` and add a `listen 8443 ssl` server block. Keep `COOKIE_SECURE=true`. With
plain HTTP, browsers drop the `__Host-` session cookie.

## Updating

```bash
docker compose pull            # or docker load a new offline bundle
docker compose up -d           # API and worker restart; indexes are created idempotently at startup
```

The API and worker are stateless. Approvals in flight survive restarts: jobs stay in the Redis stream and
unacknowledged jobs are reclaimed. See [operations.md](operations.md#gateway-restart-and-rolling-update).

## First-install verification checklist

- [ ] `docker compose ps` shows every service `healthy`. `curl http://127.0.0.1:8088/health/ready` returns `ready`.
- [ ] `docker compose exec mongodb mongosh --quiet --eval 'db.adminCommand({listDatabases:1})'` without credentials fails with *requires authentication*.
- [ ] No ports other than the web-ui port are listening on the host (`ss -lntp`).
- [ ] Sign in, change the admin password, register a test upstream, discover tools.
- [ ] Run `deploy/examples/demo_agent.py` with a new agent key: allowed call works, denied call is denied.
- [ ] Audit Logs show the session's events.
