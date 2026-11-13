# Operations & Runbooks

Every emergency action below is available to authorized administrators in the console and through the API,
and writes a high-severity audit event. Commands assume the Compose deployment (`docker compose …` run in
the install directory).

- [Initial installation and bootstrap administrator](#initial-installation-and-bootstrap-administrator)
- [Air-gapped image and dependency transfer](#air-gapped-image-and-dependency-transfer)
- [Backup and restore (MongoDB and keys)](#backup-and-restore)
- [Redis recovery and quota behaviour](#redis-recovery-and-quota-behaviour)
- [Gateway restart and rolling update](#gateway-restart-and-rolling-update)
- [MCP server outage](#mcp-server-outage)
- [Compromised agent credential](#compromised-agent-credential)
- [Tenant suspension](#tenant-suspension)
- [Emergency server or tool disablement](#emergency-server-or-tool-disablement)
- [Policy rollback](#policy-rollback)
- [Approval queue stuck or worker failure](#approval-queue-stuck-or-worker-failure)
- [Audit export and retention](#audit-export-and-retention)
- [Encryption key rotation](#encryption-key-rotation)
- [Monitoring](#monitoring)

---

## Initial installation and bootstrap administrator

1. Follow [deployment.md](deployment.md). `generate-secrets.sh` writes `secrets/bootstrap_admin_password`.
2. On first start the API creates the platform admin `BOOTSTRAP_ADMIN_USERNAME` and the tenant
   `BOOTSTRAP_TENANT_SLUG` (with a default-deny policy). Once any platform admin exists, bootstrap does nothing.
3. Sign in and change the password (Settings → My account). Then delete `secrets/bootstrap_admin_password`
   from the host, or replace its content.
4. Create named administrator accounts (Users & Tenants) and stop using the bootstrap account day to day.

**Lost all admin access:** bootstrap runs only when *no* platform admin exists, so it can't be used to
recover. Instead, generate an Argon2id hash inside the backend container
(`docker compose run --rm gateway-api python -c "from app.core.crypto import hash_password; print(hash_password(input()))"`),
then use `mongosh` to set that hash as `password_hash` on an existing platform-admin user, with
`must_change_password: true`. Record the action in your change log. It isn't audited by the application.

## Air-gapped image and dependency transfer

See [air-gapped-installation.md](air-gapped-installation.md). Always verify `SHA256SUMS` and the image IDs
(`load-images.sh` does both) before deploying.

## Backup and restore

What to back up:

| Item | How | Notes |
|---|---|---|
| MongoDB (all state and audit) | `mongodump` (below) | daily, plus before every upgrade |
| `secrets/data_encryption_key` | offline secure storage (separate from DB backups) | without it, upstream secrets and pending approvals are unreadable |
| `secrets/api_key_hash_pepper` | same | without it, every agent key is invalid |
| `secrets/session_secret`, `.env`, `docker-compose.yml` | config backup | |
| Redis | not required | holds sessions, quota windows and the job queue. See Redis recovery. |

```bash
# backup
docker compose exec -T mongodb sh -c \
  'mongodump --quiet --archive --gzip -u mgw_root -p "$(cat /run/secrets/mongo_root_password)" --authenticationDatabase admin --db mcp_gateway' \
  > backup-$(date +%F).archive.gz

# restore (services that write must be stopped)
docker compose stop gateway-api worker
docker compose exec -T mongodb sh -c \
  'mongorestore --quiet --archive --gzip --drop -u mgw_root -p "$(cat /run/secrets/mongo_root_password)" --authenticationDatabase admin' \
  < backup-YYYY-MM-DD.archive.gz
docker compose start gateway-api worker
```

Restore with the **same** encryption key and pepper that were active when the backup was taken. Test a
restore into a staging environment at least quarterly. That drill has not been done for this release.

## Redis recovery and quota behaviour

- While Redis is down: console logins fail (sessions live in Redis), calls with hard quotas fail closed with
  `DEPENDENCY_UNAVAILABLE`, and approved jobs aren't picked up. `/health/ready` returns 503 with `redis: unavailable`.
- Recovery: restart Redis (`docker compose restart redis`). AOF persistence restores quota windows and the job
  stream. If the data is lost, users sign in again, quota windows restart empty (a brief allowance above the
  limit is possible), and **approved-but-unexecuted jobs are re-queued** automatically by the worker's
  maintenance loop from MongoDB state.
- Never set `REDIS_FAIL_OPEN_DEV` outside development (production ignores it).

## Gateway restart and rolling update

- `gateway-api` and `worker` are stateless. `docker compose up -d` recreates them, and indexes are ensured at startup.
- In-flight MCP calls on a restarting API instance fail and the agent sees an error. Schedule updates in a
  quiet window. Approved executions are safe: the claim (`APPROVED → REVALIDATING`) is atomic, unacknowledged
  stream entries are reclaimed after 60 s, and execution happens at most once.
- Rollback: redeploy the previous image tag. Data migrations are additive within 0.1.x.

## MCP server outage

Symptoms: server health shows *unhealthy* on the Overview and MCP Servers pages. Calls fail with
`UPSTREAM_UNAVAILABLE` / `UPSTREAM_TIMEOUT`.

1. **MCP Servers → server → Health** shows the latest error and latency history. **Test connection** re-checks.
2. If the server is misbehaving (errors, slow, suspicious output), **Disable** it. Its tools disappear from
   discovery and calls are refused immediately.
3. After recovery: Enable, then **Refresh tools**. Review any `schema_changed` tools before acknowledging them.

## Compromised agent credential

1. **Agents & Credentials → agent → Revoke** on the key (or **Revoke agent** for all of its keys). Effect is
   immediate. Pending approvals requested with that key abort at execution (`CREDENTIAL_REVOKED`).
2. If you can't tell which key leaked: **Emergency revoke** (Agents page, typed confirmation) revokes *every*
   agent key in the tenant. API: `POST /api/v1/emergency/revoke-all-credentials`.
3. Investigate: **Audit Logs**, filter by principal or `credential_id`. Check `last_used_source` on the key.
4. Issue a new key, deploy it to the legitimate agent, and review the agent's policies (least privilege).
5. If you suspect the **pepper** is compromised: rotating `API_KEY_HASH_PEPPER` invalidates every agent key in
   every tenant. Re-issue all keys afterwards.

## Tenant suspension

Users & Tenants → Tenants → Edit → Status **suspended** (platform admin). Every agent key and invocation of
the tenant is refused (`TENANT_SUSPENDED`) at once. Data is kept. Setting it back to **active** restores
access. Audit events record both changes.

## Emergency server or tool disablement

- Tool: **Tool Catalog → tool → toggle off** (`PATCH /api/v1/tools/{id} {"enabled": false, "version": n}`).
- Server: **MCP Servers → server → Disable** (`POST /api/v1/servers/{id}/disable`).
- Both take effect on the next call: discovery is filtered and calls are refused, including calls from
  agents that cached the tool list. Approved jobs for affected tools abort during revalidation.

## Policy rollback

1. **Policies → history icon** shows every change with the full snapshot and the fields changed.
2. To roll back, either **disable** the bad policy (fastest, takes effect immediately) or open **Edit → JSON**
   and paste the snapshot from the history view, keeping the current `version`.
3. Use the **Simulator** to confirm the effective decision for the affected agent and tool before re-enabling.

## Approval queue stuck or worker failure

Symptoms: approvals stay *Approved* and don't complete. Overview → Platform health shows **Worker unhealthy**
or a growing queue depth. The `mgw_approval_oldest_age_seconds` metric rises.

1. `docker compose ps worker` and `docker compose logs --tail=200 worker`.
2. `docker compose restart worker`. On startup it re-creates the consumer group if needed. The maintenance
   loop re-queues approvals stuck in `APPROVED` and reclaims unacknowledged jobs.
3. If the jobs abort, look at the approval's *Execution* entry. Typical codes: `CREDENTIAL_REVOKED`,
   `TOOL_DISABLED`, `ACCESS_DENIED` (policy changed), `APPROVAL_INVALIDATED` (argument integrity),
   `QUOTA_EXCEEDED`. These are deliberate safety outcomes, not worker failures.
4. Expired approvals can't be revived. The agent has to submit a new request.

## Audit export and retention

- **Export:** Audit Logs → set filters → *Export CSV/JSON* (`POST /api/v1/audit/export`). The row cap is
  `AUDIT_EXPORT_MAX_ROWS`. CSV cells are protected against formula injection. Each export is itself audited.
- **Retention:** the worker deletes events older than the tenant's `audit_retention_days` (Users & Tenants →
  Edit tenant, default `AUDIT_RETENTION_DAYS`, minimum 30) once at startup and every 6 hours after that. Each
  purge writes an `audit.retention.purged` event (high severity) with the number deleted. It is the only path
  that ever deletes audit events.
- For legal hold or long-term retention, export regularly to WORM storage before the window expires, or raise
  the tenant's retention.

## Encryption key rotation

`DATA_ENCRYPTION_KEY` (AES-256-GCM) protects upstream credentials, approval arguments and approved results.

```bash
docker compose stop gateway-api worker                     # no writers during rotation
# 1. back up MongoDB (see above) and keep the old key
head -c 32 /dev/urandom | base64 | tr '+/' '-_' > secrets/data_encryption_key.new
# 2. re-encrypt: dry run, then for real
docker compose run --rm -v "$PWD/secrets:/keys:ro" gateway-api \
  python -m app.tools.rotate_encryption_key --old-key-file /keys/data_encryption_key --new-key-file /keys/data_encryption_key.new --dry-run
docker compose run --rm -v "$PWD/secrets:/keys:ro" gateway-api \
  python -m app.tools.rotate_encryption_key --old-key-file /keys/data_encryption_key --new-key-file /keys/data_encryption_key.new
# 3. switch keys and start
mv secrets/data_encryption_key secrets/data_encryption_key.old && mv secrets/data_encryption_key.new secrets/data_encryption_key
docker compose up -d gateway-api worker
```

The tool is idempotent (values already on the new key are skipped), uses compare-and-set updates, never
prints keys or plaintext, and exits non-zero if any value could not be rotated. Destroy the old key only after
verifying that servers still connect (Test connection) and pending approvals still show *integrity verified*.

**Other secrets:**
- `SESSION_SECRET`: replace the file and restart. Users sign in again.
- `API_KEY_HASH_PEPPER`: replacing it invalidates all agent keys. Plan a key re-issue.
- MongoDB and Redis passwords: change them in the datastore, update `secrets/mongo_root_password` /
  `redis_password` and the URI files, then restart.

## Monitoring

- Liveness `/health/live` and readiness `/health/ready` (checks MongoDB and Redis).
- Prometheus: `GET /api/v1/metrics` (session- or token-authenticated admin or auditor, tenant-scoped):
  invocations by status and decision, average duration, approval queue depth and oldest age, component up/down,
  in-flight calls, upstream health.
- Logs: JSON on stdout. Secrets and keys are scrubbed. Every line carries `request_id`.
- Suggested alerts: worker unhealthy > 2 min · approval oldest age > TTL/2 · `DEPENDENCY_UNAVAILABLE` or
  `AUDIT_UNAVAILABLE` errors · upstream unhealthy > 5 min · spikes in `ACCESS_DENIED` for one agent (possible
  compromise or prompt injection).
