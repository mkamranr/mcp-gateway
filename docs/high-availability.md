# High availability and scaling out

The gateway API and the worker are stateless processes: every piece of shared state lives in MongoDB or Redis.
You can run as many replicas of each as you like, on one host or on several, and any API replica can serve any
request. This page explains what that covers, how to run it, and what you still need for a deployment that
survives the loss of a whole host.

## What is safe with several replicas

| Concern | How it works with N replicas |
|---|---|
| Console sessions, CSRF, login throttling | Redis. A session started on one replica works on all others. |
| MCP endpoint (`/mcp`) | Stateless streamable HTTP (no `Mcp-Session-Id`), authenticated on every request. No sticky sessions needed. |
| SSO sign-in state (PKCE, nonce) | Redis, single use. The callback can land on any replica. |
| Quotas and per-agent / per-tool concurrency | Atomic Redis scripts. |
| Per-server concurrency cap (`max_concurrent_calls`) | A Redis lease semaphore shared by every API replica and worker. A replica that dies mid-call can't hold its slot longer than the call could have lasted (timeout + 30 s). |
| Policies, tools, servers, settings | Read from MongoDB on every request. A change applies on all replicas at once. |
| Approved executions | Redis Streams consumer group; each approval is claimed by an atomic state transition, so it runs exactly once even if two workers receive it. A job whose worker died is re-delivered after 60 s. |
| Approval expiry, re-queueing | Atomic state transitions; run on every worker harmlessly. |
| SIEM forwarding | One worker holds a lease (60 s, renewed before every batch) and forwards. A worker that loses the lease stops before moving the cursor. On a clean stop the lease is released, so another worker takes over at once. |
| Upstream health checks | One worker per round (lease), so upstreams are probed once per interval, not once per worker. |
| Audit retention | At most one run per 6 hours across all workers. |
| First boot | A Redis lease serialises creation of the bootstrap administrator; the other replicas wait, then find it there. |
| Worker health | Each worker beats under its own host name: a hung worker fails its own container healthcheck even while others are fine. The console and `mgw_workers_alive` show how many are alive. |

Caches that are per process: OIDC discovery documents and JWKS (1 hour; an unknown signing key triggers an
immediate refetch, so IdP key rotation works). Nothing else is cached in process.

Quota windows use each replica's clock. Keep hosts synchronised with NTP, as you would for TLS and audit
timestamps anyway.

## Several replicas on one host (Compose)

```sh
docker compose -f docker-compose.yml -f docker-compose.ha.yml up -d --wait
docker compose -f docker-compose.yml -f docker-compose.ha.yml up -d --scale gateway-api=4 --no-recreate   # resize
```

[`docker-compose.ha.yml`](../docker-compose.ha.yml) runs 2 API replicas and 2 workers. Set
`COMPOSE_FILE=docker-compose.yml:docker-compose.ha.yml` in your shell (or `.env`) so every `docker compose`
command, including the backup and restore scripts, uses both files.

`web-ui` (nginx) spreads requests over all API replicas. It re-resolves the `gateway-api` name every 10 seconds,
so added, restarted or replaced replicas take traffic without reloading nginx. A replica that refuses connections
or times out is skipped for 10 seconds, and the request goes to another one. nginx never re-sends a POST (such as
a tool invocation) once a replica received it, so a call can't run twice.

**Rolling restarts and upgrades.** Restart or replace one replica at a time:
`docker compose up -d --no-deps --wait gateway-api` recreates the API replicas; requests in flight get 30 seconds
to finish (`stop_grace_period`). Workers get 60 seconds to finish the approved call they are running; a call still
running after that is picked up again by another worker.

This is what CI verifies on every push (job *Multi-replica Compose*):

1. Two API replicas boot together on empty volumes; neither restarts.
2. One session works across replicas; both workers report in.
3. An API replica is stopped in the middle of 200 requests; none fails.
4. A third replica is added and both original ones are stopped; the new one serves everything (nginx resolved it
   without a reload).
5. A worker is stopped; the console reports one live worker and stays healthy; it is started again.

On a single host this protects against a crashed or hung process and allows zero-downtime restarts. It does
**not** protect against losing the host, MongoDB or Redis.

## Surviving the loss of a host

For that, run the pieces on several hosts:

```
                    ┌────────────── load balancer (TLS, health check /healthz) ──────────────┐
                    │                                                                        │
             host A: web-ui, gateway-api ×N, worker ×M             host B: web-ui, gateway-api ×N, worker ×M
                    │                                                                        │
                    └──── MongoDB replica set (3 members) ──── Redis + Sentinel (3 sentinels) ────┘
```

**MongoDB: a three-member replica set.** Point every replica at it:

```
MONGODB_URI=mongodb://mgw:<password>@mongo-1:27017,mongo-2:27017,mongo-3:27017/?replicaSet=rs0&authSource=admin&w=majority&retryWrites=true&readPreference=primary
```

`w=majority` makes acknowledged writes, including audit events, survive the loss of the primary.
`retryWrites=true` retries a write once across a failover. Reads go to the primary, so a decision never uses
stale policy. During an election (typically under 12 seconds) requests that need MongoDB fail closed with
`503 DEPENDENCY_UNAVAILABLE` and `Retry-After: 5`; nothing is executed without its audit record. If the policy
store is the part that's unreachable, the decision is still audited as a DENY (`POLICY_ENGINE_UNAVAILABLE`), but
the caller gets the retryable 503 rather than a misleading `ACCESS_DENIED`.

**Redis: one master with replicas, managed by Sentinel.**

```
REDIS_SENTINELS=sentinel-1:26379,sentinel-2:26379,sentinel-3:26379
REDIS_SENTINEL_MASTER=mgw
REDIS_SENTINEL_PASSWORD=<only if the sentinels require auth>
REDIS_URL=redis://:<password>@ignored:6379/0     # password, database and rediss:// TLS for the master
```

The gateway asks the sentinels for the current master and reconnects to the promoted replica after a failover.
Use `appendonly yes` with `appendfsync everysec` on every Redis node, and `min-replicas-to-write 1` so a
partitioned old master stops accepting writes. With that setting, run **at least two replicas**: after a failover
the promoted master needs one replica left, or it refuses writes. During a failover (seconds), hard quotas,
sessions and job queueing fail closed. Redis Cluster isn't supported: the quota scripts and the job stream need
one keyspace.

Point Sentinel at the master by **IP address or a DNS name that keeps resolving when the host is down**. Docker
and Kubernetes service names stop resolving the moment the container dies; Sentinel's blocking re-resolution then
puts it into TILT mode, in which it deliberately does nothing, so it never fails over. (`sentinel monitor mgw
10.0.0.11 6379 2`, not `sentinel monitor mgw redis 6379 2` with `resolve-hostnames yes`.)

What a Redis failover can lose, with asynchronous replication: the last second or so of writes. In practice
that means a few quota increments (limits may admit slightly more calls than configured, once), console sessions
created in that second (users sign in again), and approval jobs queued in that second. Those approvals are not
lost: they stay `APPROVED` in MongoDB, and the worker re-queues approvals that have waited too long.

**Approved calls across an outage.** Execution has one point of no return: the moment the tool call is sent
to the upstream. If MongoDB or Redis fails before it (including while the dispatch record and its audit event
are written), nothing was sent: the approved call is handed back (`APPROVED`, audited as
`approval.execution.deferred`) and retried, never aborted, and the retry is not blocked by the first attempt's
dispatch record. If it fails after it, the call is never retried: it may have reached the upstream. The
gateway keeps retrying the writes that record the outcome (the invocation record, its audit event, and the
approval's final state) for up to 30 seconds, long enough to ride out an election, so the result is normally
still recorded. The audit event keeps the same ID across retries, so a retry whose first attempt did land is not
recorded twice. This applies to direct agent calls too: a call that ran is audited even if the primary steps down
as it returns. Usage counters are best effort. If the outcome still can't be recorded, the request is marked
`FAILED` with a message saying the outcome could not be recorded.

The worker sweeps claims that have been in progress for over 5 minutes (a worker died, or was cut off for
longer than 30 seconds). With no dispatch record, the call never reached the upstream and goes back to
`APPROVED`. With one, it may have, so it is marked `FAILED` (outcome unknown, audited as
`approval.execution.failed`) and never run again. Exactly once beats at least once here; nothing stays stuck.

**Verified in CI.** The `failover` job (`.github/failover/docker-compose.failover.yml`) runs this layout: a
three-member replica set with keyfile auth and `w=majority`, a Redis master with two replicas and three
Sentinels. Under steady load it kills the MongoDB primary, then the Redis master, with approvals in flight
each time. It requires that every response is a success or a fail-closed 503 (no 500, no hang, no lost session),
that the gateway recovers by itself within seconds without restarting a process, that every approved call
completes and reaches the upstream exactly once, and that every successful call is in the audit log. Typical result:
one to three 503s out of about 450 requests per failover.

**Load balancer.** Health-check `GET /healthz` on each web-ui (or `GET /health/ready` through it, which also
checks MongoDB and Redis). No session affinity is needed.

**Clocks.** NTP on every host.

**Backups.** `deploy/scripts/backup.sh` and `restore.sh` drive the Compose `mongodb` container, so they don't
apply to an external replica set. Back the replica set up with your MongoDB tooling (for example
`mongodump --uri "$MONGODB_URI" --db mcp_gateway --archive --gzip` against a secondary, or filesystem snapshots),
restore with `mongorestore --drop`, then run `python -m app.tools.verify_data` in a gateway container before
starting traffic, exactly as `restore.sh` does. See the backup section in [operations](operations.md).

## Sizing

Start with 2 API replicas and 2 workers. API replicas are CPU-bound mostly on JSON-schema validation and
TLS to upstreams; add replicas when p95 latency of `/api/v1/gateway/*` rises. Workers mostly wait on upstream
tool calls, one approved call at a time each: add workers when `mgw_approval_queue_depth` stays above zero.
Each replica keeps its own MongoDB connection pool (up to 100 connections by default); size MongoDB's connection
limit for the total.

## Monitoring

| Metric | Watch for |
|---|---|
| `mgw_component_up{component="worker"}` | 0: no worker alive |
| `mgw_workers_alive` | fewer than you run |
| `mgw_component_up{component="mongodb"\|"redis"}` | 0 on any replica |
| `mgw_siem_up`, `mgw_siem_lag_seconds` | forwarding stopped or falling behind after a failover |
| `mgw_approval_queue_depth` | jobs piling up (too few workers) |
