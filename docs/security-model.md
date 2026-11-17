# Security Model

## Principals and authentication

| Principal | Credential | Storage | Notes |
|---|---|---|---|
| **User** (human) | username + password → server-side session | Argon2id hash; session in Redis keyed by SHA-256 of the session ID | Cookie `__Host-mgw_session` (HttpOnly, Secure, SameSite=Strict). Unsafe methods need `X-CSRF-Token` to match the `mgw_csrf` cookie (double submit). Login is throttled per user and IP: failed attempts count, successful ones don't. Sessions have absolute and idle timeouts. |
| **Agent** | API key `mgw_live_<16-hex public id>_<secret>` | HMAC-SHA256(pepper) of the key; only the prefix is stored in clear | Shown **once** at creation or rotation. Constant-time comparison. Scopes: `tools:list`, `tools:invoke`, `approvals:read`. Optional expiry. Revocable individually, per agent, or all at once (emergency). |
| **Agent** (optional) | X.509 client certificate, through a TLS proxy | nothing secret: the SHA-256 fingerprint (pinned) or a SAN to match | The proxy's handshake proves possession of the key. The forwarded certificate is accepted only from `MTLS_TRUSTED_PROXIES`, and re-checked against `MTLS_CLIENT_CA_FILE` (issuer, validity dates, client-auth usage). Same scopes, expiry and revocation as keys. See [mtls.md](mtls.md). |
| **Agent** (optional) | OAuth 2.0 access token (JWT) from a trusted IdP, e.g. client credentials | nothing secret: the issuer + client ID to match | Signature against the issuer's JWKS (asymmetric algorithms only), exact issuer, audience, expiry and a lifetime cap; ID tokens refused; optional required scopes and `at+jwt`. Mapped to exactly one OAuth credential, with the same scopes, expiry and revocation as keys. See [agent-oauth.md](agent-oauth.md). |

User sessions cannot call `/mcp`, and agent keys cannot call administrative routes.

**Single sign-on (optional).** Users can also sign in through one OpenID Connect IdP (authorization code
flow with PKCE S256, single-use state bound to the browser by a cookie, nonce, ID-token signature with
asymmetric algorithms only, exact issuer, audience/`azp`, expiry). Accounts are keyed on issuer + subject.
IdP groups map to tenant memberships and roles, re-applied at every sign-in. SSO accounts have no
password. Local password sign-in can be restricted to named break-glass platform administrators. The SSO
client secret is write-only and stored AES-256-GCM encrypted. See [sso.md](sso.md).

**LDAP / Active Directory (optional).** Users can sign in on the normal form with their directory account
(search, then bind as the user, over LDAPS or StartTLS with strict certificate and host-name verification).
The username is escaped before it goes into the LDAP filter, empty passwords are refused before any bind
(no unauthenticated binds), and referrals are never followed. Local accounts always use their local password,
so a directory user can't take over a local account by sharing its username. Directory accounts are keyed
on the entry's unique ID. Group rules and break-glass work as with SSO. The service-account password is
write-only and stored AES-256-GCM encrypted. See [ldap.md](ldap.md).

## Roles

| Role | Scope | Can |
|---|---|---|
| `platform_admin` | global | everything, including tenant lifecycle, global settings and cross-tenant audit search |
| `tenant_admin` | tenant | users, servers, tools, policies, agents, keys, approvals |
| `security_admin` | tenant | policies, tool risk/enablement, keys, approvals, audit, server enable/disable/test |
| `approver` | tenant | decide approval requests |
| `auditor` | tenant | read audit, invocations, users |
| `developer` | tenant | register servers, refresh tools, register agents, simulate policies |

Role checks happen on the server for every route (`require_user(*roles)`). The console hides controls as a
convenience only.

## Tenant isolation

- The tenant always comes from the session or the agent credential, **never** from the request body or headers.
- Every tenant-owned query goes through `TenantScopedRepository`, which requires `tenant_id`. Cross-tenant
  operations exist only as explicitly named `*_global` methods, used by platform admins and audited.
- Requests for another tenant's resources return 404, so existence is not disclosed.
- Redis keys are namespaced by tenant (`q:t:<tenant>:…`).
- Suspending a tenant blocks its agent keys and invocations immediately.

## Authorization: default-deny policy engine

`policy_service.evaluate()` is a pure function:

1. Collect enabled policies for the tenant, plus global (`tenant_id="*"`) policies.
2. A policy **matches** when principal type, ids/roles, action (`discover`/`invoke`), server (alias/id/name or
   pattern), tool (upstream name/gateway name/id or pattern), risk level, environment, time window and source
   CIDR all match.
3. **Any matching deny → DENY.** Otherwise **any matching allow → ALLOW**, or **REQUIRE_APPROVAL** if a matching
   allow requires approval, the tool requires approval, or the tool is critical and the tenant enforces
   critical approval. **No match → DENY** (`NO_MATCHING_ALLOW`).
4. Any exception during evaluation → **DENY**.

Discovery (`tools/list`) returns only tools that are enabled, reviewed, on an enabled server, and allowed for
`discover`. Discovery never grants anything: `tools/call` is evaluated again from scratch. Allow policies with
wildcards, or that match every principal, are rejected unless `confirm_broad_grant: true` is sent. The UI asks
for typed confirmation.

Policies can also be managed as code ([policy-as-code.md](policy-as-code.md)). Bundles go through the same
validation, apply only a reviewed plan (bound by fingerprint), are all or nothing, and only ever modify or prune
policies they own. Hand edits of a bundle-owned policy need an explicit override, which is audited.

## Tool lifecycle controls

- Discovered tools are **disabled** with status `pending_review`. Enabling requires a risk level.
- A tool's schema is fingerprinted (SHA-256 of canonical JSON) and versioned. A changed schema sets
  `schema_changed`, and calls are blocked until an administrator acknowledges the change.
- Tool names and schemas are validated at discovery. Invalid tools are rejected and reported.
- Upstream descriptions are shown in the console as untrusted text.

## Input and output controls

- Arguments are validated against the tool's JSON Schema. Unknown properties are rejected unless the schema
  allows them. Byte size, JSON depth, string length and array length are capped before dispatch. Invalid calls
  never reach the upstream.
- Output: byte cap, optional output-schema validation, configured field redaction. The result is returned with
  an untrusted-content marker. Audit stores only input and output **hashes**.

## Human approval

- The request stores canonical arguments, their SHA-256 hash, and AES-256-GCM ciphertext whose associated data
  is `<tenant>:<approval id>`. Swapping ciphertexts between records fails to decrypt.
- Separation of duties: the requesting principal, and the user who owns the requesting agent, cannot approve.
  Two-person approval needs two **distinct** approvers. Critical tools need `confirm_critical`, which the UI
  collects as typed confirmation. Rejection needs a comment by default.
- Approval authority can be **delegated** for up to 90 days. The delegate acts with the delegator's current
  roles and groups, separation of duties is checked against both, one person's authority counts once, and
  delegations don't chain. Policies can also require approver SSO groups and escalate stale requests to other
  roles. Details: [approvals](approvals.md).
- Requests expire (default 60 min, configurable per tool).
- Execution is claimed atomically (`APPROVED → REVALIDATING`), so it happens at most once even with many
  workers or duplicate jobs. The full pipeline runs again with the **current** credential, tenant, server,
  tool, policy and quota state. Any change → `EXECUTION_ABORTED` with a stable code.
- The console flags requests whose policy or tool state changed since they were made.

## Quota semantics

| Scope | Key | Windows |
|---|---|---|
| global | `q:global:*` | system settings `global_limits` |
| tenant | `q:t:<tenant>:*` | tenant `settings.quotas` |
| tool | `q:t:<tenant>:tool:<tool>:*` | tool `limits` |
| policy | `q:t:<tenant>:p:<principal>:tool:<tool>:*` | policy `max_calls_per_*` |
| concurrency | per agent / per tool slots | `MAX_CONCURRENT_CALLS_PER_AGENT`, tool `limits.concurrency` |

`per_minute` and `per_hour` are sliding windows (sorted sets). `per_day` and `per_month` are fixed calendar
counters (UTC). A single Lua script checks **all** applicable limits and consumes all or none, so a call
rejected by one limit doesn't use up the others. Rejections return 429 with `Retry-After`
(`RATE_LIMIT_EXCEEDED`, `QUOTA_EXCEEDED`, `CONCURRENCY_LIMIT_EXCEEDED`). Requests that need approval consume
rate quota when made, which prevents approval flooding, and pass admission again at execution. If Redis is
unavailable, calls with hard limits fail closed (`DEPENDENCY_UNAVAILABLE`). `REDIS_FAIL_OPEN_DEV` exists for
development only and is ignored in production.

## Upstream connections (SSRF and stdio)

- URLs are validated at registration and again before every connection: http(s) only, no embedded
  credentials, optional host allowlist (`UPSTREAM_HOST_ALLOWLIST`, supports `*.domain`).
- DNS is resolved **at connect time**. Every resolved address is checked and the connection goes to the
  validated IP, which defeats DNS rebinding. Link-local, cloud metadata, multicast, CGNAT and unspecified
  ranges are always blocked. Private and loopback ranges are blocked unless both the platform setting and the
  per-server flag allow them. Redirects are not followed.
- stdio servers: the executable must be on `STDIO_EXECUTABLE_ALLOWLIST`. No shell is used. Arguments are
  passed verbatim and checked for shell metacharacters. Dangerous environment variables (`LD_PRELOAD`,
  `PYTHONPATH`, …) are refused.
- Upstream errors are sanitized. Endpoints, stack traces and credentials never reach agents.
- Per server: a custom CA bundle for the upstream's certificate, and a client certificate for upstreams that
  require mTLS. The private key is write-only and encrypted ([mtls.md](mtls.md#upstream-servers-that-require-mtls)).

## Secrets and cryptography

| Secret | Protection |
|---|---|
| Upstream credentials | AES-256-GCM, AD = `<tenant>:<secret id>`, in the `secrets` collection. The API returns only `has_secret`. |
| Upstream client-certificate keys | Same as upstream credentials. The API returns only the certificate's subject, issuer, expiry and fingerprint. |
| Approval arguments and results | AES-256-GCM, AD bound to the approval |
| Agent keys | HMAC-SHA256 with `API_KEY_HASH_PEPPER` |
| Passwords | Argon2id |
| Process secrets | env vars or `<NAME>_FILE` mounted files. Production rejects placeholders and values shorter than 32 characters. |

Logs pass through a scrubber that redacts sensitive keys, `mgw_` keys and Bearer tokens. Key rotation:
[operations.md](operations.md#encryption-key-rotation).

## Audit

`audit_events` is append-only: the repository has no update or delete. Each event records type, severity,
principal (and delegating user), resource, decision, reason code, policy IDs, status, duration, input/output
hashes, and request/invocation/approval IDs for correlation. When `AUDIT_REQUIRED_FOR_EXECUTION=true` and an
audit write fails, the call fails with `AUDIT_UNAVAILABLE` before dispatch. Exports are size-capped, guarded
against CSV formula injection, and audited themselves. Events can also be streamed to a SIEM in near real time
(at least once, in order, no loss during collector outages; see [siem.md](siem.md)). Shipping them off the
host is the recommended way to protect the audit trail from a database administrator.
