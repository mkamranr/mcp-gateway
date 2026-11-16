# Threat Model

Scope: the gateway (web-ui, gateway-api, worker), its datastores, and its connections to agents and upstream
MCP servers. Method: STRIDE per trust boundary.

## Assets

Upstream credentials · agent keys · tool capabilities (what agents can do in other systems) · approval
decisions · tool arguments and results (may contain personal data) · the audit trail · encryption key and pepper.

## Trust boundaries

1. Agent → gateway (`/mcp`, `/api/v1/gateway/*`): agents are **untrusted** and may be prompt-injected.
2. Browser → console API: authenticated humans whose browsers may be attacked (CSRF/XSS).
3. Gateway → upstream MCP servers: upstreams are **semi-trusted**. Their descriptions and output are untrusted.
4. Gateway → MongoDB/Redis: internal network, authenticated.
5. Tenant ↔ tenant inside one deployment.

## Threats and mitigations

| # | Threat | Mitigations | Residual risk |
|---|---|---|---|
| T1 | Stolen or leaked agent key used by an attacker | Keys hashed with a pepper and shown once. Prefix lets you identify a key. Expiry, rotation, revocation, emergency revoke-all. `last_used_at`/source recorded. Scopes. Every call audited. | A key is a bearer token: until revoked, the attacker has that agent's permissions. Use short expiries and network controls. |
| T2 | Agent tries tools it was not granted (including hidden ones) | Default deny. Discovery filtered. Every call re-authorized. A DENY is returned before any tool-state detail. | Unknown names return `TOOL_NOT_FOUND` while existing-but-denied tools return `ACCESS_DENIED`, so tool *names* can be probed. The state of a denied tool is not revealed. |
| T3 | Prompt injection makes an allowed agent misuse an allowed tool | Least-privilege policies, risk levels, approval for high/critical tools, strict argument schemas, rate limits, output marked untrusted, full audit. | The gateway cannot judge intent inside valid arguments. Use approvals for consequential actions. |
| T4 | Malicious upstream returns injected instructions or oversized output | Output size cap, optional output-schema validation, redaction, untrusted marker. Descriptions shown as untrusted text and reviewed before enabling. | Agents must treat tool output as data. |
| T5 | Upstream changes a tool's behaviour or schema after review (rug pull) | Schema fingerprints and versions. A changed schema blocks calls until acknowledged. Re-discovery shows the diff. | Behaviour changes that keep the schema identical are not detectable. |
| T6 | SSRF via server registration (metadata service, internal admin ports) | Scheme and host validation, host allowlist, connect-time DNS resolution and IP pinning, always-blocked ranges, private ranges need two opt-ins, no redirects. Registration is admin-only. | Allowed private ranges are reachable by design. Restrict egress at the network layer as well. |
| T7 | Command injection via stdio configuration | Executable allowlist (empty by default), no shell, argument metacharacter checks, forbidden env vars. | An allowlisted executable is trusted code. |
| T8 | Approval bypass, replay or argument substitution | Hash-bound, AD-bound encrypted arguments. Atomic state transitions. Single-claim execution. Revalidation of every precondition. Separation of duties. Expiry. | Approvers can still approve a harmful but valid request. Masked previews and the changes flag help. |
| T9 | Cross-tenant data access | Tenant from credential only. Tenant-scoped repositories. 404 for foreign IDs. Tenant-namespaced Redis keys. Security tests. | Platform admins can search across tenants (audited). |
| T10 | CSRF / XSS against administrators | SameSite=Strict `__Host-` cookie and double-submit CSRF token. React escaping. Strict CSP with no inline script, no CDN, `frame-ancestors 'none'`. | A compromised admin workstation remains out of scope. |
| T11 | Brute force of logins or keys | Login throttling per user and IP. API-key lookup throttled by prefix. Argon2id. High-entropy keys. | Distributed credential stuffing needs upstream WAF or IdP controls. |
| T12 | Audit tampering or loss | Append-only repository. Execution fails closed if audit cannot be written. Hashes instead of payloads. Exports audited. | A DB administrator can still modify Mongo. Ship audit to external WORM storage for stronger guarantees. |
| T13 | Secret disclosure via API, logs or errors | Whitelisted serializers. `has_secret` only. Log scrubbing. Sanitized upstream errors. No stack traces. | Secrets inside upstream *tool output* are passed through unless redaction is configured. |
| T14 | Encryption key or pepper compromise | Supplied as files or env, never stored in the DB. Rotation tool for the encryption key. Pepper rotation is documented (it invalidates keys). | Anyone holding both a DB dump and the key can decrypt upstream secrets. |
| T15 | Quota or concurrency exhaustion (DoS) by an agent | Atomic quotas at several scopes, concurrency slots, per-server capacity limiter, request body limit, timeouts. Approval requests consume quota. | Infrastructure-level DoS is out of scope. |
| T16 | Redis or MongoDB unavailable | Hard quotas fail closed. Execution fails closed without audit. Readiness probe reports the dependency. Worker heartbeat. | Availability is reduced during an outage. This is deliberate. |
| T18 | Forged or replayed SSO sign-in (token substitution, login CSRF, open redirect, account takeover by username) | PKCE S256. State is single use, stored hashed, expires in 10 min, and is bound to the browser by an HttpOnly cookie. Nonce. Signature verified against JWKS with asymmetric algorithms only (no `none`/`HS*`). Exact issuer, audience, `azp`, expiry. Users keyed on issuer + subject. Same-username local accounts are refused unless linking is explicitly enabled. `return_to` limited to same-origin paths. No redirects followed and TLS verified when calling the IdP. Each case covered by `tests/security/test_sso.py`. | A compromised IdP, or a compromised administrator of a mapped IdP group, grants access. Removal from a group takes effect at the next sign-in, not for sessions already open. |
| T17 | Supply chain | Locked dependencies (`uv.lock`, `package-lock.json`), pinned images, SBOM generation, offline bundle with checksums and image-ID verification. | Pin base images by digest in your registry. Scan images. |

## Out of scope / not yet covered

Penetration test, SAML and SCIM provisioning, mTLS between internal
services, HSM/KMS-backed keys, and multi-host high availability. These are documented as next steps in the
operations guide.
