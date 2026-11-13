# Security Policy

MCP-Gateway is a security control. Vulnerabilities in it can expose every tool behind it, so we treat
reports as high priority.

## Reporting a vulnerability

- **Do not open a public issue.** Report privately to the project's security contact (configure this for
  your organisation, e.g. a `security@` mailbox or your internal vulnerability intake) with:
  affected version/commit, component, reproduction steps, impact, and any proof-of-concept.
- You will get an acknowledgement within **3 business days** and an initial assessment within **10 business days**.
- Please give us reasonable time to fix the issue before disclosure. We credit reporters who want credit.

### In scope (examples)
Tenant-isolation bypass; authentication or session flaws; policy bypass (a hidden or denied tool reaching an
upstream); approval bypass or replay; SSRF through server registration; stdio command injection; secret or
key disclosure through the API, logs or exports; audit tampering; CSRF/XSS in the console.

### Out of scope
Findings that require a compromised host or administrator account; vulnerabilities in upstream MCP servers
themselves; denial of service by an authenticated administrator; missing hardening in deployments that ignore
[docs/deployment.md](docs/deployment.md).

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (current) | Yes: security fixes |
| older | No |

## Security principles in this codebase

- Default deny. Discovery is never an authorization grant. Every call is re-authorized.
- Secrets (agent keys, upstream credentials, encryption keys) are never returned after creation and never logged.
- Agent keys are stored as HMAC-SHA256(pepper) hashes. Upstream secrets and approval arguments are encrypted
  with AES-256-GCM and bound to their record via associated data.
- Fail closed: the policy engine on error, quotas when Redis is down, sensitive execution when the audit log is unavailable.
- Tool output is untrusted data and is passed to agents marked as such.

See [docs/security-model.md](docs/security-model.md) and [docs/threat-model.md](docs/threat-model.md).
