# Mutual TLS

MCP-Gateway supports mutual TLS (mTLS) in two directions:

- **Agents authenticate with client certificates** instead of, or alongside, API keys. This suits agents on
  managed hosts that already have certificates from an internal PKI, such as SPIFFE/SPIRE, Vault PKI, a
  service mesh or Active Directory Certificate Services. No secret ever needs to be copied into the agent's
  configuration.
- **The gateway presents a client certificate to upstream MCP servers** that require one, and can trust an
  upstream's certificate from an internal CA.

Both are verified end to end in CI (the `mtls` job), through the real nginx and gateway containers.

## Agents: client certificates

### How it works

```
agent ──TLS + client cert──▶ nginx :8443 ──X-Client-Cert──▶ gateway-api ──▶ credential ──▶ policy
                             (handshake proves the          (accepted only from the proxy's
                              agent holds the key)           network; re-checks issuer and dates)
```

1. The agent connects to the **agent mTLS listener** with its certificate. The TLS proxy (the bundled nginx, or
   your load balancer) completes the handshake only if the certificate was issued by the agent CA. The handshake
   is what proves the agent holds the private key.
2. The proxy forwards the verified certificate to the gateway in a header (`X-Client-Cert`, URL-escaped PEM).
3. The gateway accepts that header **only from `MTLS_TRUSTED_PROXIES`**. A certificate is public, so anyone else
   sending the header proves nothing; it is ignored and logged. The gateway then re-checks that the certificate
   was issued by a CA in `MTLS_CLIENT_CA_FILE`, is within its validity dates, and is meant for client
   authentication.
4. The certificate is matched to a **certificate credential** of one agent. From there everything is the same as
   for an API key: scopes, expiry, revocation, policies, quotas, approvals and the audit log (which records the
   credential ID).

### Two ways to match a certificate

| | Match subject name (recommended) | Pin one certificate |
|---|---|---|
| Matches | any valid certificate from a trusted CA whose SAN is, for example, `spiffe://corp.example/agents/hr-bot` or `hr-bot.agents.corp.example` | exactly one certificate (SHA-256 fingerprint) |
| Renewal | automatic: issue a new certificate with the same name, nothing changes in the console | add the new certificate, then revoke the old credential |
| Expiry | the certificate's own validity, plus the credential's optional expiry | the credential expires with the certificate |
| Fits | short-lived certificates (SPIRE, Vault, cert-manager) | a few long-lived certificates issued by hand |

A subject name or certificate can belong to only one active credential. If a certificate matches a pinned
credential, that one wins; if it matches several subject-name credentials, it is refused rather than guessed.

### Setting it up with the bundled nginx

1. **Certificates.** You need the agent CA bundle (the CAs that issue agent certificates; include the issuing
   intermediate) and a server certificate for the agent listener, trusted by your agents.
2. **nginx.** Copy [`deploy/mtls/agent-mtls.conf`](../deploy/mtls/agent-mtls.conf) and the certificates into a
   directory, and mount it read-only into `web-ui` at `/etc/nginx/mtls/`:

   ```
   /etc/nginx/mtls/agent-mtls.conf   the listener (8443): ssl_verify_client on, agent endpoints only
   /etc/nginx/mtls/server.crt        the listener's certificate (+ chain)
   /etc/nginx/mtls/server.key        its key, readable by nginx (uid 101)
   /etc/nginx/mtls/agent-ca.pem      the agent CA bundle
   ```

   Publish port 8443. The listener serves only `/mcp` and `/api/v1/gateway/`; the console stays on the main
   listener. It also drops any `Authorization` header, so agents on it authenticate by certificate only. The main
   listener always strips `X-Client-Cert`, so the header can't be injected from outside.
3. **Gateway.** On `gateway-api` (and `worker`, which shares the settings):

   ```bash
   MTLS_CLIENT_CA_FILE=/run/secrets/agent_ca     # the same bundle as agent-ca.pem
   MTLS_TRUSTED_PROXIES=172.31.250.0/24           # the edge network: web-ui and gateway-api only
   ```

   In Compose, `web-ui` and `gateway-api` share a dedicated `edge` network with a fixed subnet
   (`MGW_EDGE_SUBNET`, default `172.31.250.0/24`). Nothing else is on it, so trusting it means trusting nginx.
   The gateway refuses to start with an empty or catch-all `MTLS_TRUSTED_PROXIES`.
4. **Credentials.** In the console, open the agent and choose **Add certificate**, or call
   `POST /api/v1/auth/agent-certificates`. The button appears only when client certificates are enabled.

[`.github/mtls/docker-compose.mtls.yml`](../.github/mtls/docker-compose.mtls.yml) is a complete, working
example (the CI job uses it with a throwaway PKI).

### Another TLS proxy or load balancer

Any proxy works if it (1) requires and verifies client certificates against your agent CA, (2) forwards the
certificate as URL-escaped PEM or base64 DER in one header (`MTLS_CLIENT_CERT_HEADER`, default
`x-client-cert`), (3) **overwrites** that header on every request, so a client can never supply it, and (4) is the
only thing that can reach the gateway from the `MTLS_TRUSTED_PROXIES` addresses. Examples: HAProxy
`http-request set-header X-Client-Cert %[ssl_c_der,base64]`, Traefik `passTLSClientCert` with `pem: true`.

### Revocation

- Revoke the **credential** in the console (or revoke the agent, or use emergency revocation): effective
  immediately, for every replica.
- To refuse an individual **certificate** at the TLS layer, give nginx a CRL (`ssl_crl`). Short-lived
  certificates make this rarely necessary.

### Using an agent certificate

```python
import httpx

client = httpx.Client(base_url="https://gateway.corp.example:8443",
                      cert=("/etc/agent/tls.crt", "/etc/agent/tls.key"),
                      verify="/etc/agent/gateway-ca.pem")
client.post("/api/v1/gateway/tools/hr__get_attendance_summary/invoke",
            json={"arguments": {"employee_id": "E1001"}})
```

MCP clients use the same URL with `/mcp` and their client-certificate setting; no `Authorization` header.

## Upstream servers that require mTLS

Per server (Streamable HTTP only), in the server wizard's **Authentication** step or through the API:

| Field | What it does |
|---|---|
| `tls_ca_pem` | CA bundle for the upstream's certificate, for servers with a certificate from an internal CA. Default: the standard public CAs. Empty string removes it. |
| `client_certificate` | `{cert_pem, key_pem}`: the certificate the gateway presents (chain may follow) and its unencrypted PEM private key. |
| `remove_client_certificate` | `true` removes it (PATCH). |

The private key is write-only: it is stored AES-256-GCM encrypted like other upstream secrets and never
returned. The API reports only the certificate's subject, issuer, expiry and fingerprint. Saving checks that the
key matches the certificate and that the CA bundle parses. Both can be combined with a bearer token or custom
header. The gateway builds the TLS context once per server version, so calls don't pay for it.

Upstream client certificates are per server, not per agent: the upstream sees the gateway, and the gateway
enforces which agent may call what.
