# OAuth 2.0 for agents

Agents can authenticate with **access tokens from your identity provider** instead of a gateway API key. The agent
gets a token from its IdP with the OAuth 2.0 client-credentials grant, then sends it as
`Authorization: Bearer <token>`. It works on `/mcp` and on the gateway REST API.

The gateway stores nothing secret for these agents. The client secret, or the private key for
`private_key_jwt`, stays between the agent and the IdP, and you rotate it there. The agent's identity lives in
the same directory as your other workloads.

API keys, [client certificates](mtls.md) and OAuth can be mixed, even on one agent.

Verified end to end in CI against a real Keycloak (the `agent-oauth` job). It covers client-credentials tokens
over REST and MCP, tokens for other clients, a missing audience, ID tokens, tampering, required scopes and
revocation.

## How it works

```
agent ──client credentials──▶ IdP token endpoint ──▶ access token (JWT, signed by the IdP)
agent ──Authorization: Bearer <token>──▶ gateway ──▶ verify ──▶ issuer + client ──▶ OAuth credential ──▶ policy
```

1. A bearer value that isn't a gateway key (`mgw_…`) and has the shape of a JWT is treated as an access token.
2. The token's `iss` must be a **trusted issuer** configured by a platform administrator. The issuer's signing
   keys come from its JWKS, read from the issuer's discovery document or a configured JWKS URI, and cached for an
   hour. An unknown `kid` (key rotation) triggers at most one refetch a minute.
3. The token is verified:
   - **Signature:** asymmetric algorithms only, from the issuer's allowlist. Never `none` or `HS*`, so the
     public key can't be used as an HMAC secret.
   - **Claims:** exact `iss`; `aud` must contain the gateway's audience for that issuer; `exp` is required;
     `nbf` and `iat` are honoured with 60 s leeway; the lifetime must not exceed the configured maximum.
   - **Not an ID token:** tokens with a `nonce` claim are refused. Optionally, only RFC 9068 tokens
     (`typ: at+jwt`) are accepted.
   - **Scopes:** each required scope must be in `scope` or `scp`.
4. The client is identified by **issuer + a configured claim**, usually the client ID. That pair must match exactly
   one active **OAuth credential**. From there everything is the same as for an API key: the credential's scopes
   and expiry, revocation, the agent's status, policies, quotas, approvals, and the audit log (which records the
   credential ID, never the token).

Invalid tokens get the same `401 INVALID_CREDENTIAL` as invalid keys. The reason is logged on the gateway, never
returned. If the issuer's keys can't be fetched, the answer is `503 DEPENDENCY_UNAVAILABLE`, so agents retry
instead of treating their credentials as bad.

## Set up

### 1. At the identity provider

- Register an **API** (resource) for the gateway, and note its identifier: the token audience.
- Register a **confidential client** for each agent, with **only** the client-credentials grant. If the same client
  could also sign people in, users could obtain tokens that carry its client ID.
- Make sure the client's access tokens carry the gateway's audience.

| IdP | Audience | Client claim | Notes |
|---|---|---|---|
| Microsoft Entra ID | v2 tokens: the **application (client) ID** of the gateway's API app registration; v1 tokens: its app ID URI, e.g. `api://mcp-gateway` | `azp` (v2) or `appid` (v1) | Issuer `https://login.microsoftonline.com/<tenant-id>/v2.0` (v1: `https://sts.windows.net/<tenant-id>/`). Set `accessTokenAcceptedVersion: 2` on the API app registration for v2 tokens. Agents request `<app ID URI>/.default`. Grant each agent app an application permission (app role) on the API. Use a separate app registration for the gateway API and for console SSO. |
| Keycloak | add an *audience* protocol mapper to the client | `azp` | Issuer `https://<host>/realms/<realm>`. Turn off standard flow and direct access grants. `sub` is the service-account user ID, not the client ID. |
| Okta | the authorization server's audience | `sub` or `cid` | A custom authorization server, with a scope for the gateway. |
| Auth0 | the API identifier | `azp` or `sub` (`<client-id>@clients`) | Machine-to-machine application authorized for the API. |
| AD FS | the relying party identifier | `appid` | Server application with client credentials. |

### 2. In the gateway

**Settings → Agent OAuth** (platform administrators), or `PUT /api/v1/agent-oauth/config`:

| Field | |
|---|---|
| Issuer | exactly the tokens' `iss` |
| Audience | the gateway's API identifier at that IdP. **Never the client ID of an agent or of the console's SSO app:** ID tokens carry their client's ID as the audience. (Entra ID v2 uses the API app's own client ID, which is fine as long as that app registration is used only for the API.) For MCP-native clients, use the MCP resource URI where your IdP supports resource indicators (RFC 8707). |
| Client claim | which claim identifies the client (see the table) |
| JWKS URI | optional; read from `/.well-known/openid-configuration` or `/.well-known/oauth-authorization-server` otherwise |
| Required scopes | optional; each must be granted |
| Maximum token lifetime | default 24 h. Tokens valid for longer are refused. |
| Signing algorithms | asymmetric only; default RS256, PS256, ES256 |
| Require `at+jwt` | accept only RFC 9068 access tokens |
| Advertise to MCP clients | list the issuer in the discovery document (below). Off: trusted, but not advertised. |

**Test keys** checks that the gateway can fetch the issuer's keys. Up to 10 issuers can be trusted.

The gateway reaches the IdP with the same TLS settings as single sign-on: the system CAs, or
`OIDC_CA_BUNDLE_FILE` for an IdP behind an internal CA. Plain `http://` issuers are accepted only with
`OIDC_ALLOW_INSECURE_HTTP=true` outside production.

### 3. For each agent

Open the agent and choose **Add OAuth client** (tenant, security, or platform administrators), or call
`POST /api/v1/auth/agent-oauth-clients` with `{agent_id, issuer, subject, scopes, expires_at}`. `subject` is the
value of the client claim, usually the client ID. An issuer + client pair can belong to only one active
credential.

### 4. In the agent

```python
import httpx

tok = httpx.post("https://idp.corp.example/realms/corp/protocol/openid-connect/token",
                 data={"grant_type": "client_credentials"}, auth=("hr-bot", CLIENT_SECRET)).json()["access_token"]
httpx.post("https://gateway.corp.example/api/v1/gateway/tools/hr__get_attendance_summary/invoke",
           headers={"Authorization": f"Bearer {tok}"}, json={"arguments": {"employee_id": "E1001"}})
```

Fetch a new token before the old one expires; most client libraries do this automatically.

### Without a client secret: `private_key_jwt`

Most IdPs let a client authenticate with a signed JWT instead of a secret (RFC 7523): the agent keeps a private
key, and the IdP holds only the public key (or a JWKS URL). Nothing that can be replayed crosses the network, and
the key can live in a TPM, an HSM or a cloud KMS. The gateway needs no change for this; it only sees the
resulting access token.

```python
import time, uuid, httpx, jwt

TOKEN_URL = "https://idp.corp.example/realms/corp/protocol/openid-connect/token"
assertion = jwt.encode({"iss": "hr-bot", "sub": "hr-bot", "aud": TOKEN_URL, "jti": str(uuid.uuid4()),
                        "iat": int(time.time()), "exp": int(time.time()) + 60},
                       open("/etc/agent/client.key").read(), algorithm="RS256", headers={"kid": "hr-bot-2026"})
tok = httpx.post(TOKEN_URL, data={
    "grant_type": "client_credentials",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": assertion}).json()["access_token"]
```

Keycloak: client authenticator **Signed JWT**. Entra ID: upload a certificate to the agent's app registration and
use its thumbprint (`x5t`) as the header instead of `kid`. Okta: `private_key_jwt` with the public key registered
on the application.

## MCP clients: discovery

MCP clients that implement the MCP authorization specification find the identity provider on their own; the
user only enters the gateway's MCP URL:

1. The client calls `/mcp` without a token and gets `401` with
   `WWW-Authenticate: Bearer realm="mcp-gateway", resource_metadata="https://<gateway>/.well-known/oauth-protected-resource/mcp"`.
2. It reads that document (OAuth 2.0 Protected Resource Metadata, RFC 9728):

   ```json
   {"resource": "https://gateway.corp.example/mcp",
    "authorization_servers": ["https://idp.corp.example/realms/corp"],
    "bearer_methods_supported": ["header"], "resource_name": "MCP-Gateway", "scopes_supported": ["mcp.tools"]}
   ```

3. It discovers the IdP from its metadata, obtains a token (requesting `resource=https://gateway.corp.example/mcp`,
   RFC 8707), and calls `/mcp` with it. The token must still pass every check above and map to an OAuth
   credential.

The document is served only while OAuth for agents is enabled and at least one issuer is advertised; otherwise
`404`, and the 401 challenge is a plain `Bearer realm="mcp-gateway"`. A rejected token adds
`error="invalid_token"`. The `resource` URI comes from `PUBLIC_BASE_URL` and `MCP_ENDPOINT_PATH`, never from the
request, so set `PUBLIC_BASE_URL` to the URL agents use. The gateway REST API answers 401s with the same challenge.
The document is public and contains nothing secret; it can be read cross-origin.

## Revocation

- **Revoke the credential** in the console, revoke the agent, or use emergency revocation. This takes effect
  immediately for every replica, whatever tokens the agent still holds.
- Disabling the client or rotating its secret at the IdP stops **new** tokens. Tokens already issued stay valid
  until they expire, because the gateway doesn't call the IdP per request. Keep access-token lifetimes short
  (5–60 minutes) and use the gateway credential for immediate cut-off.

## Security notes

- **Configuration is trusted input.** Anyone who can change the trusted issuers decides which tokens are
  accepted, so only platform administrators can, and every change is audited with high severity
  (`agent_oauth.config.updated`).
- **IdP compromise.** A compromised IdP, or a compromised IdP admin, can mint tokens for any registered client.
  That's inherent to federation. Scope each agent's policies narrowly, as for keys.
- **Audience confusion.** Configure the gateway's own audience. Tokens issued for other APIs at the same IdP are
  refused.
- **Mapping is explicit.** A valid token for a client that has no OAuth credential is refused. Nothing is
  provisioned automatically.

## Audit events

`credential.created` (`credential_type: oauth_client`, issuer and client), `credential.revoked`,
`agent_oauth.config.updated`, `agent_oauth.issuer.tested`. Tool calls record the agent and the credential ID,
like any other credential.
