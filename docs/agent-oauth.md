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
| Microsoft Entra ID | the app ID URI of the gateway's app registration, e.g. `api://mcp-gateway` | `azp` (v2 tokens) or `appid` (v1) | Issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`. Set `accessTokenAcceptedVersion: 2` on the gateway's app registration to get v2 tokens. Grant the agent app an application permission (app role) on the gateway's API. |
| Keycloak | add an *audience* protocol mapper to the client | `azp` | Issuer `https://<host>/realms/<realm>`. Turn off standard flow and direct access grants. `sub` is the service-account user ID, not the client ID. |
| Okta | the authorization server's audience | `sub` or `cid` | A custom authorization server, with a scope for the gateway. |
| Auth0 | the API identifier | `azp` or `sub` (`<client-id>@clients`) | Machine-to-machine application authorized for the API. |
| AD FS | the relying party identifier | `appid` | Server application with client credentials. |

### 2. In the gateway

**Settings → Agent OAuth** (platform administrators), or `PUT /api/v1/agent-oauth/config`:

| Field | |
|---|---|
| Issuer | exactly the tokens' `iss` |
| Audience | the gateway's API identifier at that IdP. **Never a client ID:** ID tokens carry the client ID as their audience. |
| Client claim | which claim identifies the client (see the table) |
| JWKS URI | optional; read from `/.well-known/openid-configuration` or `/.well-known/oauth-authorization-server` otherwise |
| Required scopes | optional; each must be granted |
| Maximum token lifetime | default 24 h. Tokens valid for longer are refused. |
| Signing algorithms | asymmetric only; default RS256, PS256, ES256 |
| Require `at+jwt` | accept only RFC 9068 access tokens |

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

Fetch a new token before the old one expires; most client libraries do this automatically. MCP clients that
support OAuth client credentials can use the same flow against `/mcp`.

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
