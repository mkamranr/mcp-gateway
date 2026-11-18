# Single sign-on (OpenID Connect)

MCP-Gateway can sign console users in through one platform-wide OpenID Connect identity provider (IdP):
Keycloak, Microsoft Entra ID, AD FS, or any other provider that supports discovery and the authorization code
flow. SSO applies to **human console users only**. Agents keep using API keys.

To sign users in with a directory password instead (or as well), see [LDAP / Active Directory](ldap.md). To
provision accounts and groups from the IdP ahead of sign-in, and deprovision them at once, see
[SCIM provisioning](scim.md).

## How it works

1. The browser opens `GET /api/v1/auth/oidc/login`. The gateway creates a random `state`, a `nonce` and a
   PKCE verifier. It stores them in Redis for 10 minutes under the SHA-256 of `state`, and sets a short-lived
   `mgw_oidc` cookie (HttpOnly, SameSite=Lax, path `/api/v1/auth/oidc`) that binds the flow to this browser.
   It then redirects to the IdP with `code_challenge_method=S256`.
2. The IdP redirects to `GET /api/v1/auth/oidc/callback`. The gateway:
   - checks that the browser-binding cookie matches, then atomically consumes the `state` (single use);
   - exchanges the code at the token endpoint (`client_secret_basic`, `client_secret_post`, or a public client
     with PKCE only);
   - validates the ID token: signature against the IdP's JWKS, **asymmetric algorithms only** (never `none`
     or `HS*`), exact `iss`, `aud` contains the client ID (`azp` checked for multi-audience tokens), `exp`/`iat`
     with 60 s leeway, and the `nonce`;
   - reads groups from the ID token, or from the userinfo endpoint if the claim is absent (only if userinfo's
     `sub` matches).
3. The user is found by **issuer + subject**, never by username or email. On first sign-in the account is
   created just-in-time (`auth_source: oidc`, no password).
4. **Group rules** (`IdP group → tenant → roles`) are applied at every sign-in:
   - memberships created by SSO (`managed_by: oidc`) are created, updated, or **disabled** when the group no
     longer maps to the tenant, so removing a user from a group in the IdP removes their access here at the
     next sign-in;
   - memberships an administrator created by hand are never changed;
   - members of a *platform administrator group* get the platform administrator role (SSO accounts only; a
     local administrator is never demoted).
5. A user with no active membership and no platform administrator role is refused (`no_access`). Otherwise
   a normal gateway session is created, with the same timeouts and CSRF protection as a password sign-in.

Existing sessions are not ended when someone is removed from a group. They end at the session idle or
absolute timeout. To cut access immediately, disable the user or the membership in **Users & Tenants**.

Every outcome is audited: `auth.login.succeeded` (with `method: oidc`), `auth.oidc.failed`,
`auth.oidc.denied`, `user.oidc.provisioned`, `user.membership.created/changed`, `user.platform_admin.changed`
and `sso.config.updated`.

## Configure the gateway

1. Set `PUBLIC_BASE_URL` to the exact URL users open in the browser, such as `https://mcp-gateway.corp.example`.
   The redirect URI is `PUBLIC_BASE_URL + /api/v1/auth/oidc/callback`, and **Settings → Single sign-on** shows
   it.
2. If the IdP uses an internal CA, mount the CA bundle and set `OIDC_CA_BUNDLE_FILE`. TLS is always verified,
   and redirects are never followed.
3. Register the client at the IdP (see below), then open **Settings → Single sign-on** as a platform
   administrator:
   - **Issuer URL**: exactly the `issuer` value in the IdP's `/.well-known/openid-configuration`.
   - **Client ID** and **Client secret**. The secret is write-only: it is stored AES-256-GCM encrypted and
     never returned by the API.
   - **Claims**: which claims hold the username, email, display name and groups.
   - **Group rules** and **Platform administrator groups**.
   - Save, then **Test connection**. This fetches discovery and the signing keys, and warns when none of the
     IdP's signing algorithms are accepted.
4. Enable SSO and sign in from a private window before you restrict local sign-in.

| Setting | Default | Purpose |
|---|---|---|
| `OIDC_CA_BUNDLE_FILE` | unset | PEM bundle used to verify the IdP's TLS certificate |
| `OIDC_HTTP_TIMEOUT_SECONDS` | `10` | Timeout for discovery, JWKS, token and userinfo requests |
| `OIDC_ALLOW_INSECURE_HTTP` | `false` | Allow an `http://` issuer. **Ignored when `APP_ENV=production`.** Development only. |

### Local sign-in and break-glass accounts

**Local password sign-in** can be set to:

- **Allowed for all local accounts** (default). SSO and passwords both work.
- **Only break-glass accounts**. Password sign-in is refused for everyone except the named accounts. The
  gateway accepts this setting only if at least one named account is an *active local platform
  administrator*, so an IdP outage cannot lock everyone out. Every break-glass sign-in is audited as
  `auth.break_glass.used` with high severity, so alert on it.

SSO accounts never have a password: password sign-in and password change are refused for them.

### Linking existing local accounts

By default an SSO identity whose username matches an existing local account is refused (`account_conflict`).
Otherwise anyone who can choose their username at the IdP could take over a local account. During a
migration you can turn on **Link SSO identities to existing local accounts**. The first SSO sign-in then binds
the local account to that issuer and subject (audited as `user.oidc.linked`). Turn it off when the migration is
done.

What linking does and doesn't do:
- **The account becomes SSO-only.** Its local password is removed, and sessions opened with that password end.
  Whoever knew the password (for example the tenant administrator who created the account) can't sign in as the
  linked user.
- **Some accounts are never linked by username:** platform administrators, break-glass accounts and directory
  (LDAP) accounts. The sign-in is refused with `account_conflict` and audited (`auth.oidc.denied`).
- **The platform administrator flag follows the IdP group** (`platform_admin_groups`) for every account that
  signs in through SSO, in both directions. Each change is audited as `user.platform_admin.changed`.

Changing the **issuer** requires entering the client secret again (or clearing it), so a stored secret is never
sent to a token endpoint it wasn't entered for.

## IdP setup

In every case the redirect URI is `https://<gateway>/api/v1/auth/oidc/callback`, and the scopes are at least
`openid profile email`.

### Keycloak

1. **Clients → Create client**: type *OpenID Connect*, client ID `mcp-gateway`.
2. *Client authentication* **On**, *Standard flow* **On**, and disable *Direct access grants* and *Implicit
   flow*.
3. **Valid redirect URIs**: the gateway callback. **Web origins**: leave empty.
4. **Advanced → Proof Key for Code Exchange**: `S256`.
5. Copy the secret from **Credentials**.
6. Groups claim: **Client scopes → mcp-gateway-dedicated → Add mapper → Group Membership**, token claim name
   `groups`, *Full group path* **Off**, and add it to the ID token.
7. Issuer: `https://<keycloak>/realms/<realm>`.

### Microsoft Entra ID

1. **App registrations → New registration**. Platform **Web**, redirect URI = the gateway callback.
2. **Certificates & secrets → New client secret**. Note its expiry date and plan the rotation.
3. **Token configuration → Add groups claim**: *Security groups*, ID token: *Group ID*. Entra sends group
   **object IDs**, so use those IDs in the group rules. To limit token size, use *Groups assigned to the
   application* and assign the groups under **Enterprise applications → Users and groups**. Users in more
   than 200 groups get no `groups` claim (overage), so assign only the groups you need.
4. Username claim: `preferred_username` (the UPN) works. Add the optional `email` claim if you need it.
5. Issuer: `https://login.microsoftonline.com/<tenant-id>/v2.0` (exactly what the discovery document says).
6. Algorithm: RS256.

### AD FS (Windows Server 2016 or later)

1. **Application Groups → Add → Server application accessing a web API**, or *Web browser accessing a web
   application* for a public client. Redirect URI = the gateway callback. Generate a shared secret.
2. Add an *Issuance Transform Rule* that sends group membership as a `groups` claim:
   *Send LDAP Attributes as Claims* → *Token-Groups - Unqualified Names* → outgoing type `groups`. Also send
   `upn` or `sAMAccountName` as the username, and set the **Username claim** setting to match.
3. Grant the `openid`, `profile` and `email` scopes (`allatclaims` if you need claims in the ID token).
4. Issuer: `https://<adfs>/adfs`. The gateway always sends a PKCE S256 challenge. It refuses an IdP only if
   discovery lists `code_challenge_methods_supported` without `S256`.
5. If AD FS uses an internal CA, set `OIDC_CA_BUNDLE_FILE`.

## Troubleshooting

The login page shows a short reason. The detail is in the audit log (`auth.oidc.failed` / `auth.oidc.denied`)
and the gateway log (`oidc.callback.failed`).

| Code | Usual cause |
|---|---|
| `state_invalid` | Sign-in took longer than 10 minutes, was finished in another browser, the back button replayed the callback, or `PUBLIC_BASE_URL` differs from the URL in the browser (the binding cookie isn't sent). |
| `token_exchange_failed` | Wrong client secret or authentication method, or the redirect URI isn't registered exactly. |
| `token_invalid` | Issuer mismatch, wrong client ID (audience), clock skew over 60 s, or an algorithm outside the accepted list. |
| `idp_unreachable` / `idp_misconfigured` | Network or TLS problem (try `OIDC_CA_BUNDLE_FILE`), or the discovery `issuer` doesn't match the configured issuer exactly (watch trailing slashes). |
| `no_access` | No group rule matches the user's groups. Check the groups claim name and, for Entra ID, that the rules use group object IDs. |
| `account_conflict` | A local account already has that username. See *Linking existing local accounts*. |

## IdP outage

Sign in with a break-glass account (**Break-glass sign-in** on the login page). Existing SSO sessions keep
working until they time out. See [operations](operations.md#identity-provider-outage).

## Development

`uv run python -m devtools.dev_stack --with-oidc` starts a mock IdP on port 9400 and configures SSO for it.
Demo users: `alice` (tenant admin), `bob` (developer and auditor), `carol` (no mapped group), `root`
(platform administrator). The mock IdP is in `backend/devtools/mock_oidc.py`. The security tests in
`backend/tests/security/test_sso.py` use it to check that tampered tokens, replayed state, open redirects and
account takeover attempts are all rejected.
