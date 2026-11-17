# LDAP and Active Directory sign-in

Console users can sign in with their corporate directory account: Active Directory, OpenLDAP, FreeIPA, or any
other LDAPv3 directory. They use the normal sign-in form. Directory groups map to tenants and roles, using the
same group rules as [single sign-on](sso.md), and are re-applied at every sign-in.

Directory sign-in applies to **human console users only**. Agents keep using API keys or
[client certificates](mtls.md). LDAP and OIDC SSO can be enabled together.

Verified end to end in CI against a real OpenLDAP server (the `ldap` job). It checks LDAPS, StartTLS, host-name
and CA verification, group search and `memberOf`, group removal, filter injection, and a directory outage.

## How it works

```
username + password ──▶ gateway ──(1) service account: find the user──▶ directory
                                 ──(2) bind as the user's DN with the password──▶
                                 ──(3) read groups → group rules → tenant roles
```

1. **Who signs in where.** A username that belongs to a **local account** always signs in with the local
   password. It never reaches the directory, so a directory user can never take over a local account by having
   the same username. Unknown usernames, and accounts created by the directory, are authenticated against the
   directory.
2. **Search, then bind.** The gateway binds as a read-only service account and searches the user search base
   with the user filter. Exactly one entry must match. It then binds as that entry's DN with the password the
   user typed. The password is never stored or logged.
3. **Groups.** Groups are read from the user's `memberOf` attribute, from a group search, or both. Groups are
   identified by their **full DN**, compared case-insensitively and ignoring spaces after commas.
4. **Account.** The account is found by the entry's **unique ID** (`objectGUID` in AD, `entryUUID` in
   OpenLDAP), never by username. On the first sign-in it is created just-in-time (`auth_source: ldap`, no local
   password). If a directory entry is deleted and re-created with the same name, the new entry does not inherit
   the old account; an administrator must delete the old account first.
5. **Group rules** (`group DN → tenant → roles`) are applied at every sign-in:
   - memberships created by the directory (`managed_by: ldap`) are created, updated, or **disabled** when the
     group no longer maps to the tenant;
   - memberships created by hand, or by SSO, are never changed;
   - members of a *platform administrator group* get the platform administrator role, and lose it when they
     leave the group.
6. A user with no active membership and no platform administrator role is refused. Otherwise a normal session
   is created, with the same timeouts and CSRF protection as a password sign-in.

Existing sessions are not ended when someone leaves a group or is disabled in the directory. They end at the
session idle or absolute timeout. To cut access immediately, disable the user in **Users & Tenants**.

## Security properties

| Risk | What the gateway does |
|---|---|
| Passwords on the wire | **TLS always**: `ldaps://`, or `ldap://` with StartTLS. The certificate is verified against the system CAs or your CA bundle, with **strict host-name checking** by the Python standard library (ldap3's own check is not used). Plain `ldap://` can't be saved unless `LDAP_ALLOW_INSECURE=true`, and that is ignored in production. |
| LDAP filter injection | The username is escaped (RFC 4515) before it is put into the filter, so `*`, `(`, `)`, `\` and NUL are literal. Placeholders are substituted, never `format()`ed. Only `{username}` (and `{user_dn}` in the group filter) are allowed. |
| Unauthenticated bind | An empty password is refused **before** any bind. Many directories treat a bind with a DN and an empty password as anonymous and report success (RFC 4513 §5.1.2). |
| Ambiguous users | Exactly one entry must match the filter; two or more is a failed sign-in. |
| Referrals | Never followed, so credentials are never sent to a server the directory names. |
| Account takeover | Local accounts never authenticate against the directory. Directory accounts are keyed on the unique ID. A directory user whose username belongs to another account is refused and audited. |
| Password guessing | The same per-user-and-IP throttle as local sign-in. Failed attempts count; successful ones don't. Directory account lockout (AD `badPwdCount`) still applies. |
| Service account | Needs read access only. Its password is write-only, stored AES-256-GCM encrypted, never returned by the API, and never written to the audit log. |
| Directory outage | Directory users get `503`. Local accounts, including break-glass administrators, keep working. Servers are tried in order; the next one is used only if a server can't be reached, never after a wrong password, so a bad password isn't counted twice. |
| Load | At most `LDAP_MAX_CONCURRENT_BINDS` (default 20) directory operations run at once per replica. Each has the configured timeout (default 5 s). |

## Configure

**Settings → LDAP / Active Directory** (platform administrators), or `PUT /api/v1/ldap/config`.

| Setting | Active Directory | OpenLDAP |
|---|---|---|
| Server URLs | `ldaps://dc1.corp.example`, `ldaps://dc2.corp.example` | `ldaps://ldap.corp.example` |
| CA certificates | your enterprise root CA (PEM), if it isn't in the system store | the directory's CA |
| Service account DN | `CN=svc-mcp-gateway,OU=Service Accounts,DC=corp,DC=example` | `cn=readonly,dc=corp,dc=example` |
| User search base | `OU=Staff,DC=corp,DC=example` | `ou=people,dc=corp,dc=example` |
| User filter | `(&(objectClass=user)(sAMAccountName={username})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))` | `(&(objectClass=person)(uid={username}))` |
| Username / unique ID attribute | `sAMAccountName` / `objectGUID` | `uid` / `entryUUID` |
| Groups | `memberOf`; for **nested groups**, a group search with `(member:1.2.840.113556.1.4.1941:={user_dn})` | `memberOf` (overlay) or a group search with `(|(member={user_dn})(uniqueMember={user_dn}))` |
| Group rule | `CN=MCP Developers,OU=Groups,DC=corp,DC=example` → tenant → Developer | `cn=mcp-developers,ou=groups,dc=corp,dc=example` → tenant → Developer |

The **Active Directory** and **OpenLDAP** buttons fill in these defaults. The AD filter skips disabled
accounts. AD refuses binds for them anyway, but filtering them out keeps them from being provisioned.

To let users sign in with their email address too, use a filter such as
`(&(objectClass=user)(|(sAMAccountName={username})(mail={username})))`. The account is still named after the
username attribute.

**Test connection** checks the saved settings: TLS, the service-account bind, and read access to the user
search base. **Look up user** also finds a user (no password needed) and shows their DN, groups, and the access
the rules would grant. Use it before you turn sign-in on.

Deployment settings (environment variables):

| Variable | Default | |
|---|---|---|
| `LDAP_ALLOW_INSECURE` | `false` | allow `ldap://` without StartTLS. Ignored when `APP_ENV=production`. For labs only. |
| `LDAP_MAX_CONCURRENT_BINDS` | `20` | directory operations in flight per replica |

The gateway must be able to reach the directory: in Compose, `gateway-api` uses the `frontend` network for
egress. If the API containers' egress is restricted, allow the directory servers on port 636 (or 389 with
StartTLS).

## Local accounts and break-glass

With **Local password sign-in → Only break-glass accounts**, only the named local platform administrators can
sign in with a local password. Everyone else must use the directory (or SSO). Saving refuses a list without at
least one active local platform administrator. Each break-glass sign-in is audited with high severity
(`auth.break_glass.used`). If both SSO and LDAP restrict local sign-in, an account named in either list may
use its password.

Keep at least one break-glass administrator, and keep its password offline. It is the way back in when the
directory is down or misconfigured.

## Audit events

`auth.login.succeeded` (`method: ldap`), `auth.login.failed` (`method: ldap` and a `reason`),
`auth.ldap.failed` (directory unreachable or misconfigured; high severity), `user.ldap.provisioned`,
`user.membership.created` and `user.membership.changed` (`source: ldap`), `user.platform_admin.changed`,
`ldap.config.updated` (lists the changed fields, never the password) and `ldap.config.tested`.

## Troubleshooting

| Symptom | Check |
|---|---|
| Test: `tls` | The CA bundle doesn't include the directory's issuing CA, or the URL's host name isn't in the certificate. Use the name on the certificate, not an IP address. |
| Test: `config`, "rejected the service account credentials" | The service account DN or password is wrong. |
| Test: `unavailable` | Network path, port, or firewall between the gateway and the directory. |
| Sign-in: "Invalid username or password", and the audit reason is "no directory entry matches" | User search base or filter. Use **Look up user**. |
| Sign-in refused, and the audit reason is "no group mapping grants access" | No group rule matches. **Look up user** lists the groups the gateway sees. Group rules need the full DN. |
| Nested AD groups are ignored | `memberOf` lists direct groups only. Use a group search with the `1.2.840.113556.1.4.1941` matching rule. |
