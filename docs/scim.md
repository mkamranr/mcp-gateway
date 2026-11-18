# SCIM 2.0 provisioning

The identity provider pushes users and groups to the gateway over SCIM 2.0 (RFC 7643 and 7644). New starters
can sign in on day one with the right roles. When someone leaves, deactivating them in the IdP **locks them out at
once**, including sessions already open. Without SCIM, access only changes at the person's next single sign-on.

SCIM works together with [single sign-on](sso.md). SCIM decides who has an account and which groups they are in;
SSO is how they sign in. Provisioned accounts have no password.

The SCIM endpoints are exercised end to end in CI through the real nginx and gateway containers (part of the
compose smoke test, `.github/scripts/scim_check.py`).

## What it covers

| | |
|---|---|
| Base URL | `https://<gateway>/api/v1/scim/v2` |
| Authentication | `Authorization: Bearer <token>`, a token generated in the console |
| Users | create, read, list with filters, replace (PUT), PATCH, delete |
| Groups | create, read, list with filters, replace, PATCH (add, remove and replace members), delete |
| Filters | `userName`, `externalId`, `id` and `emails.value` for users; `displayName`, `externalId` and `id` for groups; `eq` only |
| Discovery | `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` |
| Not supported | bulk operations, sorting, ETags, password changes, `/Me` |

User attributes kept: `userName`, `externalId`, `displayName`, `name` (formatted, given, family), the primary
email and `active`. Other attributes (title, addresses, the enterprise extension) are accepted and ignored, so
default attribute mappings work unchanged.

## Boundaries

- **SCIM only sees accounts it created.** Local accounts, break-glass administrators, LDAP accounts and SSO
  accounts created at sign-in are invisible to it: they aren't listed, and reading, changing or deleting them
  returns 404. A SCIM user with the same `userName` as an existing account is refused with 409. A leaked SCIM
  token can't lock out the administrators who would revoke it.
- **Only provisioned users can be group members.** Other member IDs are ignored.
- **Deleting a user** disables the account, ends its sessions, removes it from every group and disables **all**
  of its tenant memberships, including ones an administrator added by hand. The record stays, so its audit
  history remains attached. If the IdP provisions the same `userName` again, the record is reused, but none of
  the previous access is: user names get recycled, and the new owner may be a different person. Memberships
  come back only through the new user's own groups (or an administrator adding them again).
- **Deactivating a user** (`active: false`) disables the account and ends its sessions at once.

## Roles: groups and group rules

Pushed groups go through the same **group rules** and **platform-administrator groups** as single sign-on
(Settings → Single sign-on). A rule matches a SCIM group if its group equals the group's **`externalId`**. For
Entra ID, the `externalId` is usually the group's object ID, so rules written for SSO `groups` claims (object
IDs) keep working.

The `displayName` is **not** matched by default. In many IdPs any user can create a group and name it as they
like, for example after the object ID of the platform-administrator group. If your IdP sends groups without an
`externalId`, turn on **Match groups without an external ID by display name** (`match_group_display_name`).
Then only groups that have no `externalId` are matched by `displayName`, so make sure that only administrators
can create groups that the IdP provisions. Changing the setting re-evaluates every provisioned user at once.

Membership changes apply as soon as the IdP pushes them. Sessions re-read memberships on every request, so
there's no need to sign in again. Renaming a group re-evaluates all of its members.

With **Roles from SCIM groups** on (the default), the ID token's groups are ignored at sign-in for provisioned
users, and the profile comes from SCIM too. Turn it off to provision accounts with SCIM but take roles from the
ID token at each sign-in, as for other SSO users.

## Linking provisioned users to their SSO identity

At a user's first SSO sign-in, the gateway looks for a provisioned account whose `externalId` equals a claim of
the ID token (**Link claim**). If exactly one matches and isn't linked yet, the IdP identity (issuer + subject) is
linked to it (`user.oidc.linked`, `source: scim`). From then on, issuer + subject decide, as for every SSO
account. Accounts are **never linked by username**. If the claim doesn't match and the username belongs to a
provisioned account, sign-in is refused (`account_conflict`).

| IdP | SCIM `externalId` | Link claim |
|---|---|---|
| Microsoft Entra ID | `objectId` (the default mapping) | `oid` |
| Okta | map `externalId` to the user ID | `sub` |
| Keycloak (SCIM extension), others | the IdP's user ID | `sub` |

## Set up

1. **Settings → Provisioning (SCIM)** (platform administrators): **Generate token**. The token is shown once; only
   an HMAC is stored. Note the base URL.
2. Check the **link claim** and the **group rules** under Single sign-on. Then turn provisioning on and save.
3. In the IdP:
   - **Entra ID:** Enterprise application → Provisioning → Automatic. Tenant URL = the base URL; Secret token =
     the token. Test connection, then assign users and groups. Entra ID provisions on a cycle (about 40 minutes)
     unless you use *Provision on demand*.
   - **Okta:** App → General → enable SCIM provisioning. SCIM connector base URL = the base URL; unique
     identifier field `userName`; supported actions *Push New Users*, *Push Profile Updates*, *Push Groups*;
     authentication mode *HTTP Header* with the token. Map `externalId` to the user ID.
   - **Others:** any SCIM 2.0 client with bearer-token authentication.
4. The gateway must be reachable from the IdP. For a cloud IdP and an air-gapped gateway, use the IdP's
   on-premises provisioning agent (Entra ID: the *provisioning agent* for on-premises apps), or don't use SCIM.

**Rotate token** creates a new token, and the old one stops working immediately: update it in the IdP straight
away. **Revoke token** also turns provisioning off.

## Security notes

- **The token is a high-value credential.** It can create accounts and, through the group rules, grant any role
  they map to, including platform administrator. Store it only in the IdP, rotate it when IdP administrators
  change, and keep the group rules narrow. Failed attempts are throttled per source address.
- **Group rules are the authorization boundary.** Whoever can change membership of a mapped group in the IdP
  controls access here, as with SSO. Groups are matched by `externalId`, which the IdP sets, not by a name a
  user can choose (see above).
- **Profile data is untrusted input.** Values are length-limited and control characters refused; nothing from
  SCIM is rendered as HTML.
- **Everything is audited** under `_system`: `user.scim.created|updated|deactivated|deleted`,
  `group.scim.created|updated|deleted`, membership changes (actor *SCIM group sync*), `user.platform_admin.changed`,
  and with high severity `scim.config.updated`, `scim.token.rotated` and `scim.token.revoked`. The token is never
  logged.

## API

| Method | Path | Who | |
|---|---|---|---|
| GET | `/api/v1/scim/config` | platform admin | `{enabled, link_claim, groups_authoritative, match_group_display_name, has_token, token_prefix, token_created_at, last_used_at, base_url}` |
| PUT | `/api/v1/scim/config` | platform admin | `{enabled, link_claim, groups_authoritative, match_group_display_name}`. Enabling needs a token. |
| POST | `/api/v1/scim/token` | platform admin | A new token, returned once as `token` |
| DELETE | `/api/v1/scim/token` | platform admin | Revoke the token and turn provisioning off |
| * | `/api/v1/scim/v2/...` | SCIM token | The SCIM protocol. Errors use SCIM's error format (`application/scim+json`). |
