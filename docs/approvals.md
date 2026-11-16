# Approvals: delegation, approver groups and escalation

A call that needs human sign-off waits as an **approval request** until enough eligible people approve it,
someone rejects it, or it expires. This guide covers three ways to make sure the right people are always
available: **delegation**, **approver groups** and **escalation with reminders**. For the security model
(argument binding, revalidation, run-exactly-once), see [security model → human approval](security-model.md#human-approval).

## Who may decide a request

A user may decide a request when **all** of these hold:

1. **Authority.** They hold one of the request's *approver roles* (default: `approver`, `security_admin`,
   `tenant_admin`; a policy can narrow this) **and**, if the policy names *approver groups*, they belong to one
   of them. Platform administrators skip the role check but not the group check. After **escalation**, users
   with one of the *escalation roles* also qualify, with or without the groups.
2. **Separation of duties.** They are not the requester, the user an agent acts for, or the owner of the
   requesting agent (unless the policy explicitly allows self-approval).
3. **One vote per person.** They have not already approved this request. With two-person approval, the two
   approvals must come from two different people.

The authority in step 1 can be their own or **delegated** to them, as described below.

## Delegation

An approver going on leave delegates their approval authority to a colleague for a fixed period, under
**Approvals → Delegations → Delegate approvals**. Administrators (`security_admin`, `tenant_admin`, platform
admin) can also set up cover for an approver who is already away.

| Rule | Why |
|---|---|
| The delegate needs no approver role of their own. | Cover is often a team-mate in another role. |
| The delegate acts with the delegator's **current** roles and groups. | A delegator who loses the approver role, is disabled or leaves the tenant passes nothing on, immediately. |
| Separation of duties applies to **both** people. | A delegate can't approve the delegator's own agent's request, and a requester can't approve through someone else's delegation. |
| One person's authority counts once. | If Alice approved, her delegate can't add a second approval in her name under a two-person rule, and the other way round. |
| Delegations don't chain. | Only authority delegated directly to a user counts. Someone covering for Alice can't delegate to a third person. |
| At most 90 days, at most 10 current delegations per approver. | Long-lived delegations are role assignments in disguise. |
| A user decides with their own authority first, then with a delegation. | The record shows the most direct authority used. |

Every decision made under delegation records both people: the approval shows *"Approved by Sam Patel on
behalf of Dana Reyes"*, and the `approval.approved` / `approval.rejected` audit events carry
`metadata.on_behalf_of` and `metadata.delegation_id`. Creating and revoking delegations is audited as
`approval.delegation.created` and `approval.delegation.revoked`. The delegator, the delegate, whoever created
it, or an administrator can revoke a delegation at any time. Decisions already made stay valid.

API: `GET /api/v1/approvals/delegations` (`?scope=all` for administrators, `&include_past=true`),
`POST /api/v1/approvals/delegations`, `DELETE /api/v1/approvals/delegations/{id}`.

```json
POST /api/v1/approvals/delegations
{"delegate_user_id": "usr_…", "starts_at": "2026-12-01T08:00:00Z", "ends_at": "2026-12-15T18:00:00Z",
 "reason": "Annual leave"}
```

## Approver groups (SSO)

A policy can require that approvers belong to one of a list of identity-provider groups, for example so that
only the HR approvers group signs off payroll emails, whatever other roles people hold:

```yaml
constraints:
  require_approval: true
  approver_roles: [approver]
  approver_groups: [hr-approvers]
```

Groups are the user's groups at their **last SSO sign-in** (the same `groups` claim used for
[SSO role mapping](sso.md)). Removal from a group takes effect at the next sign-in. Local accounts have no
groups, so they can't approve group-restricted requests unless escalation opens the request to their role.
When several policies require approval for the same call, their groups narrow each other, as roles do.

## Escalation and reminders

```yaml
constraints:
  require_approval: true
  escalate_after_minutes: 30             # still pending after 30 min:
  escalation_roles: [security_admin]     #   security admins may decide too
  remind_before_expiry_minutes: 15       # raise approval.expiring 15 min before expiry
```

- **Escalation.** When a request is still pending after `escalate_after_minutes`, the worker marks it
  escalated and raises an `approval.escalated` audit event. From then on, users with one of the
  `escalation_roles` may decide it as well (separation of duties still applies). Without escalation roles,
  escalation only raises the event. The console shows an *escalated* badge.
- **Reminders.** `remind_before_expiry_minutes` before a pending request expires, the worker raises one
  `approval.expiring` event per request.

Both events go through [SIEM forwarding](siem.md), so your SIEM or paging tool turns them into alerts. A
Splunk example:

```
index=mcp_gateway event_type IN ("approval.escalated", "approval.expiring")
| table _time tenant_id approval_id resource.tool_name metadata.approvals metadata.required metadata.expires_at
```

Each request is escalated and reminded at most once, even with several worker replicas: each step is
claimed with a compare-and-set. When several policies apply, the earliest escalation, all escalation roles
and the earliest reminder win. Values set on the tool's own approval configuration combine the same way.
Escalation or reminder points that would fall after expiry are skipped.
