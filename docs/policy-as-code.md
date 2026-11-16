# Policy as code

Policies can be kept as YAML files in git, reviewed in pull requests, and applied by CI (or by hand) instead
of being edited in the console. The gateway stays the authority: every bundle is validated by the same models
and rules as the console and API, and every change is audited.

The pieces:

- **Bundle format.** One YAML (or JSON) file holds a named set of policies.
- **API.** `export`, `plan` and `apply` under `/api/v1/policies/bundle/…`.
- **CLI.** [`deploy/policy-as-code/mgw_policy.py`](../deploy/policy-as-code/mgw_policy.py) uses only the Python
  standard library (3.9+), so it runs on any CI runner or air-gapped admin host with nothing to install.
- **Console.** The **Policies → Policy as code** tab previews and applies a bundle, and exports the live
  policies.

## The bundle format

```yaml
apiVersion: mcp-gateway/v1
kind: PolicyBundle
metadata:
  name: hr-assistants        # bundle identity: lowercase letters, digits, . _ - (max 63)
  scope: tenant              # tenant (the tenant you sign in to) | global (platform administrators)
  description: Access for the HR assistant agents.
policies:
  - name: hr-assistant-read
    description: Read-only HR lookups during business hours.
    effect: allow            # allow | deny (deny always wins)
    principals:
      types: [agent]         # agent | user | service | "*"
      ids: [agt_6f1c…]       # agent or user ids, wildcards allowed
      roles: []              # or match users by tenant role
    resources:
      servers: [hr]          # server alias, id or name; wildcards allowed
      tools: [get_attendance_summary, "get_*"]
      risk_levels: []        # optional: low | medium | high | critical
    actions: [discover, invoke]
    constraints:             # all optional
      environments: [production]
      max_calls_per_minute: 30
      require_approval: false
      time_windows: [{days: [0, 1, 2, 3, 4], start: "07:00", end: "19:00"}]   # UTC, 0 = Monday
      source_cidrs: [10.20.0.0/16]
    priority: 100
    enabled: true
    confirm_broad_grant: false   # must be true for an allow policy that uses wildcards or matches everyone
```

Each policy has exactly the fields of the console's JSON editor; see the policy document in the
[API reference](api-reference.md#policies). Unknown fields are rejected, so a typo like `efect:` fails
validation instead of being ignored. A complete example is in
[`deploy/policy-as-code/example.policies.yaml`](../deploy/policy-as-code/example.policies.yaml).

Wildcard grants have to be acknowledged **in the file** with `confirm_broad_grant: true`. That keeps the
acknowledgement visible to whoever reviews the pull request.

## How plan and apply work

**Matching.** Bundle entries are matched to live policies by name (case-insensitive) within the bundle's scope:
the current tenant, or global.

**Ownership.** A policy created or updated by a bundle is *owned* by it, and the console shows the bundle name as
a badge. Ownership controls what a bundle may touch:

| Live policy | In the file | Plan shows | Apply does |
|---|---|---|---|
| none | yes | `create` | creates it, owned by the bundle |
| owned by this bundle | yes, different | `update` with a field diff | updates it |
| owned by this bundle | yes, same | `unchanged` | nothing |
| hand-made (no owner) | yes | `adopt` | updates it and takes ownership |
| owned by **another** bundle | yes | error `OWNED_BY_OTHER_BUNDLE` | refuses the whole bundle |
| owned by this bundle | no | `orphan` (or `delete` with `--prune`) | nothing (or deletes it with `--prune`) |
| hand-made or another bundle's | no | not listed | never touched |

Prune never deletes hand-made policies or policies owned by another bundle. A bundle with an empty `policies:`
list and `--prune` therefore removes exactly what that bundle owns. System policies (the default deny) can't be
managed by bundles.

**Plan changes nothing.** It validates the file, computes the diff, and lists warnings for exact server, tool or
agent names that don't exist in the tenant yet. These are warnings, not errors: a policy may be committed before
its server is registered, and it simply won't match until then.

**Apply makes exactly the reviewed plan.** Plan returns a fingerprint of the precise changes it computed. Apply
recomputes the plan and refuses with `409 VERSION_CONFLICT` if the fingerprint differs. That happens when someone
edited a policy in the console, another apply ran, or the file changed since the plan. Nothing is applied in that
case: run plan again and review the new diff.

**All or nothing.** If a write fails partway through an apply, the changes already made are reverted and a
`policy.bundle.rolled_back` event (severity high) is recorded.

**Audited.** Each created, changed or deleted policy gets its usual audit event (`policy.created`,
`policy.changed`, `policy.deleted`) with `source: bundle`, the bundle name and a full snapshot, so policy history
works as usual. One `policy.bundle.applied` event records the bundle, fingerprint and summary. Exports are audited
as `policy.bundle.exported`.

## Hand edits of managed policies

Editing, enabling, disabling or deleting a bundle-owned policy in the console or through the API is refused with
`409 POLICY_MANAGED_BY_CODE`, unless the request confirms the override (`confirm_managed_override`). The console
asks for that confirmation explicitly. Overrides are allowed so that an operator can disable a policy during an
incident without waiting for a pull request. They are recorded with `managed_override: true` in the audit event,
and the next plan shows the override as drift, which the next apply reverts.

Cloning a managed policy produces an ordinary hand-made copy.

## Who can do what

| Action | Roles |
|---|---|
| Plan / validate | developer, auditor, security admin, tenant admin, platform admin |
| Export | auditor, security admin, tenant admin, platform admin |
| Apply | security admin, tenant admin, platform admin |
| Global bundles (`scope: global`) | platform admin only |

Bundles are tenant-isolated like everything else: a tenant bundle can only see, adopt or prune policies of the
tenant it is applied to.

## The CLI

```sh
export MGW_URL=https://gateway.example.internal
export MGW_USERNAME=policy-ci            # a local account (see below)
export MGW_PASSWORD=…                    # read from the environment only, never from a flag
export MGW_TENANT=ten_…                  # optional: tenant to act in
export MGW_CA_FILE=/etc/ssl/internal-ca.pem   # optional: internal CA

python3 mgw_policy.py export -o policies.yaml --bundle hr-assistants   # start from what is live
python3 mgw_policy.py validate policies.yaml
python3 mgw_policy.py plan policies.yaml --out plan.json
python3 mgw_policy.py apply policies.yaml --plan plan.json             # apply exactly that plan
python3 mgw_policy.py apply policies.yaml --prune --auto-approve       # plan + apply in one go (CI)
```

Example plan output:

```
Bundle 'hr-assistants' (tenant ten_0a70f6cb35c0e16dd17f1e48)
  ~ hr-assistant-read
      constraints.max_calls_per_minute: 30 -> 10
  + hr-assistant-email
  ? old-policy  (owned by this bundle but not in the file; use --prune to delete)
Plan: 1 to create, 1 to change (0 adopted), 0 to delete, 1 unchanged, 1 orphaned
Fingerprint: 563c57a3…
```

| Exit code | Meaning |
|---|---|
| 0 | success (`plan --detailed-exitcode`: valid, no changes) |
| 1 | invalid bundle, sign-in failure, missing permission, or apply cancelled |
| 2 | `plan --detailed-exitcode` only: valid, and there are changes |
| 3 | apply refused because live policies changed since the plan |

Without `--auto-approve` or `--plan`, apply asks for confirmation, and refuses when there is no terminal to ask
on. A pipeline can't apply by accident.

**The account.** The CLI signs in with a username and password, so it needs a **local** account: SSO accounts
can't sign in non-interactively. Create a dedicated user per purpose, and give it only the role it needs:

- `developer` for a pull-request job that only runs `plan`.
- `security_admin` for the job that applies.

If single sign-on is set to *break-glass only*, local sign-in is limited to the break-glass list; add the
apply account there only if you accept that, and keep its password in your CI secret store. Failed sign-ins count
towards the login rate limit; successful ones don't, so frequent pipeline runs don't lock the account.

Use `https://`. The CLI warns when a non-local URL is plain `http://`. It doesn't follow redirects, so the session
can't be carried to another host.

## CI example (GitHub Actions)

The pattern: plan on every pull request and post the diff for review; apply on merge, in a protected
environment.

```yaml
name: policies
on:
  pull_request: {paths: ["policies/**"]}
  push: {branches: [main], paths: ["policies/**"]}
jobs:
  plan:
    if: github.event_name == 'pull_request'
    runs-on: [self-hosted, gateway-network]        # a runner that can reach the gateway
    steps:
      - uses: actions/checkout@v4
      - name: Plan
        env:
          MGW_URL: ${{ vars.MGW_URL }}
          MGW_USERNAME: ${{ vars.MGW_PLAN_USERNAME }}   # developer role
          MGW_PASSWORD: ${{ secrets.MGW_PLAN_PASSWORD }}
        run: |
          for f in policies/*.yaml; do
            python3 deploy/policy-as-code/mgw_policy.py plan "$f" --prune | tee -a "$GITHUB_STEP_SUMMARY"
          done
  apply:
    if: github.event_name == 'push'
    runs-on: [self-hosted, gateway-network]
    environment: production-policies                # require reviewers on this environment
    steps:
      - uses: actions/checkout@v4
      - name: Apply
        env:
          MGW_URL: ${{ vars.MGW_URL }}
          MGW_USERNAME: ${{ vars.MGW_APPLY_USERNAME }}  # security_admin role
          MGW_PASSWORD: ${{ secrets.MGW_APPLY_PASSWORD }}
        run: |
          for f in policies/*.yaml; do
            python3 deploy/policy-as-code/mgw_policy.py apply "$f" --prune --auto-approve
          done
```

The same steps work in GitLab CI, Jenkins or Azure Pipelines: they only need Python 3 and network access to the
gateway.

For the strictest flow, save the plan from the reviewed pull request (`plan --out plan.json`) as an artifact, and
apply that file with `apply --plan plan.json`. If anything changed between review and merge, apply exits with 3
instead of applying something nobody reviewed.

## Adopting policy as code on an existing tenant

1. `mgw_policy.py export --bundle <name> -o policies/<name>.yaml` writes every hand-made policy into a bundle.
   Wildcard policies are exported with `confirm_broad_grant: true`.
2. Commit it, then run `plan`. Every policy shows as `adopt` with no field changes.
3. `apply` takes ownership. From then on, `plan` shows `unchanged` until someone edits the file, and console
   edits of these policies need an explicit override.

Several teams can manage separate bundles in one tenant. Each bundle owns only its own policies, and a name
already owned by another bundle is reported as an error rather than taken over.

## API

| Method | Path | Body / query | Returns |
|---|---|---|---|
| GET | `/api/v1/policies/bundle/export` | `?bundle=<name>&scope=tenant\|global&include=all\|bundle` | YAML (`application/yaml`) |
| POST | `/api/v1/policies/bundle/plan` | `{"content": "<yaml>"}`, `?prune=true` | plan: `valid`, `errors`, `warnings`, `summary`, `changes[]` with `diff`, `fingerprint` |
| POST | `/api/v1/policies/bundle/apply` | `{"content", "expected_fingerprint", "prune"}` | the applied plan, `applied: true` |

Bundles are limited to 1 MB and 1,000 policies. YAML is parsed with a safe loader: tags that construct objects
are rejected.
