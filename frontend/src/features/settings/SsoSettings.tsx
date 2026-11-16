import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, Copy, Loader2, Plus, PlugZap, Save, Trash2 } from 'lucide-react'
import { api, ApiError, errorMessage } from '../../services/api'
import { dateTime, ROLE_LABELS, TENANT_ROLES } from '../../services/format'
import type { Page, SsoConfig, SsoGroupRule, SsoTestResult, Tenant } from '../../services/types'
import { Badge, Callout, Field, ListInput, Panel, QueryState, Switch, useToast } from '../../components/ui'

const ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA']
type Form = Omit<SsoConfig, 'has_client_secret' | 'redirect_uri' | 'updated_at' | 'updated_by'>

export function SsoSettings() {
  const q = useQuery({ queryKey: ['sso-config'], queryFn: () => api.get<SsoConfig>('/sso/config') })
  return <QueryState q={q}>{d => <SsoForm cfg={d} />}</QueryState>
}

function SsoForm({ cfg }: { cfg: SsoConfig }) {
  const { has_client_secret, redirect_uri, updated_at, updated_by: _updatedBy, ...initial } = cfg
  const [f, setF] = useState<Form>(initial)
  const [secret, setSecret] = useState('')
  const [err, setErr] = useState<ApiError | null>(null)
  const [test, setTest] = useState<SsoTestResult | null>(null)
  useEffect(() => { setF(initial) }, [cfg]) // eslint-disable-line react-hooks/exhaustive-deps
  const qc = useQueryClient()
  const toast = useToast()
  const tenants = useQuery({ queryKey: ['tenants'], queryFn: () => api.get<Page<Tenant>>('/tenants', { limit: 200 }) })
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setF(x => ({ ...x, [k]: v }))

  const save = useMutation({
    mutationFn: () => api.put<SsoConfig>('/sso/config', { ...f, ...(secret ? { client_secret: secret } : {}) }),
    onSuccess: () => { setErr(null); setSecret(''); qc.invalidateQueries({ queryKey: ['sso-config'] }); qc.invalidateQueries({ queryKey: ['sso-public'] }); toast.ok('Single sign-on settings saved') },
    onError: e => e instanceof ApiError ? setErr(e) : toast.error(e),
  })
  const check = useMutation({
    mutationFn: () => api.post<SsoTestResult>('/sso/test'),
    onSuccess: r => setTest(r), onError: e => toast.error(e),
  })
  const rule = (i: number, patch: Partial<SsoGroupRule>) => set('group_rules', f.group_rules.map((r, j) => j === i ? { ...r, ...patch } : r))
  const tenantList = tenants.data?.items || []
  const restricting = f.local_login === 'break_glass_only'

  return <>
    <Panel title="Identity provider" subtitle="One OpenID Connect provider for the whole platform. Authorization code flow with PKCE."
      actions={<div className="toggle-row" style={{ border: 0, padding: 0 }}><span>{f.enabled ? <Badge color="green">enabled</Badge> : <Badge>disabled</Badge>}</span><Switch on={f.enabled} onChange={v => set('enabled', v)} label="SSO enabled" /></div>}>
      {err && <Callout kind="danger">{errorMessage(err)}</Callout>}
      <Field label="Redirect URI (register this at your IdP)">
        <div className="secret-box"><span className="mono" style={{ flex: 1, userSelect: 'all' }}>{redirect_uri}</span>
          <button type="button" className="small-btn" onClick={() => navigator.clipboard?.writeText(redirect_uri).then(() => toast.ok('Copied'), () => {})}><Copy size={10} /></button></div>
      </Field>
      <div className="field-row">
        <Field label="Issuer URL" hint="Exactly the issuer value from the IdP's discovery document (Keycloak: .../realms/<realm>)"><input value={f.issuer} onChange={e => set('issuer', e.target.value)} placeholder="https://" /></Field>
        <Field label="Button label"><input value={f.display_name} onChange={e => set('display_name', e.target.value)} /></Field>
      </div>
      <div className="field-row">
        <Field label="Client ID"><input value={f.client_id} onChange={e => set('client_id', e.target.value)} /></Field>
        <Field label="Client secret" hint={has_client_secret ? 'Stored (encrypted). Leave blank to keep it.' : 'Not set. Leave blank for a public client (PKCE only).'}>
          <input type="password" autoComplete="new-password" value={secret} onChange={e => setSecret(e.target.value)} placeholder={has_client_secret ? '••••••••' : ''} /></Field>
        <Field label="Client authentication"><select value={f.token_auth_method} onChange={e => set('token_auth_method', e.target.value as Form['token_auth_method'])}><option value="client_secret_basic">client_secret_basic</option><option value="client_secret_post">client_secret_post</option></select></Field>
      </div>
      <Field label="Scopes"><ListInput value={f.scopes} onChange={v => set('scopes', v)} placeholder="openid, profile, email, groups" /></Field>
      <div className="field"><span>Accepted ID-token signing algorithms (asymmetric only)</span><div className="chips">{ALGORITHMS.map(a => <label className="check" key={a}>
        <input type="checkbox" checked={f.allowed_algorithms.includes(a)} onChange={e => set('allowed_algorithms', e.target.checked ? [...f.allowed_algorithms, a] : f.allowed_algorithms.filter(x => x !== a))} />{a}</label>)}</div></div>
      <div className="form-actions">
        <button type="button" className="btn secondary" disabled={check.isPending || !cfg.issuer} title={!cfg.issuer ? 'Save an issuer first' : ''} onClick={() => check.mutate()}>{check.isPending ? <Loader2 size={13} className="spin" /> : <PlugZap size={13} />}Test connection</button>
        <span className="muted" style={{ fontSize: 10, alignSelf: 'center' }}>Tests the saved configuration.</span>
      </div>
      {test && (test.ok
        ? <Callout kind="ok"><b>Discovery and signing keys OK.</b> {test.signing_keys} key(s). Token endpoint {test.token_endpoint}.
            {test.algorithm_overlap && test.algorithm_overlap.length === 0 && <div><b>Warning:</b> none of the IdP's algorithms ({test.signing_algorithms?.join(', ')}) are accepted here.</div>}</Callout>
        : <Callout kind="danger"><b>{test.error}</b>: {test.detail}</Callout>)}
    </Panel>

    <Panel title="Claims" subtitle="Which ID-token claims identify the user. Accounts are keyed on issuer + subject, never on the username.">
      <div className="field-row">
        <Field label="Username"><input value={f.username_claim} onChange={e => set('username_claim', e.target.value)} /></Field>
        <Field label="Email"><input value={f.email_claim} onChange={e => set('email_claim', e.target.value)} /></Field>
        <Field label="Display name"><input value={f.name_claim} onChange={e => set('name_claim', e.target.value)} /></Field>
        <Field label="Groups" hint="Falls back to the userinfo endpoint if absent from the ID token."><input value={f.groups_claim} onChange={e => set('groups_claim', e.target.value)} /></Field>
      </div>
    </Panel>

    <Panel title="Group rules" subtitle="Members of an IdP group get these roles in the tenant. Re-applied at every SSO sign-in: removing someone from the group removes their access."
      actions={<button type="button" className="btn secondary" onClick={() => set('group_rules', [...f.group_rules, { group: '', tenant_id: tenantList[0]?.id || '', roles: ['developer'] }])}><Plus size={13} />Add rule</button>}>
      {f.group_rules.length === 0 && <p className="muted" style={{ fontSize: 10 }}>No rules. SSO users will have no access unless they are platform administrators.</p>}
      {f.group_rules.map((r, i) => <div className="rule-row" key={i}>
        <input placeholder="IdP group (name or id)" value={r.group} onChange={e => rule(i, { group: e.target.value })} />
        <select value={r.tenant_id} onChange={e => rule(i, { tenant_id: e.target.value })}>{!tenantList.some(t => t.id === r.tenant_id) && <option value={r.tenant_id}>{r.tenant_id || 'Select tenant'}</option>}{tenantList.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
        <div className="chips">{TENANT_ROLES.map(role => <label className="check" key={role}><input type="checkbox" checked={r.roles.includes(role)} onChange={e => rule(i, { roles: e.target.checked ? [...r.roles, role] : r.roles.filter(x => x !== role) })} />{ROLE_LABELS[role]}</label>)}</div>
        <button type="button" className="small-btn" aria-label="Remove rule" onClick={() => set('group_rules', f.group_rules.filter((_, j) => j !== i))}><Trash2 size={11} /></button>
      </div>)}
      <Field label="Platform administrator groups" hint="Members become platform administrators (all tenants, system settings). Keep this list short."><ListInput value={f.platform_admin_groups} onChange={v => set('platform_admin_groups', v)} placeholder="group name or id" /></Field>
    </Panel>

    <Panel title="Accounts and local sign-in">
      <div className="toggle-row"><span>Create accounts on first SSO sign-in (just-in-time)</span><Switch on={f.jit_provisioning} onChange={v => set('jit_provisioning', v)} label="JIT provisioning" /></div>
      <div className="toggle-row"><span>Link SSO identities to existing local accounts with the same username <Badge color="orange">use only during migration</Badge></span><Switch on={f.link_local_accounts} onChange={v => set('link_local_accounts', v)} label="Link local accounts" /></div>
      {f.link_local_accounts && <Callout kind="warn">Anyone who can choose their username at the IdP could take over the matching local account. Turn this off once migration is complete.</Callout>}
      <Field label="Local password sign-in"><select value={f.local_login} onChange={e => set('local_login', e.target.value as Form['local_login'])}><option value="enabled">Allowed for all local accounts</option><option value="break_glass_only">Only break-glass accounts</option></select></Field>
      {restricting && <>
        <Field label="Break-glass accounts" hint="Local platform administrators who can still sign in with a password if the IdP is unavailable."><ListInput value={f.break_glass_usernames} onChange={v => set('break_glass_usernames', v)} placeholder="username" /></Field>
        <Callout kind="warn">Every other local account loses password sign-in immediately. Each break-glass sign-in is audited with high severity.</Callout>
      </>}
      <div className="form-actions">
        <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? <Loader2 size={13} className="spin" /> : <Save size={13} />}Save</button>
        {updated_at && <span className="muted" style={{ fontSize: 10, alignSelf: 'center' }}><CheckCircle2 size={10} /> Last saved {dateTime(updated_at)}</span>}
      </div>
    </Panel>
  </>
}
