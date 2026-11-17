import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, Loader2, Plus, PlugZap, Save, Search, Trash2 } from 'lucide-react'
import { api, ApiError, errorMessage } from '../../services/api'
import { dateTime, ROLE_LABELS, TENANT_ROLES } from '../../services/format'
import type { LdapConfig, LdapTestResult, Page, SsoGroupRule, Tenant } from '../../services/types'
import { Badge, Callout, Field, ListInput, Panel, QueryState, Switch, useToast } from '../../components/ui'

type Form = Omit<LdapConfig, 'has_bind_password' | 'updated_at' | 'updated_by'>

const PRESETS: Record<'openldap' | 'ad', Partial<Form>> = {
  openldap: {
    user_filter: '(&(objectClass=person)(uid={username}))', username_attribute: 'uid', unique_id_attribute: 'entryUUID',
    name_attribute: 'displayName', group_membership_attribute: 'memberOf', group_search_filter: '(|(member={user_dn})(uniqueMember={user_dn}))',
  },
  ad: {
    user_filter: '(&(objectClass=user)(sAMAccountName={username})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
    username_attribute: 'sAMAccountName', unique_id_attribute: 'objectGUID', name_attribute: 'displayName',
    group_membership_attribute: 'memberOf', group_search_filter: '(member:1.2.840.113556.1.4.1941:={user_dn})',
  },
}

export function LdapSettings() {
  const q = useQuery({ queryKey: ['ldap-config'], queryFn: () => api.get<LdapConfig>('/ldap/config') })
  return <QueryState q={q}>{d => <LdapForm cfg={d} />}</QueryState>
}

function LdapForm({ cfg }: { cfg: LdapConfig }) {
  const { has_bind_password, updated_at, updated_by: _updatedBy, ...initial } = cfg
  const [f, setF] = useState<Form>(initial)
  const [password, setPassword] = useState('')
  const [err, setErr] = useState<ApiError | null>(null)
  const [lookup, setLookup] = useState('')
  const [test, setTest] = useState<LdapTestResult | null>(null)
  useEffect(() => { setF(initial) }, [cfg]) // eslint-disable-line react-hooks/exhaustive-deps
  const qc = useQueryClient()
  const toast = useToast()
  const tenants = useQuery({ queryKey: ['tenants'], queryFn: () => api.get<Page<Tenant>>('/tenants', { limit: 200 }) })
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setF(x => ({ ...x, [k]: v }))

  const save = useMutation({
    mutationFn: () => api.put<LdapConfig>('/ldap/config', { ...f, ...(password ? { bind_password: password } : {}) }),
    onSuccess: () => { setErr(null); setPassword(''); qc.invalidateQueries({ queryKey: ['ldap-config'] }); qc.invalidateQueries({ queryKey: ['ldap-public'] }); toast.ok('Directory settings saved') },
    onError: e => e instanceof ApiError ? setErr(e) : toast.error(e),
  })
  const check = useMutation({
    mutationFn: (username?: string) => api.post<LdapTestResult>('/ldap/test', username ? { username } : undefined),
    onSuccess: r => setTest(r), onError: e => toast.error(e),
  })
  const rule = (i: number, patch: Partial<SsoGroupRule>) => set('group_rules', f.group_rules.map((r, j) => j === i ? { ...r, ...patch } : r))
  const tenantList = tenants.data?.items || []
  const tenantName = (id: string) => tenantList.find(t => t.id === id)?.name || id
  const saved = cfg.server_urls.length > 0 && !!cfg.user_search_base
  const clearText = !f.start_tls && f.server_urls.some(u => u.startsWith('ldap://'))

  return <>
    <Panel title="Directory" subtitle="One LDAP directory or Active Directory domain for the whole platform. Users sign in on the normal form with their directory username and password."
      actions={<div className="toggle-row" style={{ border: 0, padding: 0 }}><span>{f.enabled ? <Badge color="green">enabled</Badge> : <Badge>disabled</Badge>}</span><Switch on={f.enabled} onChange={v => set('enabled', v)} label="Directory sign-in enabled" /></div>}>
      {err && <Callout kind="danger">{errorMessage(err)}</Callout>}
      <div className="form-actions" style={{ marginTop: 0 }}>
        <span className="muted" style={{ fontSize: 10, alignSelf: 'center' }}>Fill in defaults for</span>
        <button type="button" className="small-btn" onClick={() => setF(x => ({ ...x, ...PRESETS.ad }))}>Active Directory</button>
        <button type="button" className="small-btn" onClick={() => setF(x => ({ ...x, ...PRESETS.openldap }))}>OpenLDAP</button>
      </div>
      <Field label="Server URLs" hint="Tried in order; the next one is used only if a server can't be reached. ldaps://dc1.corp.example:636 or ldap://… with StartTLS.">
        <ListInput value={f.server_urls} onChange={v => set('server_urls', v)} placeholder="ldaps://dc1.corp.example" /></Field>
      <div className="toggle-row"><span>Use StartTLS (for ldap:// URLs)</span><Switch on={f.start_tls} onChange={v => set('start_tls', v)} label="StartTLS" /></div>
      {clearText && <Callout kind="danger">Passwords would cross the network in clear text. Use ldaps:// or turn on StartTLS.</Callout>}
      <Field label="CA certificates (PEM)" hint="For a directory certificate from an internal CA. Leave empty to use the system's trusted CAs. The host name is always verified.">
        <textarea className="mono" rows={4} value={f.ca_pem} onChange={e => set('ca_pem', e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" /></Field>
      <div className="field-row">
        <Field label="Service account DN" hint="Read-only account used to find users and groups."><input value={f.bind_dn} onChange={e => set('bind_dn', e.target.value)} placeholder="CN=svc-mcp-gateway,OU=Service,DC=corp,DC=example" /></Field>
        <Field label="Service account password" hint={has_bind_password ? 'Stored (encrypted). Leave blank to keep it.' : 'Not set.'}>
          <input type="password" autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} placeholder={has_bind_password ? '••••••••' : ''} /></Field>
      </div>
      <div className="field-row">
        <Field label="Login hint on the sign-in page"><input value={f.display_name} onChange={e => set('display_name', e.target.value)} /></Field>
        <Field label="Timeout (seconds)"><input type="number" min={1} max={30} value={f.timeout_seconds} onChange={e => set('timeout_seconds', Number(e.target.value))} /></Field>
      </div>
      <div className="form-actions">
        <button type="button" className="btn secondary" disabled={check.isPending || !saved} title={!saved ? 'Save a server and user search base first' : ''} onClick={() => check.mutate(undefined)}>{check.isPending ? <Loader2 size={13} className="spin" /> : <PlugZap size={13} />}Test connection</button>
        <label className="field" style={{ margin: 0, width: 190 }}><input placeholder="username (optional)" value={lookup} onChange={e => setLookup(e.target.value)} aria-label="Username to look up" /></label>
        <button type="button" className="btn secondary" disabled={check.isPending || !saved || !lookup.trim()} onClick={() => check.mutate(lookup.trim())}><Search size={13} />Look up user</button>
      </div>
      <p className="muted" style={{ fontSize: 10 }}>Tests the saved configuration. Looking up a user shows their groups and the access the rules grant; no password is needed.</p>
      {test && (test.ok
        ? <Callout kind="ok"><b>Connected</b>{test.server && <> to {test.server}</>}. The service account can read the user search base.
            {test.user === null && <div>{test.detail}</div>}
            {test.user && <div style={{ marginTop: 6 }}>
              <div className="mono" style={{ fontSize: 10 }}>{test.user.dn}</div>
              <div>{test.user.display_name || test.user.username}{test.user.email ? ` · ${test.user.email}` : ''}</div>
              <div><b>Access:</b> {test.user.platform_admin && <Badge color="red">platform admin</Badge>} {Object.keys(test.user.grants).length === 0 && !test.user.platform_admin ? 'none (no group rule matches)' : Object.entries(test.user.grants).map(([t, r]) => `${tenantName(t)}: ${r.map(x => ROLE_LABELS[x] || x).join(', ')}`).join(' · ')}</div>
              <div className="muted" style={{ fontSize: 10 }}>{test.user.groups.length} group(s): {test.user.groups.slice(0, 12).join(' · ')}{test.user.groups.length > 12 ? ' …' : ''}</div>
            </div>}</Callout>
        : <Callout kind="danger"><b>{test.error}</b>: {test.detail}</Callout>)}
    </Panel>

    <Panel title="Users" subtitle="How a username is found. {username} is escaped before it is used. Accounts are keyed on the unique ID attribute, never on the username.">
      <Field label="User search base"><input value={f.user_search_base} onChange={e => set('user_search_base', e.target.value)} placeholder="OU=Staff,DC=corp,DC=example" /></Field>
      <Field label="User filter"><input className="mono" value={f.user_filter} onChange={e => set('user_filter', e.target.value)} /></Field>
      <div className="field-row">
        <Field label="Username attribute"><input value={f.username_attribute} onChange={e => set('username_attribute', e.target.value)} /></Field>
        <Field label="Unique ID attribute" hint="objectGUID (AD), entryUUID (OpenLDAP)"><input value={f.unique_id_attribute} onChange={e => set('unique_id_attribute', e.target.value)} /></Field>
        <Field label="Email attribute"><input value={f.email_attribute} onChange={e => set('email_attribute', e.target.value)} /></Field>
        <Field label="Display name attribute"><input value={f.name_attribute} onChange={e => set('name_attribute', e.target.value)} /></Field>
      </div>
    </Panel>

    <Panel title="Groups" subtitle="Groups come from the user's membership attribute, a group search, or both. Groups are identified by their full DN.">
      <div className="field-row">
        <Field label="Membership attribute on the user" hint="memberOf; empty to skip"><input value={f.group_membership_attribute} onChange={e => set('group_membership_attribute', e.target.value)} /></Field>
        <Field label="Group search base" hint="Empty: no group search"><input value={f.group_search_base} onChange={e => set('group_search_base', e.target.value)} placeholder="OU=Groups,DC=corp,DC=example" /></Field>
      </div>
      <Field label="Group search filter" hint="{user_dn} and {username} are escaped. For nested AD groups use (member:1.2.840.113556.1.4.1941:={user_dn})."><input className="mono" value={f.group_search_filter} onChange={e => set('group_search_filter', e.target.value)} /></Field>
    </Panel>

    <Panel title="Group rules" subtitle="Members of a directory group get these roles in the tenant. Re-applied at every directory sign-in: removing someone from the group removes their access."
      actions={<button type="button" className="btn secondary" onClick={() => set('group_rules', [...f.group_rules, { group: '', tenant_id: tenantList[0]?.id || '', roles: ['developer'] }])}><Plus size={13} />Add rule</button>}>
      {f.group_rules.length === 0 && <p className="muted" style={{ fontSize: 10 }}>No rules. Directory users will have no access unless they are platform administrators.</p>}
      {f.group_rules.map((r, i) => <div className="rule-row" key={i}>
        <input placeholder="CN=MCP Developers,OU=Groups,DC=corp,DC=example" value={r.group} onChange={e => rule(i, { group: e.target.value })} />
        <select value={r.tenant_id} onChange={e => rule(i, { tenant_id: e.target.value })}>{!tenantList.some(t => t.id === r.tenant_id) && <option value={r.tenant_id}>{r.tenant_id || 'Select tenant'}</option>}{tenantList.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
        <div className="chips">{TENANT_ROLES.map(role => <label className="check" key={role}><input type="checkbox" checked={r.roles.includes(role)} onChange={e => rule(i, { roles: e.target.checked ? [...r.roles, role] : r.roles.filter(x => x !== role) })} />{ROLE_LABELS[role]}</label>)}</div>
        <button type="button" className="small-btn" aria-label="Remove rule" onClick={() => set('group_rules', f.group_rules.filter((_, j) => j !== i))}><Trash2 size={11} /></button>
      </div>)}
      <Field label="Platform administrator groups" hint="Full DNs. Members become platform administrators (all tenants, system settings). Keep this list short."><ListInput value={f.platform_admin_groups} onChange={v => set('platform_admin_groups', v)} placeholder="CN=MCP Platform Admins,OU=Groups,DC=corp,DC=example" /></Field>
    </Panel>

    <Panel title="Accounts and local sign-in" subtitle="Local accounts always sign in with their local password, so a directory user can never take over a local account by sharing its username.">
      <div className="toggle-row"><span>Create accounts on first directory sign-in (just-in-time)</span><Switch on={f.jit_provisioning} onChange={v => set('jit_provisioning', v)} label="JIT provisioning" /></div>
      <Field label="Local password sign-in"><select value={f.local_login} onChange={e => set('local_login', e.target.value as Form['local_login'])}><option value="enabled">Allowed for all local accounts</option><option value="break_glass_only">Only break-glass accounts</option></select></Field>
      {f.local_login === 'break_glass_only' && <>
        <Field label="Break-glass accounts" hint="Local platform administrators who can still sign in with a password if the directory is unavailable."><ListInput value={f.break_glass_usernames} onChange={v => set('break_glass_usernames', v)} placeholder="username" /></Field>
        <Callout kind="warn">Every other local account loses password sign-in immediately. Each break-glass sign-in is audited with high severity.</Callout>
      </>}
      <div className="form-actions">
        <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? <Loader2 size={13} className="spin" /> : <Save size={13} />}Save</button>
        {updated_at && <span className="muted" style={{ fontSize: 10, alignSelf: 'center' }}><CheckCircle2 size={10} /> Last saved {dateTime(updated_at)}</span>}
      </div>
    </Panel>
  </>
}
