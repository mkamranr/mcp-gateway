import { Fragment, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, Loader2, Save } from 'lucide-react'
import { useAuth } from '../../app/auth'
import { api } from '../../services/api'
import { cn, timeAgo } from '../../services/format'
import type { HealthComponent } from '../../services/types'
import { Badge, Callout, Field, JsonView, PageHeading, Panel, QueryState, Status, useToast } from '../../components/ui'
import { SiemSettings } from './SiemSettings'
import { LdapSettings } from './LdapSettings'
import { SsoSettings } from './SsoSettings'

interface SettingsResp {
  system: {
    version: string; environment: string; mcp_endpoint: string; public_base_url: string | null
    session: { ttl_minutes: number; idle_minutes: number; cookie_secure: boolean }
    security: { default_deny: boolean; audit_required_for_execution: boolean; allow_private_upstream_networks: boolean }
    payload_limits: Record<string, number>
    network: { upstream_host_allowlist: string[]; stdio_executable_allowlist: string[]; cors_allowed_origins: string[] }
    audit: { retention_days: number; export_max_rows: number }
  }
  stored: Record<string, any>; tenant: Record<string, any>; health: HealthComponent[]; editable: boolean
}

type Section = 'general' | 'security' | 'sso' | 'ldap' | 'siem' | 'limits' | 'network' | 'account' | 'health'
const SECTIONS: { value: Section; label: string }[] = [
  { value: 'general', label: 'General & MCP endpoint' }, { value: 'security', label: 'Security' }, { value: 'sso', label: 'Single sign-on' }, { value: 'ldap', label: 'LDAP / Active Directory' }, { value: 'siem', label: 'SIEM forwarding' }, { value: 'limits', label: 'Payload & global limits' },
  { value: 'network', label: 'Network allowlists' }, { value: 'account', label: 'My account' }, { value: 'health', label: 'System health' },
]

export function SettingsPage() {
  const [section, setSection] = useState<Section>('general')
  const { me } = useAuth()
  const sections = SECTIONS.filter(s => !['sso', 'ldap', 'siem'].includes(s.value) || me?.is_platform_admin)
  const q = useQuery({ queryKey: ['settings'], queryFn: () => api.get<SettingsResp>('/settings') })
  return (
    <>
      <PageHeading eyebrow="ADMINISTRATION" title="Settings" subtitle="Platform configuration. Values set from environment variables are read-only here." />
      <div className="settings-layout">
        <div className="settings-tabs">{sections.map(s => <button key={s.value} className={cn(section === s.value && 'selected')} onClick={() => setSection(s.value)}>{s.label}</button>)}</div>
        <div className="settings-form" style={{ maxWidth: 820 }}>
          {section === 'account' ? <Account /> : section === 'sso' ? <SsoSettings /> : section === 'ldap' ? <LdapSettings /> : section === 'siem' ? <SiemSettings /> : <QueryState q={q}>{d => <SettingsSection section={section} d={d} />}</QueryState>}
        </div>
      </div>
    </>
  )
}

function SettingsSection({ section, d }: { section: Section; d: SettingsResp }) {
  const s = d.system
  const toast = useToast()
  const mcpUrl = (s.public_base_url || window.location.origin).replace(/\/$/, '') + s.mcp_endpoint
  if (section === 'general') return <Panel title="General">
    <dl className="kv">
      <dt>Version</dt><dd>{s.version}</dd>
      <dt>Environment</dt><dd><Badge color={s.environment === 'production' ? 'green' : 'orange'}>{s.environment}</Badge></dd>
      <dt>MCP endpoint</dt><dd className="mono">{mcpUrl} <button className="small-btn" onClick={() => navigator.clipboard?.writeText(mcpUrl).then(() => toast.ok('Copied'), () => {})}><Copy size={10} /></button></dd>
      <dt>Session lifetime</dt><dd>{s.session.ttl_minutes} min (idle timeout {s.session.idle_minutes} min)</dd>
      <dt>Secure cookies</dt><dd>{s.session.cookie_secure ? 'Yes' : <Badge color="orange">No (development only)</Badge>}</dd>
      <dt>Audit retention</dt><dd>{s.audit.retention_days} days · export max {s.audit.export_max_rows.toLocaleString()} rows</dd>
    </dl>
    <div className="section-title">MCP client configuration</div>
    <JsonView value={{ mcpServers: { 'mcp-gateway': { type: 'streamable-http', url: mcpUrl, headers: { Authorization: 'Bearer <agent key>' } } } }} />
  </Panel>

  if (section === 'security') return <Panel title="Security posture">
    <div className="toggle-row"><span>Default deny</span><Badge color="green">always on</Badge></div>
    <div className="toggle-row"><span>Block sensitive execution when audit storage is unavailable</span>{s.security.audit_required_for_execution ? <Badge color="green">on</Badge> : <Badge color="red">off</Badge>}</div>
    <div className="toggle-row"><span>Allow private upstream networks (platform default)</span>{s.security.allow_private_upstream_networks ? <Badge color="orange">allowed</Badge> : <Badge color="green">blocked</Badge>}</div>
    <div className="toggle-row"><span>Critical tools require approval (this tenant)</span>{d.tenant.critical_requires_approval !== false ? <Badge color="green">on</Badge> : <Badge color="red">off</Badge>}</div>
    <Callout>Secrets, encryption keys and peppers are configured only through environment variables or mounted secret files. They are never shown here.</Callout>
  </Panel>

  if (section === 'limits') return <LimitsEditor d={d} />

  if (section === 'network') return <Panel title="Network allowlists" subtitle="Configured by environment variables">
    <div className="section-title">Upstream host allowlist</div>
    {s.network.upstream_host_allowlist.length ? <div className="chips">{s.network.upstream_host_allowlist.map(h => <span className="chip mono" key={h}>{h}</span>)}</div> : <p className="muted" style={{ fontSize: 10 }}>Not set. Any public host is allowed and private ranges are blocked.</p>}
    <div className="section-title">stdio executable allowlist</div>
    {s.network.stdio_executable_allowlist.length ? <div className="chips">{s.network.stdio_executable_allowlist.map(h => <span className="chip mono" key={h}>{h}</span>)}</div> : <p className="muted" style={{ fontSize: 10 }}>Empty. stdio servers cannot be registered.</p>}
    <div className="section-title">CORS allowed origins</div>
    {s.network.cors_allowed_origins.length ? <div className="chips">{s.network.cors_allowed_origins.map(h => <span className="chip mono" key={h}>{h}</span>)}</div> : <p className="muted" style={{ fontSize: 10 }}>None (same-origin only).</p>}
  </Panel>

  return <Panel title="System health" subtitle="Live status of gateway dependencies">
    <div className="service-grid">{d.health.map(h => <div key={h.name}><span>{h.name}</span><span style={{ display: 'grid', justifyItems: 'end', gap: 3 }}><Status value={h.status} />
      {h.last_heartbeat && <small className="muted" style={{ fontSize: 9 }}>beat {timeAgo(h.last_heartbeat)}</small>}{h.workers_alive != null && <small className="muted" style={{ fontSize: 9 }}>{h.workers_alive} alive</small>}{h.queue_depth != null && <small className="muted" style={{ fontSize: 9 }}>queue {h.queue_depth}</small>}</span></div>)}</div>
  </Panel>
}

function LimitsEditor({ d }: { d: SettingsResp }) {
  const gl = d.stored.global_limits || {}
  const [limits, setLimits] = useState<Record<string, string>>({ per_minute: gl.per_minute ?? '', per_hour: gl.per_hour ?? '', per_day: gl.per_day ?? '', per_month: gl.per_month ?? '' })
  const qc = useQueryClient()
  const toast = useToast()
  const m = useMutation({
    mutationFn: () => api.patch('/settings', { values: { global_limits: Object.fromEntries(Object.entries(limits).filter(([, v]) => v !== '').map(([k, v]) => [k, Number(v)])) } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['settings'] }); toast.ok('Global limits saved') },
    onError: e => toast.error(e),
  })
  return <>
    <Panel title="Payload limits" subtitle="Platform defaults. Individual tools can be stricter.">
      <dl className="kv">{Object.entries(d.system.payload_limits).map(([k, v]) => <Fragment key={k}><dt>{k.replace(/_/g, ' ')}</dt><dd>{v.toLocaleString()}</dd></Fragment>)}</dl>
    </Panel>
    <Panel title="Global call limits" subtitle="Apply across all tenants. Only platform administrators can change them.">
      <fieldset disabled={!d.editable} style={{ border: 0, padding: 0, margin: 0 }}>
        <div className="field-row">{Object.keys(limits).map(k => <Field key={k} label={k.replace('_', ' ')}><input type="number" min={1} placeholder="no limit" value={limits[k]} onChange={e => setLimits({ ...limits, [k]: e.target.value })} /></Field>)}</div>
      </fieldset>
      {d.editable ? <div className="form-actions"><button className="btn primary" disabled={m.isPending} onClick={() => m.mutate()}>{m.isPending ? <Loader2 size={13} className="spin" /> : <Save size={13} />}Save</button></div>
        : <Callout>Read-only: requires the platform administrator role.</Callout>}
    </Panel>
  </>
}

function Account() {
  const { me, logout } = useAuth()
  const toast = useToast()
  const [cur, setCur] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const m = useMutation({
    mutationFn: () => api.post('/auth/change-password', { current_password: cur, new_password: next }),
    onSuccess: () => { toast.ok('Password changed. Please sign in again.'); setTimeout(() => logout(), 1200) },
    onError: e => toast.error(e),
  })
  const sso = me?.auth_source === 'oidc'
  const directory = me?.auth_source === 'ldap'
  return <Panel title="My account">
    <dl className="kv"><dt>Name</dt><dd>{me?.display_name}</dd><dt>Roles</dt><dd>{me?.is_platform_admin ? 'Platform Admin' : me?.roles.join(', ')}</dd>
      <dt>Sign-in</dt><dd>{sso ? <Badge color="blue">single sign-on</Badge> : directory ? <Badge color="blue">directory account</Badge> : <Badge>local password</Badge>}</dd></dl>
    {sso ? <Callout>Your account is managed by your organisation's identity provider. Change your password and group memberships there; roles here follow your IdP groups at each sign-in.</Callout>
      : directory ? <Callout>Your account is managed in your organisation's directory. Change your password there; roles here follow your directory groups at each sign-in.</Callout> : <>
    <div className="section-title">Change password</div>
    <Field label="Current password"><input type="password" autoComplete="current-password" value={cur} onChange={e => setCur(e.target.value)} /></Field>
    <Field label="New password" hint="At least 12 characters." error={next && next.length < 12 ? 'Too short' : null}><input type="password" autoComplete="new-password" value={next} onChange={e => setNext(e.target.value)} /></Field>
    <Field label="Confirm new password" error={confirm && confirm !== next ? 'Passwords do not match' : null}><input type="password" autoComplete="new-password" value={confirm} onChange={e => setConfirm(e.target.value)} /></Field>
    <div className="form-actions"><button className="btn primary" disabled={!cur || next.length < 12 || next !== confirm || m.isPending} onClick={() => m.mutate()}>Change password</button></div>
    </>}
  </Panel>
}
