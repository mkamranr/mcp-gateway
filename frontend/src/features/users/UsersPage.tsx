import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Building2, Loader2, Pencil, Plus, UserPlus } from 'lucide-react'
import { useAuth, useTenantId } from '../../app/auth'
import { api, ApiError, errorMessage } from '../../services/api'
import { dateTime, ROLE_LABELS, TENANT_ROLES, timeAgo } from '../../services/format'
import type { Page, Tenant, TenantUser } from '../../services/types'
import { Badge, Callout, Field, Modal, PageHeading, Panel, QueryState, Status, Switch, Tabs, useToast } from '../../components/ui'

export function UsersPage() {
  const { can, me } = useAuth()
  const [tab, setTab] = useState<'users' | 'tenants'>('users')
  return (
    <>
      <PageHeading eyebrow="ADMINISTRATION" title="Users & Tenants" subtitle="Human accounts, their roles in this tenant, and tenant lifecycle." />
      {me?.is_platform_admin && <Tabs large value={tab} onChange={setTab} options={[{ value: 'users', label: 'Users' }, { value: 'tenants', label: 'Tenants' }]} />}
      {tab === 'users' || !me?.is_platform_admin ? <Users canManage={can('platform_admin', 'tenant_admin')} /> : <Tenants />}
    </>
  )
}

function Users({ canManage }: { canManage: boolean }) {
  const tenantId = useTenantId()
  const { me } = useAuth()
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<TenantUser | null>(null)
  const q = useQuery({ queryKey: ['users', tenantId], queryFn: () => api.get<Page<TenantUser>>(`/tenants/${tenantId}/users`, { limit: 200 }) })
  return <Panel title="Users in this tenant" actions={canManage && <button className="btn primary" onClick={() => setAdding(true)}><UserPlus size={13} />Add user</button>}>
    <QueryState q={q} empty={d => d.items.length === 0}>
      {d => <div className="table-wrap"><table>
        <thead><tr><th>USER</th><th>ROLES</th><th>MEMBERSHIP</th><th>ACCOUNT</th><th>LAST LOGIN</th><th>ADDED</th><th /></tr></thead>
        <tbody>{d.items.map(u => <tr key={u.membership_id}>
          <td><b>{u.display_name || u.username}</b><div className="muted mono" style={{ fontSize: 9, marginTop: 3 }}>{u.username}{u.email ? ` · ${u.email}` : ''}</div></td>
          <td><div className="chips">{u.roles.map(r => <span className="chip" key={r}>{ROLE_LABELS[r] || r}</span>)}</div></td>
          <td><Status value={u.status} /></td><td><Status value={u.user_status} /></td>
          <td className="muted">{timeAgo(u.last_login_at)}</td><td className="muted">{dateTime(u.created_at)}</td>
          <td>{canManage && u.user_id !== me?.principal_id && <button className="small-btn" onClick={() => setEditing(u)}><Pencil size={11} />Edit</button>}</td>
        </tr>)}</tbody>
      </table></div>}
    </QueryState>
    {adding && <AddUser tenantId={tenantId} onClose={() => setAdding(false)} />}
    {editing && <EditUser tenantId={tenantId} user={editing} onClose={() => setEditing(null)} />}
  </Panel>
}

function InitialPassword({ username, password, onClose }: { username: string; password: string; onClose: () => void }) {
  return <Modal title="Temporary password" onClose={onClose} footer={<button className="btn primary" onClick={onClose}>Done</button>}>
    <Callout kind="warn">Shown only once. Give it to <b>{username}</b> over a secure channel. They must change it at first sign-in.</Callout>
    <div className="secret-box"><span style={{ flex: 1, userSelect: 'all' }}>{password}</span></div>
  </Modal>
}

function RolePicker({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  return <div className="field"><span>Roles</span>{TENANT_ROLES.map(r => <label className="check" key={r}>
    <input type="checkbox" checked={value.includes(r)} onChange={e => onChange(e.target.checked ? [...value, r] : value.filter(x => x !== r))} />{ROLE_LABELS[r]}
  </label>)}</div>
}

function AddUser({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const [f, setF] = useState({ username: '', email: '', display_name: '', password: '' })
  const [roles, setRoles] = useState<string[]>(['developer'])
  const [err, setErr] = useState<ApiError | null>(null)
  const [issued, setIssued] = useState<string | null>(null)
  const qc = useQueryClient()
  const toast = useToast()
  const m = useMutation({
    mutationFn: () => api.post<{ initial_password?: string | null }>(`/tenants/${tenantId}/users`, {
      username: f.username, roles, email: f.email || null, display_name: f.display_name || null, password: f.password || null,
    }),
    onSuccess: r => {
      qc.invalidateQueries({ queryKey: ['users', tenantId] })
      toast.ok('User added')
      if (r?.initial_password) setIssued(r.initial_password)
      else onClose()
    },
    onError: e => e instanceof ApiError ? setErr(e) : toast.error(e),
  })
  if (issued) return <InitialPassword username={f.username} password={issued} onClose={onClose} />
  return <Modal title="Add user" onClose={onClose} footer={<>
    <button className="btn secondary" onClick={onClose}>Cancel</button>
    <button className="btn primary" disabled={!f.username || !roles.length || (f.password !== '' && f.password.length < 12) || m.isPending} onClick={() => m.mutate()}>{m.isPending && <Loader2 size={13} className="spin" />}Add user</button>
  </>}>
    {err && <Callout kind="danger">{errorMessage(err)}</Callout>}
    <Field label="Username"><input value={f.username} onChange={e => setF({ ...f, username: e.target.value })} autoFocus /></Field>
    <div className="field-row">
      <Field label="Display name"><input value={f.display_name} onChange={e => setF({ ...f, display_name: e.target.value })} /></Field>
      <Field label="Email"><input type="email" value={f.email} onChange={e => setF({ ...f, email: e.target.value })} /></Field>
    </div>
    <Field label="Initial password" hint="At least 12 characters. Leave blank to generate a one-time temporary password. An existing username is simply added to this tenant. New users must change the password at first login.">
      <input type="password" autoComplete="new-password" value={f.password} onChange={e => setF({ ...f, password: e.target.value })} />
    </Field>
    <RolePicker value={roles} onChange={setRoles} />
  </Modal>
}

function EditUser({ tenantId, user, onClose }: { tenantId: string; user: TenantUser; onClose: () => void }) {
  const [roles, setRoles] = useState<string[]>(user.roles)
  const [active, setActive] = useState(user.status === 'active')
  const qc = useQueryClient()
  const toast = useToast()
  const m = useMutation({
    mutationFn: () => api.patch(`/tenants/${tenantId}/users/${user.user_id}`, { roles, status: active ? 'active' : 'disabled' }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['users', tenantId] }); toast.ok('User updated. Active sessions pick up the change on their next request.'); onClose() },
    onError: e => toast.error(e),
  })
  return <Modal title={`Edit ${user.display_name || user.username}`} onClose={onClose} footer={<>
    <button className="btn secondary" onClick={onClose}>Cancel</button>
    <button className="btn primary" disabled={!roles.length || m.isPending} onClick={() => m.mutate()}>Save</button>
  </>}>
    <RolePicker value={roles} onChange={setRoles} />
    <div className="toggle-row"><span>Membership active</span><Switch on={active} onChange={setActive} label="Active" /></div>
    {!active && <Callout kind="warn">The user loses access to this tenant immediately.</Callout>}
  </Modal>
}

function Tenants() {
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState<Tenant | null>(null)
  const q = useQuery({ queryKey: ['tenants'], queryFn: () => api.get<Page<Tenant>>('/tenants', { limit: 200 }) })
  return <Panel title="Tenants" subtitle="Isolated workspaces. Every record is scoped to exactly one tenant." actions={<button className="btn primary" onClick={() => setCreating(true)}><Plus size={13} />New tenant</button>}>
    <QueryState q={q} empty={d => d.items.length === 0}>
      {d => <div className="table-wrap"><table>
        <thead><tr><th>TENANT</th><th>SLUG</th><th>STATUS</th><th>DEFAULT ENV</th><th>QUOTAS</th><th>RETENTION</th><th>CREATED</th><th /></tr></thead>
        <tbody>{d.items.map(t => <tr key={t.id}>
          <td><div className="server-name"><div className="server-icon"><Building2 size={14} /></div><b>{t.name}</b></div></td>
          <td className="mono">{t.slug}</td><td><Status value={t.status} /></td><td>{t.settings?.default_environment || '-'}</td>
          <td className="mono">{Object.entries(t.settings?.quotas || {}).map(([k, v]) => `${k}: ${v}`).join(', ') || '-'}</td>
          <td>{t.settings?.audit_retention_days ? `${t.settings.audit_retention_days} d` : '-'}</td><td className="muted">{dateTime(t.created_at)}</td>
          <td><button className="small-btn" onClick={() => setEditing(t)}><Pencil size={11} />Edit</button></td>
        </tr>)}</tbody>
      </table></div>}
    </QueryState>
    {creating && <CreateTenant onClose={() => setCreating(false)} />}
    {editing && <EditTenant tenant={editing} onClose={() => setEditing(null)} />}
  </Panel>
}

function CreateTenant({ onClose }: { onClose: () => void }) {
  const [f, setF] = useState({ name: '', slug: '', admin_username: '', admin_email: '', admin_password: '' })
  const [err, setErr] = useState<ApiError | null>(null)
  const qc = useQueryClient()
  const toast = useToast()
  const [issued, setIssued] = useState<string | null>(null)
  const m = useMutation({
    mutationFn: () => api.post<{ initial_admin_password?: string | null }>('/tenants', { ...f, admin_email: f.admin_email || null, admin_password: f.admin_password || null }),
    onSuccess: r => {
      qc.invalidateQueries({ queryKey: ['tenants'] }); qc.invalidateQueries({ queryKey: ['me'] })
      toast.ok('Tenant created with a default-deny policy')
      if (r?.initial_admin_password) setIssued(r.initial_admin_password)
      else onClose()
    },
    onError: e => e instanceof ApiError ? setErr(e) : toast.error(e),
  })
  if (issued) return <InitialPassword username={f.admin_username} password={issued} onClose={onClose} />
  return <Modal title="New tenant" onClose={onClose} footer={<>
    <button className="btn secondary" onClick={onClose}>Cancel</button>
    <button className="btn primary" disabled={!f.name || !f.slug || !f.admin_username || m.isPending} onClick={() => m.mutate()}>{m.isPending && <Loader2 size={13} className="spin" />}Create tenant</button>
  </>}>
    {err && <Callout kind="danger">{errorMessage(err)}</Callout>}
    <div className="field-row">
      <Field label="Name"><input value={f.name} onChange={e => setF({ ...f, name: e.target.value, slug: f.slug || '' })} autoFocus /></Field>
      <Field label="Slug" hint="lowercase, digits, hyphens"><input value={f.slug} onChange={e => setF({ ...f, slug: e.target.value.toLowerCase() })} /></Field>
    </div>
    <div className="section-title">First tenant administrator</div>
    <div className="field-row">
      <Field label="Username"><input value={f.admin_username} onChange={e => setF({ ...f, admin_username: e.target.value })} /></Field>
      <Field label="Email"><input value={f.admin_email} onChange={e => setF({ ...f, admin_email: e.target.value })} /></Field>
    </div>
    <Field label="Initial password" hint="12+ characters. Leave blank to generate a one-time temporary password. An existing username just becomes the administrator."><input type="password" autoComplete="new-password" value={f.admin_password} onChange={e => setF({ ...f, admin_password: e.target.value })} /></Field>
    <Callout>The tenant starts with a default-deny policy and no servers. Nothing is reachable until it is configured.</Callout>
  </Modal>
}

function EditTenant({ tenant, onClose }: { tenant: Tenant; onClose: () => void }) {
  const s = tenant.settings || {}
  const [name, setName] = useState(tenant.name)
  const [status, setStatus] = useState(tenant.status)
  const [retention, setRetention] = useState<number>(s.audit_retention_days ?? 365)
  const [env, setEnv] = useState<string>(s.default_environment ?? 'production')
  const [perMin, setPerMin] = useState<number>(s.quotas?.per_minute ?? 600)
  const [perDay, setPerDay] = useState<number>(s.quotas?.per_day ?? 100000)
  const [critical, setCritical] = useState<boolean>(s.critical_requires_approval ?? true)
  const qc = useQueryClient()
  const toast = useToast()
  const m = useMutation({
    mutationFn: () => api.patch(`/tenants/${tenant.id}`, { name, status, settings: { audit_retention_days: retention, default_environment: env, quotas: { ...(s.quotas || {}), per_minute: perMin, per_day: perDay }, critical_requires_approval: critical } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['tenants'] }); qc.invalidateQueries({ queryKey: ['me'] }); toast.ok('Tenant updated'); onClose() },
    onError: e => toast.error(e),
  })
  return <Modal title={`Edit ${tenant.name}`} onClose={onClose} footer={<>
    <button className="btn secondary" onClick={onClose}>Cancel</button>
    <button className="btn primary" disabled={m.isPending} onClick={() => m.mutate()}>Save</button>
  </>}>
    <Field label="Name"><input value={name} onChange={e => setName(e.target.value)} /></Field>
    <div className="field-row">
      <Field label="Status"><select value={status} onChange={e => setStatus(e.target.value)}><option value="active">active</option><option value="suspended">suspended</option></select></Field>
      <Field label="Default environment"><select value={env} onChange={e => setEnv(e.target.value)}><option>production</option><option>test</option><option>development</option></select></Field>
    </div>
    {status === 'suspended' && <Callout kind="danger">Suspending blocks every agent key and invocation in this tenant immediately.</Callout>}
    <div className="field-row">
      <Field label="Calls per minute (tenant)"><input type="number" min={1} value={perMin} onChange={e => setPerMin(Number(e.target.value))} /></Field>
      <Field label="Calls per day (tenant)"><input type="number" min={1} value={perDay} onChange={e => setPerDay(Number(e.target.value))} /></Field>
      <Field label="Audit retention (days)"><input type="number" min={30} max={3650} value={retention} onChange={e => setRetention(Number(e.target.value))} /></Field>
    </div>
    <div className="toggle-row"><span>Critical tools always require approval <Badge color="green">recommended</Badge></span><Switch on={critical} onChange={setCritical} label="Critical requires approval" /></div>
  </Modal>
}
