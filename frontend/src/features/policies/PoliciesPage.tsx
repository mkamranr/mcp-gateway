import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, History, Lock, Pencil, Play, Plus, Trash2 } from 'lucide-react'
import { useAuth, useTenantId } from '../../app/auth'
import { api, errorMessage } from '../../services/api'
import { dateTime, normalizePolicy } from '../../services/format'
import type { Agent, Decision, Page, Policy, Tool, TenantUser } from '../../services/types'
import { Badge, Callout, Confirm, DecisionBadge, Drawer, Empty, Field, JsonView, Loading, PageHeading, Panel, QueryState, Status, Switch, Tabs, useToast } from '../../components/ui'
import { PolicyEditor } from './PolicyEditor'

export function PoliciesPage() {
  const [tab, setTab] = useState<'list' | 'simulate'>('list')
  const { can } = useAuth()
  const [editing, setEditing] = useState<Policy | 'new' | null>(null)
  const canWrite = can('platform_admin', 'tenant_admin', 'security_admin')
  return (
    <>
      <PageHeading eyebrow="ACCESS CONTROL" title="Policies" subtitle="Default deny. A tool is reachable only when an allow policy matches and no deny policy does."
        actions={canWrite && <button className="btn primary" onClick={() => setEditing('new')}><Plus size={14} />New policy</button>} />
      <Tabs large value={tab} onChange={setTab} options={[{ value: 'list', label: 'Policies' }, { value: 'simulate', label: 'Simulator' }]} />
      {tab === 'list' ? <PolicyList canWrite={canWrite} onEdit={setEditing} /> : <Simulator />}
      {editing && <PolicyEditor policy={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} />}
    </>
  )
}

function PolicyList({ canWrite, onEdit }: { canWrite: boolean; onEdit: (p: Policy) => void }) {
  const [params] = useSearchParams()
  const highlight = params.get('id')
  const q = useQuery({ queryKey: ['policies'], queryFn: async () => { const r = await api.get<Page<Policy>>('/policies', { limit: 200 }); return { ...r, items: r.items.map(normalizePolicy) } } })
  const qc = useQueryClient()
  const toast = useToast()
  const [deleting, setDeleting] = useState<Policy | null>(null)
  const [history, setHistory] = useState<Policy | null>(null)
  const done = (msg: string) => () => { qc.invalidateQueries({ queryKey: ['policies'] }); toast.ok(msg) }
  const toggle = useMutation({ mutationFn: (p: Policy) => api.post(`/policies/${p.id}/${p.enabled ? 'disable' : 'enable'}`), onSuccess: done('Policy updated'), onError: e => toast.error(e) })
  const clone = useMutation({ mutationFn: (p: Policy) => api.post(`/policies/${p.id}/clone`), onSuccess: done('Policy cloned (disabled)'), onError: e => toast.error(e) })
  const del = useMutation({ mutationFn: (p: Policy) => api.del(`/policies/${p.id}`), onSuccess: () => { done('Policy deleted')(); setDeleting(null) }, onError: e => toast.error(e) })

  const summary = (p: Policy) => {
    const who = [...p.principals.ids.map(i => i.slice(0, 10)), ...p.principals.roles.map(r => `role:${r}`)].join(', ') || `all ${p.principals.types.join('/')}`
    const what = `${p.resources.servers.join(',')} / ${p.resources.tools.join(',')}`
    return { who, what }
  }

  return <Panel>
    <QueryState q={q} empty={d => d.items.length === 0}>
      {d => <div className="table-wrap"><table>
        <thead><tr><th>POLICY</th><th>EFFECT</th><th>PRINCIPALS</th><th>RESOURCES</th><th>ACTIONS</th><th>CONDITIONS</th><th>PRIORITY</th><th>ENABLED</th><th /></tr></thead>
        <tbody>{d.items.map(p => {
          const s = summary(p)
          const locked = p.system || p.scope === 'global'
          const c = p.constraints || {} as Policy['constraints']
          return <tr key={p.id} style={p.id === highlight ? { background: '#1c3c6b55' } : undefined}>
            <td><b>{p.name}</b>{p.system && <> <Badge><Lock size={9} />system</Badge></>}{p.scope === 'global' && <> <Badge color="blue">global</Badge></>}
              {p.broad?.length > 0 && p.effect === 'allow' && <> <Badge color="orange">broad</Badge></>}
              <div className="muted" style={{ fontSize: 9, marginTop: 3 }}>{p.description}</div></td>
            <td>{p.kind === 'default_deny' ? <DecisionBadge value="DENY" /> : <DecisionBadge value={p.effect} />}</td>
            <td className="mono" style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>{p.kind === 'default_deny' ? 'everyone' : s.who}</td>
            <td className="mono" style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis' }}>{p.kind === 'default_deny' ? 'everything not allowed' : s.what}</td>
            <td>{p.actions?.join(', ')}</td>
            <td>{c.require_approval && <Badge color="purple">approval</Badge>} {c.environments?.length > 0 && <Badge>{c.environments.join('/')}</Badge>} {c.time_windows?.length > 0 && <Badge>time window</Badge>} {c.source_cidrs?.length > 0 && <Badge>network</Badge>} {(c.max_calls_per_minute || c.max_calls_per_hour || c.max_calls_per_day) && <Badge>rate</Badge>}</td>
            <td>{p.priority}</td>
            <td><Switch on={p.enabled} disabled={!canWrite || locked || toggle.isPending} onChange={() => toggle.mutate(p)} label="Enabled" /></td>
            <td><div className="row-actions">
              <button className="small-btn" title="History" onClick={() => setHistory(p)}><History size={11} /></button>
              {canWrite && !locked && <button className="small-btn" title="Edit" onClick={() => onEdit(p)}><Pencil size={11} /></button>}
              {canWrite && p.kind !== 'default_deny' && <button className="small-btn" title="Clone" onClick={() => clone.mutate(p)}><Copy size={11} /></button>}
              {canWrite && !locked && <button className="small-btn" title="Delete" onClick={() => setDeleting(p)}><Trash2 size={11} /></button>}
            </div></td>
          </tr>
        })}</tbody>
      </table></div>}
    </QueryState>
    {deleting && <Confirm danger title="Delete policy" confirmLabel="Delete" busy={del.isPending}
      message={<>Delete <b>{deleting.name}</b>? Access granted by it ends immediately. Its history stays in the audit log.</>}
      onConfirm={() => del.mutate(deleting)} onClose={() => setDeleting(null)} />}
    {history && <PolicyHistory policy={history} onClose={() => setHistory(null)} />}
  </Panel>
}

function PolicyHistory({ policy, onClose }: { policy: Policy; onClose: () => void }) {
  const q = useQuery({ queryKey: ['policy-history', policy.id], queryFn: () => api.get<{ items: { event_id: string; event_type: string; timestamp: string; principal: { name?: string; id: string } | null; snapshot: unknown; changed_fields: string[] | null }[] }>(`/policies/${policy.id}/history`) })
  return <Drawer title={`History: ${policy.name}`} onClose={onClose}>
    <QueryState q={q} empty={d => d.items.length === 0}>
      {d => <div className="timeline">{d.items.map(e => <div key={e.event_id}>
        <b className="mono">{e.event_type}</b>
        <small>{dateTime(e.timestamp)} · {e.principal?.name || e.principal?.id || 'system'}{e.changed_fields?.length ? ` · changed: ${e.changed_fields.join(', ')}` : ''}</small>
        {e.snapshot != null && <details><summary className="muted" style={{ fontSize: 9, cursor: 'pointer' }}>snapshot</summary><JsonView value={e.snapshot} /></details>}
      </div>)}</div>}
    </QueryState>
  </Drawer>
}

type SimResult = Decision & { effective_decision: string; state_issues: string[]; validation: { valid: boolean; code?: string; errors: any[] } | null; tool: { gateway_name: string } }

function Simulator() {
  const tenantId = useTenantId()
  const toast = useToast()
  const [ptype, setPtype] = useState<'agent' | 'user'>('agent')
  const [principal, setPrincipal] = useState('')
  const [toolId, setToolId] = useState('')
  const [action, setAction] = useState<'invoke' | 'discover'>('invoke')
  const [args, setArgs] = useState('')
  const [ip, setIp] = useState('')
  const [argErr, setArgErr] = useState<string | null>(null)
  const agents = useQuery({ queryKey: ['agents', tenantId, 'all'], queryFn: () => api.get<Page<Agent>>(`/tenants/${tenantId}/agents`, { limit: 200 }) })
  const users = useQuery({ queryKey: ['users', tenantId], queryFn: () => api.get<Page<TenantUser>>(`/tenants/${tenantId}/users`, { limit: 200 }), enabled: ptype === 'user', retry: false })
  const tools = useQuery({ queryKey: ['tools', 'all'], queryFn: () => api.get<Page<Tool>>('/tools', { limit: 200 }) })
  const sim = useMutation({
    mutationFn: () => {
      let parsed: unknown = undefined
      if (args.trim()) parsed = JSON.parse(args)
      return api.post<SimResult>('/policies/simulate', { principal_type: ptype, principal_id: principal, tool_id: toolId, action, ...(parsed !== undefined ? { arguments: parsed } : {}), ...(ip ? { source_ip: ip } : {}) })
    },
    onError: e => toast.error(e),
  })
  const run = () => {
    if (args.trim()) { try { JSON.parse(args) } catch (e) { setArgErr((e as Error).message); return } }
    setArgErr(null); sim.mutate()
  }
  const r = sim.data
  return <div className="two-col">
    <Panel title="Simulate a request" subtitle="Evaluates policy, tool state and argument validation. Never calls the upstream tool.">
      <div className="field-row">
        <Field label="Principal type"><select value={ptype} onChange={e => { setPtype(e.target.value as 'agent' | 'user'); setPrincipal('') }}><option value="agent">Agent</option><option value="user">User</option></select></Field>
        <Field label="Principal">
          <select value={principal} onChange={e => setPrincipal(e.target.value)}>
            <option value="">Select…</option>
            {ptype === 'agent' ? agents.data?.items.map(a => <option key={a.id} value={a.id}>{a.name}</option>) : users.data?.items.map(u => <option key={u.user_id} value={u.user_id}>{u.display_name || u.username}</option>)}
          </select>
        </Field>
      </div>
      <div className="field-row">
        <Field label="Tool"><select value={toolId} onChange={e => setToolId(e.target.value)}><option value="">Select…</option>{tools.data?.items.map(t => <option key={t.id} value={t.id}>{t.gateway_name}</option>)}</select></Field>
        <Field label="Action"><select value={action} onChange={e => setAction(e.target.value as 'invoke' | 'discover')}><option value="invoke">invoke</option><option value="discover">discover</option></select></Field>
      </div>
      <Field label="Arguments (JSON, optional)" error={argErr}><textarea style={{ fontFamily: 'ui-monospace,monospace', fontSize: 10 }} value={args} onChange={e => setArgs(e.target.value)} placeholder='{"employee_id": "E-1001"}' /></Field>
      <Field label="Source IP (optional)"><input value={ip} onChange={e => setIp(e.target.value)} placeholder="10.20.1.15" /></Field>
      <div className="form-actions"><button className="btn primary" disabled={!principal || !toolId || sim.isPending} onClick={run}><Play size={13} />Run simulation</button></div>
    </Panel>
    <Panel title="Result">
      {sim.isPending ? <Loading label="Evaluating…" /> : sim.error ? <Callout kind="danger">{errorMessage(sim.error)}</Callout> : !r ? <Empty title="No simulation yet">Pick a principal and a tool.</Empty> : <>
        <div className="detail-grid" style={{ gridTemplateColumns: 'repeat(3,1fr)' }}>
          <div><small>EFFECTIVE DECISION</small><b><DecisionBadge value={r.effective_decision} /></b></div>
          <div><small>POLICY DECISION</small><b><DecisionBadge value={r.decision} /></b></div>
          <div><small>REASON</small><b className="mono">{r.reason_code}</b></div>
        </div>
        {r.state_issues.length > 0 && <Callout kind="warn">Tool or server state blocks the call: {r.state_issues.join(', ')}</Callout>}
        {r.validation && (r.validation.valid ? <Callout kind="ok">Arguments are valid for the tool schema.</Callout> : <Callout kind="danger">Arguments rejected ({r.validation.code}): {r.validation.errors.map((e: any) => `${e.field}: ${e.message || e.code}`).join('; ')}</Callout>)}
        {Object.keys(r.obligations || {}).length > 0 && <><div className="section-title">Obligations</div><JsonView value={r.obligations} /></>}
        <div className="section-title">Policy evaluation</div>
        <div className="table-wrap"><table>
          <thead><tr><th>POLICY</th><th>EFFECT</th><th>MATCHED</th><th>NOT MATCHED ON</th></tr></thead>
          <tbody>{r.explanation.map(x => <tr key={x.policy_id}><td>{x.name}</td><td><DecisionBadge value={x.effect} /></td><td>{x.matched ? <Status value="active" label="matched" /> : <span className="muted">no</span>}</td><td className="mono">{x.not_matched_on || '-'}</td></tr>)}</tbody>
        </table></div>
        <p className="muted" style={{ fontSize: 9 }}>Dispatched: no. Simulations are recorded in the audit log.</p>
      </>}
    </Panel>
  </div>
}
