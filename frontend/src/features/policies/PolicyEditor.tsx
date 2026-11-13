import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Loader2 } from 'lucide-react'
import { useTenantId } from '../../app/auth'
import { api, ApiError, errorMessage } from '../../services/api'
import { ROLE_LABELS, TENANT_ROLES } from '../../services/format'
import type { Agent, Page, Policy, PolicyConstraints, Risk, Server, Tool } from '../../services/types'
import { Callout, Confirm, Field, ListInput, Modal, Switch, Tabs, useToast } from '../../components/ui'

interface Draft {
  name: string; description: string; effect: 'allow' | 'deny'
  principals: { types: string[]; ids: string[]; roles: string[] }
  resources: { servers: string[]; tools: string[]; risk_levels: Risk[] }
  actions: ('discover' | 'invoke')[]; constraints: PolicyConstraints; priority: number; enabled: boolean
}

const EMPTY_CONSTRAINTS: PolicyConstraints = {
  environments: [], max_calls_per_minute: null, max_calls_per_hour: null, max_calls_per_day: null, require_approval: false,
  required_approvals: null, approver_roles: null, approval_policy_id: null, time_windows: [], source_cidrs: [],
}

function toDraft(p?: Policy): Draft {
  return {
    name: p?.name || '', description: p?.description || '', effect: p?.effect || 'allow',
    principals: p?.principals ? { ...p.principals } : { types: ['agent'], ids: [], roles: [] },
    resources: p?.resources ? { ...p.resources } : { servers: [], tools: [], risk_levels: [] },
    actions: p?.actions || ['discover', 'invoke'], constraints: { ...EMPTY_CONSTRAINTS, ...(p?.constraints || {}) },
    priority: p?.priority ?? 100, enabled: p?.enabled ?? true,
  }
}

/** Mirrors the server's is_broad() so the warning shows before submit. The server still decides. */
function broadReasons(d: Draft): string[] {
  const r: string[] = []
  if (d.resources.servers.some(s => s.includes('*'))) r.push('all servers')
  if (d.resources.tools.some(t => t.includes('*'))) r.push('all tools')
  if (d.principals.types.includes('*') || d.principals.ids.some(i => i.includes('*')) || (!d.principals.ids.length && !d.principals.roles.length)) r.push('all principals')
  return r
}

export function PolicyEditor({ policy, onClose }: { policy?: Policy; onClose: () => void }) {
  const editing = !!policy
  const tenantId = useTenantId()
  const [d, setD] = useState<Draft>(() => toDraft(policy))
  const [mode, setMode] = useState<'guided' | 'json'>('guided')
  const [json, setJson] = useState('')
  const [jsonErr, setJsonErr] = useState<string | null>(null)
  const [err, setErr] = useState<ApiError | null>(null)
  const [needBroad, setNeedBroad] = useState(false)
  const qc = useQueryClient()
  const toast = useToast()

  const servers = useQuery({ queryKey: ['servers', 'all'], queryFn: () => api.get<Page<Server>>('/servers', { limit: 200 }) })
  const tools = useQuery({ queryKey: ['tools', 'all'], queryFn: () => api.get<Page<Tool>>('/tools', { limit: 200 }) })
  const agents = useQuery({ queryKey: ['agents', tenantId, 'all'], queryFn: () => api.get<Page<Agent>>(`/tenants/${tenantId}/agents`, { limit: 200 }) })

  const toolOptions = useMemo(() => {
    const aliases = d.resources.servers
    const all = tools.data?.items || []
    return aliases.includes('*') ? all : all.filter(t => servers.data?.items.some(s => s.id === t.server_id && (aliases.includes(s.alias) || aliases.includes(s.id))))
  }, [tools.data, servers.data, d.resources.servers])

  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD(x => ({ ...x, [k]: v }))
  const setC = <K extends keyof PolicyConstraints>(k: K, v: PolicyConstraints[K]) => setD(x => ({ ...x, constraints: { ...x.constraints, [k]: v } }))
  const toggleIn = <T,>(arr: T[], v: T, on: boolean) => on ? Array.from(new Set([...arr, v])) : arr.filter(x => x !== v)

  const switchMode = (m: 'guided' | 'json') => {
    if (m === 'json') { setJson(JSON.stringify(d, null, 2)); setJsonErr(null) }
    else {
      try { setD({ ...toDraft(), ...JSON.parse(json) }); setJsonErr(null) } catch (e) { setJsonErr(`Invalid JSON: ${(e as Error).message}`); return }
    }
    setMode(m)
  }

  const save = useMutation({
    mutationFn: (confirm: boolean) => {
      let body: Draft = d
      if (mode === 'json') body = JSON.parse(json)
      const payload = { ...body, confirm_broad_grant: confirm }
      return editing ? api.patch<Policy>(`/policies/${policy!.id}`, { ...payload, version: policy!.version }) : api.post<Policy>('/policies', payload)
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['policies'] }); toast.ok(editing ? 'Policy updated' : 'Policy created'); onClose() },
    onError: e => {
      if (e instanceof ApiError && e.code === 'BROAD_GRANT_CONFIRMATION_REQUIRED') { setNeedBroad(true); return }
      if (e instanceof ApiError) setErr(e); else setJsonErr(errorMessage(e))
    },
  })

  const fieldErr = (prefix: string) => err?.details.filter(x => x.field.startsWith(prefix)).map(x => x.message || x.code).join('; ') || null
  const broad = broadReasons(d)
  const tenantRoles = TENANT_ROLES

  return (
    <Modal wide title={editing ? `Edit policy: ${policy!.name}` : 'New policy'} onClose={onClose} footer={<>
      <button className="btn secondary" onClick={onClose}>Cancel</button>
      <button className="btn primary" disabled={save.isPending || (mode === 'json' && !!jsonErr)} onClick={() => {
        if (mode === 'json') { try { JSON.parse(json) } catch (e) { setJsonErr(`Invalid JSON: ${(e as Error).message}`); return } }
        setErr(null); save.mutate(false)
      }}>{save.isPending && <Loader2 size={13} className="spin" />}{editing ? 'Save policy' : 'Create policy'}</button>
    </>}>
      <Tabs value={mode} onChange={switchMode} options={[{ value: 'guided', label: 'Guided' }, { value: 'json', label: 'JSON' }]} />
      {err && <Callout kind="danger">{errorMessage(err)}</Callout>}
      {editing && policy!.system && <Callout kind="warn">This is a system policy. The server may reject changes to it.</Callout>}

      {mode === 'json' ? <>
        <Field label="Policy document" error={jsonErr} hint="Unknown fields are rejected by the server.">
          <textarea className="mono" style={{ minHeight: 380, fontFamily: 'ui-monospace,monospace', fontSize: 10 }} value={json} onChange={e => { setJson(e.target.value); setJsonErr(null) }} spellCheck={false} />
        </Field>
      </> : <>
        <div className="field-row">
          <Field label="Name" error={fieldErr('name')}><input value={d.name} onChange={e => set('name', e.target.value)} placeholder="HR agents read attendance" /></Field>
          <Field label="Effect">
            <select value={d.effect} onChange={e => set('effect', e.target.value as 'allow' | 'deny')}><option value="allow">Allow</option><option value="deny">Deny (always overrides allow)</option></select>
          </Field>
          <Field label="Priority" hint="Lower is evaluated first (for explanation order)."><input type="number" min={0} value={d.priority} onChange={e => set('priority', Number(e.target.value))} /></Field>
        </div>
        <Field label="Description"><textarea value={d.description} onChange={e => set('description', e.target.value)} /></Field>

        <div className="section-title">Who: principals</div>
        <div className="field"><span>Principal types</span><div style={{ display: 'flex', gap: 14 }}>
          {['agent', 'user', 'service'].map(t => <label className="check" key={t}><input type="checkbox" checked={d.principals.types.includes(t)} onChange={e => set('principals', { ...d.principals, types: toggleIn(d.principals.types.filter(x => x !== '*'), t, e.target.checked) })} />{t}</label>)}
        </div></div>
        <Field label="Specific agents" hint="Leave empty and choose roles, or leave both empty to match every principal of the selected types (broad).">
          <select multiple value={d.principals.ids} style={{ minHeight: 90 }} onChange={e => set('principals', { ...d.principals, ids: Array.from(e.target.selectedOptions).map(o => o.value) })}>
            {agents.data?.items.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
            {d.principals.ids.filter(id => !agents.data?.items.some(a => a.id === id)).map(id => <option key={id} value={id}>{id}</option>)}
          </select>
        </Field>
        <div className="field"><span>Or users with roles</span><div className="chips">
          {tenantRoles.map(r => <label className="check" key={r} style={{ marginRight: 10 }}><input type="checkbox" checked={d.principals.roles.includes(r)} onChange={e => set('principals', { ...d.principals, roles: toggleIn(d.principals.roles, r, e.target.checked) })} />{ROLE_LABELS[r]}</label>)}
        </div></div>

        <div className="section-title">What: resources & actions</div>
        <Field label="Servers" error={fieldErr('resources.servers')}>
          <select multiple value={d.resources.servers} style={{ minHeight: 80 }} onChange={e => set('resources', { ...d.resources, servers: Array.from(e.target.selectedOptions).map(o => o.value) })}>
            <option value="*">* (all servers)</option>
            {servers.data?.items.map(s => <option key={s.id} value={s.alias}>{s.name} ({s.alias})</option>)}
          </select>
        </Field>
        <Field label="Tools" error={fieldErr('resources.tools')} hint={<>Upstream or gateway names, or patterns such as <span className="mono">get_*</span>. Use <span className="mono">*</span> for all tools (broad).</>}>
          <ListInput value={d.resources.tools} onChange={v => set('resources', { ...d.resources, tools: v })} placeholder="tool name or pattern" />
        </Field>
        {toolOptions.length > 0 && <div className="chips" style={{ marginTop: -4 }}>{toolOptions.slice(0, 40).map(t => (
          <button type="button" key={t.id} className="chip" style={{ border: 0, cursor: 'pointer' }} onClick={() => set('resources', { ...d.resources, tools: Array.from(new Set([...d.resources.tools, t.upstream_name])) })}>+ {t.upstream_name}</button>
        ))}</div>}
        <div className="field"><span>Only for risk levels (optional)</span><div style={{ display: 'flex', gap: 14 }}>
          {(['low', 'medium', 'high', 'critical'] as Risk[]).map(r => <label className="check" key={r}><input type="checkbox" checked={d.resources.risk_levels.includes(r)} onChange={e => set('resources', { ...d.resources, risk_levels: toggleIn(d.resources.risk_levels, r, e.target.checked) })} />{r}</label>)}
        </div></div>
        <div className="field"><span>Actions</span><div style={{ display: 'flex', gap: 14 }}>
          <label className="check"><input type="checkbox" checked={d.actions.includes('discover')} onChange={e => set('actions', toggleIn(d.actions, 'discover', e.target.checked))} />discover (tools/list)</label>
          <label className="check"><input type="checkbox" checked={d.actions.includes('invoke')} onChange={e => set('actions', toggleIn(d.actions, 'invoke', e.target.checked))} />invoke (tools/call)</label>
        </div></div>

        <div className="section-title">Conditions</div>
        <div className="field"><span>Environments (empty = any)</span><div style={{ display: 'flex', gap: 14 }}>
          {(['production', 'test', 'development'] as const).map(env => <label className="check" key={env}><input type="checkbox" checked={d.constraints.environments.includes(env)} onChange={e => setC('environments', toggleIn(d.constraints.environments, env, e.target.checked))} />{env}</label>)}
        </div></div>
        <div className="field-row">
          {(['max_calls_per_minute', 'max_calls_per_hour', 'max_calls_per_day'] as const).map(k => <Field key={k} label={k.replace(/_/g, ' ').replace('max calls', 'Max calls')}>
            <input type="number" min={1} value={d.constraints[k] ?? ''} placeholder="no limit" onChange={e => setC(k, e.target.value ? Number(e.target.value) : null)} />
          </Field>)}
        </div>
        <Field label="Source networks (CIDR, empty = any)"><ListInput value={d.constraints.source_cidrs} onChange={v => setC('source_cidrs', v)} placeholder="10.20.0.0/16" /></Field>
        <div className="toggle-row"><span>Restrict to a time window</span><Switch on={d.constraints.time_windows.length > 0} onChange={on => setC('time_windows', on ? [{ days: [0, 1, 2, 3, 4], start: '08:00', end: '18:00' }] : [])} label="Time window" /></div>
        {d.constraints.time_windows.slice(0, 1).map((w, i) => <div key={i}>
          <div className="chips" style={{ margin: '8px 0' }}>{['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((n, di) => <label className="check" key={n} style={{ marginRight: 8 }}><input type="checkbox" checked={w.days.includes(di)} onChange={e => setC('time_windows', [{ ...w, days: toggleIn(w.days, di, e.target.checked).sort() }])} />{n}</label>)}</div>
          <div className="field-row">
            <Field label="Start (UTC)"><input type="time" value={w.start} onChange={e => setC('time_windows', [{ ...w, start: e.target.value }])} /></Field>
            <Field label="End (UTC)"><input type="time" value={w.end} onChange={e => setC('time_windows', [{ ...w, end: e.target.value }])} /></Field>
          </div>
        </div>)}
        {d.effect === 'allow' && <>
          <div className="toggle-row"><span>Require human approval for matching calls</span><Switch on={d.constraints.require_approval} onChange={v => setC('require_approval', v)} label="Require approval" /></div>
          {d.constraints.require_approval && <div className="field-row">
            <Field label="Approvers required"><select value={d.constraints.required_approvals ?? 1} onChange={e => setC('required_approvals', Number(e.target.value) as 1 | 2)}><option value={1}>1</option><option value={2}>2 distinct</option></select></Field>
          </div>}
        </>}
        <div className="toggle-row"><span>Enabled</span><Switch on={d.enabled} onChange={v => set('enabled', v)} label="Enabled" /></div>
      </>}

      {mode === 'guided' && d.effect === 'allow' && broad.length > 0 && <Callout kind="warn">Broad grant: this policy applies to {broad.join(', ')}. You will be asked to confirm.</Callout>}

      {needBroad && <Confirm danger title="Confirm broad grant" confirmLabel="Grant broad access" typed="CONFIRM" busy={save.isPending}
        message={<>This allow policy uses wildcards or matches every principal ({broad.join(', ') || 'see details'}). Agents may gain access to tools added later. Confirm only if this is intended.</>}
        onConfirm={() => { setNeedBroad(false); save.mutate(true) }} onClose={() => setNeedBroad(false)} />}
    </Modal>
  )
}
