import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, KeyRound, Plus, Power, RotateCw, ShieldOff, XCircle } from 'lucide-react'
import { useAuth } from '../../app/auth'
import { api } from '../../services/api'
import { dateTime, timeAgo } from '../../services/format'
import type { Agent, Credential } from '../../services/types'
import { Badge, Callout, Confirm, DecisionBadge, Empty, Field, PageHeading, Panel, QueryState, RiskBadge, Status, useToast } from '../../components/ui'
import { CreateKeyDialog, SecretOnce } from './KeyDialogs'

export function AgentDetailPage() {
  const { id = '' } = useParams()
  const q = useQuery({ queryKey: ['agent', id], queryFn: () => api.get<Agent>(`/agents/${id}`) })
  return <QueryState q={q}>{a => <AgentDetail a={a} />}</QueryState>
}

function AgentDetail({ a }: { a: Agent }) {
  const { can } = useAuth()
  const security = can('platform_admin', 'tenant_admin', 'security_admin')
  const qc = useQueryClient()
  const toast = useToast()
  const [creating, setCreating] = useState(false)
  const [secret, setSecret] = useState<Credential | null>(null)
  const [revoking, setRevoking] = useState<Credential | null>(null)
  const [rotating, setRotating] = useState<Credential | null>(null)
  const [revokeAgent, setRevokeAgent] = useState(false)
  const [reason, setReason] = useState('')
  const refresh = () => { qc.invalidateQueries({ queryKey: ['agent', a.id] }); qc.invalidateQueries({ queryKey: ['agents'] }) }

  const rotate = useMutation({ mutationFn: (c: Credential) => api.post<Credential>(`/auth/agent-keys/${c.id}/rotate`), onSuccess: c => { refresh(); setRotating(null); setSecret(c) }, onError: e => toast.error(e) })
  const revoke = useMutation({ mutationFn: (c: Credential) => api.post(`/auth/agent-keys/${c.id}/revoke`, { reason }), onSuccess: () => { refresh(); setRevoking(null); setReason(''); toast.ok('Key revoked') }, onError: e => toast.error(e) })
  const toggle = useMutation({ mutationFn: () => api.patch(`/agents/${a.id}`, { version: a.version, status: a.status === 'active' ? 'disabled' : 'active' }), onSuccess: () => { refresh(); toast.ok('Agent updated') }, onError: e => toast.error(e) })
  const revokeA = useMutation({ mutationFn: () => api.post(`/agents/${a.id}/revoke`, { reason }), onSuccess: () => { refresh(); setRevokeAgent(false); setReason(''); toast.ok('Agent revoked and all keys invalidated') }, onError: e => toast.error(e) })

  const creds = a.credentials || []
  return (
    <>
      <Link to="/agents" className="text-btn" style={{ marginBottom: 10 }}><ArrowLeft size={12} />All agents</Link>
      <PageHeading eyebrow="AGENT" title={a.name} subtitle={a.description || undefined}
        actions={security && <>
          {a.status !== 'revoked' && <button className="btn secondary" disabled={toggle.isPending} onClick={() => toggle.mutate()}><Power size={13} />{a.status === 'active' ? 'Disable' : 'Enable'}</button>}
          {a.status !== 'revoked' && <button className="btn danger" onClick={() => setRevokeAgent(true)}><ShieldOff size={13} />Revoke agent</button>}
        </>} />
      {a.status !== 'active' && <Callout kind="warn">This agent is {a.status}. Its keys are rejected.</Callout>}
      <div className="panel"><div className="detail-grid">
        <div><small>STATUS</small><b><Status value={a.status} /></b></div>
        <div><small>ENVIRONMENT</small><b>{a.environment}</b></div>
        <div><small>LAST ACTIVITY</small><b>{timeAgo(a.last_activity_at)}</b></div>
        <div><small>CREATED</small><b>{dateTime(a.created_at)}</b></div>
      </div></div>

      <Panel title="Credentials" subtitle="Keys authenticate the agent at /mcp and the gateway REST API."
        actions={security && a.status === 'active' && <button className="btn primary" onClick={() => setCreating(true)}><Plus size={13} />New key</button>}>
        {creds.length === 0 ? <Empty title="No keys">Create a key to let this agent connect.</Empty> : <div className="table-wrap"><table>
          <thead><tr><th>NAME</th><th>PREFIX</th><th>SCOPES</th><th>STATUS</th><th>EXPIRES</th><th>LAST USED</th><th>CREATED</th><th /></tr></thead>
          <tbody>{creds.map(c => <tr key={c.id}>
            <td><KeyRound size={11} /> {c.name}</td><td className="mono">{c.key_prefix}…</td>
            <td><div className="chips">{c.scopes.map(s => <span className="chip" key={s}>{s}</span>)}</div></td>
            <td><Status value={c.status} /></td><td>{c.expires_at ? dateTime(c.expires_at) : <span className="muted">never</span>}</td>
            <td className="muted">{timeAgo(c.last_used_at)}{c.last_used_source ? ` · ${c.last_used_source}` : ''}</td><td className="muted">{dateTime(c.created_at)}</td>
            <td>{security && c.status === 'active' && <div className="row-actions">
              <button className="small-btn" onClick={() => setRotating(c)}><RotateCw size={11} />Rotate</button>
              <button className="small-btn" onClick={() => setRevoking(c)}><XCircle size={11} />Revoke</button>
            </div>}</td>
          </tr>)}</tbody>
        </table></div>}
      </Panel>

      <div className="two-col">
        <Panel title="Tools this agent can discover" subtitle="Computed from current policies and tool state">
          {!a.permitted_tools?.length ? <Empty title="No tools">Default deny: add an allow policy for this agent.</Empty> :
            <div className="mini-server-list">{a.permitted_tools.map(t => <div key={t.id}><Link className="mono" to={`/tools/${t.id}`}>{t.gateway_name}</Link><RiskBadge risk={t.risk_level} /></div>)}</div>}
        </Panel>
        <Panel title="Applicable policies" actions={<Link className="text-btn" to="/policies">Manage</Link>}>
          {!a.policies?.length ? <Empty title="No policies" /> :
            <div className="mini-server-list">{a.policies.map(p => <div key={p.id}><Link to={`/policies?id=${p.id}`}>{p.name}</Link><span><DecisionBadge value={p.effect} /> {!p.enabled && <Badge>disabled</Badge>}</span></div>)}</div>}
        </Panel>
      </div>

      <Panel title="Recent invocations">
        {!a.recent_invocations?.length ? <Empty title="No calls yet" /> : <div className="table-wrap"><table>
          <thead><tr><th>TIME</th><th>TOOL</th><th>DECISION</th><th>STATUS</th><th>DURATION</th><th>ERROR</th></tr></thead>
          <tbody>{a.recent_invocations.map(i => <tr key={i.id}><td>{dateTime(i.created_at)}</td><td className="mono">{i.gateway_name}</td><td><DecisionBadge value={i.decision} /></td><td><Status value={i.status} /></td><td>{i.duration_ms} ms</td><td className="mono muted">{i.error_code || '-'}</td></tr>)}</tbody>
        </table></div>}
      </Panel>

      {creating && <CreateKeyDialog agentId={a.id} agentName={a.name} onClose={() => setCreating(false)} onCreated={c => { setCreating(false); setSecret(c) }} />}
      {secret && <SecretOnce cred={secret} onClose={() => setSecret(null)} />}
      {rotating && <Confirm title="Rotate key" confirmLabel="Rotate" busy={rotate.isPending}
        message={<>A new key with the same scopes is issued and <b>{rotating.key_prefix}…</b> is revoked immediately. Update the agent configuration right away.</>}
        onConfirm={() => rotate.mutate(rotating)} onClose={() => setRotating(null)} />}
      {revoking && <Confirm danger title="Revoke key" confirmLabel="Revoke" busy={revoke.isPending}
        message={<>Requests using <b className="mono">{revoking.key_prefix}…</b> are rejected immediately. Pending approvals it requested will abort.</>}
        onConfirm={() => revoke.mutate(revoking)} onClose={() => setRevoking(null)}>
        <Field label="Reason"><input value={reason} onChange={e => setReason(e.target.value)} /></Field>
      </Confirm>}
      {revokeAgent && <Confirm danger title="Revoke agent" confirmLabel="Revoke agent" typed={a.name} busy={revokeA.isPending}
        message={<>This permanently disables <b>{a.name}</b> and revokes all of its keys.</>}
        onConfirm={() => revokeA.mutate()} onClose={() => setRevokeAgent(false)}>
        <Field label="Reason"><input value={reason} onChange={e => setReason(e.target.value)} /></Field>
      </Confirm>}
    </>
  )
}
