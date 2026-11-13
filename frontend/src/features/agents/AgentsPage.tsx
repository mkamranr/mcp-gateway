import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bot, Loader2, Plus, ShieldOff } from 'lucide-react'
import { useAuth, useTenantId } from '../../app/auth'
import { api } from '../../services/api'
import { timeAgo } from '../../services/format'
import type { Agent, Page } from '../../services/types'
import { Confirm, Field, ListInput, Modal, PageHeading, Pager, Panel, QueryState, Status, useToast } from '../../components/ui'

const PAGE = 50

export function AgentsPage() {
  const tenantId = useTenantId()
  const { can } = useAuth()
  const [page, setPage] = useState(0)
  const [cursors, setCursors] = useState<(string | null)[]>([null])
  const [creating, setCreating] = useState(false)
  const [emergency, setEmergency] = useState(false)
  const toast = useToast()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['agents', tenantId, cursors[page]], queryFn: () => api.get<Page<Agent>>(`/tenants/${tenantId}/agents`, { limit: PAGE, cursor: cursors[page] }) })
  const revokeAll = useMutation({
    mutationFn: (reason: string) => api.post<{ revoked: number }>('/emergency/revoke-all-credentials', { reason }),
    onSuccess: r => { qc.invalidateQueries({ queryKey: ['agents'] }); toast.ok(`${r.revoked} credentials revoked`); setEmergency(false) },
    onError: e => toast.error(e),
  })
  const security = can('platform_admin', 'tenant_admin', 'security_admin')

  return (
    <>
      <PageHeading eyebrow="ACCESS CONTROL" title="Agents & Credentials" subtitle="Each AI agent is a principal with its own keys. Keys are shown once and stored only as hashes."
        actions={<>
          {security && <button className="btn danger" onClick={() => setEmergency(true)}><ShieldOff size={13} />Emergency revoke</button>}
          {can('platform_admin', 'tenant_admin', 'security_admin', 'developer') && <button className="btn primary" onClick={() => setCreating(true)}><Plus size={14} />Register agent</button>}
        </>} />
      <Panel>
        <QueryState q={q} empty={d => d.items.length === 0} emptyText="Register an agent, then create a key for it to connect to the MCP endpoint.">
          {d => <>
            <div className="table-wrap"><table>
              <thead><tr><th>AGENT</th><th>STATUS</th><th>ENVIRONMENT</th><th>ACTIVE KEYS</th><th>LAST ACTIVITY</th><th>TAGS</th></tr></thead>
              <tbody>{d.items.map(a => <tr key={a.id}>
                <td><div className="server-name"><div className="server-icon"><Bot size={14} /></div><div><Link to={`/agents/${a.id}`}><b>{a.name}</b></Link><small>{a.description}</small></div></div></td>
                <td><Status value={a.status} /></td><td><span className="category">{a.environment}</span></td>
                <td>{a.active_credentials ?? 0}</td><td className="muted">{timeAgo(a.last_activity_at)}</td>
                <td><div className="chips">{a.tags.map(t => <span key={t} className="chip">{t}</span>)}</div></td>
              </tr>)}</tbody>
            </table></div>
            <Pager page={page} pageSize={PAGE} total={d.total} hasNext={!!d.next_cursor} onPage={p => {
              if (p > page && d.next_cursor) setCursors(c => { const n = c.slice(0, p); n[p] = d.next_cursor; return n })
              setPage(p)
            }} />
          </>}
        </QueryState>
      </Panel>
      {creating && <CreateAgent tenantId={tenantId} onClose={() => setCreating(false)} />}
      {emergency && <EmergencyRevoke busy={revokeAll.isPending} onConfirm={r => revokeAll.mutate(r)} onClose={() => setEmergency(false)} />}
    </>
  )
}

function EmergencyRevoke({ busy, onConfirm, onClose }: { busy: boolean; onConfirm: (reason: string) => void; onClose: () => void }) {
  const [reason, setReason] = useState('')
  return <Confirm danger title="Revoke ALL agent credentials" confirmLabel="Revoke all keys" typed="REVOKE ALL" busy={busy}
    message={<>Every active agent key in this tenant stops working immediately. Agents need new keys to reconnect. Use this when a key leaks and you can't tell which one.</>}
    onConfirm={() => onConfirm(reason)} onClose={onClose}>
    <Field label="Reason (recorded in the audit log)"><input value={reason} onChange={e => setReason(e.target.value)} /></Field>
  </Confirm>
}

function CreateAgent({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [environment, setEnvironment] = useState('production')
  const [tags, setTags] = useState<string[]>([])
  const qc = useQueryClient()
  const toast = useToast()
  const nav = useNavigate()
  const m = useMutation({
    mutationFn: () => api.post<Agent>(`/tenants/${tenantId}/agents`, { name, description, environment, tags }),
    onSuccess: a => { qc.invalidateQueries({ queryKey: ['agents'] }); toast.ok('Agent registered. Create a key to connect it.'); nav(`/agents/${a.id}`) },
    onError: e => toast.error(e),
  })
  return <Modal title="Register agent" onClose={onClose} footer={<>
    <button className="btn secondary" onClick={onClose}>Cancel</button>
    <button className="btn primary" disabled={name.trim().length < 2 || m.isPending} onClick={() => m.mutate()}>{m.isPending && <Loader2 size={13} className="spin" />}Register</button>
  </>}>
    <Field label="Name" hint="Letters, digits, spaces, dot, underscore, hyphen."><input value={name} onChange={e => setName(e.target.value)} placeholder="hr-assistant" autoFocus /></Field>
    <Field label="Description"><textarea value={description} onChange={e => setDescription(e.target.value)} /></Field>
    <Field label="Environment"><select value={environment} onChange={e => setEnvironment(e.target.value)}><option>production</option><option>test</option><option>development</option></select></Field>
    <Field label="Tags"><ListInput value={tags} onChange={setTags} /></Field>
  </Modal>
}
