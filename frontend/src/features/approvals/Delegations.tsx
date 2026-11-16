import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Loader2, Plus, UserCheck } from 'lucide-react'
import { useAuth } from '../../app/auth'
import { api, ApiError, errorMessage } from '../../services/api'
import { dateTime, timeAgo } from '../../services/format'
import { APPROVERS, SECURITY } from '../../services/roles'
import type { DelegateCandidate, Delegation } from '../../services/types'
import { Badge, Callout, Confirm, Field, Modal, Panel, QueryState, useToast } from '../../components/ui'

const STATUS_COLOR: Record<Delegation['status'], 'green' | 'blue' | 'orange' | 'red'> = {
  active: 'green', scheduled: 'blue', expired: 'orange', revoked: 'red',
}

/** "YYYY-MM-DDTHH:mm" in local time, for datetime-local inputs. */
function localInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}

export function Delegations() {
  const { me, can } = useAuth()
  const isAdmin = can(...SECURITY)
  const canDelegate = can(...APPROVERS)
  const [everyone, setEveryone] = useState(false)
  const [past, setPast] = useState(false)
  const [creating, setCreating] = useState(false)
  const [revoking, setRevoking] = useState<Delegation | null>(null)
  const qc = useQueryClient()
  const toast = useToast()
  const q = useQuery({
    queryKey: ['delegations', everyone, past],
    queryFn: () => api.get<{ items: Delegation[] }>('/approvals/delegations', { scope: everyone ? 'all' : 'mine', include_past: past }),
  })
  const revoke = useMutation({
    mutationFn: (d: Delegation) => api.del<Delegation>(`/approvals/delegations/${d.id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['delegations'] }); toast.ok('Delegation revoked'); setRevoking(null) },
    onError: e => toast.error(e),
  })
  const mine = (id: string) => id === me?.principal_id

  return (
    <Panel title="Delegations" subtitle="While you are away, a colleague can decide approval requests with your authority. Separation of duties still applies to both of you, and every decision records who acted for whom."
      actions={canDelegate || isAdmin ? <button className="btn primary" onClick={() => setCreating(true)}><Plus size={13} />Delegate approvals</button> : undefined}>
      <div className="filters">
        {isAdmin && <label className="check"><input type="checkbox" checked={everyone} onChange={e => setEveryone(e.target.checked)} />All delegations in this tenant</label>}
        <label className="check"><input type="checkbox" checked={past} onChange={e => setPast(e.target.checked)} />Include expired and revoked</label>
      </div>
      <QueryState q={q} empty={d => d.items.length === 0} emptyText={everyone ? 'No delegations in this tenant.' : 'Nobody is covering for you, and you are not covering for anyone.'}>
        {d => <div className="table-wrap"><table>
          <thead><tr><th>FROM</th><th>TO</th><th>PERIOD</th><th>STATUS</th><th>REASON</th><th /></tr></thead>
          <tbody>{d.items.map(x => (
            <tr key={x.id}>
              <td>{x.delegator_name}{mine(x.delegator_user_id) && <span className="muted"> (you)</span>}</td>
              <td><UserCheck size={12} style={{ verticalAlign: -2, marginRight: 4 }} />{x.delegate_name}{mine(x.delegate_user_id) && <span className="muted"> (you)</span>}</td>
              <td>{dateTime(x.starts_at)} → {dateTime(x.ends_at)}{x.status === 'active' && <div className="muted" style={{ fontSize: 9 }}>ends {timeAgo(x.ends_at)}</div>}</td>
              <td><Badge color={STATUS_COLOR[x.status]}>{x.status}</Badge></td>
              <td>{x.reason || <span className="muted">-</span>}</td>
              <td style={{ textAlign: 'right' }}>{(x.status === 'active' || x.status === 'scheduled') && <button className="small-btn" onClick={() => setRevoking(x)}>Revoke</button>}</td>
            </tr>
          ))}</tbody>
        </table></div>}
      </QueryState>
      {creating && <DelegationDialog isAdmin={isAdmin} canDelegate={canDelegate} onClose={() => setCreating(false)} />}
      {revoking && <Confirm danger title="Revoke delegation" confirmLabel="Revoke" busy={revoke.isPending}
        message={<>{revoking.delegate_name} immediately loses the authority to decide requests for {revoking.delegator_name}. Decisions already made stay valid.</>}
        onConfirm={() => revoke.mutate(revoking)} onClose={() => setRevoking(null)} />}
    </Panel>
  )
}

function DelegationDialog({ isAdmin, canDelegate, onClose }: { isAdmin: boolean; canDelegate: boolean; onClose: () => void }) {
  const { me } = useAuth()
  const qc = useQueryClient()
  const toast = useToast()
  const now = new Date()
  const [delegator, setDelegator] = useState(canDelegate ? '' : '__pick__')
  const [delegate, setDelegate] = useState('')
  const [start, setStart] = useState(localInput(now))
  const [end, setEnd] = useState(localInput(new Date(now.getTime() + 7 * 864e5)))
  const [reason, setReason] = useState('')
  const [err, setErr] = useState<ApiError | null>(null)
  const people = useQuery({ queryKey: ['delegate-candidates'], queryFn: () => api.get<{ items: DelegateCandidate[] }>('/approvals/delegations/candidates') })
  const fromId = delegator && delegator !== '__pick__' ? delegator : null
  const save = useMutation({
    mutationFn: () => api.post<Delegation>('/approvals/delegations', {
      delegate_user_id: delegate, delegator_user_id: fromId, reason,
      starts_at: new Date(start).toISOString(), ends_at: new Date(end).toISOString(),
    }),
    onSuccess: d => { qc.invalidateQueries({ queryKey: ['delegations'] }); toast.ok(`${d.delegate_name} can now decide requests for ${d.delegator_name}`); onClose() },
    onError: e => { if (e instanceof ApiError) setErr(e); else toast.error(e) },
  })
  const candidates = people.data?.items || []
  const delegates = candidates.filter(c => c.id !== fromId)
  const ready = !!delegate && !!end && delegator !== '__pick__'

  return (
    <Modal title="Delegate approvals" onClose={onClose} footer={<>
      <button className="btn secondary" onClick={onClose}>Cancel</button>
      <button className="btn primary" disabled={!ready || save.isPending} onClick={() => save.mutate()}>{save.isPending && <Loader2 size={13} className="spin" />}Delegate</button>
    </>}>
      {err && <Callout kind="danger">{errorMessage(err)}</Callout>}
      {isAdmin && <Field label="Whose approvals" hint="Administrators can set up cover for an approver who is already away.">
        <select value={delegator} onChange={e => setDelegator(e.target.value)}>
          {canDelegate && <option value="">Mine ({me?.display_name})</option>}
          {!canDelegate && <option value="__pick__">Choose an approver…</option>}
          {candidates.filter(c => c.can_approve).map(c => <option key={c.id} value={c.id}>{c.display_name} ({c.username})</option>)}
        </select>
      </Field>}
      <Field label="Delegate to" hint="They don't need an approver role of their own. They act with the delegator's current roles and groups, and cannot pass the delegation on.">
        <select value={delegate} onChange={e => setDelegate(e.target.value)}>
          <option value="">Choose a colleague…</option>
          {delegates.map(c => <option key={c.id} value={c.id}>{c.display_name} ({c.username})</option>)}
        </select>
      </Field>
      <div className="field-row">
        <Field label="From"><input type="datetime-local" value={start} onChange={e => setStart(e.target.value)} /></Field>
        <Field label="Until" hint="At most 90 days."><input type="datetime-local" value={end} onChange={e => setEnd(e.target.value)} /></Field>
      </div>
      <Field label="Reason (optional)"><input value={reason} maxLength={500} placeholder="e.g. Annual leave" onChange={e => setReason(e.target.value)} /></Field>
    </Modal>
  )
}
