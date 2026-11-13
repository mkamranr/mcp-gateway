import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bot, CheckCircle2, Clock, Loader2, Search, ShieldAlert, XCircle } from 'lucide-react'
import { useAuth } from '../../app/auth'
import { api, ApiError, errorMessage } from '../../services/api'
import { dateTime, shortHash, timeAgo } from '../../services/format'
import type { Approval, Page } from '../../services/types'
import { Badge, Callout, DecisionBadge, Drawer, Field, JsonView, Modal, PageHeading, Pager, Panel, QueryState, RiskBadge, Status, Tabs, useToast } from '../../components/ui'

type Tab = 'pending' | 'approved' | 'rejected' | 'expired' | 'cancelled'
const PAGE = 25
const STATUS_COLOR: Record<string, 'green' | 'red' | 'orange' | 'purple' | 'blue'> = {
  PENDING: 'orange', APPROVED: 'blue', REVALIDATING: 'blue', EXECUTING: 'blue', COMPLETED: 'green',
  REJECTED: 'red', EXPIRED: 'orange', CANCELLED: 'red', CANCELLED_BY_ADMIN: 'red', FAILED: 'red', EXECUTION_ABORTED: 'red',
}

export function ApprovalsPage() {
  const { id } = useParams()
  const nav = useNavigate()
  const [tab, setTab] = useState<Tab>('pending')
  const [risk, setRisk] = useState('')
  const [tool, setTool] = useState('')
  const [requester, setRequester] = useState('')
  const [page, setPage] = useState(0)
  const [cursors, setCursors] = useState<(string | null)[]>([null])
  const reset = () => { setPage(0); setCursors([null]) }
  const q = useQuery({
    queryKey: ['approvals', tab, risk, tool, requester, cursors[page]],
    queryFn: () => api.get<Page<Approval> & { counts: { pending: number; oldest_pending_age_seconds: number } }>('/approvals', { status: tab, risk, tool, requester, limit: PAGE, cursor: cursors[page] }),
    refetchInterval: tab === 'pending' ? 15_000 : false,
  })
  const pendingCount = q.data?.counts?.pending

  return (
    <>
      <PageHeading eyebrow="ACCESS CONTROL" title="Approvals" subtitle="Calls that need human sign-off. Approved calls are re-checked against current policy before they run, and run exactly once." />
      <Tabs large value={tab} onChange={v => { setTab(v); reset() }} options={[
        { value: 'pending', label: `Pending${pendingCount ? ` (${pendingCount})` : ''}` }, { value: 'approved', label: 'Approved' },
        { value: 'rejected', label: 'Rejected' }, { value: 'expired', label: 'Expired' }, { value: 'cancelled', label: 'Cancelled' },
      ]} />
      <Panel>
        <div className="filters">
          <div className="search"><Search size={14} /><input placeholder="Tool name" value={tool} onChange={e => { setTool(e.target.value); reset() }} /></div>
          <input placeholder="Requester (agent id or name)" value={requester} onChange={e => { setRequester(e.target.value); reset() }} />
          <select value={risk} onChange={e => { setRisk(e.target.value); reset() }} aria-label="Risk"><option value="">Any risk</option><option>low</option><option>medium</option><option>high</option><option>critical</option></select>
        </div>
        <QueryState q={q} empty={d => d.items.length === 0} emptyText={tab === 'pending' ? 'No requests are waiting for approval.' : 'No requests in this state.'}>
          {d => <>
            <div className="approval-cards">{d.items.map(a => (
              <div className="approval-card clickable" key={a.id} onClick={() => nav(`/approvals/${a.id}`)} style={{ borderLeftColor: a.risk_level === 'critical' ? '#ef626c' : a.risk_level === 'high' ? '#e9a23b' : '#478cf6' }}>
                <div className="approval-icon"><Bot size={17} /></div>
                <div className="approval-main">
                  <div className="approval-title"><b className="mono">{a.gateway_name}</b><RiskBadge risk={a.risk_level} /><Badge color={STATUS_COLOR[a.status]}>{a.status.replace(/_/g, ' ')}</Badge>
                    {a.required_approvals > 1 && <Badge color="purple">{a.approvals.length}/{a.required_approvals} approvals</Badge>}</div>
                  <p>{a.purpose || <span className="muted">No purpose given</span>}</p>
                  <small>Requested by <b>{a.requester?.name || a.requester?.id}</b> · {timeAgo(a.created_at)}{a.status === 'PENDING' && <> · expires {timeAgo(a.expires_at)}</>}</small>
                </div>
                <div className="approval-actions"><button className="btn secondary" onClick={e => { e.stopPropagation(); nav(`/approvals/${a.id}`) }}>Review</button></div>
              </div>
            ))}</div>
            <Pager page={page} pageSize={PAGE} total={d.total} hasNext={!!d.next_cursor} onPage={p => {
              if (p > page && d.next_cursor) setCursors(c => { const n = c.slice(0, p); n[p] = d.next_cursor; return n })
              setPage(p)
            }} />
          </>}
        </QueryState>
      </Panel>
      {id && <ApprovalDetail id={id} onClose={() => nav('/approvals')} />}
    </>
  )
}

function ApprovalDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['approval', id], queryFn: () => api.get<Approval>(`/approvals/${id}`) })
  const { can } = useAuth()
  const qc = useQueryClient()
  const toast = useToast()
  const [decision, setDecision] = useState<'approve' | 'reject' | null>(null)
  const [comment, setComment] = useState('')
  const [typed, setTyped] = useState('')
  const [err, setErr] = useState<ApiError | null>(null)
  const a = q.data

  const act = useMutation({
    mutationFn: (kind: 'approve' | 'reject') => api.post<Approval>(`/approvals/${id}/${kind}`, kind === 'approve' ? { comment, confirm_critical: a?.risk_level === 'critical' } : { comment }),
    onSuccess: (r, kind) => {
      qc.invalidateQueries({ queryKey: ['approvals'] }); qc.invalidateQueries({ queryKey: ['approval', id] }); qc.invalidateQueries({ queryKey: ['approvals-count'] })
      toast.ok(kind === 'reject' ? 'Request rejected' : r.status === 'APPROVED' ? 'Approved. Queued for revalidation and execution.' : 'Approval recorded. Waiting for another approver.')
      setDecision(null); setComment(''); setTyped(''); setErr(null)
    },
    onError: e => { if (e instanceof ApiError) setErr(e); else toast.error(e) },
  })

  const canAct = !!a && a.status === 'PENDING' && can('platform_admin', 'tenant_admin', 'security_admin', 'approver')
  const policyCfg = a?.approval_policy || {}
  const commentRequired = decision === 'reject' ? policyCfg.require_comment_on_reject !== false : !!policyCfg.require_comment_on_approve
  const criticalOk = a?.risk_level !== 'critical' || decision !== 'approve' || typed === a.tool_name

  return (
    <Drawer title="Approval request" onClose={onClose} footer={canAct && <>
      <button className="btn danger" disabled={!a?.can_decide} onClick={() => { setDecision('reject'); setErr(null) }}><XCircle size={13} />Reject</button>
      <button className="btn primary" disabled={!a?.can_decide} onClick={() => { setDecision('approve'); setErr(null) }}><CheckCircle2 size={13} />Approve</button>
    </>}>
      <QueryState q={q}>{a => <>
        <div className="approval-title" style={{ marginBottom: 10 }}><b className="mono" style={{ fontSize: 13 }}>{a.gateway_name}</b><RiskBadge risk={a.risk_level} /><Badge color={STATUS_COLOR[a.status]}>{a.status.replace(/_/g, ' ')}</Badge></div>
        {a.separation_of_duties_warning && <Callout kind="danger"><ShieldAlert size={12} /> You requested this call, or own the requesting agent. Separation of duties means someone else has to approve it.</Callout>}
        {a.status === 'PENDING' && !a.can_decide && !a.separation_of_duties_warning && <Callout kind="warn">You can't decide this request: you lack an approver role for it, or you already approved it.</Callout>}
        {a.changes_since_request && a.changes_since_request.length > 0 && <Callout kind="warn">Changed since the request: {a.changes_since_request.map(c => c.replace(/_/g, ' ')).join(', ')}. The call is revalidated against current state before it runs.</Callout>}
        {a.integrity && a.integrity !== 'verified' && <Callout kind="danger">Argument integrity check failed ({a.integrity}). Don't approve. Execution would be aborted.</Callout>}
        {a.risk_level === 'critical' && a.status === 'PENDING' && <Callout kind="danger">Critical action. It may be destructive or irreversible.</Callout>}

        <dl className="kv">
          <dt>Requester</dt><dd>{a.requester?.name || a.requester?.id} <span className="muted">({a.requester?.type})</span></dd>
          <dt>Server</dt><dd>{a.server_name}</dd>
          <dt>Purpose</dt><dd>{a.purpose || <span className="muted">not stated</span>}</dd>
          <dt>Requested</dt><dd>{dateTime(a.created_at)}</dd>
          <dt>Expires</dt><dd>{dateTime(a.expires_at)} {a.status === 'PENDING' && <span className="muted">({timeAgo(a.expires_at)})</span>}</dd>
          <dt>Approvals</dt><dd>{a.approvals.length} of {a.required_approvals} required</dd>
          <dt>Argument hash</dt><dd className="mono">{shortHash(a.arguments_hash)} {a.integrity === 'verified' && <Badge color="green">verified</Badge>}</dd>
          {(policyCfg.reasons?.length ?? 0) > 0 && <><dt>Why approval</dt><dd>{policyCfg.reasons!.join(', ')}</dd></>}
        </dl>

        <div className="section-title">Arguments</div>
        <p className="muted" style={{ fontSize: 9, margin: '0 0 4px' }}>Sensitive fields are masked by the server. This exact payload, verified by hash, is what runs.</p>
        <JsonView value={a.arguments ?? a.arguments_preview} />

        {(a.approvals.length > 0 || a.rejection || a.cancellation || a.execution) && <>
          <div className="section-title">Decision trail</div>
          <div className="timeline">
            <div><b>Requested</b><small>{dateTime(a.created_at)} · {a.requester?.name}</small></div>
            {a.approvals.map(x => <div key={x.approver_id + x.at}><b>Approved by {x.approver_name}</b><small>{dateTime(x.at)}{x.comment ? ` · “${x.comment}”` : ''}</small></div>)}
            {a.rejection && <div><b>Rejected by {a.rejection.by_name}</b><small>{dateTime(a.rejection.at)} · “{a.rejection.comment}”</small></div>}
            {a.cancellation && <div><b>Cancelled</b><small>{dateTime(a.cancellation.at)} · {a.cancellation.reason}</small></div>}
            {a.executed_at && <div><b>Executed</b><small>{dateTime(a.executed_at)}</small></div>}
            {a.execution && <div><b>Execution {a.execution.status || ''}</b><small>{a.execution.error_code ? `${a.execution.error_code}: ${a.execution.message || ''}` : 'completed'}</small></div>}
          </div>
        </>}

        {a.related_invocations && a.related_invocations.length > 0 && <>
          <div className="section-title">Related invocations</div>
          <div className="table-wrap"><table><thead><tr><th>TIME</th><th>DECISION</th><th>STATUS</th><th>ERROR</th></tr></thead>
            <tbody>{a.related_invocations.map(i => <tr key={i.id}><td>{dateTime(i.created_at)}</td><td><DecisionBadge value={i.decision} /></td><td><Status value={i.status} /></td><td className="mono">{i.error_code || '-'}</td></tr>)}</tbody></table></div>
        </>}

        {decision && <Modal title={decision === 'approve' ? 'Approve request' : 'Reject request'} onClose={() => setDecision(null)} footer={<>
          <button className="btn secondary" onClick={() => setDecision(null)}>Cancel</button>
          <button className={decision === 'approve' ? 'btn primary' : 'btn danger'} disabled={act.isPending || (commentRequired && !comment.trim()) || !criticalOk} onClick={() => act.mutate(decision)}>
            {act.isPending ? <Loader2 size={13} className="spin" /> : decision === 'approve' ? <CheckCircle2 size={13} /> : <XCircle size={13} />}{decision === 'approve' ? 'Approve' : 'Reject'}
          </button>
        </>}>
          {err && <Callout kind="danger">{errorMessage(err)}</Callout>}
          <p style={{ fontSize: 11 }}>{decision === 'approve'
            ? <>Approve <b className="mono">{a.gateway_name}</b> for <b>{a.requester?.name}</b>{a.required_approvals > 1 && a.approvals.length + 1 < a.required_approvals ? '. Another approver is still needed.' : '. The worker revalidates it and runs it once.'}</>
            : <>The request is closed and never runs.</>}</p>
          <Field label={`Comment${commentRequired ? ' (required)' : ''}`}><textarea value={comment} onChange={e => setComment(e.target.value)} autoFocus /></Field>
          {decision === 'approve' && a.risk_level === 'critical' && <Field label={`Type the tool name "${a.tool_name}" to confirm this critical action`}><input value={typed} onChange={e => setTyped(e.target.value)} /></Field>}
          <p className="muted" style={{ fontSize: 9 }}><Clock size={10} /> Your decision is recorded in the audit log.</p>
        </Modal>}
      </>}</QueryState>
    </Drawer>
  )
}
