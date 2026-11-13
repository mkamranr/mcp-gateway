import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Download, Filter, X } from 'lucide-react'
import { useAuth } from '../../app/auth'
import { api } from '../../services/api'
import { dateTime, shortHash } from '../../services/format'
import type { AuditEvent, Page } from '../../services/types'
import { Badge, DecisionBadge, Drawer, JsonView, PageHeading, Pager, Panel, QueryState, Status, useToast } from '../../components/ui'

const PAGE = 50
const EMPTY = { start: '', end: '', event_type: '', decision: '', status: '', principal: '', tool: '', severity: '', request_id: '', tenant: '' }
const SEVERITY_COLOR: Record<string, 'red' | 'orange' | 'blue' | undefined> = { critical: 'red', high: 'red', medium: 'orange', low: 'blue' }

export function AuditPage() {
  const { me } = useAuth()
  const toast = useToast()
  const [draft, setDraft] = useState(EMPTY)
  const [filters, setFilters] = useState(EMPTY)
  const [page, setPage] = useState(0)
  const [cursors, setCursors] = useState<(string | null)[]>([null])
  const [selected, setSelected] = useState<string | null>(null)
  const [exporting, setExporting] = useState(false)

  const params = { ...filters, start: filters.start ? new Date(filters.start).toISOString() : '', end: filters.end ? new Date(filters.end).toISOString() : '' }
  const q = useQuery({ queryKey: ['audit', params, cursors[page]], queryFn: () => api.get<Page<AuditEvent>>('/audit/events', { ...params, limit: PAGE, cursor: cursors[page] }) })
  const apply = () => { setFilters(draft); setPage(0); setCursors([null]) }
  const clear = () => { setDraft(EMPTY); setFilters(EMPTY); setPage(0); setCursors([null]) }
  const doExport = async (format: 'csv' | 'json') => {
    setExporting(true)
    try {
      const f = Object.fromEntries(Object.entries(params).filter(([, v]) => v))
      await api.download('/audit/export', { format, filters: f }, `audit-export.${format}`)
      toast.ok('Export downloaded. The export itself is recorded in the audit log.')
    } catch (e) { toast.error(e) } finally { setExporting(false) }
  }
  const set = (k: keyof typeof EMPTY, v: string) => setDraft(d => ({ ...d, [k]: v }))

  return (
    <>
      <PageHeading eyebrow="OBSERVABILITY" title="Audit Logs" subtitle="Append-only record of every decision, invocation, approval and administrative change. Arguments are stored only as hashes."
        actions={<>
          <button className="btn secondary" disabled={exporting} onClick={() => doExport('csv')}><Download size={13} />Export CSV</button>
          <button className="btn secondary" disabled={exporting} onClick={() => doExport('json')}><Download size={13} />Export JSON</button>
        </>} />
      <Panel>
        <form className="filters" onSubmit={e => { e.preventDefault(); apply() }}>
          <input type="datetime-local" title="From" aria-label="From" value={draft.start} onChange={e => set('start', e.target.value)} />
          <input type="datetime-local" title="To" aria-label="To" value={draft.end} onChange={e => set('end', e.target.value)} />
          <input placeholder="Event type (e.g. tool.*)" value={draft.event_type} onChange={e => set('event_type', e.target.value)} />
          <input placeholder="Principal (id or name)" value={draft.principal} onChange={e => set('principal', e.target.value)} />
          <input placeholder="Tool" value={draft.tool} onChange={e => set('tool', e.target.value)} />
          <select value={draft.decision} onChange={e => set('decision', e.target.value)} aria-label="Decision"><option value="">Any decision</option><option>ALLOW</option><option>DENY</option><option>REQUIRE_APPROVAL</option></select>
          <select value={draft.status} onChange={e => set('status', e.target.value)} aria-label="Status"><option value="">Any status</option><option>completed</option><option>rejected</option><option>failed</option><option>tool_error</option><option>pending</option><option>success</option></select>
          <select value={draft.severity} onChange={e => set('severity', e.target.value)} aria-label="Severity"><option value="">Any severity</option><option>low</option><option>medium</option><option>high</option><option>critical</option></select>
          <input placeholder="Request ID" value={draft.request_id} onChange={e => set('request_id', e.target.value)} />
          {me?.is_platform_admin && <select value={draft.tenant} onChange={e => set('tenant', e.target.value)} aria-label="Tenant"><option value="">Current tenant</option><option value="*">All tenants</option>{me.tenants.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}</select>}
          <button className="btn primary" type="submit"><Filter size={12} />Apply</button>
          <button className="btn ghost" type="button" onClick={clear}><X size={12} />Clear</button>
        </form>
        <QueryState q={q} empty={d => d.items.length === 0} emptyText="No events match these filters.">
          {d => <>
            <div className="table-wrap"><table>
              <thead><tr><th>TIME</th><th>EVENT</th><th>SEVERITY</th><th>PRINCIPAL</th><th>RESOURCE</th><th>DECISION</th><th>REASON</th><th>STATUS</th><th>DURATION</th></tr></thead>
              <tbody>{d.items.map(e => (
                <tr key={e.id} className="clickable" onClick={() => setSelected(e.event_id || e.id)}>
                  <td>{dateTime(e.timestamp)}</td><td className="mono">{e.event_type}</td>
                  <td>{e.severity && e.severity !== 'info' ? <Badge color={SEVERITY_COLOR[e.severity]}>{e.severity}</Badge> : <span className="muted">info</span>}</td>
                  <td>{e.principal?.name || e.principal?.id || <span className="muted">system</span>}</td>
                  <td className="mono" style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis' }}>{e.resource?.gateway_name || e.resource?.tool_name || e.resource?.server_name || e.resource?.policy_name || e.resource?.agent_name || '-'}</td>
                  <td><DecisionBadge value={e.decision} /></td><td className="mono muted">{e.reason_code || '-'}</td>
                  <td>{e.status ? <Status value={e.status} /> : '-'}</td><td>{e.duration_ms != null ? `${e.duration_ms} ms` : '-'}</td>
                </tr>
              ))}</tbody>
            </table></div>
            <Pager page={page} pageSize={PAGE} total={d.total} hasNext={!!d.next_cursor} onPage={p => {
              if (p > page && d.next_cursor) setCursors(c => { const n = c.slice(0, p); n[p] = d.next_cursor; return n })
              setPage(p)
            }} />
          </>}
        </QueryState>
      </Panel>
      {selected && <EventDrawer id={selected} onClose={() => setSelected(null)} onSelect={setSelected} />}
    </>
  )
}

function EventDrawer({ id, onClose, onSelect }: { id: string; onClose: () => void; onSelect: (id: string) => void }) {
  const q = useQuery({ queryKey: ['audit-event', id], queryFn: () => api.get<AuditEvent>(`/audit/events/${id}`) })
  return <Drawer title="Audit event" onClose={onClose}>
    <QueryState q={q}>{e => <>
      <dl className="kv">
        <dt>Event</dt><dd className="mono">{e.event_type}</dd>
        <dt>Time</dt><dd>{dateTime(e.timestamp)}</dd>
        <dt>Event ID</dt><dd className="mono">{e.event_id}</dd>
        <dt>Severity</dt><dd>{e.severity}</dd>
        <dt>Principal</dt><dd>{e.principal ? `${e.principal.name || e.principal.id} (${e.principal.type})` : 'system'}{e.principal?.credential_id && <span className="muted mono"> · key {e.principal.credential_id.slice(0, 10)}</span>}</dd>
        {e.delegated_by_user_id && <><dt>Delegated by</dt><dd className="mono">{e.delegated_by_user_id}</dd></>}
        <dt>Decision</dt><dd><DecisionBadge value={e.decision} /> {e.reason_code && <span className="mono muted">{e.reason_code}</span>}</dd>
        <dt>Status</dt><dd>{e.status || '-'}{e.duration_ms != null && ` · ${e.duration_ms} ms`}</dd>
        {e.policy_ids?.length > 0 && <><dt>Policies</dt><dd>{e.policy_ids.map(p => <Link key={p} className="mono" to={`/policies?id=${p}`} style={{ marginRight: 6 }}>{p.slice(0, 12)}</Link>)}</dd></>}
        <dt>Request ID</dt><dd className="mono">{e.request_id || '-'}</dd>
        {e.invocation_id && <><dt>Invocation</dt><dd className="mono">{e.invocation_id}</dd></>}
        {e.approval_id && <><dt>Approval</dt><dd><Link className="mono" to={`/approvals/${e.approval_id}`}>{e.approval_id}</Link>{e.approval && <> · {e.approval.status}</>}</dd></>}
        {e.input_hash && <><dt>Input hash</dt><dd className="mono">{shortHash(e.input_hash)}</dd></>}
        {e.output_hash && <><dt>Output hash</dt><dd className="mono">{shortHash(e.output_hash)}</dd></>}
      </dl>
      {e.resource && Object.keys(e.resource).length > 0 && <><div className="section-title">Resource</div><JsonView value={e.resource} /></>}
      {e.metadata && Object.keys(e.metadata).length > 0 && <><div className="section-title">Metadata</div><JsonView value={e.metadata} /></>}
      {e.correlated && e.correlated.length > 0 && <>
        <div className="section-title">Correlated events ({e.correlated.length})</div>
        <div className="timeline">{e.correlated.map(c => <div key={c.id}>
          <button className="link-btn mono" onClick={() => onSelect(c.event_id || c.id)}>{c.event_type}</button> {c.decision && <DecisionBadge value={c.decision} />} {c.status && <Status value={c.status} />}
          <small>{dateTime(c.timestamp)} · {c.principal?.name || c.principal?.id || 'system'}</small>
        </div>)}</div>
      </>}
    </>}</QueryState>
  </Drawer>
}
