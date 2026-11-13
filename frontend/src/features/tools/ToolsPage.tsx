import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { api } from '../../services/api'
import { num } from '../../services/format'
import type { Page, Server, Tool } from '../../services/types'
import { Badge, PageHeading, Pager, Panel, QueryState, RiskBadge, Status } from '../../components/ui'

const PAGE = 50

export function ToolsPage() {
  const [f, setF] = useState({ search: '', server_id: '', risk: '', enabled: '', review_status: '', approval_required: '', environment: '' })
  const [page, setPage] = useState(0)
  const [cursors, setCursors] = useState<(string | null)[]>([null])
  const servers = useQuery({ queryKey: ['servers', 'all'], queryFn: () => api.get<Page<Server>>('/servers', { limit: 200 }) })
  const q = useQuery({
    queryKey: ['tools', f, cursors[page]],
    queryFn: () => api.get<Page<Tool>>('/tools', { ...f, limit: PAGE, cursor: cursors[page] }),
  })
  const set = (k: keyof typeof f, v: string) => { setF(x => ({ ...x, [k]: v })); setPage(0); setCursors([null]) }

  return (
    <>
      <PageHeading eyebrow="REGISTRY" title="Tool Catalog" subtitle="Every discovered tool. New tools stay disabled until an administrator reviews them, assigns a risk level and enables them." />
      <Panel>
        <div className="filters">
          <div className="search"><Search size={14} /><input placeholder="Search tools" value={f.search} onChange={e => set('search', e.target.value)} /></div>
          <select value={f.server_id} onChange={e => set('server_id', e.target.value)} aria-label="Server"><option value="">All servers</option>{servers.data?.items.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}</select>
          <select value={f.risk} onChange={e => set('risk', e.target.value)} aria-label="Risk"><option value="">Any risk</option><option>low</option><option>medium</option><option>high</option><option>critical</option></select>
          <select value={f.enabled} onChange={e => set('enabled', e.target.value)} aria-label="Enabled"><option value="">Enabled & disabled</option><option value="true">Enabled</option><option value="false">Disabled</option></select>
          <select value={f.review_status} onChange={e => set('review_status', e.target.value)} aria-label="Review status"><option value="">Any review state</option><option value="pending_review">Pending review</option><option value="schema_changed">Schema changed</option><option value="approved">Reviewed</option></select>
          <select value={f.approval_required} onChange={e => set('approval_required', e.target.value)} aria-label="Approval"><option value="">Approval: any</option><option value="true">Requires approval</option><option value="false">No approval</option></select>
          <select value={f.environment} onChange={e => set('environment', e.target.value)} aria-label="Environment"><option value="">All environments</option><option>production</option><option>test</option><option>development</option></select>
        </div>
        <QueryState q={q} empty={d => d.items.length === 0} emptyText="No tools match. Register a server and refresh its tools to populate the catalog.">
          {d => <>
            <div className="table-wrap"><table>
              <thead><tr><th>TOOL</th><th>SERVER</th><th>RISK</th><th>STATUS</th><th>REVIEW</th><th>APPROVAL</th><th>CALLS (7D)</th><th>SCHEMA</th></tr></thead>
              <tbody>{d.items.map(t => (
                <tr key={t.id}>
                  <td><Link to={`/tools/${t.id}`}><b className="mono">{t.gateway_name}</b></Link><div className="muted" style={{ fontSize: 9, marginTop: 3, maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis' }}>{t.description}</div></td>
                  <td>{t.server_name || '-'}</td>
                  <td><RiskBadge risk={t.risk_level} /></td>
                  <td>{!t.available ? <Badge color="red">unavailable</Badge> : <Status value={t.enabled ? 'enabled' : 'disabled'} />}</td>
                  <td><Status value={t.review_status} label={t.review_status === 'approved' ? 'reviewed' : undefined} /></td>
                  <td>{t.approval.required ? <Badge color="purple">{t.approval.policy.required_approvals}-person</Badge> : <span className="muted">-</span>}</td>
                  <td>{num(t.calls_7d ?? 0)}</td>
                  <td className="muted">v{t.schema_version}</td>
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
    </>
  )
}
