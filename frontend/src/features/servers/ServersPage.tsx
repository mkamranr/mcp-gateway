import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, CheckCircle2, Plus, RefreshCw, Search, Server as ServerIcon, Wrench, XCircle } from 'lucide-react'
import { useAuth } from '../../app/auth'
import { REGISTRY_WRITE } from '../../services/roles'
import { api } from '../../services/api'
import { timeAgo } from '../../services/format'
import type { Page, Server } from '../../services/types'
import { Metric, PageHeading, Pager, Panel, QueryState, Status, useToast } from '../../components/ui'
import { ServerWizard } from './ServerWizard'

const PAGE = 25

export function ServersPage() {
  const { can } = useAuth()
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(0)
  const [cursors, setCursors] = useState<(string | null)[]>([null])
  const [adding, setAdding] = useState(false)
  const qc = useQueryClient()
  const toast = useToast()

  const q = useQuery({
    queryKey: ['servers', search, cursors[page]],
    queryFn: () => api.get<Page<Server>>('/servers', { search, limit: PAGE, cursor: cursors[page] }),
  })
  const action = useMutation({
    mutationFn: ({ id, op }: { id: string; op: 'test' | 'refresh-tools' }) => api.post<any>(`/servers/${id}/${op}`),
    onSuccess: (r, v) => {
      qc.invalidateQueries({ queryKey: ['servers'] })
      if (v.op === 'test') r.healthy ? toast.ok(`Connection healthy (${r.latency_ms} ms)`) : toast.error(new Error(`Connection failed: ${r.error || r.status}`))
      else toast.ok(`Discovery complete: ${r.new?.length ?? 0} new, ${r.changed?.length ?? 0} changed, ${r.rejected?.length ?? 0} rejected`)
    },
    onError: e => toast.error(e),
  })
  const canWrite = can(...REGISTRY_WRITE)
  const canTest = can(...REGISTRY_WRITE, 'security_admin')
  const items = q.data?.items || []

  return (
    <>
      <PageHeading eyebrow="REGISTRY" title="MCP Servers" subtitle="Upstream MCP servers registered for this tenant. Credentials are stored encrypted and never displayed."
        actions={canWrite && <button className="btn primary" onClick={() => setAdding(true)}><Plus size={14} />Add server</button>} />
      <div className="metric-grid compact-metrics">
        <Metric icon={<ServerIcon size={18} />} color="blue" label="Registered" value={q.data?.total ?? '-'} />
        <Metric icon={<CheckCircle2 size={18} />} color="green" label="Healthy (this page)" value={items.filter(s => s.health_status === 'healthy').length} />
        <Metric icon={<XCircle size={18} />} color="orange" label="Unhealthy / disabled" value={items.filter(s => s.health_status !== 'healthy' || !s.enabled).length} />
        <Metric icon={<Wrench size={18} />} color="purple" label="Enabled tools" value={items.reduce((a, s) => a + (s.enabled_tool_count || 0), 0)} sub={`${items.reduce((a, s) => a + (s.tool_count || 0), 0)} discovered`} />
      </div>
      <Panel>
        <div className="toolbar">
          <div className="search"><Search size={14} /><input placeholder="Search by name or alias" value={search} onChange={e => { setSearch(e.target.value); setPage(0); setCursors([null]) }} /></div>
        </div>
        <QueryState q={q} empty={d => d.items.length === 0} emptyText={search ? 'No servers match your search.' : 'Register your first MCP server to start building the tool catalog.'}>
          {d => <>
            <div className="table-wrap"><table>
              <thead><tr><th>SERVER</th><th>TRANSPORT</th><th>ENVIRONMENT</th><th>HEALTH</th><th>TOOLS</th><th>LAST CHECK</th><th>ACTIONS</th></tr></thead>
              <tbody>{d.items.map(s => (
                <tr key={s.id}>
                  <td><div className="server-name"><div className="server-icon"><ServerIcon size={14} /></div><div><Link to={`/servers/${s.id}`}><b>{s.name}</b></Link><small className="mono">{s.alias}</small></div></div></td>
                  <td>{s.transport === 'stdio' ? 'stdio' : 'HTTP'}</td>
                  <td><span className="category">{s.environment}</span></td>
                  <td>{s.enabled ? <Status value={s.health_status} /> : <Status value="disabled" />}</td>
                  <td>{s.enabled_tool_count}/{s.tool_count}</td>
                  <td className="muted">{timeAgo(s.last_health_check_at)}{s.last_latency_ms != null && ` · ${s.last_latency_ms} ms`}</td>
                  <td><div className="row-actions">
                    {canTest && <button className="small-btn" disabled={action.isPending} onClick={() => action.mutate({ id: s.id, op: 'test' })}><Activity size={11} />Test</button>}
                    {canWrite && <button className="small-btn" disabled={action.isPending || !s.enabled} onClick={() => action.mutate({ id: s.id, op: 'refresh-tools' })}><RefreshCw size={11} />Refresh tools</button>}
                    <Link className="small-btn" to={`/servers/${s.id}`}>Details</Link>
                  </div></td>
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
      {adding && <ServerWizard onClose={() => setAdding(false)} />}
    </>
  )
}
