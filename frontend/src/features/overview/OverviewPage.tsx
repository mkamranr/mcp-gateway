import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Activity, Bot, CheckSquare, RefreshCw, Server, Wrench } from 'lucide-react'
import { api } from '../../services/api'
import { fmtDuration, num, timeAgo } from '../../services/format'
import type { Overview } from '../../services/types'
import { DecisionBadge, Empty, Metric, PageHeading, Panel, QueryState, Status } from '../../components/ui'

const DECISION_COLORS: Record<string, string> = { ALLOW: '#20c58a', DENY: '#ef626c', REQUIRE_APPROVAL: '#8b7cf6' }
const TOOLTIP = { contentStyle: { background: '#111e30', border: '1px solid #25364d', borderRadius: 8, fontSize: 11 }, labelStyle: { color: '#8b9bb2' } }

export function OverviewPage() {
  const q = useQuery({ queryKey: ['overview'], queryFn: () => api.get<Overview>('/overview'), refetchInterval: 30_000 })
  return (
    <>
      <PageHeading eyebrow="WORKSPACE" title="Overview" subtitle="Gateway activity, policy decisions and dependency health for the current tenant."
        actions={<button className="btn secondary" onClick={() => q.refetch()} disabled={q.isFetching}><RefreshCw size={13} className={q.isFetching ? 'spin' : ''} />Refresh</button>} />
      <QueryState q={q}>{d => <OverviewBody d={d} />}</QueryState>
    </>
  )
}

function OverviewBody({ d }: { d: Overview }) {
  const c = d.cards
  const decisions = Object.entries(d.decisions || {}).filter(([, v]) => v > 0).map(([k, v]) => ({ name: k, value: v }))
  const totalDecisions = decisions.reduce((a, b) => a + b.value, 0)
  const maxTop = Math.max(1, ...d.top_tools.map(t => t.count))
  // Always show the full 7-day window (UTC dates, as returned by the API), with zero for quiet days.
  const byDate = new Map(d.series.map(s => [s.date, s]))
  const week = Array.from({ length: 7 }, (_, i) => new Date(Date.now() - (6 - i) * 86_400_000).toISOString().slice(0, 10)).map(date => {
    const s = byDate.get(date) ?? { date, count: 0, completed: 0, failed: 0, rejected: 0, pending: 0, tool_error: 0 }
    return { ...s, bad: s.rejected + s.failed + s.tool_error, label: date.slice(5) }
  })
  return (
    <>
      <div className="metric-grid">
        <Metric icon={<Server size={19} />} color="blue" label="MCP servers" value={c.servers} sub={<span className={c.servers_healthy === c.servers ? 'positive' : ''}>{c.servers_healthy} healthy</span>} />
        <Metric icon={<Wrench size={19} />} color="green" label="Enabled tools" value={c.enabled_tools} sub={`${c.total_tools} discovered`} />
        <Metric icon={<Activity size={19} />} color="purple" label="Calls today" value={num(c.calls_today)} sub={`${num(c.denied_today)} denied`} />
        <Metric icon={<CheckSquare size={19} />} color="orange" label="Pending approvals" value={c.pending_approvals}
          sub={d.approvals.pending ? `oldest ${fmtDuration(d.approvals.oldest_pending_age_seconds)}` : `${c.active_agents} active agents`} />
      </div>

      <div className="dashboard-grid">
        <Panel title="Tool invocations" subtitle="Last 7 days, by outcome">
          {d.series.length === 0 ? <Empty title="No invocations yet">Agent calls through the gateway appear here.</Empty> : <>
            <div className="chart-legend"><span><i className="dot green" />Completed</span><span><i className="dot red" />Denied / failed</span></div>
            <div className="chart">
              <ResponsiveContainer>
                <AreaChart data={week}>
                  <defs>
                    <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#20c58a" stopOpacity={0.35} /><stop offset="1" stopColor="#20c58a" stopOpacity={0} /></linearGradient>
                    <linearGradient id="g2" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#ef626c" stopOpacity={0.3} /><stop offset="1" stopColor="#ef626c" stopOpacity={0} /></linearGradient>
                  </defs>
                  <CartesianGrid stroke="#25364d" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: '#8b9bb2', fontSize: 9 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#8b9bb2', fontSize: 9 }} axisLine={false} tickLine={false} width={32} allowDecimals={false} />
                  <Tooltip {...TOOLTIP} />
                  <Area type="monotone" dataKey="completed" name="Completed" stroke="#20c58a" fill="url(#g1)" strokeWidth={2} />
                  <Area type="monotone" dataKey="bad" name="Denied / failed" stroke="#ef626c" fill="url(#g2)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </>}
        </Panel>
        <Panel title="Policy decisions" subtitle="Last 7 days">
          {totalDecisions === 0 ? <Empty title="No decisions yet" /> : (
            <div className="tenant-chart">
              <div className="donut">
                <ResponsiveContainer>
                  <PieChart>
                    <Pie data={decisions} dataKey="value" innerRadius={52} outerRadius={74} paddingAngle={2} stroke="none">
                      {decisions.map(x => <Cell key={x.name} fill={DECISION_COLORS[x.name] || '#5797ff'} />)}
                    </Pie>
                    <Tooltip {...TOOLTIP} />
                  </PieChart>
                </ResponsiveContainer>
                <div><b>{num(totalDecisions)}</b><small>decisions</small></div>
              </div>
              <div className="legend-list">
                {decisions.map(x => <div key={x.name}><i style={{ background: DECISION_COLORS[x.name] || '#5797ff' }} /><span>{x.name.replace('_', ' ')}</span><b>{num(x.value)}</b></div>)}
              </div>
            </div>
          )}
        </Panel>
      </div>

      <div className="grid-3">
        <Panel title="Top tools" subtitle="By calls, last 7 days" actions={<Link className="text-btn" to="/usage">Usage</Link>}>
          {d.top_tools.length === 0 ? <Empty title="No tool calls" /> : d.top_tools.map(t => (
            <div className="bar-row" key={t.tool_id}>
              <Link to={`/tools/${t.tool_id}`} className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{t.gateway_name || t.tool_id}</Link>
              <b style={{ textAlign: 'right' }}>{num(t.count)}</b>
              <div className="progress"><i style={{ width: `${(t.count / maxTop) * 100}%` }} /></div>
            </div>
          ))}
        </Panel>
        <Panel title="Upstream server health" actions={<Link className="text-btn" to="/servers">All servers</Link>}>
          {d.server_health.length === 0 ? <Empty title="No servers registered" /> : (
            <div className="mini-server-list">
              {d.server_health.map(s => (
                <div key={s.id}>
                  <Link to={`/servers/${s.id}`}>{s.name}</Link>
                  <span className="muted">{s.latency_ms != null ? `${s.latency_ms} ms` : ''}</span>
                  <Status value={s.enabled ? s.status : 'disabled'} />
                </div>
              ))}
            </div>
          )}
        </Panel>
        <Panel title="Platform health" subtitle="Gateway dependencies">
          <div className="mini-server-list">
            {d.health.map(h => (
              <div key={h.name}>
                <span>{h.name}</span>
                <span className="muted">{[h.workers_alive != null && h.workers_alive > 1 ? `${h.workers_alive} workers` : '', h.queue_depth != null ? `queue ${h.queue_depth}` : h.last_heartbeat ? timeAgo(h.last_heartbeat) : ''].filter(Boolean).join(' · ')}</span>
                <Status value={h.status} />
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <Panel title="Recent activity" subtitle="Latest invocations through the gateway" actions={<Link className="text-btn" to="/audit">Audit logs</Link>}>
        {d.recent.length === 0 ? <Empty title="No activity yet"><span><Bot size={12} /> Connect an agent to the MCP endpoint to see calls here.</span></Empty> : (
          <div className="table-wrap"><table>
            <thead><tr><th>TIME</th><th>PRINCIPAL</th><th>TOOL</th><th>DECISION</th><th>STATUS</th><th>DURATION</th></tr></thead>
            <tbody>{d.recent.map(r => (
              <tr key={r.id}><td>{timeAgo(r.at)}</td><td>{r.principal?.name || r.principal?.id}</td><td className="mono">{r.tool}</td>
                <td><DecisionBadge value={r.decision} /></td><td><Status value={r.status} /></td><td>{r.duration_ms} ms</td></tr>
            ))}</tbody>
          </table></div>
        )}
      </Panel>
    </>
  )
}
