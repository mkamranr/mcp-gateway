import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Activity, AlertTriangle, CheckCircle2, Gauge } from 'lucide-react'
import { api } from '../../services/api'
import { num } from '../../services/format'
import type { Risk } from '../../services/types'
import { Empty, Metric, PageHeading, Panel, QueryState, RiskBadge, Tabs } from '../../components/ui'

interface Counts { count: number; units: number; completed: number; failed: number; rejected: number; pending: number; tool_error: number }
interface Summary {
  days: number; totals: Counts; daily: (Counts & { date: string })[]
  quotas: { scope: string; window: string; limit: number; used: number | null }[]; in_flight: number
  limits: { max_concurrent_calls_per_agent: number }
}

const TOOLTIP = { contentStyle: { background: '#111e30', border: '1px solid #25364d', borderRadius: 8, fontSize: 11 }, labelStyle: { color: '#8b9bb2' } }

export function UsagePage() {
  const [days, setDays] = useState<'1' | '7' | '30' | '90'>('7')
  const summary = useQuery({ queryKey: ['usage', 'summary', days], queryFn: () => api.get<Summary>('/usage/summary', { days }), refetchInterval: 30_000 })
  const byTool = useQuery({ queryKey: ['usage', 'tool', days], queryFn: () => api.get<{ items: (Counts & { tool_id: string; gateway_name: string | null; risk_level: Risk | null })[] }>('/usage/by-tool', { days }) })
  const byAgent = useQuery({ queryKey: ['usage', 'agent', days], queryFn: () => api.get<{ items: (Counts & { agent_id: string; agent_name: string | null })[] }>('/usage/by-agent', { days }) })

  return (
    <>
      <PageHeading eyebrow="OBSERVABILITY" title="Usage & Quotas" subtitle="Call volume, outcomes and how close the tenant is to its limits. Hard limits fail closed if the quota store is unavailable."
        actions={<Tabs value={days} onChange={setDays} options={[{ value: '1', label: '24h' }, { value: '7', label: '7 days' }, { value: '30', label: '30 days' }, { value: '90', label: '90 days' }]} />} />
      <QueryState q={summary}>{s => <>
        <div className="metric-grid">
          <Metric icon={<Activity size={19} />} color="blue" label="Total calls" value={num(s.totals.count)} sub={`${num(s.totals.units)} cost units`} />
          <Metric icon={<CheckCircle2 size={19} />} color="green" label="Completed" value={num(s.totals.completed)} sub={s.totals.count ? `${Math.round((s.totals.completed / s.totals.count) * 100)}% success` : undefined} />
          <Metric icon={<AlertTriangle size={19} />} color="orange" label="Denied / failed" value={num(s.totals.rejected + s.totals.failed + s.totals.tool_error)} sub={`${num(s.totals.rejected)} denied by policy or quota`} />
          <Metric icon={<Gauge size={19} />} color="purple" label="In-flight calls" value={s.in_flight} sub={`max ${s.limits.max_concurrent_calls_per_agent} per agent`} />
        </div>
        <div className="dashboard-grid">
          <Panel title="Daily calls by outcome">
            {s.daily.length === 0 ? <Empty title="No usage in this period" /> : <div className="chart" style={{ height: 240 }}>
              <ResponsiveContainer>
                <BarChart data={s.daily.map(x => ({ ...x, label: x.date.slice(5) }))}>
                  <CartesianGrid stroke="#25364d" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: '#8b9bb2', fontSize: 9 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#8b9bb2', fontSize: 9 }} axisLine={false} tickLine={false} width={34} allowDecimals={false} />
                  <Tooltip {...TOOLTIP} />
                  <Legend wrapperStyle={{ fontSize: 10 }} />
                  <Bar dataKey="completed" stackId="a" name="Completed" fill="#20c58a" />
                  <Bar dataKey="pending" stackId="a" name="Pending approval" fill="#8b7cf6" />
                  <Bar dataKey="rejected" stackId="a" name="Denied" fill="#ef626c" />
                  <Bar dataKey="failed" stackId="a" name="Failed" fill="#e9a23b" />
                  <Bar dataKey="tool_error" stackId="a" name="Tool error" fill="#c2577d" />
                </BarChart>
              </ResponsiveContainer>
            </div>}
          </Panel>
          <Panel title="Tenant quotas" subtitle="Current utilisation of tenant-wide limits">
            {s.quotas.length === 0 ? <Empty title="No tenant quotas configured" /> : <div className="big-resource">
              {s.quotas.map(qu => {
                const pct = qu.used == null ? 0 : Math.min(100, (qu.used / qu.limit) * 100)
                return <div key={qu.window}>
                  <span>{qu.window.replace('_', ' ')}</span>
                  <b>{qu.used == null ? 'unavailable' : `${num(qu.used)} / ${num(qu.limit)}`}</b>
                  <div className="progress"><i style={{ width: `${pct}%`, background: pct > 90 ? '#ef626c' : pct > 75 ? '#e9a23b' : undefined }} /></div>
                </div>
              })}
            </div>}
          </Panel>
        </div>
      </>}</QueryState>

      <div className="two-col">
        <Panel title="By tool">
          <QueryState q={byTool} empty={d => d.items.length === 0}>{d => <div className="table-wrap"><table>
            <thead><tr><th>TOOL</th><th>RISK</th><th>CALLS</th><th>OK</th><th>DENIED</th><th>ERRORS</th><th>UNITS</th></tr></thead>
            <tbody>{d.items.map(r => <tr key={r.tool_id}><td><Link className="mono" to={`/tools/${r.tool_id}`}>{r.gateway_name || r.tool_id}</Link></td><td><RiskBadge risk={r.risk_level} /></td>
              <td>{num(r.count)}</td><td>{num(r.completed)}</td><td>{num(r.rejected)}</td><td>{num(r.failed + r.tool_error)}</td><td>{num(r.units)}</td></tr>)}</tbody>
          </table></div>}</QueryState>
        </Panel>
        <Panel title="By agent">
          <QueryState q={byAgent} empty={d => d.items.length === 0}>{d => <div className="table-wrap"><table>
            <thead><tr><th>AGENT</th><th>CALLS</th><th>OK</th><th>DENIED</th><th>ERRORS</th><th>UNITS</th></tr></thead>
            <tbody>{d.items.map(r => <tr key={r.agent_id}><td><Link to={`/agents/${r.agent_id}`}>{r.agent_name || r.agent_id}</Link></td>
              <td>{num(r.count)}</td><td>{num(r.completed)}</td><td>{num(r.rejected)}</td><td>{num(r.failed + r.tool_error)}</td><td>{num(r.units)}</td></tr>)}</tbody>
          </table></div>}</QueryState>
        </Panel>
      </div>
    </>
  )
}
