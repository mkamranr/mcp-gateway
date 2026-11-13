import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, ArrowLeft, Archive, Pencil, Power, RefreshCw } from 'lucide-react'
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useAuth } from '../../app/auth'
import { ADMINS, REGISTRY_WRITE } from '../../services/roles'
import { api } from '../../services/api'
import { dateTime, timeAgo } from '../../services/format'
import type { AuditEvent, Page, Server, Tool } from '../../services/types'
import { Badge, Callout, Confirm, Empty, JsonView, PageHeading, Panel, QueryState, RiskBadge, Status, Tabs, useToast } from '../../components/ui'
import { ServerWizard } from './ServerWizard'

type Tab = 'overview' | 'tools' | 'config' | 'health' | 'history'

export function ServerDetailPage() {
  const { id = '' } = useParams()
  const q = useQuery({ queryKey: ['server', id], queryFn: () => api.get<Server>(`/servers/${id}`) })
  return <QueryState q={q}>{s => <ServerDetail s={s} />}</QueryState>
}

function ServerDetail({ s }: { s: Server }) {
  const [tab, setTab] = useState<Tab>('overview')
  const [editing, setEditing] = useState(false)
  const [archiving, setArchiving] = useState(false)
  const { can } = useAuth()
  const qc = useQueryClient()
  const toast = useToast()
  const nav = useNavigate()
  const canWrite = can(...REGISTRY_WRITE)
  const canTest = can(...REGISTRY_WRITE, 'security_admin')
  const canToggle = can(...ADMINS, 'security_admin')
  const refresh = () => { qc.invalidateQueries({ queryKey: ['server', s.id] }); qc.invalidateQueries({ queryKey: ['servers'] }); qc.invalidateQueries({ queryKey: ['server-tools', s.id] }) }

  const op = useMutation({
    mutationFn: (o: 'test' | 'refresh-tools' | 'enable' | 'disable') => api.post<any>(`/servers/${s.id}/${o}`),
    onSuccess: (r, o) => {
      refresh()
      if (o === 'test') r.healthy ? toast.ok(`Connection healthy (${r.latency_ms} ms, ${r.tool_count} tools)`) : toast.error(new Error(`Connection failed: ${r.error || r.status}`))
      else if (o === 'refresh-tools') toast.ok(`Discovery: ${r.new?.length ?? 0} new, ${r.changed?.length ?? 0} changed, ${r.unchanged ?? 0} unchanged, ${r.rejected?.length ?? 0} rejected`)
      else toast.ok(`Server ${o}d`)
    },
    onError: e => toast.error(e),
  })
  const archive = useMutation({
    mutationFn: () => api.del(`/servers/${s.id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['servers'] }); toast.ok('Server archived. Its tools are no longer callable.'); nav('/servers') },
    onError: e => toast.error(e),
  })

  return (
    <>
      <Link to="/servers" className="text-btn" style={{ marginBottom: 10 }}><ArrowLeft size={12} />All servers</Link>
      <PageHeading eyebrow={`MCP SERVER · ${s.alias}`} title={s.name} subtitle={s.description || undefined}
        actions={(canTest || canWrite || canToggle) && <>
          {canTest && <button className="btn secondary" disabled={op.isPending} onClick={() => op.mutate('test')}><Activity size={13} />Test connection</button>}
          {canWrite && <button className="btn secondary" disabled={op.isPending || !s.enabled} onClick={() => op.mutate('refresh-tools')}><RefreshCw size={13} />Refresh tools</button>}
          {canWrite && <button className="btn secondary" onClick={() => setEditing(true)}><Pencil size={13} />Edit</button>}
          {canToggle && <button className={s.enabled ? 'btn danger' : 'btn primary'} disabled={op.isPending} onClick={() => op.mutate(s.enabled ? 'disable' : 'enable')}><Power size={13} />{s.enabled ? 'Disable' : 'Enable'}</button>}
        </>} />
      {!s.enabled && <Callout kind="warn">This server is disabled. None of its tools can be discovered or invoked.</Callout>}
      {s.discovery?.status === 'failed' && <Callout kind="danger">Last discovery failed: {s.discovery.error}</Callout>}
      <Tabs large value={tab} onChange={setTab} options={[
        { value: 'overview', label: 'Overview' }, { value: 'tools', label: `Tools (${s.tool_count})` },
        { value: 'config', label: 'Configuration' }, { value: 'health', label: 'Health' }, { value: 'history', label: 'History' },
      ]} />

      {tab === 'overview' && <Panel>
        <div className="detail-grid">
          <div><small>HEALTH</small><b>{s.enabled ? <Status value={s.health_status} /> : <Status value="disabled" />}</b></div>
          <div><small>LATENCY</small><b>{s.last_latency_ms != null ? `${s.last_latency_ms} ms` : '-'}</b></div>
          <div><small>TOOLS ENABLED</small><b>{s.enabled_tool_count} / {s.tool_count}</b></div>
          <div><small>LAST CHECK</small><b>{timeAgo(s.last_health_check_at)}</b></div>
          <div><small>TRANSPORT</small><b>{s.transport}</b></div>
          <div><small>ENVIRONMENT</small><b>{s.environment}</b></div>
          <div><small>OWNER</small><b>{s.owner || '-'}</b></div>
          <div><small>LAST DISCOVERY</small><b>{s.discovery?.at ? timeAgo(s.discovery.at) : 'Never'}</b></div>
        </div>
        {s.last_health_error && <Callout kind="danger">Last error: {s.last_health_error}</Callout>}
        {s.tags.length > 0 && <div className="chips">{s.tags.map(t => <span className="chip" key={t}>{t}</span>)}</div>}
        {can(...ADMINS) && <div className="form-actions"><button className="btn danger" onClick={() => setArchiving(true)}><Archive size={13} />Archive server</button></div>}
      </Panel>}

      {tab === 'tools' && <ServerTools serverId={s.id} />}

      {tab === 'config' && <Panel title="Connection configuration" subtitle="Secrets are write-only. The API reports only whether one is stored.">
        <dl className="kv">
          <dt>Transport</dt><dd>{s.transport}</dd>
          {s.transport === 'streamable_http' ? <><dt>Endpoint</dt><dd className="mono">{s.endpoint}</dd><dt>TLS verification</dt><dd>{s.verify_tls ? 'Enabled' : <Badge color="red">Disabled</Badge>}</dd></>
            : <><dt>Command</dt><dd className="mono">{s.command}</dd><dt>Arguments</dt><dd className="mono">{s.args.join(' ') || '-'}</dd><dt>Working dir</dt><dd className="mono">{s.cwd || '-'}</dd><dt>Environment keys</dt><dd className="mono">{s.env_keys.join(', ') || '-'}</dd></>}
          <dt>Authentication</dt><dd>{s.authentication_mode} {s.has_secret && <Badge color="green">secret stored</Badge>}</dd>
          <dt>Timeouts</dt><dd>{s.connection_timeout_seconds}s connect · {s.request_timeout_seconds}s request</dd>
          <dt>Max concurrent calls</dt><dd>{s.max_concurrent_calls}</dd>
          <dt>Private network</dt><dd>{s.allow_private_network ? <Badge color="orange">allowed</Badge> : 'blocked'}</dd>
          <dt>Version</dt><dd>{s.version} · updated {dateTime(s.updated_at)} by {s.updated_by}</dd>
        </dl>
      </Panel>}

      {tab === 'health' && <Panel title="Health checks" subtitle="Last 20 checks (worker and manual tests)">
        {s.health_history.length === 0 ? <Empty title="No health checks yet" /> : <>
          <div className="chart">
            <ResponsiveContainer>
              <LineChart data={s.health_history.map(h => ({ ...h, t: new Date(h.at).toLocaleTimeString() }))}>
                <XAxis dataKey="t" tick={{ fill: '#8b9bb2', fontSize: 9 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#8b9bb2', fontSize: 9 }} axisLine={false} tickLine={false} width={36} unit="ms" />
                <Tooltip contentStyle={{ background: '#111e30', border: '1px solid #25364d', fontSize: 11 }} />
                <Line dataKey="latency_ms" name="Latency" stroke="#397cf6" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="table-wrap"><table>
            <thead><tr><th>TIME</th><th>STATUS</th><th>LATENCY</th><th>ERROR</th></tr></thead>
            <tbody>{[...s.health_history].reverse().map(h => <tr key={h.at}><td>{dateTime(h.at)}</td><td><Status value={h.status} /></td><td>{h.latency_ms} ms</td><td className="muted">{h.error || '-'}</td></tr>)}</tbody>
          </table></div>
        </>}
      </Panel>}

      {tab === 'history' && <ServerHistory serverId={s.id} />}

      {editing && <ServerWizard server={s} onClose={() => setEditing(false)} />}
      {archiving && <Confirm danger title="Archive server" confirmLabel="Archive" typed={s.alias} busy={archive.isPending}
        message={<>Archiving <b>{s.name}</b> disables the server and all of its tools. Agents lose access immediately. History and audit records are kept.</>}
        onConfirm={() => archive.mutate()} onClose={() => setArchiving(false)} />}
    </>
  )
}

function ServerTools({ serverId }: { serverId: string }) {
  const q = useQuery({ queryKey: ['server-tools', serverId], queryFn: () => api.get<Page<Tool>>(`/servers/${serverId}/tools`) })
  return <Panel>
    <QueryState q={q} empty={d => d.items.length === 0} emptyText="No tools discovered yet. Use Refresh tools.">
      {d => <div className="table-wrap"><table>
        <thead><tr><th>GATEWAY NAME</th><th>RISK</th><th>REVIEW</th><th>ENABLED</th><th>APPROVAL</th><th>SCHEMA</th></tr></thead>
        <tbody>{d.items.map(t => <tr key={t.id}>
          <td><Link to={`/tools/${t.id}`} className="mono">{t.gateway_name}</Link></td><td><RiskBadge risk={t.risk_level} /></td>
          <td><Status value={t.review_status} /></td><td><Status value={t.enabled ? 'enabled' : 'disabled'} /></td>
          <td>{t.approval.required ? <Badge color="purple">required</Badge> : <span className="muted">no</span>}</td><td className="muted">v{t.schema_version}</td>
        </tr>)}</tbody>
      </table></div>}
    </QueryState>
  </Panel>
}

function ServerHistory({ serverId }: { serverId: string }) {
  const q = useQuery({ queryKey: ['server-history', serverId], queryFn: () => api.get<{ items: AuditEvent[] }>(`/servers/${serverId}/history`) })
  return <Panel title="Change and discovery history" subtitle="From the audit log">
    <QueryState q={q} empty={d => d.items.length === 0}>
      {d => <div className="timeline">{d.items.map(e => <div key={e.event_id}>
        <b className="mono">{e.event_type}</b> {e.status && <Status value={e.status} />}
        <small>{dateTime(e.timestamp)} · {e.principal?.name || e.principal?.id || 'system'}</small>
        {e.metadata && Object.keys(e.metadata).length > 0 && <details><summary className="muted" style={{ fontSize: 9, cursor: 'pointer' }}>details</summary><JsonView value={e.metadata} /></details>}
      </div>)}</div>}
    </QueryState>
  </Panel>
}
