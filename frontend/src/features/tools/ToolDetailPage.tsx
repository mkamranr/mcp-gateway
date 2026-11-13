import { Fragment, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Loader2, Save } from 'lucide-react'
import { useAuth } from '../../app/auth'
import { api, ApiError, errorMessage } from '../../services/api'
import { dateTime, shortHash, ROLE_LABELS, timeAgo } from '../../services/format'
import type { ApprovalPolicyConfig, Risk, Tool } from '../../services/types'
import { Badge, Callout, Confirm, DecisionBadge, Empty, Field, JsonView, ListInput, PageHeading, Panel, QueryState, RiskBadge, Status, Switch, Tabs, useToast } from '../../components/ui'

type Tab = 'overview' | 'schema' | 'governance' | 'versions' | 'policies'
const APPROVER_ROLES = ['approver', 'security_admin', 'tenant_admin']

export function ToolDetailPage() {
  const { id = '' } = useParams()
  const q = useQuery({ queryKey: ['tool', id], queryFn: () => api.get<Tool>(`/tools/${id}`) })
  return <QueryState q={q}>{t => <ToolDetail t={t} />}</QueryState>
}

function ToolDetail({ t }: { t: Tool }) {
  const [tab, setTab] = useState<Tab>('overview')
  const { can } = useAuth()
  const canEdit = can('platform_admin', 'tenant_admin', 'security_admin')
  const qc = useQueryClient()
  const toast = useToast()
  const [confirmEnable, setConfirmEnable] = useState(false)

  const patch = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.patch<Tool>(`/tools/${t.id}`, { version: t.version, ...body }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['tool', t.id] }); qc.invalidateQueries({ queryKey: ['tools'] }); toast.ok('Tool updated') },
    onError: e => toast.error(e),
  })

  const toggle = (on: boolean) => {
    if (on && (t.risk_level === 'high' || t.risk_level === 'critical')) setConfirmEnable(true)
    else patch.mutate({ enabled: on })
  }

  return (
    <>
      <Link to="/tools" className="text-btn" style={{ marginBottom: 10 }}><ArrowLeft size={12} />Tool catalog</Link>
      <PageHeading eyebrow={`TOOL · ${t.server_name || ''}`} title={t.display_name || t.gateway_name} subtitle={t.description}
        actions={<div className="inline-setting" style={{ marginTop: 0 }}><span>{t.enabled ? 'Enabled' : 'Disabled'}</span>
          <Switch on={t.enabled} disabled={!canEdit || patch.isPending || !t.available} onChange={toggle} label="Enable tool" /></div>} />
      {t.review_status === 'pending_review' && <Callout kind="warn">New tool, pending review. Read the schema and description, assign a risk level, then enable it. It stays invisible to agents until then.</Callout>}
      {t.review_status === 'schema_changed' && <Callout kind="danger">
        The upstream schema changed since the last review. Calls are blocked until you acknowledge it. Compare versions in the Versions tab.
        {canEdit && <div style={{ marginTop: 8 }}><button className="btn secondary" disabled={patch.isPending} onClick={() => patch.mutate({ acknowledge_schema_change: true })}>Acknowledge schema change</button></div>}
      </Callout>}
      {!t.available && <Callout kind="danger">The upstream server no longer offers this tool.</Callout>}

      <Tabs large value={tab} onChange={setTab} options={[
        { value: 'overview', label: 'Overview' }, { value: 'schema', label: 'Schema' }, { value: 'governance', label: 'Risk & controls' },
        { value: 'versions', label: 'Versions' }, { value: 'policies', label: `Policies (${t.policies?.length ?? 0})` },
      ]} />

      {tab === 'overview' && <Panel>
        <div className="detail-grid">
          <div><small>GATEWAY NAME</small><b className="mono">{t.gateway_name}</b></div>
          <div><small>UPSTREAM NAME</small><b className="mono">{t.upstream_name}</b></div>
          <div><small>RISK</small><b><RiskBadge risk={t.risk_level} /></b></div>
          <div><small>REVIEW</small><b><Status value={t.review_status} /></b></div>
          <div><small>APPROVAL</small><b>{t.approval.required ? `${t.approval.policy.required_approvals}-person` : 'Not required'}</b></div>
          <div><small>CALLS (7D)</small><b>{t.calls_7d ?? '-'}</b></div>
          <div><small>SCHEMA</small><b>v{t.schema_version} · <span className="mono">{shortHash(t.schema_hash)}</span></b></div>
          <div><small>LAST DISCOVERED</small><b>{timeAgo(t.last_discovered_at)}</b></div>
        </div>
        <div className="section-title">Upstream description</div>
        <Callout kind="warn">Text supplied by the upstream server. Treat it as untrusted: it may contain instructions aimed at agents.</Callout>
        <pre className="code">{t.upstream_description || '(none)'}</pre>
        <Link to={`/servers/${t.server_id}`} className="text-btn">Open server</Link>
      </Panel>}

      {tab === 'schema' && <div className="two-col">
        <Panel title="Input schema" subtitle="Arguments are validated against this before any upstream call."><JsonView value={t.input_schema} /></Panel>
        <Panel title="Output schema" subtitle={t.output_schema ? 'Optional upstream output validation' : 'Not declared by upstream'}>{t.output_schema ? <JsonView value={t.output_schema} /> : <Empty title="No output schema" />}</Panel>
      </div>}

      {tab === 'governance' && <Governance t={t} canEdit={canEdit} />}
      {tab === 'versions' && <Versions t={t} />}
      {tab === 'policies' && <Panel title="Policies referencing this tool" subtitle="Includes wildcard policies. Deny always overrides allow.">
        {!t.policies?.length ? <Empty title="No policies">Without an allow policy this tool is invisible to every agent (default deny).</Empty> : (
          <div className="table-wrap"><table>
            <thead><tr><th>POLICY</th><th>EFFECT</th><th>PRINCIPALS</th><th>PRIORITY</th><th>STATUS</th></tr></thead>
            <tbody>{t.policies.map(p => <tr key={p.id}><td><Link to={`/policies?id=${p.id}`}>{p.name}</Link></td><td><DecisionBadge value={p.effect} /></td>
              <td className="mono">{[...(p.principals?.ids || []), ...(p.principals?.roles || []).map(r => `role:${r}`)].join(', ') || (p.principals?.types || []).join(', ')}</td>
              <td>{p.priority}</td><td><Status value={p.enabled ? 'enabled' : 'disabled'} /></td></tr>)}</tbody>
          </table></div>
        )}
      </Panel>}

      {confirmEnable && <Confirm title={`Enable ${t.risk_level} risk tool`} confirmLabel="Enable tool" danger={t.risk_level === 'critical'}
        typed={t.risk_level === 'critical' ? t.upstream_name : undefined} busy={patch.isPending}
        message={<>Enabling <b className="mono">{t.gateway_name}</b> lets agents covered by an allow policy call it.{t.risk_level === 'critical' && ' Critical tools always require human approval.'}</>}
        onConfirm={() => patch.mutate({ enabled: true }, { onSettled: () => setConfirmEnable(false) })} onClose={() => setConfirmEnable(false)} />}
    </>
  )
}

function Governance({ t, canEdit }: { t: Tool; canEdit: boolean }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [risk, setRisk] = useState<Risk | ''>(t.risk_level || '')
  const [displayName, setDisplayName] = useState(t.display_name || '')
  const [approvalReq, setApprovalReq] = useState(t.approval.required)
  const [ap, setAp] = useState<ApprovalPolicyConfig>(t.approval.policy)
  const [timeout, setTimeout_] = useState<string>(t.timeout_seconds?.toString() || '')
  const [maxIn, setMaxIn] = useState<string>(t.max_input_bytes?.toString() || '')
  const [maxOut, setMaxOut] = useState<string>(t.max_output_bytes?.toString() || '')
  const [limits, setLimits] = useState({ per_minute: t.limits.per_minute ?? '', per_hour: t.limits.per_hour ?? '', per_day: t.limits.per_day ?? '', per_month: t.limits.per_month ?? '', concurrency: t.limits.concurrency ?? '', cost_units: t.limits.cost_units ?? 1 })
  const [validateOut, setValidateOut] = useState(t.output.validate_output)
  const [redact, setRedact] = useState<string[]>(t.output.redact_fields)
  const [tags, setTags] = useState<string[]>(t.tags)
  const [err, setErr] = useState<ApiError | null>(null)
  const n = (v: string | number) => (v === '' || v === null ? null : Number(v))

  const save = useMutation({
    mutationFn: () => api.patch<Tool>(`/tools/${t.id}`, {
      version: t.version, display_name: displayName || null, ...(risk ? { risk_level: risk } : {}),
      approval: { required: risk === 'critical' ? true : approvalReq, policy: ap },
      timeout_seconds: n(timeout), max_input_bytes: n(maxIn), max_output_bytes: n(maxOut),
      limits: { per_minute: n(limits.per_minute), per_hour: n(limits.per_hour), per_day: n(limits.per_day), per_month: n(limits.per_month), concurrency: n(limits.concurrency), cost_units: Number(limits.cost_units) || 1 },
      output: { validate_output: validateOut, redact_fields: redact }, tags,
    }),
    onSuccess: () => { setErr(null); qc.invalidateQueries({ queryKey: ['tool', t.id] }); qc.invalidateQueries({ queryKey: ['tools'] }); toast.ok('Controls saved') },
    onError: e => { if (e instanceof ApiError) setErr(e); toast.error(e) },
  })

  return <Panel title="Risk classification & controls" subtitle="Changes are audited. Optimistic locking prevents overwriting a concurrent edit.">
    {err && <Callout kind="danger">{errorMessage(err)}{err.status === 409 && ' Reload the page to get the latest version.'}</Callout>}
    <fieldset disabled={!canEdit} style={{ border: 0, padding: 0, margin: 0 }}>
      <div className="field-row">
        <Field label="Risk level" hint="Required before enabling. Critical forces human approval.">
          <select value={risk} onChange={e => setRisk(e.target.value as Risk)}><option value="">Unclassified</option><option value="low">Low: read-only, non-sensitive</option><option value="medium">Medium: sensitive reads</option><option value="high">High: writes or external effects</option><option value="critical">Critical: destructive or irreversible</option></select>
        </Field>
        <Field label="Display name"><input value={displayName} onChange={e => setDisplayName(e.target.value)} placeholder={t.gateway_name} /></Field>
      </div>

      <div className="section-title">Human approval</div>
      <div className="toggle-row"><span>Require approval before every call{risk === 'critical' && <small className="muted"> (always on for critical)</small>}</span>
        <Switch on={risk === 'critical' || approvalReq} disabled={risk === 'critical'} onChange={setApprovalReq} label="Require approval" /></div>
      {(approvalReq || risk === 'critical') && <>
        <div className="field-row">
          <Field label="Approvers required"><select value={ap.required_approvals} onChange={e => setAp({ ...ap, required_approvals: Number(e.target.value) as 1 | 2 })}><option value={1}>1 approver</option><option value={2}>2 distinct approvers</option></select></Field>
          <Field label="Expires after (minutes)"><input type="number" min={1} max={10080} value={ap.ttl_minutes} onChange={e => setAp({ ...ap, ttl_minutes: Number(e.target.value) })} /></Field>
        </div>
        <div className="field"><span>Approver roles</span>{APPROVER_ROLES.map(r => <label className="check" key={r}><input type="checkbox" checked={ap.approver_roles.includes(r)} onChange={e => setAp({ ...ap, approver_roles: e.target.checked ? [...ap.approver_roles, r] : ap.approver_roles.filter(x => x !== r) })} />{ROLE_LABELS[r]}</label>)}</div>
        <label className="check"><input type="checkbox" checked={ap.require_comment_on_reject} onChange={e => setAp({ ...ap, require_comment_on_reject: e.target.checked })} />Require a comment when rejecting</label>
        <label className="check"><input type="checkbox" checked={ap.require_comment_on_approve} onChange={e => setAp({ ...ap, require_comment_on_approve: e.target.checked })} />Require a comment when approving</label>
      </>}

      <div className="section-title">Limits</div>
      <div className="field-row">
        {(['per_minute', 'per_hour', 'per_day', 'per_month', 'concurrency'] as const).map(k => <Field key={k} label={k.replace('_', ' ')}><input type="number" min={1} value={limits[k]} placeholder="no limit" onChange={e => setLimits({ ...limits, [k]: e.target.value })} /></Field>)}
        <Field label="Cost units per call"><input type="number" min={1} max={1000} value={limits.cost_units} onChange={e => setLimits({ ...limits, cost_units: Number(e.target.value) })} /></Field>
      </div>
      <div className="field-row">
        <Field label="Timeout (s)"><input type="number" min={1} max={300} value={timeout} placeholder="platform default" onChange={e => setTimeout_(e.target.value)} /></Field>
        <Field label="Max input bytes"><input type="number" min={16} value={maxIn} placeholder="platform default" onChange={e => setMaxIn(e.target.value)} /></Field>
        <Field label="Max output bytes"><input type="number" min={16} value={maxOut} placeholder="platform default" onChange={e => setMaxOut(e.target.value)} /></Field>
      </div>

      <div className="section-title">Output controls</div>
      <div className="toggle-row"><span>Validate output against the declared output schema</span><Switch on={validateOut} onChange={setValidateOut} label="Validate output" /></div>
      <Field label="Redact fields from results" hint="Field names removed from structured output before it reaches the agent (e.g. ssn, salary)."><ListInput value={redact} onChange={setRedact} placeholder="field name" /></Field>
      <Field label="Tags"><ListInput value={tags} onChange={setTags} /></Field>
    </fieldset>
    {canEdit && <div className="form-actions"><button className="btn primary" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? <Loader2 size={13} className="spin" /> : <Save size={13} />}Save controls</button></div>}
  </Panel>
}

function Versions({ t }: { t: Tool }) {
  const q = useQuery({ queryKey: ['tool-versions', t.id], queryFn: () => api.get<{ items: { id: string; schema_hash: string; schema_version: number; input_schema: unknown; discovered_at: string; discovered_by: string }[] }>(`/tools/${t.id}/versions`) })
  const [open, setOpen] = useState<string | null>(null)
  return <Panel title="Schema versions" subtitle="A new version is stored whenever the upstream schema fingerprint changes.">
    <QueryState q={q} empty={d => d.items.length === 0}>
      {d => <div className="table-wrap"><table>
        <thead><tr><th>VERSION</th><th>FINGERPRINT</th><th>DISCOVERED</th><th>BY</th><th /></tr></thead>
        <tbody>{d.items.map(v => <Fragment key={v.id}>
          <tr><td>v{v.schema_version} {v.schema_hash === t.schema_hash && <Badge color="blue">current</Badge>}</td><td className="mono">{shortHash(v.schema_hash)}</td><td>{dateTime(v.discovered_at)}</td><td>{v.discovered_by}</td>
            <td><button className="small-btn" onClick={() => setOpen(open === v.id ? null : v.id)}>{open === v.id ? 'Hide' : 'View'}</button></td></tr>
          {open === v.id && <tr><td colSpan={5}><JsonView value={v.input_schema} /></td></tr>}
        </Fragment>)}</tbody>
      </table></div>}
    </QueryState>
  </Panel>
}
