import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Loader2, PlugZap, Save } from 'lucide-react'
import { api, ApiError, errorMessage } from '../../services/api'
import { dateTime, timeAgo } from '../../services/format'
import type { SiemConfig, SiemStatus } from '../../services/types'
import { Badge, Callout, Field, ListInput, Panel, QueryState, Switch, useToast } from '../../components/ui'

type Form = Omit<SiemConfig, 'has_http_auth_value' | 'updated_at' | 'updated_by'>
type TestResult = { ok: boolean; error?: string; note?: string | null }
const DEFAULT_PORTS: Record<string, number> = { syslog_tls: 6514, syslog_tcp: 514, syslog_udp: 514 }

export function SiemSettings() {
  const q = useQuery({ queryKey: ['siem-config'], queryFn: () => api.get<SiemConfig>('/siem/config') })
  return <>
    <SiemStatusPanel />
    <QueryState q={q}>{d => <SiemForm cfg={d} />}</QueryState>
  </>
}

function SiemStatusPanel() {
  const q = useQuery({ queryKey: ['siem-status'], queryFn: () => api.get<SiemStatus>('/siem/status'), refetchInterval: 10_000 })
  const s = q.data
  if (!s) return null
  const state = !s.enabled ? <Badge>disabled</Badge> : s.failing ? <Badge color="red">failing</Badge> : <Badge color="green">forwarding</Badge>
  return <Panel title="Forwarding status" actions={state}>
    <dl className="kv">
      <dt>Events forwarded</dt><dd>{s.forwarded_total.toLocaleString()}</dd>
      <dt>Waiting to be sent</dt><dd>{s.pending_events ?? '—'}{s.lag_seconds != null && s.enabled && <span className="muted"> · newest sent event is {s.lag_seconds}s old</span>}</dd>
      <dt>Last success</dt><dd>{s.last_success_at ? `${timeAgo(s.last_success_at)} (${dateTime(s.last_success_at)})` : '—'}</dd>
      {s.last_error && <><dt>Last error</dt><dd><span className={s.failing ? 'error-text' : 'muted'}>{s.last_error}</span> <span className="muted">{timeAgo(s.last_error_at)}</span></dd></>}
    </dl>
    {s.failing && <Callout kind="warn">Events are kept and sent in order once the collector is reachable again. Retries back off up to 5 minutes.</Callout>}
  </Panel>
}

function SiemForm({ cfg }: { cfg: SiemConfig }) {
  const { has_http_auth_value, updated_at, updated_by: _updatedBy, ...initial } = cfg
  const [f, setF] = useState<Form>(initial)
  const [authValue, setAuthValue] = useState('')
  const [err, setErr] = useState<ApiError | null>(null)
  const [test, setTest] = useState<TestResult | null>(null)
  useEffect(() => { setF(initial) }, [cfg]) // eslint-disable-line react-hooks/exhaustive-deps
  const qc = useQueryClient()
  const toast = useToast()
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setF(x => ({ ...x, [k]: v }))
  const save = useMutation({
    mutationFn: () => api.put<SiemConfig>('/siem/config', { ...f, ...(authValue ? { http_auth_value: authValue } : {}) }),
    onSuccess: () => { setErr(null); setAuthValue(''); qc.invalidateQueries({ queryKey: ['siem-config'] }); qc.invalidateQueries({ queryKey: ['siem-status'] }); toast.ok('SIEM forwarding saved') },
    onError: e => e instanceof ApiError ? setErr(e) : toast.error(e),
  })
  const check = useMutation({ mutationFn: () => api.post<TestResult>('/siem/test'), onSuccess: setTest, onError: e => toast.error(e) })
  const http = f.transport === 'http'
  const tls = f.transport === 'syslog_tls' || (http && f.url.startsWith('https://'))
  const plaintext = f.transport === 'syslog_tcp' || f.transport === 'syslog_udp' || (http && f.url.startsWith('http://'))
  const saved = !!(cfg.host || cfg.url)

  return <>
    <Panel title="Destination" subtitle="Audit events are streamed to your SIEM within seconds. Nothing is lost while the collector is down."
      actions={<div className="toggle-row" style={{ border: 0, padding: 0 }}><span>{f.enabled ? <Badge color="green">enabled</Badge> : <Badge>disabled</Badge>}</span><Switch on={f.enabled} onChange={v => set('enabled', v)} label="Forwarding enabled" /></div>}>
      {err && <Callout kind="danger">{errorMessage(err)}</Callout>}
      <div className="field-row">
        <Field label="Transport">
          <select value={f.transport} onChange={e => { const t = e.target.value as Form['transport']; setF(x => ({ ...x, transport: t, port: DEFAULT_PORTS[t] ?? x.port })) }}>
            <option value="syslog_tls">Syslog over TLS (RFC 5425)</option>
            <option value="syslog_tcp">Syslog over TCP (RFC 6587)</option>
            <option value="syslog_udp">Syslog over UDP (RFC 5426)</option>
            <option value="http">HTTP(S) collector</option>
          </select>
        </Field>
        <Field label="Event format">
          <select value={f.format} onChange={e => set('format', e.target.value as Form['format'])} disabled={http && f.http_body === 'splunk_hec'}>
            <option value="json">JSON</option><option value="cef">CEF (ArcSight, QRadar)</option>
          </select>
        </Field>
      </div>
      {http ? <>
        <Field label="Collector URL" hint="For example a Splunk HEC endpoint (/services/collector/event) or any endpoint that accepts a POST.">
          <input value={f.url} onChange={e => set('url', e.target.value)} placeholder="https://" />
        </Field>
        <div className="field-row">
          <Field label="Body">
            <select value={f.http_body} onChange={e => { const b = e.target.value as Form['http_body']; setF(x => ({ ...x, http_body: b, format: b === 'splunk_hec' ? 'json' : x.format })) }}>
              <option value="ndjson">One event per line</option><option value="json_array">JSON array</option><option value="splunk_hec">Splunk HEC</option>
            </select>
          </Field>
          <Field label="Auth header"><input value={f.http_auth_header} onChange={e => set('http_auth_header', e.target.value)} /></Field>
          <Field label="Auth header value" hint={has_http_auth_value ? 'Stored (encrypted). Leave blank to keep it.' : 'For example: Splunk <token>, or Bearer <token>.'}>
            <input type="password" autoComplete="new-password" value={authValue} onChange={e => setAuthValue(e.target.value)} placeholder={has_http_auth_value ? '••••••••' : ''} />
          </Field>
        </div>
      </> : <div className="field-row">
        <Field label="Syslog host"><input value={f.host} onChange={e => set('host', e.target.value)} placeholder="siem.corp.example" /></Field>
        <Field label="Port"><input type="number" min={1} max={65535} value={f.port} onChange={e => set('port', Number(e.target.value))} /></Field>
        <Field label="Facility" hint="13 = log audit"><input type="number" min={0} max={23} value={f.syslog_facility} onChange={e => set('syslog_facility', Number(e.target.value))} /></Field>
      </div>}
      {plaintext && <Callout kind="warn">This transport is not encrypted. Audit events (user names, IP addresses, tool names) cross the network in clear text. Prefer TLS.</Callout>}
      {f.transport === 'syslog_udp' && <Callout kind="warn">UDP has no delivery confirmation. Events lost on the network cannot be detected or resent.</Callout>}
      {tls && <>
        <Field label="CA certificate (PEM)" hint="Leave empty to use the system trust store. Paste your internal CA for an internal collector.">
          <textarea className="mono" rows={4} value={f.tls_ca_pem} onChange={e => set('tls_ca_pem', e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
        </Field>
        <div className="toggle-row"><span>Verify the collector host name</span><Switch on={f.tls_verify_hostname} onChange={v => set('tls_verify_hostname', v)} label="Verify host name" /></div>
      </>}
      <div className="form-actions">
        <button type="button" className="btn secondary" disabled={check.isPending || !saved} title={saved ? '' : 'Save a destination first'} onClick={() => check.mutate()}>
          {check.isPending ? <Loader2 size={13} className="spin" /> : <PlugZap size={13} />}Send test event
        </button>
        <span className="muted" style={{ fontSize: 10, alignSelf: 'center' }}>Sends one <span className="mono">siem.test</span> event using the saved settings.</span>
      </div>
      {test && (test.ok
        ? <Callout kind="ok">Test event sent. {test.note ? `${test.note}.` : 'Check that it arrived in your SIEM.'}</Callout>
        : <Callout kind="danger">{test.error}</Callout>)}
    </Panel>

    <Panel title="What to forward">
      <div className="field-row">
        <Field label="Minimum severity">
          <select value={f.min_severity} onChange={e => set('min_severity', e.target.value as Form['min_severity'])}>
            <option value="info">All events</option><option value="warning">Warning and above</option>
            <option value="high">High and critical</option><option value="critical">Critical only</option>
          </select>
        </Field>
        <Field label="Batch size"><input type="number" min={1} max={1000} value={f.batch_size} onChange={e => set('batch_size', Number(e.target.value))} /></Field>
      </div>
      <Field label="Event types" hint="Prefixes such as auth. or policy. Empty = every event type.">
        <ListInput value={f.event_types} onChange={v => set('event_types', v)} placeholder="auth., policy., emergency." />
      </Field>
      <div className="form-actions">
        <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? <Loader2 size={13} className="spin" /> : <Save size={13} />}Save</button>
        {updated_at && <span className="muted" style={{ fontSize: 10, alignSelf: 'center' }}>Last saved {dateTime(updated_at)}</span>}
      </div>
    </Panel>
  </>
}
