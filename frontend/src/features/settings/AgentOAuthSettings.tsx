import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, Loader2, Plus, PlugZap, Save, Trash2 } from 'lucide-react'
import { api, ApiError, errorMessage } from '../../services/api'
import { dateTime } from '../../services/format'
import type { AgentOAuthConfig, TrustedIssuer } from '../../services/types'
import { Badge, Callout, Field, ListInput, Panel, QueryState, Switch, useToast } from '../../components/ui'

const ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA']
const BLANK: TrustedIssuer = {
  issuer: '', display_name: '', audience: '', jwks_uri: '', subject_claim: 'sub', allowed_algorithms: ['RS256', 'PS256', 'ES256'],
  required_scopes: [], max_token_lifetime_seconds: 86400, require_at_jwt_type: false,
}
interface TestResult { ok: boolean; error?: string; detail?: string; jwks_uri?: string; signing_keys?: number }

export function AgentOAuthSettings() {
  const q = useQuery({ queryKey: ['agent-oauth-config'], queryFn: () => api.get<AgentOAuthConfig>('/agent-oauth/config') })
  return <QueryState q={q}>{d => <Form cfg={d} />}</QueryState>
}

function Form({ cfg }: { cfg: AgentOAuthConfig }) {
  const [enabled, setEnabled] = useState(cfg.enabled)
  const [issuers, setIssuers] = useState<TrustedIssuer[]>(cfg.issuers)
  const [err, setErr] = useState<ApiError | null>(null)
  const [tests, setTests] = useState<Record<string, TestResult>>({})
  useEffect(() => { setEnabled(cfg.enabled); setIssuers(cfg.issuers) }, [cfg])
  const qc = useQueryClient()
  const toast = useToast()
  const save = useMutation({
    mutationFn: () => api.put<AgentOAuthConfig>('/agent-oauth/config', { enabled, issuers }),
    onSuccess: () => { setErr(null); qc.invalidateQueries({ queryKey: ['agent-oauth-config'] }); qc.invalidateQueries({ queryKey: ['agent-oauth-status'] }); toast.ok('Agent OAuth settings saved') },
    onError: e => e instanceof ApiError ? setErr(e) : toast.error(e),
  })
  const test = useMutation({
    mutationFn: (issuer: string) => api.post<TestResult>('/agent-oauth/test', { issuer }).then(r => [issuer, r] as const),
    onSuccess: ([issuer, r]) => setTests(t => ({ ...t, [issuer]: r })), onError: e => toast.error(e),
  })
  const patch = (i: number, p: Partial<TrustedIssuer>) => setIssuers(list => list.map((x, j) => j === i ? { ...x, ...p } : x))
  const saved = new Set(cfg.issuers.map(i => i.issuer))

  return <>
    <Panel title="OAuth 2.0 for agents" subtitle="Agents can present access tokens from your identity provider (client-credentials grant) instead of a gateway key. Each agent is then linked to its client under Agents."
      actions={<div className="toggle-row" style={{ border: 0, padding: 0 }}><span>{enabled ? <Badge color="green">enabled</Badge> : <Badge>disabled</Badge>}</span><Switch on={enabled} onChange={setEnabled} label="Agent OAuth enabled" /></div>}>
      {err && <Callout kind="danger">{errorMessage(err)}</Callout>}
      <Callout>Tokens are verified against the issuer's published keys: signature (asymmetric algorithms only), exact issuer, audience, expiry and lifetime. ID tokens are refused. Nothing secret is stored here.</Callout>
    </Panel>

    {issuers.map((it, i) => <Panel key={i} title={it.display_name || it.issuer || 'New issuer'}
      actions={<div className="heading-actions">
        {saved.has(it.issuer) && <button type="button" className="btn secondary" disabled={test.isPending} onClick={() => test.mutate(it.issuer)}>{test.isPending && test.variables === it.issuer ? <Loader2 size={13} className="spin" /> : <PlugZap size={13} />}Test keys</button>}
        <button type="button" className="small-btn" aria-label="Remove issuer" onClick={() => setIssuers(list => list.filter((_, j) => j !== i))}><Trash2 size={11} /></button>
      </div>}>
      {tests[it.issuer] && (tests[it.issuer].ok
        ? <Callout kind="ok"><b>Keys OK.</b> {tests[it.issuer].signing_keys} signing key(s) at {tests[it.issuer].jwks_uri}.</Callout>
        : <Callout kind="danger"><b>{tests[it.issuer].error}</b>: {tests[it.issuer].detail}</Callout>)}
      <div className="field-row">
        <Field label="Issuer" hint="Exactly the iss claim of the tokens (for Entra ID it ends in /<tenant>/v2.0)"><input value={it.issuer} onChange={e => patch(i, { issuer: e.target.value })} placeholder="https://" /></Field>
        <Field label="Name"><input value={it.display_name} onChange={e => patch(i, { display_name: e.target.value })} placeholder="Corporate IdP" /></Field>
      </div>
      <div className="field-row">
        <Field label="Audience" hint="The gateway's API identifier at the IdP (aud claim). Never a client ID."><input value={it.audience} onChange={e => patch(i, { audience: e.target.value })} placeholder="api://mcp-gateway" /></Field>
        <Field label="Client claim" hint="sub (Okta, Auth0), azp (Keycloak, Entra v2), appid (Entra v1)"><input value={it.subject_claim} onChange={e => patch(i, { subject_claim: e.target.value })} /></Field>
      </div>
      <Field label="JWKS URI (optional)" hint="Leave empty to read it from the issuer's discovery document."><input value={it.jwks_uri} onChange={e => patch(i, { jwks_uri: e.target.value })} /></Field>
      <div className="field-row">
        <Field label="Required scopes (optional)" hint="Every one must be in the token's scope or scp claim."><ListInput value={it.required_scopes} onChange={v => patch(i, { required_scopes: v })} placeholder="mcp.tools" /></Field>
        <Field label="Maximum token lifetime (seconds)"><input type="number" min={60} max={604800} value={it.max_token_lifetime_seconds} onChange={e => patch(i, { max_token_lifetime_seconds: Number(e.target.value) })} /></Field>
      </div>
      <div className="field"><span>Accepted signing algorithms (asymmetric only)</span><div className="chips">{ALGORITHMS.map(a => <label className="check" key={a}>
        <input type="checkbox" checked={it.allowed_algorithms.includes(a)} onChange={e => patch(i, { allowed_algorithms: e.target.checked ? [...it.allowed_algorithms, a] : it.allowed_algorithms.filter(x => x !== a) })} />{a}</label>)}</div></div>
      <div className="toggle-row"><span>Require RFC 9068 access tokens (typ at+jwt)</span><Switch on={it.require_at_jwt_type} onChange={v => patch(i, { require_at_jwt_type: v })} label="Require at+jwt" /></div>
    </Panel>)}

    <Panel title="Save">
      <div className="form-actions" style={{ marginTop: 0, borderTop: 0, paddingTop: 0 }}>
        <button type="button" className="btn secondary" disabled={issuers.length >= 10} onClick={() => setIssuers(list => [...list, { ...BLANK }])}><Plus size={13} />Add issuer</button>
        <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? <Loader2 size={13} className="spin" /> : <Save size={13} />}Save</button>
        {cfg.updated_at && <span className="muted" style={{ fontSize: 10, alignSelf: 'center' }}><CheckCircle2 size={10} /> Last saved {dateTime(cfg.updated_at)}</span>}
      </div>
    </Panel>
  </>
}
