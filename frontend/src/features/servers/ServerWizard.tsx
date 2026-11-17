import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Loader2 } from 'lucide-react'
import { api, ApiError, errorMessage } from '../../services/api'
import { cn } from '../../services/format'
import type { Server } from '../../services/types'
import { Callout, Field, ListInput, Modal, Switch, useToast } from '../../components/ui'

const STEPS = ['Basics', 'Transport', 'Authentication', 'Limits', 'Security', 'Review']
const ALIAS = /^[a-z][a-z0-9-]{0,30}[a-z0-9]$/

interface Form {
  name: string; alias: string; description: string; environment: string; owner: string; tags: string[]
  transport: 'streamable_http' | 'stdio'; endpoint: string; command: string; args: string[]; cwd: string
  envPairs: string; verify_tls: boolean
  authentication_mode: 'none' | 'bearer' | 'header' | 'env'; token: string; header_name: string; secretEnv: string
  connection_timeout_seconds: number; request_timeout_seconds: number; max_concurrent_calls: number
  allow_private_network: boolean; enabled: boolean
  tls_ca_pem: string; clear_ca: boolean; client_cert_pem: string; client_key_pem: string; remove_client_cert: boolean
}

function initial(s?: Server): Form {
  return {
    name: s?.name || '', alias: s?.alias || '', description: s?.description || '', environment: s?.environment || 'production',
    owner: s?.owner || '', tags: s?.tags || [], transport: s?.transport || 'streamable_http', endpoint: s?.endpoint || '',
    command: s?.command || '', args: s?.args || [], cwd: s?.cwd || '', envPairs: '', verify_tls: s?.verify_tls ?? true,
    authentication_mode: (s?.authentication_mode as Form['authentication_mode']) || 'none', token: '', header_name: '', secretEnv: '',
    connection_timeout_seconds: s?.connection_timeout_seconds ?? 10, request_timeout_seconds: s?.request_timeout_seconds ?? 30,
    max_concurrent_calls: s?.max_concurrent_calls ?? 10, allow_private_network: s?.allow_private_network ?? false, enabled: s?.enabled ?? true,
    tls_ca_pem: '', clear_ca: false, client_cert_pem: '', client_key_pem: '', remove_client_cert: false,
  }
}

function parsePairs(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  text.split('\n').map(l => l.trim()).filter(Boolean).forEach(l => {
    const i = l.indexOf('=')
    if (i > 0) out[l.slice(0, i).trim()] = l.slice(i + 1)
  })
  return out
}

function stepErrors(f: Form, step: number, editing: boolean): string[] {
  const e: string[] = []
  if (step === 0) {
    if (f.name.trim().length < 2) e.push('Name must be at least 2 characters.')
    if (!editing && !ALIAS.test(f.alias)) e.push('Alias must be lowercase letters, digits and hyphens (2–32 chars), starting with a letter.')
  }
  if (step === 1) {
    if (f.transport === 'streamable_http') {
      try { const u = new URL(f.endpoint); if (!['http:', 'https:'].includes(u.protocol)) e.push('Endpoint must be http(s).') } catch { e.push('Enter a valid endpoint URL.') }
    } else if (!f.command.trim()) e.push('Command is required for stdio servers.')
  }
  if (step === 2 && f.authentication_mode !== 'none' && !editing) {
    if (f.authentication_mode === 'env' ? !f.secretEnv.trim() : !f.token) e.push('Provide the credential for this authentication mode.')
    if (f.authentication_mode === 'header' && !f.header_name) e.push('Header name is required.')
  }
  if (step === 2 && f.transport === 'streamable_http') {
    if (Boolean(f.client_cert_pem.trim()) !== Boolean(f.client_key_pem.trim())) e.push('A client certificate needs both the certificate and its private key.')
    if (f.client_cert_pem.trim() && !f.client_cert_pem.includes('BEGIN CERTIFICATE')) e.push('The client certificate must be PEM.')
    if (f.tls_ca_pem.trim() && !f.tls_ca_pem.includes('BEGIN CERTIFICATE')) e.push('The CA bundle must be PEM certificates.')
  }
  return e
}

export function ServerWizard({ server, onClose, onSaved }: { server?: Server; onClose: () => void; onSaved?: (s: Server) => void }) {
  const editing = !!server
  const [f, setF] = useState<Form>(() => initial(server))
  const [step, setStep] = useState(0)
  const [serverErr, setServerErr] = useState<ApiError | null>(null)
  const qc = useQueryClient()
  const toast = useToast()
  // Validation messages appear once the user has edited something on the current step (or when editing).
  const [touched, setTouched] = useState<Set<number>>(() => new Set())
  const set = <K extends keyof Form>(k: K, v: Form[K]) => {
    setF(x => ({ ...x, [k]: v }))
    setTouched(t => (t.has(step) ? t : new Set(t).add(step)))
  }
  const errs = stepErrors(f, step, editing)

  const save = useMutation({
    mutationFn: async () => {
      const secretGiven = f.authentication_mode !== 'none' && (f.token || f.secretEnv.trim())
      const secret = !secretGiven ? undefined : f.authentication_mode === 'env'
        ? { env: parsePairs(f.secretEnv) }
        : { token: f.token, ...(f.authentication_mode === 'header' ? { header_name: f.header_name } : {}) }
      const common = {
        description: f.description, environment: f.environment, owner: f.owner || null, tags: f.tags,
        verify_tls: f.verify_tls, authentication_mode: f.authentication_mode,
        connection_timeout_seconds: f.connection_timeout_seconds, request_timeout_seconds: f.request_timeout_seconds,
        max_concurrent_calls: f.max_concurrent_calls, allow_private_network: f.allow_private_network,
        ...(f.transport === 'streamable_http' ? { endpoint: f.endpoint } : { command: f.command, args: f.args, cwd: f.cwd || null, ...(f.envPairs.trim() ? { env: parsePairs(f.envPairs) } : {}) }),
        ...(secret ? { secret } : {}),
        ...(f.transport === 'streamable_http' ? {
          ...(f.tls_ca_pem.trim() ? { tls_ca_pem: f.tls_ca_pem.trim() } : editing && f.clear_ca ? { tls_ca_pem: '' } : {}),
          ...(f.client_cert_pem.trim() ? { client_certificate: { cert_pem: f.client_cert_pem.trim(), key_pem: f.client_key_pem.trim() } } : {}),
          ...(editing && f.remove_client_cert && !f.client_cert_pem.trim() ? { remove_client_certificate: true } : {}),
        } : {}),
      }
      if (editing) return api.patch<Server>(`/servers/${server!.id}`, { version: server!.version, name: f.name, ...common })
      return api.post<Server>('/servers', { name: f.name, alias: f.alias, transport: f.transport, enabled: f.enabled, ...common })
    },
    onSuccess: s => {
      qc.invalidateQueries({ queryKey: ['servers'] })
      qc.invalidateQueries({ queryKey: ['server', s.id] })
      toast.ok(editing ? 'Server updated' : 'Server registered. Refresh tools to discover its catalog.')
      onSaved?.(s); onClose()
    },
    onError: e => { setServerErr(e instanceof ApiError ? e : null); if (!(e instanceof ApiError)) toast.error(e) },
  })

  const footer = <>
    <button className="btn secondary" onClick={step === 0 ? onClose : () => setStep(step - 1)}>{step === 0 ? 'Cancel' : 'Back'}</button>
    {step < STEPS.length - 1
      ? <button className="btn primary" disabled={errs.length > 0} onClick={() => setStep(step + 1)}>Continue</button>
      : <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending && <Loader2 size={13} className="spin" />}{editing ? 'Save changes' : 'Register server'}</button>}
  </>

  return (
    <Modal wide title={editing ? `Edit ${server!.name}` : 'Add MCP server'} onClose={onClose} footer={footer}>
      <div className="steps">{STEPS.map((s, i) => <span key={s} className={cn(i === step && 'on', i < step && 'done')}>{i + 1}. {s}</span>)}</div>
      {serverErr && <Callout kind="danger">{errorMessage(serverErr)}</Callout>}

      {step === 0 && <>
        <div className="field-row">
          <Field label="Display name"><input value={f.name} onChange={e => set('name', e.target.value)} placeholder="HR Data Service" /></Field>
          <Field label="Alias (namespace)" hint={editing ? 'The alias cannot change after registration.' : <>Tools are exposed as <span className="mono">{f.alias || 'alias'}__tool_name</span></>}>
            <input value={f.alias} disabled={editing} onChange={e => set('alias', e.target.value.toLowerCase())} placeholder="hr" />
          </Field>
        </div>
        <Field label="Description"><textarea value={f.description} onChange={e => set('description', e.target.value)} /></Field>
        <div className="field-row">
          <Field label="Environment"><select value={f.environment} onChange={e => set('environment', e.target.value)}><option>production</option><option>test</option><option>development</option></select></Field>
          <Field label="Owner"><input value={f.owner} onChange={e => set('owner', e.target.value)} placeholder="team or person" /></Field>
        </div>
        <Field label="Tags" hint="Press Enter to add"><ListInput value={f.tags} onChange={v => set('tags', v)} /></Field>
      </>}

      {step === 1 && <>
        <Field label="Transport">
          <select value={f.transport} disabled={editing} onChange={e => set('transport', e.target.value as Form['transport'])}>
            <option value="streamable_http">Streamable HTTP (recommended)</option><option value="stdio">stdio (local process)</option>
          </select>
        </Field>
        {f.transport === 'streamable_http' ? <>
          <Field label="Endpoint URL" hint="The gateway resolves DNS at connect time and blocks private, loopback, link-local and metadata addresses unless allowed in the Security step.">
            <input value={f.endpoint} onChange={e => set('endpoint', e.target.value)} placeholder="https://hr-mcp.internal.example/mcp" />
          </Field>
          <div className="toggle-row"><span>Verify TLS certificates</span><Switch on={f.verify_tls} onChange={v => set('verify_tls', v)} label="Verify TLS" /></div>
          {!f.verify_tls && <Callout kind="danger">TLS verification disabled. Traffic to this server can be intercepted. Use only for isolated test environments.</Callout>}
          {f.endpoint.startsWith('http:') && <Callout kind="warn">Plain HTTP endpoint. Credentials and tool arguments travel unencrypted.</Callout>}
        </> : <>
          <Callout kind="warn">stdio servers run as local processes of the gateway. Only allowlisted executables are accepted. No shell is used, and arguments are passed verbatim.</Callout>
          <Field label="Executable"><input value={f.command} onChange={e => set('command', e.target.value)} placeholder="/usr/local/bin/hr-mcp" /></Field>
          <Field label="Arguments" hint="Each entry is one argv element. Press Enter to add."><ListInput value={f.args} onChange={v => set('args', v)} /></Field>
          <Field label="Working directory"><input value={f.cwd} onChange={e => set('cwd', e.target.value)} /></Field>
          <Field label="Non-secret environment (KEY=value per line)" hint={editing && server?.env_keys.length ? `Currently set: ${server.env_keys.join(', ')}. Leave blank to keep.` : undefined}>
            <textarea value={f.envPairs} onChange={e => set('envPairs', e.target.value)} placeholder="LOG_LEVEL=info" />
          </Field>
        </>}
      </>}

      {step === 2 && <>
        <Field label="Authentication">
          <select value={f.authentication_mode} onChange={e => set('authentication_mode', e.target.value as Form['authentication_mode'])}>
            <option value="none">None</option>
            {f.transport === 'streamable_http' && <option value="bearer">Bearer token</option>}
            {f.transport === 'streamable_http' && <option value="header">Custom header</option>}
            {f.transport === 'stdio' && <option value="env">Secret environment variables</option>}
          </select>
        </Field>
        {editing && server?.has_secret && <Callout kind="ok">A credential is stored (encrypted). Leave the fields empty to keep it, or enter a new value to replace it.</Callout>}
        {f.authentication_mode === 'header' && <Field label="Header name"><input value={f.header_name} onChange={e => set('header_name', e.target.value)} placeholder="X-Api-Key" /></Field>}
        {(f.authentication_mode === 'bearer' || f.authentication_mode === 'header') &&
          <Field label="Token" hint="Encrypted with AES-GCM at rest. It is never shown again or returned by the API."><input type="password" autoComplete="new-password" value={f.token} onChange={e => set('token', e.target.value)} /></Field>}
        {f.authentication_mode === 'env' &&
          <Field label="Secret environment (KEY=value per line)" hint="Encrypted at rest and injected only into the server process."><textarea value={f.secretEnv} onChange={e => set('secretEnv', e.target.value)} /></Field>}
        {f.transport === 'streamable_http' && <>
          <div className="section-title">Mutual TLS (optional)</div>
          <Field label="CA bundle for this server's certificate" hint={editing && server?.tls?.ca_certificates.length
            ? `Currently: ${server.tls.ca_certificates.map(c => c.subject).join('; ')}. Leave blank to keep.`
            : 'For servers with a certificate from an internal CA. Default: the standard public CAs.'}>
            <textarea className="mono" rows={3} value={f.tls_ca_pem} onChange={e => set('tls_ca_pem', e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" /></Field>
          {editing && !!server?.tls?.ca_certificates.length && <label className="check"><input type="checkbox" checked={f.clear_ca} onChange={e => set('clear_ca', e.target.checked)} />Remove the custom CA bundle</label>}
          {editing && server?.tls?.client_certificate && <Callout kind="ok">The gateway presents <b>{server.tls.client_certificate.subject}</b> (expires {new Date(server.tls.client_certificate.not_after).toLocaleDateString()}). Enter a new pair to replace it.</Callout>}
          <div className="field-row">
            <Field label="Client certificate (PEM)" hint="Presented when the server requires mTLS. Chain certificates may follow it.">
              <textarea className="mono" rows={4} value={f.client_cert_pem} onChange={e => set('client_cert_pem', e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" /></Field>
            <Field label="Private key (PEM, unencrypted)" hint="Write-only: encrypted with AES-GCM at rest and never returned by the API.">
              <textarea className="mono" rows={4} autoComplete="off" spellCheck={false} value={f.client_key_pem} onChange={e => set('client_key_pem', e.target.value)} placeholder="-----BEGIN PRIVATE KEY-----" /></Field>
          </div>
          {editing && server?.tls?.client_certificate && <label className="check"><input type="checkbox" checked={f.remove_client_cert} onChange={e => set('remove_client_cert', e.target.checked)} />Remove the client certificate</label>}
        </>}
      </>}

      {step === 3 && <div className="field-row">
        <Field label="Connection timeout (s)"><input type="number" min={1} max={120} value={f.connection_timeout_seconds} onChange={e => set('connection_timeout_seconds', Number(e.target.value))} /></Field>
        <Field label="Request timeout (s)"><input type="number" min={1} max={300} value={f.request_timeout_seconds} onChange={e => set('request_timeout_seconds', Number(e.target.value))} /></Field>
        <Field label="Max concurrent calls"><input type="number" min={1} max={200} value={f.max_concurrent_calls} onChange={e => set('max_concurrent_calls', Number(e.target.value))} /></Field>
      </div>}

      {step === 4 && <>
        <div className="toggle-row"><span>Allow private network addresses<br /><small className="muted">Needed for servers inside your network (10.x, 172.16/12, 192.168.x, loopback). Link-local and cloud metadata addresses stay blocked.</small></span><Switch on={f.allow_private_network} onChange={v => set('allow_private_network', v)} label="Allow private network" /></div>
        {f.allow_private_network && <Callout kind="warn">Private-network access widens the SSRF surface. Combine it with the platform host allowlist.</Callout>}
        {!editing && <div className="toggle-row"><span>Enable server after registration<br /><small className="muted">Discovered tools stay disabled until reviewed, whatever this setting.</small></span><Switch on={f.enabled} onChange={v => set('enabled', v)} label="Enabled" /></div>}
      </>}

      {step === 5 && <>
        <Callout>Saving does not expose any tool. New tools are discovered as <b>disabled / pending review</b> and need a risk level and a policy before agents can see them.</Callout>
        <dl className="kv">
          <dt>Name</dt><dd>{f.name} <span className="mono muted">({f.alias})</span></dd>
          <dt>Transport</dt><dd>{f.transport}</dd>
          <dt>{f.transport === 'stdio' ? 'Command' : 'Endpoint'}</dt><dd className="mono">{f.transport === 'stdio' ? [f.command, ...f.args].join(' ') : f.endpoint}</dd>
          <dt>Environment</dt><dd>{f.environment}</dd>
          <dt>Authentication</dt><dd>{f.authentication_mode}{(f.token || f.secretEnv) ? ' (new secret provided)' : ''}</dd>
          <dt>Limits</dt><dd>{f.connection_timeout_seconds}s connect · {f.request_timeout_seconds}s request · {f.max_concurrent_calls} concurrent</dd>
          <dt>TLS / network</dt><dd>{f.verify_tls ? 'verify TLS' : 'NO TLS verification'} · {f.allow_private_network ? 'private network allowed' : 'public addresses only'}</dd>
          {f.transport === 'streamable_http' && <><dt>Mutual TLS</dt><dd>{f.client_cert_pem.trim() ? 'new client certificate provided' : f.remove_client_cert ? 'client certificate removed' : server?.tls?.client_certificate ? 'client certificate kept' : 'no client certificate'}{f.tls_ca_pem.trim() ? ' · custom CA bundle' : ''}</dd></>}
        </dl>
      </>}

      {errs.length > 0 && step < 5 && (editing || touched.has(step)) && <Callout kind="warn">{errs.map(e => <div key={e}>{e}</div>)}</Callout>}
    </Modal>
  )
}
