import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Check, Copy, KeyRound, Loader2 } from 'lucide-react'
import { api } from '../../services/api'
import type { CertInfo, Credential } from '../../services/types'
import { Callout, Field, Modal, Tabs, useToast } from '../../components/ui'

const SCOPES = [
  { value: 'tools:list', label: 'tools:list: discover permitted tools' },
  { value: 'tools:invoke', label: 'tools:invoke: call permitted tools' },
  { value: 'approvals:read', label: 'approvals:read: poll own approval requests' },
]

/** The secret is returned exactly once by the API. It lives only in this component's state and is never cached. */
export function SecretOnce({ cred, onClose }: { cred: Credential; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  const [ack, setAck] = useState(false)
  const copy = async () => {
    try { await navigator.clipboard.writeText(cred.secret || ''); setCopied(true) } catch { /* clipboard blocked: user can select manually */ }
  }
  const mcpUrl = `${window.location.origin}/mcp`
  return (
    <Modal title="Agent key created" onClose={() => { if (ack) onClose() }} footer={<button className="btn primary" disabled={!ack} onClick={onClose}>Done</button>}>
      <Callout kind="warn">Copy this key now. It is shown only once and cannot be retrieved later. Only a hash is stored.</Callout>
      <div className="secret-box"><KeyRound size={14} /><span style={{ flex: 1, userSelect: 'all' }}>{cred.secret}</span>
        <button className="small-btn" onClick={copy}>{copied ? <Check size={11} /> : <Copy size={11} />}{copied ? 'Copied' : 'Copy'}</button></div>
      <div className="section-title">Use it from an MCP client</div>
      <pre className="code">{`URL:    ${mcpUrl}
Header: Authorization: Bearer <this key>`}</pre>
      <label className="check"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />I stored the key in a secret manager</label>
    </Modal>
  )
}

export interface CertificateStatus { enabled: boolean; trusted_cas: CertInfo[] }

/** Client certificate credential: nothing secret is entered here. The agent keeps its private key, and the TLS proxy
 *  checks that it holds it; the gateway only learns which certificate (or which subject name) belongs to this agent. */
export function AddCertificateDialog({ agentId, agentName, status, onClose }: { agentId: string; agentName: string; status: CertificateStatus; onClose: () => void }) {
  const [mode, setMode] = useState<'subject' | 'pin'>('subject')
  const [name, setName] = useState('certificate')
  const [subject, setSubject] = useState('')
  const [pem, setPem] = useState('')
  const [scopes, setScopes] = useState<string[]>(SCOPES.map(s => s.value))
  const [expires, setExpires] = useState('')
  const qc = useQueryClient()
  const toast = useToast()
  const m = useMutation({
    mutationFn: () => api.post<Credential>('/auth/agent-certificates', {
      agent_id: agentId, name, scopes, expires_at: expires ? new Date(expires).toISOString() : null,
      ...(mode === 'subject' ? { subject_name: subject.trim() } : { certificate_pem: pem.trim() }),
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['agent', agentId] }); qc.invalidateQueries({ queryKey: ['agents'] }); toast.ok('Certificate credential added'); onClose() },
    onError: e => toast.error(e),
  })
  const ready = name && scopes.length && (mode === 'subject' ? subject.trim() : pem.includes('BEGIN CERTIFICATE'))
  return (
    <Modal title={`Client certificate for ${agentName}`} onClose={onClose} footer={<>
      <button className="btn secondary" onClick={onClose}>Cancel</button>
      <button className="btn primary" disabled={!ready || m.isPending} onClick={() => m.mutate()}>{m.isPending && <Loader2 size={13} className="spin" />}Add certificate</button>
    </>}>
      <Field label="Name"><input value={name} onChange={e => setName(e.target.value)} /></Field>
      <Tabs value={mode} onChange={v => setMode(v as 'subject' | 'pin')} options={[{ value: 'subject', label: 'Match subject name' }, { value: 'pin', label: 'Pin one certificate' }]} />
      {mode === 'subject'
        ? <Field label="Subject alternative name" hint="A URI such as a SPIFFE ID, or a DNS name. Any valid certificate from a trusted CA carrying it is accepted, so certificates can be renewed without changing anything here.">
            <input className="mono" value={subject} onChange={e => setSubject(e.target.value)} placeholder="spiffe://corp.example/agents/hr-bot" /></Field>
        : <Field label="Certificate (PEM)" hint="Only this exact certificate is accepted. The credential expires with it. Paste the certificate, never the private key.">
            <textarea className="mono" rows={7} value={pem} onChange={e => setPem(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" /></Field>}
      <div className="field"><span>Scopes</span>{SCOPES.map(s => <label className="check" key={s.value}><input type="checkbox" checked={scopes.includes(s.value)} onChange={e => setScopes(e.target.checked ? [...scopes, s.value] : scopes.filter(x => x !== s.value))} />{s.label}</label>)}</div>
      <Field label="Expires (optional)"><input type="datetime-local" value={expires} onChange={e => setExpires(e.target.value)} /></Field>
      <Callout>Accepted from: {status.trusted_cas.map(c => c.subject).join('; ') || 'no CA configured'}. The agent connects to the gateway's mTLS listener with its certificate; no key is shown or stored.</Callout>
    </Modal>
  )
}

export function CreateKeyDialog({ agentId, agentName, onClose, onCreated }: { agentId: string; agentName: string; onClose: () => void; onCreated: (c: Credential) => void }) {
  const [name, setName] = useState('default')
  const [scopes, setScopes] = useState<string[]>(SCOPES.map(s => s.value))
  const [expires, setExpires] = useState('')
  const qc = useQueryClient()
  const toast = useToast()
  const m = useMutation({
    mutationFn: () => api.post<Credential>('/auth/agent-keys', { agent_id: agentId, name, scopes, expires_at: expires ? new Date(expires).toISOString() : null }),
    onSuccess: c => { qc.invalidateQueries({ queryKey: ['agent', agentId] }); qc.invalidateQueries({ queryKey: ['agents'] }); onCreated(c) },
    onError: e => toast.error(e),
  })
  return (
    <Modal title={`New key for ${agentName}`} onClose={onClose} footer={<>
      <button className="btn secondary" onClick={onClose}>Cancel</button>
      <button className="btn primary" disabled={!name || !scopes.length || m.isPending} onClick={() => m.mutate()}>{m.isPending && <Loader2 size={13} className="spin" />}Create key</button>
    </>}>
      <Field label="Key name"><input value={name} onChange={e => setName(e.target.value)} /></Field>
      <div className="field"><span>Scopes</span>{SCOPES.map(s => <label className="check" key={s.value}><input type="checkbox" checked={scopes.includes(s.value)} onChange={e => setScopes(e.target.checked ? [...scopes, s.value] : scopes.filter(x => x !== s.value))} />{s.label}</label>)}</div>
      <Field label="Expires (optional)" hint="Keys without expiry should be rotated regularly."><input type="datetime-local" value={expires} onChange={e => setExpires(e.target.value)} /></Field>
      <Callout>Scopes only limit what the key may attempt. Policies still decide which tools are visible and callable.</Callout>
    </Modal>
  )
}
