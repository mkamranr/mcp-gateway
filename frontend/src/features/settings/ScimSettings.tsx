import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, CheckCircle2, Copy, KeyRound, Loader2, RefreshCw, Save, Trash2 } from 'lucide-react'
import { api, ApiError, errorMessage } from '../../services/api'
import { dateTime, timeAgo } from '../../services/format'
import type { ScimConfig } from '../../services/types'
import { Badge, Callout, Field, Modal, Panel, QueryState, Switch, useToast } from '../../components/ui'

export function ScimSettings() {
  const q = useQuery({ queryKey: ['scim-config'], queryFn: () => api.get<ScimConfig>('/scim/config') })
  return <QueryState q={q}>{d => <Form cfg={d} />}</QueryState>
}

function Form({ cfg }: { cfg: ScimConfig }) {
  const [enabled, setEnabled] = useState(cfg.enabled)
  const [linkClaim, setLinkClaim] = useState(cfg.link_claim)
  const [authoritative, setAuthoritative] = useState(cfg.groups_authoritative)
  const [byName, setByName] = useState(cfg.match_group_display_name)
  const [err, setErr] = useState<ApiError | null>(null)
  const [token, setToken] = useState<string | null>(null)
  useEffect(() => { setEnabled(cfg.enabled); setLinkClaim(cfg.link_claim); setAuthoritative(cfg.groups_authoritative); setByName(cfg.match_group_display_name) }, [cfg])
  const qc = useQueryClient()
  const toast = useToast()
  const refresh = () => qc.invalidateQueries({ queryKey: ['scim-config'] })
  const save = useMutation({
    mutationFn: () => api.put<ScimConfig>('/scim/config', { enabled, link_claim: linkClaim, groups_authoritative: authoritative, match_group_display_name: byName }),
    onSuccess: () => { setErr(null); refresh(); toast.ok('Provisioning settings saved') },
    onError: e => e instanceof ApiError ? setErr(e) : toast.error(e),
  })
  const rotate = useMutation({
    mutationFn: () => api.post<ScimConfig>('/scim/token', {}),
    onSuccess: r => { setToken(r.token || null); refresh() }, onError: e => toast.error(e),
  })
  const revoke = useMutation({
    mutationFn: () => api.del<ScimConfig>('/scim/token'),
    onSuccess: () => { refresh(); toast.ok('SCIM token revoked; provisioning is off') }, onError: e => toast.error(e),
  })

  return <>
    <Panel title="Provisioning (SCIM 2.0)" subtitle="Your identity provider creates, updates and deactivates single sign-on users, and pushes group memberships, as soon as they change there."
      actions={<div className="toggle-row" style={{ border: 0, padding: 0 }}><span>{enabled ? <Badge color="green">enabled</Badge> : <Badge>disabled</Badge>}</span><Switch on={enabled} onChange={setEnabled} label="SCIM provisioning enabled" /></div>}>
      {err && <Callout kind="danger">{errorMessage(err)}</Callout>}
      <Callout>SCIM manages only the accounts it creates. Local, break-glass and directory accounts are never visible to it. Deactivating a user in the identity provider ends their sessions at once.</Callout>
      <dl className="kv">
        <dt>SCIM base URL (tenant URL)</dt><dd className="mono">{cfg.base_url}</dd>
        <dt>Token</dt><dd>{cfg.has_token ? <><span className="mono">{cfg.token_prefix}…</span> <span className="muted">created {dateTime(cfg.token_created_at)}</span></> : <span className="muted">none</span>}</dd>
        <dt>Last request</dt><dd className="muted">{cfg.last_used_at ? timeAgo(cfg.last_used_at) : 'never'}</dd>
      </dl>
      <div className="form-actions" style={{ marginTop: 8, borderTop: 0, paddingTop: 0 }}>
        <button type="button" className="btn secondary" disabled={rotate.isPending} onClick={() => { if (!cfg.has_token || confirm('Generate a new token? The current one stops working immediately.')) rotate.mutate() }}>
          {rotate.isPending ? <Loader2 size={13} className="spin" /> : cfg.has_token ? <RefreshCw size={13} /> : <KeyRound size={13} />}{cfg.has_token ? 'Rotate token' : 'Generate token'}</button>
        {cfg.has_token && <button type="button" className="btn danger" disabled={revoke.isPending} onClick={() => { if (confirm('Revoke the SCIM token? Provisioning stops until a new token is configured in the identity provider.')) revoke.mutate() }}><Trash2 size={13} />Revoke token</button>}
      </div>
    </Panel>

    <Panel title="Sign-in and groups">
      <Field label="Link claim" hint="ID-token claim that equals the user's SCIM externalId. Entra ID: oid (the default externalId mapping is objectId). Okta: sub, with externalId mapped to the user ID. Accounts are never linked by username.">
        <input value={linkClaim} onChange={e => setLinkClaim(e.target.value)} placeholder="sub" />
      </Field>
      <div className="toggle-row"><span>Roles from SCIM groups (the single sign-on group rules are applied to the pushed groups). Off: roles come from the ID token at each sign-in.</span><Switch on={authoritative} onChange={setAuthoritative} label="SCIM groups authoritative" /></div>
      <div className="toggle-row"><span>Match groups without an external ID by display name. Only for identity providers that send no externalId: anyone who can create a provisioned group could name it after an administrator group.</span><Switch on={byName} onChange={setByName} label="Match groups by display name" /></div>
      <p className="muted" style={{ fontSize: 10 }}>Group rules and platform-administrator groups are configured under Single sign-on. A rule matches a SCIM group by its external ID{byName ? ', or by its display name if the group has no external ID' : ''}.</p>
      <div className="form-actions" style={{ borderTop: 0, paddingTop: 0 }}>
        <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? <Loader2 size={13} className="spin" /> : <Save size={13} />}Save</button>
        {cfg.updated_at && <span className="muted" style={{ fontSize: 10, alignSelf: 'center' }}><CheckCircle2 size={10} /> Last saved {dateTime(cfg.updated_at)}</span>}
      </div>
    </Panel>

    {token && <TokenOnce token={token} baseUrl={cfg.base_url} onClose={() => setToken(null)} />}
  </>
}

function TokenOnce({ token, baseUrl, onClose }: { token: string; baseUrl: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  const [ack, setAck] = useState(false)
  const copy = async () => {
    try { await navigator.clipboard.writeText(token); setCopied(true) } catch { /* clipboard blocked: user can select manually */ }
  }
  return <Modal title="SCIM token created" onClose={() => { if (ack) onClose() }} footer={<button className="btn primary" disabled={!ack} onClick={onClose}>Done</button>}>
    <Callout kind="warn">Copy this token now. It is shown only once and cannot be retrieved later. Only a hash is stored.</Callout>
    <div className="secret-box"><KeyRound size={14} /><span style={{ flex: 1, userSelect: 'all', wordBreak: 'break-all' }}>{token}</span>
      <button className="small-btn" onClick={copy}>{copied ? <Check size={11} /> : <Copy size={11} />}{copied ? 'Copied' : 'Copy'}</button></div>
    <div className="section-title">In the identity provider</div>
    <pre className="code">{`Tenant URL / SCIM base URL:  ${baseUrl}
Secret token / API token:    <this token>  (HTTP header: Authorization: Bearer)`}</pre>
    <p className="muted" style={{ fontSize: 10 }}>Then turn on provisioning here and save.</p>
    <label className="check"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />I entered the token in the identity provider</label>
  </Modal>
}
