import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Download, FileUp, Loader2, Play, Upload } from 'lucide-react'
import { useAuth } from '../../app/auth'
import { api, ApiError, errorMessage } from '../../services/api'
import type { BundleAction, BundlePlan } from '../../services/types'
import { Badge, Callout, Confirm, Empty, Field, Panel, Switch, useToast } from '../../components/ui'

const ACTION: Record<BundleAction, { label: string; color?: 'green' | 'red' | 'orange' | 'purple' | 'blue' }> = {
  create: { label: 'create', color: 'green' }, update: { label: 'change', color: 'blue' },
  adopt: { label: 'adopt', color: 'purple' }, delete: { label: 'delete', color: 'red' },
  orphan: { label: 'orphaned', color: 'orange' }, unchanged: { label: 'unchanged' },
}

/** constraints: {...} becomes constraints.max_calls_per_minute: 30 → 10 (only what differs). */
function leafChanges(path: string, from: unknown, to: unknown): [string, unknown, unknown][] {
  const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)
  if (isObj(from) && isObj(to)) {
    return Array.from(new Set([...Object.keys(from), ...Object.keys(to)])).sort()
      .filter(k => JSON.stringify(from[k]) !== JSON.stringify(to[k]))
      .flatMap(k => leafChanges(`${path}.${k}`, from[k], to[k]))
  }
  return [[path, from, to]]
}

const show = (v: unknown) => v === undefined ? '-' : JSON.stringify(v)

export function PolicyBundles() {
  const { can } = useAuth()
  const canApply = can('platform_admin', 'tenant_admin', 'security_admin')
  const canExport = can('platform_admin', 'tenant_admin', 'security_admin', 'auditor')
  const isPlatform = can('platform_admin')
  const qc = useQueryClient()
  const toast = useToast()
  const [content, setContent] = useState('')
  const [prune, setPrune] = useState(false)
  const [plan, setPlan] = useState<BundlePlan | null>(null)
  const [planned, setPlanned] = useState<{ content: string; prune: boolean } | null>(null)
  const [showUnchanged, setShowUnchanged] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [exportScope, setExportScope] = useState<'tenant' | 'global'>('tenant')

  const stale = !!plan && (planned?.content !== content || planned?.prune !== prune)
  const doPlan = useMutation({
    mutationFn: () => api.post<BundlePlan>(`/policies/bundle/plan${prune ? '?prune=true' : ''}`, { content }),
    onSuccess: r => { setPlan(r); setPlanned({ content, prune }) },
    onError: () => setPlan(null),
  })
  const doApply = useMutation({
    mutationFn: () => api.post<BundlePlan>('/policies/bundle/apply', { content, prune, expected_fingerprint: plan!.fingerprint }),
    onSuccess: r => {
      setConfirming(false); setPlan(null); setPlanned(null)
      qc.invalidateQueries({ queryKey: ['policies'] })
      toast.ok(`Bundle ${r.bundle} applied: ${r.summary.create} created, ${r.summary.update + r.summary.adopt} changed, ${r.summary.delete} deleted`)
    },
    onError: e => {
      setConfirming(false)
      if (e instanceof ApiError && e.code === 'VERSION_CONFLICT') { setPlan(null); toast.error('Policies changed since the preview. Preview again and review the new diff.') }
      else toast.error(e)
    },
  })
  const exportBundle = async () => {
    try { await api.download(`/policies/bundle/export?scope=${exportScope}&bundle=exported`, undefined, 'exported.policies.yaml', 'GET') }
    catch (e) { toast.error(e) }
  }
  const load = (f: File | undefined) => {
    if (!f) return
    if (f.size > 1_000_000) { toast.error('The bundle is larger than 1 MB.'); return }
    f.text().then(t => setContent(t))
  }

  const s = plan?.summary
  const changes = (plan?.changes || []).filter(c => showUnchanged || c.action !== 'unchanged')
  const hasChanges = !!s && (s.create + s.update + s.adopt + s.delete) > 0

  return <div className="two-col">
    <Panel title="Policy bundle" subtitle="Manage policies as a versioned YAML file. Preview changes nothing; apply makes exactly the previewed changes."
      actions={canExport && <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        {isPlatform && <select className="compact-select" aria-label="Export scope" value={exportScope} onChange={e => setExportScope(e.target.value as 'tenant' | 'global')}>
          <option value="tenant">This tenant</option><option value="global">Global</option></select>}
        <button className="btn secondary" onClick={exportBundle}><Download size={13} />Export live policies</button>
      </div>}>
      <Field label="Bundle (YAML or JSON)" hint={<>Format and CI setup: <span className="mono">docs/policy-as-code.md</span>. The command-line tool is in <span className="mono">deploy/policy-as-code/</span>.</>}>
        <textarea className="mono" spellCheck={false} style={{ minHeight: 340, fontFamily: 'ui-monospace,monospace', fontSize: 10 }}
          value={content} onChange={e => setContent(e.target.value)}
          placeholder={'apiVersion: mcp-gateway/v1\nkind: PolicyBundle\nmetadata:\n  name: hr-assistants\n  scope: tenant\npolicies:\n  - name: hr-read\n    effect: allow\n    principals: {types: [agent], ids: [agt_...]}\n    resources: {servers: [hr], tools: [get_employee]}\n    actions: [discover, invoke]'} />
      </Field>
      <div className="toggle-row"><span>Delete policies this bundle owns that are no longer in the file (prune)</span><Switch on={prune} onChange={setPrune} label="Prune" /></div>
      <div className="form-actions">
        <label className="btn secondary" style={{ cursor: 'pointer' }}><FileUp size={13} />Load file
          <input type="file" accept=".yaml,.yml,.json,text/yaml,application/json" style={{ display: 'none' }} onChange={e => { load(e.target.files?.[0]); e.target.value = '' }} />
        </label>
        <button className="btn primary" disabled={!content.trim() || doPlan.isPending} onClick={() => doPlan.mutate()}>
          {doPlan.isPending ? <Loader2 size={13} className="spin" /> : <Play size={13} />}Preview changes</button>
      </div>
    </Panel>

    <Panel title="Preview" actions={plan && <label className="check" style={{ fontSize: 10 }}><input type="checkbox" checked={showUnchanged} onChange={e => setShowUnchanged(e.target.checked)} />show unchanged</label>}>
      {doPlan.error ? <Callout kind="danger">{errorMessage(doPlan.error)}</Callout>
        : !plan ? <Empty title="No preview yet">Paste or load a bundle, then preview what applying it would change.</Empty>
        : <>
          <div className="detail-grid" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
            <div><small>BUNDLE</small><b className="mono">{plan.bundle}</b></div>
            <div><small>SCOPE</small><b>{plan.scope === 'global' ? 'global' : 'this tenant'}</b></div>
            <div><small>CHANGES</small><b>{s!.create} new · {s!.update + s!.adopt} changed · {s!.delete} deleted</b></div>
            <div><small>UNCHANGED</small><b>{s!.unchanged}{s!.orphan ? ` · ${s!.orphan} orphaned` : ''}</b></div>
          </div>
          {stale && <Callout kind="warn">The bundle or the prune setting changed since this preview. Preview again before applying.</Callout>}
          {plan.errors.length > 0 && <Callout kind="danger"><b>The bundle can't be applied:</b><ul style={{ margin: '4px 0 0', paddingLeft: 16 }}>{plan.errors.map((e, i) => <li key={i}><b>{e.policy}</b>: {e.message}</li>)}</ul></Callout>}
          {plan.warnings.length > 0 && <Callout kind="warn"><b>Warnings</b> (the policy is saved, but won't match until these exist):<ul style={{ margin: '4px 0 0', paddingLeft: 16 }}>{plan.warnings.slice(0, 20).map((w, i) => <li key={i}><b>{w.policy}</b>: {w.message}</li>)}</ul></Callout>}
          {s!.orphan > 0 && !prune && <Callout kind="info">Orphaned policies are owned by this bundle but missing from the file. They stay as they are unless you turn on prune.</Callout>}
          {changes.length === 0 ? <p className="muted">Nothing to change. The live policies already match the bundle.</p> : <div className="table-wrap"><table>
            <thead><tr><th>POLICY</th><th>ACTION</th><th>DIFFERENCE</th></tr></thead>
            <tbody>{changes.map(c => <tr key={`${c.action}-${c.name}`}>
              <td><b>{c.name}</b>{c.broad && c.broad.length > 0 && <> <Badge color="orange">broad</Badge></>}</td>
              <td><Badge color={ACTION[c.action].color}>{ACTION[c.action].label}</Badge></td>
              <td className="mono" style={{ fontSize: 9 }}>{c.action === 'create' ? <span className="muted">new policy</span>
                : c.action === 'adopt' && Object.keys(c.diff).length === 0 ? <span className="muted">take ownership; no field changes</span>
                : Object.entries(c.diff).flatMap(([f, d]) => leafChanges(f, d.from, d.to)).map(([p, from, to]) =>
                  <div key={p}>{p}: <span className="diff-old">{show(from)}</span> → <span className="diff-new">{show(to)}</span></div>)}</td>
            </tr>)}</tbody>
          </table></div>}
          <p className="muted mono" style={{ fontSize: 9 }}>Fingerprint {plan.fingerprint.slice(0, 16)}…</p>
          {canApply ? <div className="form-actions">
            <button className="btn primary" disabled={!plan.valid || !hasChanges || stale || doApply.isPending} onClick={() => setConfirming(true)}>
              <Upload size={13} />Apply {s!.create + s!.update + s!.adopt + s!.delete} change{s!.create + s!.update + s!.adopt + s!.delete === 1 ? '' : 's'}</button>
          </div> : <Callout kind="info">Your role can preview bundles. Applying needs a security or tenant administrator.</Callout>}
        </>}
    </Panel>

    {confirming && plan && <Confirm danger={s!.delete > 0} title="Apply policy bundle" confirmLabel="Apply" busy={doApply.isPending}
      typed={s!.delete > 0 ? 'APPLY' : undefined}
      message={<>Apply bundle <b>{plan.bundle}</b>: {s!.create} new, {s!.update + s!.adopt} changed, {s!.delete} deleted. Access changes take effect immediately.
        If anyone changed these policies since the preview, nothing is applied.</>}
      onConfirm={() => doApply.mutate()} onClose={() => setConfirming(false)} />}
  </div>
}
