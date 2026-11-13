import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from 'react'
import { AlertTriangle, CheckCircle2, ChevronLeft, ChevronRight, Inbox, Loader2, X } from 'lucide-react'
import { errorMessage } from '../services/api'
import { cn } from '../services/format'
import type { Risk } from '../services/types'

/* ---------- layout ---------- */
export function PageHeading({ eyebrow, title, subtitle, actions }: { eyebrow?: string; title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="page-heading">
      <div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h1>{title}</h1>{subtitle && <p>{subtitle}</p>}</div>
      {actions && <div className="heading-actions">{actions}</div>}
    </div>
  )
}

export function Panel({ title, subtitle, actions, children, className }: { title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cn('panel', className)}>
      {(title || actions) && <div className="panel-head"><div>{title && <h3>{title}</h3>}{subtitle && <p>{subtitle}</p>}</div>{actions}</div>}
      {children}
    </section>
  )
}

export function Metric({ icon, color, label, value, sub }: { icon: ReactNode; color: 'blue' | 'green' | 'purple' | 'orange'; label: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <div className="metric">
      <div className={cn('metric-icon', color)}>{icon}</div>
      <div className="metric-info"><span>{label}</span><strong>{value}</strong>{sub && <small className="muted">{sub}</small>}</div>
    </div>
  )
}

/* ---------- states ---------- */
export function Loading({ label = 'Loading…' }: { label?: string }) {
  return <div className="state"><Loader2 size={20} className="spin" />{label}</div>
}
export function Empty({ title = 'Nothing here yet', children }: { title?: string; children?: ReactNode }) {
  return <div className="state"><Inbox size={22} /><b>{title}</b>{children}</div>
}
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <div className="state error"><AlertTriangle size={22} /><b>Could not load data</b><span>{errorMessage(error)}</span>
      {onRetry && <button className="btn secondary" onClick={onRetry}>Retry</button>}</div>
  )
}

/** Renders loading/error/empty states for a react-query result, else children. */
export function QueryState<T>({ q, empty, emptyText, children }: { q: { isLoading: boolean; error: unknown; data?: T; refetch: () => unknown }; empty?: (d: T) => boolean; emptyText?: ReactNode; children: (d: T) => ReactNode }) {
  if (q.isLoading) return <Loading />
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  if (q.data === undefined) return null
  if (empty && empty(q.data)) return <Empty>{emptyText}</Empty>
  return <>{children(q.data)}</>
}

/* ---------- badges ---------- */
export function RiskBadge({ risk }: { risk?: Risk | null }) {
  if (!risk) return <span className="risk none">unclassified</span>
  return <span className={cn('risk', risk)}>{risk}</span>
}

const STATUS_CLASS: Record<string, string> = {
  healthy: 'healthy', active: 'healthy', completed: 'healthy', approved: 'healthy', enabled: 'healthy', ok: 'healthy',
  degraded: 'warning', warning: 'warning', pending: 'warning', pending_review: 'warning', schema_changed: 'warning', expired: 'warning',
  unhealthy: 'offline', offline: 'offline', failed: 'offline', revoked: 'offline', disabled: 'offline', suspended: 'offline',
  rejected: 'offline', error: 'offline', tool_error: 'offline', execution_aborted: 'offline',
}
export function Status({ value, label }: { value?: string | null; label?: string }) {
  const v = (value || 'unknown').toLowerCase()
  return <span className={cn('status', STATUS_CLASS[v] || 'unknown')}><i />{label || v.replace(/_/g, ' ')}</span>
}

export function Badge({ children, color }: { children: ReactNode; color?: 'green' | 'red' | 'orange' | 'purple' | 'blue' }) {
  return <span className={cn('badge', color)}>{children}</span>
}

export function DecisionBadge({ value }: { value?: string | null }) {
  if (!value) return <span className="muted">-</span>
  return <span className={cn('decision', value)}>{value.replace('_', ' ')}</span>
}

/* ---------- controls ---------- */
export function Switch({ on, onChange, disabled, label }: { on: boolean; onChange: (v: boolean) => void; disabled?: boolean; label?: string }) {
  return <button type="button" role="switch" aria-checked={on} aria-label={label} disabled={disabled} className={cn('switch', on && 'on')} onClick={() => onChange(!on)}><i /></button>
}

export function Tabs<T extends string>({ value, options, onChange, large }: { value: T; options: { value: T; label: ReactNode }[]; onChange: (v: T) => void; large?: boolean }) {
  return (
    <div className={cn('tabs page-tabs', large && 'large')} role="tablist">
      {options.map(o => <button key={o.value} role="tab" aria-selected={value === o.value} className={cn(value === o.value && 'selected')} onClick={() => onChange(o.value)}>{o.label}</button>)}
    </div>
  )
}

export function Field({ label, hint, error, children }: { label: string; hint?: ReactNode; error?: string | null; children: ReactNode }) {
  return <label className="field"><span>{label}</span>{children}{hint && <span className="hint">{hint}</span>}{error && <span className="err">{error}</span>}</label>
}

export function Pager({ page, hasNext, total, pageSize, onPage }: { page: number; hasNext: boolean; total?: number; pageSize: number; onPage: (p: number) => void }) {
  const from = total === 0 ? 0 : page * pageSize + 1
  const to = page * pageSize + pageSize
  return (
    <div className="table-foot">
      <span>{total !== undefined ? `Showing ${from}–${Math.min(to, total)} of ${total}` : `Page ${page + 1}`}</span>
      <div>
        <button aria-label="Previous page" disabled={page === 0} onClick={() => onPage(page - 1)}><ChevronLeft size={13} /></button>
        <button className="current">{page + 1}</button>
        <button aria-label="Next page" disabled={!hasNext} onClick={() => onPage(page + 1)}><ChevronRight size={13} /></button>
      </div>
    </div>
  )
}

/* ---------- overlays ---------- */
export function Modal({ title, onClose, children, footer, wide }: { title: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])
  return (
    <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}>
      <div className={cn('modal', wide && 'wide')} role="dialog" aria-modal="true">
        <div className="modal-head"><h3>{title}</h3><button className="icon-btn" aria-label="Close" onClick={onClose}><X size={16} /></button></div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  )
}

export function Drawer({ title, onClose, children, footer }: { title: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])
  return (
    <div className="drawer-overlay" onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}>
      <aside className="drawer" role="dialog" aria-modal="true">
        <div className="modal-head"><h3>{title}</h3><button className="icon-btn" aria-label="Close" onClick={onClose}><X size={16} /></button></div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </aside>
    </div>
  )
}

export function Confirm({ title, message, confirmLabel = 'Confirm', danger, typed, onConfirm, onClose, busy, children }: {
  title: string; message: ReactNode; confirmLabel?: string; danger?: boolean; typed?: string; busy?: boolean
  onConfirm: () => void; onClose: () => void; children?: ReactNode
}) {
  const [text, setText] = useState('')
  const ok = !typed || text === typed
  return (
    <Modal title={title} onClose={onClose} footer={<>
      <button className="btn secondary" onClick={onClose}>Cancel</button>
      <button className={cn('btn', danger ? 'danger' : 'primary')} disabled={!ok || busy} onClick={onConfirm}>{busy && <Loader2 size={13} className="spin" />}{confirmLabel}</button>
    </>}>
      <div style={{ fontSize: 11, lineHeight: 1.5 }}>{message}</div>
      {children}
      {typed && <Field label={`Type "${typed}" to confirm`}><input value={text} onChange={e => setText(e.target.value)} autoFocus /></Field>}
    </Modal>
  )
}

export function JsonView({ value }: { value: unknown }) {
  return <pre className="code">{JSON.stringify(value, null, 2)}</pre>
}

export function Callout({ kind = 'info', children }: { kind?: 'info' | 'warn' | 'danger' | 'ok'; children: ReactNode }) {
  const Icon = kind === 'ok' ? CheckCircle2 : AlertTriangle
  return <div className={cn('callout', kind !== 'info' && kind)}><Icon size={14} /><div>{children}</div></div>
}

/* ---------- toasts ---------- */
type Toast = { id: number; kind: 'ok' | 'error'; text: string }
const ToastCtx = createContext<{ ok: (t: string) => void; error: (e: unknown) => void }>({ ok: () => {}, error: () => {} })
export const useToast = () => useContext(ToastCtx)

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([])
  const push = useCallback((kind: Toast['kind'], text: string) => {
    const id = Date.now() + Math.random()
    setItems(x => [...x.slice(-3), { id, kind, text }])
    setTimeout(() => setItems(x => x.filter(t => t.id !== id)), kind === 'error' ? 7000 : 3500)
  }, [])
  const value = { ok: (t: string) => push('ok', t), error: (e: unknown) => push('error', errorMessage(e)) }
  return (
    <ToastCtx.Provider value={value}>
      {children}
      <div className="toast-stack" aria-live="polite">
        {items.map(t => <div key={t.id} className={cn('toast', t.kind === 'error' && 'error')}>{t.kind === 'ok' ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}{t.text}</div>)}
      </div>
    </ToastCtx.Provider>
  )
}

/* ---------- list input ---------- */
export function ListInput({ value, onChange, placeholder }: { value: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const [text, setText] = useState('')
  const add = () => {
    const parts = text.split(',').map(s => s.trim()).filter(Boolean)
    if (parts.length) onChange(Array.from(new Set([...value, ...parts])))
    setText('')
  }
  return (
    <div style={{ display: 'grid', gap: 6 }}>
      <input value={text} placeholder={placeholder} onChange={e => setText(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add() } }} onBlur={add} />
      {value.length > 0 && <div className="chips">{value.map(v => <span className="chip" key={v}>{v}<button type="button" aria-label={`Remove ${v}`} onClick={() => onChange(value.filter(x => x !== v))}><X size={10} /></button></span>)}</div>}
    </div>
  )
}
