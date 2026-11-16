import type { Policy } from './types'

export function cn(...v: (string | false | null | undefined)[]) { return v.filter(Boolean).join(' ') }

export function timeAgo(iso?: string | null): string {
  if (!iso) return 'Never'
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return '-'
  const s = Math.round((Date.now() - t) / 1000)
  if (s < 0) return `in ${fmtDuration(-s)}`
  if (s < 45) return 'just now'
  return `${fmtDuration(s)} ago`
}

export function fmtDuration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h`
  return `${Math.round(seconds / 86400)} d`
}

export function dateTime(iso?: string | null): string {
  if (!iso) return '-'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '-' : d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function num(n?: number | null): string {
  if (n === undefined || n === null) return '-'
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M'
  if (n >= 10_000) return (n / 1000).toFixed(1) + 'K'
  return n.toLocaleString()
}

export function shortHash(h?: string | null): string { return h ? h.replace('sha256:', '').slice(0, 12) + '…' : '-' }

export const ROLE_LABELS: Record<string, string> = {
  platform_admin: 'Platform Admin', security_admin: 'Security Admin', tenant_admin: 'Tenant Admin',
  approver: 'Approver', auditor: 'Auditor', developer: 'Developer',
}
export const TENANT_ROLES = ['tenant_admin', 'security_admin', 'approver', 'auditor', 'developer']

export function hasRole(roles: string[] | undefined, ...wanted: string[]): boolean {
  return !!roles && wanted.some(r => roles.includes(r))
}

export function initials(name: string): string {
  return name.split(/[\s._@-]+/).filter(Boolean).slice(0, 2).map(x => x[0]?.toUpperCase()).join('') || '?'
}

/** Fill optional policy arrays so older stored policies (missing e.g. roles or risk_levels) render safely. */
export function normalizePolicy<P extends Policy>(p: P): P {
  const pr: Partial<Policy['principals']> = p.principals || {}
  const rs: Partial<Policy['resources']> = p.resources || {}
  const cs: Partial<Policy['constraints']> = p.constraints || {}
  return {
    ...p,
    principals: { types: pr.types ?? [], ids: pr.ids ?? [], roles: pr.roles ?? [] },
    resources: { servers: rs.servers ?? [], tools: rs.tools ?? [], risk_levels: rs.risk_levels ?? [] },
    actions: p.actions ?? [],
    constraints: { ...cs, environments: cs.environments ?? [], time_windows: cs.time_windows ?? [], source_cidrs: cs.source_cidrs ?? [] } as Policy['constraints'],
    broad: p.broad ?? [],
  }
}
