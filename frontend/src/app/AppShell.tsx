import { ReactNode, useState } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Activity, BarChart3, Bell, Bot, CheckSquare, ChevronRight, FileText, LayoutDashboard, LogOut, Menu, Moon,
  Server, Settings, Shield, ShieldCheck, Sun, Users, Wrench, X,
} from 'lucide-react'
import { useAuth } from './auth'
import { api } from '../services/api'
import { cn, initials, ROLE_LABELS } from '../services/format'
import type { HealthComponent } from '../services/types'
import { useToast } from '../components/ui'
import { AUDIT_READ, SECURITY } from '../services/roles'

interface NavEntry { to: string; label: string; icon: typeof Server; roles?: string[]; group?: string }

/** Navigation follows spec §18.2. Visibility is a convenience. The server enforces every permission. */
export const NAV: NavEntry[] = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, group: 'Workspace' },
  { to: '/servers', label: 'MCP Servers', icon: Server, group: 'Registry' },
  { to: '/tools', label: 'Tool Catalog', icon: Wrench },
  { to: '/policies', label: 'Policies', icon: ShieldCheck, group: 'Access control' },
  { to: '/agents', label: 'Agents & Credentials', icon: Bot },
  { to: '/approvals', label: 'Approvals', icon: CheckSquare },
  { to: '/audit', label: 'Audit Logs', icon: FileText, roles: AUDIT_READ, group: 'Observability' },
  { to: '/usage', label: 'Usage & Quotas', icon: BarChart3 },
  { to: '/users', label: 'Users & Tenants', icon: Users, roles: [...SECURITY, 'auditor'], group: 'Administration' },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export function AppShell({ children }: { children: ReactNode }) {
  const { me, can, logout, switchTenant } = useAuth()
  const [mobileNav, setMobileNav] = useState(false)
  const [light, setLight] = useState(() => { try { return localStorage.getItem('mgw-theme') === 'light' } catch { return false } })
  const loc = useLocation()
  const nav = useNavigate()
  const toast = useToast()

  const pending = useQuery({
    queryKey: ['approvals-count'],
    queryFn: () => api.get<{ counts: { pending: number } }>('/approvals', { status: 'pending', limit: 1 }),
    refetchInterval: 30_000,
    enabled: !!me,
  })
  const health = useQuery({
    queryKey: ['health-components'],
    queryFn: () => api.get<{ health: HealthComponent[] }>('/settings'),
    refetchInterval: 60_000,
    enabled: !!me,
  })
  const pendingCount = pending.data?.counts?.pending ?? 0
  const unhealthy = (health.data?.health || []).filter(h => h.status !== 'healthy')
  const healthText = health.isLoading ? 'Checking health…' : health.error ? 'Health unknown' : unhealthy.length ? `${unhealthy.map(u => u.name).join(', ')} degraded` : 'All systems operational'

  const current = [...NAV].reverse().find(n => n.to === '/' ? loc.pathname === '/' : loc.pathname.startsWith(n.to))
  const toggleTheme = () => {
    setLight(v => { try { localStorage.setItem('mgw-theme', v ? 'dark' : 'light') } catch { /* ignore */ } return !v })
  }
  const roleLabel = me?.is_platform_admin ? 'Platform Admin' : (me?.roles || []).map(r => ROLE_LABELS[r] || r).join(', ')
  const currentTenant = me?.tenants.find(t => t.id === me.tenant_id)

  return (
    <div className={cn('app', light && 'light')}>
      {mobileNav && <div className="scrim" onClick={() => setMobileNav(false)} />}
      <aside className={cn('sidebar', mobileNav && 'open')}>
        <div className="brand">
          <div className="brand-mark"><Shield size={21} color="#fff" /></div>
          <div><b>MCP-Gateway</b><small>Secure Agent Tool Gateway</small></div>
          <button className="mobile-close" aria-label="Close menu" onClick={() => setMobileNav(false)}><X size={18} /></button>
        </div>
        {me && me.tenants.length > 1 ? (
          <div className="tenant-switch">
            <label htmlFor="tenant-select">TENANT</label>
            <select id="tenant-select" value={me.tenant_id} onChange={async e => {
              try { await switchTenant(e.target.value); nav('/'); toast.ok('Tenant switched') } catch (err) { toast.error(err) }
            }}>
              {me.tenants.map(t => <option key={t.id} value={t.id}>{t.name}{t.status !== 'active' ? ` (${t.status})` : ''}</option>)}
            </select>
          </div>
        ) : currentTenant && (
          <div className="tenant-switch"><label>TENANT</label><div style={{ fontSize: 12, padding: '4px 2px' }}>{currentTenant.name}</div></div>
        )}
        <nav className="nav-list">
          {NAV.filter(n => !n.roles || can(...n.roles)).map(n => (
            <div key={n.to}>
              {n.group && <div className="nav-group">{n.group}</div>}
              <NavLink to={n.to} end={n.to === '/'} onClick={() => setMobileNav(false)} className={({ isActive }) => cn('nav-item', isActive && 'active')}>
                <n.icon size={17} /><span>{n.label}</span>
                {n.to === '/approvals' && pendingCount > 0 && <em>{pendingCount}</em>}
              </NavLink>
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="health"><span className="pulse" style={unhealthy.length ? { background: '#e9a23b', boxShadow: '0 0 0 4px #e9a23b20' } : undefined} />{healthText}</div>
          <div className="profile">
            <div className="avatar">{initials(me?.display_name || '?')}</div>
            <div style={{ minWidth: 0 }}><b>{me?.display_name}</b><small>{roleLabel}</small></div>
            <button className="icon-btn" title="Sign out" aria-label="Sign out" style={{ marginLeft: 'auto' }} onClick={() => logout()}><LogOut size={15} /></button>
          </div>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="top-left">
            <button className="icon-btn menu-btn" aria-label="Open menu" onClick={() => setMobileNav(true)}><Menu /></button>
            <div className="crumb">{currentTenant?.name || 'Workspace'} <ChevronRight size={14} /> <b>{current?.label || 'Overview'}</b></div>
          </div>
          <div className="top-actions">
            <div className="system-pill" style={unhealthy.length ? { color: '#f4b45e' } : undefined}><Activity size={12} />{me?.environment} · v{me?.version}</div>
            <button className="icon-btn" title="Toggle theme" aria-label="Toggle theme" onClick={toggleTheme}>{light ? <Moon size={17} /> : <Sun size={17} />}</button>
            <button className="icon-btn bell" title="Pending approvals" aria-label="Pending approvals" onClick={() => nav('/approvals')}><Bell size={17} />{pendingCount > 0 && <i>{pendingCount > 99 ? '99+' : pendingCount}</i>}</button>
            <div className="top-avatar" title={me?.display_name}>{initials(me?.display_name || '?')}</div>
          </div>
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  )
}
