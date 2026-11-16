import { lazy, Suspense, type ComponentType } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './auth'
import { AppShell } from './AppShell'
import { Loading } from '../components/ui'
import { LoginPage } from '../features/auth/LoginPage'

// Each page is its own chunk, so the first load only ships the shell and the current page.
function page<K extends string>(load: () => Promise<Record<K, ComponentType>>, name: K) {
  return lazy(() => load().then(m => ({ default: m[name] })))
}

const OverviewPage = page(() => import('../features/overview/OverviewPage'), 'OverviewPage')
const ServersPage = page(() => import('../features/servers/ServersPage'), 'ServersPage')
const ServerDetailPage = page(() => import('../features/servers/ServerDetailPage'), 'ServerDetailPage')
const ToolsPage = page(() => import('../features/tools/ToolsPage'), 'ToolsPage')
const ToolDetailPage = page(() => import('../features/tools/ToolDetailPage'), 'ToolDetailPage')
const PoliciesPage = page(() => import('../features/policies/PoliciesPage'), 'PoliciesPage')
const AgentsPage = page(() => import('../features/agents/AgentsPage'), 'AgentsPage')
const AgentDetailPage = page(() => import('../features/agents/AgentDetailPage'), 'AgentDetailPage')
const ApprovalsPage = page(() => import('../features/approvals/ApprovalsPage'), 'ApprovalsPage')
const AuditPage = page(() => import('../features/audit/AuditPage'), 'AuditPage')
const UsagePage = page(() => import('../features/usage/UsagePage'), 'UsagePage')
const UsersPage = page(() => import('../features/users/UsersPage'), 'UsersPage')
const SettingsPage = page(() => import('../features/settings/SettingsPage'), 'SettingsPage')

export default function App() {
  const { me, loading } = useAuth()
  if (loading) return <div className="login-page"><Loading label="Connecting to the gateway…" /></div>
  if (!me) return <LoginPage />
  return (
    <AppShell>
      <Suspense fallback={<Loading />}>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/servers" element={<ServersPage />} />
          <Route path="/servers/:id" element={<ServerDetailPage />} />
          <Route path="/tools" element={<ToolsPage />} />
          <Route path="/tools/:id" element={<ToolDetailPage />} />
          <Route path="/policies" element={<PoliciesPage />} />
          <Route path="/agents" element={<AgentsPage />} />
          <Route path="/agents/:id" element={<AgentDetailPage />} />
          <Route path="/approvals" element={<ApprovalsPage />} />
          <Route path="/approvals/:id" element={<ApprovalsPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/usage" element={<UsagePage />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </AppShell>
  )
}
