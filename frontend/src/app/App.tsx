import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './auth'
import { AppShell } from './AppShell'
import { Loading } from '../components/ui'
import { LoginPage } from '../features/auth/LoginPage'
import { OverviewPage } from '../features/overview/OverviewPage'
import { ServersPage } from '../features/servers/ServersPage'
import { ServerDetailPage } from '../features/servers/ServerDetailPage'
import { ToolsPage } from '../features/tools/ToolsPage'
import { ToolDetailPage } from '../features/tools/ToolDetailPage'
import { PoliciesPage } from '../features/policies/PoliciesPage'
import { AgentsPage } from '../features/agents/AgentsPage'
import { AgentDetailPage } from '../features/agents/AgentDetailPage'
import { ApprovalsPage } from '../features/approvals/ApprovalsPage'
import { AuditPage } from '../features/audit/AuditPage'
import { UsagePage } from '../features/usage/UsagePage'
import { UsersPage } from '../features/users/UsersPage'
import { SettingsPage } from '../features/settings/SettingsPage'

export default function App() {
  const { me, loading } = useAuth()
  if (loading) return <div className="login-page"><Loading label="Connecting to the gateway…" /></div>
  if (!me) return <LoginPage />
  return (
    <AppShell>
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
    </AppShell>
  )
}
