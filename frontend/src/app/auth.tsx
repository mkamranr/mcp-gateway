import { createContext, ReactNode, useContext, useEffect } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError, setCsrfToken, setUnauthorizedHandler } from '../services/api'
import { hasRole } from '../services/format'
import type { Me } from '../services/types'

interface AuthState {
  me: Me | null
  loading: boolean
  login: (username: string, password: string) => Promise<Me>
  logout: () => Promise<void>
  switchTenant: (tenantId: string) => Promise<void>
  can: (...roles: string[]) => boolean
}

const AuthCtx = createContext<AuthState | null>(null)

export function useAuth(): AuthState {
  const v = useContext(AuthCtx)
  if (!v) throw new Error('useAuth outside AuthProvider')
  return v
}

/** Convenience: the current user's tenant id (always present once authenticated). */
export function useTenantId(): string { return useAuth().me?.tenant_id || '' }

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const meQ = useQuery({
    queryKey: ['me'],
    queryFn: async () => {
      try {
        const me = await api.get<Me>('/auth/me')
        setCsrfToken(me.csrf_token)
        return me
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null
        throw e
      }
    },
    staleTime: 60_000,
    retry: false,
  })

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setCsrfToken(null)
      qc.setQueryData(['me'], null)
    })
  }, [qc])

  const me = meQ.data ?? null
  const value: AuthState = {
    me,
    loading: meQ.isLoading,
    login: async (username, password) => {
      const res = await api.post<Me>('/auth/login', { username, password })
      setCsrfToken(res.csrf_token)
      qc.clear()
      qc.setQueryData(['me'], res)
      return res
    },
    logout: async () => {
      try { await api.post('/auth/logout') } finally {
        setCsrfToken(null)
        qc.clear()
        qc.setQueryData(['me'], null)
      }
    },
    switchTenant: async (tenantId) => {
      const res = await api.post<Me>('/auth/switch-tenant', { tenant_id: tenantId })
      // Drop every cached tenant-scoped query, then load the new principal.
      qc.clear()
      qc.setQueryData(['me'], { ...res, csrf_token: me?.csrf_token })
    },
    can: (...roles) => !!me && (me.is_platform_admin || hasRole(me.roles, ...roles)),
  }
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>
}
