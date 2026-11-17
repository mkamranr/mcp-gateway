import { FormEvent, useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { KeyRound, Loader2, Lock, LogIn, Shield } from 'lucide-react'
import { useAuth } from '../../app/auth'
import { api, ApiError, errorMessage } from '../../services/api'
import type { LdapPublicConfig, SsoPublicConfig } from '../../services/types'
import { Callout, Field } from '../../components/ui'

// Codes come from the gateway's /auth/oidc/callback redirect (?sso_error=...). Details are in the audit log.
const SSO_ERRORS: Record<string, string> = {
  state_invalid: 'The sign-in attempt expired or was started in another browser tab. Please try again.',
  idp_error: 'The identity provider did not complete the sign-in.',
  token_invalid: "The identity provider's response could not be verified. Contact your administrator.",
  token_exchange_failed: 'The identity provider rejected the sign-in. Contact your administrator.',
  no_access: 'Your account has no access to MCP-Gateway. Ask an administrator to map one of your groups.',
  account_conflict: 'A local account with this username already exists. Ask an administrator to link it.',
  sso_disabled: 'Single sign-on is not enabled.',
  idp_unreachable: 'The identity provider is unreachable. Try again later.',
  idp_misconfigured: 'Single sign-on is misconfigured. Contact your administrator.',
  rate_limited: 'Too many sign-in attempts. Wait a few minutes and try again.',
  unavailable: 'Sign-in is temporarily unavailable. Try again later.',
}

function readSsoError(): string | null {
  const code = new URLSearchParams(window.location.search).get('sso_error')
  return code ? SSO_ERRORS[code] || 'Single sign-on failed.' : null
}

function stripSsoError() {
  const params = new URLSearchParams(window.location.search)
  if (!params.has('sso_error')) return
  params.delete('sso_error')
  const rest = params.toString()
  window.history.replaceState(null, '', window.location.pathname + (rest ? `?${rest}` : ''))
}

export function LoginPage() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(readSsoError)
  const [showLocal, setShowLocal] = useState(false)
  useEffect(stripSsoError, [])
  const sso = useQuery({ queryKey: ['sso-public'], queryFn: () => api.get<SsoPublicConfig>('/auth/oidc/config'), retry: false, staleTime: 60_000 })
  const ldap = useQuery({ queryKey: ['ldap-public'], queryFn: () => api.get<LdapPublicConfig>('/auth/ldap/config'), retry: false, staleTime: 60_000 })

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true); setError(null)
    try {
      await login(username, password)
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) setError(`Too many attempts. Try again in ${err.retryAfter ?? 60} seconds.`)
      else if (err instanceof ApiError && err.status === 401) setError('Invalid username or password.')
      else if (err instanceof ApiError && err.status === 503) setError('The directory is unavailable. Try again later.')
      else setError(errorMessage(err))
    } finally {
      setBusy(false)
      setPassword('')
    }
  }

  const ssoOn = !!sso.data?.enabled
  const ldapOn = !!ldap.data?.enabled
  // Directory accounts use the password form, so it stays visible whenever directory sign-in is on.
  const breakGlassOnly = ssoOn && !ldapOn && sso.data?.local_login === 'break_glass_only'
  const localVisible = !breakGlassOnly || showLocal
  const directoryName = ldap.data?.display_name.toLowerCase() || 'directory account'
  const formLabel = ldapOn ? `or with your ${directoryName}` : breakGlassOnly ? 'Break-glass administrator' : 'or with a local account'
  const returnTo = window.location.pathname + window.location.search.replace(/[?&]sso_error=[^&]*/, '')
  const ssoHref = `/api/v1/auth/oidc/login?return_to=${encodeURIComponent(returnTo)}`

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={submit}>
        <div className="brand" style={{ height: 'auto', padding: 0, border: 0 }}>
          <div className="brand-mark"><Shield size={21} color="#fff" /></div>
          <div><b>MCP-Gateway</b><small style={{ color: '#8b9bb2' }}>Secure Agent Tool Gateway</small></div>
        </div>
        <h1>Sign in</h1>
        <p>Administrative console. Access is logged.</p>
        {error && <Callout kind="danger">{error}</Callout>}
        {ssoOn && <a className="btn primary sso-btn" href={ssoHref}><LogIn size={14} />Sign in with {sso.data!.display_name}</a>}
        {ssoOn && localVisible && <div className="login-divider"><span>{formLabel}</span></div>}
        {!ssoOn && ldapOn && <p className="muted" style={{ marginTop: -6 }}>Use your {directoryName}.</p>}
        {localVisible && <>
          <Field label="Username"><input autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} required autoFocus={!ssoOn} /></Field>
          <Field label="Password"><input type="password" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} required /></Field>
          <button className={ssoOn ? 'btn secondary' : 'btn primary'} disabled={busy || !username || !password}>{busy ? <Loader2 size={14} className="spin" /> : <Lock size={14} />}Sign in</button>
        </>}
        {breakGlassOnly && !showLocal && <button type="button" className="text-btn break-glass" onClick={() => setShowLocal(true)}><KeyRound size={11} />Break-glass sign-in</button>}
      </form>
    </div>
  )
}
