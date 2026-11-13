import { FormEvent, useState } from 'react'
import { Loader2, Lock, Shield } from 'lucide-react'
import { useAuth } from '../../app/auth'
import { ApiError, errorMessage } from '../../services/api'
import { Callout, Field } from '../../components/ui'

export function LoginPage() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true); setError(null)
    try {
      await login(username, password)
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) setError(`Too many attempts. Try again in ${err.retryAfter ?? 60} seconds.`)
      else if (err instanceof ApiError && err.status === 401) setError('Invalid username or password.')
      else setError(errorMessage(err))
    } finally {
      setBusy(false)
      setPassword('')
    }
  }

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
        <Field label="Username"><input autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} required autoFocus /></Field>
        <Field label="Password"><input type="password" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} required /></Field>
        <button className="btn primary" disabled={busy || !username || !password}>{busy ? <Loader2 size={14} className="spin" /> : <Lock size={14} />}Sign in</button>
      </form>
    </div>
  )
}
