import { useState } from 'react'
import { api } from '../lib/api'

export function Login({ onDone }: { onDone: () => void }) {
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.post('/api/login', { password })
      onDone()
    } catch (err) {
      // The daemon deliberately does not say which part was wrong; don't
      // invent a more specific message than it gave.
      setError(err instanceof Error ? err.message : 'login failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="login stack" onSubmit={submit}>
      <div>
        <h1 style={{ fontSize: 18, margin: '0 0 2px' }}>torrentd</h1>
        <p className="muted small" style={{ margin: 0 }}>Sign in to manage the pool.</p>
      </div>
      <div>
        <label htmlFor="pw">Password</label>
        <input
          id="pw"
          type="password"
          autoFocus
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>
      {error && <div className="banner err">{error}</div>}
      <button className="action" type="submit" disabled={busy || !password}>
        {busy ? 'Signing in…' : 'Sign in'}
      </button>
    </form>
  )
}
