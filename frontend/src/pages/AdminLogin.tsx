import { FormEvent, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Shield, KeyRound, AlertTriangle } from 'lucide-react'
import { adminLogin } from '../api/client'
import { setAdminToken } from '../lib/adminAuth'

export default function AdminLogin() {
  const navigate = useNavigate()
  const location = useLocation()
  const target = (location.state as any)?.from || '/admin/dashboard'

  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const res = await adminLogin({
        username,
        password,
        ...(totpCode.trim() ? { totp_code: totpCode.trim() } : {}),
      })
      setAdminToken(res.access_token)
      navigate(target, { replace: true })
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#080810] text-slate-200 grid place-items-center p-4">
      <div className="w-full max-w-md space-y-3">
        <div className="bg-amber-950/20 border border-amber-900/30 px-3 py-2 rounded">
          <p className="flex items-center justify-center gap-1.5 text-[10px] text-amber-400/80 text-center">
            <AlertTriangle size={10} className="shrink-0" />
            CTI Monitor relies on automated parsing and AI enrichment — data may contain errors,
            omissions, or incorrect classifications. Always verify before acting.
          </p>
        </div>
        <form onSubmit={onSubmit} className="bg-[#0d0d16] border border-[#1a1a28] p-6 space-y-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-cyan-300">
            <Shield size={16} />
            <h1 className="text-sm font-semibold text-white">Admin Access</h1>
          </div>
          <p className="text-xs text-slate-500">Private dashboard authentication</p>
        </div>

        <label className="block text-xs text-slate-400">
          Username
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="mt-1 w-full bg-[#12121e] border border-[#20202f] px-3 py-2 text-slate-200 outline-none"
            autoComplete="username"
          />
        </label>

        <label className="block text-xs text-slate-400">
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full bg-[#12121e] border border-[#20202f] px-3 py-2 text-slate-200 outline-none"
            autoComplete="current-password"
          />
        </label>

        <label className="block text-xs text-slate-400">
          MFA code (optional)
          <input
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value)}
            className="mt-1 w-full bg-[#12121e] border border-[#20202f] px-3 py-2 text-slate-200 outline-none"
            placeholder="123456"
            inputMode="numeric"
          />
        </label>

        {error && <p className="text-xs text-red-400">{error}</p>}

        <button
          type="submit"
          disabled={loading}
          className="w-full flex items-center justify-center gap-2 bg-cyan-700/30 border border-cyan-700/50 text-cyan-200 py-2 text-xs hover:bg-cyan-700/40 disabled:opacity-60"
        >
          <KeyRound size={12} />
          {loading ? 'Signing in...' : 'Sign in'}
        </button>
      </form>
      </div>
    </div>
  )
}
