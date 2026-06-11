import { useState } from 'react'
import { Trash2, Copy, CheckCircle, XCircle, Loader2 } from 'lucide-react'
import { resetDatabase, deduplicateThreats } from '../api/client'

type Status = { ok: boolean; detail: string } | null

export default function Settings() {
  const [dedupStatus, setDedupStatus] = useState<Status>(null)
  const [dedupLoading, setDedupLoading] = useState(false)

  const [resetStatus, setResetStatus] = useState<Status>(null)
  const [resetLoading, setResetLoading] = useState(false)
  const [confirmReset, setConfirmReset] = useState(false)

  const handleDedup = async () => {
    setDedupLoading(true)
    setDedupStatus(null)
    try {
      const res = await deduplicateThreats()
      setDedupStatus(res)
    } catch (e: any) {
      setDedupStatus({ ok: false, detail: e?.response?.data?.detail ?? 'Request failed' })
    } finally {
      setDedupLoading(false)
    }
  }

  const handleResetDb = async () => {
    if (!confirmReset) {
      setConfirmReset(true)
      return
    }
    setResetLoading(true)
    setResetStatus(null)
    setConfirmReset(false)
    try {
      const res = await resetDatabase()
      setResetStatus(res)
    } catch (e: any) {
      setResetStatus({ ok: false, detail: e?.response?.data?.detail ?? 'Request failed' })
    } finally {
      setResetLoading(false)
    }
  }

  return (
    <div className="space-y-4 max-w-2xl">
      <div>
        <h1 className="text-base font-bold text-white">Settings</h1>
        <p className="text-xs text-slate-600">Database management and maintenance.</p>
      </div>

      {/* Deduplicate threats */}
      <div className="bg-[#0d0d16] border border-[#1a1a28] p-4">
        <div className="flex items-center gap-2 mb-3">
          <Copy size={14} className="text-cyan-400" />
          <h2 className="text-sm font-semibold text-white">Remove Duplicates</h2>
        </div>
        <p className="text-xs text-slate-500 mb-3">
          Scans all collected threats and removes duplicates sharing the same normalized title and
          actor. The highest-scored entry is kept.
        </p>
        <div className="flex items-center gap-3">
          <button
            onClick={handleDedup}
            disabled={dedupLoading}
            className="flex items-center gap-2 px-3 py-1.5 text-xs bg-[#1a1a28] hover:bg-cyan-900/40 border border-[#2a2a3f] hover:border-cyan-800/60 disabled:opacity-50 text-white transition-colors"
          >
            {dedupLoading ? <Loader2 size={12} className="animate-spin" /> : <Copy size={12} />}
            Remove duplicates
          </button>
          {dedupStatus && (
            <span className={`flex items-center gap-1 text-xs ${dedupStatus.ok ? 'text-green-400' : 'text-red-400'}`}>
              {dedupStatus.ok ? <CheckCircle size={12} /> : <XCircle size={12} />}
              {dedupStatus.detail}
            </span>
          )}
        </div>
      </div>

      {/* Reset database */}
      <div className="bg-[#0d0d16] border border-red-900/40 p-4">
        <div className="flex items-center gap-2 mb-3">
          <Trash2 size={14} className="text-red-400" />
          <h2 className="text-sm font-semibold text-white">Reset Database</h2>
        </div>
        <p className="text-xs text-slate-500 mb-3">
          Clears all collected threats, actors, and graph data. Sources are kept. This action is
          irreversible.
        </p>
        <div className="flex items-center gap-3">
          <button
            onClick={handleResetDb}
            disabled={resetLoading}
            className={`flex items-center gap-2 px-3 py-1.5 text-xs disabled:opacity-50 text-white transition-colors ${
              confirmReset
                ? 'bg-red-600 hover:bg-red-500 animate-pulse'
                : 'bg-[#1a1a28] hover:bg-red-900/50 border border-red-900/60'
            }`}
          >
            {resetLoading ? <Loader2 size={12} className="animate-spin" /> : <Trash2 size={12} />}
            {confirmReset ? 'Click again to confirm' : 'Clear all data'}
          </button>
          {confirmReset && (
            <button
              onClick={() => setConfirmReset(false)}
              className="text-xs text-slate-500 hover:text-slate-300"
            >
              Cancel
            </button>
          )}
          {resetStatus && (
            <span className={`flex items-center gap-1 text-xs ${resetStatus.ok ? 'text-green-400' : 'text-red-400'}`}>
              {resetStatus.ok ? <CheckCircle size={12} /> : <XCircle size={12} />}
              {resetStatus.detail}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}
