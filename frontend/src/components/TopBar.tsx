import { useState, useCallback } from 'react'
import { Search, RefreshCw } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { pollAllSources } from '../api/client'

const COOLDOWN_MS = 30_000

interface Props {
  search: string
  onSearch: (v: string) => void
  allowRefresh?: boolean
}

export default function TopBar({ search, onSearch, allowRefresh = false }: Props) {
  const qc = useQueryClient()
  const [spinning, setSpinning] = useState(false)
  const [lastRefresh, setLastRefresh] = useState(0)

  const handleRefresh = useCallback(async () => {
    if (Date.now() - lastRefresh < COOLDOWN_MS) return
    setSpinning(true)
    setLastRefresh(Date.now())
    try {
      await pollAllSources()
      await qc.refetchQueries({ type: 'active' })
    } finally {
      setSpinning(false)
    }
  }, [qc, lastRefresh])

  const coolingDown = Date.now() - lastRefresh < COOLDOWN_MS

  return (
    <header className="h-12 bg-[#0d0d16] border-b border-[#1a1a28] flex items-center px-4 gap-3 shrink-0">
      <div className="flex items-center gap-2 bg-[#12121e] border border-[#20202f] px-3 py-1.5 flex-1 max-w-md">
        <Search size={12} className="text-slate-600 shrink-0" />
        <input
          type="text"
          placeholder="Search threats, actors, keywords"
          value={search}
          onChange={e => onSearch(e.target.value)}
          className="bg-transparent text-xs text-slate-300 placeholder-slate-600 outline-none flex-1 min-w-0"
        />
        {search && (
          <button onClick={() => onSearch('')} className="text-slate-600 hover:text-slate-300 text-xs">×</button>
        )}
      </div>

      <div className="flex-1" />

      {allowRefresh && (
        <button
          onClick={handleRefresh}
          disabled={spinning || coolingDown}
          className="p-1.5 text-slate-600 hover:text-white hover:bg-[#1c1c2e] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          title={coolingDown ? 'Wait 30s between refreshes' : 'Refresh'}
        >
          <RefreshCw size={13} className={spinning ? 'animate-spin' : ''} />
        </button>
      )}

      <div className="flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 bg-green-500 animate-pulse" />
        <span className="text-[10px] text-slate-600 font-mono">LIVE</span>
      </div>
    </header>
  )
}
