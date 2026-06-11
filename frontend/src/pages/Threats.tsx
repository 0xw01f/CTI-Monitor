import { useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow, format } from 'date-fns'
import { X, ChevronRight, ShieldCheck, List, LayoutGrid, Twitter, Copy, Download, Check, Trash2, Eye, EyeOff } from 'lucide-react'
import { getThreats, getThreat, generateXPost, deleteThreat, setThreatVisibility, setThreatVisibilityBulk } from '../api/client'
import { getSev, getTypeBadge, TYPE_KEYS, getTypeMeta } from '../lib/severity'
import { countryLabel } from '../lib/countries'
import type { Threat, ThreatListResponse } from '../types'

type ViewMode = 'list' | 'card'

interface Props { search?: string; readOnly?: boolean }

const SCORE_COLOR = (s: number) =>
  s >= 80 ? 'text-red-400' : s >= 60 ? 'text-orange-400' : s >= 40 ? 'text-yellow-400' : 'text-green-400'

export default function Threats({ search = '', readOnly = false }: Props) {
  const qc = useQueryClient()
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [viewMode, setViewMode] = useState<ViewMode>('list')
  const [busy, setBusy] = useState(false)
  const [filters, setFilters] = useState({
    type: '',
    severity: '',
    country: '',
    tag: '',
    start_date: '',
    end_date: '',
    visibility: '',
    noisy_only: false,
  })

  const { data, isLoading } = useQuery<ThreatListResponse>({
    queryKey: ['threats', filters, search],
    queryFn: () =>
      getThreats({
        limit: 200,
        ...(filters.type && { type: filters.type }),
        ...(filters.severity && { severity: filters.severity }),
        ...(filters.country && { country: filters.country }),
        ...(filters.tag && { tag: filters.tag }),
        ...(filters.start_date && { start_date: `${filters.start_date}T00:00:00` }),
        ...(filters.end_date && { end_date: `${filters.end_date}T23:59:59` }),
        ...(!readOnly && filters.visibility && { visibility: filters.visibility }),
        ...(!readOnly && filters.noisy_only && { noisy_only: true }),
        ...(search && { search }),
      }),
  })

  const { data: detail } = useQuery<Threat | null>({
    queryKey: ['threat', selectedId],
    queryFn: () => (selectedId ? getThreat(selectedId) : null),
    enabled: !!selectedId,
  })

  const countries = useMemo(
    () => Array.from(new Set<string>((data?.items ?? []).map((t) => String(t.country || '')).filter(Boolean))).sort(),
    [data]
  )
  const tags = useMemo(
    () => Array.from(new Set<string>((data?.items ?? []).flatMap((t) => (t.tags ?? []).map((x) => String(x))))).sort(),
    [data]
  )

  const bulkSetVisible = async (isPublic: boolean, noisyOnly = false) => {
    const items = data?.items ?? []
    const ids = items
      .filter((t) => (noisyOnly ? Boolean(t.noise_candidate) : true))
      .map((t) => Number(t.id))
    if (!ids.length) return
    setBusy(true)
    try {
      await setThreatVisibilityBulk(ids, isPublic)
      await qc.invalidateQueries({ queryKey: ['threats'] })
      if (selectedId) await qc.invalidateQueries({ queryKey: ['threat', selectedId] })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex gap-3 h-full overflow-hidden">
      <div className={`flex flex-col min-w-0 flex-1 ${selectedId ? 'max-w-[58%]' : ''}`}>
        <div className="flex items-center justify-between mb-3 shrink-0">
          <div>
            <h1 className="text-base font-bold text-white">Threat Feed</h1>
            {data && <p className="text-xs text-slate-600">{data.total.toLocaleString()} events</p>}
          </div>
          <div className="flex items-center border border-[#20202f]">
            {([
              { id: 'list' as ViewMode, Icon: List, label: 'List' },
              { id: 'card' as ViewMode, Icon: LayoutGrid, label: 'Cards' },
            ]).map(({ id, Icon, label }) => (
              <button
                key={id}
                onClick={() => setViewMode(id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs transition-colors ${
                  viewMode === id
                    ? 'bg-cyan-900/40 text-cyan-300 border-x border-cyan-700/40'
                    : 'text-slate-500 hover:text-slate-200 hover:bg-[#12121e]'
                }`}
              >
                <Icon size={12} />
                <span>{label}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="flex gap-2 mb-2 shrink-0 flex-wrap">
          {([
            { key: 'type', options: [['', 'All types'], ...TYPE_KEYS.map(k => [k, getTypeMeta(k).label])] as [string,string][] },
            { key: 'severity', options: [['', 'All severities'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']] as [string,string][] },
          ] as { key: keyof typeof filters; options: [string, string][] }[]).map(({ key, options }) => (
            <select
              key={key}
              value={String(filters[key])}
              onChange={e => setFilters(f => ({ ...f, [key]: e.target.value }))}
              className="bg-[#12121e] border border-[#20202f] text-xs text-slate-300 px-2 py-1.5 outline-none"
            >
              {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          ))}
          <select
            value={filters.country}
            onChange={e => setFilters(f => ({ ...f, country: e.target.value }))}
            className="bg-[#12121e] border border-[#20202f] text-xs text-slate-300 px-2 py-1.5 outline-none"
          >
            <option value="">All countries</option>
            {countries.map(c => <option key={c} value={c}>{countryLabel(c)}</option>)}
          </select>
          <input
            type="date"
            value={filters.start_date}
            onChange={e => setFilters(f => ({ ...f, start_date: e.target.value }))}
            className="bg-[#12121e] border border-[#20202f] text-xs text-slate-300 px-2 py-1.5 outline-none"
          />
          <input
            type="date"
            value={filters.end_date}
            onChange={e => setFilters(f => ({ ...f, end_date: e.target.value }))}
            className="bg-[#12121e] border border-[#20202f] text-xs text-slate-300 px-2 py-1.5 outline-none"
          />
          <button
            onClick={() => setFilters({ type: '', severity: '', country: '', tag: '', start_date: '', end_date: '', visibility: '', noisy_only: false })}
            className="bg-[#12121e] border border-[#20202f] text-xs text-slate-400 px-2 py-1.5 hover:text-white"
          >
            Reset
          </button>
          {!readOnly && (
            <>
              <select
                value={filters.visibility}
                onChange={e => setFilters(f => ({ ...f, visibility: e.target.value }))}
                className="bg-[#12121e] border border-[#20202f] text-xs text-slate-300 px-2 py-1.5 outline-none"
              >
                <option value="">All visibility</option>
                <option value="public">Public only</option>
                <option value="hidden">Hidden only</option>
              </select>
              <label className="inline-flex items-center gap-2 text-xs text-slate-400 px-2 py-1.5 border border-[#20202f] bg-[#12121e]">
                <input
                  type="checkbox"
                  checked={filters.noisy_only}
                  onChange={e => setFilters(f => ({ ...f, noisy_only: e.target.checked }))}
                />
                Noisy only
              </label>
              <button
                onClick={() => bulkSetVisible(false, true)}
                disabled={busy}
                className="bg-[#12121e] border border-[#20202f] text-xs text-red-300 px-2 py-1.5 hover:text-red-200 disabled:opacity-60"
                title="Hide noisy items from current list from public view"
              >
                Hide noisy (shown)
              </button>
              <button
                onClick={() => bulkSetVisible(true, false)}
                disabled={busy}
                className="bg-[#12121e] border border-[#20202f] text-xs text-emerald-300 px-2 py-1.5 hover:text-emerald-200 disabled:opacity-60"
                title="Publish all currently shown items to public view"
              >
                Publish shown
              </button>
            </>
          )}
        </div>

        <div className="mb-3 flex flex-wrap gap-1.5 shrink-0">
          <button
            onClick={() => setFilters(f => ({ ...f, tag: '' }))}
            className={`px-2 py-1 text-[10px] border ${!filters.tag ? 'border-cyan-500/50 text-cyan-300' : 'border-[#2a2a3f] text-slate-500'}`}
          >
            All tags
          </button>
          {tags.map(tag => (
            <button
              key={tag}
              onClick={() => setFilters(f => ({ ...f, tag: f.tag === tag ? '' : tag }))}
              className={`px-2 py-1 text-[10px] border ${filters.tag === tag ? 'border-cyan-500/50 text-cyan-300 bg-cyan-900/20' : 'border-[#2a2a3f] text-slate-400 hover:text-white'}`}
            >
              #{tag}
            </button>
          ))}
        </div>

        {viewMode === 'list' ? (
          <div className="bg-[#0d0d16] border border-[#1a1a28] overflow-auto flex-1">
            <table className="w-full text-xs">
              <thead className="sticky top-0 z-10 bg-[#0d0d16]">
                <tr className="border-b border-[#1a1a28] text-[10px] text-slate-600 uppercase tracking-wider">
                  <th className="text-left px-3 py-2.5 font-semibold">Time</th>
                  <th className="text-left px-3 py-2.5 font-semibold">Type</th>
                  <th className="text-left px-3 py-2.5 font-semibold">Title</th>
                  <th className="text-left px-3 py-2.5 font-semibold">Actor</th>
                  <th className="text-left px-3 py-2.5 font-semibold">Country</th>
                  <th className="text-left px-3 py-2.5 font-semibold">Severity</th>
                  <th className="text-left px-3 py-2.5 font-semibold">Risk</th>
                  {!readOnly && <th className="text-left px-3 py-2.5 font-semibold">Visibility</th>}
                  <th className="text-left px-3 py-2.5 font-semibold">Tags</th>
                  <th className="px-3 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {isLoading && <tr><td colSpan={readOnly ? 9 : 10} className="py-12 text-center text-slate-600">Loading...</td></tr>}
                {!isLoading && data?.items?.length === 0 && <tr><td colSpan={readOnly ? 9 : 10} className="py-12 text-center text-slate-600">No events found.</td></tr>}
                {(data?.items ?? []).map((t) => {
                  const sev = getSev(t.severity)
                  const isSelected = t.id === selectedId
                  return (
                    <tr
                      key={t.id}
                      onClick={() => setSelectedId(isSelected ? null : t.id)}
                      className={`border-b border-[#12121e] cursor-pointer transition-colors ${isSelected ? 'bg-[#16162a]' : 'hover:bg-[#0f0f1c]'}`}
                    >
                      <td className="px-3 py-2.5 text-slate-600 whitespace-nowrap">{(t.published_at || t.fetched_at) ? formatDistanceToNow(new Date(t.published_at ?? t.fetched_at ?? ''), { addSuffix: true }) : '—'}</td>
                      <td className="px-3 py-2.5"><span className={`px-1.5 py-0.5 text-[10px] font-mono font-medium ${getTypeBadge(t.type)}`}>{getTypeMeta(t.type).label}</span></td>
                      <td className="px-3 py-2.5 max-w-[240px]"><span className="text-slate-300 block truncate">{t.title}</span></td>
                      <td className="px-3 py-2.5 font-mono text-slate-500 max-w-[110px] truncate">{t.actor || '—'}</td>
                      <td className="px-3 py-2.5 text-slate-400 whitespace-nowrap">{countryLabel(t.country)}</td>
                      <td className="px-3 py-2.5"><span className={`px-2 py-0.5 text-[10px] font-mono ${sev.badge}`}>{sev.label}</span></td>
                      <td className="px-3 py-2.5"><span className={`font-mono font-bold ${SCORE_COLOR(t.score)}`}>{t.score}</span></td>
                      {!readOnly && (
                        <td className="px-3 py-2.5">
                          <span className={`px-1.5 py-0.5 text-[10px] font-mono ${t.is_public ? 'text-emerald-300 border border-emerald-700/40' : 'text-amber-300 border border-amber-700/40'}`}>
                            {t.is_public ? 'Public' : 'Hidden'}
                          </span>
                        </td>
                      )}
                      <td className="px-3 py-2.5">
                        <div className="flex flex-wrap gap-1">
                          {(t.tags ?? []).slice(0, 3).map((tag) => (
                            <button
                              key={tag}
                              onClick={(e) => {
                                e.stopPropagation()
                                setFilters(f => ({ ...f, tag }))
                              }}
                              className="px-2 py-0.5 text-[10px] border border-[#2a2a3f] text-slate-400 hover:text-white"
                            >
                              #{tag}
                            </button>
                          ))}
                        </div>
                      </td>
                      <td className="px-3 py-2.5"><ChevronRight size={12} className="text-slate-700" /></td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="overflow-auto flex-1">
            {isLoading && <div className="py-12 text-center text-slate-600 text-xs">Loading...</div>}
            {!isLoading && data?.items?.length === 0 && <div className="py-12 text-center text-slate-600 text-xs">No events found.</div>}
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3 pb-3">
              {(data?.items ?? []).map((t) => {
                const sev = getSev(t.severity)
                const isSelected = t.id === selectedId
                return (
                  <div
                    key={t.id}
                    onClick={() => setSelectedId(isSelected ? null : t.id)}
                    className={`bg-[#0d0d16] border cursor-pointer transition-colors flex flex-col ${isSelected ? 'border-cyan-700/60 bg-[#0d1020]' : 'border-[#1a1a28] hover:border-[#2a2a3f]'}`}
                  >
                    {/* Screenshot thumbnail */}
                    <div className="w-full h-32 bg-[#0a0a14] border-b border-[#1a1a28] overflow-hidden shrink-0">
                      {t.post_screenshot ? (
                        <img
                          src={t.post_screenshot}
                          alt="Screenshot"
                          className="w-full h-full object-cover object-top"
                        />
                      ) : (
                        <div className="w-full h-full flex items-center justify-center text-[10px] text-slate-700">
                          No screenshot
                        </div>
                      )}
                    </div>

                    {/* Card body */}
                    <div className="p-3 flex flex-col gap-2 flex-1">
                      <div className="flex items-start gap-1.5 flex-wrap">
                        <span className={`px-1.5 py-0.5 text-[10px] font-mono font-medium shrink-0 ${getTypeBadge(t.type)}`}>{getTypeMeta(t.type).label}</span>
                        <span className={`px-2 py-0.5 text-[10px] font-mono shrink-0 ${sev.badge}`}>{sev.label}</span>
                        <span className={`font-mono font-bold text-[10px] ml-auto shrink-0 ${SCORE_COLOR(t.score)}`}>{t.score}/100</span>
                      </div>
                      {!readOnly && (
                        <div className="text-[10px]">
                          <span className={`${t.is_public ? 'text-emerald-300' : 'text-amber-300'}`}>
                            {t.is_public ? 'Public' : 'Hidden'}
                          </span>
                          {t.noise_candidate && <span className="text-slate-500"> · noisy</span>}
                        </div>
                      )}

                      <p className="text-xs text-slate-300 line-clamp-2 leading-snug">{t.title}</p>

                      <div className="flex items-center justify-between text-[10px] text-slate-600 mt-auto">
                        <span className="font-mono truncate max-w-[50%]">{t.actor || '—'}</span>
                        <span>{countryLabel(t.country)}</span>
                      </div>

                      {t.tags?.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {(t.tags ?? []).slice(0, 3).map((tag) => (
                            <button
                              key={tag}
                              onClick={(e) => {
                                e.stopPropagation()
                                setFilters(f => ({ ...f, tag }))
                              }}
                              className="px-2 py-0.5 text-[10px] border border-[#2a2a3f] text-slate-400 hover:text-white"
                            >
                              #{tag}
                            </button>
                          ))}
                        </div>
                      )}

                      <div className="text-[10px] text-slate-700">
                        {(t.published_at || t.fetched_at) ? formatDistanceToNow(new Date(t.published_at ?? t.fetched_at ?? ''), { addSuffix: true }) : '—'}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {selectedId && detail && (
        <div className="w-[42%] shrink-0 bg-[#0d0d16] border border-[#1a1a28] overflow-y-auto">
          <ThreatDetail
            threat={detail}
            readOnly={readOnly}
            setBusy={setBusy}
            onClose={() => setSelectedId(null)}
            onDelete={() => setSelectedId(null)}
          />
        </div>
      )}
    </div>
  )
}

function ThreatDetail({
  threat,
  readOnly,
  setBusy,
  onClose,
  onDelete,
}: {
  threat: Threat
  readOnly: boolean
  setBusy: (v: boolean) => void
  onClose: () => void
  onDelete: () => void
}) {
  const qc = useQueryClient()
  const sev = getSev(threat.severity)
  const origin = threat.victim_origin || { country: 'Unknown', confidence: 0 }

  const [xPost, setXPost] = useState<{ text: string; char_count: number; screenshot_url: string | null } | null>(null)
  const [xLoading, setXLoading] = useState(false)
  const [xText, setXText] = useState('')
  const [copied, setCopied] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState(false)
  const [deleting, setDeleting] = useState(false)

  const handleGenerateX = async () => {
    setXLoading(true)
    try {
      const result = await generateXPost(threat.id)
      setXPost(result)
      setXText(result.text)
    } finally {
      setXLoading(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteConfirm) { setDeleteConfirm(true); return }
    setDeleting(true)
    try {
      await deleteThreat(threat.id)
      onDelete()
    } finally {
      setDeleting(false)
      setDeleteConfirm(false)
    }
  }

  const handleVisibility = async (isPublic: boolean) => {
    setBusy(true)
    try {
      await setThreatVisibility(threat.id, isPublic)
      await qc.invalidateQueries({ queryKey: ['threats'] })
      await qc.invalidateQueries({ queryKey: ['threat', threat.id] })
    } finally {
      setBusy(false)
    }
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(xText)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleTweet = () => {
    window.open(`https://x.com/intent/tweet?text=${encodeURIComponent(xText)}`, '_blank')
  }

  return (
    <div className="p-4 space-y-4 text-xs">
      <div className="flex items-start gap-2">
        <div className="flex-1">
          <h3 className="text-sm font-semibold text-white leading-snug">{threat.title}</h3>
          <div className="flex flex-wrap items-center gap-2 mt-2">
            <span className={`px-2 py-0.5 font-mono text-[10px] ${sev.badge}`}>{sev.label}</span>
            <span className={`px-1.5 py-0.5 font-mono text-[10px] ${getTypeBadge(threat.type)}`}>{getTypeMeta(threat.type).label}</span>
            <span className={`font-mono font-bold text-[11px] ${SCORE_COLOR(threat.score)}`}>Risk {threat.score}/100</span>
          </div>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          {!readOnly && (
            <>
              <button
                onClick={() => handleVisibility(!threat.is_public)}
                title={threat.is_public ? 'Hide from public view' : 'Publish to public view'}
                className={`p-1 transition-colors ${threat.is_public ? 'text-slate-600 hover:text-amber-400' : 'text-amber-400 hover:text-amber-300'}`}
              >
                {threat.is_public ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
              <button
                onClick={handleDelete}
                disabled={deleting}
                title={deleteConfirm ? 'Click again to confirm deletion' : 'Delete threat'}
                className={`p-1 transition-colors disabled:opacity-50 ${deleteConfirm ? 'text-red-400 hover:text-red-300' : 'text-slate-600 hover:text-red-400'}`}
              >
                <Trash2 size={14} />
              </button>
            </>
          )}
          <button onClick={onClose} className="text-slate-600 hover:text-white p-1"><X size={14} /></button>
        </div>
      </div>

      {!readOnly && (
        <div className="bg-[#12121e] border border-[#1a1a28] p-2 text-[11px] text-slate-400 flex items-center gap-2">
          <span className={`px-2 py-0.5 font-mono ${threat.is_public ? 'text-emerald-300 border border-emerald-700/40' : 'text-amber-300 border border-amber-700/40'}`}>
            {threat.is_public ? 'PUBLIC' : 'HIDDEN'}
          </span>
          {threat.noise_candidate && <span className="text-amber-300">Noisy candidate</span>}
        </div>
      )}

      <div className="bg-[#12121e] border border-[#1a1a28] p-3 space-y-2">
        <Meta label="Actor" value={threat.actor || 'Unknown'} mono />
        <Meta label="Detected country" value={countryLabel(origin.country)} />
        <Meta label="Confidence" value={`${Math.round((origin.confidence || 0) * 100)}%`} />
        {threat.published_at && <Meta label="Published" value={format(new Date(threat.published_at), 'MMM d yyyy, HH:mm:ss')} />}
      </div>

      <div>
        <h4 className="text-[10px] font-semibold text-slate-600 uppercase tracking-wider mb-2">Post Evidence</h4>
        {threat.post_screenshot ? (
          <img src={threat.post_screenshot} alt="Threat post screenshot" className="w-full border border-[#1a1a28]" />
        ) : (
          <div className="bg-[#10101a] border border-[#1a1a28] p-4 text-slate-500 text-[11px]">
            Screenshot not available yet. The system captures the post DOM element only.
          </div>
        )}
      </div>

      {threat.tags?.length > 0 && (
        <div>
          <h4 className="text-[10px] font-semibold text-slate-600 uppercase tracking-wider mb-2">Tags</h4>
          <div className="flex flex-wrap gap-1.5">
            {threat.tags.map((tag: string) => (
              <span key={tag} className="flex items-center gap-1 bg-[#1a1a28] border border-[#20202f] text-slate-300 px-2 py-0.5 text-[10px]">
                <ShieldCheck size={9} />
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Generate X Post button */}
      {!readOnly && (
        <button
          onClick={handleGenerateX}
          disabled={xLoading}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 border border-[#20202f] text-slate-400 hover:text-white hover:border-slate-500 transition-colors text-[11px] disabled:opacity-50"
        >
          <Twitter size={12} />
          {xLoading ? 'Generating…' : 'Generate X Post'}
        </button>
      )}

      {/* X Post Modal */}
      {xPost && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
          <div className="bg-[#0d0d16] border border-[#2a2a3f] w-full max-w-2xl mx-4 flex flex-col">
            {/* Modal header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-[#1a1a28]">
              <div className="flex items-center gap-2 text-xs font-semibold text-white">
                <Twitter size={13} />
                X / Twitter Post
              </div>
              <button onClick={() => setXPost(null)} className="text-slate-500 hover:text-white"><X size={14} /></button>
            </div>

            <div className="flex gap-0 flex-1 overflow-hidden">
              {/* Text side */}
              <div className="flex-1 p-4 flex flex-col gap-3">
                <textarea
                  value={xText}
                  onChange={e => setXText(e.target.value)}
                  className="w-full h-48 bg-[#12121e] border border-[#1a1a28] text-slate-200 text-xs p-3 resize-none outline-none focus:border-slate-500 font-mono leading-relaxed"
                  spellCheck={false}
                />
                <div className="flex items-center justify-between">
                  <span className={`text-[10px] font-mono ${xText.length > 280 ? 'text-red-400' : xText.length > 260 ? 'text-yellow-400' : 'text-slate-500'}`}>
                    {xText.length} / 280
                  </span>
                  <div className="flex gap-2">
                    <button
                      onClick={handleCopy}
                      className="flex items-center gap-1.5 px-3 py-1.5 border border-[#2a2a3f] text-[11px] text-slate-400 hover:text-white hover:border-slate-500 transition-colors"
                    >
                      {copied ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
                      {copied ? 'Copied' : 'Copy'}
                    </button>
                    <button
                      onClick={handleTweet}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1a8cd8]/20 border border-[#1a8cd8]/40 text-[11px] text-[#1a8cd8] hover:bg-[#1a8cd8]/30 transition-colors"
                    >
                      <Twitter size={11} />
                      Open X
                    </button>
                  </div>
                </div>
              </div>

              {/* Screenshot side */}
              {xPost.screenshot_url && (
                <div className="w-56 shrink-0 border-l border-[#1a1a28] p-3 flex flex-col gap-2">
                  <p className="text-[10px] text-slate-600 uppercase tracking-wider font-semibold">Screenshot</p>
                  <img
                    src={xPost.screenshot_url}
                    alt="Anonymized screenshot"
                    className="w-full border border-[#1a1a28] object-top object-cover"
                    style={{ maxHeight: '200px' }}
                  />
                  <a
                    href={xPost.screenshot_url}
                    download
                    className="flex items-center justify-center gap-1.5 px-2 py-1.5 border border-[#2a2a3f] text-[10px] text-slate-400 hover:text-white hover:border-slate-500 transition-colors"
                  >
                    <Download size={10} />
                    Download
                  </a>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function Meta({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start gap-2">
      <span className="text-slate-600 shrink-0 w-28">{label}</span>
      <span className={`text-slate-300 break-all ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  )
}
