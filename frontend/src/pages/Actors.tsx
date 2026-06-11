import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNow, format } from 'date-fns'
import { X, ChevronRight } from 'lucide-react'
import { getActors, getActor } from '../api/client'
import { getSev, getTypeBadge, getTypeMeta } from '../lib/severity'
import { countryLabel } from '../lib/countries'
import type { Actor, ActorListResponse } from '../types'

const RISK_COLOR: Record<string, string> = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  medium:   'text-yellow-400',
  low:      'text-slate-500',
}

const RISK_BADGE: Record<string, string> = {
  critical: 'bg-red-900/40 text-red-400 border border-red-800/50',
  high:     'bg-orange-900/40 text-orange-400 border border-orange-800/50',
  medium:   'bg-yellow-900/40 text-yellow-400 border border-yellow-800/50',
  low:      'bg-slate-800/60 text-slate-500 border border-slate-700/40',
}

const SCORE_COLOR = (s: number) =>
  s >= 80 ? 'text-red-400' : s >= 60 ? 'text-orange-400' : s >= 40 ? 'text-yellow-400' : 'text-green-400'

export default function Actors() {
  const [selectedUsername, setSelectedUsername] = useState<string | null>(null)

  const { data, isLoading } = useQuery<ActorListResponse>({
    queryKey: ['actors'],
    queryFn: () => getActors(),
  })

  const { data: detail } = useQuery({
    queryKey: ['actor', selectedUsername],
    queryFn: () => (selectedUsername ? getActor(selectedUsername) : null),
    enabled: !!selectedUsername,
  })

  return (
    <div className="flex gap-3 h-full overflow-hidden">
      <div className={`flex flex-col min-w-0 flex-1 ${selectedUsername ? 'max-w-[58%]' : ''}`}>
        <div className="mb-3 shrink-0">
          <h1 className="text-base font-bold text-white">Threat Actors</h1>
          <p className="text-xs text-slate-600">Actor intelligence — reputation, specialization, activity</p>
        </div>

        <div className="bg-[#0d0d16] border border-[#1a1a28] overflow-auto flex-1">
          <table className="w-full text-xs">
            <thead className="sticky top-0 z-10 bg-[#0d0d16]">
              <tr className="border-b border-[#1a1a28] text-[10px] text-slate-600 uppercase tracking-wider">
                <th className="text-left px-4 py-3 font-semibold">Actor</th>
                <th className="text-left px-4 py-3 font-semibold">Specialization</th>
                <th className="text-left px-4 py-3 font-semibold">Posts</th>
                <th className="text-left px-4 py-3 font-semibold">Leaks</th>
                <th className="text-left px-4 py-3 font-semibold">Score</th>
                <th className="text-left px-4 py-3 font-semibold">Risk</th>
                <th className="text-left px-4 py-3 font-semibold">Last seen</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-slate-600">Loading…</td>
                </tr>
              )}
              {(data?.actors ?? []).map((a) => {
                const isSelected = a.username === selectedUsername
                return (
                  <tr
                    key={a.id}
                    onClick={() => setSelectedUsername(isSelected ? null : a.username)}
                    className={`border-b border-[#12121e] cursor-pointer transition-colors ${isSelected ? 'bg-[#16162a]' : 'hover:bg-[#0f0f1c]'}`}
                  >
                    <td className="px-4 py-3 font-mono text-slate-300">
                      {a.username}
                      {a.is_spammer && (
                        <span className="ml-2 text-[9px] bg-slate-800 text-slate-500 px-1 py-0.5 rounded">
                          spam
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-400 capitalize">{a.specialization || 'other'}</td>
                    <td className="px-4 py-3 text-slate-400">{a.post_count}</td>
                    <td className="px-4 py-3 text-cyan-400">{a.total_leaks ?? 0}</td>
                    <td className={`px-4 py-3 font-mono font-semibold ${RISK_COLOR[a.risk_level] ?? 'text-slate-400'}`}>
                      {(a.reputation_score ?? 0).toFixed(0)}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] px-2 py-0.5 rounded font-semibold ${RISK_BADGE[a.risk_level] ?? RISK_BADGE.low}`}>
                        {a.risk_level ?? 'low'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-600">
                      {a.last_seen ? new Date(a.last_seen).toLocaleDateString() : '—'}
                    </td>
                    <td className="px-4 py-3"><ChevronRight size={12} className="text-slate-700" /></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {selectedUsername && detail && (
        <div className="w-[42%] shrink-0 bg-[#0d0d16] border border-[#1a1a28] overflow-y-auto">
          <ActorDetail actor={detail} onClose={() => setSelectedUsername(null)} />
        </div>
      )}
    </div>
  )
}

function ActorDetail({ actor, onClose }: { actor: Actor; onClose: () => void }) {
  return (
    <div className="p-4 space-y-4 text-xs">
      {/* Header */}
      <div className="flex items-start gap-2">
        <div className="flex-1">
          <h3 className="text-sm font-semibold text-white font-mono">{actor.username}</h3>
          <div className="flex flex-wrap items-center gap-2 mt-2">
            <span className={`text-[10px] px-2 py-0.5 rounded font-semibold ${RISK_BADGE[actor.risk_level] ?? RISK_BADGE.low}`}>
              {actor.risk_level ?? 'low'}
            </span>
            {actor.is_spammer && (
              <span className="text-[9px] bg-slate-800 text-slate-500 px-1 py-0.5 rounded">spam</span>
            )}
            <span className={`font-mono font-bold text-[11px] ${RISK_COLOR[actor.risk_level] ?? 'text-slate-400'}`}>
              Score {(actor.reputation_score ?? 0).toFixed(0)}
            </span>
          </div>
        </div>
        <button onClick={onClose} className="text-slate-600 hover:text-white p-1 shrink-0"><X size={14} /></button>
      </div>

      {/* Summary */}
      <div className="bg-[#12121e] border border-[#1a1a28] p-3 space-y-2">
        <Meta label="Platform" value={actor.platform || '—'} />
        <Meta label="Specialization" value={<span className="capitalize">{actor.specialization || 'other'}</span>} />
        <Meta label="Posts" value={actor.post_count ?? 0} />
        <Meta label="Total leaks" value={<span className="text-cyan-400">{actor.total_leaks ?? 0}</span>} />
        {actor.first_seen && <Meta label="First seen" value={format(new Date(actor.first_seen), 'MMM d yyyy')} />}
        {actor.last_seen && <Meta label="Last seen" value={formatDistanceToNow(new Date(actor.last_seen), { addSuffix: true })} />}
      </div>

      {/* Active sources */}
      {actor.sources && actor.sources.length > 0 && (
        <div>
          <h4 className="text-[10px] font-semibold text-slate-600 uppercase tracking-wider mb-2">Active on</h4>
          <div className="flex flex-wrap gap-1.5">
            {actor.sources.map((s) => (
              <span key={s.name} className="bg-[#1a1a28] border border-[#20202f] text-slate-300 px-2 py-0.5 text-[10px]">
                {s.name} <span className="text-slate-600">({s.post_count})</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Contacts / identities */}
      {actor.identities && actor.identities.length > 0 && (
        <div>
          <h4 className="text-[10px] font-semibold text-slate-600 uppercase tracking-wider mb-2">Identities</h4>
          <div className="space-y-1">
            {actor.identities.map((c, i) => (
              <div key={i} className="flex items-center gap-2 bg-[#12121e] border border-[#1a1a28] px-2 py-1.5">
                <span className="text-slate-500 w-16 shrink-0 capitalize">{c.type}</span>
                <span className="font-mono text-slate-300 break-all flex-1">{c.value}</span>
                <span className="text-slate-600 shrink-0">{Math.round(c.confidence * 100)}%</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Username history */}
      {actor.username_history && actor.username_history.length > 0 && (
        <div>
          <h4 className="text-[10px] font-semibold text-slate-600 uppercase tracking-wider mb-2">Previous usernames</h4>
          <div className="flex flex-wrap gap-1.5">
            {actor.username_history.map((u: string) => (
              <span key={u} className="font-mono text-[10px] bg-[#1a1a28] border border-[#20202f] text-slate-400 px-2 py-0.5">{u}</span>
            ))}
          </div>
        </div>
      )}

      {/* Tags */}
      {actor.tags && actor.tags.length > 0 && (
        <div>
          <h4 className="text-[10px] font-semibold text-slate-600 uppercase tracking-wider mb-2">Tags</h4>
          <div className="flex flex-wrap gap-1.5">
            {actor.tags.map((tag: string) => (
              <span key={tag} className="bg-[#1a1a28] border border-[#20202f] text-slate-300 px-2 py-0.5 text-[10px]">#{tag}</span>
            ))}
          </div>
        </div>
      )}

      {/* Recent threats */}
      {actor.recent_threats && actor.recent_threats.length > 0 && (
        <div>
          <h4 className="text-[10px] font-semibold text-slate-600 uppercase tracking-wider mb-2">Recent activity</h4>
          <div className="space-y-1">
            {actor.recent_threats.map((t) => {
              const sev = getSev(t.severity)
              return (
                <div key={t.id} className="bg-[#12121e] border border-[#1a1a28] px-3 py-2 space-y-1">
                  <div className="flex items-center gap-2">
                    <span className={`px-1.5 py-0.5 text-[10px] font-mono font-medium ${getTypeBadge(t.type)}`}>
                      {getTypeMeta(t.type).label}
                    </span>
                    <span className={`px-2 py-0.5 text-[10px] font-mono ${sev.badge}`}>{sev.label}</span>
                    <span className={`font-mono font-bold text-[10px] ml-auto ${SCORE_COLOR(t.score)}`}>{t.score}</span>
                  </div>
                  <p className="text-slate-300 leading-snug">{t.title}</p>
                  <div className="flex items-center gap-2 text-slate-600">
                    {t.country && <span>{countryLabel(t.country)}</span>}
                    {(t.published_at || t.fetched_at) && <span>{formatDistanceToNow(new Date(t.published_at ?? t.fetched_at ?? ''), { addSuffix: true })}</span>}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

function Meta({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2">
      <span className="text-slate-600 shrink-0 w-28">{label}</span>
      <span className="text-slate-300 break-all">{value}</span>
    </div>
  )
}
