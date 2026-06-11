import { useEffect, useMemo, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell, PieChart, Pie, Legend,
} from 'recharts'
import { AlertTriangle, Layers, ShieldAlert, Activity, ExternalLink, Radar, DatabaseZap } from 'lucide-react'
import { Link, useLocation } from 'react-router-dom'
import L from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { getStats, getTimeline, getThreats } from '../api/client'
import { countryLabel, getCountryInfo } from '../lib/countries'
import { getSev, getTypeMeta, TYPE_KEYS } from '../lib/severity'
import type { DashboardStats, Threat, ThreatListResponse, TimelinePoint } from '../types'

// ── Mini map helpers ──────────────────────────────────────────────────────────
interface MapThreat { country: string | null; severity: string }

function bucketByCountry(threats: MapThreat[]) {
  const acc: Record<string, { lat: number; lng: number; count: number; critical: number; high: number }> = {}
  for (const t of threats) {
    if (!t.country) continue
    const info = getCountryInfo(t.country)
    if (!info) continue
    if (!acc[t.country]) acc[t.country] = { lat: info.lat, lng: info.lng, count: 0, critical: 0, high: 0 }
    acc[t.country].count++
    if (t.severity === 'critical') acc[t.country].critical++
    else if (t.severity === 'high') acc[t.country].high++
  }
  return Object.values(acc)
}

function MiniMap({ threats }: { threats: MapThreat[] }) {
  const mapElRef = useRef<HTMLDivElement>(null)
  const mapRef   = useRef<L.Map | null>(null)
  const layerRef = useRef<L.LayerGroup | null>(null)

  const buckets = useMemo(() => bucketByCountry(threats), [threats])

  useEffect(() => {
    if (mapRef.current || !mapElRef.current) return
    const map = L.map(mapElRef.current, {
      center: [20, 10], zoom: 2, zoomControl: false, attributionControl: false,
    })
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map)
    layerRef.current = L.layerGroup().addTo(map)
    mapRef.current   = map
    return () => { map.remove(); mapRef.current = null }
  }, [])

  useEffect(() => {
    const layer = layerRef.current
    if (!layer) return
    layer.clearLayers()
    const maxCount = Math.max(1, ...buckets.map(b => b.count))
    for (const b of buckets) {
      const col    = b.critical > 0 ? '#ef4444' : b.high > 0 ? '#f97316' : '#eab308'
      const radius = Math.max(5, Math.sqrt(b.count / maxCount) * 50)
      L.circleMarker([b.lat, b.lng], {
        radius, fillColor: col, color: '#fff', weight: 0.5, fillOpacity: 0.5,
      }).addTo(layer)
    }
  }, [buckets])

  return <div ref={mapElRef} className="w-full h-full" style={{ background: '#080810' }} />
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
export default function Dashboard() {
  const location = useLocation()
  const base = location.pathname.startsWith('/admin') ? '/admin' : ''
  const { data: stats, isLoading, dataUpdatedAt } = useQuery<DashboardStats>({ queryKey: ['stats'], queryFn: getStats })
  const { data: timeline = [] } = useQuery<TimelinePoint[]>({ queryKey: ['timeline', 7], queryFn: () => getTimeline(7) })
  const { data: threatData } = useQuery<ThreatListResponse>({
    queryKey: ['threats-map-dash'],
    queryFn: () => getThreats({ limit: 2000 }),
    staleTime: 60_000,
  })

  const threats: MapThreat[] = threatData?.items ?? []

  if (isLoading) return <p className="text-sm text-slate-500">Loading dashboard...</p>

  // Severity donut
  const sev = stats?.severity_breakdown ?? {}
  const sevData = [
    { name: 'Critical', value: sev.critical ?? 0, color: '#ef4444' },
    { name: 'High',     value: sev.high     ?? 0, color: '#f97316' },
    { name: 'Medium',   value: sev.medium   ?? 0, color: '#eab308' },
    { name: 'Low',      value: sev.low      ?? 0, color: '#22c55e' },
  ].filter(d => d.value > 0)

  // Threat type breakdown
  const typeRaw  = stats?.type_breakdown ?? {}
  const typeData = TYPE_KEYS
    .filter(k => (typeRaw[k] ?? 0) > 0)
    .map(k => ({ name: getTypeMeta(k).label, value: typeRaw[k] as number, color: getTypeMeta(k).color }))
    .sort((a, b) => b.value - a.value)

  // Top actors
  const actorData = ((stats?.top_actors ?? []) as { username: string; post_count: number }[])
    .slice(0, 8)
    .map(a => ({ name: a.username, posts: a.post_count }))

  const hotspots = (stats?.target_hotspots ?? []) as { target: string; count: number }[]
  const countries = (stats?.country_hotspots ?? []) as { country: string; count: number }[]
  const analystQueue = (stats?.analyst_queue ?? []) as {
    id: number
    title: string
    type: string
    severity: string
    score: number
    actor?: string | null
    target?: string | null
    country?: string | null
    published_at?: string | null
  }[]
  const actorRisk = (stats?.actor_risk_breakdown ?? {}) as Record<string, number>
  const sourceHealth = (stats?.source_health ?? {}) as { unstable_sources?: number; degraded_sources?: number }

  const tooltipStyle = { background: '#0d0d16', border: '1px solid #1a1a28', fontSize: 11, color: '#e2e8f0' }

  return (
    <div className="space-y-4">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-base font-bold text-white">Overview</h1>
          <p className="text-xs text-slate-600">Situation awareness in one screen</p>
        </div>
        {dataUpdatedAt > 0 && (
          <p className="text-[10px] text-slate-600 tabular-nums">
            Updated {new Date(dataUpdatedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </p>
        )}
      </div>

      {/* ── KPIs ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <KPI icon={<AlertTriangle size={14} className="text-red-400" />} label="Priority Queue (24h)" value={stats?.high_priority_24h ?? 0} />
        <KPI icon={<ShieldAlert size={14} className="text-orange-400" />} label="High-Risk Actors" value={stats?.high_risk_actors ?? 0} />
        <KPI icon={<Layers size={14} className="text-cyan-400" />} label="Events (7d)" value={stats?.threats_7d ?? 0} />
        <KPI icon={<Activity size={14} className="text-emerald-400" />} label="Active Sources" value={stats?.active_sources ?? 0} subValue={`${stats?.total_sources ?? 0} total`} />
      </div>

      {/* ── Analyst queue + source health ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <div className="lg:col-span-2 bg-[#0d0d16] border border-[#1a1a28] p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Analyst Priority Queue (48h)</h3>
            <Link to={`${base}/threats`} className="text-[10px] text-cyan-500 hover:text-cyan-300 transition-colors">Open feed</Link>
          </div>
          {analystQueue.length > 0 ? (
            <div className="space-y-2">
              {analystQueue.map(item => {
                const sevMeta = getSev(item.severity)
                return (
                  <div key={item.id} className="border border-[#1a1a28] bg-[#12121e] p-2.5">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 text-[10px] font-mono ${sevMeta.badge}`}>{sevMeta.label}</span>
                      <span className="px-1.5 py-0.5 text-[10px] font-mono bg-cyan-900/30 text-cyan-300">{getTypeMeta(item.type).label}</span>
                      <span className={`ml-auto text-[11px] font-mono font-bold ${item.score >= 80 ? 'text-red-400' : item.score >= 60 ? 'text-orange-400' : 'text-yellow-400'}`}>
                        {item.score}/100
                      </span>
                    </div>
                    <p className="mt-1.5 text-xs text-slate-300 line-clamp-1">{item.title}</p>
                    <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-slate-500">
                      <span>{item.actor || 'unknown actor'}</span>
                      <span>{item.target || 'unknown target'}</span>
                      <span>{countryLabel(item.country)}</span>
                      <span>{item.published_at ? formatDistanceToNow(new Date(item.published_at), { addSuffix: true }) : 'unknown time'}</span>
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <p className="text-xs text-slate-600">No high-priority items detected in the last 48h.</p>
          )}
        </div>

        <div className="bg-[#0d0d16] border border-[#1a1a28] p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Collector Health</h3>
          <div className="space-y-3 text-xs">
            <HealthRow icon={<Activity size={12} className="text-emerald-400" />} label="Active Sources" value={stats?.active_sources ?? 0} />
            <HealthRow icon={<AlertTriangle size={12} className="text-amber-400" />} label="Unstable Sources" value={sourceHealth.unstable_sources ?? 0} />
            <HealthRow icon={<DatabaseZap size={12} className="text-red-400" />} label="Degraded Sources" value={sourceHealth.degraded_sources ?? 0} />
            <HealthRow icon={<Radar size={12} className="text-slate-300" />} label="Deleted Posts (24h)" value={stats?.deleted_24h ?? 0} />
          </div>
        </div>
      </div>

      {/* ── Timeline + Severity donut ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <div className="lg:col-span-2 bg-[#0d0d16] border border-[#1a1a28] p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Event Timeline (7d)</h3>
          {timeline.length > 0 ? (
            <ResponsiveContainer width="100%" height={160}>
              <LineChart data={timeline}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a1a28" />
                <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#64748b' }} />
                <YAxis tick={{ fontSize: 10, fill: '#64748b' }} width={28} />
                <Tooltip contentStyle={tooltipStyle} />
                <Line type="monotone" dataKey="count" stroke="#22d3ee" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-xs text-slate-600">No timeline data yet.</p>
          )}
        </div>

        <div className="bg-[#0d0d16] border border-[#1a1a28] p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Severity Distribution</h3>
          {sevData.length > 0 ? (
            <ResponsiveContainer width="100%" height={160}>
              <PieChart>
                <Pie data={sevData} dataKey="value" cx="50%" cy="45%" innerRadius={38} outerRadius={60} paddingAngle={2}>
                  {sevData.map((d, i) => <Cell key={i} fill={d.color} />)}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
                <Legend
                  iconType="circle" iconSize={7}
                  formatter={v => <span style={{ fontSize: 10, color: '#94a3b8' }}>{v}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-xs text-slate-600">No severity data yet.</p>
          )}
        </div>
      </div>

      {/* ── Threat Map ── */}
      <div className="bg-[#0d0d16] border border-[#1a1a28]">
        <div className="flex items-center justify-between px-4 pt-3 pb-2 shrink-0">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Threat Map</h3>
          <Link to={`${base}/map`} className="text-[10px] text-cyan-500 hover:text-cyan-300 flex items-center gap-1 transition-colors">
            <ExternalLink size={10} /> Full map
          </Link>
        </div>
        <div style={{ height: 280 }}>
          <MiniMap threats={threats} />
        </div>
      </div>

      {/* ── Type breakdown + Top actors ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <div className="bg-[#0d0d16] border border-[#1a1a28] p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Threat Type Breakdown</h3>
          {typeData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={typeData} layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a1a28" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 10, fill: '#64748b' }} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: '#94a3b8' }} width={82} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="value" name="Threats" radius={[0, 2, 2, 0]}>
                  {typeData.map((d, i) => <Cell key={i} fill={d.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-xs text-slate-600">No type data yet.</p>
          )}
        </div>

        <div className="bg-[#0d0d16] border border-[#1a1a28] p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Top Threat Actors</h3>
          {actorData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={actorData} layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a1a28" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 10, fill: '#64748b' }} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: '#94a3b8' }} width={82} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="posts" name="Posts" fill="#818cf8" radius={[0, 2, 2, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-xs text-slate-600">No actor data yet.</p>
          )}
        </div>
      </div>

      {/* ── Hotspots + actor risk ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <div className="lg:col-span-2 bg-[#0d0d16] border border-[#1a1a28] p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Target Hotspots (30d)</h3>
          {hotspots.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {hotspots.map((h) => (
                <div key={h.target} className="border border-[#1a1a28] bg-[#12121e] p-2">
                  <p className="text-xs text-slate-300 capitalize">{h.target}</p>
                  <p className="text-[11px] text-slate-500 mt-0.5">{h.count} events</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-600">No target hotspot data yet.</p>
          )}

          {countries.length > 0 && (
            <div className="mt-3">
              <h4 className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-2">Country Focus</h4>
              <div className="flex flex-wrap gap-1.5">
                {countries.map(c => (
                  <span key={c.country} className="px-2 py-1 text-[10px] border border-[#2a2a3f] text-slate-300">
                    {countryLabel(c.country)} <span className="text-slate-500">({c.count})</span>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="bg-[#0d0d16] border border-[#1a1a28] p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Actor Risk Distribution</h3>
          <div className="space-y-2">
            {[
              { key: 'critical', color: 'bg-red-500' },
              { key: 'high', color: 'bg-orange-500' },
              { key: 'medium', color: 'bg-yellow-500' },
              { key: 'low', color: 'bg-slate-500' },
            ].map(row => {
              const value = actorRisk[row.key] ?? 0
              const total = Object.values(actorRisk).reduce((acc, n) => acc + Number(n || 0), 0)
              const pct = total > 0 ? Math.round((value / total) * 100) : 0
              return (
                <div key={row.key} className="space-y-1">
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span className="capitalize">{row.key}</span>
                    <span className="font-mono">{value}</span>
                  </div>
                  <div className="h-1.5 bg-[#1a1a28]">
                    <div className={`h-full ${row.color}`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}

function KPI({ icon, label, value, subValue }: { icon: React.ReactNode; label: string; value: number; subValue?: string }) {
  return (
    <div className="bg-[#0d0d16] border border-[#1a1a28] p-4">
      <div className="flex items-center justify-between mb-2">{icon}</div>
      <p className="text-2xl font-bold text-white tabular-nums">{value.toLocaleString()}</p>
      <p className="text-[11px] text-slate-500 mt-0.5">{label}</p>
      {subValue && <p className="text-[10px] text-slate-600 mt-1">{subValue}</p>}
    </div>
  )
}

function HealthRow({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return (
    <div className="flex items-center justify-between border border-[#1a1a28] bg-[#12121e] p-2">
      <span className="flex items-center gap-2 text-slate-400">
        {icon}
        {label}
      </span>
      <span className="font-mono text-slate-200">{value}</span>
    </div>
  )
}
