import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import L from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { getThreats } from '../api/client'
import { getCountryInfo, countryLabel } from '../lib/countries'
import { getSev, getTypeMeta } from '../lib/severity'
import { Map, Flame, Circle, Layers, X } from 'lucide-react'
import type { Threat } from '../types'

// ── Types ──────────────────────────────────────────────────────────────────
type ViewMode = 'pins' | 'heatmap' | 'bubbles'

interface CountryBucket {
  code: string
  lat: number
  lng: number
  count: number
  critical: number
  high: number
  threats: Threat[]
}

// Severity → leaflet circle colour
const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
}

// ── CartoDB dark tile ──────────────────────────────────────────────────────
const TILE_URL   = 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
const TILE_ATTR  = '&copy; <a href="https://carto.com/">CARTO</a> &copy; <a href="https://www.openstreetmap.org/copyright">OSM</a>'

// ── Helpers ────────────────────────────────────────────────────────────────
function bucketByCountry(threats: Threat[]): CountryBucket[] {
  const acc: Record<string, CountryBucket> = {}
  for (const t of threats) {
    if (!t.country) continue
    const info = getCountryInfo(t.country)
    if (!info) continue
    if (!acc[t.country]) {
      acc[t.country] = { code: t.country, lat: info.lat, lng: info.lng, count: 0, critical: 0, high: 0, threats: [] }
    }
    const b = acc[t.country]
    b.count++
    b.threats.push(t)
    if (t.severity === 'critical') b.critical++
    else if (t.severity === 'high')  b.high++
  }
  return Object.values(acc).sort((a, b) => b.count - a.count)
}

function bucketColour(b: CountryBucket): string {
  if (b.critical > 0) return '#ef4444'
  if (b.high     > 0) return '#f97316'
  return '#eab308'
}

// ── Component ──────────────────────────────────────────────────────────────
export default function ThreatMap() {
  const mapRef    = useRef<L.Map | null>(null)
  const mapElRef  = useRef<HTMLDivElement>(null)
  const layerRef  = useRef<L.LayerGroup | null>(null)

  const [mode,    setMode]    = useState<ViewMode>('bubbles')
  const [tooltip, setTooltip] = useState<CountryBucket | null>(null)
  const [filter,  setFilter]  = useState<{ severity: string; type: string }>({ severity: '', type: '' })

  const { data, isLoading } = useQuery({
    queryKey: ['threats-map'],
    queryFn:  () => getThreats({ limit: 2000 }),
    staleTime: 60_000,
  })

  const threats: Threat[] = data?.items ?? []

  const filtered = useMemo(() => threats.filter(t => {
    if (filter.severity && t.severity !== filter.severity) return false
    if (filter.type     && t.type     !== filter.type)     return false
    return true
  }), [threats, filter])

  const buckets = useMemo(() => bucketByCountry(filtered), [filtered])

  // ── Init map once ─────────────────────────────────────────────────────────
  useEffect(() => {
    if (mapRef.current || !mapElRef.current) return

    const map = L.map(mapElRef.current, {
      center: [20, 10],
      zoom:   2,
      zoomControl: true,
      attributionControl: true,
    })

    L.tileLayer(TILE_URL, { attribution: TILE_ATTR, maxZoom: 18 }).addTo(map)
    const layer = L.layerGroup().addTo(map)
    layerRef.current  = layer
    mapRef.current    = map

    return () => { map.remove(); mapRef.current = null }
  }, [])

  // ── Re-draw layer when data / mode / filter change ────────────────────────
  useEffect(() => {
    const map   = mapRef.current
    const layer = layerRef.current
    if (!map || !layer) return

    layer.clearLayers()

    if (mode === 'pins') {
      // One circle per threat
      for (const t of filtered) {
        if (!t.country) continue
        const info = getCountryInfo(t.country)
        if (!info) continue
        const col = SEV_COLOR[t.severity] ?? '#94a3b8'
        L.circleMarker([info.lat + (Math.random() - 0.5) * 2, info.lng + (Math.random() - 0.5) * 2], {
          radius: 5,
          fillColor: col,
          color: col,
          weight: 0,
          fillOpacity: 0.75,
        })
          .bindTooltip(
            `<div style="font:11px monospace;color:#e2e8f0;background:#0d0d16;border:1px solid #1e2035;padding:6px 8px;border-radius:3px">
              <b>${t.title?.slice(0, 60)}</b><br/>
              ${getTypeMeta(t.type).label} · ${getSev(t.severity).label} · Score ${t.score}<br/>
              ${countryLabel(t.country)}
            </div>`,
            { className: 'leaflet-cti-tooltip', sticky: true }
          )
          .addTo(layer)
      }
    }

    if (mode === 'heatmap') {
      // Large semi-transparent circles — visual heat effect
      for (const b of buckets) {
        const radius = Math.max(40, Math.min(150, b.count * 6))
        const alpha  = Math.min(0.45, 0.08 + b.count * 0.02)
        const col    = bucketColour(b)

        L.circleMarker([b.lat, b.lng], {
          radius,
          fillColor: col,
          color: 'transparent',
          fillOpacity: alpha,
        }).addTo(layer)

        // Smaller brighter core
        L.circleMarker([b.lat, b.lng], {
          radius: Math.max(8, radius * 0.3),
          fillColor: col,
          color: 'transparent',
          fillOpacity: 0.6,
        }).addTo(layer)
      }
    }

    if (mode === 'bubbles') {
      const maxCount = Math.max(1, ...buckets.map(b => b.count))
      for (const b of buckets) {
        const radius = Math.max(6, Math.sqrt(b.count / maxCount) * 60)
        const col    = bucketColour(b)

        const marker = L.circleMarker([b.lat, b.lng], {
          radius,
          fillColor: col,
          color: '#fff',
          weight: 0.5,
          fillOpacity: 0.5,
        })

        marker.bindTooltip('', { sticky: true, className: 'leaflet-cti-tooltip' })
        marker.on('mouseover', () => {
          marker.setStyle({ fillOpacity: 0.75 })
          setTooltip(b)
        })
        marker.on('mouseout',  () => {
          marker.setStyle({ fillOpacity: 0.5 })
          setTooltip(null)
        })
        marker.addTo(layer)
      }
    }
  }, [filtered, buckets, mode])

  // ── Stats for sidebar ─────────────────────────────────────────────────────
  const topCountries = buckets.slice(0, 8)

  return (
    <div className="flex flex-col h-full gap-3 overflow-hidden">
      {/* ── Toolbar ── */}
      <div className="flex items-center justify-between shrink-0">
        <div>
          <h1 className="text-base font-bold text-white">Threat Map</h1>
          <p className="text-xs text-slate-600">
            {isLoading ? 'Loading…' : `${filtered.length} threats · ${buckets.length} countries`}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Severity filter */}
          <select
            value={filter.severity}
            onChange={e => setFilter(f => ({ ...f, severity: e.target.value }))}
            className="bg-[#12121e] border border-[#20202f] text-xs text-slate-300 px-2 py-1.5 outline-none"
          >
            <option value="">All severities</option>
            {['critical','high','medium','low'].map(s => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>

          {/* View mode */}
          <div className="flex items-center border border-[#20202f]">
            {([
              { id: 'bubbles',  Icon: Circle, label: 'Bubbles' },
              { id: 'heatmap',  Icon: Flame,  label: 'Heatmap' },
              { id: 'pins',     Icon: Map,    label: 'Pins'    },
            ] as { id: ViewMode; Icon: typeof Map; label: string }[]).map(({ id, Icon, label }) => (
              <button
                key={id}
                onClick={() => setMode(id)}
                title={label}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs transition-colors ${
                  mode === id
                    ? 'bg-cyan-900/40 text-cyan-300 border-x border-cyan-700/40'
                    : 'text-slate-500 hover:text-slate-200 hover:bg-[#12121e]'
                }`}
              >
                <Icon size={12} />
                <span className="hidden sm:inline">{label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ── Main area ── */}
      <div className="flex gap-3 flex-1 overflow-hidden">
        {/* Map */}
        <div className="flex-1 relative border border-[#1a1a28] overflow-hidden">
          <div ref={mapElRef} className="w-full h-full" style={{ background: '#080810' }} />

          {/* Floating tooltip panel (bubbles mode) */}
          {tooltip && (
            <div className="absolute bottom-4 left-4 z-[9999] bg-[#0d0d16]/95 border border-[#252540] p-3 min-w-[220px] text-xs pointer-events-none">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-lg leading-none">{getCountryInfo(tooltip.code)?.flag}</span>
                <span className="font-semibold text-white text-sm">{getCountryInfo(tooltip.code)?.name ?? tooltip.code}</span>
              </div>
              <div className="space-y-1 text-slate-400">
                <div className="flex justify-between"><span>Total threats</span><span className="text-white font-mono">{tooltip.count}</span></div>
                {tooltip.critical > 0 && <div className="flex justify-between"><span className="text-red-400">Critical</span><span className="text-red-400 font-mono">{tooltip.critical}</span></div>}
                {tooltip.high     > 0 && <div className="flex justify-between"><span className="text-orange-400">High</span><span className="text-orange-400 font-mono">{tooltip.high}</span></div>}
              </div>
              {tooltip.threats.slice(0, 3).map(t => (
                <div key={t.id} className="mt-2 pt-2 border-t border-[#1a1a28] text-[10px] text-slate-500 truncate">
                  {getTypeMeta(t.type).label} · {t.title?.slice(0, 55)}
                </div>
              ))}
              {tooltip.count > 3 && (
                <div className="text-[10px] text-slate-600 mt-1">+{tooltip.count - 3} more</div>
              )}
            </div>
          )}

          {/* View-mode legend */}
          <div className="absolute top-3 right-3 z-[9999] bg-[#0d0d16]/90 border border-[#252540] p-2.5 text-[10px] space-y-1.5">
            <div className="text-slate-500 uppercase tracking-wider mb-1">Severity</div>
            {[['critical','#ef4444'],['high','#f97316'],['medium','#eab308'],['low','#22c55e']].map(([s, c]) => (
              <div key={s} className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: c }} />
                <span className="text-slate-400 capitalize">{s}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top countries sidebar */}
        <div className="w-52 shrink-0 flex flex-col gap-2 overflow-y-auto">
          <div className="text-[10px] text-slate-600 uppercase tracking-wider">Top targets</div>
          {isLoading && <div className="text-xs text-slate-600 py-4 text-center">Loading…</div>}
          {topCountries.map((b, i) => {
            const info = getCountryInfo(b.code)
            const maxC = topCountries[0]?.count ?? 1
            return (
              <div
                key={b.code}
                className="bg-[#0d0d16] border border-[#1a1a28] p-2.5 cursor-pointer hover:border-[#252540] transition-colors"
                onClick={() => mapRef.current?.flyTo([b.lat, b.lng], 4, { duration: 1.2 })}
              >
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-sm leading-none">{info?.flag}</span>
                  <span className="text-xs text-slate-300 font-medium flex-1 truncate">{info?.name ?? b.code}</span>
                  <span className="font-mono text-xs text-white">{b.count}</span>
                </div>
                {/* Mini bar */}
                <div className="h-1 bg-[#1a1a28] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{
                      width: `${(b.count / maxC) * 100}%`,
                      background: bucketColour(b),
                    }}
                  />
                </div>
                <div className="flex gap-2 mt-1.5 text-[10px]">
                  {b.critical > 0 && <span className="text-red-400">{b.critical} crit</span>}
                  {b.high     > 0 && <span className="text-orange-400">{b.high} high</span>}
                </div>
              </div>
            )
          })}
          {topCountries.length === 0 && !isLoading && (
            <div className="text-xs text-slate-600 text-center py-6">No data</div>
          )}
        </div>
      </div>
    </div>
  )
}
