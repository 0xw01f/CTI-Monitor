export const SEVERITY = {
  critical: {
    label: 'CRITICAL',
    dot: 'bg-red-500',
    badge: 'bg-red-500/10 text-red-400 border border-red-500/30',
    text: 'text-red-400',
    bar: '#ef4444',
  },
  high: {
    label: 'HIGH',
    dot: 'bg-orange-500',
    badge: 'bg-orange-500/10 text-orange-400 border border-orange-500/30',
    text: 'text-orange-400',
    bar: '#f97316',
  },
  medium: {
    label: 'MEDIUM',
    dot: 'bg-yellow-500',
    badge: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30',
    text: 'text-yellow-400',
    bar: '#eab308',
  },
  low: {
    label: 'LOW',
    dot: 'bg-green-500',
    badge: 'bg-green-500/10 text-green-400 border border-green-500/30',
    text: 'text-green-400',
    bar: '#22c55e',
  },
} as const

export type SeverityKey = keyof typeof SEVERITY

export function getSev(key: string) {
  return SEVERITY[key as SeverityKey] ?? SEVERITY.low
}

// ── Threat type badges ──────────────────────────────────────────────────────

export interface TypeMeta {
  label: string
  badge: string       // Tailwind classes for the badge
  dot: string         // dot/icon colour class
  color: string       // hex for charts
}

export const TYPE_META: Record<string, TypeMeta> = {
  // ── New taxonomy ──────────────────────────────────────────────────────────
  database: {
    label: 'Database',
    badge: 'bg-cyan-950/70 text-cyan-300 border border-cyan-600/40',
    dot:   'bg-cyan-400',
    color: '#22d3ee',
  },
  access: {
    label: 'Access',
    badge: 'bg-blue-950/70 text-blue-300 border border-blue-600/40',
    dot:   'bg-blue-400',
    color: '#60a5fa',
  },
  credentials: {
    label: 'Credentials',
    badge: 'bg-amber-950/70 text-amber-300 border border-amber-600/40',
    dot:   'bg-amber-400',
    color: '#fbbf24',
  },
  stealer_logs: {
    label: 'Stealer Logs',
    badge: 'bg-purple-950/70 text-purple-300 border border-purple-600/40',
    dot:   'bg-purple-400',
    color: '#c084fc',
  },
  source_code: {
    label: 'Source Code',
    badge: 'bg-emerald-950/70 text-emerald-300 border border-emerald-600/40',
    dot:   'bg-emerald-400',
    color: '#34d399',
  },
  // ── Legacy types (backward compat) ───────────────────────────────────────
  ransomware: {
    label: 'Ransomware',
    badge: 'bg-red-950/70 text-red-300 border border-red-600/40',
    dot:   'bg-red-400',
    color: '#f87171',
  },
  leak: {
    label: 'Leak',
    badge: 'bg-orange-950/70 text-orange-300 border border-orange-600/40',
    dot:   'bg-orange-400',
    color: '#fb923c',
  },
  malware: {
    label: 'Malware',
    badge: 'bg-fuchsia-950/70 text-fuchsia-300 border border-fuchsia-600/40',
    dot:   'bg-fuchsia-400',
    color: '#e879f9',
  },
  // ── Fallback ──────────────────────────────────────────────────────────────
  other: {
    label: 'Other',
    badge: 'bg-slate-800/60 text-slate-400 border border-slate-600/30',
    dot:   'bg-slate-500',
    color: '#94a3b8',
  },
}

export function getTypeMeta(type: string): TypeMeta {
  return TYPE_META[type] ?? TYPE_META.other
}

/** Legacy alias — returns only the badge class string */
export function getTypeBadge(type: string): string {
  return getTypeMeta(type).badge
}

/** All known type keys in display order */
export const TYPE_KEYS = [
  'database', 'access', 'credentials', 'stealer_logs', 'source_code',
  'ransomware', 'leak', 'malware', 'other',
] as const
