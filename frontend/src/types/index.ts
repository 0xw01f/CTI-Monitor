export interface Threat {
  id: number
  title: string
  type: string
  severity: string
  score: number
  actor: string | null
  target: string | null
  country: string | null
  tags: string[]
  published_at: string | null
  fetched_at: string | null
  is_public: boolean
  noise_candidate?: boolean
  post_screenshot?: string | null
  victim_origin?: {
    country: string
    method: string
    confidence: number
    evidence: string
  }
  post_capture?: {
    text_length: number
    html_length: number
  }
  extracted_links?: { url: string; domain: string; type: string }[]
}

export interface ThreatListResponse {
  total: number
  items: Threat[]
}

export interface Actor {
  id: number
  username: string
  platform: string | null
  specialization: string
  first_seen: string | null
  last_seen: string | null
  post_count: number
  total_leaks: number
  reputation_score: number
  risk_level: string
  is_spammer: boolean
  sources?: { name: string; post_count: number }[]
  identities?: { type: string; value: string; confidence: number }[]
  username_history?: string[]
  tags?: string[]
  recent_threats?: Threat[]
}

export interface ActorListResponse {
  total: number
  actors: Actor[]
}

export interface DashboardStats {
  threats_24h: number
  threats_7d: number
  high_priority_24h: number
  deleted_24h: number
  total_threats: number
  hidden_threats: number
  total_sources: number
  active_sources: number
  source_health: {
    unstable_sources: number
    degraded_sources: number
  }
  severity_breakdown: Record<string, number>
  type_breakdown: Record<string, number>
  actor_risk_breakdown: Record<string, number>
  critical_actors: number
  high_risk_actors: number
  target_hotspots: { target: string; count: number }[]
  country_hotspots: { country: string; count: number }[]
  top_actors: { username: string; post_count: number; platform: string | null; risk_level: string; specialization: string }[]
  recent_threats: { id: number; title: string; type: string; severity: string; score: number; actor: string | null; published_at: string | null }[]
  analyst_queue: { id: number; title: string; type: string; severity: string; score: number; actor: string | null; target: string | null; country: string | null; published_at: string | null }[]
}

export interface TimelinePoint {
  date: string
  count: number
}

export interface XPostResult {
  ok: boolean
  text: string
  char_count: number
  screenshot_url: string | null
}

export interface ApiStatus {
  ok: boolean
  detail: string
}
